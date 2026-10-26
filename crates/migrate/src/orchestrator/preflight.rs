/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use model::{ClaimId, RegistryKey, Source, Target, TargetProbe};
use rustc_hash::FxHashMap;
use state::{ContentHash, MetaKey, StateStore};

use super::{
    AfterFinal, RegistryConverter, RunKind, context::Context, error::RunError, retry::Backoff,
};

const REGISTRY_SAMPLE: u32 = 16;
const MOVED_BY_ANOTHER_STATE: &str = "another state directory has used this target since this one last ran; use the --state directory that ran last. A state directory restored from a backup or copied cannot continue: start again with a new --state directory and a new, empty target";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn preflight(&self) -> Result<(), RunError> {
        let edition = self.options.edition.as_str();
        match self.state.meta(MetaKey::Edition).await? {
            Some(recorded) if recorded != edition => {
                return Err(RunError::preflight(format!(
                    "the state database was created by the {recorded} edition but this binary is the {edition} edition"
                )));
            }
            Some(_) => {}
            None => {
                self.state
                    .set_meta(MetaKey::Edition, edition.into())
                    .await?
            }
        }

        let final_done = self.state.meta(MetaKey::FinalDone).await?.is_some();
        if final_done && self.options.after_final == AfterFinal::Refuse {
            return Err(RunError::preflight(
                "the final run has already completed and v1 may be live; use --force-after-final to write anyway",
            ));
        }

        let identity = &self.options.identity;
        self.check_identity(
            MetaKey::SourceDefHash,
            identity.source_def_hash.as_deref(),
            "source",
        )
        .await?;
        self.check_identity(
            MetaKey::TargetDefHash,
            identity.target_def_hash.as_deref(),
            "target",
        )
        .await?;
        if let Some(location) = &identity.source_store {
            self.state
                .set_meta(MetaKey::SourceStore, location.clone())
                .await?;
        }

        let categories = self.options.categories.to_string();
        match self.state.meta(MetaKey::Categories).await? {
            Some(recorded) if recorded != categories => {
                tracing::warn!(
                    %recorded,
                    current = %categories,
                    "data categories changed since the previous run; newly included categories are copied for every account by this run, and data of excluded categories stays in the target as last copied"
                );
                self.state.set_meta(MetaKey::Categories, categories).await?;
            }
            Some(_) => {}
            None => self.state.set_meta(MetaKey::Categories, categories).await?,
        }
        self.state
            .set_meta(MetaKey::ToolVersion, TOOL_VERSION.into())
            .await?;
        if self.state.meta(MetaKey::CreatedAt).await?.is_none() {
            self.state
                .set_meta(MetaKey::CreatedAt, unix_now().to_string())
                .await?;
        }

        self.check_target().await?;
        self.advance_claim_generation().await?;
        if self.options.kind == RunKind::Final && !self.options.final_observation.is_zero() {
            self.observe_source().await?;
        }
        if final_done {
            self.state.remove_meta(MetaKey::FinalDone).await?;
            failpoint!("preflight.reopened");
            tracing::warn!(
                "the completed final run is no longer marked done because this run writes to the target again; run --final again before starting v1"
            );
        }
        Ok(())
    }

    async fn observe_source(&self) -> Result<(), RunError> {
        let window = self.options.final_observation;
        let server = self.options.direction.source_server();
        tracing::info!(
            seconds = window.as_secs(),
            "watching the source change counters to make sure {server} is stopped"
        );
        let before: FxHashMap<u32, u64> = self
            .retry(|| self.source.accounts())
            .await?
            .into_iter()
            .map(|account| (account.account_id, account.change_counter))
            .collect();
        tokio::select! {
            _ = tokio::time::sleep(window) => {}
            _ = self.shutdown.wait() => return Err(RunError::Interrupted),
        }
        self.retry(|| self.source.catch_up()).await?;
        let after = self.retry(|| self.source.accounts()).await?;
        let moved = after.len() != before.len()
            || after
                .iter()
                .any(|account| before.get(&account.account_id) != Some(&account.change_counter));
        if moved {
            Err(RunError::preflight(format!(
                "source change counters moved during the {} second observation window; stop every {server} node before {}",
                window.as_secs(),
                self.options.direction.final_command()
            )))
        } else {
            Ok(())
        }
    }

    async fn check_identity(
        &self,
        key: MetaKey,
        value: Option<&str>,
        what: &str,
    ) -> Result<(), RunError> {
        let Some(value) = value else {
            return Ok(());
        };
        match self.state.meta(key).await? {
            Some(recorded) if recorded != value => Err(RunError::preflight(format!(
                "the {what} store definition differs from the one recorded in the state database"
            ))),
            Some(_) => Ok(()),
            None => Ok(self.state.set_meta(key, value.into()).await?),
        }
    }

    async fn check_target(&self) -> Result<(), RunError> {
        let recorded = match self.state.meta(MetaKey::TargetSchemaVersion).await? {
            Some(value) => Some(value.parse::<u64>().map_err(|_| {
                RunError::preflight(format!("invalid target schema version {value:?} in state"))
            })?),
            None => None,
        };
        let probe = self.retry(|| self.target.probe()).await?;
        match (probe, recorded) {
            (TargetProbe::Empty, None) => {
                let edition = self.options.edition;
                self.retry(|| self.target.prepare_store(edition)).await?;
                failpoint!("preflight.prepared");
                match self.retry(|| self.target.probe()).await? {
                    TargetProbe::Initialized { schema_version } => {
                        self.state
                            .set_meta(MetaKey::TargetSchemaVersion, schema_version.to_string())
                            .await?;
                        Ok(())
                    }
                    other => Err(RunError::preflight(format!(
                        "target store is not initialized after preparing it ({other:?})"
                    ))),
                }
            }
            (TargetProbe::Empty, Some(_)) => Err(RunError::preflight(
                "the target store is empty but the state database records earlier progress; use a new --state directory",
            )),
            (TargetProbe::Initialized { schema_version }, Some(recorded))
                if schema_version == recorded =>
            {
                self.check_registry_sample().await
            }
            (TargetProbe::Initialized { schema_version }, Some(recorded)) => {
                Err(RunError::preflight(format!(
                    "target schema version {schema_version} differs from the recorded {recorded}"
                )))
            }
            (TargetProbe::Initialized { schema_version }, None) => {
                if self.retry(|| self.target.holds_claim()).await? {
                    self.state
                        .set_meta(MetaKey::TargetSchemaVersion, schema_version.to_string())
                        .await?;
                    Ok(())
                } else {
                    Err(RunError::preflight(
                        "the target store is not empty; the first run requires an empty target",
                    ))
                }
            }
            (TargetProbe::Foreign, _) => Err(RunError::preflight(
                "the target store contains data that was not written by this tool",
            )),
        }
    }

    async fn advance_claim_generation(&self) -> Result<(), RunError> {
        let recorded = |key| async move {
            Ok::<_, RunError>(
                self.state
                    .meta(key)
                    .await?
                    .as_deref()
                    .and_then(ClaimId::parse_hex),
            )
        };
        let current = recorded(MetaKey::ClaimGeneration).await?;
        let pending = recorded(MetaKey::ClaimGenerationPending).await?;
        let expected = self.retry(|| self.target.claim_generation()).await?;
        if expected.is_some_and(|stored| Some(stored) != current && Some(stored) != pending) {
            return Err(RunError::preflight(MOVED_BY_ANOTHER_STATE));
        }
        let next = ClaimId::random();
        self.state
            .set_meta(MetaKey::ClaimGenerationPending, next.to_string())
            .await?;
        let mut backoff = Backoff::new(self.policy());
        loop {
            let err = match self.target.swap_claim_generation(expected, next).await {
                Ok(true) => {
                    failpoint!("preflight.claimed");
                    break;
                }
                Ok(false) => return Err(RunError::preflight(MOVED_BY_ANOTHER_STATE)),
                Err(err) => err,
            };
            let stored = self.retry(|| self.target.claim_generation()).await?;
            if stored == Some(next) {
                break;
            }
            if stored != expected {
                return Err(RunError::preflight(MOVED_BY_ANOTHER_STATE));
            }
            if !backoff.wait(&err).await {
                return Err(err.into());
            }
        }
        self.state
            .set_meta(MetaKey::ClaimGeneration, next.to_string())
            .await?;
        Ok(())
    }

    async fn check_registry_sample(&self) -> Result<(), RunError> {
        let sample = self.state.registry_sample(REGISTRY_SAMPLE).await?;
        if sample.is_empty() {
            return Ok(());
        }
        let keys: Vec<RegistryKey> = sample.iter().map(|entry| entry.key.clone()).collect();
        let records = self.retry(|| self.target.read_registry(&keys)).await?;
        let mut buf = Vec::new();
        for (entry, record) in sample.iter().zip(records) {
            let Some(record) = record else {
                return Err(RunError::preflight(format!(
                    "registry object {} recorded in the state database is missing from the target",
                    entry.key
                )));
            };
            buf.clear();
            serde_json::to_writer(&mut buf, &record.json).map_err(|err| {
                RunError::preflight(format!("cannot serialize {}: {err}", entry.key))
            })?;
            if entry.stored_hash != Some(ContentHash::of(&buf)) {
                return Err(RunError::preflight(format!(
                    "registry object {} in the target differs from the one this tool wrote; is this the right target store?",
                    entry.key
                )));
            }
        }
        Ok(())
    }
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
