/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod account;
mod blobs;
mod context;
mod error;
mod executor;
mod finalize;
mod global;
mod job;
mod preflight;
mod rate;
mod registry;
mod retry;
mod spam;
mod stats;
mod tasks;
mod verify;

use crate::failpoint::failpoint;
use std::{num::NonZeroU32, sync::Arc, time::Duration};

use tokio::task::AbortHandle;

use model::{
    CategorySet, Edition, Issue, IssueKind, Severity, SharedDeletes, Source, Subject, Target,
};
use state::{RunId, RunMode, RunStatus, StateStore};

use crate::shutdown::Shutdown;
use context::Context;
use global::GlobalPhase;

pub use error::RunError;
pub use registry::{
    ConversionError, Converted, ConvertedRecord, EnumValue, RecordSide, RegistryConverter,
    RegistryDeletes, RegistryPatch, read_registry, registry_categories,
};
pub use retry::RetryPolicy;
pub use stats::StatsSnapshot;
pub use verify::{
    GlobalCheck, MIN_SAMPLE_ACCOUNTS, VerifyOptions, VerifyScope, VerifySummary, verify,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    pub concurrency: usize,
    pub batch_ops: usize,
    pub batch_bytes: u64,
    pub blob_concurrency: usize,
    pub read_ahead: usize,
    pub max_ops_per_sec: Option<NonZeroU32>,
    pub account_split: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            concurrency: 4,
            batch_ops: 1000,
            batch_bytes: 5 * 1024 * 1024,
            blob_concurrency: 16,
            read_ahead: 2,
            max_ops_per_sec: None,
            account_split: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    Incremental,
    Final,
}

impl RunKind {
    const fn mode(self) -> RunMode {
        match self {
            RunKind::Incremental => RunMode::Incremental,
            RunKind::Final => RunMode::Final,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobMode {
    Shared,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorPolicy {
    Refuse,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterFinal {
    Refuse,
    Force,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalPolicy {
    Guarded,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDirection {
    Migration,
    Rollback,
}

impl RunDirection {
    pub const fn source_server(self) -> &'static str {
        match self {
            RunDirection::Migration => "v0.16",
            RunDirection::Rollback => "v1",
        }
    }

    pub const fn final_command(self) -> &'static str {
        match self {
            RunDirection::Migration => "run --final",
            RunDirection::Rollback => "rollback",
        }
    }
}

pub const FINAL_OBSERVATION: Duration = Duration::from_secs(30);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const WRITE_FLOOR_BYTES_PER_SEC: u64 = 1_000_000;
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreIdentity {
    pub source_def_hash: Option<String>,
    pub target_def_hash: Option<String>,
    pub source_store: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub kind: RunKind,
    pub direction: RunDirection,
    pub edition: Edition,
    pub categories: CategorySet,
    pub blob_mode: BlobMode,
    pub tuning: Tuning,
    pub retry: RetryPolicy,
    pub errors: ErrorPolicy,
    pub after_final: AfterFinal,
    pub identity: StoreIdentity,
    pub removals: RemovalPolicy,
    pub final_observation: Duration,
    pub final_verify: VerifyScope,
    pub progress_interval: Option<Duration>,
    pub write_timeout: Duration,
    pub shared_deletes: SharedDeletes,
    pub notices: Vec<Box<str>>,
}

impl RunOptions {
    pub fn new(kind: RunKind, edition: Edition) -> Self {
        RunOptions {
            kind,
            direction: RunDirection::Migration,
            edition,
            categories: CategorySet::defaults(),
            blob_mode: BlobMode::Shared,
            tuning: Tuning::default(),
            retry: RetryPolicy::default(),
            errors: ErrorPolicy::Refuse,
            after_final: AfterFinal::Refuse,
            identity: StoreIdentity::default(),
            removals: RemovalPolicy::Guarded,
            final_observation: FINAL_OBSERVATION,
            final_verify: VerifyScope::Sample { percent: 1 },
            progress_interval: None,
            write_timeout: WRITE_TIMEOUT,
            shared_deletes: SharedDeletes::Forbid,
            notices: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    pub run_id: RunId,
    pub status: RunStatus,
    pub interrupted_runs: Vec<RunId>,
    pub stats: StatsSnapshot,
    pub error: Option<RunError>,
    pub verify: Option<VerifySummary>,
}

impl RunSummary {
    pub fn succeeded(&self) -> bool {
        self.status == RunStatus::Ok
            && self
                .verify
                .as_ref()
                .is_none_or(|verify| verify.status == RunStatus::Ok)
    }
}

pub struct Orchestrator<S, T, R, St, C> {
    source: Arc<S>,
    target: Arc<T>,
    reader: Arc<R>,
    state: Arc<St>,
    converter: Arc<C>,
    options: RunOptions,
    shutdown: Shutdown,
}

impl<S: Source, T: Target, R: Source, St: StateStore, C: RegistryConverter>
    Orchestrator<S, T, R, St, C>
{
    pub fn new(
        source: Arc<S>,
        target: Arc<T>,
        reader: Arc<R>,
        state: Arc<St>,
        converter: Arc<C>,
        options: RunOptions,
        shutdown: Shutdown,
    ) -> Self {
        Orchestrator {
            source,
            target,
            reader,
            state,
            converter,
            options,
            shutdown,
        }
    }

    pub async fn run(self) -> Result<RunSummary, RunError> {
        let start = self.state.begin_run(self.options.kind.mode()).await?;
        if !start.interrupted.is_empty() {
            tracing::warn!(runs = ?start.interrupted, "previous runs were interrupted; resuming from saved progress");
        }
        let context = Arc::new(Context::new(
            self.source,
            self.target,
            self.state,
            self.converter,
            self.options,
            self.shutdown,
            start.clone(),
        ));

        let progress = context
            .options
            .progress_interval
            .map(|interval| {
                let context = context.clone();
                tokio::spawn(async move {
                    let mut ticks = tokio::time::interval(interval);
                    ticks.tick().await;
                    loop {
                        ticks.tick().await;
                        context.stats.snapshot().log_progress(context.run_id);
                    }
                })
                .abort_handle()
            })
            .map(AbortOnDrop);
        let result = context.execute().await;
        drop(progress);
        let stats = context.stats.snapshot();
        let mut finalized = false;
        let (status, error) = match result {
            Ok(Outcome {
                failed_accounts: 0,
                finalized: false,
            }) if context.options.kind == RunKind::Final => (RunStatus::Failed, None),
            Ok(Outcome {
                failed_accounts: 0,
                finalized: done,
            }) if stats.errors == 0 || (done && context.options.errors == ErrorPolicy::Allow) => {
                finalized = done;
                if stats.errors > 0 {
                    tracing::warn!(
                        errors = stats.errors,
                        "objects that could not be copied were accepted with --allow-errors; see the report"
                    );
                }
                (RunStatus::Ok, None)
            }
            Ok(Outcome {
                failed_accounts: 0,
                finalized: done,
            }) => {
                finalized = done;
                tracing::error!(
                    errors = stats.errors,
                    "run finished with objects that could not be copied; see the report"
                );
                (RunStatus::Failed, None)
            }
            Ok(Outcome {
                failed_accounts,
                finalized: done,
            }) => {
                finalized = done;
                tracing::error!(failed_accounts, "run finished with failed accounts");
                (RunStatus::Failed, None)
            }
            Err(RunError::Interrupted) => (RunStatus::Interrupted, None),
            Err(err) => {
                tracing::error!(error = %err, "run failed");
                (RunStatus::Failed, Some(err))
            }
        };
        let mut stats_json = stats.to_json();
        if let (Some(err), Some(map)) = (&error, stats_json.as_object_mut()) {
            map.insert("error".into(), err.to_string().into());
        }
        context
            .state
            .finish_run(start.run_id, status, stats_json.to_string())
            .await?;
        failpoint!("run.finished", status.as_str());
        tracing::info!(run_id = start.run_id, %status, stats = %stats_json, "run finished");
        let mut status = status;
        let verify = if finalized {
            let mut verified = context.verify_after_final(self.reader.clone()).await?;
            if verified.status == RunStatus::Interrupted {
                status = RunStatus::Interrupted;
                tracing::warn!(
                    "finalize completed but verification was interrupted: the final run is not marked done; repeat the command (run --final, or rollback with the same --state)"
                );
            } else if verified.status == RunStatus::Ok && status == RunStatus::Ok {
                match context.write_final_spam_model(&*self.reader).await? {
                    0 => context.mark_final_done().await?,
                    mismatches => {
                        verified.status = RunStatus::Failed;
                        verified.mismatches += mismatches;
                        verified.unexplained += mismatches;
                        tracing::error!(
                            mismatches,
                            "the spam model written by the final step does not match the source: the final run is not marked done; repeat the command (run --final, or rollback with the same --state)"
                        );
                    }
                }
            } else if verified.status == RunStatus::Ok {
                tracing::error!(
                    "finalize completed but the run reported errors: the final run is not marked done; fix them and repeat the command (run --final, or rollback with the same --state), or accept them with --allow-errors"
                );
            } else {
                tracing::error!(
                    "finalize completed but verification failed: the final run is not marked done; fix the reported mismatches and repeat the command (run --final, or rollback with the same --state)"
                );
            }
            Some(verified)
        } else {
            None
        };
        Ok(RunSummary {
            run_id: start.run_id,
            status,
            interrupted_runs: start.interrupted,
            stats,
            error,
            verify,
        })
    }
}

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Outcome {
    failed_accounts: u64,
    finalized: bool,
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    async fn execute(self: &Arc<Self>) -> Result<Outcome, RunError> {
        self.preflight().await?;
        let notices = self
            .options
            .notices
            .iter()
            .map(|notice| {
                Issue::new(
                    Severity::Warning,
                    IssueKind::Skipped,
                    Subject::None,
                    notice.clone(),
                )
            })
            .collect();
        self.report(None, notices).await?;
        self.retry(|| self.source.catch_up()).await?;
        let mut accounts = self.plan_accounts().await?;
        let blob_records = self.registry_pass(accounts.removals_held()).await?;
        accounts.keep(&blob_records.held_accounts);
        self.check_shutdown()?;
        self.retry(|| self.target.start_server()).await?;
        self.registry_blob_pass(blob_records).await?;
        self.account_pass(accounts).await?;
        self.global_pass(GlobalPhase::Incremental).await?;
        let failed_accounts = self.failed_accounts().await?;
        let mut finalized = false;
        if self.options.kind == RunKind::Final {
            if self.options.errors == ErrorPolicy::Allow {
                self.global_pass(GlobalPhase::Final).await?;
                self.finalize().await?;
                self.accept_errors().await?;
                finalized = true;
            } else if failed_accounts > 0 {
                tracing::error!(
                    failed_accounts,
                    "not finalizing: accounts are in error (use --allow-errors to finalize anyway)"
                );
            } else if let errors @ 1.. = self.stats.snapshot().errors {
                tracing::error!(
                    errors,
                    "not finalizing: this run reported errors; fix them and run again, or accept the losses with --allow-errors"
                );
            } else {
                let outstanding = self.outstanding_errors().await?;
                if outstanding == 0 {
                    self.global_pass(GlobalPhase::Final).await?;
                    self.finalize().await?;
                    finalized = true;
                } else {
                    tracing::error!(
                        outstanding,
                        "not finalizing: objects and settings reported as failed are still missing in the target; fix them and run again, or accept the losses with --allow-errors"
                    );
                }
            }
        }
        Ok(Outcome {
            failed_accounts,
            finalized,
        })
    }

    async fn verify_after_final<R: Source>(
        &self,
        reader: Arc<R>,
    ) -> Result<VerifySummary, RunError> {
        verify(
            self.source.clone(),
            reader,
            self.state.clone(),
            self.converter.clone(),
            VerifyOptions {
                scope: self.options.final_verify,
                min_sample: MIN_SAMPLE_ACCOUNTS,
                categories: self.options.categories,
                globals: GlobalCheck::Final,
                tuning: self.options.tuning,
                retry: self.options.retry,
            },
            self.shutdown.clone(),
        )
        .await
    }
}
