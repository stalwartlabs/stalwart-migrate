/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::{cmp::Reverse, sync::Arc};

use model::{AccountRef, Issue, IssueKind, Severity, SharedDeletes, Source, Subject, Target};
use rustc_hash::{FxHashMap, FxHashSet};
use state::{AccountPhase, AccountState, AccountUpdate, StateStore};

use super::{
    RegistryConverter, RemovalPolicy, RunKind,
    context::Context,
    error::RunError,
    executor::{for_each_bounded, for_each_with_slots},
    job::{AccountJob, Previous, account_categories},
    stats::incr,
};

const REMOVAL_GUARD_MIN: usize = 10;
const REMOVAL_GUARD_PERCENT: usize = 10;

fn pending_changes(account: &AccountRef, state: Option<&AccountState>) -> u64 {
    match state.and_then(|state| state.checkpoint) {
        Some(checkpoint) => account.change_counter.saturating_sub(checkpoint),
        None => account.change_counter,
    }
}

pub(super) fn mass_removal(removed: usize, tracked: usize) -> bool {
    removed >= REMOVAL_GUARD_MIN && removed * 100 > tracked * REMOVAL_GUARD_PERCENT
}

pub(super) struct AccountPlan {
    work: Vec<(AccountRef, Option<AccountState>)>,
    removed: Vec<u32>,
    removals_held: bool,
}

impl AccountPlan {
    pub(super) fn removals_held(&self) -> bool {
        self.removals_held
    }

    pub(super) fn keep(&mut self, accounts: &FxHashSet<u32>) {
        self.removed
            .retain(|account_id| !accounts.contains(account_id));
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn plan_accounts(&self) -> Result<AccountPlan, RunError> {
        let accounts = self.retry(|| self.source.accounts()).await?;
        let mut known: FxHashMap<u32, AccountState> = self
            .state
            .accounts()
            .await?
            .into_iter()
            .map(|account| (account.account_id, account))
            .collect();
        let tracked = known.len();

        let accounts_listed = accounts.len();
        let mut work = Vec::with_capacity(accounts.len());
        for account in accounts {
            let state = known.remove(&account.account_id);
            if self.needs_work(&account, state.as_ref()) {
                work.push((account, state));
            } else {
                incr(&self.stats.accounts_unchanged);
            }
        }
        work.sort_unstable_by_key(|(account, state): &(AccountRef, Option<AccountState>)| {
            Reverse(pending_changes(account, state.as_ref()))
        });
        let removals_held = !self
            .removals_allowed(known.len(), tracked, accounts_listed)
            .await?;
        let removed = if removals_held {
            Vec::new()
        } else {
            known.into_keys().collect()
        };
        Ok(AccountPlan {
            work,
            removed,
            removals_held,
        })
    }

    pub(super) async fn account_pass(self: &Arc<Self>, plan: AccountPlan) -> Result<(), RunError> {
        let AccountPlan { work, removed, .. } = plan;
        tracing::info!(
            accounts = work.len(),
            removed = removed.len(),
            "account pass started"
        );

        let context = self.clone();
        for_each_with_slots(
            work,
            &self.write_slots,
            &self.shutdown,
            move |(account, state), slot| {
                let context = context.clone();
                async move {
                    let result = context.account_task(account, state).await;
                    drop(slot);
                    result
                }
            },
        )
        .await?;

        let context = self.clone();
        for_each_bounded(
            removed,
            self.options.tuning.concurrency,
            &self.shutdown,
            move |account_id| {
                let context = context.clone();
                async move { context.removal_task(account_id).await }
            },
        )
        .await
    }

    pub(super) async fn wipe_target_account(&self, account_id: u32) -> Result<(), RunError> {
        let deletions = self
            .retry(|| self.target.shared_deletions(account_id))
            .await?;
        if !deletions.is_empty() {
            match self.options.shared_deletes {
                SharedDeletes::Forbid => {
                    let issues = deletions
                        .into_iter()
                        .map(|deletion| {
                            Issue::new(
                                Severity::Warning,
                                IssueKind::Skipped,
                                Subject::None,
                                format!(
                                    "not deleted outside the target: {deletion}; pass --allow-shared-deletes to delete it"
                                ),
                            )
                        })
                        .collect();
                    self.report(Some(account_id), issues).await?;
                }
                SharedDeletes::Allow => {
                    for deletion in deletions {
                        tracing::warn!(%deletion, "deleting data in a shared service");
                    }
                }
            }
        }
        self.retry(|| self.target.wipe_account(account_id)).await
    }

    async fn removals_allowed(
        &self,
        removed: usize,
        tracked: usize,
        listed: usize,
    ) -> Result<bool, RunError> {
        if removed == 0 || self.options.removals == RemovalPolicy::Allow {
            return Ok(true);
        }
        if listed != 0 && !mass_removal(removed, tracked) {
            return Ok(true);
        }
        let message = format!(
            "the source lists {removed} fewer accounts than the state database ({tracked} tracked); not wiping them. Check the source configuration or pass --allow-mass-removal"
        );
        tracing::error!("{message}");
        self.report(
            None,
            vec![Issue::new(
                Severity::Error,
                IssueKind::Skipped,
                Subject::None,
                message,
            )],
        )
        .await?;
        Ok(false)
    }

    fn needs_work(&self, account: &AccountRef, state: Option<&AccountState>) -> bool {
        match state {
            Some(state) => {
                self.options.kind == RunKind::Final
                    || state.phase != AccountPhase::Done
                    || state.checkpoint != Some(account.change_counter)
                    || !state
                        .synced
                        .contains_all(account_categories(self.options.categories))
            }
            None => true,
        }
    }

    async fn account_task(
        self: Arc<Self>,
        account: AccountRef,
        state: Option<AccountState>,
    ) -> Result<(), RunError> {
        let result = self.migrate_account(account, state).await;
        self.settle(account.account_id, result).await
    }

    async fn removal_task(self: Arc<Self>, account_id: u32) -> Result<(), RunError> {
        self.check_shutdown()?;
        let result = async {
            tracing::info!(
                account_id,
                "account removed from source; wiping it in the target"
            );
            self.wipe_target_account(account_id).await?;
            failpoint!("account.remove_wipe");
            self.state
                .update_account(AccountUpdate::Remove { account_id })
                .await?;
            failpoint!("account.removed");
            incr(&self.stats.accounts_removed);
            Ok(())
        }
        .await;
        self.settle(account_id, result).await
    }

    async fn settle(&self, account_id: u32, result: Result<(), RunError>) -> Result<(), RunError> {
        match result {
            Err(err) if err.is_account_scoped() => {
                tracing::error!(account_id, error = %err, "account failed");
                let message = err.to_string().into_boxed_str();
                self.state
                    .update_account(AccountUpdate::Fail {
                        account_id,
                        error: message.clone(),
                    })
                    .await?;
                incr(&self.stats.accounts_failed);
                self.report(
                    Some(account_id),
                    vec![Issue::new(
                        Severity::Error,
                        IssueKind::Failed,
                        Subject::None,
                        message,
                    )],
                )
                .await
            }
            other => other,
        }
    }

    async fn migrate_account(
        self: &Arc<Self>,
        account: AccountRef,
        state: Option<AccountState>,
    ) -> Result<(), RunError> {
        self.check_shutdown()?;
        self.retry(|| self.source.catch_up()).await?;
        let previous = state.as_ref().and_then(|state| {
            state.checkpoint.map(|checkpoint| Previous {
                checkpoint,
                synced: state.synced,
            })
        });
        let bounds = self.retry(|| self.source.change_bounds(account)).await?;
        let mut job = AccountJob::new(self, account, bounds, previous);
        match state {
            Some(AccountState {
                checkpoint: Some(checkpoint),
                phase,
                synced,
                ..
            }) => {
                let required = account_categories(self.options.categories);
                if account.change_counter < checkpoint {
                    self.report(
                        Some(account.account_id),
                        vec![Issue::new(
                            Severity::Warning,
                            IssueKind::Changed,
                            Subject::None,
                            format!(
                                "source change counter {} is below the checkpoint {checkpoint}; copying the account again",
                                account.change_counter
                            ),
                        )],
                    )
                    .await?;
                    job.wipe().await?;
                    job.full_copy(None).await
                } else if account.change_counter > checkpoint
                    || phase != AccountPhase::Done
                    || !synced.contains_all(required)
                {
                    job.delta().await
                } else {
                    job.refresh_unlogged().await
                }
            }
            Some(AccountState {
                full_target: Some(full_target),
                ..
            }) => job.full_copy(Some(full_target)).await,
            _ => job.full_copy(None).await,
        }
    }
}
