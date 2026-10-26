/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::sync::Arc;

use model::{Collection, GlobalCategory, IssueKind, Source, Subject, Target};
use state::{AccountPhase, CursorMode, MetaKey, RegistryStatus, RunId, StateStore};

use super::{
    RegistryConverter, context::Context, error::RunError, executor::for_each_bounded,
    preflight::unix_now, registry::registry_categories,
};

const FINALIZED_CURSOR: u8 = 0;

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn finalize(self: &Arc<Self>) -> Result<(), RunError> {
        self.retry(|| self.source.catch_up()).await?;
        self.add_stock_spam_tags().await?;
        let accounts: Vec<u32> = self
            .state
            .accounts()
            .await?
            .into_iter()
            .filter(|account| account.phase == AccountPhase::Done)
            .map(|account| account.account_id)
            .collect();
        tracing::info!(accounts = accounts.len(), "finalizing target");

        let context = self.clone();
        for_each_bounded(
            accounts,
            self.options.tuning.concurrency,
            &self.shutdown,
            move |account_id| {
                let context = context.clone();
                async move {
                    let finalized = context
                        .state
                        .cursors(account_id)
                        .await?
                        .iter()
                        .any(|cursor| cursor.mode == CursorMode::Finalized);
                    if finalized {
                        return Ok(());
                    }
                    context.check_shutdown()?;
                    let counters = context
                        .retry(|| context.source.counters(account_id))
                        .await?;
                    let outcome = context
                        .retry(|| context.target.finalize_account(account_id, &counters))
                        .await?;
                    failpoint!("finalize.account");
                    context.report(Some(account_id), outcome.issues).await?;
                    context
                        .state
                        .set_cursor(account_id, FINALIZED_CURSOR, CursorMode::Finalized, 1)
                        .await?;
                    failpoint!("finalize.cursor");
                    Ok(())
                }
            },
        )
        .await?;

        let categories = self.options.categories;
        let outcome = self
            .retry(|| self.target.finalize_store(categories))
            .await?;
        failpoint!("finalize.store");
        self.report(None, outcome.issues).await?;
        Ok(())
    }

    pub(super) async fn outstanding_errors(&self) -> Result<u64, RunError> {
        let categories = registry_categories(self.options.categories);
        let mut outstanding = 0u64;
        for object in self.state.registry_objects().await? {
            if !categories.contains(self.converter.category(&object)) {
                continue;
            }
            outstanding += self
                .state
                .registry_states(object)
                .await?
                .iter()
                .filter(|entry| entry.status == RegistryStatus::Error)
                .count() as u64;
        }
        let accepted = self.accepted_errors().await?;
        outstanding += self
            .state
            .account_errors(accepted, IssueKind::Skipped)
            .await?;
        for category in GlobalCategory::ALL {
            if !self.options.categories.contains(category.category())
                || category.category().is_final_only()
            {
                continue;
            }
            for object in category.objects() {
                outstanding += self
                    .state
                    .global_errors(accepted.saturating_add(1)..RunId::MAX, (*object).into())
                    .await?;
            }
        }

        let limit = self.options.tuning.batch_ops.max(1);
        let page_limit = u32::try_from(limit).unwrap_or(u32::MAX);
        let mut ids: Vec<u32> = Vec::with_capacity(limit);
        let mut present = Vec::with_capacity(limit);
        let mut group: Option<(u32, Collection)> = None;
        let mut from = None;
        loop {
            self.check_shutdown()?;
            let page = self
                .state
                .failed_documents(accepted, from, page_limit)
                .await?;
            let Some(last) = page.last() else {
                break;
            };
            from = Some(*last);
            let complete = page.len() < limit;
            for document in page {
                if !self
                    .options
                    .categories
                    .contains_collection(document.collection)
                {
                    continue;
                }
                let key = (document.account_id, document.collection);
                if group != Some(key) || ids.len() == limit {
                    if let Some((account_id, collection)) = group {
                        outstanding += self
                            .missing_in_target(account_id, collection, &ids, &mut present)
                            .await?;
                    }
                    ids.clear();
                    group = Some(key);
                }
                ids.push(document.document_id);
            }
            if complete {
                break;
            }
        }
        if let Some((account_id, collection)) = group {
            outstanding += self
                .missing_in_target(account_id, collection, &ids, &mut present)
                .await?;
        }
        Ok(outstanding)
    }

    async fn missing_in_target(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
        present: &mut Vec<u32>,
    ) -> Result<u64, RunError> {
        self.check_shutdown()?;
        let page = self
            .retry(|| self.source.read(account_id, collection, ids))
            .await?;
        present.clear();
        page.batch.collect_ids(present);
        present.extend(page.issues.iter().filter_map(|issue| match issue.subject {
            Subject::Document {
                collection: issue_collection,
                document_id,
            } if issue_collection == collection && ids.binary_search(&document_id).is_ok() => {
                Some(document_id)
            }
            _ => None,
        }));
        present.sort_unstable();
        present.dedup();
        if present.is_empty() {
            return Ok(0);
        }
        let copied = self
            .retry(|| self.target.exists(account_id, collection, present))
            .await?;
        Ok(present
            .iter()
            .filter(|document_id| !copied.contains(**document_id))
            .count() as u64)
    }

    pub(super) async fn accepted_errors(&self) -> Result<RunId, RunError> {
        Ok(self
            .state
            .meta(MetaKey::AcceptedErrors)
            .await?
            .and_then(|value| value.parse().ok())
            .unwrap_or(0))
    }

    pub(super) async fn mark_final_done(&self) -> Result<(), RunError> {
        self.state
            .set_meta(MetaKey::FinalDone, unix_now().to_string())
            .await?;
        failpoint!("run.final_done");
        Ok(())
    }

    pub(super) async fn accept_errors(&self) -> Result<(), RunError> {
        self.state
            .set_meta(MetaKey::AcceptedErrors, self.run_id.to_string())
            .await?;
        Ok(())
    }
}
