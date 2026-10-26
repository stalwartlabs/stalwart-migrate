/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::mem;

use model::{
    Category, ChangeLogRecord, Explanation, Issue, IssueKind, LogCollection, LogRange, Severity,
    Source, Subject, Target,
};
use state::{CursorMode, StateStore};

use super::AccountJob;
use crate::orchestrator::{RegistryConverter, RunKind, error::RunError, stats::add};

const SHARE_CURSOR: u8 = LogCollection::ShareNotification.as_u8();

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'_, S, T, St, C> {
    pub(super) async fn copy_log(&mut self) -> Result<(), RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let limit = context.options.tuning.batch_ops;
        let batch_bytes = context.batch_bytes();
        for collection in LogCollection::CHANGES {
            if !context
                .options
                .categories
                .contains_log_collection(collection)
            {
                continue;
            }
            let code = collection.as_u8();
            let up_to = self.bounds.log(collection);
            let mut after = self.cursor(code, CursorMode::Log).unwrap_or(0);
            while after < up_to {
                context.check_shutdown()?;
                context.rate.acquire(limit).await;
                let range = LogRange { after, up_to };
                let mut rows = context
                    .retry(|| {
                        context
                            .source
                            .changelog(account_id, collection, range, limit)
                    })
                    .await?;
                let Some(last) = rows.last().map(|row| row.change_id) else {
                    break;
                };
                if last <= after || last > up_to {
                    return Err(model::Error::account(format!(
                        "source changelog for {collection:?} returned change id {last} outside ({after}, {up_to}]"
                    ))
                    .into());
                }
                while !rows.is_empty() {
                    let count = log_front_len(&rows, limit, batch_bytes);
                    let tail = rows.split_off(count);
                    let chunk = mem::replace(&mut rows, tail);
                    self.write_log_rows(chunk).await?;
                }
                self.set_cursor(code, CursorMode::Log, last).await?;
                after = last;
            }
            if after < up_to {
                self.set_cursor(code, CursorMode::Log, up_to).await?;
            }
        }
        Ok(())
    }

    async fn write_log_rows(&self, rows: Vec<ChangeLogRecord>) -> Result<(), RunError> {
        let context = self.context;
        let mut pending = vec![rows];
        while let Some(mut rows) = pending.pop() {
            let result = context
                .retry(|| context.target.write_changelog(self.account_id, &rows))
                .await;
            match result {
                Ok(()) => {
                    failpoint!("log.write");
                    add(&context.stats.log_rows, rows.len() as u64)
                }
                Err(RunError::Data(err)) if err.is_too_large() && rows.len() > 1 => {
                    let tail = rows.split_off(rows.len() / 2);
                    pending.push(tail);
                    pending.push(rows);
                }
                Err(RunError::Data(err)) if err.is_too_large() => {
                    let issue = match rows.first() {
                        Some(row) => Issue::new(
                            Severity::Error,
                            IssueKind::Skipped,
                            Subject::None,
                            format!(
                                "changelog row {:?}/{}: {}",
                                row.collection,
                                row.change_id,
                                err.message()
                            ),
                        )
                        .explaining(Explanation::LogRow(row.collection, row.change_id)),
                        None => Issue::new(
                            Severity::Error,
                            IssueKind::Skipped,
                            Subject::None,
                            err.message(),
                        ),
                    };
                    context.report(Some(self.account_id), vec![issue]).await?;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub(super) async fn copy_share_notifications(&mut self) -> Result<(), RunError> {
        let context = self.context;
        if !context.options.categories.contains(Category::Principals) {
            return Ok(());
        }
        let account_id = self.account_id;
        let limit = context.options.tuning.batch_ops;
        let mut after = self.cursor(SHARE_CURSOR, CursorMode::Share);
        loop {
            context.check_shutdown()?;
            context.rate.acquire(limit).await;
            let rows = context
                .retry(|| context.source.share_notifications(account_id, after, limit))
                .await?;
            let (Some(first), Some(last)) = (rows.first(), rows.last()) else {
                break;
            };
            if after.is_some_and(|after| first.id <= after) || last.id < first.id {
                return Err(model::Error::account(format!(
                    "source share notifications did not advance past {after:?}"
                ))
                .into());
            }
            let last = last.id;
            context
                .retry(|| context.target.write_share_notifications(account_id, &rows))
                .await?;
            failpoint!("share.write");
            add(&context.stats.log_rows, rows.len() as u64);
            self.set_cursor(SHARE_CURSOR, CursorMode::Share, last)
                .await?;
            after = Some(last);
        }
        if context.options.kind == RunKind::Final {
            self.retain_share_notifications().await?;
        }
        Ok(())
    }

    async fn retain_share_notifications(&mut self) -> Result<(), RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let limit = context.options.tuning.batch_ops;
        let mut keep = Vec::new();
        let mut after = None;
        loop {
            context.check_shutdown()?;
            context.rate.acquire(limit).await;
            let rows = context
                .retry(|| context.source.share_notifications(account_id, after, limit))
                .await?;
            let Some(last) = rows.last().map(|row| row.id) else {
                break;
            };
            if after.is_some_and(|after| last <= after) {
                return Err(model::Error::account(format!(
                    "source share notifications did not advance past {after:?}"
                ))
                .into());
            }
            keep.extend(rows.iter().map(|row| row.id));
            after = Some(last);
        }
        keep.sort_unstable();
        context
            .retry(|| context.target.retain_share_notifications(account_id, &keep))
            .await?;
        failpoint!("share.retain");
        Ok(())
    }
}

fn log_front_len(rows: &[ChangeLogRecord], max_ops: usize, max_bytes: u64) -> usize {
    let limit = max_ops.max(1).min(rows.len());
    let mut total = 0u64;
    let mut count = 0usize;
    for row in rows.iter().take(limit) {
        total = total.saturating_add(row.weight());
        if count > 0 && total > max_bytes {
            break;
        }
        count += 1;
    }
    count
}
