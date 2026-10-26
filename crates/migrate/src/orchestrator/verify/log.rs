/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::VecDeque;

use model::{
    ChangeBounds, ChangeLogRecord, Collection, LogCollection, LogEntry, LogRange, RecordBatch,
    Source, Subject,
};
use rustc_hash::FxHashMap;
use state::StateStore;

use super::{
    Findings, Verifier, VerifyScope, compare::same_log_entry, explain::Explanations, mismatch,
};
use crate::orchestrator::{
    RegistryConverter,
    error::RunError,
    retry::{RetryPolicy, retry},
};

const MAX_LOG_ROWS: u64 = 100;

struct LogStream<'x, S> {
    source: &'x S,
    account_id: u32,
    collection: LogCollection,
    after: u64,
    up_to: u64,
    limit: usize,
    policy: RetryPolicy,
    buffer: VecDeque<ChangeLogRecord>,
    done: bool,
}

impl<'x, S: Source> LogStream<'x, S> {
    fn new(
        source: &'x S,
        account_id: u32,
        collection: LogCollection,
        up_to: u64,
        limit: usize,
        policy: RetryPolicy,
    ) -> Self {
        LogStream {
            source,
            account_id,
            collection,
            after: 0,
            up_to,
            limit: limit.max(1),
            policy,
            buffer: VecDeque::new(),
            done: false,
        }
    }

    async fn peek(&mut self) -> Result<Option<&ChangeLogRecord>, RunError> {
        if self.buffer.is_empty() && !self.done {
            let range = LogRange {
                after: self.after,
                up_to: self.up_to,
            };
            let rows = retry(self.policy, || {
                self.source
                    .changelog(self.account_id, self.collection, range, self.limit)
            })
            .await?;
            match rows.last() {
                Some(last) if last.change_id > self.after => {
                    self.after = last.change_id;
                    self.buffer.extend(rows);
                }
                _ => self.done = true,
            }
        }
        Ok(self.buffer.front())
    }

    fn pop(&mut self) -> Option<ChangeLogRecord> {
        self.buffer.pop_front()
    }
}

#[derive(Default)]
struct LogFindings {
    listed: u64,
    hidden: u64,
}

impl LogFindings {
    fn add(
        &mut self,
        findings: &mut Findings,
        collection: LogCollection,
        message: String,
        explained: bool,
    ) {
        if self.listed < MAX_LOG_ROWS {
            self.listed += 1;
            findings.add(
                mismatch(
                    Subject::None,
                    format!("changelog {collection:?}: {message}"),
                ),
                explained,
            );
        } else {
            self.hidden += 1;
            findings.mismatches += 1;
            if !explained {
                findings.unexplained += 1;
            }
        }
    }
}

fn skipped_last(
    explanations: &Explanations,
    collection: LogCollection,
    source_last: Option<u64>,
    target_last: Option<u64>,
) -> bool {
    source_last.is_some_and(|last| {
        explanations.log_row(collection, last) && target_last.is_none_or(|target| target < last)
    })
}

impl<S: Source, R: Source, St: StateStore, C: RegistryConverter> Verifier<S, R, St, C> {
    pub(super) async fn verify_changelog(
        &self,
        account_id: u32,
        checkpoint: u64,
        bounds: &ChangeBounds,
        explanations: &Explanations,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let limit = self.options.tuning.batch_ops;
        let policy = self.options.retry;
        let rows = self.options.scope == VerifyScope::Full;
        let mut log = LogFindings::default();
        for collection in LogCollection::CHANGES {
            if !self.options.categories.contains_log_collection(collection) {
                continue;
            }
            let up_to = checkpoint.min(bounds.log(collection));
            if !rows {
                let source_last = retry(policy, || {
                    self.source.last_change_id(account_id, collection, up_to)
                })
                .await?;
                let target_last = retry(policy, || {
                    self.target.last_change_id(account_id, collection, up_to)
                })
                .await?;
                if source_last != target_last {
                    let explained = match source_last {
                        Some(last) if explanations.log_row(collection, last) => {
                            self.last_copied(account_id, collection, last, explanations)
                                .await?
                                == target_last
                        }
                        _ => false,
                    };
                    log.add(
                        findings,
                        collection,
                        format!(
                            "last change id {target_last:?} in the target, {source_last:?} in the source"
                        ),
                        explained,
                    );
                }
                continue;
            }
            let mut source =
                LogStream::new(&*self.source, account_id, collection, up_to, limit, policy);
            let mut target =
                LogStream::new(&*self.target, account_id, collection, up_to, limit, policy);
            let floor = match source.peek().await? {
                Some(row) if row.entry == LogEntry::Truncated => row.change_id,
                _ => 0,
            };
            let mut source_last = None;
            let mut target_last = None;
            loop {
                self.check_shutdown()?;
                let left = source.peek().await?.map(|row| row.change_id);
                let right = target.peek().await?.map(|row| row.change_id);
                match (left, right) {
                    (None, None) => break,
                    (Some(left), Some(right)) if left == right => {
                        let (Some(original), Some(copy)) = (source.pop(), target.pop()) else {
                            break;
                        };
                        source_last = Some(left);
                        target_last = Some(right);
                        if !same_log_entry(&original.entry, &copy.entry) {
                            log.add(
                                findings,
                                collection,
                                format!("row {left} differs in the target"),
                                false,
                            );
                        }
                    }
                    (Some(left), right) if right.is_none_or(|right| left < right) => {
                        source.pop();
                        source_last = Some(left);
                        log.add(
                            findings,
                            collection,
                            format!("row {left} is missing in the target"),
                            explanations.log_row(collection, left),
                        );
                    }
                    (_, Some(right)) => {
                        target.pop();
                        target_last = Some(right);
                        if right >= floor {
                            log.add(
                                findings,
                                collection,
                                format!("row {right} is not in the source"),
                                false,
                            );
                        }
                    }
                    _ => break,
                }
            }
            if source_last != target_last {
                log.add(
                    findings,
                    collection,
                    format!(
                        "last change id {target_last:?} in the target, {source_last:?} in the source"
                    ),
                    skipped_last(explanations, collection, source_last, target_last),
                );
            }
        }
        if log.hidden > 0 {
            findings.issues.push(mismatch(
                Subject::None,
                format!("{} more changelog mismatches are not listed", log.hidden),
            ));
        }
        Ok(())
    }

    async fn last_copied(
        &self,
        account_id: u32,
        collection: LogCollection,
        mut last: u64,
        explanations: &Explanations,
    ) -> Result<Option<u64>, RunError> {
        while explanations.log_row(collection, last) {
            let Some(below) = last.checked_sub(1) else {
                return Ok(None);
            };
            match retry(self.options.retry, || {
                self.source.last_change_id(account_id, collection, below)
            })
            .await?
            {
                Some(id) => last = id,
                None => return Ok(None),
            }
        }
        Ok(Some(last))
    }

    pub(super) async fn verify_counters(
        &self,
        account_id: u32,
        checkpoint: u64,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let policy = self.options.retry;
        let source = retry(policy, || self.source.counters(account_id)).await?;
        let target = retry(policy, || self.target.counters(account_id)).await?;
        let mut report = |message: String| {
            findings.add(mismatch(Subject::None, message), false);
        };
        if target.change_id < checkpoint.min(source.change_id) {
            report(format!(
                "change counter {} in the target is below {}",
                target.change_id,
                checkpoint.min(source.change_id)
            ));
        }
        for collection in Collection::ALL {
            if !RecordBatch::has_records(collection)
                || !self.options.categories.contains_collection(collection)
            {
                continue;
            }
            if let Some(wanted) = source.document_id(collection)
                && target.document_id(collection).unwrap_or(0) < wanted
            {
                report(format!(
                    "{collection} document id counter {} in the target is below {wanted}",
                    target.document_id(collection).unwrap_or(0)
                ));
            }
        }
        if self
            .options
            .categories
            .contains_collection(Collection::Mailbox)
        {
            let copied: FxHashMap<u32, u32> = target
                .mailbox_uids
                .iter()
                .map(|uid| (uid.mailbox_id, uid.uid))
                .collect();
            for uid in &source.mailbox_uids {
                let current = copied.get(&uid.mailbox_id).copied().unwrap_or(0);
                if current < uid.uid {
                    report(format!(
                        "mailbox {} UID counter {current} in the target is below {}",
                        uid.mailbox_id, uid.uid
                    ));
                }
            }
        }
        Ok(())
    }
}
