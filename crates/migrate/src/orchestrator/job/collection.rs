/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::mem;

use model::{ChangeSet, Changes, Collection, RecordBatch, Source, Target, WriteMode};
use roaring::RoaringBitmap;
use state::{CursorMode, StateStore};
use tokio::sync::mpsc;

use super::{AccountJob, parallel::WriteSlots, reader::Reader};
use crate::orchestrator::{RegistryConverter, error::RunError, stats::add};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanFilter {
    All,
    FilesOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Existing {
    UpToPending,
    Always,
}

impl ScanFilter {
    fn apply(self, batch: &mut RecordBatch) {
        if let (ScanFilter::FilesOnly, RecordBatch::FileNode(records)) = (self, batch) {
            records.retain(|record| record.file.is_some());
        }
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'_, S, T, St, C> {
    pub(super) async fn scan_collection(
        &mut self,
        collection: Collection,
        filter: ScanFilter,
        existing: Existing,
    ) -> Result<(), RunError> {
        let context = self.context;
        let code = collection.as_u8();
        let after = match self.cursor(code, CursorMode::Full) {
            Some(last_id) => Some(u32::try_from(last_id).map_err(|_| {
                RunError::Data(model::Error::account(format!(
                    "invalid {collection} cursor {last_id} in state"
                )))
            })?),
            None => None,
        };
        let pending = self.cursor(code, CursorMode::Pending);

        let tuning = context.options.tuning;
        let batch_bytes = context.batch_bytes();
        let (sender, mut receiver) = mpsc::channel(tuning.read_ahead);
        let mut reader = Reader {
            source: context.source.clone(),
            rate: context.rate.clone(),
            policy: context.policy(),
            shutdown: context.shutdown.clone(),
            account_id: self.account_id,
            collection,
            limit: tuning.batch_ops,
        }
        .spawn(after, sender);

        let parallel = collection == Collection::Email && tuning.account_split > 1;
        let mut slots = WriteSlots::new(tuning.account_split);
        let mut result = async {
            while let Some(message) = receiver.recv().await {
                let page = message?;
                context.report(Some(self.account_id), page.issues).await?;
                let mut batch = page.batch;
                let last_scanned = page.last_scanned;
                filter.apply(&mut batch);
                let check = match existing {
                    Existing::Always => true,
                    Existing::UpToPending => batch
                        .first_id()
                        .zip(pending)
                        .is_some_and(|(first, pending)| u64::from(first) <= pending),
                };
                if check {
                    let mut existing = self.split_existing(&mut batch).await?;
                    self.write_chunked(&mut existing, WriteMode::Replace)
                        .await?;
                }
                while !batch.is_empty() {
                    context.check_shutdown()?;
                    let count = batch.front_len(tuning.batch_ops, batch_bytes);
                    let chunk = batch.take_front(count);
                    let Some(last_id) = chunk.last_id() else {
                        continue;
                    };
                    if parallel {
                        self.dispatch_create(&mut slots, collection, chunk, last_id)
                            .await?;
                        continue;
                    }
                    self.set_cursor(code, CursorMode::Pending, u64::from(last_id))
                        .await?;
                    self.write_records(chunk, WriteMode::Create).await?;
                    self.set_cursor(code, CursorMode::Full, u64::from(last_id))
                        .await?;
                }
                match last_scanned {
                    Some(last_scanned) if parallel => {
                        self.scanned_up_to(&mut slots, code, last_scanned).await?;
                    }
                    Some(last_scanned)
                        if self
                            .cursor(code, CursorMode::Full)
                            .is_none_or(|cursor| cursor < u64::from(last_scanned)) =>
                    {
                        self.set_cursor(code, CursorMode::Full, u64::from(last_scanned))
                            .await?;
                    }
                    _ => {}
                }
            }
            if parallel {
                self.drain_slots(&mut slots, code).await?;
            }
            Ok(())
        }
        .await;
        if parallel && matches!(result, Err(RunError::Interrupted)) {
            result = self.drain_interrupted(&mut slots, code).await;
        }
        drop(slots);

        drop(receiver);
        if result.is_err() {
            reader.0.abort();
        }
        match (&mut reader.0).await {
            Ok(()) => result,
            Err(err) if err.is_cancelled() => result,
            Err(err) => result.and(Err(RunError::Panic(err.to_string().into_boxed_str()))),
        }
    }

    pub(super) async fn apply_delta(
        &mut self,
        collection: Collection,
        since: u64,
    ) -> Result<bool, RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let changes = context
            .retry(|| context.source.changes(account_id, collection, since))
            .await?;
        let changes = match changes {
            Changes::Truncated => return Ok(false),
            Changes::Delta(changes) => changes,
        };
        self.apply_deletes(collection, &changes.deleted).await?;
        if collection == Collection::FileNode {
            self.apply_file_changes(&changes).await?;
        } else if collection == Collection::Email && context.options.tuning.account_split > 1 {
            self.apply_writes_parallel(collection, &changes).await?;
        } else {
            self.apply_writes(collection, &changes).await?;
        }
        Ok(true)
    }

    async fn apply_deletes(
        &mut self,
        collection: Collection,
        deleted: &RoaringBitmap,
    ) -> Result<(), RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let limit = context.options.tuning.batch_ops;
        let mut ids = mem::take(&mut self.ids);
        let mut pending = deleted.iter();
        let result = async {
            loop {
                ids.clear();
                ids.extend(pending.by_ref().take(limit));
                if ids.is_empty() {
                    return Ok(());
                }
                context.check_shutdown()?;
                context
                    .retry(|| {
                        context.bounded(0, context.target.delete(account_id, collection, &ids))
                    })
                    .await?;
                failpoint!("delta.delete", collection.as_str());
                add(&context.stats.objects_deleted, ids.len() as u64);
            }
        }
        .await;
        self.ids = ids;
        result
    }

    async fn apply_writes(
        &mut self,
        collection: Collection,
        changes: &ChangeSet,
    ) -> Result<(), RunError> {
        let updated = &changes.updated - &changes.inserted;
        for (bitmap, mode) in [
            (&changes.inserted, WriteMode::Replace),
            (&updated, WriteMode::Update),
        ] {
            let mut pending = bitmap.iter();
            while let Some(mut batch) = self.read_next(collection, &mut pending).await? {
                self.write_chunked(&mut batch, mode).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn read_next(
        &mut self,
        collection: Collection,
        pending: &mut impl Iterator<Item = u32>,
    ) -> Result<Option<RecordBatch>, RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let mut ids = mem::take(&mut self.ids);
        ids.clear();
        ids.extend(pending.take(context.options.tuning.batch_ops));
        if ids.is_empty() {
            self.ids = ids;
            return Ok(None);
        }
        let result = async {
            context.check_shutdown()?;
            context.rate.acquire(ids.len()).await;
            let page = context
                .retry(|| context.source.read(account_id, collection, &ids))
                .await?;
            context.report(Some(account_id), page.issues).await?;
            let batch = page.batch;
            if batch.collection() != collection {
                return Err(model::Error::account(format!(
                    "source returned {} records when {collection} was requested",
                    batch.collection()
                ))
                .into());
            }
            Ok(Some(batch))
        }
        .await;
        self.ids = ids;
        result
    }

    pub(super) async fn write_chunked(
        &mut self,
        batch: &mut RecordBatch,
        mode: WriteMode,
    ) -> Result<(), RunError> {
        let limit = self.context.options.tuning.batch_ops;
        let batch_bytes = self.context.batch_bytes();
        while !batch.is_empty() {
            self.context.check_shutdown()?;
            let count = batch.front_len(limit, batch_bytes);
            let chunk = batch.take_front(count);
            self.write_records(chunk, mode).await?;
        }
        Ok(())
    }
}
