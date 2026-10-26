/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::mem;

use model::{BlobCache, Issue, IssueKind, RecordBatch, Severity, Source, Target, WriteMode};
use state::StateStore;

use super::AccountJob;
use crate::orchestrator::context::Context;
use crate::orchestrator::{
    BlobMode, RegistryConverter, blobs::KeptBlobs, error::RunError, retry::Backoff, stats::add,
};

pub(super) struct ChunkWriter<'x, S, T, St, C> {
    pub(super) context: &'x Context<S, T, St, C>,
    pub(super) account_id: u32,
    pub(super) ids: Vec<u32>,
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'_, S, T, St, C> {
    fn chunk_writer(&mut self) -> ChunkWriter<'_, S, T, St, C> {
        ChunkWriter {
            context: self.context,
            account_id: self.account_id,
            ids: mem::take(&mut self.ids),
        }
    }

    pub(super) async fn split_existing(
        &mut self,
        batch: &mut RecordBatch,
    ) -> Result<RecordBatch, RunError> {
        let mut writer = self.chunk_writer();
        let result = writer.split_existing(batch).await;
        self.ids = writer.ids;
        result
    }

    pub(super) async fn write_records(
        &mut self,
        batch: RecordBatch,
        mode: WriteMode,
    ) -> Result<(), RunError> {
        let mut writer = self.chunk_writer();
        let result = writer.write_records(batch, mode).await;
        self.ids = writer.ids;
        result
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> ChunkWriter<'_, S, T, St, C> {
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

    pub(super) async fn split_existing(
        &mut self,
        batch: &mut RecordBatch,
    ) -> Result<RecordBatch, RunError> {
        let mut existing_batch = batch.split_off(batch.len());
        if batch.is_empty() {
            return Ok(existing_batch);
        }
        let context = self.context;
        let account_id = self.account_id;
        let collection = batch.collection();
        let mut ids = mem::take(&mut self.ids);
        ids.clear();
        batch.collect_ids(&mut ids);
        let existing = context
            .retry(|| context.bounded(0, context.target.exists(account_id, collection, &ids)))
            .await;
        self.ids = ids;
        let existing = existing?;
        if !existing.is_empty() {
            existing_batch = batch.clone();
            existing_batch.retain_ids(|id| existing.contains(id));
            batch.retain_ids(|id| !existing.contains(id));
        }
        Ok(existing_batch)
    }

    pub(super) async fn write_records(
        &mut self,
        mut batch: RecordBatch,
        mode: WriteMode,
    ) -> Result<(), RunError> {
        let context = self.context;
        let KeptBlobs {
            cache: blobs,
            memory: _memory,
        } = if context.options.blob_mode == BlobMode::Copy {
            context.copy_blobs(self.account_id, &mut batch).await?
        } else {
            KeptBlobs {
                cache: BlobCache::default(),
                memory: None,
            }
        };
        let mut pending = vec![(batch, mode)];
        while let Some((mut batch, mode)) = pending.pop() {
            if batch.is_empty() {
                continue;
            }
            let mut backoff = Backoff::new(context.policy());
            let result = loop {
                match context
                    .bounded(
                        batch.weight(),
                        context
                            .target
                            .upsert_with_blobs(self.account_id, &batch, mode, &blobs),
                    )
                    .await
                {
                    Ok(outcome) => break Ok(outcome),
                    Err(err) => {
                        if !backoff.wait(&err).await {
                            break Err(err);
                        }
                        if mode == WriteMode::Create {
                            let existing = self.split_existing(&mut batch).await?;
                            if !existing.is_empty() {
                                pending.push((existing, WriteMode::Replace));
                            }
                            if batch.is_empty() {
                                break Ok(Default::default());
                            }
                        }
                    }
                }
            };
            match result {
                Ok(outcome) => {
                    failpoint!("upsert", batch.collection().as_str());
                    add(&context.stats.objects_written, batch.len() as u64);
                    if let RecordBatch::Email(emails) = &batch {
                        add(&context.stats.emails_written, emails.len() as u64);
                    }
                    add(&context.stats.bytes_written, batch.weight());
                    context
                        .report(Some(self.account_id), outcome.issues)
                        .await?;
                }
                Err(err) if err.is_too_large() => {
                    if mode == WriteMode::Create {
                        let existing = self.split_existing(&mut batch).await?;
                        if !existing.is_empty() {
                            pending.push((existing, WriteMode::Replace));
                        }
                    }
                    match batch.len() {
                        0 => {}
                        1 => {
                            context
                                .report(
                                    Some(self.account_id),
                                    vec![Issue::new(
                                        Severity::Error,
                                        IssueKind::Failed,
                                        batch.first_subject(),
                                        err.message(),
                                    )],
                                )
                                .await?;
                        }
                        len => {
                            let tail = batch.split_off(len / 2);
                            pending.push((tail, mode));
                            pending.push((batch, mode));
                        }
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }
}
