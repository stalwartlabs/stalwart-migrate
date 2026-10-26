/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::VecDeque, sync::Arc};

use model::{ChangeSet, Collection, RecordBatch, Source, Target, WriteMode};
use state::{CursorMode, StateStore};
use tokio::{
    sync::OwnedSemaphorePermit,
    task::{JoinError, JoinSet},
};

use super::{AccountJob, write::ChunkWriter};
use crate::orchestrator::{RegistryConverter, context::Context, error::RunError};

pub(super) struct WriteSlots {
    tasks: JoinSet<Result<u32, RunError>>,
    order: VecDeque<(u32, bool)>,
    limit: usize,
}

impl WriteSlots {
    pub(super) fn new(limit: usize) -> Self {
        WriteSlots {
            tasks: JoinSet::new(),
            order: VecDeque::new(),
            limit: limit.max(1),
        }
    }

    fn finished(
        &mut self,
        joined: Result<Result<u32, RunError>, JoinError>,
    ) -> Result<(), RunError> {
        let last_id = match joined {
            Ok(result) => result?,
            Err(err) if err.is_cancelled() => return Err(RunError::Interrupted),
            Err(err) => return Err(RunError::Panic(err.to_string().into_boxed_str())),
        };
        if let Some(entry) = self
            .order
            .iter_mut()
            .find(|(id, done)| *id == last_id && !*done)
        {
            entry.1 = true;
        }
        Ok(())
    }

    fn completed_prefix(&mut self) -> Option<u32> {
        let mut last = None;
        while let Some(&(id, true)) = self.order.front() {
            last = Some(id);
            self.order.pop_front();
        }
        last
    }
}

fn spawn_write<S, T, St, C>(
    slots: &mut WriteSlots,
    context: Arc<Context<S, T, St, C>>,
    account_id: u32,
    chunk: RecordBatch,
    last_id: u32,
    permit: Option<OwnedSemaphorePermit>,
) where
    S: Source,
    T: Target,
    St: StateStore,
    C: RegistryConverter,
{
    slots.order.push_back((last_id, false));
    slots.tasks.spawn(async move {
        let _permit = permit;
        let mut writer = ChunkWriter {
            context: &context,
            account_id,
            ids: Vec::new(),
        };
        writer
            .write_records(chunk, WriteMode::Create)
            .await
            .map(|()| last_id)
    });
}

fn spawn_delta<S, T, St, C>(
    slots: &mut WriteSlots,
    context: Arc<Context<S, T, St, C>>,
    account_id: u32,
    collection: Collection,
    ids: Vec<u32>,
    mode: WriteMode,
    permit: Option<OwnedSemaphorePermit>,
) where
    S: Source,
    T: Target,
    St: StateStore,
    C: RegistryConverter,
{
    slots.tasks.spawn(async move {
        let _permit = permit;
        context.rate.acquire(ids.len()).await;
        let page = context
            .retry(|| context.source.read(account_id, collection, &ids))
            .await?;
        context.report(Some(account_id), page.issues).await?;
        let mut batch = page.batch;
        if batch.collection() != collection {
            return Err(model::Error::account(format!(
                "source returned {} records when {collection} was requested",
                batch.collection()
            ))
            .into());
        }
        let mut writer = ChunkWriter {
            context: &context,
            account_id,
            ids,
        };
        writer.write_chunked(&mut batch, mode).await?;
        Ok(0)
    });
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'_, S, T, St, C> {
    pub(super) async fn apply_writes_parallel(
        &mut self,
        collection: Collection,
        changes: &ChangeSet,
    ) -> Result<(), RunError> {
        let tuning = self.context.options.tuning;
        let code = collection.as_u8();
        let updated = &changes.updated - &changes.inserted;
        let mut slots = WriteSlots::new(tuning.account_split);
        let result = async {
            'dispatch: for (bitmap, mode) in [
                (&changes.inserted, WriteMode::Replace),
                (&updated, WriteMode::Update),
            ] {
                let mut pending = bitmap.iter();
                loop {
                    let ids: Vec<u32> = pending.by_ref().take(tuning.batch_ops).collect();
                    if ids.is_empty() {
                        break;
                    }
                    if self.context.shutdown.is_requested() {
                        break 'dispatch;
                    }
                    let permit = self.free_slot(&mut slots, code).await?;
                    spawn_delta(
                        &mut slots,
                        Arc::clone(self.context),
                        self.account_id,
                        collection,
                        ids,
                        mode,
                        permit,
                    );
                }
            }
            while let Some(joined) = slots.tasks.join_next().await {
                slots.finished(joined)?;
            }
            self.context.check_shutdown()
        }
        .await;
        if !matches!(result, Err(RunError::Interrupted)) {
            return result;
        }
        let mut failure = None;
        while let Some(joined) = slots.tasks.join_next().await {
            if let Err(err) = slots.finished(joined)
                && err != RunError::Interrupted
            {
                failure.get_or_insert(err);
            }
        }
        failure.map_or(Err(RunError::Interrupted), Err)
    }

    async fn free_slot(
        &mut self,
        slots: &mut WriteSlots,
        code: u8,
    ) -> Result<Option<OwnedSemaphorePermit>, RunError> {
        loop {
            while let Some(joined) = slots.tasks.try_join_next() {
                slots.finished(joined)?;
            }
            self.advance_full(slots, code).await?;
            if slots.tasks.is_empty() {
                return Ok(None);
            }
            if slots.tasks.len() < slots.limit
                && let Ok(permit) = self.context.write_slots.clone().try_acquire_owned()
            {
                return Ok(Some(permit));
            }
            if let Some(joined) = slots.tasks.join_next().await {
                slots.finished(joined)?;
            }
        }
    }

    pub(super) async fn dispatch_create(
        &mut self,
        slots: &mut WriteSlots,
        collection: Collection,
        chunk: RecordBatch,
        last_id: u32,
    ) -> Result<(), RunError> {
        let code = collection.as_u8();
        let permit = self.free_slot(slots, code).await?;
        self.set_cursor(code, CursorMode::Pending, u64::from(last_id))
            .await?;
        spawn_write(
            slots,
            Arc::clone(self.context),
            self.account_id,
            chunk,
            last_id,
            permit,
        );
        Ok(())
    }

    pub(super) async fn scanned_up_to(
        &mut self,
        slots: &mut WriteSlots,
        code: u8,
        last_scanned: u32,
    ) -> Result<(), RunError> {
        if slots
            .order
            .back()
            .is_none_or(|(last, _)| *last < last_scanned)
        {
            slots.order.push_back((last_scanned, true));
        }
        self.advance_full(slots, code).await
    }

    pub(super) async fn drain_slots(
        &mut self,
        slots: &mut WriteSlots,
        code: u8,
    ) -> Result<(), RunError> {
        while let Some(joined) = slots.tasks.join_next().await {
            slots.finished(joined)?;
        }
        self.advance_full(slots, code).await
    }

    pub(super) async fn drain_interrupted(
        &mut self,
        slots: &mut WriteSlots,
        code: u8,
    ) -> Result<(), RunError> {
        let mut failure = None;
        while let Some(joined) = slots.tasks.join_next().await {
            match slots.finished(joined) {
                Ok(()) | Err(RunError::Interrupted) => {}
                Err(err) => {
                    failure.get_or_insert(err);
                }
            }
        }
        self.advance_full(slots, code).await?;
        failure.map_or(Err(RunError::Interrupted), Err)
    }

    async fn advance_full(&mut self, slots: &mut WriteSlots, code: u8) -> Result<(), RunError> {
        if let Some(last) = slots.completed_prefix()
            && self
                .cursor(code, CursorMode::Full)
                .is_none_or(|cursor| cursor < u64::from(last))
        {
            self.set_cursor(code, CursorMode::Full, u64::from(last))
                .await?;
        }
        Ok(())
    }
}
