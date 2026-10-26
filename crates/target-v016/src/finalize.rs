/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{Counters, LogChanges, LogCollection as ModelLogCollection, WriteOutcome};
use registry::schema::{
    enums::TaskAccountMaintenanceType,
    structs::{Task, TaskAccountMaintenance, TaskStatus},
};
use store::{
    IterateParams, Key, LogKey, SUBSPACE_LOGS, U32_LEN, ValueKey,
    write::{AnyKey, BatchBuilder, key::DeserializeBigEndian},
};
use types::collection::{Collection, SyncCollection};

use crate::{
    changelog::{encode_changes, log_class},
    counters::change_id_key,
    error::trc_error,
    target::V016Target,
};

const DAV_COLLECTIONS: [(
    SyncCollection,
    Option<Collection>,
    Collection,
    ModelLogCollection,
); 4] = [
    (
        SyncCollection::Calendar,
        Some(Collection::Calendar),
        Collection::CalendarEvent,
        ModelLogCollection::Calendar,
    ),
    (
        SyncCollection::AddressBook,
        Some(Collection::AddressBook),
        Collection::ContactCard,
        ModelLogCollection::AddressBook,
    ),
    (
        SyncCollection::FileNode,
        None,
        Collection::FileNode,
        ModelLogCollection::FileNode,
    ),
    (
        SyncCollection::CalendarEventNotification,
        None,
        Collection::CalendarEventNotification,
        ModelLogCollection::CalendarEventNotification,
    ),
];

fn log_key(account_id: u32, sync: SyncCollection, change_id: u64) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: SUBSPACE_LOGS,
        key: LogKey {
            account_id,
            collection: u8::from(sync),
            change_id,
        }
        .serialize(0),
    }
}

impl V016Target {
    async fn document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> model::Result<Vec<u64>> {
        let mut ids = Vec::new();
        self.store
            .iterate(
                IterateParams::new(
                    ValueKey::archive(account_id, collection, 0),
                    ValueKey::archive(account_id, collection, u32::MAX),
                )
                .no_values()
                .ascending(),
                |key, _| {
                    ids.push(u64::from(key.deserialize_be_u32(key.len() - U32_LEN)?));
                    Ok(true)
                },
            )
            .await
            .map_err(trc_error)?;
        Ok(ids)
    }

    pub(crate) async fn finalize_one(
        &self,
        account_id: u32,
        counters: &Counters,
    ) -> model::Result<WriteOutcome> {
        let counter = change_id_key(account_id);
        let current = self
            .store
            .get_counter(counter.clone())
            .await
            .map_err(trc_error)?;
        let change_id = u64::try_from(current)
            .unwrap_or_default()
            .max(counters.change_id)
            .saturating_add(1);
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        let mut logged = false;
        for (sync, container, item, _) in DAV_COLLECTIONS {
            let updated_items = self.document_ids(account_id, item).await?;
            let updated_containers = match container {
                Some(container) => self.document_ids(account_id, container).await?,
                None => Vec::new(),
            };
            if updated_items.is_empty() && updated_containers.is_empty() {
                continue;
            }
            let changes = LogChanges {
                updated_items,
                updated_containers,
                ..Default::default()
            };
            if let Some(bytes) = encode_changes(&changes) {
                batch
                    .set(log_class(account_id, u8::from(sync), change_id), bytes)
                    .commit_point();
                logged = true;
            }
        }
        if logged {
            batch.add(
                counter.class,
                i64::try_from(change_id).unwrap_or(i64::MAX) - current,
            );
        }
        batch.schedule_task(Task::AccountMaintenance(TaskAccountMaintenance {
            account_id: u64::from(account_id).into(),
            maintenance_type: TaskAccountMaintenanceType::RecalculateQuota,
            status: TaskStatus::now(),
        }));
        self.commit(batch).await?;
        Ok(WriteOutcome::ok())
    }

    pub(crate) async fn reopen_one(
        &self,
        account_id: u32,
        copied: &[(ModelLogCollection, u64)],
    ) -> model::Result<()> {
        for (sync, _, _, collection) in DAV_COLLECTIONS {
            let after = copied
                .iter()
                .find(|(copied, _)| *copied == collection)
                .map_or(0, |(_, change_id)| *change_id);
            let from = log_key(account_id, sync, after.saturating_add(1));
            let to = log_key(account_id, sync, u64::MAX);
            let mut found = false;
            self.store
                .iterate(
                    IterateParams::new(from.clone(), to.clone())
                        .no_values()
                        .ascending()
                        .only_first(),
                    |_, _| {
                        found = true;
                        Ok(false)
                    },
                )
                .await
                .map_err(trc_error)?;
            if found {
                self.store.delete_range(from, to).await.map_err(trc_error)?;
            }
        }
        Ok(())
    }
}
