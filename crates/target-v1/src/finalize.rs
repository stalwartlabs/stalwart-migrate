/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{Counters, LogCollection as ModelLogCollection, WriteOutcome};
#[cfg(feature = "enterprise")]
use registry::schema::prelude::ObjectType;
use roaring::RoaringBitmap;
use services::task_manager::tasks::maintenance::recalculate_quota;
#[cfg(feature = "enterprise")]
use services::task_manager::tasks::maintenance::recalculate_tenant_quota;
#[cfg(feature = "enterprise")]
use store::registry::RegistryQuery;
use store::{
    IterateParams, Key, Subspace, U32_LEN, ValueKey,
    write::{
        AnyClass, AnyKey, BatchBuilder, LogCollection, ValueClass,
        key::DeserializeBigEndian,
        log::{ChangeSet, Changes},
    },
};
use types::collection::{Collection, SyncCollection};

use crate::{error::trc_error, target::V1Target};

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

fn log_key(sync: SyncCollection, account_id: u32, change_id: u64) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: Subspace::Logs,
        key: LogCollection::Sync(sync)
            .log_key(account_id, change_id)
            .serialize(0),
    }
}

fn change_set(ids: &RoaringBitmap) -> ChangeSet<u64> {
    let mut set = ChangeSet::default();
    for id in ids {
        set.insert(u64::from(id));
    }
    set
}

impl V1Target {
    async fn document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> model::Result<RoaringBitmap> {
        let mut ids = RoaringBitmap::new();
        self.store
            .iterate(
                IterateParams::new(
                    ValueKey::archive(account_id, collection, 0),
                    ValueKey::archive(account_id, collection, u32::MAX),
                )
                .no_values()
                .ascending(),
                |key, _| {
                    ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
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
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        let mut scratch = Vec::new();
        for (sync, container, item, _) in DAV_COLLECTIONS {
            let items = self.document_ids(account_id, item).await?;
            let containers = match container {
                Some(container) => self.document_ids(account_id, container).await?,
                None => RoaringBitmap::new(),
            };
            if items.is_empty() && containers.is_empty() {
                continue;
            }
            let counter = ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::ChangeId(sync.change_group()),
            };
            let current = self
                .store
                .get_counter(counter.clone())
                .await
                .map_err(trc_error)?;
            let change_id = u64::try_from(current)
                .unwrap_or_default()
                .max(counters.change_id)
                + 1;
            let mut changes = Changes::default();
            changes.item_updates = change_set(&items);
            changes.container_updates = change_set(&containers);
            let Some(bytes) = changes.serialize(sync.is_prefixed(), &mut scratch) else {
                continue;
            };
            batch
                .set(
                    ValueClass::Any(AnyClass {
                        subspace: Subspace::Logs,
                        key: LogCollection::Sync(sync)
                            .log_key(account_id, change_id)
                            .serialize(0),
                    }),
                    bytes,
                )
                .add(
                    counter.class,
                    i64::try_from(change_id).unwrap_or(i64::MAX) - current,
                )
                .commit_point();
        }
        self.store
            .write_batch(&mut batch)
            .await
            .map_err(trc_error)?;
        recalculate_quota(self.server()?, account_id)
            .await
            .map_err(trc_error)?;
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
            let from = log_key(sync, account_id, after.saturating_add(1));
            let to = log_key(sync, account_id, u64::MAX);
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

    pub(crate) async fn finalize_all(&self) -> model::Result<WriteOutcome> {
        let server = self.server()?;
        #[cfg(feature = "enterprise")]
        for tenant_id in server
            .registry()
            .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Tenant))
            .await
            .map_err(trc_error)?
        {
            recalculate_tenant_quota(server, tenant_id)
                .await
                .map_err(trc_error)?;
        }
        #[cfg(not(feature = "enterprise"))]
        let _ = server;
        Ok(WriteOutcome::ok())
    }
}
