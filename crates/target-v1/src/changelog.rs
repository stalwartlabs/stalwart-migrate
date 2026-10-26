/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    ChangeLogRecord, LogChanges, LogCollection as ModelLogCollection, LogEntry,
    ShareNotificationRecord, VanishedRecord,
};
use store::{
    IterateParams, Key, Subspace, ValueKey,
    write::{
        AnyClass, BatchBuilder, LogCollection, ValueClass,
        log::{ChangeSet, Changes, VanishedItem, VanishedItems},
    },
};
use types::collection::{SyncCollection, VanishedCollection};

use crate::{
    error::{account, trc_error},
    target::V1Target,
};

fn change_set(ids: &[u64]) -> ChangeSet<u64> {
    let mut set = ChangeSet::default();
    for id in ids {
        set.insert(*id);
    }
    set
}

fn changes(entry: &LogChanges) -> Changes {
    let mut changes = Changes::default();
    changes.item_inserts = change_set(&entry.inserted_items);
    changes.item_updates = change_set(&entry.updated_items);
    changes.item_deletes = change_set(&entry.deleted_items);
    changes.container_inserts = change_set(&entry.inserted_containers);
    changes.container_updates = change_set(&entry.updated_containers);
    changes.container_deletes = change_set(&entry.deleted_containers);
    changes.container_property_changes = change_set(&entry.updated_container_properties);
    changes
}

fn log_collection(collection: ModelLogCollection) -> Option<LogCollection> {
    let value = collection.as_u8();
    if collection.is_vanished() {
        let vanished = match collection {
            ModelLogCollection::VanishedEmail => VanishedCollection::Email,
            ModelLogCollection::VanishedCalendar => VanishedCollection::Calendar,
            ModelLogCollection::VanishedAddressBook => VanishedCollection::AddressBook,
            ModelLogCollection::VanishedFileNode => VanishedCollection::FileNode,
            _ => return None,
        };
        Some(LogCollection::Vanished(vanished))
    } else if collection == ModelLogCollection::ShareNotification {
        None
    } else {
        Some(LogCollection::Sync(SyncCollection::from(value)))
    }
}

impl V1Target {
    pub(crate) async fn write_log_rows(
        &self,
        account_id: u32,
        rows: &[ChangeLogRecord],
    ) -> model::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        let mut scratch = Vec::new();
        for row in rows {
            let collection = log_collection(row.collection).ok_or_else(|| {
                account(format!(
                    "log collection {} cannot be written as a change log row",
                    row.collection.as_u8()
                ))
            })?;
            let bytes = match (&row.entry, collection) {
                (LogEntry::Truncated, _) => Vec::new(),
                (LogEntry::Changes(entry), LogCollection::Sync(sync)) => changes(entry)
                    .serialize(sync.is_prefixed(), &mut scratch)
                    .ok_or_else(|| account("change log row holds unresolved ids"))?,
                (
                    LogEntry::Vanished(VanishedRecord::Email(uids)),
                    LogCollection::Vanished(vanished),
                ) if !vanished.is_named() => VanishedItems(
                    uids.iter()
                        .map(|uid| VanishedItem::from((uid.mailbox_id, uid.uid)))
                        .collect(),
                )
                .serialize(false, &mut scratch),
                (
                    LogEntry::Vanished(VanishedRecord::Paths(paths)),
                    LogCollection::Vanished(vanished),
                ) if vanished.is_named() => VanishedItems(
                    paths
                        .iter()
                        .map(|path| VanishedItem::Name(path.to_string()))
                        .collect(),
                )
                .serialize(true, &mut scratch),
                _ => {
                    return Err(account(format!(
                        "change log row {} of collection {} has the wrong shape",
                        row.change_id,
                        row.collection.as_u8()
                    )));
                }
            };
            batch.set(
                ValueClass::Any(AnyClass {
                    subspace: Subspace::Logs,
                    key: collection.log_key(account_id, row.change_id).serialize(0),
                }),
                bytes,
            );
            batch.commit_point();
        }
        self.store
            .write_batch(&mut batch)
            .await
            .map(|_| ())
            .map_err(trc_error)
    }

    pub(crate) async fn write_shares(
        &self,
        account_id: u32,
        records: &[ShareNotificationRecord],
    ) -> model::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        for record in records {
            batch
                .set(
                    ValueClass::ShareNotification {
                        notification_id: record.id,
                        notify_account_id: account_id,
                    },
                    record.payload.to_vec(),
                )
                .commit_point();
        }
        self.store
            .write_batch(&mut batch)
            .await
            .map(|_| ())
            .map_err(trc_error)
    }

    pub(crate) async fn retain_shares(&self, account_id: u32, keep: &[u64]) -> model::Result<()> {
        let key = |notification_id| {
            ValueKey::from(ValueClass::ShareNotification {
                notification_id,
                notify_account_id: account_id,
            })
        };
        let mut stale = Vec::new();
        self.store
            .iterate(
                IterateParams::new(key(0), key(u64::MAX)).no_values(),
                |key, _| {
                    if let Some(id) = key.last_chunk::<8>().map(|id| u64::from_be_bytes(*id))
                        && keep.binary_search(&id).is_err()
                    {
                        stale.push(id);
                    }
                    Ok(true)
                },
            )
            .await
            .map_err(trc_error)?;
        if stale.is_empty() {
            return Ok(());
        }
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        for notification_id in stale {
            batch
                .clear(ValueClass::ShareNotification {
                    notification_id,
                    notify_account_id: account_id,
                })
                .commit_point();
        }
        self.store
            .write_batch(&mut batch)
            .await
            .map(|_| ())
            .map_err(trc_error)
    }
}
