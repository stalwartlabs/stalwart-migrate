/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    ChangeLogRecord, LogChanges, LogCollection, LogEntry, ShareNotificationRecord, VanishedRecord,
};
use store::{
    IterateParams, Key, LogKey, SUBSPACE_LOGS, U64_LEN,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use utils::codec::leb128::Leb128Vec;

use crate::{
    error::{account, trc_error},
    target::V016Target,
};

const NAME_TERMINATOR: u8 = 0;

pub(crate) fn encode_changes(changes: &LogChanges) -> Option<Vec<u8>> {
    let containers = [
        &changes.inserted_containers,
        &changes.updated_containers,
        &changes.updated_container_properties,
        &changes.deleted_containers,
    ];
    let items = [
        &changes.inserted_items,
        &changes.updated_items,
        &changes.deleted_items,
    ];
    if containers
        .iter()
        .any(|list| list.iter().any(|id| u32::try_from(*id).is_err()))
    {
        return None;
    }
    let total = containers
        .iter()
        .chain(items.iter())
        .map(|list| list.len())
        .sum::<usize>();
    let mut buf = Vec::with_capacity(8 + total * 5);
    for list in containers.iter().chain(items.iter()) {
        buf.push_leb128(list.len());
    }
    for list in containers.iter().chain(items.iter()) {
        for id in list.iter() {
            buf.push_leb128(*id);
        }
    }
    Some(buf)
}

fn encode_vanished(collection: LogCollection, record: &VanishedRecord) -> Option<Vec<u8>> {
    match (collection, record) {
        (LogCollection::VanishedEmail, VanishedRecord::Email(uids)) => {
            let mut buf = Vec::with_capacity(uids.len() * U64_LEN);
            for uid in uids {
                buf.extend_from_slice(&uid.mailbox_id.to_be_bytes());
                buf.extend_from_slice(&uid.uid.to_be_bytes());
            }
            Some(buf)
        }
        (
            LogCollection::VanishedCalendar
            | LogCollection::VanishedAddressBook
            | LogCollection::VanishedFileNode,
            VanishedRecord::Paths(paths),
        ) => {
            let mut buf = Vec::with_capacity(paths.iter().map(|path| path.len() + 1).sum());
            for path in paths {
                buf.extend_from_slice(path.as_bytes());
                buf.push(NAME_TERMINATOR);
            }
            Some(buf)
        }
        _ => None,
    }
}

pub(crate) fn log_class(account_id: u32, collection: u8, change_id: u64) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_LOGS,
        key: LogKey {
            account_id,
            collection,
            change_id,
        }
        .serialize(0),
    })
}

impl V016Target {
    pub(crate) async fn write_log_rows(
        &self,
        account_id: u32,
        rows: &[ChangeLogRecord],
    ) -> model::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        for row in rows {
            if row.collection == LogCollection::ShareNotification {
                return Err(account(
                    "share notifications cannot be written as change log rows",
                ));
            }
            let bytes = match &row.entry {
                LogEntry::Truncated => Vec::new(),
                LogEntry::Changes(changes) if !row.collection.is_vanished() => {
                    encode_changes(changes).unwrap_or_default()
                }
                LogEntry::Vanished(vanished) if row.collection.is_vanished() => {
                    encode_vanished(row.collection, vanished).ok_or_else(|| {
                        account(format!(
                            "vanished row {} of collection {} has the wrong shape",
                            row.change_id,
                            row.collection.as_u8()
                        ))
                    })?
                }
                _ => {
                    return Err(account(format!(
                        "change log row {} of collection {} has the wrong shape",
                        row.change_id,
                        row.collection.as_u8()
                    )));
                }
            };
            batch
                .set(
                    log_class(account_id, row.collection.as_u8(), row.change_id),
                    bytes,
                )
                .commit_point();
        }
        self.commit(batch).await
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
                    log_class(
                        account_id,
                        LogCollection::ShareNotification.as_u8(),
                        record.id,
                    ),
                    record.payload.to_vec(),
                )
                .commit_point();
        }
        self.commit(batch).await
    }

    pub(crate) async fn retain_shares(&self, account_id: u32, keep: &[u64]) -> model::Result<()> {
        let collection = LogCollection::ShareNotification.as_u8();
        let key = |change_id| LogKey {
            account_id,
            collection,
            change_id,
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
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        for id in stale {
            batch
                .clear(log_class(account_id, collection, id))
                .commit_point();
        }
        self.commit(batch).await
    }

    pub(crate) async fn commit(&self, mut batch: BatchBuilder) -> model::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut points = batch.commit_points();
        for point in points.iter() {
            self.store
                .write(batch.build_one(point))
                .await
                .map_err(trc_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encoded rows use the v0.16 count header followed by containers, then items.
    #[test]
    fn rows_encode_in_v016_layout() {
        let changes = LogChanges {
            inserted_containers: vec![7],
            inserted_items: vec![100, (5 << 32) | 200],
            updated_items: vec![100],
            ..Default::default()
        };
        let bytes = encode_changes(&changes).expect("encodes");
        assert_eq!(&bytes[..7], &[1, 0, 0, 0, 2, 1, 0]);
        assert_eq!(bytes[7], 7);
        let wide = LogChanges {
            updated_containers: vec![u64::from(u32::MAX) + 1],
            ..Default::default()
        };
        assert!(encode_changes(&wide).is_none());
        assert_eq!(
            encode_vanished(
                LogCollection::VanishedCalendar,
                &VanishedRecord::Paths(vec!["a.ics".into()])
            ),
            Some(b"a.ics\0".to_vec())
        );
    }
}
