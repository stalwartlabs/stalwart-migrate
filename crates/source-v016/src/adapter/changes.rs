/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use model::{
    ChangeLogRecord, ChangeSet, Changes, Collection, LogChanges, LogCollection, LogEntry, LogRange,
    MailboxUid, ShareNotificationRecord, VanishedRecord,
};
use rustc_hash::FxHashMap;
use store::{IterateParams, LogKey, Store, U64_LEN, write::key::DeserializeBigEndian};
use utils::codec::leb128::Leb128Iterator;

use super::error::{corrupt, trc_error};

const SYNC_EMAIL: u8 = 0;
const SYNC_CALENDAR: u8 = 2;
const SYNC_ADDRESS_BOOK: u8 = 3;
const SYNC_FILE_NODE: u8 = 4;
const SYNC_IDENTITY: u8 = 5;
const SYNC_SUBMISSION: u8 = 6;
const SYNC_SIEVE: u8 = 7;
const SYNC_NOTIFICATION: u8 = 8;
const SYNC_SHARE: u8 = 9;
const DOCUMENT_MASK: u64 = u32::MAX as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Items,
    Containers,
    Both,
}

const fn source_log(collection: Collection) -> Option<(u8, Part)> {
    match collection {
        Collection::Email => Some((SYNC_EMAIL, Part::Items)),
        Collection::Mailbox => Some((SYNC_EMAIL, Part::Containers)),
        Collection::Identity => Some((SYNC_IDENTITY, Part::Items)),
        Collection::EmailSubmission => Some((SYNC_SUBMISSION, Part::Items)),
        Collection::SieveScript => Some((SYNC_SIEVE, Part::Items)),
        Collection::Calendar => Some((SYNC_CALENDAR, Part::Containers)),
        Collection::CalendarEvent => Some((SYNC_CALENDAR, Part::Items)),
        Collection::AddressBook => Some((SYNC_ADDRESS_BOOK, Part::Containers)),
        Collection::ContactCard => Some((SYNC_ADDRESS_BOOK, Part::Items)),
        Collection::FileNode => Some((SYNC_FILE_NODE, Part::Both)),
        Collection::CalendarEventNotification => Some((SYNC_NOTIFICATION, Part::Items)),
        Collection::Thread | Collection::Principal | Collection::PushSubscription => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Insert,
    Update,
    Delete,
}

const fn classify((first, last): (Op, Op)) -> Op {
    match (first, last) {
        (_, Op::Delete) => Op::Delete,
        (_, Op::Insert) | (Op::Insert, Op::Update) => Op::Insert,
        (Op::Update | Op::Delete, Op::Update) => Op::Update,
    }
}

fn decode_row(bytes: &[u8]) -> Option<LogChanges> {
    let mut iter = bytes.iter();
    let mut counts = [0usize; 7];
    for count in counts.iter_mut() {
        *count = iter.next_leb128()?;
    }
    let [
        container_inserts,
        container_updates,
        container_properties,
        container_deletes,
        item_inserts,
        item_updates,
        item_deletes,
    ] = counts;
    let mut read = |count: usize| -> Option<Vec<u64>> {
        let mut list = Vec::with_capacity(count.min(bytes.len()));
        for _ in 0..count {
            list.push(iter.next_leb128()?);
        }
        Some(list)
    };
    let inserted_containers = read(container_inserts)?;
    let updated_containers = read(container_updates)?;
    let updated_container_properties = read(container_properties)?;
    let deleted_containers = read(container_deletes)?;
    let inserted_items = read(item_inserts)?;
    let updated_items = read(item_updates)?;
    let deleted_items = read(item_deletes)?;
    Some(LogChanges {
        inserted_items,
        updated_items,
        deleted_items,
        inserted_containers,
        updated_containers,
        deleted_containers,
        updated_container_properties,
    })
}

fn log_range(account_id: u32, collection: u8, from: u64, to: u64) -> IterateParams<LogKey> {
    IterateParams::new(
        LogKey {
            account_id,
            collection,
            change_id: from,
        },
        LogKey {
            account_id,
            collection,
            change_id: to,
        },
    )
    .ascending()
}

fn track(ops: &mut FxHashMap<u32, (Op, Op)>, ids: &[u64], op: Op) -> Option<()> {
    for id in ids {
        let document_id = u32::try_from(id & DOCUMENT_MASK).ok()?;
        ops.entry(document_id)
            .and_modify(|(_, last)| *last = op)
            .or_insert((op, op));
    }
    Some(())
}

pub(super) async fn changes(
    store: &Store,
    account_id: u32,
    collection: Collection,
    since: u64,
) -> model::Result<Changes> {
    let Some((log, part)) = source_log(collection) else {
        return Ok(Changes::Delta(ChangeSet::default()));
    };
    let mut ops: FxHashMap<u32, (Op, Op)> = FxHashMap::default();
    let mut truncated = false;
    let mut invalid = None;
    store
        .iterate(log_range(account_id, log, since, u64::MAX), |key, value| {
            let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
            if change_id == since {
                return Ok(true);
            }
            if value.is_empty() {
                truncated = true;
                return Ok(false);
            }
            let tracked = decode_row(value).and_then(|row| {
                if part != Part::Items {
                    track(&mut ops, &row.deleted_containers, Op::Delete)?;
                    track(&mut ops, &row.inserted_containers, Op::Insert)?;
                    track(&mut ops, &row.updated_containers, Op::Update)?;
                    track(&mut ops, &row.updated_container_properties, Op::Update)?;
                }
                if part != Part::Containers {
                    track(&mut ops, &row.deleted_items, Op::Delete)?;
                    track(&mut ops, &row.inserted_items, Op::Insert)?;
                    track(&mut ops, &row.updated_items, Op::Update)?;
                }
                Some(())
            });
            if tracked.is_none() {
                invalid = Some(change_id);
                return Ok(false);
            }
            Ok(true)
        })
        .await
        .map_err(trc_error)?;
    if let Some(change_id) = invalid {
        return Err(corrupt(format!(
            "changelog row {change_id} of collection {log} for account {account_id}"
        )));
    }
    if truncated {
        return Ok(Changes::Truncated);
    }
    let mut set = ChangeSet::default();
    for (document_id, ops) in ops {
        match classify(ops) {
            Op::Insert => set.inserted.insert(document_id),
            Op::Update => set.updated.insert(document_id),
            Op::Delete => set.deleted.insert(document_id),
        };
    }
    Ok(Changes::Delta(set))
}

fn decode_vanished(collection: LogCollection, value: &[u8]) -> Option<VanishedRecord> {
    match collection {
        LogCollection::VanishedEmail => {
            let (chunks, remainder) = value.as_chunks::<U64_LEN>();
            if !remainder.is_empty() {
                return None;
            }
            Some(VanishedRecord::Email(
                chunks
                    .iter()
                    .map(|chunk| {
                        let id = u64::from_be_bytes(*chunk);
                        MailboxUid {
                            mailbox_id: (id >> 32) as u32,
                            uid: (id & DOCUMENT_MASK) as u32,
                        }
                    })
                    .collect(),
            ))
        }
        _ => {
            let body = value.strip_suffix(&[0])?;
            body.split(|byte| *byte == 0)
                .map(|name| std::str::from_utf8(name).ok().map(Box::from))
                .collect::<Option<Vec<_>>>()
                .map(VanishedRecord::Paths)
        }
    }
}

pub(super) async fn last_change_id(
    store: &Store,
    account_id: u32,
    collection: LogCollection,
    up_to: u64,
) -> model::Result<Option<u64>> {
    if collection == LogCollection::ShareNotification {
        return Err(model::Error::fatal(
            "share notifications are not change-id log rows",
        ));
    }
    let mut last = None;
    store
        .iterate(
            log_range(account_id, collection.as_u8(), 0, up_to)
                .descending()
                .no_values()
                .only_first(),
            |key, _| {
                last = Some(key.deserialize_be_u64(key.len() - U64_LEN)?);
                Ok(false)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(last)
}

pub(super) async fn changelog(
    store: &Store,
    account_id: u32,
    collection: LogCollection,
    range: LogRange,
    limit: usize,
) -> model::Result<Vec<ChangeLogRecord>> {
    if collection == LogCollection::ShareNotification {
        return Err(model::Error::fatal(
            "share notifications are not change-id log rows",
        ));
    }
    if range.is_empty() {
        return Ok(Vec::new());
    }
    let limit = limit.max(1);
    let mut rows = Vec::with_capacity(limit.min(1024));
    let mut invalid = None;
    store
        .iterate(
            log_range(
                account_id,
                collection.as_u8(),
                range.after.saturating_add(1),
                range.up_to,
            )
            .with_limit(limit),
            |key, value| {
                let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                let entry = if value.is_empty() {
                    Some(LogEntry::Truncated)
                } else if collection.is_vanished() {
                    decode_vanished(collection, value).map(LogEntry::Vanished)
                } else {
                    decode_row(value).map(LogEntry::Changes)
                };
                match entry {
                    Some(entry) => {
                        rows.push(ChangeLogRecord {
                            collection,
                            change_id,
                            entry,
                        });
                        Ok(rows.len() < limit)
                    }
                    None => {
                        invalid = Some(change_id);
                        Ok(false)
                    }
                }
            },
        )
        .await
        .map_err(trc_error)?;
    match invalid {
        Some(change_id) => Err(corrupt(format!(
            "changelog row {change_id} of {collection:?} for account {account_id}"
        ))),
        None => Ok(rows),
    }
}

pub(super) async fn share_notifications(
    store: &Store,
    account_id: u32,
    after: Option<u64>,
    limit: usize,
) -> model::Result<Vec<ShareNotificationRecord>> {
    let from = match after {
        Some(u64::MAX) => return Ok(Vec::new()),
        Some(after) => after + 1,
        None => 0,
    };
    let limit = limit.max(1);
    let mut rows = Vec::with_capacity(limit.min(1024));
    store
        .iterate(
            log_range(account_id, SYNC_SHARE, from, u64::MAX).with_limit(limit),
            |key, value| {
                rows.push(ShareNotificationRecord {
                    id: key.deserialize_be_u64(key.len() - U64_LEN)?,
                    payload: Bytes::copy_from_slice(value),
                });
                Ok(rows.len() < limit)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every (first, last) pair folds to the documented kind; a document whose last change is a delete is deleted (G1).
    #[test]
    fn classify_folds_first_and_last_change() {
        use Op::{Delete, Insert, Update};
        for (pair, expected) in [
            ((Insert, Insert), Insert),
            ((Insert, Update), Insert),
            ((Insert, Delete), Delete),
            ((Update, Insert), Insert),
            ((Update, Update), Update),
            ((Update, Delete), Delete),
            ((Delete, Insert), Insert),
            ((Delete, Update), Update),
            ((Delete, Delete), Delete),
        ] {
            assert_eq!(classify(pair), expected, "{pair:?}");
        }
    }

    // A document inserted after the checkpoint and deleted later in the range is reported deleted, so a copy made between the two rows is removed.
    #[test]
    fn insert_then_delete_across_rows_is_a_delete() {
        let mut ops = FxHashMap::default();
        track(&mut ops, &[4, 5], Op::Insert).expect("ids");
        track(&mut ops, &[(9 << 32) | 4], Op::Update).expect("ids");
        track(&mut ops, &[4], Op::Delete).expect("ids");
        assert_eq!(ops.get(&4).copied().map(classify), Some(Op::Delete));
        assert_eq!(ops.get(&5).copied().map(classify), Some(Op::Insert));
    }

    #[test]
    fn rows_and_vanished_items_decode() {
        let mut row = Vec::new();
        for value in [1u64, 0, 0, 0, 2, 1, 0, 7, 100, (5 << 32) | 200, 100] {
            let mut buf = [0u8; 10];
            let mut n = value;
            let mut len = 0;
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    buf[len] = byte;
                    len += 1;
                    break;
                }
                buf[len] = byte | 0x80;
                len += 1;
            }
            row.extend_from_slice(&buf[..len]);
        }
        let changes = decode_row(&row).expect("row");
        assert_eq!(changes.inserted_containers, [7]);
        assert_eq!(changes.inserted_items, [100, (5 << 32) | 200]);
        assert_eq!(changes.updated_items, [100]);
        assert!(decode_row(&row[..row.len() - 1]).is_none());

        let mut email = Vec::new();
        email.extend_from_slice(&((3u64 << 32) | 9).to_be_bytes());
        assert_eq!(
            decode_vanished(LogCollection::VanishedEmail, &email),
            Some(VanishedRecord::Email(vec![MailboxUid {
                mailbox_id: 3,
                uid: 9
            }]))
        );
        assert_eq!(
            decode_vanished(LogCollection::VanishedCalendar, b"a.ics\0b/c.ics\0"),
            Some(VanishedRecord::Paths(vec![
                "a.ics".into(),
                "b/c.ics".into()
            ]))
        );
        assert!(decode_vanished(LogCollection::VanishedEmail, &email[..5]).is_none());
    }
}
