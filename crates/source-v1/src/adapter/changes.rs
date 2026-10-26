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
use store::{
    IterateParams, LogKey, Store, U64_LEN, ValueKey,
    query::log::DeserializeVanished,
    write::{ValueClass, key::DeserializeBigEndian},
};
use types::collection::SyncCollection;
use utils::codec::leb128::Leb128Reader;

use super::error::{corrupt, trc_error};

const SYNC_EMAIL: u8 = 0;
const SYNC_CALENDAR: u8 = 2;
const SYNC_ADDRESS_BOOK: u8 = 3;
const SYNC_FILE_NODE: u8 = 4;
const SYNC_IDENTITY: u8 = 5;
const SYNC_SUBMISSION: u8 = 6;
const SYNC_SIEVE: u8 = 7;
const SYNC_NOTIFICATION: u8 = 8;
const DOCUMENT_MASK: u64 = u32::MAX as u64;

const PRESENCE_EXTENDED: u8 = 0x80;
const CONTAINER_INSERTS: u32 = 0;
const CONTAINER_UPDATES: u32 = 1;
const CONTAINER_PROPERTY_CHANGES: u32 = 2;
const CONTAINER_DELETES: u32 = 3;
const ITEM_INSERTS: u32 = 4;
const ITEM_UPDATES: u32 = 5;
const ITEM_DELETES: u32 = 6;
const CONTAINER_METADATA: u32 = 7;
const ITEM_METADATA: u32 = 8;
const CHANGE_LISTS: usize = 9;
const BASE_LISTS: u32 = CONTAINER_METADATA;
const ITEM_LISTS: u16 =
    (1 << ITEM_INSERTS) | (1 << ITEM_UPDATES) | (1 << ITEM_DELETES) | (1 << ITEM_METADATA);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Part {
    Items,
    Containers,
    Both,
}

pub(super) const fn source_log(collection: Collection) -> Option<(u8, Part)> {
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

const fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

fn list_mut(changes: &mut LogChanges, slot: u32) -> Option<&mut Vec<u64>> {
    Some(match slot {
        CONTAINER_INSERTS => &mut changes.inserted_containers,
        CONTAINER_UPDATES | CONTAINER_METADATA => &mut changes.updated_containers,
        CONTAINER_PROPERTY_CHANGES => &mut changes.updated_container_properties,
        CONTAINER_DELETES => &mut changes.deleted_containers,
        ITEM_INSERTS => &mut changes.inserted_items,
        ITEM_UPDATES | ITEM_METADATA => &mut changes.updated_items,
        ITEM_DELETES => &mut changes.deleted_items,
        _ => return None,
    })
}

fn decode_lists(
    bytes: &mut &[u8],
    presence: u16,
    is_prefixed: bool,
    changes: &mut LogChanges,
) -> Option<()> {
    let mut counts = [0usize; CHANGE_LISTS];
    let mut bits = presence;
    while bits != 0 {
        let slot = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        *counts.get_mut(slot)? = bytes.read_leb128()?;
    }
    let mut bits = presence;
    while bits != 0 {
        let slot = bits.trailing_zeros();
        bits &= bits - 1;
        let count = *counts.get(slot as usize)?;
        let prefixed = is_prefixed && ITEM_LISTS & (1 << slot) != 0;
        let list = list_mut(changes, slot)?;
        list.reserve(count.min(bytes.len()));
        let mut prev_id = 0u64;
        let mut prev_prefix = 0u64;
        let mut prev_document_id = 0i64;
        for _ in 0..count {
            let id = if prefixed {
                prev_prefix = prev_prefix.wrapping_add(bytes.read_leb128::<u64>()?);
                prev_document_id =
                    prev_document_id.wrapping_add(zigzag_decode(bytes.read_leb128::<u64>()?));
                (prev_prefix << 32) | (prev_document_id as u64 & DOCUMENT_MASK)
            } else {
                prev_id = prev_id.wrapping_add(bytes.read_leb128::<u64>()?);
                prev_id
            };
            list.push(id);
        }
    }
    Some(())
}

pub(super) fn decode_row(bytes: &[u8], is_prefixed: bool) -> Option<LogChanges> {
    let (&first, mut rest) = bytes.split_first()?;
    let mut changes = LogChanges::default();
    decode_lists(
        &mut rest,
        u16::from(first & !PRESENCE_EXTENDED),
        is_prefixed,
        &mut changes,
    )?;
    if first & PRESENCE_EXTENDED != 0 {
        let (&extended, tail) = rest.split_first()?;
        rest = tail;
        if u32::from(extended) >> (CHANGE_LISTS as u32 - BASE_LISTS) != 0 {
            return None;
        }
        decode_lists(
            &mut rest,
            u16::from(extended) << BASE_LISTS,
            is_prefixed,
            &mut changes,
        )?;
        for list in [&mut changes.updated_containers, &mut changes.updated_items] {
            list.sort_unstable();
            list.dedup();
        }
    }
    rest.is_empty().then_some(changes)
}

fn decode_vanished(collection: LogCollection, value: &[u8]) -> Option<VanishedRecord> {
    if collection == LogCollection::VanishedEmail {
        let mut items: Vec<(u32, u32)> = Vec::new();
        <(u32, u32)>::deserialize_vanished(value, &mut items)?;
        Some(VanishedRecord::Email(
            items
                .into_iter()
                .map(|(mailbox_id, uid)| MailboxUid { mailbox_id, uid })
                .collect(),
        ))
    } else {
        let mut items: Vec<String> = Vec::new();
        String::deserialize_vanished(value, &mut items)?;
        Some(VanishedRecord::Paths(
            items.into_iter().map(String::into_boxed_str).collect(),
        ))
    }
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

fn track(ops: &mut FxHashMap<u32, (Op, Op)>, ids: &[u64], op: Op) {
    for id in ids {
        let document_id = (id & DOCUMENT_MASK) as u32;
        ops.entry(document_id)
            .and_modify(|(_, last)| *last = op)
            .or_insert((op, op));
    }
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
    let is_prefixed = SyncCollection::from(log).is_prefixed();
    let mut rows: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut truncated = false;
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
            rows.push((change_id, value.to_vec()));
            Ok(true)
        })
        .await
        .map_err(trc_error)?;
    if truncated {
        return Ok(Changes::Truncated);
    }
    let mut ops: FxHashMap<u32, (Op, Op)> = FxHashMap::default();
    for (change_id, value) in rows {
        let row = decode_row(&value, is_prefixed).ok_or_else(|| {
            corrupt(format!(
                "changelog row {change_id} of collection {log} for account {account_id}"
            ))
        })?;
        if part != Part::Items {
            track(&mut ops, &row.deleted_containers, Op::Delete);
            track(&mut ops, &row.inserted_containers, Op::Insert);
            track(&mut ops, &row.updated_containers, Op::Update);
            track(&mut ops, &row.updated_container_properties, Op::Update);
        }
        if part != Part::Containers {
            track(&mut ops, &row.deleted_items, Op::Delete);
            track(&mut ops, &row.inserted_items, Op::Insert);
            track(&mut ops, &row.updated_items, Op::Update);
        }
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
    let mut raw: Vec<(u64, Vec<u8>)> = Vec::with_capacity(limit.min(1024));
    store
        .iterate(
            log_range(
                account_id,
                collection.as_u8(),
                range.after.saturating_add(1),
                range.up_to,
            )
            .limit(limit),
            |key, value| {
                raw.push((key.deserialize_be_u64(key.len() - U64_LEN)?, value.to_vec()));
                Ok(raw.len() < limit)
            },
        )
        .await
        .map_err(trc_error)?;
    let is_prefixed =
        !collection.is_vanished() && SyncCollection::from(collection.as_u8()).is_prefixed();
    let mut rows = Vec::with_capacity(raw.len());
    for (change_id, value) in raw {
        let entry = if value.is_empty() {
            Some(LogEntry::Truncated)
        } else if collection.is_vanished() {
            decode_vanished(collection, &value).map(LogEntry::Vanished)
        } else {
            decode_row(&value, is_prefixed).map(LogEntry::Changes)
        };
        let entry = entry.ok_or_else(|| {
            corrupt(format!(
                "changelog row {change_id} of {collection:?} for account {account_id}"
            ))
        })?;
        rows.push(ChangeLogRecord {
            collection,
            change_id,
            entry,
        });
    }
    Ok(rows)
}

fn share_key(account_id: u32, notification_id: u64) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: 0,
        document_id: 0,
        class: ValueClass::ShareNotification {
            notification_id,
            notify_account_id: account_id,
        },
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
            IterateParams::new(share_key(account_id, from), share_key(account_id, u64::MAX))
                .ascending()
                .limit(limit),
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
    use store::write::log::{ChangeSet as V1ChangeSet, Changes as V1Changes};

    use super::*;

    fn set(ids: &[u64]) -> V1ChangeSet<u64> {
        let mut set = V1ChangeSet::default();
        for id in ids {
            set.insert(*id);
        }
        set
    }

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
        track(&mut ops, &[4, 5], Op::Insert);
        track(&mut ops, &[(9 << 32) | 4], Op::Update);
        track(&mut ops, &[4], Op::Delete);
        assert_eq!(ops.get(&4).copied().map(classify), Some(Op::Delete));
        assert_eq!(ops.get(&5).copied().map(classify), Some(Op::Insert));
    }

    // Rows encoded by the v1 serializer decode back to the same lists.
    #[test]
    fn decodes_v1_rows() {
        let mut changes = V1Changes::default();
        changes.container_inserts = set(&[3, 7]);
        changes.container_property_changes = set(&[9]);
        changes.item_inserts = set(&[(5 << 32) | 10, (2 << 32) | 11, 4]);
        changes.item_updates = set(&[(5 << 32) | 3]);
        changes.item_deletes = set(&[(1 << 32) | 900, 12]);
        let mut scratch = Vec::new();
        for is_prefixed in [true, false] {
            let bytes = changes.serialize(is_prefixed, &mut scratch).expect("row");
            let row = decode_row(&bytes, is_prefixed).expect("decode");
            assert_eq!(row.inserted_containers, [3, 7]);
            assert_eq!(row.updated_container_properties, [9]);
            assert_eq!(row.inserted_items, [4, (2 << 32) | 11, (5 << 32) | 10]);
            assert_eq!(row.updated_items, [(5 << 32) | 3]);
            assert_eq!(row.deleted_items, [12, (1 << 32) | 900]);
            assert!(decode_row(&bytes[..bytes.len() - 1], is_prefixed).is_none());
        }
    }
}
