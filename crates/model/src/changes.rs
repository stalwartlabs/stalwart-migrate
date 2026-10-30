/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use roaring::RoaringBitmap;

use crate::{
    category::{Category, CategorySet},
    ids::{Collection, LogCollection, MailboxUid},
    mail::PushRecord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountRef {
    pub account_id: u32,
    pub change_counter: u64,
}

impl AccountRef {
    pub fn registered(mut counted: Vec<AccountRef>, registered: &RoaringBitmap) -> Vec<AccountRef> {
        counted.sort_unstable_by_key(|account| account.account_id);
        registered
            .iter()
            .map(|account_id| AccountRef {
                account_id,
                change_counter: counted
                    .binary_search_by_key(&account_id, |account| account.account_id)
                    .ok()
                    .and_then(|position| counted.get(position))
                    .map_or(0, |account| account.change_counter),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeBounds {
    collections: [u64; Collection::COUNT],
    logs: [u64; LogCollection::CHANGES.len()],
}

impl ChangeBounds {
    pub const fn uniform(counter: u64) -> Self {
        ChangeBounds {
            collections: [counter; Collection::COUNT],
            logs: [counter; LogCollection::CHANGES.len()],
        }
    }

    pub fn collection(&self, collection: Collection) -> u64 {
        self.collections
            .get(usize::from(collection.as_u8()))
            .copied()
            .unwrap_or_default()
    }

    pub fn set_collection(&mut self, collection: Collection, bound: u64) {
        if let Some(slot) = self.collections.get_mut(usize::from(collection.as_u8())) {
            *slot = bound;
        }
    }

    pub fn log(&self, collection: LogCollection) -> u64 {
        log_slot(collection)
            .and_then(|slot| self.logs.get(slot))
            .copied()
            .unwrap_or_default()
    }

    pub fn set_log(&mut self, collection: LogCollection, bound: u64) {
        if let Some(slot) = log_slot(collection).and_then(|slot| self.logs.get_mut(slot)) {
            *slot = bound;
        }
    }
}

fn log_slot(collection: LogCollection) -> Option<usize> {
    LogCollection::CHANGES
        .iter()
        .position(|candidate| *candidate == collection)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChangeSet {
    pub inserted: RoaringBitmap,
    pub updated: RoaringBitmap,
    pub deleted: RoaringBitmap,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.inserted.is_empty() && self.updated.is_empty() && self.deleted.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Changes {
    Truncated,
    Delta(ChangeSet),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRange {
    pub after: u64,
    pub up_to: u64,
}

impl LogRange {
    pub const fn is_empty(&self) -> bool {
        self.after >= self.up_to
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogChanges {
    pub inserted_items: Vec<u64>,
    pub updated_items: Vec<u64>,
    pub deleted_items: Vec<u64>,
    pub inserted_containers: Vec<u64>,
    pub updated_containers: Vec<u64>,
    pub deleted_containers: Vec<u64>,
    pub updated_container_properties: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VanishedRecord {
    Email(Vec<MailboxUid>),
    Paths(Vec<Box<str>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogEntry {
    Changes(LogChanges),
    Vanished(VanishedRecord),
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeLogRecord {
    pub collection: LogCollection,
    pub change_id: u64,
    pub entry: LogEntry,
}

impl ChangeLogRecord {
    pub fn weight(&self) -> u64 {
        const ITEM: u64 = 8;
        let items = match &self.entry {
            LogEntry::Changes(changes) => {
                changes.inserted_items.len()
                    + changes.updated_items.len()
                    + changes.deleted_items.len()
                    + changes.inserted_containers.len()
                    + changes.updated_containers.len()
                    + changes.deleted_containers.len()
                    + changes.updated_container_properties.len()
            }
            LogEntry::Vanished(VanishedRecord::Email(uids)) => uids.len(),
            LogEntry::Vanished(VanishedRecord::Paths(paths)) => {
                paths.iter().map(|path| path.len()).sum::<usize>() / 8
            }
            LogEntry::Truncated => 0,
        };
        ITEM + ITEM * items as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Counters {
    pub change_id: u64,
    pub document_ids: [Option<u32>; Collection::COUNT],
    pub mailbox_uids: Vec<MailboxUid>,
}

impl Counters {
    pub fn document_id(&self, collection: Collection) -> Option<u32> {
        self.document_ids
            .get(usize::from(collection.as_u8()))
            .copied()
            .flatten()
    }

    pub fn set_document_id(&mut self, collection: Collection, value: u32) {
        if let Some(slot) = self.document_ids.get_mut(usize::from(collection.as_u8())) {
            *slot = Some(value);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaUsage {
    pub stored: i64,
    pub computed: i64,
    pub objects: [ObjectCountUsage; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectCountUsage {
    pub name: &'static str,
    pub stored: i64,
    pub computed: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParticipantIdentityRecord {
    pub id: u32,
    pub name: Option<String>,
    pub calendar_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParticipantIdentitiesRecord {
    pub identities: Vec<ParticipantIdentityRecord>,
    pub default_name: String,
    pub default: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Pointer<T> {
    #[default]
    Keep,
    Set(Option<T>),
}

impl<T> Pointer<T> {
    pub const fn is_keep(&self) -> bool {
        matches!(self, Pointer::Keep)
    }

    pub fn take(&mut self) -> Pointer<T> {
        std::mem::take(self)
    }

    pub fn as_set(&self) -> Option<Option<&T>> {
        match self {
            Pointer::Keep => None,
            Pointer::Set(value) => Some(value.as_ref()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AccountPointers {
    pub active_script: Pointer<u32>,
    pub default_calendar: Pointer<u32>,
    pub default_address_book: Pointer<u32>,
    pub identity_addresses_hash: Pointer<u64>,
    pub participant_identities: Pointer<ParticipantIdentitiesRecord>,
    pub push_subscriptions: Pointer<Vec<PushRecord>>,
}

impl AccountPointers {
    pub fn is_empty(&self) -> bool {
        self.active_script.is_keep()
            && self.default_calendar.is_keep()
            && self.default_address_book.is_keep()
            && self.identity_addresses_hash.is_keep()
            && self.participant_identities.is_keep()
            && self.push_subscriptions.is_keep()
    }

    pub fn retain_categories(&mut self, categories: CategorySet) {
        if !categories.contains(Category::Sieve) {
            self.active_script = Pointer::Keep;
        }
        if !categories.contains(Category::Calendars) {
            self.default_calendar = Pointer::Keep;
            self.participant_identities = Pointer::Keep;
        }
        if !categories.contains(Category::Contacts) {
            self.default_address_book = Pointer::Keep;
        }
        if !categories.contains(Category::Identities) {
            self.identity_addresses_hash = Pointer::Keep;
        }
        if !categories.contains(Category::PushSubscriptions) {
            self.push_subscriptions = Pointer::Keep;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareNotificationRecord {
    pub id: u64,
    pub payload: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every data collection and change log keeps its own bound; share notifications have none.
    #[test]
    fn change_bounds_are_kept_per_collection_and_log() {
        let mut bounds = ChangeBounds::uniform(9);
        bounds.set_collection(Collection::Calendar, 3);
        bounds.set_log(LogCollection::VanishedFileNode, 4);
        bounds.set_log(LogCollection::FileNode, 5);
        bounds.set_log(LogCollection::ShareNotification, 6);
        assert_eq!(bounds.collection(Collection::Calendar), 3);
        assert_eq!(bounds.collection(Collection::CalendarEvent), 9);
        assert_eq!(bounds.log(LogCollection::VanishedFileNode), 4);
        assert_eq!(bounds.log(LogCollection::FileNode), 5);
        assert_eq!(bounds.log(LogCollection::VanishedCalendar), 9);
        assert_eq!(bounds.log(LogCollection::ShareNotification), 0);
    }

    // Every registered account is listed, without a change counter as 0; counted but unregistered ones are dropped.
    #[test]
    fn registered_accounts_include_those_without_a_counter() {
        let account = |account_id, change_counter| AccountRef {
            account_id,
            change_counter,
        };
        let registered = RoaringBitmap::from_iter([1, 2, 5, 9]);
        let counted = vec![account(9, 7), account(3, 4), account(1, 2)];
        assert_eq!(
            AccountRef::registered(counted, &registered),
            [account(1, 2), account(2, 0), account(5, 0), account(9, 7)]
        );
    }
}
