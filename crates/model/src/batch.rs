/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;

use crate::{
    groupware::{
        AddressBookRecord, CalendarEventRecord, CalendarRecord, ContactRecord,
        EventNotificationRecord, FileNodeRecord,
    },
    ids::{BlobHash, Collection},
    issue::{Issue, Subject},
    mail::{EmailRecord, IdentityRecord, MailboxRecord, SieveRecord, SubmissionRecord},
};

const BASE_WEIGHT: u64 = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct RecordPage {
    pub batch: RecordBatch,
    pub issues: Vec<Issue>,
    pub last_scanned: Option<u32>,
}

impl RecordPage {
    pub fn new(batch: RecordBatch) -> Self {
        RecordPage {
            last_scanned: batch.last_id(),
            batch,
            issues: Vec::new(),
        }
    }
}

pub trait Record: Sized {
    const COLLECTION: Collection;

    fn document_id(&self) -> u32;

    fn weight(&self) -> u64 {
        BASE_WEIGHT
    }

    fn blob(&self) -> Option<(BlobHash, u64)> {
        None
    }
}

impl Record for MailboxRecord {
    const COLLECTION: Collection = Collection::Mailbox;

    fn document_id(&self) -> u32 {
        self.document_id
    }
}

impl Record for EmailRecord {
    const COLLECTION: Collection = Collection::Email;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn weight(&self) -> u64 {
        BASE_WEIGHT + u64::from(self.size) + self.extra_headers.len() as u64
    }

    fn blob(&self) -> Option<(BlobHash, u64)> {
        Some((self.blob_hash, u64::from(self.size)))
    }
}

impl Record for SieveRecord {
    const COLLECTION: Collection = Collection::SieveScript;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn weight(&self) -> u64 {
        BASE_WEIGHT + u64::from(self.size)
    }

    fn blob(&self) -> Option<(BlobHash, u64)> {
        Some((self.blob_hash, u64::from(self.size)))
    }
}

impl Record for IdentityRecord {
    const COLLECTION: Collection = Collection::Identity;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn weight(&self) -> u64 {
        BASE_WEIGHT + (self.text_signature.len() + self.html_signature.len()) as u64
    }
}

impl Record for SubmissionRecord {
    const COLLECTION: Collection = Collection::EmailSubmission;

    fn document_id(&self) -> u32 {
        self.document_id
    }
}

impl Record for CalendarRecord {
    const COLLECTION: Collection = Collection::Calendar;

    fn document_id(&self) -> u32 {
        self.document_id
    }
}

impl Record for CalendarEventRecord {
    const COLLECTION: Collection = Collection::CalendarEvent;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn weight(&self) -> u64 {
        BASE_WEIGHT + 2 * self.icalendar.len() as u64
    }
}

impl Record for EventNotificationRecord {
    const COLLECTION: Collection = Collection::CalendarEventNotification;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn weight(&self) -> u64 {
        BASE_WEIGHT + 2 * self.icalendar.len() as u64
    }
}

impl Record for AddressBookRecord {
    const COLLECTION: Collection = Collection::AddressBook;

    fn document_id(&self) -> u32 {
        self.document_id
    }
}

impl Record for ContactRecord {
    const COLLECTION: Collection = Collection::ContactCard;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn weight(&self) -> u64 {
        BASE_WEIGHT + 2 * self.vcard.len() as u64
    }
}

impl Record for FileNodeRecord {
    const COLLECTION: Collection = Collection::FileNode;

    fn document_id(&self) -> u32 {
        self.document_id
    }

    fn blob(&self) -> Option<(BlobHash, u64)> {
        self.file
            .as_ref()
            .map(|file| (file.blob_hash, u64::from(file.size)))
    }
}

macro_rules! record_batch {
    ($($variant:ident => $record:ty),* $(,)?) => {
        #[derive(Debug, Clone, PartialEq)]
        pub enum RecordBatch {
            $($variant(Vec<$record>),)*
        }

        $(
            impl From<Vec<$record>> for RecordBatch {
                fn from(records: Vec<$record>) -> Self {
                    RecordBatch::$variant(records)
                }
            }
        )*

        impl RecordBatch {
            pub fn new(collection: Collection) -> Option<Self> {
                match collection {
                    $(Collection::$variant => Some(RecordBatch::$variant(Vec::new())),)*
                    _ => None,
                }
            }

            pub const fn has_records(collection: Collection) -> bool {
                matches!(collection, $(Collection::$variant)|*)
            }

            pub const fn collection(&self) -> Collection {
                match self {
                    $(RecordBatch::$variant(_) => Collection::$variant,)*
                }
            }

            pub fn len(&self) -> usize {
                match self {
                    $(RecordBatch::$variant(records) => records.len(),)*
                }
            }

            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }

            pub fn last_id(&self) -> Option<u32> {
                match self {
                    $(RecordBatch::$variant(records) => records.last().map(Record::document_id),)*
                }
            }

            pub fn first_id(&self) -> Option<u32> {
                match self {
                    $(RecordBatch::$variant(records) => records.first().map(Record::document_id),)*
                }
            }

            pub fn collect_ids(&self, out: &mut Vec<u32>) {
                match self {
                    $(RecordBatch::$variant(records) => {
                        out.extend(records.iter().map(Record::document_id))
                    })*
                }
            }

            pub fn collect_blobs(&self, out: &mut Vec<(BlobHash, u64)>) {
                match self {
                    $(RecordBatch::$variant(records) => {
                        out.extend(records.iter().filter_map(Record::blob))
                    })*
                }
            }

            pub fn collect_blob_refs(&self, out: &mut Vec<(BlobHash, u32)>) {
                match self {
                    $(RecordBatch::$variant(records) => out.extend(
                        records
                            .iter()
                            .filter_map(|record| record.blob().map(|(hash, _)| (hash, record.document_id())))
                    ),)*
                }
            }

            pub fn weight(&self) -> u64 {
                match self {
                    $(RecordBatch::$variant(records) => records.iter().map(Record::weight).sum(),)*
                }
            }

            pub fn split_off(&mut self, at: usize) -> Self {
                match self {
                    $(RecordBatch::$variant(records) => {
                        RecordBatch::$variant(records.split_off(at.min(records.len())))
                    })*
                }
            }

            pub fn take_front(&mut self, count: usize) -> Self {
                let tail = self.split_off(count);
                mem::replace(self, tail)
            }

            pub fn retain_ids(&mut self, mut keep: impl FnMut(u32) -> bool) {
                match self {
                    $(RecordBatch::$variant(records) => {
                        records.retain(|record| keep(record.document_id()))
                    })*
                }
            }

            pub fn front_len(&self, max_ops: usize, max_bytes: u64) -> usize {
                match self {
                    $(RecordBatch::$variant(records) => front_len(records, max_ops, max_bytes),)*
                }
            }

            pub fn first_subject(&self) -> Subject {
                match self.first_id() {
                    Some(document_id) => Subject::Document {
                        collection: self.collection(),
                        document_id,
                    },
                    None => Subject::None,
                }
            }
        }
    };
}

record_batch! {
    Mailbox => MailboxRecord,
    Calendar => CalendarRecord,
    AddressBook => AddressBookRecord,
    FileNode => FileNodeRecord,
    Identity => IdentityRecord,
    SieveScript => SieveRecord,
    Email => EmailRecord,
    EmailSubmission => SubmissionRecord,
    CalendarEvent => CalendarEventRecord,
    CalendarEventNotification => EventNotificationRecord,
    ContactCard => ContactRecord,
}

fn front_len<R: Record>(records: &[R], max_ops: usize, max_bytes: u64) -> usize {
    let limit = max_ops.max(1).min(records.len());
    let mut total = 0u64;
    let mut count = 0usize;
    for record in records.iter().take(limit) {
        total = total.saturating_add(record.weight());
        if count > 0 && total > max_bytes {
            break;
        }
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emails(sizes: &[u32]) -> RecordBatch {
        RecordBatch::Email(
            sizes
                .iter()
                .zip(1u32..)
                .map(|(size, document_id)| EmailRecord {
                    document_id,
                    size: *size,
                    ..Default::default()
                })
                .collect(),
        )
    }

    #[test]
    fn front_len_respects_ops_and_bytes() {
        let batch = emails(&[1000, 1000, 1000, 1000]);
        assert_eq!(batch.front_len(10, 10_000), 4);
        assert_eq!(batch.front_len(2, 10_000), 2);
        assert_eq!(batch.front_len(10, 2600), 2);
        assert_eq!(batch.front_len(10, 1), 1);
        assert_eq!(emails(&[]).front_len(10, 10), 0);
    }

    #[test]
    fn take_front_and_retain() {
        let mut batch = emails(&[1, 2, 3, 4, 5]);
        let front = batch.take_front(2);
        assert_eq!(front.first_id(), Some(1));
        assert_eq!(front.last_id(), Some(2));
        assert_eq!(batch.first_id(), Some(3));
        batch.retain_ids(|id| id != 4);
        let mut ids = Vec::new();
        batch.collect_ids(&mut ids);
        assert_eq!(ids, [3, 5]);
        assert!(RecordBatch::new(Collection::Thread).is_none());
        assert!(RecordBatch::has_records(Collection::FileNode));
    }
}
