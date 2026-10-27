/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    ops::Bound,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use bytes::Bytes;
use mapping::ids::JmapId;
use migrate::{
    orchestrator::{
        ConversionError, Converted, ConvertedRecord, RecordSide, RegistryConverter,
        RegistryDeletes, RegistryPatch,
    },
    shutdown::Shutdown,
};
use model::{
    AccountPointers, AccountRef, AddressBookRecord, BlobHash, CalendarEventRecord, CalendarRecord,
    Category, CategorySet, ChangeBounds, ChangeLogRecord, ChangeSet, Changes, Collection,
    ContactRecord, Counters, EmailRecord, Error, EventNotificationRecord, FileNodeRecord,
    FileRecord, GlobalBatch, GlobalCategory, GlobalKey, GlobalPage, IdentityRecord,
    InternalReportRecord, Issue, IssueKind, LogChanges, LogCollection, LogEntry, LogRange,
    MailboxRecord, MailboxUid, Pointer, RecordBatch, RecordPage, RegistryCounter, RegistryEntries,
    RegistryId, RegistryKey, RegistryRecord, ReportKind, Result, Severity, ShareNotificationRecord,
    SieveRecord, Source, SpamModelChange, SpamModelKind, SpamModelRecord, Subject,
    SubmissionRecord, Target, TargetProbe, WriteMode, WriteOutcome,
};

const SPAM_CLASSIFIER: &str = "spamClassifier";
const SPAM_TRAINER: &str = "spamTrainer";
use roaring::RoaringBitmap;
use rustc_hash::FxHashSet;
use tokio::sync::Notify;

pub const SCHEMA_VERSION: u64 = 7;

#[derive(Debug, Clone, PartialEq)]
pub enum FakeSpamBlob {
    Source(SpamModelRecord),
    Target(SpamModelRecord),
    Garbage,
}

pub type SpamBlobs = Arc<Mutex<BTreeMap<SpamModelKind, FakeSpamBlob>>>;

fn spam_blob_page(
    blobs: &SpamBlobs,
    side: fn(&FakeSpamBlob) -> Option<&SpamModelRecord>,
) -> GlobalPage {
    let blobs = lock(blobs);
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for (kind, blob) in blobs.iter() {
        match side(blob) {
            Some(record) => records.push(record.clone()),
            None => issues.push(Issue::new(
                Severity::Warning,
                IssueKind::Skipped,
                Subject::Registry(RegistryKey::new(kind.as_str(), 0)),
                "undecodable spam model",
            )),
        }
    }
    let mut page = GlobalPage::last(GlobalBatch::SpamModel(records));
    page.issues = issues;
    page
}

fn source_side(blob: &FakeSpamBlob) -> Option<&SpamModelRecord> {
    match blob {
        FakeSpamBlob::Source(record) => Some(record),
        _ => None,
    }
}

fn target_side(blob: &FakeSpamBlob) -> Option<&SpamModelRecord> {
    match blob {
        FakeSpamBlob::Target(record) => Some(record),
        _ => None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rec {
    Mailbox(MailboxRecord),
    Email(EmailRecord),
    Identity(IdentityRecord),
    Sieve(SieveRecord),
    FileNode(FileNodeRecord),
    Calendar(CalendarRecord),
    CalendarEvent(CalendarEventRecord),
    AddressBook(AddressBookRecord),
    Contact(ContactRecord),
    Notification(EventNotificationRecord),
    Submission(SubmissionRecord),
}

impl Rec {
    pub fn collection(&self) -> Collection {
        match self {
            Rec::Mailbox(_) => Collection::Mailbox,
            Rec::Email(_) => Collection::Email,
            Rec::Identity(_) => Collection::Identity,
            Rec::Sieve(_) => Collection::SieveScript,
            Rec::FileNode(_) => Collection::FileNode,
            Rec::Calendar(_) => Collection::Calendar,
            Rec::CalendarEvent(_) => Collection::CalendarEvent,
            Rec::AddressBook(_) => Collection::AddressBook,
            Rec::Contact(_) => Collection::ContactCard,
            Rec::Notification(_) => Collection::CalendarEventNotification,
            Rec::Submission(_) => Collection::EmailSubmission,
        }
    }

    pub fn id(&self) -> u32 {
        match self {
            Rec::Mailbox(record) => record.document_id,
            Rec::Email(record) => record.document_id,
            Rec::Identity(record) => record.document_id,
            Rec::Sieve(record) => record.document_id,
            Rec::FileNode(record) => record.document_id,
            Rec::Calendar(record) => record.document_id,
            Rec::CalendarEvent(record) => record.document_id,
            Rec::AddressBook(record) => record.document_id,
            Rec::Contact(record) => record.document_id,
            Rec::Notification(record) => record.document_id,
            Rec::Submission(record) => record.document_id,
        }
    }
}

fn batch_of(collection: Collection, records: Vec<Rec>) -> RecordBatch {
    let mut batch = RecordBatch::new(collection).expect("collection with records");
    for record in records {
        match (&mut batch, record) {
            (RecordBatch::Mailbox(list), Rec::Mailbox(record)) => list.push(record),
            (RecordBatch::Email(list), Rec::Email(record)) => list.push(record),
            (RecordBatch::Identity(list), Rec::Identity(record)) => list.push(record),
            (RecordBatch::SieveScript(list), Rec::Sieve(record)) => list.push(record),
            (RecordBatch::FileNode(list), Rec::FileNode(record)) => list.push(record),
            (RecordBatch::Calendar(list), Rec::Calendar(record)) => list.push(record),
            (RecordBatch::CalendarEvent(list), Rec::CalendarEvent(record)) => list.push(record),
            (RecordBatch::AddressBook(list), Rec::AddressBook(record)) => list.push(record),
            (RecordBatch::ContactCard(list), Rec::Contact(record)) => list.push(record),
            (RecordBatch::CalendarEventNotification(list), Rec::Notification(record)) => {
                list.push(record)
            }
            (RecordBatch::EmailSubmission(list), Rec::Submission(record)) => list.push(record),
            _ => panic!("record does not match collection"),
        }
    }
    batch
}

fn records_of(batch: &RecordBatch) -> Vec<Rec> {
    match batch {
        RecordBatch::Mailbox(list) => list.iter().cloned().map(Rec::Mailbox).collect(),
        RecordBatch::Email(list) => list.iter().cloned().map(Rec::Email).collect(),
        RecordBatch::Identity(list) => list.iter().cloned().map(Rec::Identity).collect(),
        RecordBatch::SieveScript(list) => list.iter().cloned().map(Rec::Sieve).collect(),
        RecordBatch::FileNode(list) => list.iter().cloned().map(Rec::FileNode).collect(),
        RecordBatch::Calendar(list) => list.iter().cloned().map(Rec::Calendar).collect(),
        RecordBatch::CalendarEvent(list) => list.iter().cloned().map(Rec::CalendarEvent).collect(),
        RecordBatch::AddressBook(list) => list.iter().cloned().map(Rec::AddressBook).collect(),
        RecordBatch::ContactCard(list) => list.iter().cloned().map(Rec::Contact).collect(),
        RecordBatch::CalendarEventNotification(list) => {
            list.iter().cloned().map(Rec::Notification).collect()
        }
        RecordBatch::EmailSubmission(list) => list.iter().cloned().map(Rec::Submission).collect(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Default)]
pub struct SourceAccount {
    pub counter: u64,
    groups: BTreeMap<u8, u64>,
    pub records: BTreeMap<Collection, BTreeMap<u32, Rec>>,
    history: Vec<(u64, Collection, u32, Op)>,
    purged_through: u64,
    pub pointers: AccountPointers,
    pub shares: BTreeMap<u64, Bytes>,
}

#[derive(Default)]
pub struct SourceWorld {
    pub grouped: bool,
    pub accounts: BTreeMap<u32, SourceAccount>,
    pub registry: BTreeMap<RegistryKey, serde_json::Value>,
    pub blobs: HashMap<BlobHash, Bytes>,
    pub queue: Vec<u64>,
    pub task_types: Vec<&'static str>,
    pub task_account: Option<&'static str>,
    pub task_json: Option<serde_json::Value>,
    pub spans: BTreeMap<u64, serde_json::Value>,
    pub queued: BTreeMap<u64, model::QueuedMessageRecord>,
    pub reports: ReportMap,
    pub span_resume: Option<Vec<u8>>,
    pub span_cursors: Vec<Option<Vec<u8>>>,
    pub id_counters: Vec<RegistryCounter>,
    pub undecodable: BTreeSet<(u32, Collection, u32)>,
    pub undecodable_queued: BTreeSet<u64>,
    pub unreadable_registry: BTreeSet<RegistryKey>,
    pub catch_up_fails: bool,
    pub starts_on_queue_read: bool,
    pub starts_on_scan: bool,
    pub starts_on_changelog: bool,
    pub started: bool,
    pub spam: Vec<SpamModelRecord>,
    pub spam_blobs: Option<SpamBlobs>,
}

#[derive(Default)]
pub struct FakeSource {
    pub world: Mutex<SourceWorld>,
    pub scans: Mutex<u64>,
    pub live_blobs: Arc<LiveBytes>,
}

#[derive(Debug, Default)]
pub struct LiveBytes {
    pub tracking: std::sync::atomic::AtomicBool,
    pub current: std::sync::atomic::AtomicU64,
    pub peak: std::sync::atomic::AtomicU64,
}

struct TrackedBlob {
    data: Bytes,
    live: Arc<LiveBytes>,
}

impl TrackedBlob {
    fn new(data: Bytes, live: Arc<LiveBytes>) -> Self {
        let size = data.len() as u64;
        let current = live
            .current
            .fetch_add(size, std::sync::atomic::Ordering::SeqCst)
            + size;
        live.peak
            .fetch_max(current, std::sync::atomic::Ordering::SeqCst);
        TrackedBlob { data, live }
    }
}

impl AsRef<[u8]> for TrackedBlob {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for TrackedBlob {
    fn drop(&mut self) {
        self.live
            .current
            .fetch_sub(self.data.len() as u64, std::sync::atomic::Ordering::SeqCst);
    }
}

fn change_group(collection: Collection) -> u8 {
    log_collection(collection).map_or(100 + collection.as_u8(), |(log, _)| log.as_u8())
}

fn log_group(log: LogCollection) -> u8 {
    match log {
        LogCollection::Thread | LogCollection::VanishedEmail => LogCollection::Email.as_u8(),
        LogCollection::VanishedCalendar => LogCollection::Calendar.as_u8(),
        LogCollection::VanishedAddressBook => LogCollection::AddressBook.as_u8(),
        LogCollection::VanishedFileNode => LogCollection::FileNode.as_u8(),
        log => log.as_u8(),
    }
}

impl SourceAccount {
    fn next_change_id(&mut self, collection: Collection, grouped: bool) -> u64 {
        if !grouped {
            self.counter += 1;
            return self.counter;
        }
        let group = self.groups.entry(change_group(collection)).or_default();
        *group += 1;
        let change_id = *group;
        self.counter = self.groups.values().sum();
        change_id
    }

    fn highest_change_id(&self) -> u64 {
        self.groups.values().copied().max().unwrap_or(self.counter)
    }

    fn bounds(&self, grouped: bool) -> ChangeBounds {
        if !grouped {
            return ChangeBounds::uniform(self.counter);
        }
        let group = |code: u8| self.groups.get(&code).copied().unwrap_or_default();
        let mut bounds = ChangeBounds::uniform(self.highest_change_id());
        for collection in Collection::ALL {
            if log_collection(collection).is_some() {
                bounds.set_collection(collection, group(change_group(collection)));
            }
        }
        for collection in LogCollection::CHANGES {
            bounds.set_log(collection, group(log_group(collection)));
        }
        bounds
    }
}

impl FakeSource {
    pub fn new() -> Arc<Self> {
        Arc::new(FakeSource::default())
    }

    pub fn put(&self, account_id: u32, record: Rec) {
        let mut world = lock(&self.world);
        let grouped = world.grouped;
        let collection = record.collection();
        let account = world.accounts.entry(account_id).or_default();
        let change_id = account.next_change_id(collection, grouped);
        let id = record.id();
        let op = if account
            .records
            .get(&collection)
            .is_some_and(|records| records.contains_key(&id))
        {
            Op::Update
        } else {
            Op::Insert
        };
        account
            .records
            .entry(collection)
            .or_default()
            .insert(id, record);
        account.history.push((change_id, collection, id, op));
    }

    pub fn delete(&self, account_id: u32, collection: Collection, id: u32) {
        let mut world = lock(&self.world);
        let grouped = world.grouped;
        let account = world.accounts.get_mut(&account_id).expect("account");
        let change_id = account.next_change_id(collection, grouped);
        account
            .records
            .get_mut(&collection)
            .and_then(|records| records.remove(&id));
        account
            .history
            .push((change_id, collection, id, Op::Delete));
    }

    pub fn purge_log(&self, account_id: u32) {
        let mut world = lock(&self.world);
        let account = world.accounts.get_mut(&account_id).expect("account");
        account.purged_through = account.counter;
    }

    pub fn remove_account(&self, account_id: u32) {
        lock(&self.world).accounts.remove(&account_id);
    }

    pub fn set_pointers(&self, account_id: u32, pointers: AccountPointers) {
        let mut world = lock(&self.world);
        world.accounts.entry(account_id).or_default().pointers = pointers;
    }

    pub fn add_share(&self, account_id: u32, id: u64) {
        let mut world = lock(&self.world);
        world
            .accounts
            .entry(account_id)
            .or_default()
            .shares
            .insert(id, Bytes::from(id.to_be_bytes().to_vec()));
    }

    pub fn put_registry(&self, object: &str, id: u64, json: serde_json::Value) {
        lock(&self.world)
            .registry
            .insert(RegistryKey::new(object, id), json);
    }

    pub fn put_singleton(&self, object: &str, json: serde_json::Value) {
        lock(&self.world)
            .registry
            .insert(RegistryKey::singleton(object), json);
    }

    pub fn delete_registry(&self, object: &str, id: u64) {
        lock(&self.world)
            .registry
            .remove(&RegistryKey::new(object, id));
    }

    pub fn put_blob(&self, hash: BlobHash, data: &'static [u8]) {
        lock(&self.world)
            .blobs
            .insert(hash, Bytes::from_static(data));
    }

    pub fn snapshot(&self) -> BTreeMap<u32, BTreeMap<(Collection, u32), String>> {
        lock(&self.world)
            .accounts
            .iter()
            .map(|(account_id, account)| {
                let records = account
                    .records
                    .iter()
                    .flat_map(|(collection, records)| {
                        records
                            .iter()
                            .map(move |(id, record)| ((*collection, *id), format!("{record:?}")))
                    })
                    .collect();
                (*account_id, records)
            })
            .collect()
    }

    pub fn counter(&self, account_id: u32) -> u64 {
        lock(&self.world).accounts[&account_id].counter
    }

    pub fn log_rows(&self, account_id: u32, log: LogCollection) -> Vec<u64> {
        let world = lock(&self.world);
        let account = &world.accounts[&account_id];
        account
            .history
            .iter()
            .filter(|(change_id, collection, _, _)| {
                *change_id > account.purged_through
                    && log_collection(*collection).is_some_and(|(entry, _)| entry == log)
            })
            .map(|(change_id, _, _, _)| *change_id)
            .collect()
    }
}

pub const DAV_LOGS: [LogCollection; 4] = [
    LogCollection::Calendar,
    LogCollection::AddressBook,
    LogCollection::FileNode,
    LogCollection::CalendarEventNotification,
];

fn log_collection(collection: Collection) -> Option<(LogCollection, bool)> {
    match collection {
        Collection::Email => Some((LogCollection::Email, false)),
        Collection::Mailbox => Some((LogCollection::Email, true)),
        Collection::Identity => Some((LogCollection::Identity, false)),
        Collection::SieveScript => Some((LogCollection::SieveScript, false)),
        Collection::FileNode => Some((LogCollection::FileNode, false)),
        Collection::Calendar => Some((LogCollection::Calendar, true)),
        Collection::CalendarEvent => Some((LogCollection::Calendar, false)),
        Collection::AddressBook => Some((LogCollection::AddressBook, true)),
        Collection::ContactCard => Some((LogCollection::AddressBook, false)),
        Collection::EmailSubmission => Some((LogCollection::EmailSubmission, false)),
        Collection::CalendarEventNotification => {
            Some((LogCollection::CalendarEventNotification, false))
        }
        _ => None,
    }
}

impl Source for FakeSource {
    async fn catch_up(&self) -> Result<()> {
        if lock(&self.world).catch_up_fails {
            return Err(Error::fatal("a v0.16 server started"));
        }
        Ok(())
    }

    fn check_unchanged(&self) -> Result<()> {
        if lock(&self.world).started {
            return Err(Error::fatal("a v0.16 server started"));
        }
        Ok(())
    }

    async fn registry_types(&self) -> Result<Vec<Box<str>>> {
        let world = lock(&self.world);
        let mut types: Vec<Box<str>> = world
            .registry
            .keys()
            .map(|key| key.object.clone())
            .collect();
        types.dedup();
        Ok(types)
    }

    async fn registry_page(
        &self,
        object: &str,
        after: Option<u64>,
        limit: usize,
    ) -> Result<RegistryEntries> {
        let world = lock(&self.world);
        let mut entries = RegistryEntries::default();
        for (key, json) in world.registry.iter().filter(|(key, _)| {
            &*key.object == object
                && after.is_none_or(|after| key.id.id().is_some_and(|id| id > after))
        }) {
            if entries.records.len() == limit {
                break;
            }
            if world.unreadable_registry.contains(key) {
                entries.unreadable.push(key.clone());
            } else {
                entries.records.push(RegistryRecord {
                    key: key.clone(),
                    json: json.clone(),
                });
            }
        }
        Ok(entries)
    }

    async fn registry_id_counters(&self) -> Result<Vec<RegistryCounter>> {
        Ok(lock(&self.world).id_counters.clone())
    }

    async fn accounts(&self) -> Result<Vec<AccountRef>> {
        Ok(lock(&self.world)
            .accounts
            .iter()
            .map(|(account_id, account)| AccountRef {
                account_id: *account_id,
                change_counter: account.counter,
            })
            .collect())
    }

    async fn change_bounds(&self, account: AccountRef) -> Result<ChangeBounds> {
        let world = lock(&self.world);
        Ok(world
            .accounts
            .get(&account.account_id)
            .map_or(ChangeBounds::uniform(account.change_counter), |source| {
                source.bounds(world.grouped)
            }))
    }

    async fn changes(
        &self,
        account_id: u32,
        collection: Collection,
        since: u64,
    ) -> Result<Changes> {
        let world = lock(&self.world);
        let account = world
            .accounts
            .get(&account_id)
            .ok_or_else(|| Error::account("unknown account"))?;
        if since < account.purged_through {
            return Ok(Changes::Truncated);
        }
        let mut first: BTreeMap<u32, Op> = BTreeMap::new();
        let mut last: BTreeMap<u32, Op> = BTreeMap::new();
        for (change_id, entry_collection, id, op) in &account.history {
            if *change_id > since && *entry_collection == collection {
                first.entry(*id).or_insert(*op);
                last.insert(*id, *op);
            }
        }
        let mut set = ChangeSet::default();
        for (id, last_op) in last {
            match (first[&id], last_op) {
                (_, Op::Delete) => {
                    set.deleted.insert(id);
                }
                (Op::Insert, _) => {
                    set.inserted.insert(id);
                }
                _ => {
                    set.updated.insert(id);
                }
            }
        }
        Ok(Changes::Delta(set))
    }

    async fn changelog(
        &self,
        account_id: u32,
        collection: LogCollection,
        range: LogRange,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        let mut world = lock(&self.world);
        world.started |= world.starts_on_changelog;
        let Some(account) = world.accounts.get(&account_id) else {
            return Ok(Vec::new());
        };
        Ok(account
            .history
            .iter()
            .filter(|(change_id, entry_collection, _, _)| {
                *change_id > range.after
                    && *change_id <= range.up_to
                    && *change_id > account.purged_through
                    && log_collection(*entry_collection).is_some_and(|(log, _)| log == collection)
            })
            .take(limit)
            .map(|(change_id, entry_collection, id, op)| {
                let (_, container) = log_collection(*entry_collection).expect("logged");
                let mut changes = LogChanges::default();
                let list = match (container, op) {
                    (false, Op::Insert) => &mut changes.inserted_items,
                    (false, Op::Update) => &mut changes.updated_items,
                    (false, Op::Delete) => &mut changes.deleted_items,
                    (true, Op::Insert) => &mut changes.inserted_containers,
                    (true, Op::Update) => &mut changes.updated_containers,
                    (true, Op::Delete) => &mut changes.deleted_containers,
                };
                list.push(u64::from(*id));
                ChangeLogRecord {
                    collection,
                    change_id: *change_id,
                    entry: LogEntry::Changes(changes),
                }
            })
            .collect())
    }

    async fn scan(
        &self,
        account_id: u32,
        collection: Collection,
        after: Option<u32>,
        limit: usize,
    ) -> Result<RecordPage> {
        *lock(&self.scans) += 1;
        let mut world = lock(&self.world);
        world.started |= world.starts_on_scan;
        let records = world
            .accounts
            .get(&account_id)
            .and_then(|account| account.records.get(&collection))
            .map(|records| {
                records
                    .iter()
                    .filter(|(id, _)| after.is_none_or(|after| **id > after))
                    .take(limit)
                    .map(|(_, record)| record.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(undecodable_page(&world, account_id, collection, records))
    }

    async fn read(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> Result<RecordPage> {
        let world = lock(&self.world);
        let records = world
            .accounts
            .get(&account_id)
            .and_then(|account| account.records.get(&collection))
            .map(|records| {
                ids.iter()
                    .filter_map(|id| records.get(id).cloned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(undecodable_page(&world, account_id, collection, records))
    }

    async fn share_notifications(
        &self,
        account_id: u32,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<ShareNotificationRecord>> {
        let world = lock(&self.world);
        Ok(world
            .accounts
            .get(&account_id)
            .map(|account| {
                account
                    .shares
                    .iter()
                    .filter(|(id, _)| after.is_none_or(|after| **id > after))
                    .take(limit)
                    .map(|(id, payload)| ShareNotificationRecord {
                        id: *id,
                        payload: payload.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn read_blob(&self, hash: &BlobHash) -> Result<Option<Bytes>> {
        let data = lock(&self.world).blobs.get(hash).cloned();
        if !self
            .live_blobs
            .tracking
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(data);
        }
        Ok(data.map(|data| Bytes::from_owner(TrackedBlob::new(data, self.live_blobs.clone()))))
    }

    async fn pointers(&self, account_id: u32) -> Result<AccountPointers> {
        Ok(lock(&self.world)
            .accounts
            .get(&account_id)
            .map(|account| account.pointers.clone())
            .unwrap_or_default())
    }

    async fn counters(&self, account_id: u32) -> Result<Counters> {
        let world = lock(&self.world);
        let account = world
            .accounts
            .get(&account_id)
            .ok_or_else(|| Error::account("unknown account"))?;
        let mut counters = Counters {
            change_id: account.highest_change_id(),
            ..Counters::default()
        };
        for (collection, records) in &account.records {
            if let Some(max) = records.keys().next_back() {
                counters.set_document_id(*collection, *max);
            }
        }
        let mut uids: BTreeMap<u32, u32> = BTreeMap::new();
        if let Some(emails) = account.records.get(&Collection::Email) {
            for record in emails.values() {
                if let Rec::Email(email) = record {
                    for mailbox in &email.mailboxes {
                        let entry = uids.entry(mailbox.mailbox_id).or_default();
                        *entry = (*entry).max(mailbox.uid);
                    }
                }
            }
        }
        counters.mailbox_uids = uids
            .into_iter()
            .map(|(mailbox_id, uid)| MailboxUid { mailbox_id, uid })
            .collect();
        Ok(counters)
    }

    async fn global_page(
        &self,
        category: GlobalCategory,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> Result<GlobalPage> {
        let mut world = lock(&self.world);
        match category {
            GlobalCategory::Telemetry => {
                world.span_cursors.push(cursor.map(<[u8]>::to_vec));
                let mut page = span_page(&world.spans, cursor, limit);
                if page.next.is_none() {
                    page.resume = world.span_resume.clone();
                }
                return Ok(page);
            }
            GlobalCategory::Queue => {
                world.catch_up_fails |= world.starts_on_queue_read;
                let mut page = queue_page(&world.queued, cursor, limit);
                if let GlobalBatch::Queue(messages) = &mut page.batch {
                    messages.retain(|message| {
                        let undecodable = world.undecodable_queued.contains(&message.queue_id);
                        if undecodable {
                            page.issues.push(Issue::new(
                                Severity::Error,
                                IssueKind::Skipped,
                                Subject::Registry(RegistryKey::new(
                                    model::QueuedMessageRecord::OBJECT,
                                    message.queue_id,
                                )),
                                "undecodable queued message",
                            ));
                        }
                        !undecodable
                    });
                }
                return Ok(page);
            }
            GlobalCategory::Reports => return Ok(report_page(&world.reports, cursor, limit)),
            GlobalCategory::Tasks => {}
            GlobalCategory::SpamModel => {
                return Ok(match &world.spam_blobs {
                    Some(blobs) => spam_blob_page(blobs, source_side),
                    None => GlobalPage::last(GlobalBatch::SpamModel(world.spam.clone())),
                });
            }
        }
        let start = cursor
            .and_then(|cursor| cursor.try_into().ok())
            .map_or(0, |bytes: [u8; 8]| u64::from_be_bytes(bytes) as usize);
        let tasks: Vec<model::TaskRecord> = world
            .queue
            .iter()
            .skip(start)
            .take(limit)
            .enumerate()
            .map(|(index, due)| model::TaskRecord {
                id: (start + index) as u64,
                json: world.task_json.clone().unwrap_or_else(|| match world.task_account {
                    Some(account) => serde_json::json!({
                        "@type": world.task_types.get(start + index).copied().unwrap_or("Maintenance"),
                        "due": due,
                        "accountId": account,
                    }),
                    None => serde_json::json!({
                        "@type": world.task_types.get(start + index).copied().unwrap_or("Maintenance"),
                        "due": due,
                    }),
                }),
            })
            .collect();
        let end = start + tasks.len();
        Ok(GlobalPage {
            next: (end < world.queue.len()).then(|| (end as u64).to_be_bytes().to_vec()),
            resume: None,
            batch: GlobalBatch::Tasks(tasks),
            issues: Vec::new(),
        })
    }
}

fn first_after(cursor: Option<&[u8]>) -> u64 {
    cursor
        .and_then(|cursor| <[u8; 8]>::try_from(cursor).ok())
        .map_or(0, |bytes| u64::from_be_bytes(bytes) + 1)
}

fn paged<T: Clone>(
    map: &BTreeMap<u64, T>,
    cursor: Option<&[u8]>,
    limit: usize,
) -> (Vec<(u64, T)>, Option<Vec<u8>>) {
    let items: Vec<(u64, T)> = map
        .range(first_after(cursor)..)
        .take(limit)
        .map(|(id, item)| (*id, item.clone()))
        .collect();
    let next = (items.len() == limit)
        .then(|| items.last().map(|(id, _)| id.to_be_bytes().to_vec()))
        .flatten();
    (items, next)
}

pub fn span_page(
    spans: &BTreeMap<u64, serde_json::Value>,
    cursor: Option<&[u8]>,
    limit: usize,
) -> GlobalPage {
    let (items, next) = paged(spans, cursor, limit);
    GlobalPage {
        batch: GlobalBatch::Telemetry(
            items
                .into_iter()
                .map(|(id, json)| model::TelemetryRecord {
                    kind: model::TelemetryKind::Span,
                    id,
                    json,
                })
                .collect(),
        ),
        issues: Vec::new(),
        next,
        resume: None,
    }
}

pub fn queue_page(
    queued: &BTreeMap<u64, model::QueuedMessageRecord>,
    cursor: Option<&[u8]>,
    limit: usize,
) -> GlobalPage {
    let (items, next) = paged(queued, cursor, limit);
    GlobalPage {
        batch: GlobalBatch::Queue(items.into_iter().map(|(_, record)| record).collect()),
        issues: Vec::new(),
        next,
        resume: None,
    }
}

pub type ReportMap = BTreeMap<(ReportKind, u64), InternalReportRecord>;

pub fn report_page(reports: &ReportMap, cursor: Option<&[u8]>, limit: usize) -> GlobalPage {
    let after = cursor.and_then(|cursor| {
        let (&tag, id) = cursor.split_first()?;
        let kind = if tag == 0 {
            ReportKind::Dmarc
        } else {
            ReportKind::Tls
        };
        Some((kind, u64::from_be_bytes(id.try_into().ok()?)))
    });
    let items: Vec<InternalReportRecord> = match after {
        Some(after) => reports
            .range((Bound::Excluded(after), Bound::Unbounded))
            .take(limit)
            .map(|(_, record)| record.clone())
            .collect(),
        None => reports.values().take(limit).cloned().collect(),
    };
    let next = (items.len() == limit)
        .then(|| {
            items.last().map(|record| {
                let mut cursor = vec![u8::from(record.kind == ReportKind::Tls)];
                cursor.extend_from_slice(&record.id.to_be_bytes());
                cursor
            })
        })
        .flatten();
    GlobalPage {
        batch: GlobalBatch::Reports(items),
        issues: Vec::new(),
        next,
        resume: None,
    }
}

pub fn internal_report(kind: ReportKind, id: u64, count: u64) -> InternalReportRecord {
    let report = match kind {
        ReportKind::Dmarc => serde_json::json!({"records": [{"count": count}]}),
        ReportKind::Tls => serde_json::json!({"policies": [{"totalSuccessfulSessions": count}]}),
    };
    InternalReportRecord {
        kind,
        id,
        json: serde_json::json!({"domain": "example.org", "report": report}),
    }
}

pub fn queued_message(queue_id: u64, blob: u8) -> model::QueuedMessageRecord {
    model::QueuedMessageRecord {
        queue_id,
        created: 1_000 + queue_id,
        blob_hash: BlobHash([blob; 32]),
        size: 10,
        return_path: "sender@example.org".into(),
        recipients: Vec::new(),
        received_from_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        received_via_port: 25,
        flags: 0,
        env_id: None,
        priority: 0,
        metadata: Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultOp {
    Upsert,
    Delete,
    Changelog,
    Reopen,
    Counters,
    Pointers,
    Finalize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
    TooLarge,
    Transient,
    TransientAfterCommit,
    Account,
    Fatal,
    Panic,
}

#[derive(Debug, Default)]
pub struct TargetAccount {
    pub records: BTreeMap<(Collection, u32), String>,
    pub typed: BTreeMap<(Collection, u32), Rec>,
    pub changelog: BTreeMap<(LogCollection, u64), ChangeLogRecord>,
    pub counters: Counters,
    pub pointers: AccountPointers,
    pub shares: BTreeMap<u64, Bytes>,
    pub finalized: u32,
    pub reopened: u32,
}

#[derive(Debug, Default)]
pub struct TargetWorld {
    pub schema: Option<u64>,
    pub foreign: bool,
    pub registry: BTreeMap<RegistryKey, serde_json::Value>,
    pub id_counters: BTreeMap<Box<str>, u64>,
    pub canonical: bool,
    pub accounts: BTreeMap<u32, TargetAccount>,
    pub blobs: BTreeSet<BlobHash>,
    pub blob_data: HashMap<BlobHash, Bytes>,
    pub lost_blobs: BTreeSet<BlobHash>,
    pub stored_blobs: BTreeSet<BlobHash>,
    pub blob_puts: u64,
    pub blob_puts_by_hash: BTreeMap<BlobHash, u64>,
    pub commits: BTreeMap<CommitKind, u64>,
    pub blobs_passed: BTreeSet<BlobHash>,
    pub blob_writers: BTreeMap<BlobHash, u32>,
    pub peak_blob_writers: u32,
    pub torn_blob_reads: u64,
    pub duplicates: u64,
    pub orphans: u64,
    pub dangling_scripts: u64,
    pub upserts: u64,
    pub server_started: bool,
    pub store_finalized: bool,
    pub finalize_issues: Vec<Issue>,
    pub global: u64,
    pub spans: BTreeMap<u64, serde_json::Value>,
    pub queued: BTreeMap<u64, model::QueuedMessageRecord>,
    pub reports: ReportMap,
    pub deleted_globals: Vec<GlobalKey>,
    pub tasks: BTreeMap<u64, serde_json::Value>,
    pub quota_drift: BTreeMap<u32, i64>,
    pub oversized_reports: BTreeSet<(ReportKind, u64)>,
    pub email_count_drift: BTreeMap<u32, i64>,
    pub shared: Vec<model::SharedDeletion>,
    pub spam: Vec<SpamModelRecord>,
    pub spam_blobs: Option<SpamBlobs>,
    pub claimed: bool,
    pub claim_generation: Option<model::ClaimId>,
    pub claim_interloper: Option<model::ClaimId>,
    pub claim_swap_faults: VecDeque<SwapFault>,
    pub claim_swaps: Vec<model::ClaimId>,
    pub claim_stale_read: Option<Option<model::ClaimId>>,
    pub shared_spam_store: bool,
    pub spam_write_ignored: bool,
    pub spam_write_skipped: bool,
    pub spam_final_writes: u32,
    pub spam_written_after_catch_ups: Option<u32>,
    pub unlisted: BTreeSet<RegistryKey>,
    pub telemetry_issues: Vec<Issue>,
    pub skipped_spans: BTreeSet<u64>,
    pub reader_catch_ups: u32,
    pub rejected_registry: BTreeSet<RegistryKey>,
    pub registry_too_large_above: Option<usize>,
    pub registry_reads: BTreeMap<RegistryKey, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitKind {
    Delete,
    Wipe,
    RegistryWrite,
    RegistryDelete,
    GlobalDelete,
    Reopen,
    Changelog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashPoint {
    pub kind: CommitKind,
    pub after: u64,
    pub partial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapFault {
    LostBeforeCommit,
    UnknownAfterCommit,
    UnknownAfterCommitStaleRead,
}

#[derive(Default)]
pub struct FakeTarget {
    pub world: Mutex<TargetWorld>,
    pub faults: Mutex<VecDeque<(FaultOp, Option<u32>, Fault)>>,
    pub too_large_above: Mutex<Option<usize>>,
    pub poison: Mutex<BTreeSet<u32>>,
    pub crash_after_commits: Mutex<Option<u64>>,
    pub crash_at: Mutex<Option<CrashPoint>>,
    pub put_blob_faults: Mutex<Vec<(BlobHash, Fault)>>,
    pub upsert_delays: Mutex<Vec<(u32, u32, std::time::Duration)>>,
    pub put_blob_delay: Mutex<Option<std::time::Duration>>,
    pub blobs_exist_delay: Mutex<Option<(BlobHash, std::time::Duration)>>,
    pub upsert_log: Mutex<Vec<(u32, u32)>>,
    pub write_order: Mutex<Vec<(WriteKind, Collection)>>,
    pub in_flight: std::sync::atomic::AtomicUsize,
    pub peak_in_flight: std::sync::atomic::AtomicUsize,
    pub cached_in_flight: std::sync::atomic::AtomicU64,
    pub peak_cached: std::sync::atomic::AtomicU64,
    pub shutdown_after_commits: Mutex<Option<(u64, Shutdown)>>,
    pub shutdown_on_finalize: Mutex<Option<Shutdown>>,
    pub crashed: Notify,
    pub paths: Vec<PathBuf>,
}

impl FakeTarget {
    async fn write_final_spam_model(&self, records: &[SpamModelRecord]) -> Result<WriteOutcome> {
        let mut world = lock(&self.world);
        if world.spam_write_skipped {
            return Ok(WriteOutcome {
                issues: [SPAM_CLASSIFIER, SPAM_TRAINER]
                    .into_iter()
                    .map(|object| {
                        Issue::new(
                            Severity::Warning,
                            IssueKind::Skipped,
                            Subject::Registry(RegistryKey::new(object, 0)),
                            "shared blob store, the spam model was not written",
                        )
                        .explaining(model::Explanation::Missing)
                    })
                    .collect(),
            });
        }
        world.spam_final_writes += 1;
        world.spam_written_after_catch_ups = Some(world.reader_catch_ups);
        if world.spam_write_ignored {
            return Ok(WriteOutcome::ok());
        }
        world.spam = records.to_vec();
        let issues = if world.shared_spam_store {
            vec![Issue::new(
                Severity::Info,
                IssueKind::Changed,
                Subject::Registry(RegistryKey::new(SPAM_CLASSIFIER, 0)),
                "the spam model in the shared blob store was overwritten",
            )]
        } else {
            Vec::new()
        };
        Ok(WriteOutcome { issues })
    }

    pub fn new() -> Arc<Self> {
        Arc::new(FakeTarget::default())
    }

    pub fn inject(&self, op: FaultOp, account_id: Option<u32>, fault: Fault) {
        lock(&self.faults).push_back((op, account_id, fault));
    }

    fn take_fault(&self, op: FaultOp, account_id: u32) -> Option<Fault> {
        let mut faults = lock(&self.faults);
        let position = faults.iter().position(|(fault_op, fault_account, _)| {
            *fault_op == op && fault_account.is_none_or(|fault_account| fault_account == account_id)
        })?;
        faults.remove(position).map(|(_, _, fault)| fault)
    }

    fn store_global(&self, batch: &GlobalBatch) {
        let mut world = lock(&self.world);
        world.global += batch.len() as u64;
        match batch {
            GlobalBatch::Telemetry(records) => {
                let stored: Vec<(u64, serde_json::Value)> = records
                    .iter()
                    .filter(|record| !world.skipped_spans.contains(&record.id))
                    .map(|record| (record.id, record.json.clone()))
                    .collect();
                world.spans.extend(stored);
            }
            GlobalBatch::Queue(records) => world.queued.extend(
                records
                    .iter()
                    .map(|record| (record.queue_id, record.clone())),
            ),
            GlobalBatch::Tasks(records) => world.tasks.extend(records.iter().map(|record| {
                (
                    source_v1::singleton_task_id(&record.json).unwrap_or(record.id),
                    record.json.clone(),
                )
            })),
            GlobalBatch::Reports(records) => world.reports.extend(
                records
                    .iter()
                    .map(|record| ((record.kind, record.id), record.clone())),
            ),
            GlobalBatch::SpamModel(records) => world.spam.clone_from(records),
        }
    }

    fn before_commit(&self, op: FaultOp, account_id: u32) -> Result<Option<Fault>> {
        match self.take_fault(op, account_id) {
            Some(Fault::TooLarge) => Err(Error::too_large("injected too large")),
            Some(Fault::Transient) => Err(Error::transient("injected transient error")),
            Some(Fault::Account) => Err(Error::account("injected account error")),
            Some(Fault::Fatal) => Err(Error::fatal("injected fatal error")),
            Some(Fault::Panic) => panic!("injected panic"),
            other => Ok(other),
        }
    }

    pub fn snapshot(&self) -> BTreeMap<u32, BTreeMap<(Collection, u32), String>> {
        lock(&self.world)
            .accounts
            .iter()
            .map(|(account_id, account)| (*account_id, account.records.clone()))
            .filter(|(_, records)| !records.is_empty())
            .collect()
    }

    pub fn duplicates(&self) -> u64 {
        lock(&self.world).duplicates
    }

    fn count_commit(&self, kind: CommitKind) -> Option<bool> {
        let point = *lock(&self.crash_at);
        let mut world = lock(&self.world);
        let count = world.commits.entry(kind).or_default();
        *count += 1;
        point
            .filter(|point| point.kind == kind && point.after == *count)
            .map(|point| point.partial)
    }

    fn store_registry(&self, records: &[RegistryRecord]) -> WriteOutcome {
        let mut world = lock(&self.world);
        let mut outcome = WriteOutcome::ok();
        for record in records {
            let name = record.json.get("name");
            let conflict = name.is_some()
                && world.registry.iter().any(|(key, json)| {
                    key.object == record.key.object
                        && *key != record.key
                        && json.get("name") == name
                });
            if conflict {
                outcome.issues.push(
                    Issue::new(
                        Severity::Error,
                        IssueKind::Failed,
                        Subject::Registry(record.key.clone()),
                        "name already in use",
                    )
                    .rejected(model::Rejection::Conflict),
                );
                continue;
            }
            if record.json.get("ref").and_then(|value| value.as_str()) == Some("dangling") {
                outcome.issues.push(
                    Issue::new(
                        Severity::Error,
                        IssueKind::Failed,
                        Subject::Registry(record.key.clone()),
                        "unknown reference",
                    )
                    .rejected(model::Rejection::Invalid),
                );
                continue;
            }
            if record.json.get("invalid").is_some() || world.rejected_registry.contains(&record.key)
            {
                outcome.issues.push(
                    Issue::new(
                        Severity::Error,
                        IssueKind::Failed,
                        Subject::Registry(record.key.clone()),
                        "rejected by target validation",
                    )
                    .rejected(model::Rejection::Invalid),
                );
                continue;
            }
            let mut json = record.json.clone();
            if world.canonical
                && let Some(map) = json.as_object_mut()
            {
                map.insert("createdAt".into(), 1.into());
            }
            if let Some(hash) = self.registry_blob(record) {
                world.blobs.insert(hash);
            }
            world.registry.insert(record.key.clone(), json);
        }
        outcome
    }

    fn remove_globals(&self, keys: &[GlobalKey]) {
        let mut world = lock(&self.world);
        for key in keys {
            match *key {
                GlobalKey::Queue(id) => {
                    world.queued.remove(&id);
                }
                GlobalKey::Report(kind, id) => {
                    world.reports.remove(&(kind, id));
                }
                GlobalKey::Task(id) => {
                    world.tasks.remove(&id);
                }
            }
            world.deleted_globals.push(*key);
        }
    }

    async fn park(&self) {
        self.crashed.notify_one();
        std::future::pending::<()>().await;
    }

    pub fn commits(&self, kind: CommitKind) -> u64 {
        lock(&self.world)
            .commits
            .get(&kind)
            .copied()
            .unwrap_or_default()
    }

    async fn after_commit(&self, fault: Option<Fault>) -> Result<()> {
        let commits = {
            let mut world = lock(&self.world);
            world.upserts += 1;
            world.upserts
        };
        if let Some((after, shutdown)) = lock(&self.shutdown_after_commits).as_ref()
            && commits >= *after
        {
            shutdown.request();
        }
        let crash = lock(&self.crash_after_commits).is_some_and(|after| commits == after);
        if crash {
            self.crashed.notify_one();
            std::future::pending::<()>().await;
        }
        match fault {
            Some(Fault::TransientAfterCommit) => Err(Error::transient("commit result unknown")),
            _ => Ok(()),
        }
    }
}

fn merge<T: Clone>(stored: &mut Pointer<T>, update: &Pointer<T>) {
    if let Pointer::Set(value) = update {
        *stored = Pointer::Set(value.clone());
    }
}

impl Target for FakeTarget {
    fn created_paths(&self) -> Vec<PathBuf> {
        self.paths.clone()
    }

    async fn shared_deletions(&self, account_id: u32) -> Result<Vec<model::SharedDeletion>> {
        Ok(lock(&self.world)
            .shared
            .iter()
            .map(|deletion| model::SharedDeletion {
                account_id,
                ..deletion.clone()
            })
            .collect())
    }

    async fn probe(&self) -> Result<TargetProbe> {
        let world = lock(&self.world);
        Ok(if world.foreign {
            TargetProbe::Foreign
        } else {
            match world.schema {
                Some(schema_version) => TargetProbe::Initialized { schema_version },
                None => TargetProbe::Empty,
            }
        })
    }

    async fn prepare_store(&self, _edition: model::Edition) -> Result<()> {
        let mut world = lock(&self.world);
        world.schema = Some(SCHEMA_VERSION);
        world.claimed = true;
        Ok(())
    }

    async fn holds_claim(&self) -> Result<bool> {
        Ok(lock(&self.world).claimed)
    }

    async fn claim_generation(&self) -> Result<Option<model::ClaimId>> {
        let mut world = lock(&self.world);
        Ok(world
            .claim_stale_read
            .take()
            .unwrap_or(world.claim_generation))
    }

    async fn swap_claim_generation(
        &self,
        expected: Option<model::ClaimId>,
        next: model::ClaimId,
    ) -> Result<bool> {
        let mut world = lock(&self.world);
        world.claim_swaps.push(next);
        if let Some(interloper) = world.claim_interloper.take() {
            world.claim_generation = Some(interloper);
        }
        let fault = world.claim_swap_faults.pop_front();
        if fault == Some(SwapFault::LostBeforeCommit) {
            return Err(model::Error::transient("claim swap lost"));
        }
        if world.claim_generation != expected {
            return Ok(world.claim_generation == Some(next));
        }
        world.claim_generation = Some(next);
        match fault {
            Some(SwapFault::UnknownAfterCommit) => {
                Err(model::Error::transient("claim swap unknown"))
            }
            Some(SwapFault::UnknownAfterCommitStaleRead) => {
                world.claim_stale_read = Some(expected);
                Err(model::Error::transient("claim swap unknown"))
            }
            _ => Ok(true),
        }
    }

    async fn read_registry(&self, keys: &[RegistryKey]) -> Result<Vec<Option<RegistryRecord>>> {
        let mut world = lock(&self.world);
        for key in keys {
            *world.registry_reads.entry(key.clone()).or_default() += 1;
        }
        Ok(keys
            .iter()
            .map(|key| {
                world.registry.get(key).map(|json| RegistryRecord {
                    key: key.clone(),
                    json: json.clone(),
                })
            })
            .collect())
    }

    async fn write_registry(&self, records: &[RegistryRecord]) -> Result<WriteOutcome> {
        if lock(&self.world)
            .registry_too_large_above
            .is_some_and(|limit| records.len() > limit)
        {
            return Err(Error::too_large("registry batch too large"));
        }
        let crash = self.count_commit(CommitKind::RegistryWrite);
        let records = match crash {
            Some(true) => &records[..records.len().div_ceil(2)],
            _ => records,
        };
        let outcome = self.store_registry(records);
        if crash.is_some() {
            self.park().await;
        }
        Ok(outcome)
    }

    async fn delete_registry(&self, keys: &[RegistryKey]) -> Result<()> {
        let crash = self.count_commit(CommitKind::RegistryDelete);
        let keys = match crash {
            Some(true) => &keys[..keys.len().div_ceil(2)],
            _ => keys,
        };
        {
            let mut world = lock(&self.world);
            for key in keys {
                if let Some(holder) = world
                    .registry
                    .iter()
                    .find(|(other, json)| *other != key && links_to(json, key))
                    .map(|(other, _)| other.clone())
                {
                    return Err(Error::fatal(format!(
                        "cannot delete {key}: {holder} still links to it"
                    )));
                }
                world.registry.remove(key);
            }
        }
        if crash.is_some() {
            self.park().await;
        }
        Ok(())
    }

    async fn raise_registry_counters(&self, counters: &[RegistryCounter]) -> Result<()> {
        let mut world = lock(&self.world);
        for counter in counters {
            let entry = world.id_counters.entry(counter.object.clone()).or_default();
            *entry = (*entry).max(counter.value);
        }
        Ok(())
    }

    async fn start_server(&self) -> Result<()> {
        lock(&self.world).server_started = true;
        Ok(())
    }

    async fn write_pointers(
        &self,
        account_id: u32,
        pointers: &AccountPointers,
    ) -> Result<WriteOutcome> {
        self.before_commit(FaultOp::Pointers, account_id)?;
        let mut world = lock(&self.world);
        let mut dangling = 0;
        let account = world.accounts.entry(account_id).or_default();
        if let Pointer::Set(Some(script)) = pointers.active_script
            && !account
                .records
                .contains_key(&(Collection::SieveScript, script))
        {
            dangling += 1;
        }
        let stored = &mut account.pointers;
        merge(&mut stored.active_script, &pointers.active_script);
        merge(&mut stored.default_calendar, &pointers.default_calendar);
        merge(
            &mut stored.default_address_book,
            &pointers.default_address_book,
        );
        merge(
            &mut stored.identity_addresses_hash,
            &pointers.identity_addresses_hash,
        );
        merge(
            &mut stored.participant_identities,
            &pointers.participant_identities,
        );
        merge(&mut stored.push_subscriptions, &pointers.push_subscriptions);
        world.dangling_scripts += dangling;
        Ok(WriteOutcome::ok())
    }

    async fn upsert_with_blobs(
        &self,
        account_id: u32,
        batch: &RecordBatch,
        mode: WriteMode,
        blobs: &model::BlobCache,
    ) -> Result<WriteOutcome> {
        {
            let mut referenced = Vec::new();
            batch.collect_blobs(&mut referenced);
            let mut world = lock(&self.world);
            let slow_puts = lock(&self.put_blob_delay).is_some();
            for (hash, _) in referenced {
                if slow_puts
                    && blobs.get(&hash).is_none()
                    && (world.blob_writers.contains_key(&hash) || !world.blobs.contains(&hash))
                {
                    world.torn_blob_reads += 1;
                }
                if let Some(data) = blobs.get(&hash) {
                    assert_eq!(
                        world.blob_data.get(&hash),
                        Some(data),
                        "passed bytes differ"
                    );
                    world.blobs_passed.insert(hash);
                }
            }
        }
        let cached = self
            .cached_in_flight
            .fetch_add(blobs.bytes(), std::sync::atomic::Ordering::SeqCst)
            + blobs.bytes();
        self.peak_cached
            .fetch_max(cached, std::sync::atomic::Ordering::SeqCst);
        let _cached = OnDrop(|| {
            self.cached_in_flight
                .fetch_sub(blobs.bytes(), std::sync::atomic::Ordering::SeqCst);
        });
        self.upsert(account_id, batch, mode).await
    }

    async fn upsert(
        &self,
        account_id: u32,
        batch: &RecordBatch,
        mode: WriteMode,
    ) -> Result<WriteOutcome> {
        let fault = self.before_commit(FaultOp::Upsert, account_id)?;
        lock(&self.write_order).push((WriteKind::Upsert, batch.collection()));
        let first = batch.first_id().unwrap_or_default();
        let delay = lock(&self.upsert_delays)
            .iter()
            .find(|(account, id, _)| *account == account_id && *id == first)
            .map(|(_, _, delay)| *delay);
        let now = self
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.peak_in_flight
            .fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        let in_flight = OnDrop(|| {
            self.in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        } else {
            tokio::task::yield_now().await;
        }
        drop(in_flight);
        lock(&self.upsert_log).push((account_id, first));
        if lock(&self.too_large_above).is_some_and(|limit| batch.len() > limit) {
            return Err(Error::too_large("transaction too large"));
        }
        let mut ids = Vec::new();
        batch.collect_ids(&mut ids);
        {
            let poison = lock(&self.poison);
            if ids.iter().any(|id| poison.contains(id)) {
                return Err(Error::too_large("object too large"));
            }
        }
        let mut issues = Vec::new();
        {
            let mut world = lock(&self.world);
            let mut duplicates = 0;
            let mut orphans = 0;
            let account = world.accounts.entry(account_id).or_default();
            for mut record in records_of(batch) {
                if let Rec::CalendarEvent(event) = &mut record
                    && !event.dead_properties.is_empty()
                {
                    event.dead_properties = Default::default();
                    issues.push(
                        Issue::new(
                            Severity::Warning,
                            IssueKind::Dropped,
                            Subject::Document {
                                collection: Collection::CalendarEvent,
                                document_id: event.document_id,
                            },
                            "dead properties dropped",
                        )
                        .explaining(model::Explanation::DeadProperties),
                    );
                }
                let key = (record.collection(), record.id());
                if let Rec::FileNode(node) = &record
                    && let Some(parent) = node.parent_id
                    && !account
                        .records
                        .contains_key(&(Collection::FileNode, parent))
                {
                    orphans += 1;
                }
                if mode == WriteMode::Create && account.records.contains_key(&key) {
                    duplicates += 1;
                }
                account.records.insert(key, format!("{record:?}"));
                account.typed.insert(key, record);
            }
            world.duplicates += duplicates;
            world.orphans += orphans;
        }
        self.after_commit(fault).await?;
        Ok(WriteOutcome { issues })
    }

    async fn delete(&self, account_id: u32, collection: Collection, ids: &[u32]) -> Result<()> {
        self.before_commit(FaultOp::Delete, account_id)?;
        lock(&self.write_order).push((WriteKind::Delete, collection));
        let crash = self.count_commit(CommitKind::Delete);
        let ids = match crash {
            Some(true) => &ids[..ids.len().div_ceil(2)],
            _ => ids,
        };
        if let Some(account) = lock(&self.world).accounts.get_mut(&account_id) {
            for id in ids {
                account.records.remove(&(collection, *id));
                account.typed.remove(&(collection, *id));
            }
        }
        if crash.is_some() {
            self.park().await;
        }
        Ok(())
    }

    async fn exists(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> Result<RoaringBitmap> {
        let world = lock(&self.world);
        let mut existing = RoaringBitmap::new();
        if let Some(account) = world.accounts.get(&account_id) {
            for id in ids {
                if account.records.contains_key(&(collection, *id)) {
                    existing.insert(*id);
                }
            }
        }
        Ok(existing)
    }

    async fn wipe_account(&self, account_id: u32) -> Result<()> {
        let crash = self.count_commit(CommitKind::Wipe);
        {
            let mut world = lock(&self.world);
            match crash {
                Some(true) => {
                    if let Some(account) = world.accounts.get_mut(&account_id) {
                        let half = account.records.len().div_ceil(2);
                        let wiped: Vec<(Collection, u32)> =
                            account.records.keys().take(half).copied().collect();
                        for key in wiped {
                            account.records.remove(&key);
                            account.typed.remove(&key);
                        }
                    }
                }
                _ => {
                    world.accounts.remove(&account_id);
                }
            }
        }
        if crash.is_some() {
            self.park().await;
        }
        Ok(())
    }

    async fn write_changelog(&self, account_id: u32, rows: &[ChangeLogRecord]) -> Result<()> {
        self.before_commit(FaultOp::Changelog, account_id)?;
        let crash = self.count_commit(CommitKind::Changelog);
        let rows = match crash {
            Some(true) => &rows[..rows.len().div_ceil(2)],
            _ => rows,
        };
        {
            let mut world = lock(&self.world);
            let account = world.accounts.entry(account_id).or_default();
            for row in rows {
                account
                    .changelog
                    .insert((row.collection, row.change_id), row.clone());
            }
        }
        if crash.is_some() {
            self.park().await;
        }
        Ok(())
    }

    async fn write_share_notifications(
        &self,
        account_id: u32,
        records: &[ShareNotificationRecord],
    ) -> Result<()> {
        let mut world = lock(&self.world);
        let account = world.accounts.entry(account_id).or_default();
        account.shares.extend(
            records
                .iter()
                .map(|record| (record.id, record.payload.clone())),
        );
        Ok(())
    }

    async fn retain_share_notifications(&self, account_id: u32, keep: &[u64]) -> Result<()> {
        if let Some(account) = lock(&self.world).accounts.get_mut(&account_id) {
            account
                .shares
                .retain(|id, _| keep.binary_search(id).is_ok());
        }
        Ok(())
    }

    async fn raise_counters(&self, account_id: u32, counters: &Counters) -> Result<()> {
        self.before_commit(FaultOp::Counters, account_id)?;
        let mut world = lock(&self.world);
        let account = world.accounts.entry(account_id).or_default();
        account.counters.change_id = account.counters.change_id.max(counters.change_id);
        for collection in Collection::ALL {
            if let Some(value) = counters.document_id(collection) {
                let current = account.counters.document_id(collection).unwrap_or(0);
                account
                    .counters
                    .set_document_id(collection, current.max(value));
            }
        }
        account.counters.mailbox_uids = counters.mailbox_uids.clone();
        Ok(())
    }

    async fn blobs_exist(&self, hashes: &[BlobHash]) -> Result<Vec<bool>> {
        let delay = *lock(&self.blobs_exist_delay);
        if let Some((_, delay)) = delay.filter(|(slow, _)| hashes.contains(slow)) {
            tokio::time::sleep(delay).await;
        }
        let world = lock(&self.world);
        Ok(hashes
            .iter()
            .map(|hash| world.blobs.contains(hash))
            .collect())
    }

    async fn stored_blobs_exist(&self, hashes: &[BlobHash]) -> Result<Vec<bool>> {
        let world = lock(&self.world);
        Ok(hashes
            .iter()
            .map(|hash| world.stored_blobs.contains(hash))
            .collect())
    }

    fn registry_blob(&self, record: &RegistryRecord) -> Option<BlobHash> {
        record
            .json
            .get("blob")
            .and_then(serde_json::Value::as_u64)
            .and_then(|byte| u8::try_from(byte).ok())
            .map(|byte| BlobHash([byte; 32]))
    }

    async fn put_blob(&self, hash: &BlobHash, data: Bytes) -> Result<()> {
        let fault = {
            let mut faults = lock(&self.put_blob_faults);
            faults
                .iter()
                .position(|(faulty, _)| faulty == hash)
                .map(|position| faults.remove(position).1)
        };
        match fault {
            Some(Fault::Account) => return Err(Error::account("injected blob write error")),
            Some(Fault::Transient) => return Err(Error::transient("injected blob write error")),
            Some(Fault::Fatal) => return Err(Error::fatal("injected blob write error")),
            _ => {}
        }
        let delay = *lock(&self.put_blob_delay);
        if let Some(delay) = delay {
            {
                let mut world = lock(&self.world);
                let writers = world.blob_writers.entry(*hash).or_default();
                *writers += 1;
                let writers = *writers;
                world.peak_blob_writers = world.peak_blob_writers.max(writers);
            }
            tokio::time::sleep(delay).await;
            let mut world = lock(&self.world);
            if let Some(writers) = world.blob_writers.get_mut(hash) {
                *writers -= 1;
                if *writers == 0 {
                    world.blob_writers.remove(hash);
                }
            }
        }
        let mut world = lock(&self.world);
        if !world.server_started {
            return Err(Error::fatal("the server stage has not been started"));
        }
        world.blobs.insert(*hash);
        world.blob_data.insert(*hash, Bytes::copy_from_slice(&data));
        world.blob_puts += 1;
        *world.blob_puts_by_hash.entry(*hash).or_default() += 1;
        Ok(())
    }

    async fn write_global(&self, batch: &GlobalBatch) -> Result<WriteOutcome> {
        if matches!(batch, GlobalBatch::SpamModel(_)) {
            return Err(Error::fatal(
                "the spam model is written only by write_final_spam_model",
            ));
        }
        if let GlobalBatch::Reports(records) = batch {
            let oversized = lock(&self.world).oversized_reports.clone();
            if !oversized.is_empty() {
                let (refused, kept): (Vec<_>, Vec<_>) = records
                    .iter()
                    .cloned()
                    .partition(|record| oversized.contains(&(record.kind, record.id)));
                self.store_global(&GlobalBatch::Reports(kept));
                return Ok(WriteOutcome {
                    issues: refused
                        .into_iter()
                        .map(|record| {
                            Issue::new(
                                Severity::Warning,
                                IssueKind::Skipped,
                                Subject::Registry(RegistryKey::new(record.kind.as_str(), record.id)),
                                "a report row exceeds the v1 row size limit; the report was not copied",
                            )
                            .explaining(model::Explanation::Missing)
                        })
                        .collect(),
                });
            }
        }
        self.store_global(batch);
        if matches!(batch, GlobalBatch::Queue(_) | GlobalBatch::Tasks(_)) {
            self.after_commit(None).await?;
        }
        if let GlobalBatch::Telemetry(records) = batch {
            let mut world = lock(&self.world);
            let mut issues = std::mem::take(&mut world.telemetry_issues);
            issues.extend(
                records
                    .iter()
                    .filter(|record| world.skipped_spans.contains(&record.id))
                    .map(|record| {
                        Issue::new(
                            Severity::Warning,
                            IssueKind::Skipped,
                            Subject::Registry(RegistryKey::new(record.kind.as_str(), record.id)),
                            "the telemetry store is disabled; the record was not copied",
                        )
                        .explaining(model::Explanation::Missing)
                    }),
            );
            return Ok(WriteOutcome { issues });
        }
        Ok(WriteOutcome::ok())
    }

    async fn apply_final_spam_model(&self, changes: &[SpamModelChange]) -> Result<WriteOutcome> {
        if lock(&self.world).spam_write_skipped || lock(&self.world).spam_write_ignored {
            let records: Vec<SpamModelRecord> = lock(&self.world)
                .spam
                .iter()
                .filter(|record| changes.iter().all(|change| change.kind() != record.kind()))
                .cloned()
                .chain(changes.iter().filter_map(|change| match change {
                    SpamModelChange::Write(record) => Some(record.clone()),
                    SpamModelChange::Delete(_) => None,
                }))
                .collect();
            return self.write_final_spam_model(&records).await;
        }
        let mut world = lock(&self.world);
        world.spam_final_writes += 1;
        world.spam_written_after_catch_ups = Some(world.reader_catch_ups);
        match world.spam_blobs.clone() {
            Some(blobs) => {
                let mut blobs = lock(&blobs);
                for change in changes {
                    match change {
                        SpamModelChange::Write(record) => {
                            blobs.insert(record.kind(), FakeSpamBlob::Target(record.clone()));
                        }
                        SpamModelChange::Delete(kind) => {
                            blobs.remove(kind);
                        }
                    }
                }
            }
            None => {
                for change in changes {
                    world.spam.retain(|record| record.kind() != change.kind());
                    if let SpamModelChange::Write(record) = change {
                        world.spam.push(record.clone());
                    }
                }
            }
        }
        let issues = if world.shared_spam_store {
            vec![Issue::new(
                Severity::Info,
                IssueKind::Changed,
                Subject::Registry(RegistryKey::new(SPAM_CLASSIFIER, 0)),
                "the spam model in the shared blob store was overwritten",
            )]
        } else {
            Vec::new()
        };
        Ok(WriteOutcome { issues })
    }

    async fn delete_global(&self, keys: &[GlobalKey]) -> Result<WriteOutcome> {
        let crash = self.count_commit(CommitKind::GlobalDelete);
        let keys = match crash {
            Some(true) => &keys[..keys.len().div_ceil(2)],
            _ => keys,
        };
        self.remove_globals(keys);
        if crash.is_some() {
            self.park().await;
        }
        Ok(WriteOutcome::ok())
    }

    async fn finalize_account(&self, account_id: u32, counters: &Counters) -> Result<WriteOutcome> {
        self.before_commit(FaultOp::Finalize, account_id)?;
        let mut world = lock(&self.world);
        let account = world.accounts.entry(account_id).or_default();
        account.finalized += 1;
        for log in DAV_LOGS {
            let items: Vec<u64> = account
                .records
                .keys()
                .filter(|(collection, _)| {
                    log_collection(*collection).is_some_and(|(collection, _)| collection == log)
                })
                .map(|(_, id)| u64::from(*id))
                .collect();
            if items.is_empty() {
                continue;
            }
            let last = account
                .changelog
                .range((log, 0)..=(log, u64::MAX))
                .next_back()
                .map_or(0, |((_, change_id), _)| *change_id);
            let change_id = last.max(counters.change_id) + 1;
            account.changelog.insert(
                (log, change_id),
                ChangeLogRecord {
                    collection: log,
                    change_id,
                    entry: LogEntry::Changes(LogChanges {
                        updated_items: items,
                        ..LogChanges::default()
                    }),
                },
            );
        }
        Ok(WriteOutcome::ok())
    }

    async fn reopen_account(&self, account_id: u32, copied: &[(LogCollection, u64)]) -> Result<()> {
        self.before_commit(FaultOp::Reopen, account_id)?;
        let crash = self.count_commit(CommitKind::Reopen);
        let logs = match crash {
            Some(true) => &DAV_LOGS[..DAV_LOGS.len() / 2],
            _ => &DAV_LOGS[..],
        };
        {
            let mut world = lock(&self.world);
            let Some(account) = world.accounts.get_mut(&account_id) else {
                return Ok(());
            };
            account.reopened += 1;
            for log in logs {
                let after = copied
                    .iter()
                    .find(|(copied, _)| copied == log)
                    .map_or(0, |(_, change_id)| *change_id);
                account
                    .changelog
                    .retain(|(collection, change_id), _| collection != log || *change_id <= after);
            }
        }
        if crash.is_some() {
            self.park().await;
        }
        Ok(())
    }

    async fn finalize_store(&self, _categories: CategorySet) -> Result<WriteOutcome> {
        if let Some(shutdown) = lock(&self.shutdown_on_finalize).as_ref() {
            shutdown.request();
        }
        let mut world = lock(&self.world);
        world.store_finalized = true;
        Ok(WriteOutcome {
            issues: std::mem::take(&mut world.finalize_issues),
        })
    }
}

pub struct FakeReader {
    pub target: Arc<FakeTarget>,
    pub shared_blobs: Option<Arc<FakeSource>>,
}

impl FakeReader {
    pub fn new(target: &Arc<FakeTarget>, source: &Arc<FakeSource>) -> Arc<Self> {
        Arc::new(FakeReader {
            target: target.clone(),
            shared_blobs: Some(source.clone()),
        })
    }
}

impl Source for FakeReader {
    async fn catch_up(&self) -> Result<()> {
        lock(&self.target.world).reader_catch_ups += 1;
        Ok(())
    }

    fn canonical_registry(&self, mut record: RegistryRecord) -> Result<RegistryRecord> {
        if bare(&record.key.object) == model::TaskRecord::OBJECT
            && let Some(id) = source_v1::singleton_task_id(&record.json)
        {
            record.key.id = RegistryId::Id(id);
        }
        Ok(record)
    }

    fn registry_blob(&self, record: &RegistryRecord) -> Option<BlobHash> {
        self.target.registry_blob(record)
    }

    async fn registry_types(&self) -> Result<Vec<Box<str>>> {
        let world = lock(&self.target.world);
        let mut types: Vec<Box<str>> = world
            .registry
            .keys()
            .map(|key| key.object.clone())
            .collect();
        types.dedup();
        Ok(types)
    }

    async fn unlisted_registry(&self, records: &[RegistryRecord]) -> Result<Vec<RegistryKey>> {
        let world = lock(&self.target.world);
        Ok(records
            .iter()
            .filter(|record| world.unlisted.contains(&record.key))
            .map(|record| record.key.clone())
            .collect())
    }

    async fn registry_page(
        &self,
        object: &str,
        after: Option<u64>,
        limit: usize,
    ) -> Result<RegistryEntries> {
        let world = lock(&self.target.world);
        Ok(RegistryEntries {
            records: world
                .registry
                .iter()
                .filter(|(key, _)| {
                    &*key.object == object
                        && after.is_none_or(|after| key.id.id().is_some_and(|id| id > after))
                })
                .take(limit)
                .map(|(key, json)| RegistryRecord {
                    key: key.clone(),
                    json: json.clone(),
                })
                .collect(),
            unreadable: Vec::new(),
        })
    }

    async fn registry_id_counters(&self) -> Result<Vec<RegistryCounter>> {
        Ok(lock(&self.target.world)
            .id_counters
            .iter()
            .map(|(object, value)| RegistryCounter {
                object: object.clone(),
                value: *value,
            })
            .collect())
    }

    async fn accounts(&self) -> Result<Vec<AccountRef>> {
        Ok(lock(&self.target.world)
            .accounts
            .iter()
            .filter(|(_, account)| !account.typed.is_empty())
            .map(|(account_id, account)| AccountRef {
                account_id: *account_id,
                change_counter: account.counters.change_id,
            })
            .collect())
    }

    async fn changes(&self, _: u32, _: Collection, _: u64) -> Result<Changes> {
        Ok(Changes::Delta(ChangeSet::default()))
    }

    async fn changelog(
        &self,
        account_id: u32,
        collection: LogCollection,
        range: LogRange,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let world = lock(&self.target.world);
        Ok(world
            .accounts
            .get(&account_id)
            .map(|account| {
                account
                    .changelog
                    .range((collection, range.after + 1)..=(collection, range.up_to))
                    .take(limit)
                    .map(|(_, row)| row.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn scan(
        &self,
        account_id: u32,
        collection: Collection,
        after: Option<u32>,
        limit: usize,
    ) -> Result<RecordPage> {
        let world = lock(&self.target.world);
        let first = after.map_or(0, |after| after.saturating_add(1));
        let records = world
            .accounts
            .get(&account_id)
            .filter(|_| after != Some(u32::MAX))
            .map(|account| {
                account
                    .typed
                    .range((collection, first)..=(collection, u32::MAX))
                    .take(limit)
                    .map(|(_, record)| record.clone())
                    .collect()
            })
            .unwrap_or_default();
        Ok(RecordPage::new(batch_of(collection, records)))
    }

    async fn read(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> Result<RecordPage> {
        let world = lock(&self.target.world);
        let records = world
            .accounts
            .get(&account_id)
            .map(|account| {
                ids.iter()
                    .filter_map(|id| account.typed.get(&(collection, *id)).cloned())
                    .collect()
            })
            .unwrap_or_default();
        Ok(RecordPage::new(batch_of(collection, records)))
    }

    async fn share_notifications(
        &self,
        account_id: u32,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<ShareNotificationRecord>> {
        Ok(lock(&self.target.world)
            .accounts
            .get(&account_id)
            .map(|account| {
                account
                    .shares
                    .iter()
                    .filter(|(id, _)| after.is_none_or(|after| **id > after))
                    .take(limit)
                    .map(|(id, payload)| ShareNotificationRecord {
                        id: *id,
                        payload: payload.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn blobs_exist(&self, hashes: &[BlobHash]) -> Result<Vec<bool>> {
        let world = lock(&self.target.world);
        Ok(hashes
            .iter()
            .map(|hash| !world.lost_blobs.contains(hash))
            .collect())
    }

    async fn read_blob(&self, hash: &BlobHash) -> Result<Option<Bytes>> {
        if let Some(data) = lock(&self.target.world).blob_data.get(hash) {
            return Ok(Some(data.clone()));
        }
        match &self.shared_blobs {
            Some(source) => Ok(lock(&source.world).blobs.get(hash).cloned()),
            None => Ok(None),
        }
    }

    async fn pointers(&self, account_id: u32) -> Result<AccountPointers> {
        Ok(lock(&self.target.world)
            .accounts
            .get(&account_id)
            .map(|account| account.pointers.clone())
            .unwrap_or_default())
    }

    async fn quota_usage(&self, account_id: u32) -> Result<Option<model::QuotaUsage>> {
        const COMPUTED: i64 = 4096;
        let world = lock(&self.target.world);
        Ok(world
            .accounts
            .contains_key(&account_id)
            .then(|| model::QuotaUsage {
                stored: COMPUTED + world.quota_drift.get(&account_id).copied().unwrap_or(0),
                computed: COMPUTED,
                objects: [
                    "emails",
                    "email submissions",
                    "calendar events",
                    "notifications",
                ]
                .map(|name| model::ObjectCountUsage {
                    name,
                    stored: 1 + match name {
                        "emails" => world
                            .email_count_drift
                            .get(&account_id)
                            .copied()
                            .unwrap_or(0),
                        _ => 0,
                    },
                    computed: 1,
                }),
            }))
    }

    async fn counters(&self, account_id: u32) -> Result<Counters> {
        Ok(lock(&self.target.world)
            .accounts
            .get(&account_id)
            .map(|account| account.counters.clone())
            .unwrap_or_default())
    }

    async fn global_page(
        &self,
        category: GlobalCategory,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> Result<GlobalPage> {
        let world = lock(&self.target.world);
        Ok(match category {
            GlobalCategory::Telemetry => span_page(&world.spans, cursor, limit),
            GlobalCategory::Queue => queue_page(&world.queued, cursor, limit),
            GlobalCategory::Reports => report_page(&world.reports, cursor, limit),
            GlobalCategory::SpamModel => match &world.spam_blobs {
                Some(blobs) => spam_blob_page(blobs, target_side),
                None => GlobalPage::last(GlobalBatch::SpamModel(world.spam.clone())),
            },
            GlobalCategory::Tasks => task_page(&world.tasks, cursor, limit),
        })
    }
}

fn task_page(
    tasks: &BTreeMap<u64, serde_json::Value>,
    cursor: Option<&[u8]>,
    limit: usize,
) -> GlobalPage {
    let start = cursor
        .and_then(|cursor| cursor.try_into().ok())
        .map_or(0, |bytes: [u8; 8]| {
            u64::from_be_bytes(bytes).saturating_add(1)
        });
    let records: Vec<model::TaskRecord> = tasks
        .range(start..)
        .take(limit.max(1))
        .map(|(id, json)| model::TaskRecord {
            id: *id,
            json: json.clone(),
        })
        .collect();
    let next = records
        .last()
        .filter(|last| tasks.range(last.id + 1..).next().is_some())
        .map(|last| last.id.to_be_bytes().to_vec());
    GlobalPage {
        next,
        resume: None,
        batch: GlobalBatch::Tasks(records),
        issues: Vec::new(),
    }
}

pub struct FakeConverter;

pub struct PrefixedConverter;

const TARGET_PREFIX: &str = "x:";
pub const UNLINKED_OBJECT: &str = "Setting";

const REFERENCE_FIELDS: [(&str, &str); 3] = [
    ("domainId", "Domain"),
    ("memberTenantId", "Tenant"),
    ("accountId", "Account"),
];

fn bare(object: &str) -> &str {
    object.strip_prefix(TARGET_PREFIX).unwrap_or(object)
}

fn prefixed(object: &str) -> Box<str> {
    if object.starts_with(TARGET_PREFIX) {
        object.into()
    } else {
        format!("{TARGET_PREFIX}{object}").into()
    }
}

fn prefix_key(key: &mut RegistryKey) {
    key.object = prefixed(&key.object);
}

fn fake_references(json: &serde_json::Value) -> impl Iterator<Item = (&'static str, u64)> + '_ {
    REFERENCE_FIELDS
        .into_iter()
        .filter_map(|(field, object)| Some((object, JmapId::parse(json.get(field)?.as_str()?)?.0)))
}

fn links_to(json: &serde_json::Value, key: &RegistryKey) -> bool {
    fake_references(json)
        .any(|(object, id)| object == bare(&key.object) && key.id == RegistryId::Id(id))
}

fn reference_order(mut remaining: Vec<RegistryRecord>) -> RegistryDeletes {
    remaining.sort_by(|left, right| left.key.cmp(&right.key));
    let mut order = Vec::with_capacity(remaining.len());
    let mut updates = Vec::new();
    while !remaining.is_empty() {
        let free = remaining.iter().position(|candidate| {
            !remaining
                .iter()
                .any(|other| other.key != candidate.key && links_to(&other.json, &candidate.key))
        });
        match free {
            Some(free) => order.push(remaining.remove(free).key),
            None => {
                let linking = remaining
                    .iter()
                    .position(|candidate| {
                        remaining.iter().any(|other| {
                            other.key != candidate.key && links_to(&candidate.json, &other.key)
                        })
                    })
                    .unwrap_or(0);
                let candidate = &mut remaining[linking];
                let mut properties = serde_json::Map::new();
                if let Some(map) = candidate.json.as_object_mut() {
                    for (field, _) in REFERENCE_FIELDS {
                        if map.remove(field).is_some() {
                            properties.insert(field.into(), serde_json::Value::Null);
                        }
                    }
                }
                updates.push(RegistryPatch {
                    key: candidate.key.clone(),
                    properties,
                });
            }
        }
    }
    RegistryDeletes { updates, order }
}

impl RegistryConverter for PrefixedConverter {
    fn category(&self, object: &str) -> Category {
        FakeConverter.category(bare(object))
    }

    fn convert(
        &self,
        objects: Vec<RegistryRecord>,
        categories: CategorySet,
    ) -> std::result::Result<Converted, ConversionError> {
        let mut converted = FakeConverter.convert(objects, categories)?;
        for record in &mut converted.records {
            prefix_key(&mut record.record.key);
        }
        for record in converted
            .deferred
            .iter_mut()
            .chain(converted.fallbacks.iter_mut())
        {
            prefix_key(&mut record.key);
        }
        Ok(converted)
    }

    fn delete_plan(&self, records: Vec<RegistryRecord>) -> RegistryDeletes {
        reference_order(records)
    }

    fn unlinked_objects(&self, keys: &[RegistryKey]) -> FxHashSet<Box<str>> {
        FakeConverter.unlinked_objects(keys)
    }

    fn references(&self, side: RecordSide, record: &RegistryRecord) -> Vec<RegistryKey> {
        fake_references(&record.json)
            .map(|(object, id)| match side {
                RecordSide::Source => RegistryKey::new(object, id),
                RecordSide::Target => RegistryKey::new(prefixed(object), id),
            })
            .collect()
    }

    fn target_object(&self, object: &str) -> Box<str> {
        prefixed(&FakeConverter.target_object(object))
    }

    fn stored_task_id(&self, task: &model::TaskRecord) -> u64 {
        FakeConverter.stored_task_id(task)
    }
}

pub static MAX_TASKS_PER_CONVERSION: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
pub static MAX_REGISTRY_WITH_TASKS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn rank(object: &str) -> u8 {
    match object {
        "Domain" => 0,
        "Account" => 1,
        _ => 2,
    }
}

impl RegistryConverter for FakeConverter {
    fn category(&self, object: &str) -> Category {
        match object {
            "Account" | "Domain" => Category::Principals,
            "SpamTrainingSample" => Category::SpamSamples,
            "Task" => Category::Tasks,
            _ => Category::Settings,
        }
    }

    fn convert(
        &self,
        mut objects: Vec<RegistryRecord>,
        categories: CategorySet,
    ) -> std::result::Result<Converted, ConversionError> {
        objects.retain(|record| categories.contains(self.category(&record.key.object)));
        let tasks = objects
            .iter()
            .filter(|record| &*record.key.object == "Task")
            .count();
        MAX_TASKS_PER_CONVERSION.fetch_max(tasks, std::sync::atomic::Ordering::Relaxed);
        if tasks > 0 {
            MAX_REGISTRY_WITH_TASKS
                .fetch_max(objects.len() - tasks, std::sync::atomic::Ordering::Relaxed);
        }
        objects.sort_by_key(|record| (rank(&record.key.object), record.key.clone()));
        let mut converted = Converted::default();
        for record in objects {
            if &*record.key.object == "SpamLlm" {
                converted.issues.push(Issue::new(
                    Severity::Warning,
                    IssueKind::Dropped,
                    Subject::Registry(record.key.clone()),
                    "no v1 equivalent",
                ));
                converted.dropped.push(record.key);
                continue;
            }
            let task_type = record.json.get("@type").and_then(|value| value.as_str());
            if (&*record.key.object == "Task" && task_type == Some("Obsolete"))
                || record.json.get("unconvertible").is_some()
            {
                converted.dropped.push(record.key);
                continue;
            }
            let linked = &*record.key.object == "Task" && task_type == Some("Linked");
            let mut json = record.json;
            if let Some(map) = json.as_object_mut() {
                map.insert("v1".into(), true.into());
            }
            if linked {
                let mut full = json.clone();
                if let Some(map) = full.as_object_mut() {
                    map.insert("link".into(), true.into());
                }
                converted.deferred.push(RegistryRecord {
                    key: record.key.clone(),
                    json: full,
                });
            }
            if json.get("fallback").is_some() {
                let mut fallback = json.clone();
                if let Some(map) = fallback.as_object_mut() {
                    map.remove("fallback");
                    map.remove("invalid");
                }
                converted.fallbacks.push(RegistryRecord {
                    key: record.key.clone(),
                    json: fallback,
                });
            }
            if &*record.key.object == "Cyclic" {
                converted.deferred.push(RegistryRecord {
                    key: record.key.clone(),
                    json: json.clone(),
                });
                if let Some(map) = json.as_object_mut() {
                    map.remove("ref");
                }
            }
            let key = if &*record.key.object == "Legacy" {
                RegistryKey {
                    object: "Renamed".into(),
                    id: record.key.id,
                }
            } else {
                record.key.clone()
            };
            converted.records.push(ConvertedRecord {
                source: record.key,
                record: RegistryRecord { key, json },
            });
        }
        Ok(converted)
    }

    fn delete_plan(&self, records: Vec<RegistryRecord>) -> RegistryDeletes {
        reference_order(records)
    }

    fn unlinked_objects(&self, keys: &[RegistryKey]) -> FxHashSet<Box<str>> {
        keys.iter()
            .filter(|key| bare(&key.object) == UNLINKED_OBJECT)
            .map(|key| key.object.clone())
            .collect()
    }

    fn references(&self, _side: RecordSide, record: &RegistryRecord) -> Vec<RegistryKey> {
        fake_references(&record.json)
            .map(|(object, id)| RegistryKey::new(object, id))
            .collect()
    }

    fn target_object(&self, object: &str) -> Box<str> {
        match object {
            "SpamLlm" => "x:SpamLlm".into(),
            object => object.into(),
        }
    }

    fn stored_task_id(&self, task: &model::TaskRecord) -> u64 {
        source_v1::singleton_task_id(&task.json).unwrap_or(task.id)
    }
}

pub fn mailbox(id: u32, name: &str) -> Rec {
    Rec::Mailbox(MailboxRecord {
        document_id: id,
        name: name.into(),
        uid_validity: 1000 + id,
        ..Default::default()
    })
}

pub fn email(id: u32, mailbox_id: u32, uid: u32, keywords: &[&str]) -> Rec {
    Rec::Email(EmailRecord {
        document_id: id,
        thread_id: id,
        change_id: u64::from(id),
        received_at: 1_700_000_000 + u64::from(id),
        keywords: keywords.iter().map(|keyword| Box::from(*keyword)).collect(),
        mailboxes: vec![MailboxUid { mailbox_id, uid }],
        blob_hash: BlobHash([u8::try_from(id % 7).unwrap_or(0); 32]),
        size: 100 + id,
        ..Default::default()
    })
}

pub fn identity(id: u32, email: &str) -> Rec {
    Rec::Identity(IdentityRecord {
        document_id: id,
        name: format!("Identity {id}"),
        email: email.into(),
        ..Default::default()
    })
}

pub fn sieve(id: u32, name: &str) -> Rec {
    Rec::Sieve(SieveRecord {
        document_id: id,
        name: name.into(),
        blob_hash: BlobHash([200; 32]),
        size: 10,
        vacation: None,
    })
}

pub fn directory(id: u32, parent: Option<u32>) -> Rec {
    Rec::FileNode(FileNodeRecord {
        document_id: id,
        parent_id: parent,
        name: format!("dir{id}"),
        ..Default::default()
    })
}

pub fn file(id: u32, parent: Option<u32>) -> Rec {
    Rec::FileNode(FileNodeRecord {
        document_id: id,
        parent_id: parent,
        name: format!("file{id}"),
        file: Some(FileRecord {
            blob_hash: BlobHash([201; 32]),
            size: 5,
            media_type: None,
            executable: false,
        }),
        ..Default::default()
    })
}

pub fn calendar(id: u32, name: &str) -> Rec {
    Rec::Calendar(CalendarRecord {
        document_id: id,
        name: name.into(),
        created: 1_700_000_000,
        ..Default::default()
    })
}

pub fn event(id: u32, calendar: u32, summary: &str) -> Rec {
    Rec::CalendarEvent(CalendarEventRecord {
        document_id: id,
        names: vec![model::DavNameRecord {
            name: format!("event{id}.ics"),
            parent_id: calendar,
        }],
        icalendar: format!("BEGIN:VCALENDAR\r\nSUMMARY:{summary}\r\nEND:VCALENDAR\r\n"),
        size: 40,
        ..Default::default()
    })
}

pub fn lossy_event(id: u32, calendar: u32) -> Rec {
    let Rec::CalendarEvent(mut record) = event(id, calendar, "Lossy") else {
        unreachable!("event record");
    };
    record.dead_properties =
        model::DeadPropertyRecord(vec![model::DeadPropertyTag::Text("x-unbound".into())]);
    Rec::CalendarEvent(record)
}

pub fn address_book(id: u32, name: &str) -> Rec {
    Rec::AddressBook(AddressBookRecord {
        document_id: id,
        name: name.into(),
        ..Default::default()
    })
}

pub fn contact(id: u32, book: u32, name: &str) -> Rec {
    Rec::Contact(ContactRecord {
        document_id: id,
        names: vec![model::DavNameRecord {
            name: format!("card{id}.vcf"),
            parent_id: book,
        }],
        vcard: format!("BEGIN:VCARD\r\nFN:{name}\r\nEND:VCARD\r\n"),
        size: 30,
        ..Default::default()
    })
}

pub fn notification(id: u32, event: Option<u32>) -> Rec {
    Rec::Notification(EventNotificationRecord {
        document_id: id,
        icalendar: format!("BEGIN:VCALENDAR\r\nUID:n{id}\r\nEND:VCALENDAR\r\n"),
        event_id: event,
        size: 35,
        ..Default::default()
    })
}

pub fn submission(id: u32, email: u32, send_at: u64) -> Rec {
    Rec::Submission(SubmissionRecord {
        document_id: id,
        email_id: email,
        thread_id: email,
        send_at,
        ..Default::default()
    })
}

fn undecodable_page(
    world: &SourceWorld,
    account_id: u32,
    collection: Collection,
    records: Vec<Rec>,
) -> RecordPage {
    let mut issues = Vec::new();
    let last = records.iter().map(Rec::id).max();
    let records = records
        .into_iter()
        .filter(|record| {
            let bad = world
                .undecodable
                .contains(&(account_id, collection, record.id()));
            if bad {
                issues.push(Issue::new(
                    Severity::Error,
                    IssueKind::Skipped,
                    Subject::Document {
                        collection,
                        document_id: record.id(),
                    },
                    "cannot read the v0.16 object",
                ));
            }
            !bad
        })
        .collect();
    let mut page = RecordPage::new(batch_of(collection, records));
    page.issues = issues;
    page.last_scanned = last.or(page.last_scanned);
    page
}

struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}
