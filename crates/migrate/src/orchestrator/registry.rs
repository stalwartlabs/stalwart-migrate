/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::fmt;

use model::{
    BlobHash, Category, CategorySet, Issue, IssueKind, RegistryEntries, RegistryKey,
    RegistryRecord, Rejection, Severity, Source, Subject, Target, TaskRecord, WriteOutcome,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{Map, Value};
use state::{ContentHash, RegistryState, RegistryStatus, RegistryUpdate, StateStore};

use super::{
    BlobMode, RemovalPolicy, RunDirection,
    account::mass_removal,
    blobs::BLOB_MEMORY_PER_SLOT,
    context::Context,
    error::RunError,
    retry::{Backoff, RetryPolicy, retry},
    stats::add,
};

const STOCK_SPAM_TAG_OBJECT: &str = "SpamTag";

const UNREADABLE_REGISTRY: &str = "unreadable in the v0.16 store and also ignored by v0.16.27; not migrated, recreate it in v1 if needed";

pub trait RegistryConverter: Send + Sync + 'static {
    fn category(&self, object: &str) -> Category;

    fn convert(
        &self,
        objects: Vec<RegistryRecord>,
        categories: CategorySet,
    ) -> Result<Converted, ConversionError>;

    fn delete_plan(&self, records: Vec<RegistryRecord>) -> RegistryDeletes;

    fn unlinked_objects(&self, _keys: &[RegistryKey]) -> FxHashSet<Box<str>> {
        FxHashSet::default()
    }

    fn references(&self, side: RecordSide, record: &RegistryRecord) -> Vec<RegistryKey>;

    fn target_object(&self, object: &str) -> Box<str> {
        object.into()
    }

    fn enum_value<'x>(&'x self, _name: &str, _value: &str) -> EnumValue<'x> {
        EnumValue::Keep
    }

    fn stored_task_id(&self, task: &TaskRecord) -> u64 {
        task.id
    }

    fn missing_spam_tags(&self, _objects: &[RegistryRecord]) -> Vec<RegistryRecord> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumValue<'x> {
    Keep,
    Rename(&'x str),
    Drop,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistryDeletes {
    pub updates: Vec<RegistryPatch>,
    pub order: Vec<RegistryKey>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegistryPatch {
    pub key: RegistryKey,
    pub properties: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSide {
    Source,
    Target,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConvertedRecord {
    pub source: RegistryKey,
    pub record: RegistryRecord,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Converted {
    pub records: Vec<ConvertedRecord>,
    pub deferred: Vec<RegistryRecord>,
    pub fallbacks: Vec<RegistryRecord>,
    pub dropped: Vec<RegistryKey>,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversionError {
    Incomplete(Vec<Box<str>>),
    Failed(Box<str>),
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversionError::Incomplete(problems) => {
                f.write_str("settings conversion is incomplete; run prepare:")?;
                for problem in problems {
                    write!(f, "\n  {problem}")?;
                }
                Ok(())
            }
            ConversionError::Failed(message) => write!(f, "settings conversion failed: {message}"),
        }
    }
}

const GUARDED_OBJECTS: [&str; 3] = ["Account", "Domain", "Tenant"];

const REGISTRY_EXCLUDED: [Category; 2] = [Category::Queue, Category::Tasks];

pub fn registry_categories(categories: CategorySet) -> CategorySet {
    let mut categories = categories;
    for category in REGISTRY_EXCLUDED {
        categories.remove(category);
    }
    categories
}

pub async fn read_registry<S: Source>(
    source: &S,
    policy: RetryPolicy,
    limit: usize,
) -> model::Result<RegistryEntries> {
    let types = retry(policy, || source.registry_types()).await?;
    let mut entries = RegistryEntries::default();
    for object in types.iter() {
        let mut after = None;
        loop {
            let page = retry(policy, || source.registry_page(object, after, limit)).await?;
            entries.unreadable.extend(page.unreadable);
            let page = page.records;
            let Some(last) = page.last().map(|record| record.key.id) else {
                break;
            };
            let model::RegistryId::Id(last) = last else {
                entries.records.extend(page);
                break;
            };
            if after.is_some_and(|after| last <= after) {
                return Err(model::Error::fatal(format!(
                    "source registry page for {object} did not advance past id {last}"
                )));
            }
            after = Some(last);
            entries.records.extend(page);
        }
    }
    entries.unreadable.sort_unstable();
    entries.unreadable.dedup();
    Ok(entries)
}

#[derive(Default)]
pub(super) struct BlobRecords {
    writes: Vec<RegistryRecord>,
    updates: Vec<RegistryUpdate>,
    repeated: FxHashSet<RegistryKey>,
    pub(super) held_accounts: FxHashSet<u32>,
}

struct SourceEntry {
    hash: ContentHash,
    json: Vec<u8>,
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn registry_pass(
        &self,
        account_removals_held: bool,
    ) -> Result<BlobRecords, RunError> {
        let limit = self.options.tuning.batch_ops;
        let categories = registry_categories(self.options.categories);
        let RegistryEntries {
            records: objects,
            unreadable,
        } = read_registry(&*self.source, self.policy(), limit).await?;
        self.check_shutdown()?;

        let mut buf = Vec::new();
        let mut sources: FxHashMap<RegistryKey, SourceEntry> =
            FxHashMap::with_capacity_and_hasher(objects.len(), Default::default());
        for record in &objects {
            let hash = content_hash(&record.json, &mut buf, &record.key)?;
            sources.insert(
                record.key.clone(),
                SourceEntry {
                    hash,
                    json: buf.clone(),
                },
            );
        }
        let converted = self
            .converter
            .convert(objects, categories)
            .map_err(|err| RunError::preflight(err.to_string()))?;
        let mut renames: FxHashMap<Box<str>, Box<str>> = FxHashMap::default();
        for ConvertedRecord { source, record } in &converted.records {
            if source.object != record.key.object && !renames.contains_key(&source.object) {
                renames.insert(source.object.clone(), record.key.object.clone());
            }
        }

        let mut known: FxHashMap<RegistryKey, RegistryState> = FxHashMap::default();
        let mut tracked: FxHashMap<Box<str>, usize> = FxHashMap::default();
        for object in self.state.registry_objects().await? {
            if !categories.contains(self.converter.category(&object)) {
                continue;
            }
            let states = self.state.registry_states(object.clone()).await?;
            tracked.insert(
                object,
                states
                    .iter()
                    .filter(|entry| entry.status != RegistryStatus::Dropped)
                    .count(),
            );
            for entry in states {
                known.insert(entry.key.clone(), entry);
            }
        }
        let mut pending: FxHashSet<RegistryKey> =
            self.state.registry_pending().await?.into_iter().collect();
        let guarded = GUARDED_OBJECTS.map(|object| self.converter.target_object(object));
        let mut listed = [0usize; GUARDED_OBJECTS.len()];

        let empty = SourceEntry {
            hash: ContentHash::of(b""),
            json: Vec::new(),
        };
        let mut final_hashes: FxHashMap<RegistryKey, ContentHash> = FxHashMap::default();
        for record in &converted.deferred {
            final_hashes.insert(
                record.key.clone(),
                content_hash(&record.json, &mut buf, &record.key)?,
            );
        }
        let mut writes = Vec::new();
        let mut updates = Vec::new();
        let mut changed: FxHashSet<RegistryKey> = FxHashSet::default();
        let mut written: FxHashSet<RegistryKey> = FxHashSet::default();
        let mut repeated: FxHashSet<RegistryKey> = FxHashSet::default();
        let mut deletes = Vec::new();
        for ConvertedRecord { source, record } in converted.records {
            for (object, count) in guarded.iter().zip(&mut listed) {
                if *object == record.key.object {
                    *count += 1;
                }
            }
            let entry = sources.get(&source).unwrap_or(&empty);
            let target_hash = match final_hashes.get(&record.key) {
                Some(hash) => *hash,
                None => content_hash(&record.json, &mut buf, &record.key)?,
            };
            let previous = known.remove(&record.key);
            let unsettled = pending.remove(&record.key);
            if let Some(previous) = previous
                && !unsettled
                && previous.source_hash == entry.hash
                && previous.target_hash == Some(target_hash)
            {
                match previous.status {
                    RegistryStatus::Ok => continue,
                    RegistryStatus::Error => {
                        repeated.insert(record.key.clone());
                    }
                    RegistryStatus::Dropped => {}
                }
            }
            updates.push(RegistryUpdate {
                key: record.key.clone(),
                source_hash: entry.hash,
                target_hash: Some(target_hash),
                stored_hash: None,
                source_json: entry.json.clone(),
                status: RegistryStatus::Ok,
            });
            changed.insert(source);
            written.insert(record.key.clone());
            writes.push(record);
        }
        let mut placeholders: FxHashMap<RegistryKey, String> = FxHashMap::default();
        let mut deferred_writes = Vec::new();
        for record in converted.deferred {
            if !written.contains(&record.key) {
                continue;
            }
            if let Some(placeholder) = writes.iter().find(|write| write.key == record.key) {
                placeholders.insert(
                    record.key.clone(),
                    changed_fields(&placeholder.json, &record.json),
                );
            }
            deferred_writes.push(record);
        }
        let (mut blob_writes, mut writes): (Vec<RegistryRecord>, Vec<RegistryRecord>) = writes
            .into_iter()
            .partition(|record| self.target.registry_blob(record).is_some());
        let (blob_deferred, deferred_writes): (Vec<RegistryRecord>, Vec<RegistryRecord>) =
            deferred_writes
                .into_iter()
                .partition(|record| self.target.registry_blob(record).is_some());
        blob_writes.extend(blob_deferred);
        let deferred_start = writes.len();
        writes.extend(deferred_writes);
        let blob_keys: FxHashSet<&RegistryKey> =
            blob_writes.iter().map(|record| &record.key).collect();
        let (blob_updates, mut updates): (Vec<RegistryUpdate>, Vec<RegistryUpdate>) =
            updates.into_iter().partition(|update| {
                update.status == RegistryStatus::Ok && blob_keys.contains(&update.key)
            });
        let blob_repeated = repeated
            .iter()
            .filter(|key| blob_keys.contains(key))
            .cloned()
            .collect();
        let mut blob_records = BlobRecords {
            writes: blob_writes,
            updates: blob_updates,
            repeated: blob_repeated,
            held_accounts: FxHashSet::default(),
        };
        for key in converted.dropped {
            let entry = sources.get(&key).unwrap_or(&empty);
            let previous = known.remove(&key);
            match previous {
                Some(previous)
                    if previous.status == RegistryStatus::Dropped
                        && previous.source_hash == entry.hash =>
                {
                    continue;
                }
                Some(previous) if previous.status != RegistryStatus::Dropped => {
                    pending.remove(&key);
                    deletes.push(key.clone());
                }
                _ => {}
            }
            updates.push(RegistryUpdate {
                key: key.clone(),
                source_hash: entry.hash,
                target_hash: None,
                stored_hash: None,
                source_json: entry.json.clone(),
                status: RegistryStatus::Dropped,
            });
            changed.insert(key);
        }

        let mut issues: Vec<Issue> = converted
            .issues
            .into_iter()
            .filter(|issue| match &issue.subject {
                Subject::Registry(key) => changed.contains(key) && !repeated.contains(key),
                _ => !changed.is_empty(),
            })
            .collect();
        issues.extend(
            unreadable
                .into_iter()
                .filter(|key| categories.contains(self.converter.category(&key.object)))
                .map(|key| {
                    Issue::new(
                        Severity::Warning,
                        IssueKind::Skipped,
                        Subject::Registry(key),
                        UNREADABLE_REGISTRY,
                    )
                }),
        );
        let in_flight: Vec<RegistryKey> = writes
            .iter()
            .chain(&blob_records.writes)
            .map(|record| record.key.clone())
            .collect();
        if !in_flight.is_empty() {
            self.state
                .set_registry_pending(in_flight, Vec::new())
                .await?;
            failpoint!("registry.pending", "writes");
        }
        let mut failed = FxHashSet::default();
        let mut write_issues = Vec::new();
        let (placeholder_writes, full_writes) = writes.split_at(deferred_start);
        for chunk in placeholder_writes.chunks(limit) {
            self.check_shutdown()?;
            let outcome = self.write_registry_records(chunk, &mut failed).await?;
            write_issues.extend(outcome.issues);
        }
        for chunk in full_writes.chunks(limit) {
            self.check_shutdown()?;
            let outcome = self.write_registry_records(chunk, &mut failed).await?;
            write_issues.extend(outcome.issues.into_iter().map(|mut issue| {
                if let Subject::Registry(key) = &issue.subject
                    && issue.severity == Severity::Error
                    && let Some(fields) = placeholders.get(key)
                {
                    issue.message = format!(
                        "written with placeholders for {fields} to split a reference cycle; the full object was rejected: {}",
                        issue.message
                    )
                    .into_boxed_str();
                }
                issue
            }));
        }
        failed.extend(failed_keys(&write_issues));

        let mut removals = Vec::with_capacity(known.len());
        for (key, entry) in known {
            if pending.remove(&key) || entry.status != RegistryStatus::Dropped {
                deletes.push(key.clone());
            }
            removals.push(key);
        }
        let orphans: FxHashSet<RegistryKey> = pending
            .into_iter()
            .filter(|key| categories.contains(self.converter.category(&key.object)))
            .collect();
        deletes.extend(orphans.iter().cloned());
        let held = self
            .held_registry_removals(
                &deletes,
                &orphans,
                &tracked,
                &guarded,
                &listed,
                account_removals_held,
            )
            .await?;
        if !held.is_empty() {
            deletes.retain(|key| !held.contains(key));
            updates.retain(|update| !held.contains(&update.key));
            removals.retain(|key| !held.contains(key));
            let [account, ..] = GUARDED_OBJECTS;
            let account_object = self.converter.target_object(account);
            blob_records.held_accounts = held
                .iter()
                .filter(|key| key.object == account_object)
                .filter_map(|key| key.id.id().and_then(|id| u32::try_from(id).ok()))
                .collect();
        }
        add(
            &self.stats.registry_dropped,
            updates
                .iter()
                .filter(|update| update.status == RegistryStatus::Dropped)
                .count() as u64,
        );
        let RegistryDeletes {
            updates: unlinks,
            order: deletes,
        } = self.deletion_plan(deletes).await?;
        if !deletes.is_empty() {
            self.state
                .set_registry_pending(deletes.clone(), Vec::new())
                .await?;
            failpoint!("registry.pending", "deletes");
        }
        let unlinks = self.unlinked_records(unlinks).await?;
        let mut unlink_issues = Vec::new();
        let mut unlink_failed = FxHashSet::default();
        for chunk in unlinks.chunks(limit) {
            self.check_shutdown()?;
            let outcome = self
                .write_registry_records(chunk, &mut unlink_failed)
                .await?;
            failpoint!("registry.unlink");
            unlink_issues.extend(outcome.issues);
        }
        self.report(None, unlink_issues).await?;
        for keys in deletes.chunks(limit) {
            self.check_shutdown()?;
            self.retry(|| self.target.delete_registry(keys)).await?;
            failpoint!("registry.delete");
        }
        add(&self.stats.registry_deleted, deletes.len() as u64);

        let fallbacks: FxHashMap<&RegistryKey, &Value> = converted
            .fallbacks
            .iter()
            .map(|record| (&record.key, &record.json))
            .collect();
        let conflicts: FxHashSet<&RegistryKey> = write_issues
            .iter()
            .filter(|issue| {
                issue.severity == Severity::Error && issue.rejection == Some(Rejection::Conflict)
            })
            .filter_map(|issue| match &issue.subject {
                Subject::Registry(key) => Some(key),
                _ => None,
            })
            .collect();
        let retry: Vec<RegistryRecord> = writes
            .iter()
            .filter(|record| {
                failed.contains(&record.key)
                    && (!deletes.is_empty() || conflicts.contains(&record.key))
            })
            .cloned()
            .collect();
        if !retry.is_empty() {
            self.retry_registry_writes(&retry, &mut failed, &mut write_issues, limit)
                .await?;
        }
        let mut fell_back = Vec::new();
        let fallback_writes: Vec<RegistryRecord> = writes
            .iter()
            .filter(|record| failed.contains(&record.key))
            .filter_map(|record| {
                let json = fallbacks.get(&record.key)?;
                let rejection = write_issues.iter().find(|issue| {
                    matches!(&issue.subject, Subject::Registry(key) if *key == record.key)
                        && issue.severity == Severity::Error
                })?;
                if rejection.rejection == Some(Rejection::Conflict) {
                    return None;
                }
                issues.push(Issue::new(
                    Severity::Warning,
                    IssueKind::Changed,
                    Subject::Registry(record.key.clone()),
                    format!(
                        "the original value from the --forward-state was rejected ({}); the converted value is written instead, which drops or changes: {}",
                        rejection.message,
                        changed_fields(&record.json, json)
                    ),
                ));
                fell_back.push(record.key.clone());
                Some(RegistryRecord {
                    key: record.key.clone(),
                    json: (*json).clone(),
                })
            })
            .collect();
        if !fallback_writes.is_empty() {
            self.retry_registry_writes(&fallback_writes, &mut failed, &mut write_issues, limit)
                .await?;
            fell_back.retain(|key| !failed.contains(key));
        }
        issues.extend(
            write_issues
                .into_iter()
                .filter(|issue| match &issue.subject {
                    Subject::Registry(key) => !repeated.contains(key),
                    _ => true,
                }),
        );

        let stored = self
            .stored_hashes(&writes, &failed, &mut issues, &mut buf)
            .await?;
        self.raise_registry_counters(&renames, categories).await?;
        self.report(None, issues).await?;
        let cleared: Vec<RegistryKey> = writes
            .iter()
            .map(|record| &record.key)
            .filter(|key| !failed.contains(*key) && !fell_back.contains(*key))
            .cloned()
            .collect();
        self.commit_registry_updates(updates, &stored, &failed)
            .await?;
        if !fell_back.is_empty() || !cleared.is_empty() {
            self.state
                .set_registry_fallbacks(fell_back, cleared)
                .await?;
            failpoint!("registry.fallbacks");
        }
        if !removals.is_empty() {
            self.state.remove_registry(removals).await?;
            failpoint!("registry.removed");
        }
        let settled: Vec<RegistryKey> = writes
            .into_iter()
            .map(|record| record.key)
            .chain(deletes)
            .collect();
        if !settled.is_empty() {
            self.state.set_registry_pending(Vec::new(), settled).await?;
            failpoint!("registry.pending", "settled");
        }
        Ok(blob_records)
    }

    async fn retry_registry_writes(
        &self,
        records: &[RegistryRecord],
        failed: &mut FxHashSet<RegistryKey>,
        write_issues: &mut Vec<Issue>,
        limit: usize,
    ) -> Result<(), RunError> {
        let retried: FxHashSet<&RegistryKey> = records.iter().map(|record| &record.key).collect();
        write_issues.retain(|issue| match &issue.subject {
            Subject::Registry(key) => !retried.contains(key),
            _ => true,
        });
        failed.retain(|key| !retried.contains(key));
        let mut retry_issues = Vec::new();
        for chunk in records.chunks(limit) {
            self.check_shutdown()?;
            let outcome = self.write_registry_records(chunk, failed).await?;
            retry_issues.extend(outcome.issues);
        }
        failed.extend(failed_keys(&retry_issues));
        write_issues.extend(retry_issues);
        Ok(())
    }

    pub(super) async fn registry_blob_pass(&self, pending: BlobRecords) -> Result<(), RunError> {
        let BlobRecords {
            mut writes,
            updates,
            repeated,
            ..
        } = pending;
        if writes.is_empty() {
            return Ok(());
        }
        let in_flight: Vec<RegistryKey> = writes.iter().map(|record| record.key.clone()).collect();
        let mut failed = FxHashSet::default();
        let mut issues = Vec::new();
        self.drop_missing_registry_blobs(&mut writes, &mut failed, &mut issues)
            .await?;
        for chunk in writes.chunks(self.options.tuning.batch_ops.max(1)) {
            self.check_shutdown()?;
            let outcome = self.write_registry_records(chunk, &mut failed).await?;
            issues.extend(outcome.issues);
        }
        failed.extend(failed_keys(&issues));
        issues.retain(
            |issue| !matches!(&issue.subject, Subject::Registry(key) if repeated.contains(key)),
        );
        let stored = self
            .stored_hashes(&writes, &failed, &mut issues, &mut Vec::new())
            .await?;
        self.report(None, issues).await?;
        self.commit_registry_updates(updates, &stored, &failed)
            .await?;
        self.state
            .set_registry_pending(Vec::new(), in_flight)
            .await?;
        failpoint!("registry.pending", "blobs_settled");
        Ok(())
    }

    async fn commit_registry_updates(
        &self,
        mut updates: Vec<RegistryUpdate>,
        stored: &FxHashMap<RegistryKey, ContentHash>,
        failed: &FxHashSet<RegistryKey>,
    ) -> Result<(), RunError> {
        let mut written = 0u64;
        for update in &mut updates {
            if update.status != RegistryStatus::Ok {
                continue;
            }
            match stored.get(&update.key) {
                Some(hash) if !failed.contains(&update.key) => {
                    update.stored_hash = Some(*hash);
                    written += 1;
                }
                _ => update.status = RegistryStatus::Error,
            }
        }
        add(&self.stats.registry_written, written);
        let limit = self.options.tuning.batch_ops.max(1);
        while !updates.is_empty() {
            let tail = updates.split_off(updates.len().min(limit));
            let chunk = std::mem::replace(&mut updates, tail);
            self.state.put_registry(self.run_id, chunk).await?;
            failpoint!("registry.put");
        }
        Ok(())
    }

    async fn drop_missing_registry_blobs(
        &self,
        writes: &mut Vec<RegistryRecord>,
        failed: &mut FxHashSet<RegistryKey>,
        issues: &mut Vec<Issue>,
    ) -> Result<(), RunError> {
        let refs: Vec<(BlobHash, RegistryKey)> = writes
            .iter()
            .filter_map(|record| {
                self.target
                    .registry_blob(record)
                    .map(|hash| (hash, record.key.clone()))
            })
            .collect();
        if refs.is_empty() {
            return Ok(());
        }
        let missing = match self.options.blob_mode {
            BlobMode::Copy => {
                self.copy_missing_blobs(
                    refs.iter()
                        .map(|(hash, _)| (*hash, BLOB_MEMORY_PER_SLOT))
                        .collect(),
                )
                .await?
            }
            BlobMode::Shared => self.missing_stored_blobs(&refs).await?,
        };
        if missing.is_empty() {
            return Ok(());
        }
        for (hash, key) in refs {
            if missing.binary_search(&hash).is_ok() {
                issues.push(Issue::new(
                    Severity::Error,
                    IssueKind::Skipped,
                    Subject::Registry(key.clone()),
                    format!("blob {hash} is missing in the source; the object was not copied"),
                ));
                failed.insert(key);
            }
        }
        writes.retain(|record| !failed.contains(&record.key));
        Ok(())
    }

    async fn missing_stored_blobs(
        &self,
        refs: &[(BlobHash, RegistryKey)],
    ) -> Result<Vec<BlobHash>, RunError> {
        let mut hashes: Vec<BlobHash> = refs.iter().map(|(hash, _)| *hash).collect();
        hashes.sort_unstable();
        hashes.dedup();
        let mut missing = Vec::new();
        for chunk in hashes.chunks(self.options.tuning.batch_ops.max(1)) {
            self.check_shutdown()?;
            let exist = self.retry(|| self.target.stored_blobs_exist(chunk)).await?;
            missing.extend(
                chunk
                    .iter()
                    .zip(exist)
                    .filter_map(|(hash, exists)| (!exists).then_some(*hash)),
            );
        }
        Ok(missing)
    }

    async fn held_registry_removals(
        &self,
        deletes: &[RegistryKey],
        orphans: &FxHashSet<RegistryKey>,
        tracked: &FxHashMap<Box<str>, usize>,
        guarded: &[Box<str>; GUARDED_OBJECTS.len()],
        listed: &[usize],
        account_removals_held: bool,
    ) -> Result<FxHashSet<RegistryKey>, RunError> {
        if deletes.is_empty() || self.options.removals == RemovalPolicy::Allow {
            return Ok(FxHashSet::default());
        }
        let mut removed: FxHashMap<&str, usize> = FxHashMap::default();
        for key in deletes {
            *removed.entry(&*key.object).or_default() += 1;
        }
        let mut issues = Vec::new();
        let mut held_objects = Vec::new();
        for (object, removed) in removed {
            let tracked = tracked.get(object).copied().unwrap_or(removed);
            let emptied = guarded
                .iter()
                .zip(listed)
                .any(|(guarded, listed)| &**guarded == object && *listed == 0);
            let [account_object, ..] = guarded;
            let held_with_accounts = account_removals_held && &**account_object == object;
            let suspicious = emptied || mass_removal(removed, tracked);
            if !suspicious {
                if held_with_accounts {
                    held_objects.push(object);
                }
                continue;
            }
            let orphaned = orphans.iter().filter(|key| &*key.object == object).count();
            let listed_fewer = removed.saturating_sub(orphaned);
            let message = match (listed_fewer, orphaned) {
                (_, 0) => format!(
                    "the source lists {removed} fewer {object} objects than the state database ({tracked} tracked); not deleting them. Check the source configuration or pass --allow-mass-removal"
                ),
                (0, _) => format!(
                    "{orphaned} {object} objects written by an interrupted run are no longer in the source; not deleting them. Check the source configuration or pass --allow-mass-removal"
                ),
                _ => format!(
                    "the source lists {listed_fewer} fewer {object} objects than the state database ({tracked} tracked), and {orphaned} more written by an interrupted run are no longer in the source; not deleting them. Check the source configuration or pass --allow-mass-removal"
                ),
            };
            tracing::error!("{message}");
            issues.push(Issue::new(
                Severity::Error,
                IssueKind::Skipped,
                Subject::None,
                message,
            ));
            held_objects.push(object);
        }
        let mut held: FxHashSet<RegistryKey> = deletes
            .iter()
            .filter(|key| held_objects.contains(&&*key.object))
            .cloned()
            .collect();
        if !held.is_empty() {
            self.hold_linked_removals(deletes, &mut held, &mut issues)
                .await?;
        }
        self.report(None, issues).await?;
        Ok(held)
    }

    async fn hold_linked_removals(
        &self,
        deletes: &[RegistryKey],
        held: &mut FxHashSet<RegistryKey>,
        issues: &mut Vec<Issue>,
    ) -> Result<(), RunError> {
        if deletes.iter().all(|key| held.contains(key)) {
            return Ok(());
        }
        let mut keys: Vec<&RegistryKey> = deletes.iter().collect();
        keys.sort_unstable();
        keys.dedup();
        let mut references: FxHashMap<RegistryKey, Vec<RegistryKey>> =
            FxHashMap::with_capacity_and_hasher(keys.len(), Default::default());
        for chunk in keys.chunks(self.options.tuning.batch_ops.max(1)) {
            self.check_shutdown()?;
            let chunk: Vec<RegistryKey> = chunk.iter().map(|key| (*key).clone()).collect();
            let records = self.retry(|| self.target.read_registry(&chunk)).await?;
            for (key, record) in chunk.into_iter().zip(records) {
                if let Some(record) = record {
                    let links = self.converter.references(RecordSide::Target, &record);
                    references.insert(key, links);
                }
            }
        }
        loop {
            let mut linked: FxHashMap<&RegistryKey, &RegistryKey> = FxHashMap::default();
            for holder in held.iter() {
                for link in references.get(holder).into_iter().flatten() {
                    linked.entry(link).or_insert(holder);
                }
            }
            let mut added: Vec<(RegistryKey, String)> = Vec::new();
            for key in &keys {
                if held.contains(*key) {
                    continue;
                }
                let owner = references
                    .get(*key)
                    .and_then(|links| links.iter().find(|link| held.contains(*link)));
                if let Some(owner) = owner {
                    added.push((
                        (*key).clone(),
                        format!(
                            "not deleting {key}: it belongs to {owner}, whose removal is held by the mass-removal guard"
                        ),
                    ));
                } else if let Some(holder) = linked.get(*key) {
                    added.push((
                        (*key).clone(),
                        format!(
                            "not deleting {key}: {holder} still links to it and its removal is held by the mass-removal guard"
                        ),
                    ));
                }
            }
            if added.is_empty() {
                return Ok(());
            }
            for (key, message) in added {
                tracing::error!("{message}");
                held.insert(key.clone());
                issues.push(Issue::new(
                    Severity::Error,
                    IssueKind::Skipped,
                    Subject::Registry(key),
                    message,
                ));
            }
        }
    }

    async fn deletion_plan(&self, keys: Vec<RegistryKey>) -> Result<RegistryDeletes, RunError> {
        if keys.is_empty() {
            return Ok(RegistryDeletes::default());
        }
        let unlinked = self.converter.unlinked_objects(&keys);
        let mut records: Vec<RegistryRecord> = keys
            .into_iter()
            .map(|key| RegistryRecord {
                key,
                json: Value::Null,
            })
            .collect();
        let mut linking: Vec<&mut RegistryRecord> = records
            .iter_mut()
            .filter(|record| !unlinked.contains(&*record.key.object))
            .collect();
        let mut keys = Vec::new();
        for chunk in linking.chunks_mut(self.options.tuning.batch_ops.max(1)) {
            self.check_shutdown()?;
            keys.clear();
            keys.extend(chunk.iter().map(|record| record.key.clone()));
            let stored = self.retry(|| self.target.read_registry(&keys)).await?;
            for (record, stored) in chunk.iter_mut().zip(stored) {
                if let Some(stored) = stored {
                    record.json = stored.json;
                }
            }
        }
        Ok(self.converter.delete_plan(records))
    }

    async fn unlinked_records(
        &self,
        patches: Vec<RegistryPatch>,
    ) -> Result<Vec<RegistryRecord>, RunError> {
        let mut records = Vec::with_capacity(patches.len());
        let keys: Vec<RegistryKey> = patches.iter().map(|patch| patch.key.clone()).collect();
        let mut patches = patches.into_iter();
        for chunk in keys.chunks(self.options.tuning.batch_ops.max(1)) {
            self.check_shutdown()?;
            let stored = self.retry(|| self.target.read_registry(chunk)).await?;
            for (stored, patch) in stored.into_iter().zip(patches.by_ref()) {
                if let Some(mut record) = stored
                    && let Some(object) = record.json.as_object_mut()
                {
                    object.extend(patch.properties);
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    async fn stored_hashes(
        &self,
        writes: &[RegistryRecord],
        failed: &FxHashSet<RegistryKey>,
        issues: &mut Vec<Issue>,
        buf: &mut Vec<u8>,
    ) -> Result<FxHashMap<RegistryKey, ContentHash>, RunError> {
        let mut keys: Vec<RegistryKey> = writes
            .iter()
            .filter(|record| !failed.contains(&record.key))
            .map(|record| record.key.clone())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let mut stored = FxHashMap::with_capacity_and_hasher(keys.len(), Default::default());
        for chunk in keys.chunks(self.options.tuning.batch_ops.max(1)) {
            self.check_shutdown()?;
            let records = self.retry(|| self.target.read_registry(chunk)).await?;
            for (key, record) in chunk.iter().zip(records) {
                match record {
                    Some(record) => {
                        stored.insert(key.clone(), content_hash(&record.json, buf, key)?);
                    }
                    None => issues.push(Issue::new(
                        Severity::Error,
                        IssueKind::Failed,
                        Subject::Registry(key.clone()),
                        "the target accepted the object but does not return it",
                    )),
                }
            }
        }
        Ok(stored)
    }

    pub(super) async fn add_stock_spam_tags(&self) -> Result<(), RunError> {
        if self.options.direction != RunDirection::Migration
            || !registry_categories(self.options.categories)
                .contains(self.converter.category(STOCK_SPAM_TAG_OBJECT))
        {
            return Ok(());
        }
        let objects = read_registry(&*self.source, self.policy(), self.options.tuning.batch_ops)
            .await?
            .records;
        let records = self.converter.missing_spam_tags(&objects);
        if records.is_empty() {
            return Ok(());
        }
        let WriteOutcome { mut issues } =
            self.retry(|| self.target.write_registry(&records)).await?;
        failpoint!("registry.stock_spam_tags");
        let failed: FxHashSet<RegistryKey> = failed_keys(&issues).collect();
        issues.extend(
            records
                .iter()
                .filter(|record| !failed.contains(&record.key))
                .map(|record| {
                    Issue::new(
                        Severity::Info,
                        IssueKind::Changed,
                        Subject::Registry(record.key.clone()),
                        format!(
                            "stock spam filter tag {} added with score {}, missing from the migrated settings",
                            record.json.get("tag").and_then(Value::as_str).unwrap_or_default(),
                            record.json.get("score").and_then(Value::as_f64).unwrap_or_default()
                        ),
                    )
                }),
        );
        self.report(None, issues).await
    }

    async fn raise_registry_counters(
        &self,
        renames: &FxHashMap<Box<str>, Box<str>>,
        categories: CategorySet,
    ) -> Result<(), RunError> {
        let mut counters = self.retry(|| self.source.registry_id_counters()).await?;
        counters.retain_mut(|counter| {
            counter.object = match renames.get(&counter.object) {
                Some(object) => object.clone(),
                None => self.converter.target_object(&counter.object),
            };
            categories.contains(self.converter.category(&counter.object))
        });
        if !counters.is_empty() {
            self.retry(|| self.target.raise_registry_counters(&counters))
                .await?;
            failpoint!("registry.counters");
        }
        Ok(())
    }

    async fn write_registry_records(
        &self,
        records: &[RegistryRecord],
        failed: &mut FxHashSet<RegistryKey>,
    ) -> Result<WriteOutcome, RunError> {
        let mut outcome = WriteOutcome::ok();
        let mut pending = vec![records];
        while let Some(records) = pending.pop() {
            let mut backoff = Backoff::new(self.policy());
            let result = loop {
                match self.target.write_registry(records).await {
                    Ok(written) => break Ok(written),
                    Err(err) => {
                        if !backoff.wait(&err).await {
                            break Err(err);
                        }
                    }
                }
            };
            match result {
                Ok(written) => {
                    failpoint!("registry.write");
                    outcome.merge(written)
                }
                Err(err) if err.is_too_large() && records.len() > 1 => {
                    let (head, tail) = records.split_at(records.len() / 2);
                    pending.push(tail);
                    pending.push(head);
                }
                Err(err) if err.is_too_large() => {
                    for record in records {
                        outcome.issues.push(Issue::new(
                            Severity::Error,
                            IssueKind::Failed,
                            Subject::Registry(record.key.clone()),
                            err.message(),
                        ));
                        failed.insert(record.key.clone());
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(outcome)
    }
}

fn changed_fields(original: &Value, fallback: &Value) -> String {
    let mut fields = String::new();
    if let (Value::Object(original), Value::Object(fallback)) = (original, fallback) {
        for (name, value) in original {
            if fallback.get(name) != Some(value) {
                if !fields.is_empty() {
                    fields.push_str(", ");
                }
                fields.push_str(name);
            }
        }
        for name in fallback.keys() {
            if !original.contains_key(name) {
                if !fields.is_empty() {
                    fields.push_str(", ");
                }
                fields.push_str(name);
            }
        }
    }
    if fields.is_empty() {
        fields.push_str("no field");
    }
    fields
}

fn failed_keys(issues: &[Issue]) -> impl Iterator<Item = RegistryKey> + '_ {
    issues.iter().filter_map(|issue| match &issue.subject {
        Subject::Registry(key) if issue.severity == Severity::Error => Some(key.clone()),
        _ => None,
    })
}

fn content_hash(
    json: &Value,
    buf: &mut Vec<u8>,
    key: &RegistryKey,
) -> Result<ContentHash, RunError> {
    buf.clear();
    serde_json::to_writer(&mut *buf, json).map_err(|err| {
        RunError::Data(model::Error::fatal(format!(
            "cannot serialize registry object {key}: {err}"
        )))
    })?;
    Ok(ContentHash::of(buf))
}
