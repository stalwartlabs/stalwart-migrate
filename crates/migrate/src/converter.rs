/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::hash_map::Entry as MapEntry;

use mapping::{
    Answers, Change, Direction, Entry, Instance, Level, Mapping, ObjectKey, Options, Outcome,
    Owners, Principals, SchemaVersion, SourceObject, TargetObject, rules::EnumRule,
    unique_key_value,
};
use model::{
    Category, CategorySet, Edition, Issue, IssueKind, RegistryId, RegistryKey, RegistryRecord,
    Severity, Subject, TaskRecord,
};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    references::ReferenceTargets,
    restore::{RestorePlan, RestoredRecord, plan_restore},
};
use serde_json::{Map, Value};

use source_v1::{
    registry_object_expired_at, registry_object_is_certificate, registry_object_is_stored,
    singleton_task_id,
};
use state::ContentHash;

use crate::orchestrator::{
    ConversionError, Converted, ConvertedRecord, EnumValue, RecordSide, RegistryConverter,
    RegistryDeletes, RegistryPatch,
};

const OBJECT_PREFIX: &str = "x:";
const ACCOUNT_OBJECT: &str = "Account";
const SPAM_TAG_OBJECT: &str = "SpamTag";
const SPAM_TAG: &str = "tag";
const SPAM_TAG_SCORE: &str = "Score";
const STOCK_ID_MASK: u64 = (1 << 62) - 1;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

fn stock_spam_tag_id(tag: &str) -> u64 {
    tag.bytes().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    }) & STOCK_ID_MASK
}

pub struct MappingConverter {
    mapping: Mapping,
    answers: Answers,
    options: Options,
    direction: Direction,
    originals: FxHashMap<RegistryKey, Original>,
    unconverted: Unconverted,
    reference_targets: ReferenceTargets,
}

fn reference_targets(mapping: &Mapping, direction: Direction) -> ReferenceTargets {
    ReferenceTargets::of(mapping.schema(match direction {
        Direction::Forward => SchemaVersion::V1,
        Direction::Reverse => SchemaVersion::V016,
    }))
}

pub struct Original {
    pub stored_hash: ContentHash,
    pub json: Value,
}

#[derive(Default)]
pub struct ForwardState {
    pub originals: FxHashMap<RegistryKey, Original>,
    pub unconverted: Vec<RegistryRecord>,
    pub written: Vec<RegistryKey>,
}

enum Unconverted {
    Unknown,
    Restore {
        records: Vec<RegistryRecord>,
        written: Vec<RegistryKey>,
    },
}

const NO_FORWARD_STATE: &str = "rollback without --forward-state: settings the migration dropped or could not write to v1 cannot be restored; pass the migration's --state as --forward-state to restore their original v0.16 objects";
const NOT_RESTORED_DELETED: &str = "not restored from the --forward-state: the migration wrote this object to v1 before and it was deleted there";
const RESTORED: &str = "the migration did not copy this object to v1; its original v0.16 object was restored from the --forward-state";

impl MappingConverter {
    pub fn new(mapping: Mapping, answers: Answers, options: Options) -> Self {
        MappingConverter {
            reference_targets: reference_targets(&mapping, Direction::Forward),
            mapping,
            answers,
            options,
            direction: Direction::Forward,
            originals: FxHashMap::default(),
            unconverted: Unconverted::Restore {
                records: Vec::new(),
                written: Vec::new(),
            },
        }
    }

    pub fn reverse(
        mapping: Mapping,
        answers: Answers,
        options: Options,
        forward: Option<ForwardState>,
    ) -> Self {
        let (originals, unconverted) = match forward {
            Some(forward) => (
                forward.originals,
                Unconverted::Restore {
                    records: forward.unconverted,
                    written: forward.written,
                },
            ),
            None => (FxHashMap::default(), Unconverted::Unknown),
        };
        MappingConverter {
            reference_targets: reference_targets(&mapping, Direction::Reverse),
            mapping,
            answers,
            options,
            direction: Direction::Reverse,
            originals,
            unconverted,
        }
    }

    fn restore_plan<'r>(&self, members: &[&'r RegistryRecord]) -> Option<Vec<RestoredRecord<'r>>> {
        let schema_key = |key: &RegistryKey| {
            let mut key = object_key(key);
            if !key.object.starts_with(OBJECT_PREFIX) {
                key.object = format!("{OBJECT_PREFIX}{}", key.object).into();
            }
            key
        };
        let by_key: FxHashMap<ObjectKey, &'r RegistryRecord> = members
            .iter()
            .map(|record| (schema_key(&record.key), *record))
            .collect();
        let objects = members
            .iter()
            .map(|record| {
                let key = schema_key(&record.key);
                TargetObject {
                    source: key.clone(),
                    key,
                    value: record.json.clone(),
                }
            })
            .collect();
        let plan = self
            .mapping
            .session(self.direction, &self.answers, self.options.clone())
            .write_plan(objects);
        if plan.report.errors().next().is_some() {
            return None;
        }
        let split: FxHashSet<&ObjectKey> = plan.deferred.iter().map(|update| &update.key).collect();
        plan.objects
            .iter()
            .map(|object| {
                let record = by_key.get(&object.key)?;
                Some(RestoredRecord {
                    record,
                    json: object.value.clone(),
                    deferred: split.contains(&object.key),
                })
            })
            .collect()
    }

    fn output_key(&self, key: RegistryKey) -> RegistryKey {
        match (self.direction, key.object.strip_prefix(OBJECT_PREFIX)) {
            (Direction::Reverse, Some(object)) => RegistryKey {
                object: object.into(),
                id: key.id,
            },
            _ => key,
        }
    }

    pub fn mapping(&self) -> &Mapping {
        &self.mapping
    }
}

pub fn mapping_edition(edition: Edition) -> mapping::Edition {
    match edition {
        Edition::Enterprise => mapping::Edition::Enterprise,
        Edition::Community => mapping::Edition::Oss,
    }
}

pub fn listed_owners<'k>(
    keys: impl IntoIterator<Item = (&'k str, Option<u64>)>,
    categories: CategorySet,
) -> Owners {
    let accounts = keys
        .into_iter()
        .filter(|(object, _)| {
            object.strip_prefix(OBJECT_PREFIX).unwrap_or(object) == ACCOUNT_OBJECT
        })
        .filter_map(|(_, id)| id)
        .collect();
    let principals = if categories.contains(Category::Principals) {
        Principals::Migrated
    } else {
        Principals::Excluded
    };
    Owners::Listed {
        accounts,
        principals,
    }
}

fn unique_key_of(record: &RegistryRecord) -> Option<(&str, String)> {
    let name = record
        .key
        .object
        .strip_prefix(OBJECT_PREFIX)
        .unwrap_or(&record.key.object);
    let value = unique_key_value(&format!("{OBJECT_PREFIX}{name}"), &record.json)?;
    let space = hashify::map!(name.as_bytes(), &'static str,
        "MailingList" => "Account",
        "StoreLookup" => "HttpLookup",
        "MemoryLookupKeyValue" => "MemoryLookupKey",
    )
    .copied()
    .unwrap_or(name);
    Some((space, value))
}

pub fn instance_id(instance: &Instance) -> Option<u64> {
    match instance {
        Instance::Id(id) => Some(*id),
        _ => None,
    }
}

fn bare_key(key: &RegistryKey) -> RegistryKey {
    RegistryKey {
        object: key
            .object
            .strip_prefix(OBJECT_PREFIX)
            .unwrap_or(&key.object)
            .into(),
        id: key.id,
    }
}

pub fn object_key(key: &RegistryKey) -> ObjectKey {
    let instance = match key.id {
        RegistryId::Singleton => Instance::Singleton,
        RegistryId::Id(id) => Instance::Id(id),
    };
    ObjectKey::new(&key.object, instance)
}

pub fn registry_key(key: &ObjectKey) -> Option<RegistryKey> {
    match &key.instance {
        Instance::Singleton => Some(RegistryKey::singleton(key.object.clone())),
        Instance::Id(id) => Some(RegistryKey::new(key.object.clone(), *id)),
        Instance::Client(_) | Instance::Label(_) => None,
    }
}

pub fn object_category(object: &str) -> Category {
    let name = object.strip_prefix(OBJECT_PREFIX).unwrap_or(object);
    hashify::map!(name.as_bytes(), Category,
        "Account" => Category::Principals,
        "AccountPassword" => Category::Principals,
        "ApiKey" => Category::Principals,
        "AppPassword" => Category::Principals,
        "Domain" => Category::Principals,
        "MailingList" => Category::Principals,
        "MaskedEmail" => Category::Principals,
        "OAuthClient" => Category::Principals,
        "PublicKey" => Category::Principals,
        "Role" => Category::Principals,
        "Tenant" => Category::Principals,
        "SpamTrainingSample" => Category::SpamSamples,
        "ArfExternalReport" => Category::Reports,
        "DmarcExternalReport" => Category::Reports,
        "TlsExternalReport" => Category::Reports,
        "DmarcInternalReport" => Category::Queue,
        "TlsInternalReport" => Category::Queue,
        "QueuedMessage" => Category::Queue,
        "Task" => Category::Tasks,
        "ArchivedItem" => Category::Archive,
        "Trace" => Category::Telemetry,
        "Metric" => Category::Telemetry,
    )
    .copied()
    .unwrap_or(Category::Settings)
}

fn with_placeholders(
    restored: &Value,
    converted: &Value,
    properties: &Map<String, Value>,
) -> Value {
    let mut json = restored.clone();
    if let Value::Object(map) = &mut json {
        for name in properties.keys() {
            match converted.get(name) {
                Some(placeholder) => map.insert(name.clone(), placeholder.clone()),
                None => map.remove(name),
            };
        }
    }
    json
}

pub fn outcome_problems(mapping: &Mapping, answers: &Answers, outcome: &Outcome) -> Vec<Box<str>> {
    let mut problems: Vec<Box<str>> = Vec::new();
    if outcome.aborted {
        problems.push("the conversion was aborted".into());
    }
    problems.extend(
        answers
            .validate(mapping, &outcome.report.questions)
            .into_iter()
            .filter(|issue| issue.is_error())
            .map(|issue| issue.to_string().into_boxed_str()),
    );
    problems.extend(
        outcome
            .report
            .errors()
            .filter(|entry| !drops_task(entry))
            .map(|entry| entry.to_string().into_boxed_str()),
    );
    problems
}

fn drops_task(entry: &Entry) -> bool {
    matches!(entry.change, Change::Dangling { .. })
        && object_category(&entry.key.object) == Category::Tasks
}

fn entry_issue(entry: &Entry, originals: &FxHashMap<ObjectKey, RegistryKey>) -> Issue {
    let subject = originals
        .get(&entry.key)
        .cloned()
        .or_else(|| registry_key(&entry.key))
        .map_or(Subject::None, Subject::Registry);
    if drops_task(entry) {
        return Issue::new(
            Severity::Warning,
            IssueKind::Dropped,
            subject,
            format!("{entry}; the task was not copied"),
        );
    }
    let severity = match entry.level() {
        Level::Info => Severity::Info,
        Level::Warning => Severity::Warning,
        Level::Error => Severity::Error,
    };
    let kind = match entry.change {
        Change::Dropped { .. }
        | Change::ReferenceCleared { .. }
        | Change::ReferenceOutsideTenant { .. } => IssueKind::Dropped,
        Change::Clamped { .. } => IssueKind::Clamped,
        Change::Dangling { .. } => IssueKind::Failed,
        Change::DefaultPinned { .. }
        | Change::DefaultInherited { .. }
        | Change::Transformed { .. }
        | Change::Unknown
        | Change::Moved { .. }
        | Change::ReferenceDeferred => IssueKind::Changed,
        Change::ReferenceCycle => IssueKind::Failed,
    };
    Issue::new(severity, kind, subject, entry.to_string())
}

impl RegistryConverter for MappingConverter {
    fn category(&self, object: &str) -> Category {
        object_category(object)
    }

    fn convert(
        &self,
        objects: Vec<RegistryRecord>,
        categories: CategorySet,
    ) -> Result<Converted, ConversionError> {
        let mut originals: FxHashMap<ObjectKey, RegistryKey> = FxHashMap::default();
        let mut inputs = Vec::with_capacity(objects.len());
        let mut unchanged: FxHashSet<RegistryKey> = FxHashSet::default();
        let mut buf = Vec::new();
        let owners = listed_owners(
            objects
                .iter()
                .map(|record| (&*record.key.object, record.key.id.id())),
            categories,
        );
        let in_scope =
            |record: &RegistryRecord| categories.contains(object_category(&record.key.object));
        let mut referrers: FxHashMap<RegistryKey, Vec<RegistryKey>> = objects
            .iter()
            .filter(|record| {
                in_scope(record)
                    && registry_object_is_certificate(&record.key.object)
                    && registry_object_expired_at(record).is_some()
            })
            .map(|record| (bare_key(&record.key), Vec::new()))
            .collect();
        if !referrers.is_empty() {
            for record in objects.iter().filter(|record| in_scope(record)) {
                let source = bare_key(&record.key);
                for target in self.references(RecordSide::Source, record) {
                    let target = bare_key(&target);
                    if target != source
                        && let Some(list) = referrers.get_mut(&target)
                    {
                        list.push(record.key.clone());
                    }
                }
            }
        }
        let mut expired = Vec::new();
        let mut referenced = Vec::new();
        for record in objects {
            if !in_scope(&record) {
                continue;
            }
            if let Some(at) = registry_object_expired_at(&record) {
                let at = Box::<str>::from(at);
                match referrers.remove(&bare_key(&record.key)) {
                    Some(list) if !list.is_empty() => {
                        referenced.push((at, record.key.clone(), list));
                    }
                    _ => {
                        expired.push((at, record.key));
                        continue;
                    }
                }
            }
            if let Some(original) = self.originals.get(&record.key) {
                buf.clear();
                if serde_json::to_writer(&mut buf, &record.json).is_ok()
                    && ContentHash::of(&buf) == original.stored_hash
                {
                    unchanged.insert(record.key.clone());
                }
            }
            let key = object_key(&record.key);
            originals.insert(key.clone(), record.key);
            inputs.push(SourceObject {
                key,
                value: record.json,
            });
        }
        let outcome = self
            .mapping
            .session(self.direction, &self.answers, self.options.clone())
            .with_owners(owners)
            .convert_all(inputs);
        let problems = outcome_problems(&self.mapping, &self.answers, &outcome);
        if !problems.is_empty() {
            return Err(ConversionError::Incomplete(problems));
        }

        let original = |key: &ObjectKey| {
            originals
                .get(key)
                .cloned()
                .or_else(|| registry_key(key))
                .ok_or_else(|| {
                    ConversionError::Failed(
                        format!("{key} has no registry id in the source").into_boxed_str(),
                    )
                })
        };
        let dropped_tasks: FxHashSet<&ObjectKey> = outcome
            .report
            .entries
            .iter()
            .filter(|entry| drops_task(entry))
            .map(|entry| &entry.key)
            .collect();
        let cycles: FxHashMap<&ObjectKey, &Map<String, Value>> = outcome
            .deferred
            .iter()
            .map(|update| (&update.key, &update.properties))
            .collect();
        let mut records = Vec::with_capacity(outcome.objects.len());
        let mut fallbacks = Vec::new();
        let mut restored_cycles: FxHashMap<&ObjectKey, &Value> = FxHashMap::default();
        let mut not_stored = Vec::new();
        let mut not_copied = Vec::new();
        for TargetObject { source, key, value } in &outcome.objects {
            if dropped_tasks.contains(source) {
                not_copied.push((original(source)?, key));
                continue;
            }
            let target = registry_key(key)
                .map(|target| self.output_key(target))
                .ok_or_else(|| {
                    ConversionError::Failed(format!("{key} has no registry id").into_boxed_str())
                })?;
            if self.direction == Direction::Forward && !registry_object_is_stored(&target.object) {
                not_stored.push((original(source)?, target));
                continue;
            }
            let source = original(source)?;
            let json = match self.originals.get(&source) {
                Some(restored) if unchanged.contains(&source) => match cycles.get(key) {
                    Some(properties) => {
                        restored_cycles.insert(key, &restored.json);
                        with_placeholders(&restored.json, value, properties)
                    }
                    None => {
                        if restored.json != *value {
                            fallbacks.push(RegistryRecord {
                                key: target.clone(),
                                json: value.clone(),
                            });
                        }
                        restored.json.clone()
                    }
                },
                _ => value.clone(),
            };
            records.push(ConvertedRecord {
                source,
                record: RegistryRecord { key: target, json },
            });
        }
        let mut deferred = Vec::with_capacity(outcome.deferred.len());
        let (skipped, values): (FxHashSet<ObjectKey>, FxHashMap<&ObjectKey, &Value>) =
            if outcome.deferred.is_empty() {
                Default::default()
            } else {
                (
                    not_stored
                        .iter()
                        .map(|(_, target)| object_key(target))
                        .chain(not_copied.iter().map(|(_, key)| (*key).clone()))
                        .collect(),
                    outcome
                        .objects
                        .iter()
                        .rev()
                        .map(|object| (&object.key, &object.value))
                        .collect(),
                )
            };
        for update in &outcome.deferred {
            if skipped.contains(&update.key) {
                continue;
            }
            let target = registry_key(&update.key)
                .map(|target| self.output_key(target))
                .ok_or_else(|| {
                    ConversionError::Failed(
                        format!("{} has no registry id", update.key).into_boxed_str(),
                    )
                })?;
            let json = match restored_cycles.get(&update.key) {
                Some(restored) => (*restored).clone(),
                None => {
                    let mut json = values
                        .get(&update.key)
                        .map(|value| (*value).clone())
                        .ok_or_else(|| {
                            ConversionError::Failed(
                                format!("deferred update for {} has no object", update.key)
                                    .into_boxed_str(),
                            )
                        })?;
                    if let Value::Object(map) = &mut json {
                        map.extend(update.properties.clone());
                    }
                    json
                }
            };
            deferred.push(RegistryRecord { key: target, json });
        }
        let mut dropped = outcome
            .dropped
            .iter()
            .map(original)
            .collect::<Result<Vec<_>, _>>()?;
        dropped.extend(not_copied.into_iter().map(|(source, _)| source));
        let mut issues: Vec<Issue> = outcome
            .report
            .entries
            .iter()
            .map(|entry| entry_issue(entry, &originals))
            .collect();
        for (at, key) in expired {
            issues.push(Issue::new(
                Severity::Info,
                IssueKind::Dropped,
                Subject::Registry(key.clone()),
                format!(
                    "expired at {at}; Stalwart deletes expired {} objects when it starts",
                    key.object
                ),
            ));
            dropped.push(key);
        }
        for (at, key, list) in referenced {
            let list = list
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            issues.push(Issue::new(
                Severity::Info,
                IssueKind::Changed,
                Subject::Registry(key.clone()),
                format!(
                    "expired at {at} but kept: Stalwart deletes expired {} objects when it starts only when nothing refers to them, and {list} refers to it",
                    key.object
                ),
            ));
        }
        match &self.unconverted {
            Unconverted::Unknown => issues.push(Issue::new(
                Severity::Warning,
                IssueKind::Dropped,
                Subject::None,
                NO_FORWARD_STATE,
            )),
            Unconverted::Restore {
                records: unconverted,
                written,
            } => {
                let taken: FxHashSet<&RegistryKey> = records
                    .iter()
                    .map(|converted| &converted.record.key)
                    .collect();
                for key in written {
                    if categories.contains(object_category(&key.object)) && !taken.contains(key) {
                        issues.push(Issue::new(
                            Severity::Warning,
                            IssueKind::Skipped,
                            Subject::Registry(key.clone()),
                            NOT_RESTORED_DELETED,
                        ));
                    }
                }
                let mut claimed: FxHashSet<(&str, String)> = records
                    .iter()
                    .filter_map(|converted| unique_key_of(&converted.record))
                    .collect();
                let mut pending = Vec::new();
                for record in unconverted {
                    if !categories.contains(object_category(&record.key.object))
                        || taken.contains(&record.key)
                        || registry_object_expired_at(record).is_some()
                    {
                        continue;
                    }
                    if let Some(key) = unique_key_of(record)
                        && !claimed.insert(key.clone())
                    {
                        issues.push(Issue::new(
                            Severity::Warning,
                            IssueKind::Skipped,
                            Subject::Registry(record.key.clone()),
                            format!(
                                "not restored from the --forward-state: v1 or another restored object already holds the unique key {}",
                                key.1
                            ),
                        ));
                        continue;
                    }
                    pending.push((record, self.references(RecordSide::Target, record)));
                }
                let missing = |key: &RegistryKey, restored_keys: &FxHashSet<RegistryKey>| {
                    categories.contains(object_category(&key.object))
                        && !taken.contains(key)
                        && !restored_keys.contains(key)
                };
                let RestorePlan {
                    restored: planned,
                    blocked,
                    restored_keys,
                } = plan_restore(pending, missing, |members| self.restore_plan(members));
                let mut restored = Vec::with_capacity(planned.len());
                for RestoredRecord {
                    record,
                    json,
                    deferred: split,
                } in planned
                {
                    issues.push(Issue::new(
                        Severity::Info,
                        IssueKind::Changed,
                        Subject::Registry(record.key.clone()),
                        RESTORED,
                    ));
                    if split {
                        deferred.push(record.clone());
                    }
                    restored.push(ConvertedRecord {
                        source: record.key.clone(),
                        record: RegistryRecord {
                            key: record.key.clone(),
                            json,
                        },
                    });
                }
                let pending = blocked;
                for (record, references) in pending {
                    let Some(reference) = references
                        .iter()
                        .find(|key| **key != record.key && missing(key, &restored_keys))
                    else {
                        continue;
                    };
                    let reason = if written.contains(reference) {
                        "the migration wrote it to v1 and it was deleted there"
                    } else if unconverted.iter().any(|lost| lost.key == *reference) {
                        "it never reached v1 and could not be restored either"
                    } else {
                        "v1 does not have it"
                    };
                    issues.push(Issue::new(
                        Severity::Warning,
                        IssueKind::Skipped,
                        Subject::Registry(record.key.clone()),
                        format!(
                            "not restored from the --forward-state: it refers to {reference}, and {reason}"
                        ),
                    ));
                }
                records.extend(restored);
            }
        }
        for (source, target) in not_stored {
            issues.push(Issue::new(
                Severity::Warning,
                IssueKind::Dropped,
                Subject::Registry(source.clone()),
                format!(
                    "{} objects are not stored by v1 and cannot be copied",
                    target.object
                ),
            ));
            dropped.push(source);
        }
        Ok(Converted {
            records,
            deferred,
            fallbacks,
            dropped,
            issues,
        })
    }

    fn target_object(&self, object: &str) -> Box<str> {
        let target = self.mapping.target_object(self.direction, object);
        match self.direction {
            Direction::Forward => target,
            Direction::Reverse => target
                .strip_prefix(OBJECT_PREFIX)
                .map_or_else(|| target.clone(), Box::from),
        }
    }

    fn enum_value<'x>(&'x self, name: &str, value: &str) -> EnumValue<'x> {
        match self.mapping.rules(self.direction).enum_rule(name, value) {
            None => EnumValue::Keep,
            Some(EnumRule::Rename(targets)) => targets
                .first()
                .map_or(EnumValue::Keep, |target| EnumValue::Rename(target)),
            Some(EnumRule::Drop) => EnumValue::Drop,
        }
    }

    fn stored_task_id(&self, task: &TaskRecord) -> u64 {
        match self.direction {
            Direction::Forward => singleton_task_id(&task.json).unwrap_or(task.id),
            Direction::Reverse => task.id,
        }
    }

    fn missing_spam_tags(&self, objects: &[RegistryRecord]) -> Vec<RegistryRecord> {
        if self.direction != Direction::Forward {
            return Vec::new();
        }
        let source_tags = objects.iter().filter(|record| {
            record
                .key
                .object
                .strip_prefix(OBJECT_PREFIX)
                .unwrap_or(&record.key.object)
                == SPAM_TAG_OBJECT
        });
        let mut used: FxHashSet<u64> = source_tags
            .clone()
            .filter_map(|record| record.key.id.id())
            .collect();
        self.mapping
            .missing_spam_tags(
                source_tags.filter_map(|record| record.json.get(SPAM_TAG).and_then(Value::as_str)),
            )
            .into_iter()
            .map(|(tag, score)| {
                let mut id = stock_spam_tag_id(tag);
                while !used.insert(id) {
                    id = id.wrapping_add(1) & STOCK_ID_MASK;
                }
                let json = Map::from_iter([
                    ("@type".to_string(), Value::from(SPAM_TAG_SCORE)),
                    (SPAM_TAG.to_string(), Value::from(tag)),
                    ("score".to_string(), Value::from(score)),
                ]);
                RegistryRecord {
                    key: RegistryKey::new(format!("{OBJECT_PREFIX}{SPAM_TAG_OBJECT}"), id),
                    json: Value::Object(json),
                }
            })
            .collect()
    }

    fn references(&self, side: RecordSide, record: &RegistryRecord) -> Vec<RegistryKey> {
        let (version, prefixed) = match (self.direction, side) {
            (Direction::Forward, RecordSide::Target) => (SchemaVersion::V1, true),
            (Direction::Forward, RecordSide::Source) => (SchemaVersion::V016, false),
            (Direction::Reverse, RecordSide::Target) => (SchemaVersion::V016, false),
            (Direction::Reverse, RecordSide::Source) => (SchemaVersion::V1, true),
        };
        self.mapping
            .references(version, &record.key.object, &record.json)
            .into_iter()
            .map(|(object, id)| {
                let object = match (prefixed, object.strip_prefix(OBJECT_PREFIX)) {
                    (false, Some(bare)) => bare,
                    _ => object,
                };
                RegistryKey::new(object, id)
            })
            .collect()
    }

    fn unlinked_objects(&self, keys: &[RegistryKey]) -> FxHashSet<Box<str>> {
        self.reference_targets
            .unlinked(keys.iter().map(|key| &*key.object))
    }

    fn delete_plan(&self, records: Vec<RegistryRecord>) -> RegistryDeletes {
        let mut originals: FxHashMap<ObjectKey, RegistryKey> =
            FxHashMap::with_capacity_and_hasher(records.len(), Default::default());
        let mut aliased = Vec::new();
        let mut objects = Vec::with_capacity(records.len());
        for record in records {
            match originals.entry(object_key(&record.key)) {
                MapEntry::Occupied(_) => aliased.push(record.key),
                MapEntry::Vacant(entry) => {
                    objects.push(TargetObject {
                        source: entry.key().clone(),
                        key: entry.key().clone(),
                        value: record.json,
                    });
                    entry.insert(record.key);
                }
            }
        }
        let plan = self
            .mapping
            .session(self.direction, &self.answers, self.options.clone())
            .delete_plan(objects);
        let updates = plan
            .updates
            .into_iter()
            .filter_map(|update| {
                Some(RegistryPatch {
                    key: originals.get(&update.key)?.clone(),
                    properties: update.properties,
                })
            })
            .collect();
        let order = plan
            .order
            .into_iter()
            .filter_map(|key| originals.remove(&key))
            .chain(aliased)
            .collect();
        RegistryDeletes { updates, order }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mapping::{Answer, PromptId, ToolQuestions};
    use serde_json::json;

    fn options() -> Options {
        Options {
            tool_questions: ToolQuestions::Skip,
            ..Options::default()
        }
    }

    // An object the forward run did not copy is restored, except when v1 holds an object under the same key or name, which wins.
    #[test]
    fn v1_objects_win_over_restored_forward_losses() {
        let mapping = Mapping::embedded().expect("mapping");
        let forward = ForwardState {
            originals: FxHashMap::default(),
            unconverted: vec![
                RegistryRecord {
                    key: RegistryKey::new("Domain", 7),
                    json: json!({"name": "forward.org"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Domain", 8),
                    json: json!({"name": "lost.org"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Domain", 12),
                    json: json!({"name": "lost.org"}),
                },
                RegistryRecord {
                    key: RegistryKey::singleton("Http"),
                    json: json!({"useXForwarded": false}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Domain", 9),
                    json: json!({"name": "v1.org"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("PublicKey", 4),
                    json: json!({"accountId": "e", "key": "k"}),
                },
            ],
            written: vec![RegistryKey::new("Domain", 11)],
        };
        let converter =
            MappingConverter::reverse(mapping, Answers::default(), options(), Some(forward));
        let converted = converter
            .convert(
                vec![
                    RegistryRecord {
                        key: RegistryKey::new("x:Domain", 7),
                        json: json!({"name": "v1.org"}),
                    },
                    RegistryRecord {
                        key: RegistryKey::singleton("x:Http"),
                        json: json!({"useXForwarded": true}),
                    },
                ],
                CategorySet::defaults(),
            )
            .expect("complete conversion");
        let http: Vec<&Value> = converted
            .records
            .iter()
            .filter(|converted| converted.record.key == RegistryKey::singleton("Http"))
            .map(|converted| &converted.record.json["useXForwarded"])
            .collect();
        assert_eq!(http, [&json!(true)]);
        let skipped = |key: RegistryKey, needle: &str| {
            converted.issues.iter().any(|issue| {
                issue.subject == Subject::Registry(key.clone())
                    && issue.severity == Severity::Warning
                    && issue.message.contains(needle)
            })
        };
        assert!(skipped(
            RegistryKey::new("Domain", 9),
            "already holds the unique key name \"v1.org\""
        ));
        assert!(skipped(
            RegistryKey::new("Domain", 12),
            "already holds the unique key name \"lost.org\""
        ));
        assert!(skipped(RegistryKey::new("Domain", 11), "deleted there"));
        assert!(skipped(
            RegistryKey::new("PublicKey", 4),
            "refers to Account/4"
        ));
        assert!(
            !converted
                .records
                .iter()
                .any(|converted| converted.record.key == RegistryKey::new("PublicKey", 4))
        );
        let domains: Vec<(&RegistryKey, &Value)> = converted
            .records
            .iter()
            .filter(|converted| &*converted.record.key.object == "Domain")
            .map(|converted| (&converted.record.key, &converted.record.json["name"]))
            .collect();
        assert_eq!(
            domains,
            [
                (&RegistryKey::new("Domain", 7), &json!("v1.org")),
                (&RegistryKey::new("Domain", 8), &json!("lost.org")),
            ]
        );
    }

    // Unique keys follow the mapping key table: Account and MailingList share name plus domainId, other types use their own key.
    #[test]
    fn restore_keys_follow_the_unique_key_table() {
        let key = |object: &str, json: Value| {
            unique_key_of(&RegistryRecord {
                key: RegistryKey::new(object, 1),
                json,
            })
            .map(|(space, value)| (space.to_owned(), value))
        };
        let john = key("Account", json!({"name": "john", "domainId": "a"}));
        assert!(john.is_some());
        assert_ne!(
            john,
            key("Account", json!({"name": "john", "domainId": "b"}))
        );
        assert_eq!(
            john,
            key("x:Account", json!({"name": "john", "domainId": "a"}))
        );
        assert_eq!(
            john,
            key("MailingList", json!({"name": "john", "domainId": "a"}))
        );
        assert_eq!(
            key("SpamTag", json!({"tag": "x", "name": "y"})),
            key("x:SpamTag", json!({"tag": "x"}))
        );
        assert_ne!(
            key("Domain", json!({"name": "x"})),
            key("SpamRule", json!({"name": "x"}))
        );
        assert_eq!(key("EventTracingLevel", json!({"level": "info"})), None);
        assert_eq!(key("PublicKey", json!({"name": "x"})), None);
    }

    // Renamed objects map to their new name forward and back to the v0.16 name in reverse.
    #[test]
    fn target_objects_follow_renames() {
        let forward = MappingConverter::new(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
        );
        assert_eq!(&*forward.target_object("SpamLlm"), "x:SpamAi");
        assert_eq!(&*forward.target_object("Domain"), "x:Domain");
        let reverse = MappingConverter::reverse(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
            None,
        );
        assert_eq!(&*reverse.target_object("x:SpamAi"), "SpamLlm");
        assert_eq!(&*reverse.target_object("x:Domain"), "Domain");
    }

    #[test]
    fn categories_by_object() {
        assert_eq!(object_category("x:Domain"), Category::Principals);
        assert_eq!(object_category("Account"), Category::Principals);
        assert_eq!(
            object_category("x:SpamTrainingSample"),
            Category::SpamSamples
        );
        assert_eq!(object_category("x:Http"), Category::Settings);
        assert_eq!(object_category("x:Trace"), Category::Telemetry);
    }

    #[test]
    fn keys_round_trip() {
        for key in [
            RegistryKey::singleton("x:Http"),
            RegistryKey::new("x:Domain", 42),
        ] {
            assert_eq!(registry_key(&object_key(&key)), Some(key));
        }
        assert_eq!(
            object_key(&RegistryKey::new("Domain", 1)).object.as_ref(),
            "x:Domain"
        );
    }

    #[test]
    fn unanswered_questions_make_the_conversion_incomplete() {
        let mapping = Mapping::embedded().expect("mapping");
        let converter = MappingConverter::new(mapping, Answers::default(), options());
        let objects = vec![RegistryRecord {
            key: RegistryKey::singleton("x:Http"),
            json: json!({"useXForwarded": true}),
        }];
        let Err(ConversionError::Incomplete(problems)) =
            converter.convert(objects, CategorySet::defaults())
        else {
            panic!("expected an incomplete conversion");
        };
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("http_forwarded"))
        );
    }

    #[test]
    fn converts_with_answers_and_keeps_source_keys() {
        let mapping = Mapping::embedded().expect("mapping");
        let objects = vec![
            RegistryRecord {
                key: RegistryKey::singleton("Http"),
                json: json!({"useXForwarded": false}),
            },
            RegistryRecord {
                key: RegistryKey::new("Domain", 7),
                json: json!({"name": "example.org"}),
            },
        ];
        let probe = mapping
            .session(Direction::Forward, &Answers::default(), options())
            .convert_all(
                objects
                    .iter()
                    .map(|record| SourceObject {
                        key: object_key(&record.key),
                        value: record.json.clone(),
                    })
                    .collect(),
            );
        let mut answers = Answers::default();
        for question in &probe.report.questions {
            answers.set(
                question.prompt,
                question.key.clone(),
                question.defaults.clone(),
            );
        }
        if answers.get(PromptId::ChangedDefaults, None).is_none() {
            answers.set(PromptId::ChangedDefaults, None, Answer::new());
        }
        let converter = MappingConverter::new(mapping, answers, options());
        let converted = converter
            .convert(objects, CategorySet::defaults())
            .expect("complete conversion");
        assert!(
            converted
                .records
                .iter()
                .any(|record| record.source == RegistryKey::new("Domain", 7))
        );
        let deletes = converter.delete_plan(vec![
            RegistryRecord {
                key: RegistryKey::new("x:Domain", 7),
                json: Value::Null,
            },
            RegistryRecord {
                key: RegistryKey::singleton("x:Http"),
                json: Value::Null,
            },
        ]);
        assert_eq!(deletes.order.len(), 2);

        let filtered = converter
            .convert(
                vec![RegistryRecord {
                    key: RegistryKey::new("Domain", 7),
                    json: json!({"name": "example.org"}),
                }],
                CategorySet::empty(),
            )
            .expect("nothing to convert");
        assert!(
            !filtered
                .records
                .iter()
                .any(|record| record.source == RegistryKey::new("Domain", 7))
        );
    }

    fn task_status() -> Value {
        json!({"@type": "Pending", "createdAt": "2026-01-01T00:00:00Z", "due": "2026-01-02T00:00:00Z"})
    }

    fn task_converter(objects: &[RegistryRecord]) -> (MappingConverter, CategorySet) {
        let mapping = Mapping::embedded().expect("mapping");
        let probe = mapping
            .session(Direction::Forward, &Answers::default(), options())
            .convert_all(
                objects
                    .iter()
                    .map(|record| SourceObject {
                        key: object_key(&record.key),
                        value: record.json.clone(),
                    })
                    .collect(),
            );
        let mut answers = Answers::default();
        for question in &probe.report.questions {
            answers.set(
                question.prompt,
                question.key.clone(),
                question.defaults.clone(),
            );
        }
        if answers.get(PromptId::ChangedDefaults, None).is_none() {
            answers.set(PromptId::ChangedDefaults, None, Answer::new());
        }
        let mut categories = CategorySet::defaults();
        categories.insert(Category::Tasks);
        (
            MappingConverter::new(mapping, answers, options()),
            categories,
        )
    }

    // Tasks convert with the registry graph, so their references resolve; dropped variants vanish.
    #[test]
    fn tasks_convert_with_the_registry_graph() {
        let status = task_status();
        let objects = vec![
            RegistryRecord {
                key: RegistryKey::new("Domain", 7),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Task", 3),
                json: json!({"@type": "DkimManagement", "domainId": "h", "status": status}),
            },
            RegistryRecord {
                key: RegistryKey::new("Task", 5),
                json: json!({"@type": "IndexDocument", "accountId": "b", "documentId": 1, "documentType": "email", "status": status}),
            },
        ];
        let (converter, categories) = task_converter(&objects);
        let converted = converter
            .convert(objects, categories)
            .expect("complete conversion");
        let tasks: Vec<&RegistryRecord> = converted
            .records
            .iter()
            .map(|record| &record.record)
            .filter(|record| &*record.key.object == "x:Task")
            .collect();
        assert_eq!(tasks.len(), 1, "{tasks:?} {:?}", converted.issues);
        assert_eq!(tasks[0].key, RegistryKey::new("x:Task", 3));
        assert_eq!(tasks[0].json["domainId"], "h");
        assert_eq!(tasks[0].json["@type"], "DkimManagement");
    }

    // An object owned by an account the source no longer lists is dropped as an orphan instead of blocking the conversion.
    #[test]
    fn objects_of_unlisted_accounts_are_dropped_as_orphans() {
        let objects = vec![
            RegistryRecord {
                key: RegistryKey::new("Domain", 7),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("PublicKey", 4),
                json: json!({"accountId": "e", "description": "gone", "key": "k"}),
            },
        ];
        let (converter, categories) = task_converter(&objects);
        let converted = converter
            .convert(objects, categories)
            .expect("complete conversion");
        let key = RegistryKey::new("PublicKey", 4);
        assert!(converted.dropped.contains(&key), "{:?}", converted.issues);
        assert!(
            converted
                .issues
                .iter()
                .any(|issue| issue.subject == Subject::Registry(key.clone())
                    && issue.severity == Severity::Warning
                    && issue.message.contains("is not listed by the source")),
            "{:?}",
            converted.issues
        );
    }

    // Expired blocked and allowed IPs are dropped because Stalwart deletes them when it starts; unexpired ones are kept.
    #[test]
    fn expired_ip_objects_are_dropped() {
        let ip = |object: &str, id: u64, expires: Option<&str>| {
            let mut json = json!({"address": format!("192.0.2.{id}"), "createdAt": "2024-01-01T00:00:00Z", "reason": "authFailure"});
            if object == "AllowedIp" {
                json["reason"] = json!("trusted");
            }
            if let Some(expires) = expires {
                json["expiresAt"] = json!(expires);
            }
            RegistryRecord {
                key: RegistryKey::new(object, id),
                json,
            }
        };
        let objects = vec![
            ip("BlockedIp", 1, Some("2024-01-01T01:00:00Z")),
            ip("AllowedIp", 2, Some("2024-01-01T01:00:00Z")),
            ip("BlockedIp", 3, Some("2999-01-01T00:00:00Z")),
            ip("BlockedIp", 4, None),
        ];
        let (converter, categories) = task_converter(&objects);
        let converted = converter
            .convert(objects, categories)
            .expect("complete conversion");
        for key in [
            RegistryKey::new("BlockedIp", 1),
            RegistryKey::new("AllowedIp", 2),
        ] {
            assert!(converted.dropped.contains(&key), "{:?}", converted.dropped);
            assert!(
                converted.issues.iter().any(|issue| issue.subject
                    == Subject::Registry(key.clone())
                    && issue.severity == Severity::Info
                    && issue.kind == IssueKind::Dropped
                    && issue.message.contains("expired at 2024-01-01T01:00:00Z")),
                "{:?}",
                converted.issues
            );
        }
        let kept: Vec<&RegistryKey> = converted
            .records
            .iter()
            .map(|converted| &converted.record.key)
            .filter(|key| key.object.ends_with("Ip"))
            .collect();
        assert_eq!(
            kept,
            [
                &RegistryKey::new("x:BlockedIp", 3),
                &RegistryKey::new("x:BlockedIp", 4)
            ],
            "{:?}",
            converted.issues
        );
    }

    // Expired certificates are dropped like Stalwart does at startup, except file-backed ones and those another object refers to.
    #[test]
    fn expired_certificates_follow_the_startup_purge() {
        let certificate = |id: u64, not_valid_after: &str, file: bool| {
            let text = if file {
                json!({"@type": "File", "filePath": "/etc/cert.pem"})
            } else {
                json!({"@type": "Text", "value": "-----BEGIN CERTIFICATE-----"})
            };
            RegistryRecord {
                key: RegistryKey::new("Certificate", id),
                json: json!({"certificate": text, "privateKey": {"@type": "Text", "secret": "key"}, "subjectAlternativeNames": {"mail.example.org": true}, "notValidAfter": not_valid_after, "notValidBefore": "2023-01-01T00:00:00Z", "issuer": "CA"}),
            }
        };
        let objects = vec![
            RegistryRecord {
                key: RegistryKey::new("Domain", 7),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::singleton("SystemSettings"),
                json: json!({"defaultHostname": "mail.example.org", "defaultDomainId": "h", "defaultCertificateId": "c"}),
            },
            certificate(1, "2024-01-01T00:00:00Z", false),
            certificate(2, "2024-01-01T00:00:00Z", false),
            certificate(3, "2024-01-01T00:00:00Z", true),
            certificate(4, "2999-01-01T00:00:00Z", false),
        ];
        let (converter, categories) = task_converter(&objects);
        let converted = converter
            .convert(objects, categories)
            .expect("complete conversion");
        let dropped = RegistryKey::new("Certificate", 1);
        assert_eq!(
            converted
                .dropped
                .iter()
                .filter(|key| key.object.ends_with("Certificate"))
                .collect::<Vec<_>>(),
            [&dropped],
            "{:?}",
            converted.issues
        );
        assert!(
            converted
                .issues
                .iter()
                .any(|issue| issue.subject == Subject::Registry(dropped.clone())
                    && issue.kind == IssueKind::Dropped
                    && issue.message.contains("expired at 2024-01-01T00:00:00Z")),
            "{:?}",
            converted.issues
        );
        assert!(
            converted.issues.iter().any(|issue| issue.subject
                == Subject::Registry(RegistryKey::new("Certificate", 2))
                && issue.severity == Severity::Info
                && issue.message.contains("but kept")
                && issue.message.contains("SystemSettings")),
            "{:?}",
            converted.issues
        );
        let mut kept: Vec<&RegistryKey> = converted
            .records
            .iter()
            .map(|converted| &converted.record.key)
            .filter(|key| key.object.ends_with("Certificate"))
            .collect();
        kept.sort_unstable();
        assert_eq!(
            kept,
            [
                &RegistryKey::new("x:Certificate", 2),
                &RegistryKey::new("x:Certificate", 3),
                &RegistryKey::new("x:Certificate", 4)
            ],
            "{:?}",
            converted.issues
        );
    }

    // Archived items of an account the source no longer lists (deleted in v0.16, which keeps its archive) are dropped with a warning; those of a listed account are kept.
    #[test]
    fn archived_items_of_deleted_accounts_are_dropped_as_orphans() {
        let archived = |id: u64, kind: &str, account: &str| RegistryRecord {
            key: RegistryKey::new("ArchivedItem", id),
            json: json!({"@type": kind, "accountId": account, "archivedAt": "2026-10-22T08:23:21Z", "archivedUntil": "2026-11-21T08:23:21Z", "receivedAt": "2026-10-01T00:00:00Z", "size": 10, "status": "archived"}),
        };
        let objects = vec![
            RegistryRecord {
                key: RegistryKey::new("Domain", 7),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Account", 2),
                json: json!({"@type": "User", "name": "john", "domainId": "h"}),
            },
            archived(10, "Email", "e"),
            archived(11, "SieveScript", "e"),
            archived(12, "CalendarEvent", "e"),
            archived(13, "ContactCard", "e"),
            archived(14, "FileNode", "e"),
            archived(15, "Email", "c"),
        ];
        let (converter, categories) = task_converter(&objects);
        let converted = converter
            .convert(objects, categories)
            .expect("complete conversion");
        for id in 10..=14 {
            let key = RegistryKey::new("ArchivedItem", id);
            assert!(
                converted.dropped.contains(&key),
                "{id}: {:?}",
                converted.issues
            );
            assert!(
                converted
                    .issues
                    .iter()
                    .any(|issue| issue.subject == Subject::Registry(key.clone())
                        && issue.severity == Severity::Warning
                        && issue.message.contains("is not listed by the source")),
                "{id}: {:?}",
                converted.issues
            );
        }
        let kept = RegistryKey::new("ArchivedItem", 15);
        assert!(!converted.dropped.contains(&kept), "{:?}", converted.issues);
        assert!(
            converted.records.iter().any(|record| record.source == kept),
            "{:?}",
            converted.issues
        );
    }

    // A task that references an account that is not migrated is dropped with a warning instead of failing the run.
    #[test]
    fn tasks_of_deleted_accounts_are_dropped() {
        let status = task_status();
        let objects = vec![
            RegistryRecord {
                key: RegistryKey::new("Domain", 7),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Task", 3),
                json: json!({"@type": "DkimManagement", "domainId": "h", "status": status}),
            },
            RegistryRecord {
                key: RegistryKey::new("Task", 4),
                json: json!({"@type": "DestroyAccount", "accountId": "m", "accountName": "gone", "accountDomainId": "h", "status": status}),
            },
        ];
        let (converter, categories) = task_converter(&objects);
        let converted = converter
            .convert(objects, categories)
            .expect("complete conversion");
        let task = RegistryKey::new("Task", 4);
        assert!(converted.dropped.contains(&task), "{:?}", converted.dropped);
        assert!(
            converted
                .records
                .iter()
                .all(|record| record.source != task && record.record.key.id != task.id)
        );
        assert!(
            converted
                .deferred
                .iter()
                .all(|record| record.key.id != task.id)
        );
        let issues: Vec<&Issue> = converted
            .issues
            .iter()
            .filter(|issue| issue.subject == Subject::Registry(task.clone()))
            .collect();
        assert!(!issues.is_empty());
        assert!(
            issues.iter().all(
                |issue| issue.severity == Severity::Warning && issue.kind == IssueKind::Dropped
            ),
            "{issues:?}"
        );
        assert!(
            converted
                .records
                .iter()
                .any(|record| record.record.key == RegistryKey::new("x:Task", 3))
        );
    }

    fn unchanged_since_forward(
        records: &[RegistryRecord],
        originals: &[(RegistryKey, Value)],
    ) -> ForwardState {
        let hashes: FxHashMap<&RegistryId, ContentHash> = records
            .iter()
            .map(|record| {
                (
                    &record.key.id,
                    ContentHash::of(&serde_json::to_vec(&record.json).expect("json")),
                )
            })
            .collect();
        ForwardState {
            originals: originals
                .iter()
                .map(|(key, json)| {
                    (
                        key.clone(),
                        Original {
                            stored_hash: hashes[&key.id],
                            json: json.clone(),
                        },
                    )
                })
                .collect(),
            ..ForwardState::default()
        }
    }

    fn delete_position(plan: &RegistryDeletes, object: &str, id: u64) -> usize {
        plan.order
            .iter()
            .position(|key| *key == RegistryKey::new(object, id))
            .unwrap_or_else(|| panic!("{object}/{id} is not deleted: {plan:?}"))
    }

    // Forward deletes follow the stored references, also to objects the write rank does not list: an account goes before the public key and the domain it links to.
    #[test]
    fn forward_deletes_follow_stored_references() {
        let converter = MappingConverter::new(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
        );
        let plan = converter.delete_plan(vec![
            RegistryRecord {
                key: RegistryKey::new("x:PublicKey", 3),
                json: json!({"description": "alice", "key": "-----BEGIN PGP-----"}),
            },
            RegistryRecord {
                key: RegistryKey::new("x:Domain", 1),
                json: json!({"name": "example.com"}),
            },
            RegistryRecord {
                key: RegistryKey::new("x:Account", 2),
                json: json!({
                    "@type": "User",
                    "name": "alice",
                    "domainId": "b",
                    "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}
                }),
            },
        ]);
        assert!(plan.updates.is_empty(), "{plan:?}");
        let account = delete_position(&plan, "x:Account", 2);
        assert!(
            account < delete_position(&plan, "x:PublicKey", 3),
            "{plan:?}"
        );
        assert!(account < delete_position(&plan, "x:Domain", 1), "{plan:?}");
    }

    // Rollback deletes use bare v0.16 names and still follow the stored references: an account before the public key the write rank does not list, accounts before their domain, the domain before its tenant.
    #[test]
    fn rollback_deletes_follow_stored_references() {
        let converter = MappingConverter::reverse(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
            None,
        );
        let plan = converter.delete_plan(vec![
            RegistryRecord {
                key: RegistryKey::new("Tenant", 4),
                json: json!({"name": "acme"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Domain", 1),
                json: json!({"name": "example.com", "memberTenantId": "e"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Account", 2),
                json: json!({
                    "@type": "User",
                    "name": "alice",
                    "domainId": "b",
                    "memberTenantId": "e",
                    "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}
                }),
            },
            RegistryRecord {
                key: RegistryKey::new("PublicKey", 3),
                json: json!({"description": "alice", "key": "-----BEGIN PGP-----"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Account", 5),
                json: json!({"@type": "User", "name": "bob", "domainId": "b"}),
            },
        ]);
        let domain = delete_position(&plan, "Domain", 1);
        let account = delete_position(&plan, "Account", 2);
        assert!(account < domain, "{plan:?}");
        assert!(account < delete_position(&plan, "PublicKey", 3), "{plan:?}");
        assert!(delete_position(&plan, "Account", 5) < domain, "{plan:?}");
        assert!(domain < delete_position(&plan, "Tenant", 4), "{plan:?}");
    }

    // A deleted object is read for the delete plan only when its type can reference a type that is deleted too, in both directions.
    #[test]
    fn delete_reads_follow_the_target_schema_references() {
        let names = |unlinked: FxHashSet<Box<str>>| {
            let mut names: Vec<Box<str>> = unlinked.into_iter().collect();
            names.sort_unstable();
            names
        };
        let keys = |objects: &[&str]| -> Vec<RegistryKey> {
            objects
                .iter()
                .zip(1..)
                .map(|(object, id)| RegistryKey::new(*object, id))
                .collect()
        };
        let forward = MappingConverter::new(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
        );
        assert_eq!(
            names(forward.unlinked_objects(&keys(&[
                "x:DmarcExternalReport",
                "x:TlsExternalReport",
                "x:DmarcExternalReport"
            ]))),
            ["x:DmarcExternalReport".into(), "x:TlsExternalReport".into()] as [Box<str>; 2]
        );
        let with_tenant =
            names(forward.unlinked_objects(&keys(&["x:DmarcExternalReport", "x:Tenant"])));
        assert!(
            !with_tenant.contains(&"x:DmarcExternalReport".into()),
            "{with_tenant:?}"
        );
        let with_key =
            names(forward.unlinked_objects(&keys(&["x:Account", "x:PublicKey", "x:Unknown"])));
        assert!(!with_key.contains(&"x:Account".into()), "{with_key:?}");
        assert!(!with_key.contains(&"x:Unknown".into()), "{with_key:?}");
        let reverse = MappingConverter::reverse(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
            None,
        );
        assert_eq!(
            names(reverse.unlinked_objects(&keys(&["DmarcExternalReport"]))),
            ["DmarcExternalReport".into()] as [Box<str>; 1]
        );
        assert!(
            !names(reverse.unlinked_objects(&keys(&["Account", "Domain"])))
                .contains(&"Account".into())
        );
    }

    // An account and its public key that link to each other are unlinked first: the plan writes one of them with a placeholder, then deletes both.
    #[test]
    fn deletes_in_a_reference_cycle_are_unlinked_first() {
        let converter = MappingConverter::new(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
        );
        let account = json!({
            "@type": "User",
            "name": "alice",
            "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}
        });
        let public_key = json!({"accountId": "c", "description": "alice", "key": "k"});
        let plan = converter.delete_plan(vec![
            RegistryRecord {
                key: RegistryKey::new("x:PublicKey", 3),
                json: public_key.clone(),
            },
            RegistryRecord {
                key: RegistryKey::new("x:Account", 2),
                json: account.clone(),
            },
        ]);
        assert_eq!(plan.order.len(), 2, "{plan:?}");
        let [unlinked] = plan.updates.as_slice() else {
            panic!("one unlink expected: {plan:?}");
        };
        assert_eq!(unlinked.key, plan.order[1], "{plan:?}");
        let stored = if unlinked.key.object.as_ref() == "x:Account" {
            &account
        } else {
            &public_key
        };
        assert!(!unlinked.properties.is_empty(), "{plan:?}");
        for (name, value) in &unlinked.properties {
            assert_ne!(
                stored.get(name),
                Some(value),
                "{name} is a placeholder: {plan:?}"
            );
        }
    }

    // A restored original in a reference cycle is written with the conversion's placeholder first, then patched with the full original.
    #[test]
    fn restored_originals_keep_the_cycle_split() {
        let v1 = vec![
            RegistryRecord {
                key: RegistryKey::new("x:Domain", 1),
                json: json!({"name": "example.com", "isEnabled": true}),
            },
            RegistryRecord {
                key: RegistryKey::new("x:Account", 2),
                json: json!({
                    "@type": "User",
                    "name": "alice",
                    "domainId": "b",
                    "emailAddress": "alice@example.com",
                    "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}
                }),
            },
            RegistryRecord {
                key: RegistryKey::new("x:PublicKey", 3),
                json: json!({"accountId": "c", "description": "alice", "key": "-----BEGIN PGP-----"}),
            },
        ];
        let account = json!({
            "@type": "User",
            "name": "alice",
            "description": "original",
            "domainId": "b",
            "emailAddress": "alice@example.com",
            "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}
        });
        let domain = json!({"name": "example.com", "enable": true, "original": true});
        let forward = unchanged_since_forward(
            &v1,
            &[
                (RegistryKey::new("x:Domain", 1), domain.clone()),
                (RegistryKey::new("x:Account", 2), account.clone()),
            ],
        );
        let converter = MappingConverter::reverse(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
            Some(forward),
        );
        let converted = converter
            .convert(v1, CategorySet::defaults())
            .expect("complete conversion");
        let record = |key: RegistryKey| {
            converted
                .records
                .iter()
                .find(|converted| converted.record.key == key)
                .map(|converted| &converted.record.json)
                .expect("record")
        };
        let first = record(RegistryKey::new("Account", 2));
        assert_eq!(first["description"], "original");
        assert_eq!(first["encryptionAtRest"], json!({"@type": "Disabled"}));
        assert_eq!(
            converted.deferred,
            [RegistryRecord {
                key: RegistryKey::new("Account", 2),
                json: account,
            }]
        );
        assert_eq!(record(RegistryKey::new("Domain", 1)), &domain);
        let fallback: Vec<&RegistryRecord> = converted
            .fallbacks
            .iter()
            .filter(|fallback| fallback.key == RegistryKey::new("Domain", 1))
            .collect();
        assert!(
            fallback.len() == 1 && fallback[0].json.get("original").is_none(),
            "{fallback:?}"
        );
        assert!(
            !converted
                .fallbacks
                .iter()
                .any(|fallback| fallback.key == RegistryKey::new("Account", 2))
        );
    }

    fn restore_only(unconverted: Vec<RegistryRecord>, categories: CategorySet) -> Converted {
        let forward = ForwardState {
            unconverted,
            ..ForwardState::default()
        };
        MappingConverter::reverse(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
            Some(forward),
        )
        .convert(Vec::new(), categories)
        .expect("complete conversion")
    }

    fn restored(converted: &Converted) -> Vec<&RegistryKey> {
        converted
            .records
            .iter()
            .map(|converted| &converted.record.key)
            .collect()
    }

    // A lost object whose Stalwart tenant (memberTenantId) is gone in v1 is not restored.
    #[test]
    fn restore_checks_the_member_tenant() {
        let converted = restore_only(
            vec![RegistryRecord {
                key: RegistryKey::new("Domain", 8),
                json: json!({"name": "lost.org", "memberTenantId": "e"}),
            }],
            CategorySet::defaults(),
        );
        assert!(restored(&converted).is_empty(), "{converted:?}");
        assert!(converted.issues.iter().any(|issue| {
            issue.subject == Subject::Registry(RegistryKey::new("Domain", 8))
                && issue.message.contains("refers to Tenant/4")
        }));
    }

    // Two lost objects that refer to each other are restored as a group: one with a cycle placeholder, then its full value.
    #[test]
    fn lost_objects_in_a_reference_cycle_are_restored_together() {
        let account = json!({"@type": "User", "name": "erin",
            "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}});
        let converted = restore_only(
            vec![
                RegistryRecord {
                    key: RegistryKey::new("PublicKey", 3),
                    json: json!({"accountId": "c", "description": "erin", "key": "k"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Account", 2),
                    json: account.clone(),
                },
            ],
            CategorySet::defaults(),
        );
        assert_eq!(
            restored(&converted),
            [
                &RegistryKey::new("Account", 2),
                &RegistryKey::new("PublicKey", 3)
            ],
            "{:?}",
            converted.issues
        );
        assert_eq!(
            converted.records[0].record.json["encryptionAtRest"],
            json!({"@type": "Disabled"})
        );
        assert_eq!(
            converted.deferred,
            [RegistryRecord {
                key: RegistryKey::new("Account", 2),
                json: account,
            }]
        );
    }

    // A lost object blocked by a missing reference says whether v1 deleted it or never had it.
    #[test]
    fn unrestorable_objects_name_why_the_reference_is_missing() {
        let forward = ForwardState {
            unconverted: vec![
                RegistryRecord {
                    key: RegistryKey::new("Domain", 8),
                    json: json!({"name": "a.org", "memberTenantId": "e"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Domain", 9),
                    json: json!({"name": "b.org", "memberTenantId": "f"}),
                },
            ],
            written: vec![RegistryKey::new("Tenant", 4)],
            ..ForwardState::default()
        };
        let converted = MappingConverter::reverse(
            Mapping::embedded().expect("mapping"),
            Answers::default(),
            options(),
            Some(forward),
        )
        .convert(Vec::new(), CategorySet::defaults())
        .expect("complete conversion");
        let message = |id: u64| {
            converted
                .issues
                .iter()
                .find(|issue| issue.subject == Subject::Registry(RegistryKey::new("Domain", id)))
                .map(|issue| issue.message.to_string())
                .unwrap_or_default()
        };
        assert!(message(8).contains("deleted there"), "{}", message(8));
        assert!(message(9).contains("v1 does not have it"), "{}", message(9));
    }

    // Lost objects that refer to each other are restored together, in dependency order.
    #[test]
    fn restore_counts_objects_restored_in_the_same_pass() {
        let converted = restore_only(
            vec![
                RegistryRecord {
                    key: RegistryKey::new("MailingList", 3),
                    json: json!({"name": "list", "domainId": "h"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Domain", 7),
                    json: json!({"name": "lost.org"}),
                },
            ],
            CategorySet::defaults(),
        );
        assert_eq!(
            restored(&converted),
            [
                &RegistryKey::new("Domain", 7),
                &RegistryKey::new("MailingList", 3)
            ]
        );
    }

    // A reference into a category the rollback does not copy does not block a restore.
    #[test]
    fn references_into_excluded_categories_are_satisfied() {
        let mut categories = CategorySet::defaults();
        categories.remove(Category::Principals);
        let converted = restore_only(
            vec![RegistryRecord {
                key: RegistryKey::new("SpamTrainingSample", 5),
                json: json!({"accountId": "z", "blobId": "x"}),
            }],
            categories,
        );
        assert_eq!(
            restored(&converted),
            [&RegistryKey::new("SpamTrainingSample", 5)]
        );
    }

    // The reference walk follows the schema: tenants by memberTenantId, nested and set references, never Azure tenantId strings.
    #[test]
    fn references_follow_the_schema() {
        let mapping = Mapping::embedded().expect("mapping");
        for version in [SchemaVersion::V016, SchemaVersion::V1] {
            let fields = mapping.reference_fields(version);
            let has = |object: &str, path: &str| {
                fields
                    .iter()
                    .any(|(name, field)| &**name == object && &**field == path)
            };
            assert!(has("x:Account", "memberTenantId"), "{fields:?}");
            assert!(has("x:SystemSettings", "defaultDomainId"), "{fields:?}");
            assert!(has("x:Account", "aliases/*/domainId"), "{fields:?}");
            assert!(
                !fields
                    .iter()
                    .any(|(name, field)| &**name == "x:DnsServer" && &**field == "tenantId"),
                "{fields:?}"
            );
        }
        let converter = MappingConverter::new(mapping, Answers::default(), options());
        let mut references = converter.references(
            RecordSide::Target,
            &RegistryRecord {
                key: RegistryKey::singleton("x:SystemSettings"),
                json: json!({"defaultDomainId": "c"}),
            },
        );
        references.extend(converter.references(
            RecordSide::Target,
            &RegistryRecord {
                key: RegistryKey::new("x:DnsServer", 1),
                json: json!({"@type": "AzureDns", "tenantId": "b"}),
            },
        ));
        assert_eq!(references, [RegistryKey::new("x:Domain", 2)]);
    }
}
