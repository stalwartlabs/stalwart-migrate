/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
};

use model::{
    CategorySet, GlobalBatch, GlobalCategory, InternalReportRecord, QueuedMessageRecord,
    RegistryKey, RegistryRecord, ReportKind, Source, Subject, TaskRecord, TelemetryKind,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;
use source_v1::{is_derived_task_id, is_singleton_task};
use state::ContentHash;

use super::{Findings, mismatch};
use crate::orchestrator::{
    RegistryConverter,
    error::RunError,
    global::{REPORT, convert_internal_report, remap_telemetry},
    retry::{RetryPolicy, retry},
    tasks::{ConvertedTasks, TASK_CONVERSION_CHUNK, TaskConversion, is_copied},
};

const MAX_ROWS_PER_CATEGORY: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalCheck {
    Shared,
    Final,
}

impl GlobalCheck {
    fn includes(self, category: GlobalCategory) -> bool {
        match (self, category) {
            (_, GlobalCategory::SpamModel) => false,
            (GlobalCheck::Shared, category) => category == GlobalCategory::Telemetry,
            (GlobalCheck::Final, _) => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct GlobalKey {
    tag: u8,
    id: u64,
    name: &'static str,
}

impl GlobalKey {
    fn subject(self) -> Subject {
        Subject::Registry(RegistryKey::new(self.name, self.id))
    }

    fn registry_key(self) -> RegistryKey {
        RegistryKey::new(self.name, self.id)
    }
}

#[derive(Debug, PartialEq)]
enum Entry {
    Json(Value),
    Queue(Box<QueuedMessageRecord>),
    Report(InternalReportRecord),
}

const DMARC_ROWS: &str = "records";
const DMARC_COUNT: &str = "count";
const TLS_ROWS: &str = "policies";
const TLS_IDENTIFIERS: &str = "policyIdentifiers";
const TLS_FAILURES: &str = "failureDetails";
const TLS_FAILURE_COUNT: &str = "failedSessionCount";

const fn report_object(kind: ReportKind) -> &'static str {
    match kind {
        ReportKind::Dmarc => "DmarcInternalReport",
        ReportKind::Tls => "TlsInternalReport",
    }
}

fn report_rows(rows: Value) -> Vec<Value> {
    match rows {
        Value::Array(rows) => rows,
        Value::Object(rows) => rows.into_iter().map(|(_, row)| row).collect(),
        _ => Vec::new(),
    }
}

fn comparable_report(kind: ReportKind, mut json: Value) -> Value {
    let Some(fields) = json.as_object_mut() else {
        return json;
    };
    if kind == ReportKind::Tls {
        fields.remove(TLS_IDENTIFIERS);
    }
    let Some(report) = fields.get_mut(REPORT).and_then(Value::as_object_mut) else {
        return json;
    };
    match kind {
        ReportKind::Dmarc => {
            let mut merged: BTreeMap<String, u64> = BTreeMap::new();
            for mut row in report
                .remove(DMARC_ROWS)
                .map(report_rows)
                .unwrap_or_default()
            {
                let count = row
                    .as_object_mut()
                    .and_then(|row| row.remove(DMARC_COUNT))
                    .and_then(|count| count.as_u64())
                    .unwrap_or(0);
                if count > 0 {
                    let total = merged.entry(row.to_string()).or_insert(0);
                    *total = total.saturating_add(count);
                }
            }
            report.insert(
                DMARC_ROWS.into(),
                Value::Object(
                    merged
                        .into_iter()
                        .map(|(row, count)| (row, Value::from(count)))
                        .collect(),
                ),
            );
        }
        ReportKind::Tls => {
            let mut policies: Vec<String> = report
                .remove(TLS_ROWS)
                .map(report_rows)
                .unwrap_or_default()
                .into_iter()
                .map(|mut policy| {
                    if let Some(policy) = policy.as_object_mut() {
                        let mut details: Vec<String> = policy
                            .remove(TLS_FAILURES)
                            .map(report_rows)
                            .unwrap_or_default()
                            .iter()
                            .filter(|detail| {
                                detail.get(TLS_FAILURE_COUNT).and_then(Value::as_u64) != Some(0)
                            })
                            .map(Value::to_string)
                            .collect();
                        details.sort_unstable();
                        policy.insert(
                            TLS_FAILURES.into(),
                            Value::Array(details.into_iter().map(Value::String).collect()),
                        );
                    }
                    policy.to_string()
                })
                .collect();
            policies.sort_unstable();
            report.insert(
                TLS_ROWS.into(),
                Value::Array(policies.into_iter().map(Value::String).collect()),
            );
        }
    }
    json
}

enum Shape {
    Leaf,
    Record(BTreeMap<String, Shape>),
    List(Box<Shape>),
}

impl Shape {
    fn of(value: &Value) -> Option<Shape> {
        match value {
            Value::Null => None,
            Value::Array(items) => Shape::list(items.iter()),
            Value::Object(map) if map.is_empty() => None,
            Value::Object(map)
                if map
                    .keys()
                    .all(|key| key.bytes().all(|byte| byte.is_ascii_digit()))
                    || map.values().all(|value| *value == Value::Bool(true)) =>
            {
                Shape::list(map.values())
            }
            Value::Object(map) => Some(Shape::Record(
                map.iter()
                    .filter_map(|(key, value)| Some((key.clone(), Shape::of(value)?)))
                    .collect(),
            )),
            _ => Some(Shape::Leaf),
        }
    }

    fn list<'v>(items: impl Iterator<Item = &'v Value>) -> Option<Shape> {
        items
            .filter_map(Shape::of)
            .reduce(Shape::merge)
            .map(|inner| Shape::List(Box::new(inner)))
    }

    fn merge(self, other: Shape) -> Shape {
        match (self, other) {
            (Shape::Record(mut left), Shape::Record(right)) => {
                for (key, shape) in right {
                    let merged = match left.remove(&key) {
                        Some(previous) => previous.merge(shape),
                        None => shape,
                    };
                    left.insert(key, merged);
                }
                Shape::Record(left)
            }
            (Shape::List(left), Shape::List(right)) => Shape::List(Box::new(left.merge(*right))),
            (record @ Shape::Record(_), _) | (_, record @ Shape::Record(_)) => record,
            (list @ Shape::List(_), _) | (_, list @ Shape::List(_)) => list,
            (Shape::Leaf, Shape::Leaf) => Shape::Leaf,
        }
    }

    fn missing_in(&self, output: &Shape, path: &mut String) -> bool {
        match (self, output) {
            (Shape::Record(input), Shape::Record(output)) => {
                for (key, shape) in input {
                    let start = path.len();
                    if !path.is_empty() {
                        path.push('/');
                    }
                    path.push_str(key);
                    match output.get(key) {
                        None => return true,
                        Some(found) if shape.missing_in(found, path) => return true,
                        Some(_) => path.truncate(start),
                    }
                }
                false
            }
            (Shape::List(input), Shape::List(output)) => input.missing_in(output, path),
            _ => false,
        }
    }
}

fn ignored_property(input: &Value, output: &Value) -> Option<String> {
    let input = Shape::of(input)?;
    let output = Shape::of(output)?;
    let mut path = String::new();
    input.missing_in(&output, &mut path).then_some(path)
}

fn telemetry_tag(kind: TelemetryKind) -> u8 {
    match kind {
        TelemetryKind::Span => 0,
        TelemetryKind::Metric => 1,
    }
}

fn report_tag(kind: ReportKind) -> u8 {
    match kind {
        ReportKind::Dmarc => 0,
        ReportKind::Tls => 1,
    }
}

fn extend(buffer: &mut VecDeque<(GlobalKey, Entry)>, batch: GlobalBatch) {
    match batch {
        GlobalBatch::Telemetry(records) => buffer.extend(records.into_iter().map(|record| {
            (
                GlobalKey {
                    tag: telemetry_tag(record.kind),
                    id: record.id,
                    name: record.kind.as_str(),
                },
                Entry::Json(record.json),
            )
        })),
        GlobalBatch::Queue(records) => buffer.extend(records.into_iter().map(|record| {
            (
                GlobalKey {
                    tag: 0,
                    id: record.queue_id,
                    name: QueuedMessageRecord::OBJECT,
                },
                Entry::Queue(Box::new(record)),
            )
        })),
        GlobalBatch::Reports(records) => buffer.extend(records.into_iter().map(|record| {
            (
                GlobalKey {
                    tag: report_tag(record.kind),
                    id: record.id,
                    name: record.kind.as_str(),
                },
                Entry::Report(record),
            )
        })),
        GlobalBatch::SpamModel(_) | GlobalBatch::Tasks(_) => {}
    }
}

struct Pager<'x, S, C> {
    source: &'x S,
    category: GlobalCategory,
    policy: RetryPolicy,
    limit: usize,
    cursor: Option<Vec<u8>>,
    buffer: VecDeque<(GlobalKey, Entry)>,
    last: Option<GlobalKey>,
    done: bool,
    side: Side<'x, C>,
}

enum Side<'x, C> {
    Source(&'x C),
    Target,
}

impl<'x, S: Source, C: RegistryConverter> Pager<'x, S, C> {
    fn new(
        source: &'x S,
        side: Side<'x, C>,
        category: GlobalCategory,
        policy: RetryPolicy,
        limit: usize,
    ) -> Self {
        Pager {
            source,
            category,
            policy,
            limit,
            cursor: None,
            buffer: VecDeque::new(),
            last: None,
            done: false,
            side,
        }
    }

    async fn fill(&mut self) -> Result<(), RunError> {
        while self.buffer.is_empty() && !self.done {
            let page = retry(self.policy, || {
                self.source
                    .global_page(self.category, self.cursor.as_deref(), self.limit)
            })
            .await?;
            let mut batch = page.batch;
            if let Side::Source(converter) = &self.side {
                match &mut batch {
                    GlobalBatch::Reports(records) => {
                        records.iter_mut().for_each(convert_internal_report);
                    }
                    GlobalBatch::Telemetry(records) => {
                        remap_telemetry(*converter, records, &mut Vec::new());
                    }
                    _ => {}
                }
            }
            extend(&mut self.buffer, batch);
            self.done = page.next.is_none() || page.next == self.cursor;
            self.cursor = page.next;
        }
        Ok(())
    }

    async fn peek(&mut self) -> Result<Option<GlobalKey>, RunError> {
        self.fill().await?;
        Ok(self.buffer.front().map(|(key, _)| *key))
    }

    fn pop(&mut self) -> Result<Option<(GlobalKey, Entry)>, RunError> {
        let Some((key, entry)) = self.buffer.pop_front() else {
            return Ok(None);
        };
        if self.last.is_some_and(|last| last >= key) {
            return Err(model::Error::fatal(format!(
                "{} pages are not in ascending order",
                self.category.as_str()
            ))
            .into());
        }
        self.last = Some(key);
        Ok(Some((key, entry)))
    }
}

fn advance(cursor: &mut Option<Vec<u8>>, next: Option<Vec<u8>>) -> Result<bool, RunError> {
    match next {
        None => Ok(false),
        Some(next) if cursor.as_ref() == Some(&next) => {
            Err(model::Error::fatal("tasks pages did not advance").into())
        }
        next => {
            *cursor = next;
            Ok(true)
        }
    }
}

fn task_key(id: u64) -> GlobalKey {
    GlobalKey {
        tag: 0,
        id,
        name: TaskRecord::OBJECT,
    }
}

struct ExpectedTasks<'x, R> {
    target: &'x R,
    explained: &'x FxHashSet<RegistryKey>,
    migrated_singletons: &'x FxHashSet<u64>,
    object: Box<str>,
    tasks: FxHashMap<u64, (u64, ContentHash)>,
    buf: Vec<u8>,
}

impl<R: Source> ExpectedTasks<'_, R> {
    fn canonical(&mut self, id: u64, json: Value) -> Result<(u64, ContentHash), model::Error> {
        let record = self.target.canonical_registry(RegistryRecord {
            key: RegistryKey::new(self.object.clone(), id),
            json,
        })?;
        self.buf.clear();
        serde_json::to_writer(&mut self.buf, &record.json)
            .map_err(|err| model::Error::fatal(format!("cannot serialize task {id}: {err}")))?;
        Ok((record.key.id.id().unwrap_or(id), ContentHash::of(&self.buf)))
    }

    fn add(&mut self, converted: ConvertedTasks, found: &mut CategoryFindings<'_>) {
        for (id, json) in converted.tasks {
            match self.canonical(id, json) {
                Ok((stored_id, hash)) => {
                    self.tasks.insert(stored_id, (id, hash));
                }
                Err(err) => found.add(
                    task_key(id),
                    &format!(
                        "the converted source task is not a valid v1 task: {}",
                        err.message()
                    ),
                    self.explained
                        .contains(&RegistryKey::new(TaskRecord::OBJECT, id)),
                ),
            }
        }
    }

    fn compare(&mut self, record: TaskRecord, found: &mut CategoryFindings<'_>) {
        let Some((source_id, hash)) = self.tasks.remove(&record.id) else {
            let generated_by_v1 = !self.migrated_singletons.contains(&record.id)
                && (is_derived_task_id(record.id) || is_singleton_task(&record.json));
            if is_copied(&record) && !generated_by_v1 {
                found.add(
                    task_key(record.id),
                    "present in the target but not in the source",
                    false,
                );
            }
            return;
        };
        match self.canonical(record.id, record.json) {
            Ok((_, actual)) if actual == hash => {}
            Ok(_) => found.add(task_key(source_id), "differs in the target", false),
            Err(err) => found.add(
                task_key(source_id),
                &format!("the target task cannot be read: {}", err.message()),
                false,
            ),
        }
    }
}

struct CategoryFindings<'x> {
    findings: &'x mut Findings,
    category: GlobalCategory,
    reported: u64,
    hidden: u64,
}

impl CategoryFindings<'_> {
    fn add(&mut self, key: GlobalKey, message: &str, explained: bool) {
        if self.reported < MAX_ROWS_PER_CATEGORY {
            self.reported += 1;
            self.findings
                .add(mismatch(key.subject(), message), explained);
        } else {
            self.hidden += 1;
            self.findings.mismatches += 1;
            if !explained {
                self.findings.unexplained += 1;
            }
        }
    }

    fn finish(self) {
        if self.hidden > 0 {
            self.findings.issues.push(mismatch(
                Subject::None,
                format!(
                    "{} more {} mismatches are not listed",
                    self.hidden,
                    self.category.as_str()
                ),
            ));
        }
    }
}

pub(super) struct GlobalVerify<'x, S, R, C> {
    pub(super) source: &'x S,
    pub(super) target: &'x R,
    pub(super) converter: &'x C,
    pub(super) check: GlobalCheck,
    pub(super) explained: &'x FxHashSet<RegistryKey>,
    pub(super) migrated_singletons: &'x FxHashSet<u64>,
    pub(super) policy: RetryPolicy,
    pub(super) limit: usize,
}

impl<S: Source, R: Source, C: RegistryConverter> GlobalVerify<'_, S, R, C> {
    pub(super) async fn run(
        &self,
        categories: CategorySet,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        for category in GlobalCategory::ALL {
            if !categories.contains(category.category()) || !self.check.includes(category) {
                continue;
            }
            if category == GlobalCategory::Tasks {
                self.tasks(categories, findings).await?;
            } else {
                self.category(category, findings).await?;
            }
        }
        Ok(())
    }

    fn ignored_property(&self, record: &InternalReportRecord) -> Option<String> {
        let canonical = self
            .target
            .canonical_registry(RegistryRecord {
                key: RegistryKey::new(
                    self.converter.target_object(report_object(record.kind)),
                    record.id,
                ),
                json: record.json.clone(),
            })
            .ok()?;
        ignored_property(&record.json, &canonical.json)
    }

    fn comparable(&self, record: InternalReportRecord) -> Option<Value> {
        let kind = record.kind;
        self.target
            .canonical_registry(RegistryRecord {
                key: RegistryKey::new(self.converter.target_object(report_object(kind)), record.id),
                json: record.json,
            })
            .ok()
            .map(|record| comparable_report(kind, record.json))
    }

    async fn tasks(
        &self,
        categories: CategorySet,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let mut found = CategoryFindings {
            findings,
            category: GlobalCategory::Tasks,
            reported: 0,
            hidden: 0,
        };
        let mut expected = ExpectedTasks {
            target: self.target,
            explained: self.explained,
            migrated_singletons: self.migrated_singletons,
            object: self.converter.target_object(TaskRecord::OBJECT),
            tasks: FxHashMap::default(),
            buf: Vec::new(),
        };
        let mut conversion = TaskConversion::new(
            self.source,
            self.converter,
            categories,
            self.policy,
            self.limit,
        );
        let mut pending: Vec<RegistryRecord> = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = retry(self.policy, || {
                self.source
                    .global_page(GlobalCategory::Tasks, cursor.as_deref(), self.limit)
            })
            .await?;
            if let GlobalBatch::Tasks(records) = page.batch {
                pending.extend(
                    records
                        .into_iter()
                        .filter(is_copied)
                        .map(TaskRecord::into_registry),
                );
            }
            if pending.len() >= TASK_CONVERSION_CHUNK {
                let converted = conversion.convert(std::mem::take(&mut pending)).await?;
                expected.add(converted, &mut found);
            }
            if !advance(&mut cursor, page.next)? {
                break;
            }
        }
        if !pending.is_empty() {
            let converted = conversion.convert(pending).await?;
            expected.add(converted, &mut found);
        }
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = retry(self.policy, || {
                self.target
                    .global_page(GlobalCategory::Tasks, cursor.as_deref(), self.limit)
            })
            .await?;
            if let GlobalBatch::Tasks(records) = page.batch {
                for record in records {
                    expected.compare(record, &mut found);
                }
            }
            if !advance(&mut cursor, page.next)? {
                break;
            }
        }
        let mut missing: Vec<u64> = expected
            .tasks
            .into_values()
            .map(|(source_id, _)| source_id)
            .collect();
        missing.sort_unstable();
        for id in missing {
            found.add(
                task_key(id),
                "present in the source but missing in the target",
                self.explained
                    .contains(&RegistryKey::new(TaskRecord::OBJECT, id)),
            );
        }
        found.finish();
        Ok(())
    }

    async fn category(
        &self,
        category: GlobalCategory,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let full = self.check == GlobalCheck::Final;
        let extras = full && category != GlobalCategory::Telemetry;
        let mut source = Pager::new(
            self.source,
            Side::Source(self.converter),
            category,
            self.policy,
            self.limit,
        );
        let mut target = Pager::new(
            self.target,
            Side::<C>::Target,
            category,
            self.policy,
            self.limit,
        );
        let mut found = CategoryFindings {
            findings,
            category,
            reported: 0,
            hidden: 0,
        };
        loop {
            let order = match (source.peek().await?, target.peek().await?) {
                (None, None) => break,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(left), Some(right)) => left.cmp(&right),
            };
            match order {
                Ordering::Less => {
                    let Some((key, _)) = source.pop()? else {
                        break;
                    };
                    if full {
                        found.add(
                            key,
                            "present in the source but missing in the target",
                            self.explained.contains(&key.registry_key()),
                        );
                    }
                }
                Ordering::Greater => {
                    let Some((key, _)) = target.pop()? else {
                        break;
                    };
                    if extras {
                        found.add(key, "present in the target but not in the source", false);
                    }
                }
                Ordering::Equal => {
                    let (Some((key, expected)), Some((_, actual))) = (source.pop()?, target.pop()?)
                    else {
                        break;
                    };
                    let differs = match (expected, actual) {
                        (Entry::Report(expected), Entry::Report(actual)) => {
                            if let Some(path) = self.ignored_property(&expected) {
                                found.add(
                                    key,
                                    &format!(
                                        "the source property {path} is not a v1 property, so v1 ignores it"
                                    ),
                                    false,
                                );
                            }
                            let expected = self.target.stored_report(expected).await?;
                            match (self.comparable(expected), self.comparable(actual)) {
                                (Some(expected), Some(actual)) => expected != actual,
                                _ => true,
                            }
                        }
                        (expected, actual) => expected != actual,
                    };
                    if differs {
                        let explained = category == GlobalCategory::Reports
                            && self.explained.contains(&key.registry_key());
                        found.add(key, "differs in the target", explained);
                    }
                }
            }
        }
        found.finish();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Identical DMARC rows merge with summed counts, list encodings and row order do not matter, any other change does.
    #[test]
    fn dmarc_reports_compare_rows_with_summed_counts() {
        let report = |records: Value| {
            comparable_report(
                ReportKind::Dmarc,
                json!({"domain": "example.org", "report": {"orgName": "x", "records": records}}),
            )
        };
        let full = report(json!({
            "0": {"sourceIp": "192.0.2.1", "count": 5},
            "1": {"sourceIp": "192.0.2.2", "count": 7},
            "2": {"sourceIp": "192.0.2.1", "count": 1}
        }));
        assert_eq!(
            full,
            report(json!([
                {"sourceIp": "192.0.2.2", "count": 7},
                {"sourceIp": "192.0.2.1", "count": 6}
            ]))
        );
        assert_ne!(
            full,
            report(json!([
                {"sourceIp": "192.0.2.2", "count": 7},
                {"sourceIp": "192.0.2.1", "count": 5}
            ]))
        );
        assert_ne!(
            full,
            report(json!([
                {"sourceIp": "192.0.2.3", "count": 7},
                {"sourceIp": "192.0.2.1", "count": 6}
            ]))
        );
        assert_ne!(full, report(json!({})));
        let mut renamed = full.clone();
        renamed["report"]["orgName"] = json!("y");
        assert_ne!(full, renamed);
    }

    // TLS policies compare as a set of full policies; the identifiers v1 assigns are ignored.
    #[test]
    fn tls_reports_compare_policies_in_any_order() {
        let report = |identifiers: Value, policies: Value| {
            comparable_report(
                ReportKind::Tls,
                json!({"domain": "example.org", "policyIdentifiers": identifiers, "report": {"policies": policies}}),
            )
        };
        let first = json!({"policyDomain": "a.example", "totalSuccessfulSessions": 3, "totalFailedSessions": 1});
        let second = json!({"policyDomain": "b.example", "totalSuccessfulSessions": 2, "totalFailedSessions": 0});
        let full = report(
            json!([11, 22]),
            json!({"0": first.clone(), "1": second.clone()}),
        );
        assert_eq!(
            full,
            report(json!({}), json!([second.clone(), first.clone()]))
        );
        let mut changed = second.clone();
        changed["totalFailedSessions"] = json!(4);
        assert_ne!(
            full,
            report(json!([11, 22]), json!([first.clone(), changed]))
        );
        assert_ne!(full, report(json!([11]), json!([first])));
    }

    // A source property the v1 type does not know is found at any depth, whatever list encoding either side uses; nulls, empty values and set encodings are not reported.
    #[test]
    fn properties_v1_ignores_are_found() {
        let input = json!({
            "domain": "a.example",
            "rua": {"a@a.example": true},
            "extra": null,
            "empty": {},
            "report": {"dateRangeBegin": "2020-01-01T00:00:00Z", "records": {"0": {"count": 1, "envelopeFrom": "a"}, "1": {"count": 2, "spfResults": {"0": {"domain": "b"}}}}}
        });
        let output = json!({
            "domain": "a.example",
            "rua": ["a@a.example"],
            "report": {"dateRangeStart": "2026-01-01T00:00:00Z", "records": [{"count": 3, "envelopeFrom": "a", "spfResults": [{"domain": "b"}]}]}
        });
        assert_eq!(
            ignored_property(&input, &output).as_deref(),
            Some("report/dateRangeBegin")
        );
        let mut renamed = input.clone();
        renamed["report"]
            .as_object_mut()
            .expect("report")
            .remove("dateRangeBegin");
        renamed["report"]["dateRangeStart"] = json!("2020-01-01T00:00:00Z");
        assert_eq!(ignored_property(&renamed, &output), None);
        renamed["report"]["records"]["1"]["spfResults"]["0"]["scope"] = json!("mfrom");
        assert_eq!(
            ignored_property(&renamed, &output).as_deref(),
            Some("report/records/spfResults/scope")
        );
    }

    // Failure details compare in any order (v1 returns them in key order), and zero-count rows are ignored.
    #[test]
    fn tls_failure_details_compare_in_any_order() {
        let report = |details: Value| {
            comparable_report(
                ReportKind::Tls,
                json!({"domain": "example.org", "report": {"policies": [{"policyDomain": "a.example", "totalFailedSessions": 3, "failureDetails": details}]}}),
            )
        };
        let expired = json!({"resultType": "certificateExpired", "failedSessionCount": 2});
        let starttls = json!({"resultType": "startTlsNotSupported", "failedSessionCount": 1});
        let unused = json!({"resultType": "validationFailure", "failedSessionCount": 0});
        let full = report(json!([expired.clone(), starttls.clone()]));
        assert_eq!(
            full,
            report(json!({"0": starttls.clone(), "1": expired.clone(), "2": unused}))
        );
        assert_ne!(full, report(json!([expired])));
    }
}
