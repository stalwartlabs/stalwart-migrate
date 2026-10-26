/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use model::{
    Explanation, GlobalBatch, GlobalCategory, InternalReportRecord, Issue, IssueKind,
    QueuedMessageRecord, RegistryKey, ReportKind, Severity, Source, Subject, Target, TelemetryKind,
    TelemetryRecord,
};
use rustc_hash::FxHashSet;
use serde_json::Value;
use state::{MetaKey, RunId, StateStore};

use super::{
    BlobMode, RegistryConverter, RunKind, context::Context, error::RunError, registry::EnumValue,
    stats::add,
};

pub(super) const REPORT: &str = "report";
pub(super) const DMARC_REPORT_RENAMES: [(&str, &str); 1] = [("dateRangeBegin", "dateRangeStart")];

pub(super) fn convert_internal_report(record: &mut InternalReportRecord) {
    if record.kind != ReportKind::Dmarc {
        return;
    }
    let Some(report) = record.json.get_mut(REPORT).and_then(Value::as_object_mut) else {
        return;
    };
    for (from, to) in DMARC_REPORT_RENAMES {
        if let Some(value) = report.remove(from) {
            report.entry(to).or_insert(value);
        }
    }
}

const EVENT_TYPE: &str = "EventType";
const METRIC_TYPE: &str = "MetricType";
const SPAN_EVENTS: &str = "events";
const EVENT_NAME: &str = "event";
const EVENT_KEY_VALUES: &str = "keyValues";
const VALUE: &str = "value";
const VALUE_TYPE: &str = "@type";
const VALUE_EVENT: &str = "Event";
const VALUE_LIST: &str = "List";
const METRIC_NAME: &str = "metric";

struct Dropped(Box<str>);

struct TelemetryRemap<'x, C> {
    converter: &'x C,
}

impl<C: RegistryConverter> TelemetryRemap<'_, C> {
    fn rename(&self, name: &str, object: &mut Value, field: &str) -> Result<(), Dropped> {
        let Some(slot) = object.get_mut(field) else {
            return Ok(());
        };
        let Some(current) = slot.as_str() else {
            return Ok(());
        };
        match self.converter.enum_value(name, current) {
            EnumValue::Keep => Ok(()),
            EnumValue::Rename(target) => {
                *slot = Value::String(target.to_owned());
                Ok(())
            }
            EnumValue::Drop => Err(Dropped(current.into())),
        }
    }

    fn items(
        &self,
        list: Option<&mut Value>,
        mut each: impl FnMut(&Self, &mut Value) -> Result<(), Dropped>,
    ) -> Result<(), Dropped> {
        match list {
            Some(Value::Array(items)) => items.iter_mut().try_for_each(|item| each(self, item)),
            Some(Value::Object(items)) => items.values_mut().try_for_each(|item| each(self, item)),
            _ => Ok(()),
        }
    }

    fn key_values(&self, list: Option<&mut Value>) -> Result<(), Dropped> {
        self.items(list, |remap, pair| remap.value(pair.get_mut(VALUE)))
    }

    fn value(&self, value: Option<&mut Value>) -> Result<(), Dropped> {
        let Some(value) = value else {
            return Ok(());
        };
        match value.get(VALUE_TYPE).and_then(Value::as_str) {
            Some(VALUE_EVENT) => {
                self.rename(EVENT_TYPE, value, EVENT_NAME)?;
                self.key_values(value.get_mut(VALUE))
            }
            Some(VALUE_LIST) => {
                self.items(value.get_mut(VALUE), |remap, item| remap.value(Some(item)))
            }
            _ => Ok(()),
        }
    }

    fn span(&self, span: &mut Value) -> Result<(), Dropped> {
        self.items(span.get_mut(SPAN_EVENTS), |remap, event| {
            remap.rename(EVENT_TYPE, event, EVENT_NAME)?;
            remap.key_values(event.get_mut(EVENT_KEY_VALUES))
        })
    }

    fn record(&self, record: &mut TelemetryRecord) -> Result<(), Dropped> {
        match record.kind {
            TelemetryKind::Span => self.span(&mut record.json),
            TelemetryKind::Metric => self.rename(METRIC_TYPE, &mut record.json, METRIC_NAME),
        }
    }
}

pub(super) fn remap_telemetry<C: RegistryConverter>(
    converter: &C,
    records: &mut Vec<TelemetryRecord>,
    issues: &mut Vec<Issue>,
) {
    let remap = TelemetryRemap { converter };
    records.retain_mut(|record| match remap.record(record) {
        Ok(()) => true,
        Err(Dropped(value)) => {
            let what = match record.kind {
                TelemetryKind::Span => "event type",
                TelemetryKind::Metric => "metric type",
            };
            issues.push(
                Issue::new(
                    Severity::Warning,
                    IssueKind::Skipped,
                    Subject::Registry(RegistryKey::new(record.kind.as_str(), record.id)),
                    format!(
                        "the {what} {value} has no v1 equivalent; the {} was not copied",
                        record.kind.as_str()
                    ),
                )
                .explaining(Explanation::Missing),
            );
            false
        }
    });
}

fn telemetry_subject(issue: &Issue) -> Option<(TelemetryKind, u64)> {
    match &issue.subject {
        Subject::Registry(key) => Some((TelemetryKind::parse(&key.object)?, key.id.id()?)),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GlobalPhase {
    Incremental,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalGeneration {
    Open { generation: RunId, run: RunId },
    Done(RunId),
}

impl FinalGeneration {
    const OPEN: &str = "open ";
    const DONE: &str = "done ";

    fn parse(value: &str) -> Option<Self> {
        if let Some(open) = value.strip_prefix(Self::OPEN) {
            let (generation, run) = open.split_once(' ')?;
            Some(FinalGeneration::Open {
                generation: generation.parse().ok()?,
                run: run.parse().ok()?,
            })
        } else {
            value
                .strip_prefix(Self::DONE)?
                .parse()
                .ok()
                .map(FinalGeneration::Done)
        }
    }

    fn encode(self) -> String {
        match self {
            FinalGeneration::Open { generation, run } => {
                format!("{}{generation} {run}", Self::OPEN)
            }
            FinalGeneration::Done(generation) => format!("{}{generation}", Self::DONE),
        }
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn global_pass(&self, phase: GlobalPhase) -> Result<(), RunError> {
        let limit = self.options.tuning.batch_ops;
        let generation = match phase {
            GlobalPhase::Final => Some(self.final_generation().await?),
            GlobalPhase::Incremental => None,
        };
        if let Some(generation) = generation
            && generation != self.run_id
        {
            self.report_resumed_errors(generation).await?;
        }
        for category in GlobalCategory::ALL {
            let final_only = category.category().is_final_only();
            if final_only != (phase == GlobalPhase::Final)
                || (final_only && self.options.kind != RunKind::Final)
            {
                continue;
            }
            if category == GlobalCategory::SpamModel {
                continue;
            }
            if !self.options.categories.contains(category.category()) {
                if final_only {
                    self.sweep_globals(category, RunId::MAX).await?;
                }
                continue;
            }
            if category == GlobalCategory::Tasks {
                self.tasks_pass().await?;
                self.sweep_globals(category, self.run_id).await?;
                continue;
            }
            let name: Box<str> = match generation {
                Some(generation) => format!("{}@{generation}", category.as_str()).into(),
                None => category.as_str().into(),
            };
            let mut cursor = self.state.global_cursor(name.clone()).await?;
            loop {
                self.check_shutdown()?;
                self.rate.acquire(limit).await;
                let mut page = self
                    .retry(|| self.source.global_page(category, cursor.as_deref(), limit))
                    .await?;
                let mut telemetry = Vec::new();
                match &mut page.batch {
                    GlobalBatch::Queue(messages) if self.options.blob_mode == BlobMode::Copy => {
                        self.copy_queue_blobs(messages, &mut page.issues).await?;
                    }
                    GlobalBatch::Reports(reports) => {
                        reports.iter_mut().for_each(convert_internal_report);
                    }
                    GlobalBatch::Telemetry(records) => {
                        telemetry = self.unseen_telemetry(records, &mut page.issues).await?;
                        remap_telemetry(&*self.converter, records, &mut page.issues);
                    }
                    _ => {}
                }
                self.report(None, page.issues).await?;
                if !page.batch.is_empty() {
                    if let Some(generation) = generation {
                        let keys = page.batch.global_keys();
                        if !keys.is_empty() {
                            self.state.track_globals(generation, keys).await?;
                            failpoint!("global.track", category.as_str());
                        }
                    }
                    let outcome = self.retry(|| self.target.write_global(&page.batch)).await?;
                    failpoint!("global.write", category.as_str());
                    add(&self.stats.global_records, page.batch.len() as u64);
                    self.report(None, outcome.issues).await?;
                }
                if !telemetry.is_empty() {
                    self.state.see_telemetry(telemetry).await?;
                    failpoint!("global.seen", category.as_str());
                }
                let Some(next) = page.next else {
                    if category == GlobalCategory::Telemetry {
                        for kind in TelemetryKind::ALL {
                            self.state
                                .prune_telemetry(kind, kind.lookback().saturating_mul(2))
                                .await?;
                        }
                    }
                    if let Some(resume) = page.resume {
                        self.state.set_global_cursor(name.clone(), resume).await?;
                        failpoint!("global.cursor", category.as_str());
                    }
                    if let Some(generation) = generation {
                        self.sweep_globals(category, generation).await?;
                    }
                    break;
                };
                if cursor.as_deref() == Some(next.as_slice()) {
                    return Err(model::Error::fatal(format!(
                        "source {} pages did not advance",
                        category.as_str()
                    ))
                    .into());
                }
                self.state
                    .set_global_cursor(name.clone(), next.clone())
                    .await?;
                failpoint!("global.cursor", category.as_str());
                cursor = Some(next);
            }
        }
        if let Some(generation) = generation {
            self.state
                .set_meta(
                    MetaKey::FinalGeneration,
                    FinalGeneration::Done(generation).encode(),
                )
                .await?;
            failpoint!("global.generation");
        }
        Ok(())
    }

    async fn final_generation(&self) -> Result<RunId, RunError> {
        let stored = self.state.meta(MetaKey::FinalGeneration).await?;
        let generation = match stored.as_deref().and_then(FinalGeneration::parse) {
            Some(FinalGeneration::Open { generation, run }) if self.interrupted.contains(&run) => {
                generation
            }
            _ => self.run_id,
        };
        self.state
            .set_meta(
                MetaKey::FinalGeneration,
                FinalGeneration::Open {
                    generation,
                    run: self.run_id,
                }
                .encode(),
            )
            .await?;
        Ok(generation)
    }

    async fn report_resumed_errors(&self, generation: RunId) -> Result<(), RunError> {
        let runs = generation.max(self.accepted_errors().await?.saturating_add(1))..self.run_id;
        let mut errors = 0;
        for category in GlobalCategory::ALL {
            if category == GlobalCategory::Tasks
                || !category.category().is_final_only()
                || !self.options.categories.contains(category.category())
            {
                continue;
            }
            for object in category.objects() {
                errors += self
                    .state
                    .global_errors(runs.clone(), (*object).into())
                    .await?;
            }
        }
        if errors == 0 {
            return Ok(());
        }
        self.report(
            None,
            vec![Issue::new(
                Severity::Error,
                IssueKind::Failed,
                Subject::None,
                format!(
                    "{errors} queued messages or internal reports could not be copied by the interrupted runs of this final pass (runs {} to {}); they are not read again, see their report rows",
                    runs.start,
                    runs.end - 1
                ),
            )],
        )
        .await
    }

    async fn sweep_globals(
        &self,
        category: GlobalCategory,
        generation: RunId,
    ) -> Result<(), RunError> {
        let limit = u32::try_from(self.options.tuning.batch_ops.max(1)).unwrap_or(u32::MAX);
        let mut after = None;
        loop {
            self.check_shutdown()?;
            let stale = self
                .state
                .stale_globals(category, generation, after, limit)
                .await?;
            let Some(last) = stale.last().copied() else {
                return Ok(());
            };
            self.rate.acquire(stale.len()).await;
            let outcome = self.retry(|| self.target.delete_global(&stale)).await?;
            failpoint!("global.delete", category.as_str());
            add(&self.stats.global_deleted, stale.len() as u64);
            self.report(None, outcome.issues).await?;
            self.state.forget_globals(stale).await?;
            failpoint!("global.forget", category.as_str());
            after = Some(last);
        }
    }

    async fn unseen_telemetry(
        &self,
        records: &mut Vec<TelemetryRecord>,
        issues: &mut Vec<Issue>,
    ) -> Result<Vec<(TelemetryKind, u64)>, RunError> {
        let mut keys: Vec<(TelemetryKind, u64)> = records
            .iter()
            .map(|record| (record.kind, record.id))
            .chain(issues.iter().filter_map(telemetry_subject))
            .collect();
        if keys.is_empty() {
            return Ok(keys);
        }
        let seen: FxHashSet<(TelemetryKind, u64)> = keys
            .iter()
            .zip(self.state.telemetry_seen(keys.clone()).await?)
            .filter_map(|(key, seen)| seen.then_some(*key))
            .collect();
        if !seen.is_empty() {
            records.retain(|record| !seen.contains(&(record.kind, record.id)));
            issues.retain(|issue| telemetry_subject(issue).is_none_or(|key| !seen.contains(&key)));
            keys.retain(|key| !seen.contains(key));
        }
        Ok(keys)
    }

    async fn copy_queue_blobs(
        &self,
        messages: &mut Vec<QueuedMessageRecord>,
        issues: &mut Vec<Issue>,
    ) -> Result<(), RunError> {
        let missing = self
            .copy_missing_blobs(
                messages
                    .iter()
                    .map(|message| (message.blob_hash, message.size))
                    .collect(),
            )
            .await?;
        if missing.is_empty() {
            return Ok(());
        }
        messages.retain(|message| {
            let present = missing.binary_search(&message.blob_hash).is_err();
            if !present {
                issues.push(Issue::new(
                    Severity::Error,
                    IssueKind::Skipped,
                    Subject::Registry(RegistryKey::new(
                        QueuedMessageRecord::OBJECT,
                        message.queue_id,
                    )),
                    format!(
                        "the message blob {} is missing in the source; the queued message was not copied",
                        message.blob_hash
                    ),
                )
                .explaining(Explanation::Missing));
            }
            present
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mapping::{
        Direction, Mapping, SchemaVersion,
        rules::{Conversion, PropertyRule, RuleSet},
        schema::{Schema, SchemaDef, Type, TypeDef},
    };
    use rustc_hash::FxHashSet;
    use serde_json::json;

    const REPORT_OBJECTS: [&str; 2] = ["x:DmarcInternalReport", "x:TlsInternalReport"];
    const DELIBERATELY_SKIPPED: [&str; 1] = ["x:DmarcReportRecord.envelopeFrom"];

    #[derive(Default)]
    struct Walk {
        seen: FxHashSet<String>,
        enums: FxHashSet<String>,
        renames: Vec<(String, String, String)>,
        other: Vec<String>,
    }

    impl Walk {
        fn schema(&mut self, schema: &Schema, rules: &RuleSet, name: &str, path: &str) {
            if rules.object(name).is_some() {
                self.other.push(format!("object {name}"));
            }
            match schema.schema(name) {
                Some(SchemaDef::Union(variants)) => {
                    if rules.variants.contains_key(name) {
                        self.other.push(format!("variants of {name}"));
                    }
                    for variant in variants.iter() {
                        if let Some(fields) = &variant.schema {
                            self.fields(schema, rules, fields, path);
                        }
                    }
                }
                Some(SchemaDef::Single(fields)) => self.fields(schema, rules, fields, path),
                None => self.fields(schema, rules, name, path),
            }
        }

        fn fields(&mut self, schema: &Schema, rules: &RuleSet, name: &str, path: &str) {
            if !self.seen.insert(name.to_owned()) {
                return;
            }
            if rules.defaults(name).is_some() {
                self.other.push(format!("defaults of {name}"));
            }
            for (property, rule) in rules.property_rules(name).into_iter().flatten() {
                match rule {
                    PropertyRule::Rename {
                        to,
                        convert: Conversion::Compatible,
                    } => self
                        .renames
                        .push((path.to_owned(), property.to_string(), to.to_string())),
                    _ => self.other.push(format!("{name}.{property}")),
                }
            }
            let Some(fields) = schema.fields(name) else {
                return;
            };
            for (property, definition) in &fields.properties {
                self.ty(schema, rules, &definition.ty, &format!("{path}{property}/"));
            }
        }

        fn ty(&mut self, schema: &Schema, rules: &RuleSet, ty: &TypeDef, path: &str) {
            if let Type::Enum(name) = &ty.ty {
                self.enums.insert(name.to_string());
            }
            match &ty.ty {
                Type::Enum(name)
                    if rules.enums.contains_key(name) || rules.separators.contains_key(name) =>
                {
                    self.other.push(format!("enum {name}"));
                }
                Type::Object(name) | Type::ObjectList { schema: name, .. } => {
                    self.schema(schema, rules, name, path)
                }
                Type::Set { class, .. } => self.ty(schema, rules, class, path),
                Type::Map { key, value } => {
                    self.ty(schema, rules, key, path);
                    self.ty(schema, rules, value, path);
                }
                _ => {}
            }
        }
    }

    // Every mapping rule that applies inside internal reports is either applied by convert_internal_report or deliberately skipped.
    #[test]
    fn internal_report_renames_follow_the_mapping() {
        let mapping = Mapping::embedded().expect("mapping");
        let schema = mapping.schema(SchemaVersion::V016);
        let rules = mapping.rules(Direction::Forward);
        let mut walk = Walk::default();
        for object in REPORT_OBJECTS {
            walk.schema(schema, rules, object, "");
        }
        walk.other.sort();
        assert_eq!(walk.other, DELIBERATELY_SKIPPED);
        let expected: Vec<(String, String, String)> = DMARC_REPORT_RENAMES
            .iter()
            .map(|(from, to)| (format!("{REPORT}/"), (*from).to_owned(), (*to).to_owned()))
            .collect();
        assert_eq!(walk.renames, expected);
    }

    // Object rules, default tables and enum separators inside internal reports are caught too, not only property renames and enum tables.
    #[test]
    fn internal_report_drift_covers_objects_defaults_and_separators() {
        let mapping = Mapping::embedded().expect("mapping");
        let schema = mapping.schema(SchemaVersion::V016);
        let mut rules = mapping.rules(Direction::Forward).clone();
        let mut clean = Walk::default();
        for object in REPORT_OBJECTS {
            clean.schema(schema, &rules, object, "");
        }
        let mut fields: Vec<&String> = clean.seen.iter().collect();
        fields.sort();
        let fields = fields.first().copied().expect("fields").clone();
        let enum_name = clean
            .enums
            .iter()
            .find(|name| !rules.enums.contains_key(name.as_str()))
            .expect("enum without rules")
            .clone();
        rules.objects.insert(
            REPORT_OBJECTS[0].into(),
            mapping::rules::ObjectRule {
                to: None,
                action: mapping::rules::ObjectAction::Keep,
            },
        );
        rules.defaults.insert(
            fields.as_str().into(),
            mapping::rules::DefaultsTable::default(),
        );
        rules.separators.insert(
            enum_name.as_str().into(),
            mapping::rules::Separator {
                from: "_".into(),
                to: "-".into(),
            },
        );
        let mut walk = Walk::default();
        for object in REPORT_OBJECTS {
            walk.schema(schema, &rules, object, "");
        }
        for expected in [
            format!("object {}", REPORT_OBJECTS[0]),
            format!("defaults of {fields}"),
            format!("enum {enum_name}"),
        ] {
            assert!(
                walk.other.contains(&expected),
                "{expected}: {:?}",
                walk.other
            );
        }
    }

    // Span events (in either list encoding), nested event values and metric types take their v1 names; a dropped type removes the record with an explained warning.
    #[test]
    fn telemetry_types_follow_the_mapping_enums() {
        let converter = crate::converter::MappingConverter::new(
            Mapping::embedded().expect("mapping"),
            mapping::Answers::default(),
            mapping::Options::default(),
        );
        let span = |id, events| TelemetryRecord {
            kind: TelemetryKind::Span,
            id,
            json: json!({ "events": events }),
        };
        let mut records = vec![
            span(
                1,
                json!([
                    {"event": "store.cache-hit", "keyValues": [{"key": "details", "value": {"@type": "List", "value": [{"@type": "Event", "event": "dkim.failed-verification", "value": {}}]}}]},
                    {"event": "smtp.connection-start", "keyValues": {"0": {"key": "details", "value": {"@type": "Event", "event": "arc.broken-chain", "value": []}}}}
                ]),
            ),
            span(
                2,
                json!({"0": {"event": "smtp.connection-start"}, "1": {"event": "dkim.modified"}}),
            ),
            TelemetryRecord {
                kind: TelemetryKind::Metric,
                id: 3,
                json: json!({"@type": "Counter", "count": 1, "metric": "message-ingest.index-time"}),
            },
            TelemetryRecord {
                kind: TelemetryKind::Metric,
                id: 4,
                json: json!({"@type": "Counter", "count": 1, "metric": "dkim.modified"}),
            },
        ];
        let mut issues = Vec::new();
        remap_telemetry(&converter, &mut records, &mut issues);
        assert_eq!(
            records.iter().map(|record| record.id).collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(
            records[0].json,
            json!({"events": [
                {"event": "cache.hit", "keyValues": [{"key": "details", "value": {"@type": "List", "value": [{"@type": "Event", "event": "dkim.verification-failed", "value": {}}]}}]},
                {"event": "smtp.connection-start", "keyValues": {"0": {"key": "details", "value": {"@type": "Event", "event": "arc.chain-invalid", "value": []}}}}
            ]})
        );
        assert_eq!(records[1].json["metric"], "search-index.index-time");
        assert_eq!(issues.len(), 2);
        assert!(
            issues
                .iter()
                .all(|issue| issue.severity == Severity::Warning
                    && issue.kind == IssueKind::Skipped
                    && issue.explains == Some(Explanation::Missing)
                    && issue.message.contains("dkim.modified"))
        );
    }

    // DMARC reports get the v1 name of the date range start; TLS reports already use it.
    #[test]
    fn dmarc_report_dates_are_renamed() {
        let mut dmarc = InternalReportRecord {
            kind: ReportKind::Dmarc,
            id: 1,
            json: json!({"domain": "a.example", "report": {"dateRangeBegin": "2020-01-01T00:00:00Z", "dateRangeEnd": "2020-01-02T00:00:00Z"}}),
        };
        convert_internal_report(&mut dmarc);
        assert_eq!(
            dmarc.json,
            json!({"domain": "a.example", "report": {"dateRangeStart": "2020-01-01T00:00:00Z", "dateRangeEnd": "2020-01-02T00:00:00Z"}})
        );
        let tls_json = json!({"report": {"dateRangeBegin": "x", "dateRangeStart": "y"}});
        let mut tls = InternalReportRecord {
            kind: ReportKind::Tls,
            id: 2,
            json: tls_json.clone(),
        };
        convert_internal_report(&mut tls);
        assert_eq!(tls.json, tls_json);
    }
}
