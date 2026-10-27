/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    GlobalBatch, GlobalPage, Issue, IssueKind, RegistryKey, Severity, Subject, TEXT_TIMESTAMPS,
    TaggedCursor, TelemetryKind, TelemetryRecord,
};
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs::{
            DataStore, Metric, MetricsStore, Trace, TraceKeyValue, TraceValue, TracingStore,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, list::List},
};
use serde_json::Value;
use std::fmt::Write;
use store::{
    Deserialize, IterateParams, Store, U64_LEN, ValueKey,
    write::{RegistryClass, TelemetryClass, ValueClass, key::DeserializeBigEndian},
};
use types::id::Id;

use crate::{
    adapter::error::trc_error,
    open::{OpenError, SourceScope, open_data_store},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TelemetryLocation {
    Data,
    External(Box<DataStore>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TelemetryConfig {
    pub spans: TelemetryLocation,
    pub metrics: TelemetryLocation,
}

pub(crate) struct TelemetryStores {
    pub spans: Option<Store>,
    pub metrics: Option<Store>,
}

impl TelemetryConfig {
    pub(crate) async fn read(
        data: &Store,
        rewrite: impl Fn(DataStore) -> DataStore,
    ) -> trc::Result<Self> {
        let spans = match singleton(data, ObjectType::TracingStore).await? {
            Some(ObjectInner::TracingStore(store)) => match store {
                TracingStore::FoundationDb(store) => Some(DataStore::FoundationDb(store)),
                TracingStore::PostgreSql(store) => Some(DataStore::PostgreSql(store)),
                TracingStore::MySql(store) => Some(DataStore::MySql(store)),
                TracingStore::Default | TracingStore::Disabled => None,
            },
            _ => None,
        };
        let metrics = match singleton(data, ObjectType::MetricsStore).await? {
            Some(ObjectInner::MetricsStore(store)) => match store {
                MetricsStore::FoundationDb(store) => Some(DataStore::FoundationDb(store)),
                MetricsStore::PostgreSql(store) => Some(DataStore::PostgreSql(store)),
                MetricsStore::MySql(store) => Some(DataStore::MySql(store)),
                MetricsStore::Default | MetricsStore::Disabled => None,
            },
            _ => None,
        };
        let location = |store: Option<DataStore>| match store {
            Some(store) => TelemetryLocation::External(Box::new(rewrite(store))),
            None => TelemetryLocation::Data,
        };
        Ok(TelemetryConfig {
            spans: location(spans),
            metrics: location(metrics),
        })
    }
}

impl TelemetryStores {
    pub(crate) async fn open(config: &TelemetryConfig) -> Result<Self, OpenError> {
        let spans = match &config.spans {
            TelemetryLocation::External(store) => {
                Some(open_data_store((**store).clone(), SourceScope::Full).await?)
            }
            TelemetryLocation::Data => None,
        };
        let metrics = match &config.metrics {
            TelemetryLocation::External(_) if config.metrics == config.spans => spans.clone(),
            TelemetryLocation::External(store) => {
                Some(open_data_store((**store).clone(), SourceScope::Full).await?)
            }
            TelemetryLocation::Data => None,
        };
        Ok(TelemetryStores { spans, metrics })
    }
}

async fn singleton(data: &Store, object: ObjectType) -> trc::Result<Option<ObjectInner>> {
    data.get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
        object_id: object.to_id(),
        item_id: Id::singleton().id(),
    })))
    .await
    .map(|object| object.map(|object| object.inner))
}

fn key(kind: TelemetryKind, id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Telemetry(match kind {
        TelemetryKind::Span => TelemetryClass::Span(id),
        TelemetryKind::Metric => TelemetryClass::Metric(id),
    }))
}

const KINDS: [TelemetryKind; 2] = [TelemetryKind::Span, TelemetryKind::Metric];

const SPAN_EVENTS: &str = "events";
const EVENT_TIMESTAMP: &str = "timestamp";
const EVENT_KEY_VALUES: &str = "keyValues";
const VALUE: &str = "value";

#[derive(Default)]
struct SpanJson {
    key: String,
}

impl SpanJson {
    fn encode(trace: &Trace) -> serde_json::Result<Value> {
        let mut json = serde_json::to_value(trace)?;
        if let Some(events) = json.get_mut(SPAN_EVENTS) {
            let mut encoder = SpanJson::default();
            for (id, event) in trace.events.0.iter() {
                if let Some(slot) = encoder.entry(events, *id) {
                    Self::timestamp(event.timestamp, slot.get_mut(EVENT_TIMESTAMP));
                    encoder.key_values(&event.key_values, slot.get_mut(EVENT_KEY_VALUES));
                }
            }
        }
        Ok(json)
    }

    fn entry<'x>(&mut self, list: &'x mut Value, id: u32) -> Option<&'x mut Value> {
        self.key.clear();
        write!(self.key, "{id}").ok()?;
        list.get_mut(self.key.as_str())
    }

    fn timestamp(timestamp: UTCDateTime, slot: Option<&mut Value>) {
        if let Some(slot) = slot
            && !TEXT_TIMESTAMPS.contains(&timestamp.timestamp())
        {
            *slot = Value::from(timestamp.timestamp());
        }
    }

    fn key_values(&mut self, list: &List<TraceKeyValue>, json: Option<&mut Value>) {
        let Some(json) = json else {
            return;
        };
        for (id, pair) in list.0.iter() {
            if let Some(slot) = self.entry(json, *id).and_then(|entry| entry.get_mut(VALUE)) {
                self.value(&pair.value, slot);
            }
        }
    }

    fn value(&mut self, value: &TraceValue, json: &mut Value) {
        match value {
            TraceValue::UTCDateTime(value) => Self::timestamp(value.value, json.get_mut(VALUE)),
            TraceValue::Event(event) => self.key_values(&event.value, json.get_mut(VALUE)),
            TraceValue::List(list) => {
                let Some(items) = json.get_mut(VALUE) else {
                    return;
                };
                for (id, item) in list.value.0.iter() {
                    if let Some(slot) = self.entry(items, *id) {
                        self.value(item, slot);
                    }
                }
            }
            _ => {}
        }
    }
}

fn decode(kind: TelemetryKind, value: &[u8]) -> Result<serde_json::Value, String> {
    match kind {
        TelemetryKind::Span => <Trace as Deserialize>::deserialize(value)
            .map_err(|err| err.to_string())
            .and_then(|trace| SpanJson::encode(&trace).map_err(|err| err.to_string())),
        TelemetryKind::Metric => <Metric as Deserialize>::deserialize(value)
            .map_err(|err| err.to_string())
            .and_then(|metric| serde_json::to_value(metric).map_err(|err| err.to_string())),
    }
}

pub(super) async fn page(
    stores: &TelemetryStores,
    data: &Store,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    let limit = limit.max(1);
    let mut records = Vec::with_capacity(limit.min(1024));
    let mut issues = Vec::new();
    let mut values = Vec::new();
    let mut cursor = TaggedCursor::<{ KINDS.len() }>::decode(cursor)?;
    while let Some((tag, first)) = cursor.position() {
        let Some(&kind) = KINDS.get(tag) else {
            break;
        };
        let store = match kind {
            TelemetryKind::Span => stores.spans.as_ref(),
            TelemetryKind::Metric => stores.metrics.as_ref(),
        }
        .unwrap_or(data);
        let remaining = limit - records.len() - issues.len();
        values.clear();
        store
            .iterate(
                IterateParams::new(key(kind, first), key(kind, u64::MAX))
                    .ascending()
                    .with_limit(remaining),
                |key, value| {
                    if key.len() == U64_LEN {
                        values.push((key.deserialize_be_u64(0)?, value.to_vec()));
                    }
                    Ok(values.len() < remaining)
                },
            )
            .await
            .map_err(trc_error)?;
        let full = values.len() == remaining;
        if let Some((last, _)) = values.last() {
            cursor.record(*last);
        }
        for (id, value) in values.drain(..) {
            match decode(kind, &value) {
                Ok(json) => records.push(TelemetryRecord { kind, id, json }),
                Err(err) => issues.push(Issue::new(
                    Severity::Warning,
                    IssueKind::Skipped,
                    Subject::Registry(RegistryKey::new(kind.as_str(), id)),
                    format!("undecodable v0.16 {}: {err}", kind.as_str()),
                )),
            }
        }
        if full {
            return Ok(GlobalPage {
                batch: GlobalBatch::Telemetry(records),
                issues,
                next: Some(cursor.encode()),
                resume: None,
            });
        }
        cursor.next_tag();
    }
    for (tag, kind) in KINDS.into_iter().enumerate() {
        cursor.rewind(tag, kind.lookback());
    }
    Ok(GlobalPage {
        batch: GlobalBatch::Telemetry(records),
        issues,
        next: None,
        resume: Some(cursor.restart()),
    })
}
