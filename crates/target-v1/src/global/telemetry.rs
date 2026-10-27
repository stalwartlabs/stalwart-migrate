/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use model::{Issue, TelemetryKind, TelemetryRecord};
use registry::{
    schema::{
        prelude::{ObjectInner, ObjectType},
        structs::{
            Metric, MetricsStore, Search, Trace, TraceEvent, TraceKeyValue, TraceValue,
            TraceValueEvent, TraceValueList, TraceValueUTCDateTime, TracingStore,
        },
    },
    types::{ObjectImpl, datetime::UTCDateTime, list::List},
};
use serde::{
    Deserialize,
    de::{DeserializeOwned, Error},
};
use serde_json::Value;
use store::write::{TelemetryClass, ValueClass};
use utils::map::vec_map::VecMap;

use super::skipped;
use crate::target::V1Target;

const SHARED_STORE: &str = "the v1 telemetry store is not the target data store and may be shared with v0.16; the record was not copied";
const DISABLED_STORE: &str = "the v1 telemetry store is disabled; the record was not copied";

const SPAN_EVENTS: &str = "events";
const EVENT_NAME: &str = "event";
const EVENT_TIMESTAMP: &str = "timestamp";
const EVENT_KEY_VALUES: &str = "keyValues";
const KEY: &str = "key";
const VALUE: &str = "value";
const VALUE_TYPE: &str = "@type";

fn span(json: &Value) -> serde_json::Result<Trace> {
    Ok(Trace {
        events: list(json.get(SPAN_EVENTS), event)?,
    })
}

fn list<T>(
    json: Option<&Value>,
    item: fn(&Value) -> serde_json::Result<T>,
) -> serde_json::Result<List<T>> {
    let Some(json) = json else {
        return Ok(List(VecMap::new()));
    };
    let Value::Object(entries) = json else {
        return Err(serde_json::Error::custom(
            "expected a map of string keys to values",
        ));
    };
    let mut items = VecMap::with_capacity(entries.len());
    for (key, value) in entries {
        let id: u32 = key
            .parse()
            .map_err(|_| serde_json::Error::custom(format!("invalid integer key: {key}")))?;
        items.append(id, item(value)?);
    }
    items.sort_unstable_by_key();
    Ok(List(items))
}

fn field<T: DeserializeOwned + Default>(json: &Value, name: &str) -> serde_json::Result<T> {
    json.get(name)
        .map(T::deserialize)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn timestamp(json: &Value, name: &str) -> serde_json::Result<UTCDateTime> {
    match json.get(name) {
        Some(Value::Number(number)) => number
            .as_i64()
            .map(UTCDateTime::from_timestamp)
            .ok_or_else(|| serde_json::Error::custom("invalid DateTime")),
        Some(value) => UTCDateTime::deserialize(value),
        None => Ok(UTCDateTime::default()),
    }
}

fn event(json: &Value) -> serde_json::Result<TraceEvent> {
    Ok(TraceEvent {
        event: field(json, EVENT_NAME)?,
        timestamp: timestamp(json, EVENT_TIMESTAMP)?,
        key_values: list(json.get(EVENT_KEY_VALUES), key_value)?,
    })
}

fn key_value(json: &Value) -> serde_json::Result<TraceKeyValue> {
    Ok(TraceKeyValue {
        key: field(json, KEY)?,
        value: json.get(VALUE).map(value).transpose()?.unwrap_or_default(),
    })
}

fn value(json: &Value) -> serde_json::Result<TraceValue> {
    let kind = json
        .get(VALUE_TYPE)
        .and_then(Value::as_str)
        .unwrap_or_default();
    hashify::fnc_map!(kind.as_bytes(),
        "UTCDateTime" => Ok(TraceValue::UTCDateTime(TraceValueUTCDateTime {
            value: timestamp(json, VALUE)?,
        })),
        "Event" => Ok(TraceValue::Event(TraceValueEvent {
            event: field(json, EVENT_NAME)?,
            value: list(json.get(VALUE), key_value)?,
        })),
        "List" => Ok(TraceValue::List(TraceValueList {
            value: list(json.get(VALUE), value)?,
        })),
        _ => TraceValue::deserialize(json)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    DataStore,
    Disabled,
    External,
}

struct TelemetryTargets {
    spans: Destination,
    metrics: Destination,
    index_spans: bool,
}

impl V1Target {
    async fn telemetry_targets(&self) -> model::Result<TelemetryTargets> {
        let spans = match self.singleton(ObjectType::TracingStore).await? {
            Some(ObjectInner::TracingStore(store)) => match *store {
                TracingStore::Default => Destination::DataStore,
                TracingStore::Disabled => Destination::Disabled,
                _ => Destination::External,
            },
            _ => Destination::Disabled,
        };
        let metrics = match self.singleton(ObjectType::MetricsStore).await? {
            Some(ObjectInner::MetricsStore(store)) => match *store {
                MetricsStore::Default => Destination::DataStore,
                MetricsStore::Disabled => Destination::Disabled,
                _ => Destination::External,
            },
            _ => Destination::Disabled,
        };
        let index_spans = match self.singleton(ObjectType::Search).await? {
            Some(ObjectInner::Search(search)) => search.index_telemetry,
            _ => Search::default().index_telemetry,
        };
        Ok(TelemetryTargets {
            spans,
            metrics,
            index_spans,
        })
    }

    pub(super) async fn write_telemetry(
        &self,
        records: &[TelemetryRecord],
    ) -> model::Result<Vec<Issue>> {
        let targets = self.telemetry_targets().await?;
        let mut issues = Vec::new();
        let mut batch = self.global_batch();
        for record in records {
            let destination = match record.kind {
                TelemetryKind::Span => targets.spans,
                TelemetryKind::Metric => targets.metrics,
            };
            let reason = match destination {
                Destination::DataStore => None,
                Destination::Disabled => Some(DISABLED_STORE),
                Destination::External => Some(SHARED_STORE),
            };
            if let Some(reason) = reason {
                issues.push(skipped(record.kind.as_str(), record.id, reason));
                continue;
            }
            let value = match record.kind {
                TelemetryKind::Span => span(&record.json).map(|trace| trace.to_pickled_vec()),
                TelemetryKind::Metric => <Metric as Deserialize>::deserialize(&record.json)
                    .map(|metric| metric.to_pickled_vec()),
            };
            let value = match value {
                Ok(value) => value,
                Err(err) => {
                    issues.push(skipped(
                        record.kind.as_str(),
                        record.id,
                        format!("invalid v1 {}: {err}", record.kind.as_str()),
                    ));
                    continue;
                }
            };
            let weight = value.len() as u64;
            match record.kind {
                TelemetryKind::Span => {
                    batch.batch.set(
                        ValueClass::Telemetry(TelemetryClass::Span(record.id)),
                        value,
                    );
                    if targets.index_spans {
                        batch.batch.queue_trace_index(record.id);
                    }
                }
                TelemetryKind::Metric => {
                    batch.batch.set(
                        ValueClass::Telemetry(TelemetryClass::Metric(record.id)),
                        value,
                    );
                }
            }
            batch.record_done(weight);
        }
        batch.commit(&self.store).await?;
        Ok(issues)
    }
}
