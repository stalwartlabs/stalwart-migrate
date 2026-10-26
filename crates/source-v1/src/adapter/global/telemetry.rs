/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use model::{
    GlobalBatch, GlobalPage, Issue, IssueKind, RegistryKey, Severity, Subject, TaggedCursor,
    TelemetryKind, TelemetryRecord,
};
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs::{DataStore, Metric, MetricsStore, Trace, TracingStore},
    },
    types::EnumImpl,
};
use store::{
    Deserialize, IterateParams, Store, U64_LEN, ValueKey,
    write::{RegistryClass, TelemetryClass, ValueClass, key::DeserializeBigEndian},
};
use types::id::Id;

use crate::adapter::{PathRewrite, error::trc_error, rewrite_data_store};

const KINDS: [TelemetryKind; 2] = [TelemetryKind::Span, TelemetryKind::Metric];
const NODE_ID: &str = "nodeId";

pub(crate) struct TelemetryStores {
    spans: Option<Store>,
    metrics: Option<Store>,
}

impl TelemetryStores {
    pub(crate) async fn open(data: &Store, rewrite: Option<&PathRewrite>) -> model::Result<Self> {
        let spans = match singleton(data, ObjectType::TracingStore).await? {
            Some(ObjectInner::TracingStore(store)) => match *store {
                TracingStore::FoundationDb(store) => Some(DataStore::FoundationDb(store)),
                TracingStore::PostgreSql(store) => Some(DataStore::PostgreSql(store)),
                TracingStore::MySql(store) => Some(DataStore::MySql(store)),
                TracingStore::Default | TracingStore::Disabled => None,
            },
            _ => None,
        };
        let metrics = match singleton(data, ObjectType::MetricsStore).await? {
            Some(ObjectInner::MetricsStore(store)) => match *store {
                MetricsStore::FoundationDb(store) => Some(DataStore::FoundationDb(store)),
                MetricsStore::PostgreSql(store) => Some(DataStore::PostgreSql(store)),
                MetricsStore::MySql(store) => Some(DataStore::MySql(store)),
                MetricsStore::Default | MetricsStore::Disabled => None,
            },
            _ => None,
        };
        let same = spans == metrics;
        let spans = match spans {
            Some(store) => Some(build(rewrite_data_store(store, rewrite)).await?),
            None => None,
        };
        let metrics = match metrics {
            Some(_) if same => spans.clone(),
            Some(store) => Some(build(rewrite_data_store(store, rewrite)).await?),
            None => None,
        };
        Ok(TelemetryStores { spans, metrics })
    }
}

async fn build(store: DataStore) -> model::Result<Store> {
    Store::build(store)
        .await
        .map_err(|err| model::Error::fatal(format!("cannot open the v1 telemetry store: {err}")))
}

async fn singleton(data: &Store, object: ObjectType) -> model::Result<Option<ObjectInner>> {
    data.get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
        object_id: object.to_id(),
        item_id: Id::singleton().id(),
    })))
    .await
    .map(|object| object.map(|object| object.inner))
    .map_err(trc_error)
}

fn key(kind: TelemetryKind, id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Telemetry(match kind {
        TelemetryKind::Span => TelemetryClass::Span(id),
        TelemetryKind::Metric => TelemetryClass::Metric(id),
    }))
}

fn decode(kind: TelemetryKind, value: &[u8]) -> Result<serde_json::Value, String> {
    match kind {
        TelemetryKind::Span => <Trace as Deserialize>::deserialize(value)
            .map_err(|err| err.to_string())
            .and_then(|trace| serde_json::to_value(trace).map_err(|err| err.to_string())),
        TelemetryKind::Metric => <Metric as Deserialize>::deserialize(value)
            .map_err(|err| err.to_string())
            .and_then(|metric| serde_json::to_value(metric).map_err(|err| err.to_string()))
            .map(|mut json| {
                if let Some(object) = json.as_object_mut()
                    && object.get(NODE_ID).and_then(serde_json::Value::as_u64) == Some(0)
                {
                    object.remove(NODE_ID);
                }
                json
            }),
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
        store
            .iterate(
                IterateParams::new(key(kind, first), key(kind, u64::MAX))
                    .ascending()
                    .limit(remaining),
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
                    format!("undecodable v1 {}: {err}", kind.as_str()),
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
    Ok(GlobalPage {
        batch: GlobalBatch::Telemetry(records),
        issues,
        next: None,
        resume: Some(cursor.restart()),
    })
}
