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
        structs::{Metric, MetricsStore, Search, Trace, TracingStore},
    },
    types::ObjectImpl,
};
use serde::Deserialize;
use store::write::{TelemetryClass, ValueClass};

use super::skipped;
use crate::target::V1Target;

const SHARED_STORE: &str = "the v1 telemetry store is not the target data store and may be shared with v0.16; the record was not copied";
const DISABLED_STORE: &str = "the v1 telemetry store is disabled; the record was not copied";

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
                TelemetryKind::Span => <Trace as Deserialize>::deserialize(&record.json)
                    .map(|trace| trace.to_pickled_vec()),
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
