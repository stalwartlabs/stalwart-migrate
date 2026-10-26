/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{InternalReportRecord, Issue, IssueKind, RegistryKey, ReportKind, Severity, Subject};
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{DmarcInternalReport, TlsInternalReport},
    },
    types::{EnumImpl, list::List},
};
use serde::Deserialize;
use smtp::reporting::{aggregate::ReportItem, index::InternalReportIndex};
use store::write::{BatchBuilder, RegistryClass, ValueClass};

use super::skipped;
use crate::{
    prefetch::{Prefetched, keep_last},
    target::V1Target,
};

const OVERSIZED: &str = "a report row exceeds the v1 row size limit; the report was not copied";
const UNPAIRED_POLICIES: &str = "the report's policy identifiers do not match its policies one to one; v1 keys each policy by its content instead, so sessions v1 adds to this report later may be listed under a second copy of a policy";

impl V1Target {
    pub(super) async fn write_reports(
        &self,
        records: &[InternalReportRecord],
    ) -> model::Result<Vec<Issue>> {
        let mut issues = Vec::new();
        let mut batch = self.global_batch();
        let records = keep_last(records.iter(), |record| (record.kind, record.id));
        let current = self
            .prefetch(
                records
                    .iter()
                    .map(|record| item_key(record.kind, record.id)),
            )
            .await?;
        for record in records {
            let written = match record.kind {
                ReportKind::Dmarc => write_dmarc_report(&mut batch.batch, &current, record)?,
                ReportKind::Tls => {
                    write_tls_report(&mut batch.batch, &current, record, &mut issues)?
                }
            };
            match written {
                Ok(()) => batch.record_done(json_weight(&record.json)),
                Err(message) => {
                    if delete_report(&mut batch.batch, &current, record.kind, record.id)? {
                        batch.record_done(json_weight(&record.json));
                    }
                    issues.push(skipped(record.kind.as_str(), record.id, message));
                }
            }
        }
        batch.commit(&self.store).await?;
        Ok(issues)
    }
}

fn write_dmarc_report(
    batch: &mut BatchBuilder,
    current: &Prefetched,
    record: &InternalReportRecord,
) -> model::Result<Result<(), String>> {
    let mut report = match <DmarcInternalReport as Deserialize>::deserialize(&record.json) {
        Ok(report) => report,
        Err(err) => return Ok(Err(format!("invalid v1 DMARC report: {err}"))),
    };
    let item = ReportItem::new(report_object(ReportKind::Dmarc), record.id);
    let Ok(rows) = ReportItem::encode_dmarc_records(&report) else {
        return Ok(Err(OVERSIZED.into()));
    };
    if let Some(current) =
        current.get::<DmarcInternalReport>(item_key(ReportKind::Dmarc, record.id))?
    {
        current.write_ops(batch, record.id, false);
    }
    item.clear(batch);
    item.write_rows(batch, rows);
    report.report.records = List::default();
    report.write_header(batch, record.id);
    Ok(Ok(()))
}

fn write_tls_report(
    batch: &mut BatchBuilder,
    current: &Prefetched,
    record: &InternalReportRecord,
    issues: &mut Vec<Issue>,
) -> model::Result<Result<(), String>> {
    let mut report = match <TlsInternalReport as Deserialize>::deserialize(&record.json) {
        Ok(report) => report,
        Err(err) => return Ok(Err(format!("invalid v1 TLS report: {err}"))),
    };
    if report.report.policies.is_empty()
        || report.policy_identifiers.is_empty()
        || report.policy_identifiers.len() == report.report.policies.len()
    {
        report.policy_identifiers.inner_mut().sort_unstable();
    } else {
        report.policy_identifiers.clear();
        issues.push(Issue::new(
            Severity::Warning,
            IssueKind::Changed,
            Subject::Registry(RegistryKey::new(ReportKind::Tls.as_str(), record.id)),
            UNPAIRED_POLICIES,
        ));
    }
    let item = ReportItem::new(report_object(ReportKind::Tls), record.id);
    let Ok(rows) = ReportItem::encode_tls_policies(&report) else {
        return Ok(Err(OVERSIZED.into()));
    };
    if let Some(current) = current.get::<TlsInternalReport>(item_key(ReportKind::Tls, record.id))? {
        current.write_ops(batch, record.id, false);
    }
    item.clear(batch);
    item.write_rows(batch, rows);
    report.report.policies = List::default();
    report.policy_identifiers.clear();
    report.write_header(batch, record.id);
    Ok(Ok(()))
}

pub(super) fn delete_report(
    batch: &mut BatchBuilder,
    current: &Prefetched,
    kind: ReportKind,
    id: u64,
) -> model::Result<bool> {
    let key = item_key(kind, id);
    let found = match kind {
        ReportKind::Dmarc => current
            .get::<DmarcInternalReport>(key)?
            .map(|report| report.write_ops(batch, id, false)),
        ReportKind::Tls => current
            .get::<TlsInternalReport>(key)?
            .map(|report| report.write_ops(batch, id, false)),
    };
    if found.is_some() {
        ReportItem::new(report_object(kind), id).clear(batch);
    }
    Ok(found.is_some())
}

pub(super) fn item_key(kind: ReportKind, id: u64) -> ValueClass {
    ValueClass::Registry(RegistryClass::Item {
        object_id: report_object(kind).to_id(),
        item_id: id,
    })
}

const fn report_object(kind: ReportKind) -> ObjectType {
    match kind {
        ReportKind::Dmarc => ObjectType::DmarcInternalReport,
        ReportKind::Tls => ObjectType::TlsInternalReport,
    }
}

fn json_weight(json: &serde_json::Value) -> u64 {
    match json {
        serde_json::Value::String(value) => value.len() as u64,
        serde_json::Value::Array(values) => values.iter().map(json_weight).sum(),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| key.len() as u64 + json_weight(value))
            .sum(),
        _ => 8,
    }
}
