/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    GlobalBatch, GlobalPage, InternalReportRecord, Issue, IssueKind, RegistryKey, ReportKind,
    Severity, Subject, TaggedCursor,
};
use registry::{
    schema::{
        prelude::{Deserialize as SerdeDeserialize, Object, ObjectInner, ObjectType},
        structs::{DmarcInternalReport, TlsInternalReport},
    },
    types::{EnumImpl, list::List},
};
use smtp::reporting::aggregate::{ReportItem, read_dmarc_records, read_tls_policies};
use store::{
    Deserialize, IterateParams, Store, U16_LEN, U64_LEN, ValueKey,
    backend::ephemeral::EphemeralStore,
    write::{BatchBuilder, RegistryClass, ValueClass, key::DeserializeBigEndian},
};

use crate::adapter::error::{corrupt, trc_error};

const ITEM_KEY_LEN: usize = U16_LEN + U64_LEN;

const KINDS: [(ReportKind, ObjectType); 2] = [
    (ReportKind::Dmarc, ObjectType::DmarcInternalReport),
    (ReportKind::Tls, ObjectType::TlsInternalReport),
];

fn item_key(object: ObjectType, item_id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Registry(RegistryClass::Item {
        object_id: object.to_id(),
        item_id,
    }))
}

async fn report(store: &Store, item_id: u64, key: &[u8], value: &[u8]) -> trc::Result<ObjectInner> {
    let mut inner = <Object as Deserialize>::deserialize_with_key(key, value)?.inner;
    match &mut inner {
        ObjectInner::DmarcInternalReport(report) => {
            read_dmarc_records(store, item_id, report, usize::MAX).await?
        }
        ObjectInner::TlsInternalReport(report) => {
            read_tls_policies(store, item_id, report, usize::MAX).await?
        }
        _ => {}
    }
    Ok(inner)
}

pub(super) async fn page(
    store: &Store,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    let limit = limit.max(1);
    let mut records = Vec::with_capacity(limit.min(1024));
    let mut issues = Vec::new();
    let mut raw = Vec::new();
    let mut cursor = TaggedCursor::<{ KINDS.len() }>::decode(cursor)?;
    while let Some((tag, first)) = cursor.position() {
        let Some(&(kind, object)) = KINDS.get(tag) else {
            break;
        };
        let remaining = limit - records.len() - issues.len();
        store
            .iterate(
                IterateParams::new(item_key(object, first), item_key(object, u64::MAX))
                    .ascending()
                    .limit(remaining),
                |key, value| {
                    if key.len() == ITEM_KEY_LEN {
                        raw.push((
                            key.deserialize_be_u64(U16_LEN)?,
                            key.to_vec(),
                            value.to_vec(),
                        ));
                    }
                    Ok(raw.len() < remaining)
                },
            )
            .await
            .map_err(trc_error)?;
        let full = raw.len() == remaining;
        if let Some((last, _, _)) = raw.last() {
            cursor.record(*last);
        }
        for (id, key, value) in raw.drain(..) {
            match report(store, id, &key, &value)
                .await
                .map_err(|err| err.to_string())
                .and_then(|inner| serde_json::to_value(&inner).map_err(|err| err.to_string()))
            {
                Ok(json) => records.push(InternalReportRecord { kind, id, json }),
                Err(err) => issues.push(Issue::new(
                    Severity::Warning,
                    IssueKind::Skipped,
                    Subject::Registry(RegistryKey::new(kind.as_str(), id)),
                    format!("undecodable v1 internal report: {err}"),
                )),
            }
        }
        if full {
            return Ok(GlobalPage {
                batch: GlobalBatch::Reports(records),
                issues,
                next: Some(cursor.encode()),
                resume: None,
            });
        }
        cursor.next_tag();
    }
    Ok(GlobalPage {
        batch: GlobalBatch::Reports(records),
        issues,
        next: None,
        resume: Some(cursor.restart()),
    })
}

async fn commit(store: &Store, mut batch: BatchBuilder) -> model::Result<()> {
    store.write_batch(&mut batch).await.map_err(trc_error)?;
    Ok(())
}

pub(crate) async fn stored(record: InternalReportRecord) -> model::Result<InternalReportRecord> {
    let store = EphemeralStore::open();
    let mut batch = BatchBuilder::new();
    let json = match record.kind {
        ReportKind::Dmarc => {
            let Ok(mut report) =
                <DmarcInternalReport as SerdeDeserialize>::deserialize(&record.json)
            else {
                return Ok(record);
            };
            let Ok(rows) = ReportItem::encode_dmarc_records(&report) else {
                return Ok(record);
            };
            ReportItem::new(ObjectType::DmarcInternalReport, record.id)
                .write_rows(&mut batch, rows);
            commit(&store, batch).await?;
            report.report.records = List::default();
            read_dmarc_records(&store, record.id, &mut report, usize::MAX)
                .await
                .map_err(trc_error)?;
            serde_json::to_value(&report)
        }
        ReportKind::Tls => {
            let Ok(mut report) = <TlsInternalReport as SerdeDeserialize>::deserialize(&record.json)
            else {
                return Ok(record);
            };
            if report.report.policies.is_empty()
                || report.policy_identifiers.is_empty()
                || report.policy_identifiers.len() == report.report.policies.len()
            {
                report.policy_identifiers.inner_mut().sort_unstable();
            } else {
                report.policy_identifiers.clear();
            }
            let Ok(rows) = ReportItem::encode_tls_policies(&report) else {
                return Ok(record);
            };
            ReportItem::new(ObjectType::TlsInternalReport, record.id).write_rows(&mut batch, rows);
            commit(&store, batch).await?;
            report.report.policies = List::default();
            report.policy_identifiers.clear();
            read_tls_policies(&store, record.id, &mut report, usize::MAX)
                .await
                .map_err(trc_error)?;
            serde_json::to_value(&report)
        }
    }
    .map_err(|err| corrupt(format!("{}/{}: {err}", record.kind.as_str(), record.id)))?;
    Ok(InternalReportRecord { json, ..record })
}
