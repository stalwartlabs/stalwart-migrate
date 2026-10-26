/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ::registry::{schema::prelude::ObjectType, types::EnumImpl};
use model::{GlobalBatch, GlobalPage, InternalReportRecord, RegistryId, ReportKind, TaggedCursor};
use store::Store;

use crate::adapter::registry;

const KINDS: [(ReportKind, ObjectType); 2] = [
    (ReportKind::Dmarc, ObjectType::DmarcInternalReport),
    (ReportKind::Tls, ObjectType::TlsInternalReport),
];

pub(super) async fn page(
    store: &Store,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    let limit = limit.max(1);
    let mut records = Vec::with_capacity(limit.min(1024));
    let mut cursor = TaggedCursor::<{ KINDS.len() }>::decode(cursor)?;
    while let Some((tag, first)) = cursor.position() {
        let Some(&(kind, object)) = KINDS.get(tag) else {
            break;
        };
        let remaining = limit - records.len();
        let page = registry::page(store, object.as_str(), first.checked_sub(1), remaining).await?;
        let full = page.len() == remaining;
        if let Some(last) = page.last().and_then(|record| record.key.id.id()) {
            cursor.record(last);
        }
        records.extend(page.into_iter().filter_map(|record| match record.key.id {
            RegistryId::Id(id) => Some(InternalReportRecord {
                kind,
                id,
                json: record.json,
            }),
            RegistryId::Singleton => None,
        }));
        if full {
            return Ok(GlobalPage {
                batch: GlobalBatch::Reports(records),
                issues: Vec::new(),
                next: Some(cursor.encode()),
                resume: None,
            });
        }
        cursor.next_tag();
    }
    Ok(GlobalPage {
        batch: GlobalBatch::Reports(records),
        issues: Vec::new(),
        next: None,
        resume: Some(cursor.restart()),
    })
}
