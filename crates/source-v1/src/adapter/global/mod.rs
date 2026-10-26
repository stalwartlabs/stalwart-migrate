/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod queue;
mod reports;
mod tasks;
#[cfg(feature = "enterprise")]
mod telemetry;

use model::{
    GlobalBatch, GlobalCategory, GlobalPage, Issue, IssueKind, RegistryKey, Severity, Subject,
};
use store::U64_LEN;

pub(super) use reports::stored as stored_report;
pub use tasks::{is_derived_task_id, is_singleton_task, is_singleton_task_id, singleton_task_id};
#[cfg(feature = "enterprise")]
pub(crate) use telemetry::TelemetryStores;

use super::{V1Source, trc_error};
use crate::spam_archive::{self, SpamBlob};

pub(super) async fn page(
    source: &V1Source,
    category: GlobalCategory,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    let data = source.data();
    match category {
        GlobalCategory::SpamModel => spam_model(source).await,
        #[cfg(feature = "enterprise")]
        GlobalCategory::Telemetry => {
            telemetry::page(source.telemetry_stores().await?, data, cursor, limit).await
        }
        #[cfg(not(feature = "enterprise"))]
        GlobalCategory::Telemetry => Ok(GlobalPage::last(GlobalBatch::Telemetry(Vec::new()))),
        GlobalCategory::Queue => queue::page(data, cursor, limit).await,
        GlobalCategory::Reports => reports::page(data, cursor, limit).await,
        GlobalCategory::Tasks => tasks::page(data, cursor, limit).await,
    }
}

async fn spam_model(source: &V1Source) -> model::Result<GlobalPage> {
    let blob = source.blob_store().await?;
    let mut records = Vec::with_capacity(SpamBlob::ALL.len());
    let mut issues = Vec::new();
    for kind in SpamBlob::ALL {
        let Some(data) = blob
            .get_blob(kind.key(), 0..usize::MAX)
            .await
            .map_err(trc_error)?
        else {
            continue;
        };
        match spam_archive::decode(kind, &data) {
            Ok(record) => records.push(record),
            Err(err) => issues.push(Issue::new(
                Severity::Warning,
                IssueKind::Skipped,
                Subject::Registry(RegistryKey::new(kind.as_str(), 0)),
                format!("undecodable v1 spam model: {err}"),
            )),
        }
    }
    Ok(GlobalPage {
        batch: GlobalBatch::SpamModel(records),
        issues,
        next: None,
        resume: None,
    })
}

fn invalid_cursor() -> model::Error {
    model::Error::fatal("invalid global cursor")
}

fn id_cursor(cursor: Option<&[u8]>) -> model::Result<Option<u64>> {
    match cursor {
        None => Ok(Some(0)),
        Some(cursor) => {
            let last: [u8; U64_LEN] = cursor.try_into().map_err(|_| invalid_cursor())?;
            Ok(u64::from_be_bytes(last).checked_add(1))
        }
    }
}
