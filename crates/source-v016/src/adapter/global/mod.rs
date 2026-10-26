/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod queue;
mod reports;
pub(crate) mod spam;
mod tasks;
pub(crate) mod telemetry;

use model::{GlobalCategory, GlobalPage};
use store::{BlobStore, Store, U64_LEN};
use tokio::sync::OnceCell;

pub(crate) use telemetry::{TelemetryConfig, TelemetryStores};

pub(super) async fn page(
    data: &Store,
    blob: &BlobStore,
    telemetry: &OnceCell<TelemetryStores>,
    telemetry_config: &TelemetryConfig,
    category: GlobalCategory,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    match category {
        GlobalCategory::Tasks => tasks::page(data, cursor, limit).await,
        GlobalCategory::SpamModel => spam::page(blob).await,
        GlobalCategory::Telemetry => {
            let telemetry = telemetry
                .get_or_try_init(|| TelemetryStores::open(telemetry_config))
                .await
                .map_err(|err| model::Error::fatal(err.to_string()))?;
            telemetry::page(telemetry, data, cursor, limit).await
        }
        GlobalCategory::Queue => queue::page(data, cursor, limit).await,
        GlobalCategory::Reports => reports::page(data, cursor, limit).await,
    }
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
