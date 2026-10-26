/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! run_stats {
    ($($field:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct RunStats {
            $(pub $field: AtomicU64,)*
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct StatsSnapshot {
            $(pub $field: u64,)*
        }

        impl RunStats {
            pub fn snapshot(&self) -> StatsSnapshot {
                StatsSnapshot {
                    $($field: self.$field.load(Ordering::Relaxed),)*
                }
            }
        }

        impl StatsSnapshot {
            pub fn log_progress(&self, run_id: i64) {
                tracing::info!(
                    target: "progress",
                    run_id,
                    $($field = self.$field,)*
                    "progress"
                );
            }

            pub fn to_json(&self) -> serde_json::Value {
                serde_json::json!({
                    $(stringify!($field): self.$field,)*
                })
            }
        }
    };
}

run_stats!(
    objects_written,
    emails_written,
    bytes_written,
    objects_skipped,
    objects_deleted,
    log_rows,
    blobs_copied,
    blob_bytes,
    registry_written,
    registry_dropped,
    registry_deleted,
    accounts_full,
    accounts_delta,
    accounts_unchanged,
    accounts_failed,
    accounts_wiped,
    accounts_removed,
    global_records,
    global_deleted,
    issues,
    errors,
);

pub(crate) fn add(counter: &AtomicU64, value: u64) {
    counter.fetch_add(value, Ordering::Relaxed);
}

pub(crate) fn incr(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}
