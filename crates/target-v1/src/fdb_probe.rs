/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use foundationdb::{Database, FdbError, KeySelector, RangeOption, options::DatabaseOption};
use registry::schema::structs::FoundationDbStore;

const SYSTEM_PREFIX: u8 = 0xFF;
const MAX_ATTEMPTS: usize = 10;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn probe_error(err: FdbError) -> model::Error {
    model::Error::fatal(format!(
        "cannot list the key prefixes of the FoundationDB cluster: {err}"
    ))
}

fn millis(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

fn open_database(config: &FoundationDbStore) -> Result<Database, FdbError> {
    let db = Database::new(config.cluster_file.as_deref())?;
    let timeout = config
        .transaction_timeout
        .map_or(DEFAULT_TIMEOUT, |value| value.into_inner());
    db.set_option(DatabaseOption::TransactionTimeout(millis(timeout)))?;
    if let Some(value) = config.transaction_retry_limit {
        db.set_option(DatabaseOption::TransactionRetryLimit(
            i32::try_from(value).unwrap_or(i32::MAX),
        ))?;
    }
    if let Some(value) = config.transaction_retry_delay {
        db.set_option(DatabaseOption::TransactionMaxRetryDelay(millis(
            value.into_inner(),
        )))?;
    }
    if let Some(value) = &config.machine_id {
        db.set_option(DatabaseOption::MachineId(value.clone()))?;
    }
    if let Some(value) = &config.datacenter_id {
        db.set_option(DatabaseOption::DatacenterId(value.clone()))?;
    }
    Ok(db)
}

pub(crate) async fn foreign_prefix(
    config: &FoundationDbStore,
    is_store_prefix: impl Fn(u8) -> bool,
) -> model::Result<Option<Box<str>>> {
    let db = open_database(config).map_err(probe_error)?;
    let mut from = Vec::new();
    loop {
        let range = RangeOption {
            begin: KeySelector::first_greater_or_equal(from.as_slice()),
            end: KeySelector::first_greater_or_equal(&[SYSTEM_PREFIX][..]),
            limit: Some(1),
            ..RangeOption::default()
        };
        let mut trx = db.create_trx().map_err(probe_error)?;
        let mut attempt = 1;
        let values = loop {
            match trx.get_range(&range, 1, true).await {
                Ok(values) => break values,
                Err(err) if attempt < MAX_ATTEMPTS => {
                    attempt += 1;
                    trx = trx.on_error(err).await.map_err(probe_error)?;
                }
                Err(err) => return Err(probe_error(err)),
            }
        };
        let Some(value) = values.iter().next() else {
            return Ok(None);
        };
        let Some(&prefix) = value.key().first() else {
            return Ok(Some("the empty key".into()));
        };
        if !is_store_prefix(prefix) {
            return Ok(Some(format!("keys under the prefix {prefix:#04x}").into()));
        }
        let Some(next) = prefix.checked_add(1).filter(|next| *next < SYSTEM_PREFIX) else {
            return Ok(None);
        };
        from.clear();
        from.push(next);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use registry::schema::structs::FoundationDbStore;

    async fn probe_unreachable(
        timeout: Option<u64>,
    ) -> (model::Result<Option<Box<str>>>, Duration) {
        store::backend::foundationdb::FdbStore::boot_network().expect("fdb network");
        let dir = tempfile::tempdir().expect("tempdir");
        let cluster_file = dir.path().join("fdb.cluster");
        std::fs::write(&cluster_file, "probe:probe@127.0.0.1:1\n").expect("cluster file");
        let mut config = serde_json::json!({"clusterFile": cluster_file.to_string_lossy()});
        if let Some(timeout) = timeout {
            config["transactionTimeout"] = timeout.into();
        }
        let config: FoundationDbStore = serde_json::from_value(config).expect("config");
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            super::foreign_prefix(&config, |_| true),
        )
        .await
        .expect("the probe must not block on an unreachable cluster");
        (result, started.elapsed())
    }

    // An unreachable cluster fails the probe once the configured transaction timeout expires instead of blocking forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn unreachable_cluster_times_out() {
        let (result, elapsed) = probe_unreachable(Some(1_000)).await;
        assert!(result.is_err(), "{result:?}");
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    }

    // Without a configured transaction timeout the probe still gives up, after the 30 s default.
    #[tokio::test(flavor = "multi_thread")]
    async fn unreachable_cluster_uses_the_default_timeout() {
        let (result, elapsed) = probe_unreachable(None).await;
        assert!(result.is_err(), "{result:?}");
        assert!(elapsed >= super::DEFAULT_TIMEOUT, "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(60), "{elapsed:?}");
    }
}
