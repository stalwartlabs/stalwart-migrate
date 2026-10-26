/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error, pool::SqliteConnectionManager};
use crate::*;
use ::registry::schema::structs;
use r2d2::Pool;
use tokio::sync::oneshot;

impl SqliteStore {
    pub fn open(config: structs::SqliteStore) -> Result<Store, String> {
        Ok(Store::SQLite(Arc::new(SqliteStore {
            conn_pool: Pool::builder()
                .max_size(config.pool_max_connections as u32)
                .build(SqliteConnectionManager::file(&config.path).with_init(|c| {
                    c.execute_batch(concat!(
                        "PRAGMA journal_mode = WAL; ",
                        "PRAGMA synchronous = NORMAL; ",
                        "PRAGMA temp_store = memory;",
                        "PRAGMA busy_timeout = 30000;"
                    ))
                }))
                .map_err(|err| format!("Failed to build connection pool: {err}"))?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .pool_workers
                        .filter(|v| *v > 0)
                        .map(|v| v as usize)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| format!("Failed to build worker pool: {err}"))?,
        })))
    }

    pub fn open_read_only(
        config: structs::SqliteStore,
    ) -> Result<(Store, SqliteReadOnlyMode), String> {
        let path = match std::fs::canonicalize(&config.path) {
            Ok(path) if path.is_file() => path.into_os_string().into_string().map_err(|_| {
                format!("SQLite database {} resolves to a non UTF-8 path", config.path)
            })?,
            _ => return Err(format!("SQLite database {} not found", config.path)),
        };
        let read_only =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let (location, flags, mode) = if std::path::Path::new(&format!("{path}-wal")).exists() {
            (path, read_only, SqliteReadOnlyMode::Live)
        } else {
            (
                immutable_uri(&path),
                read_only | rusqlite::OpenFlags::SQLITE_OPEN_URI,
                SqliteReadOnlyMode::Immutable,
            )
        };
        let store = Store::SQLite(Arc::new(SqliteStore {
            conn_pool: Pool::builder()
                .max_size(config.pool_max_connections as u32)
                .build(
                    SqliteConnectionManager::file(location)
                        .with_flags(flags)
                        .with_init(|c| {
                            c.execute_batch(concat!(
                                "PRAGMA query_only = ON; ",
                                "PRAGMA temp_store = memory; ",
                                "PRAGMA busy_timeout = 30000;"
                            ))
                        }),
                )
                .map_err(|err| format!("Failed to build connection pool: {err}"))?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .pool_workers
                        .filter(|v| *v > 0)
                        .map(|v| v as usize)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| format!("Failed to build worker pool: {err}"))?,
        }));
        Ok((store, mode))
    }

    #[cfg(feature = "test_mode")]
    pub fn open_memory() -> trc::Result<Self> {
        use super::into_error;

        let db = Self {
            conn_pool: Pool::builder()
                .max_size(1)
                .build(SqliteConnectionManager::memory())
                .map_err(into_error)?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .map_err(|err| {
                    into_error(err).ctx(trc::Key::Reason, "Failed to build worker pool")
                })?,
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(crate) fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_DELETED_ITEMS,
            SUBSPACE_SPAM_SAMPLES,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_REGISTRY,
            SUBSPACE_REGISTRY_PK,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_SEARCH_INDEX,
            SUBSPACE_DIRECTORY,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY,
                        v BLOB NOT NULL
                    )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_INDEXES, SUBSPACE_REGISTRY_IDX] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY
                )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA, SUBSPACE_IN_MEMORY_COUNTER] {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                    k BLOB PRIMARY KEY,
                    v INTEGER NOT NULL DEFAULT 0
                )",
                    char::from(table)
                ),
                [],
            )
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.scope(|s| {
            s.spawn(|_| {
                tx.send(f()).ok();
            });
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteReadOnlyMode {
    Immutable,
    Live,
}

fn immutable_uri(path: &str) -> String {
    use std::fmt::Write;
    let mut uri = String::with_capacity(path.len() + 24);
    uri.push_str(if path.starts_with('/') { "file://" } else { "file:" });
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            let _ = write!(uri, "%{byte:02X}");
        }
    }
    uri.push_str("?immutable=1");
    uri
}
