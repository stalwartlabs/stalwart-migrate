/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rusqlite::Connection;

use crate::error::{Error, Result};

const SCHEMA_VERSION: i64 = 4;

const PRAGMAS: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 30000;
PRAGMA foreign_keys = OFF;
";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS run (
  id INTEGER PRIMARY KEY, started_at INTEGER, finished_at INTEGER,
  mode TEXT, status TEXT, stats TEXT
);

CREATE TABLE IF NOT EXISTS registry_object (
  object TEXT, id INTEGER, source_hash BLOB, target_hash BLOB, stored_hash BLOB, run_id INTEGER,
  source_json BLOB, status TEXT, singleton INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (object, id)
);

CREATE TABLE IF NOT EXISTS account (
  account_id INTEGER PRIMARY KEY,
  phase TEXT, checkpoint INTEGER, full_target INTEGER,
  attempts INTEGER DEFAULT 0, last_error TEXT, updated_at INTEGER,
  synced INTEGER NOT NULL DEFAULT 0, full_run INTEGER
);

CREATE TABLE IF NOT EXISTS cursor (
  account_id INTEGER, collection INTEGER, mode TEXT, last_id INTEGER,
  PRIMARY KEY (account_id, collection, mode)
);

CREATE TABLE IF NOT EXISTS blob (
  hash BLOB PRIMARY KEY, size INTEGER, run_id INTEGER
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS global_cursor (name TEXT PRIMARY KEY, value BLOB);

CREATE TABLE IF NOT EXISTS global_record (
  kind INTEGER, id INTEGER, generation INTEGER,
  PRIMARY KEY (kind, id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS registry_fallback (
  object TEXT, id INTEGER, singleton INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (object, id, singleton)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS telemetry_seen (
  kind INTEGER, id INTEGER,
  PRIMARY KEY (kind, id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS registry_pending (
  object TEXT, id INTEGER, singleton INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (object, id, singleton)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS report (
  id INTEGER PRIMARY KEY, run_id INTEGER, severity TEXT, category TEXT,
  account_id INTEGER, object TEXT, object_id INTEGER, message TEXT, explains TEXT
);

CREATE INDEX IF NOT EXISTS report_run ON report (run_id);
CREATE INDEX IF NOT EXISTS report_account ON report (account_id);
CREATE INDEX IF NOT EXISTS account_phase ON account (phase);
CREATE INDEX IF NOT EXISTS report_error ON report (account_id, object, object_id) WHERE severity = 'error';
CREATE INDEX IF NOT EXISTS report_account_error ON report (category, run_id) WHERE severity = 'error' AND object IS NULL;
DROP INDEX IF EXISTS report_subject;
CREATE INDEX IF NOT EXISTS report_subject_account ON report (run_id, object, object_id, account_id) WHERE object IS NOT NULL;
";

pub(super) fn check_readable(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "query_only", true)?;
    conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let version = schema_version(conn)?;
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Error::Corrupt(
            format!("state schema version {version} differs from {SCHEMA_VERSION}")
                .into_boxed_str(),
        ))
    }
}

fn schema_version(conn: &Connection) -> Result<i64> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(Error::Corrupt(
            format!("state schema version {version} is newer than supported {SCHEMA_VERSION}")
                .into_boxed_str(),
        ));
    }
    Ok(version)
}

pub(super) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(PRAGMAS)?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::Sqlite(
            format!("cannot enable WAL journal mode (got {mode})").into_boxed_str(),
        ));
    }
    let version = schema_version(conn)?;
    let tables: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
        [],
        |row| row.get(0),
    )?;
    if version == 0 && tables > 0 {
        return Err(Error::Corrupt(
            "the state database has tables but no schema version; use a new --state directory"
                .into(),
        ));
    }
    if version != 0 && version != SCHEMA_VERSION {
        return Err(Error::Corrupt(
            format!(
                "state schema version {version} was written by a development build; use a new --state directory"
            )
            .into_boxed_str(),
        ));
    }
    conn.execute_batch(SCHEMA)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}
