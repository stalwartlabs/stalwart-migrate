/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use model::{
    BlobHash, CategorySet, Collection, Explanation, GlobalCategory, GlobalKey, IssueKind,
    RegistryId, RegistryKey, Severity, TelemetryKind,
};
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::codec::{
    GlobalKeyColumns, decode_u64, encode_u64, get_opt_u64, get_severity, get_u32, get_u64, now,
};
use crate::{
    error::{Error, Result},
    types::{
        AccountPhase, AccountState, AccountUpdate, ContentHash, CursorMode, CursorRow,
        FailedDocument, MetaKey, PhaseCount, RegistryState, RegistryStatus, RegistryUpdate,
        ReportCount, ReportFilter, ReportRow, ReportScope, ReportsAdded, RunId, RunMode, RunRecord,
        RunStart, RunStatus,
    },
};

const SOURCE_JSON_LEVEL: i32 = 3;

fn encode_registry_id(id: RegistryId) -> (i64, bool) {
    match id {
        RegistryId::Singleton => (0, true),
        RegistryId::Id(id) => (encode_u64(id), false),
    }
}

fn decode_registry_id(value: i64, singleton: bool) -> RegistryId {
    if singleton {
        RegistryId::Singleton
    } else {
        RegistryId::Id(decode_u64(value))
    }
}

pub(super) fn meta(conn: &Connection, key: MetaKey) -> Result<Option<String>> {
    conn.prepare_cached("SELECT value FROM meta WHERE key = ?1")?
        .query_row([key], |row| row.get(0))
        .optional()
        .map_err(Error::from)
}

pub(super) fn set_meta(conn: &Connection, key: MetaKey, value: &str) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )?
    .execute(params![key, value])?;
    Ok(())
}

pub(super) fn remove_meta(conn: &Connection, key: MetaKey) -> Result<()> {
    conn.prepare_cached("DELETE FROM meta WHERE key = ?1")?
        .execute(params![key])?;
    Ok(())
}

pub(super) fn begin_run(conn: &Connection, mode: RunMode) -> Result<RunStart> {
    let interrupted = conn
        .prepare_cached("UPDATE run SET status = ?1 WHERE status = ?2 RETURNING id")?
        .query_map(params![RunStatus::Interrupted, RunStatus::Running], |row| {
            row.get::<_, i64>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    conn.prepare_cached("INSERT INTO run (started_at, mode, status) VALUES (?1, ?2, ?3)")?
        .execute(params![now(), mode, RunStatus::Running])?;
    Ok(RunStart {
        run_id: conn.last_insert_rowid(),
        interrupted,
    })
}

pub(super) fn finish_run(
    conn: &Connection,
    run_id: RunId,
    status: RunStatus,
    stats: &str,
) -> Result<()> {
    conn.prepare_cached("UPDATE run SET finished_at = ?1, status = ?2, stats = ?3 WHERE id = ?4")?
        .execute(params![now(), status, stats, run_id])?;
    Ok(())
}

pub(super) fn runs(conn: &Connection, limit: u32) -> Result<Vec<RunRecord>> {
    conn.prepare_cached(
        "SELECT id, started_at, finished_at, mode, status, stats FROM run ORDER BY id DESC LIMIT ?1",
    )?
    .query_map([limit], |row| {
        Ok(RunRecord {
            id: row.get(0)?,
            started_at: row.get(1)?,
            finished_at: row.get(2)?,
            mode: row.get(3)?,
            status: row.get(4)?,
            stats: row.get(5)?,
        })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Error::from)
}

pub(super) fn last_run_except(
    conn: &Connection,
    mode: RunMode,
    before: RunId,
) -> Result<Option<RunRecord>> {
    conn.prepare_cached(
        "SELECT id, started_at, finished_at, mode, status, stats FROM run WHERE mode != ?1 AND id < ?2 ORDER BY id DESC LIMIT 1",
    )?
    .query_row(params![mode, before], |row| {
        Ok(RunRecord {
            id: row.get(0)?,
            started_at: row.get(1)?,
            finished_at: row.get(2)?,
            mode: row.get(3)?,
            status: row.get(4)?,
            stats: row.get(5)?,
        })
    })
    .optional()
    .map_err(Error::from)
}

macro_rules! select_account {
    ($tail:literal) => {
        concat!(
            "SELECT account_id, phase, checkpoint, full_target, attempts, last_error, updated_at, synced, full_run FROM account ",
            $tail
        )
    };
}

fn account_row(row: &Row<'_>) -> rusqlite::Result<AccountState> {
    Ok(AccountState {
        account_id: get_u32(row, 0)?,
        phase: row.get(1)?,
        checkpoint: get_opt_u64(row, 2)?,
        full_target: get_opt_u64(row, 3)?,
        attempts: row.get::<_, Option<u32>>(4)?.unwrap_or_default(),
        last_error: row.get::<_, Option<String>>(5)?.map(String::into_boxed_str),
        updated_at: row.get::<_, Option<i64>>(6)?.unwrap_or_default(),
        synced: CategorySet::from_bits(row.get::<_, u32>(7)?),
        full_run: row.get(8)?,
    })
}

pub(super) fn account(conn: &Connection, account_id: u32) -> Result<Option<AccountState>> {
    conn.prepare_cached(select_account!("WHERE account_id = ?1"))?
        .query_row([account_id], account_row)
        .optional()
        .map_err(Error::from)
}

pub(super) fn accounts(conn: &Connection) -> Result<Vec<AccountState>> {
    conn.prepare_cached(select_account!("ORDER BY account_id"))?
        .query_map([], account_row)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::from)
}

pub(super) fn failed_accounts(conn: &Connection, limit: u32) -> Result<Vec<AccountState>> {
    conn.prepare_cached(select_account!(
        "WHERE phase = ?1 ORDER BY account_id LIMIT ?2"
    ))?
    .query_map(params![AccountPhase::Error, limit], account_row)?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Error::from)
}

pub(super) fn phase_counts(conn: &Connection) -> Result<Vec<PhaseCount>> {
    conn.prepare_cached("SELECT phase, COUNT(*) FROM account GROUP BY phase ORDER BY phase")?
        .query_map([], |row| {
            Ok(PhaseCount {
                phase: row.get(0)?,
                count: get_u64(row, 1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::from)
}

pub(super) fn update_account(conn: &Connection, update: &AccountUpdate) -> Result<()> {
    let now = now();
    match update {
        AccountUpdate::StartFull {
            account_id,
            full_target,
            run_id,
        } => {
            conn.prepare_cached(
                "INSERT INTO account (account_id, phase, checkpoint, full_target, attempts, updated_at, full_run)
                 VALUES (?1, ?2, NULL, ?3, 0, ?4, ?5)
                 ON CONFLICT (account_id) DO UPDATE SET phase = excluded.phase, checkpoint = NULL,
                 full_target = excluded.full_target, updated_at = excluded.updated_at, synced = 0,
                 full_run = excluded.full_run",
            )?
            .execute(params![
                account_id,
                AccountPhase::Containers,
                encode_u64(*full_target),
                now,
                run_id
            ])?;
            delete_cursors(conn, *account_id)?;
        }
        AccountUpdate::SetPhase { account_id, phase } => {
            conn.prepare_cached(
                "INSERT INTO account (account_id, phase, attempts, updated_at) VALUES (?1, ?2, 0, ?3)
                 ON CONFLICT (account_id) DO UPDATE SET phase = excluded.phase,
                 updated_at = excluded.updated_at",
            )?
            .execute(params![account_id, phase, now])?;
        }
        AccountUpdate::Complete {
            account_id,
            checkpoint,
            synced,
        } => {
            conn.prepare_cached(
                "INSERT INTO account (account_id, phase, checkpoint, full_target, attempts, last_error, updated_at, synced)
                 VALUES (?1, ?2, ?3, NULL, 0, NULL, ?4, ?5)
                 ON CONFLICT (account_id) DO UPDATE SET phase = excluded.phase,
                 checkpoint = excluded.checkpoint, full_target = NULL, attempts = 0,
                 last_error = NULL, updated_at = excluded.updated_at, synced = excluded.synced",
            )?
            .execute(params![
                account_id,
                AccountPhase::Done,
                encode_u64(*checkpoint),
                now,
                synced.bits()
            ])?;
            conn.prepare_cached(
                "DELETE FROM cursor WHERE account_id = ?1 AND mode IN (?2, ?3, ?4, ?5)",
            )?
            .execute(params![
                account_id,
                CursorMode::Full,
                CursorMode::Pending,
                CursorMode::Finalized,
                CursorMode::Started
            ])?;
        }
        AccountUpdate::Fail { account_id, error } => {
            conn.prepare_cached(
                "INSERT INTO account (account_id, phase, attempts, last_error, updated_at)
                 VALUES (?1, ?2, 1, ?3, ?4)
                 ON CONFLICT (account_id) DO UPDATE SET phase = excluded.phase,
                 attempts = COALESCE(attempts, 0) + 1, last_error = excluded.last_error,
                 updated_at = excluded.updated_at",
            )?
            .execute(params![account_id, AccountPhase::Error, &**error, now])?;
        }
        AccountUpdate::Wiped { account_id, run_id } => {
            conn.prepare_cached(
                "INSERT INTO account (account_id, phase, attempts, updated_at, full_run) VALUES (?1, ?2, 0, ?3, ?4)
                 ON CONFLICT (account_id) DO UPDATE SET phase = excluded.phase, checkpoint = NULL,
                 full_target = NULL, updated_at = excluded.updated_at, synced = 0,
                 full_run = excluded.full_run",
            )?
            .execute(params![account_id, AccountPhase::Wiped, now, run_id])?;
            delete_cursors(conn, *account_id)?;
        }
        AccountUpdate::Remove { account_id } => {
            conn.prepare_cached("DELETE FROM account WHERE account_id = ?1")?
                .execute([account_id])?;
            delete_cursors(conn, *account_id)?;
        }
    }
    Ok(())
}

fn delete_cursors(conn: &Connection, account_id: u32) -> Result<()> {
    conn.prepare_cached("DELETE FROM cursor WHERE account_id = ?1")?
        .execute([account_id])?;
    Ok(())
}

pub(super) fn cursors(conn: &Connection, account_id: u32) -> Result<Vec<CursorRow>> {
    conn.prepare_cached(
        "SELECT collection, mode, last_id FROM cursor WHERE account_id = ?1 ORDER BY collection, mode",
    )?
    .query_map([account_id], |row| {
        Ok(CursorRow {
            collection: row.get(0)?,
            mode: row.get(1)?,
            last_id: get_u64(row, 2)?,
        })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Error::from)
}

pub(super) fn set_cursor(
    conn: &Connection,
    account_id: u32,
    collection: u8,
    mode: CursorMode,
    last_id: u64,
) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO cursor (account_id, collection, mode, last_id) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (account_id, collection, mode) DO UPDATE SET last_id =
             CASE WHEN excluded.mode = 'pending' THEN max(last_id, excluded.last_id) ELSE excluded.last_id END",
    )?
    .execute(params![account_id, collection, mode, encode_u64(last_id)])?;
    Ok(())
}

struct RegistryRow {
    key: RegistryKey,
    source_hash: Vec<u8>,
    target_hash: Option<Vec<u8>>,
    stored_hash: Option<Vec<u8>>,
    status: RegistryStatus,
}

fn registry_row(row: &Row<'_>) -> rusqlite::Result<RegistryRow> {
    Ok(RegistryRow {
        key: RegistryKey {
            object: row.get::<_, String>(0)?.into_boxed_str(),
            id: decode_registry_id(row.get(1)?, row.get(5)?),
        },
        source_hash: row.get(2)?,
        target_hash: row.get(3)?,
        status: row.get(4)?,
        stored_hash: row.get(6)?,
    })
}

fn registry_state(
    RegistryRow {
        key,
        source_hash,
        target_hash,
        stored_hash,
        status,
    }: RegistryRow,
) -> Result<RegistryState> {
    let source_hash = ContentHash::from_slice(&source_hash)
        .ok_or_else(|| Error::Corrupt(format!("invalid source hash for {key}").into_boxed_str()))?;
    let target_hash = optional_hash(target_hash, "target", &key)?;
    let stored_hash = optional_hash(stored_hash, "stored", &key)?;
    Ok(RegistryState {
        key,
        source_hash,
        target_hash,
        stored_hash,
        status,
    })
}

fn optional_hash(
    hash: Option<Vec<u8>>,
    what: &str,
    key: &RegistryKey,
) -> Result<Option<ContentHash>> {
    match hash {
        Some(hash) => ContentHash::from_slice(&hash).map(Some).ok_or_else(|| {
            Error::Corrupt(format!("invalid {what} hash for {key}").into_boxed_str())
        }),
        None => Ok(None),
    }
}

pub(super) fn registry_states(conn: &Connection, object: &str) -> Result<Vec<RegistryState>> {
    let mut stmt = conn.prepare_cached(
        "SELECT object, id, source_hash, target_hash, status, singleton, stored_hash FROM registry_object WHERE object = ?1",
    )?;
    let rows = stmt.query_map([object], registry_row)?;
    let mut states = Vec::new();
    for row in rows {
        states.push(registry_state(row?)?);
    }
    Ok(states)
}

pub(super) fn registry_objects(conn: &Connection) -> Result<Vec<Box<str>>> {
    conn.prepare_cached("SELECT DISTINCT object FROM registry_object ORDER BY object")?
        .query_map([], |row| {
            row.get::<_, String>(0).map(String::into_boxed_str)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::from)
}

pub(super) fn registry_sample(conn: &Connection, limit: u32) -> Result<Vec<RegistryState>> {
    let mut stmt = conn.prepare_cached(
        "SELECT object, id, source_hash, target_hash, status, singleton, stored_hash FROM registry_object
         WHERE status = ?1 AND stored_hash IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM registry_pending
           WHERE registry_pending.object = registry_object.object
             AND registry_pending.id = registry_object.id
             AND registry_pending.singleton = registry_object.singleton)
         ORDER BY random() LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![RegistryStatus::Ok, limit], registry_row)?;
    let mut states = Vec::new();
    for row in rows {
        states.push(registry_state(row?)?);
    }
    Ok(states)
}

pub(super) fn put_registry(
    conn: &Connection,
    run_id: RunId,
    updates: &[RegistryUpdate],
) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO registry_object (object, id, source_hash, target_hash, run_id, source_json, status, singleton, stored_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT (object, id) DO UPDATE SET source_hash = excluded.source_hash,
         target_hash = excluded.target_hash,
         stored_hash = CASE WHEN excluded.status = 'error' AND excluded.stored_hash IS NULL
             THEN registry_object.stored_hash ELSE excluded.stored_hash END,
         run_id = excluded.run_id,
         source_json = excluded.source_json, status = excluded.status",
    )?;
    for update in updates {
        let compressed = zstd::bulk::compress(&update.source_json, SOURCE_JSON_LEVEL)?;
        let (id, singleton) = encode_registry_id(update.key.id);
        stmt.execute(params![
            &*update.key.object,
            id,
            &update.source_hash.as_bytes()[..],
            update.target_hash.as_ref().map(|hash| &hash.as_bytes()[..]),
            run_id,
            compressed,
            update.status,
            singleton,
            update.stored_hash.as_ref().map(|hash| &hash.as_bytes()[..]),
        ])?;
    }
    Ok(())
}

pub(super) fn remove_registry(conn: &Connection, keys: &[RegistryKey]) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "DELETE FROM registry_object WHERE object = ?1 AND id = ?2 AND singleton = ?3",
    )?;
    for key in keys {
        let (id, singleton) = encode_registry_id(key.id);
        stmt.execute(params![&*key.object, id, singleton])?;
    }
    set_registry_fallbacks(conn, &[], keys)
}

pub(super) fn set_registry_fallbacks(
    conn: &Connection,
    fell_back: &[RegistryKey],
    cleared: &[RegistryKey],
) -> Result<()> {
    let mut insert = conn.prepare_cached(
        "INSERT OR IGNORE INTO registry_fallback (object, id, singleton) VALUES (?1, ?2, ?3)",
    )?;
    for key in fell_back {
        let (id, singleton) = encode_registry_id(key.id);
        insert.execute(params![&*key.object, id, singleton])?;
    }
    let mut delete = conn.prepare_cached(
        "DELETE FROM registry_fallback WHERE object = ?1 AND id = ?2 AND singleton = ?3",
    )?;
    for key in cleared {
        let (id, singleton) = encode_registry_id(key.id);
        delete.execute(params![&*key.object, id, singleton])?;
    }
    Ok(())
}

pub(super) fn set_registry_pending(
    conn: &Connection,
    added: &[RegistryKey],
    cleared: &[RegistryKey],
) -> Result<()> {
    let mut insert = conn.prepare_cached(
        "INSERT OR IGNORE INTO registry_pending (object, id, singleton) VALUES (?1, ?2, ?3)",
    )?;
    for key in added {
        let (id, singleton) = encode_registry_id(key.id);
        insert.execute(params![&*key.object, id, singleton])?;
    }
    let mut delete = conn.prepare_cached(
        "DELETE FROM registry_pending WHERE object = ?1 AND id = ?2 AND singleton = ?3",
    )?;
    for key in cleared {
        let (id, singleton) = encode_registry_id(key.id);
        delete.execute(params![&*key.object, id, singleton])?;
    }
    Ok(())
}

pub(super) fn registry_fallbacks(conn: &Connection) -> Result<Vec<RegistryKey>> {
    conn.prepare_cached("SELECT object, id, singleton FROM registry_fallback")?
        .query_map([], |row| {
            Ok(RegistryKey {
                object: row.get::<_, String>(0)?.into_boxed_str(),
                id: decode_registry_id(row.get(1)?, row.get(2)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::from)
}

pub(super) fn registry_pending(conn: &Connection) -> Result<Vec<RegistryKey>> {
    conn.prepare_cached("SELECT object, id, singleton FROM registry_pending")?
        .query_map([], |row| {
            Ok(RegistryKey {
                object: row.get::<_, String>(0)?.into_boxed_str(),
                id: decode_registry_id(row.get(1)?, row.get(2)?),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::from)
}

pub(super) fn registry_source_json(
    conn: &Connection,
    key: &RegistryKey,
) -> Result<Option<Vec<u8>>> {
    let (id, singleton) = encode_registry_id(key.id);
    let compressed: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT source_json FROM registry_object WHERE object = ?1 AND id = ?2 AND singleton = ?3",
        )?
        .query_row(params![&*key.object, id, singleton], |row| row.get(0))
        .optional()?
        .flatten();
    match compressed {
        Some(compressed) => zstd::stream::decode_all(compressed.as_slice())
            .map(Some)
            .map_err(|err| Error::Corrupt(format!("source JSON of {key}: {err}").into_boxed_str())),
        None => Ok(None),
    }
}

pub(super) fn blobs_known(conn: &Connection, hashes: &[BlobHash]) -> Result<Vec<bool>> {
    let mut stmt = conn.prepare_cached("SELECT 1 FROM blob WHERE hash = ?1")?;
    let mut known = Vec::with_capacity(hashes.len());
    for hash in hashes {
        known.push(stmt.exists([&hash.as_bytes()[..]])?);
    }
    Ok(known)
}

pub(super) fn add_blobs(conn: &Connection, run_id: RunId, blobs: &[(BlobHash, u64)]) -> Result<()> {
    let mut stmt =
        conn.prepare_cached("INSERT OR IGNORE INTO blob (hash, size, run_id) VALUES (?1, ?2, ?3)")?;
    for (hash, size) in blobs {
        stmt.execute(params![&hash.as_bytes()[..], encode_u64(*size), run_id])?;
    }
    Ok(())
}

pub(super) fn global_cursor(conn: &Connection, name: &str) -> Result<Option<Vec<u8>>> {
    conn.prepare_cached("SELECT value FROM global_cursor WHERE name = ?1")?
        .query_row([name], |row| row.get(0))
        .optional()
        .map_err(Error::from)
}

pub(super) fn set_global_cursor(conn: &Connection, name: &str, value: &[u8]) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO global_cursor (name, value) VALUES (?1, ?2)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value",
    )?
    .execute(params![name, value])?;
    Ok(())
}

pub(super) fn track_globals(
    conn: &Connection,
    generation: RunId,
    keys: &[GlobalKey],
) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO global_record (kind, id, generation) VALUES (?1, ?2, ?3)
         ON CONFLICT (kind, id) DO UPDATE SET generation = excluded.generation",
    )?;
    for key in keys {
        let GlobalKeyColumns { kind, id } = GlobalKeyColumns::encode(*key);
        stmt.execute(params![kind, id, generation])?;
    }
    Ok(())
}

pub(super) fn stale_globals(
    conn: &Connection,
    category: GlobalCategory,
    generation: RunId,
    after: Option<GlobalKey>,
    limit: u32,
) -> Result<Vec<GlobalKey>> {
    let Some((first, last)) = GlobalKeyColumns::kinds(category) else {
        return Ok(Vec::new());
    };
    let keys = match after.map(GlobalKeyColumns::encode) {
        None => conn
            .prepare_cached(
                "SELECT kind, id FROM global_record
                 WHERE kind BETWEEN ?1 AND ?2 AND generation < ?3
                 ORDER BY kind, id LIMIT ?4",
            )?
            .query_map(
                params![first, last, generation, limit],
                GlobalKeyColumns::read,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        Some(GlobalKeyColumns { kind, id }) => conn
            .prepare_cached(
                "SELECT kind, id FROM global_record
                 WHERE kind BETWEEN ?1 AND ?2 AND generation < ?3 AND (kind, id) > (?4, ?5)
                 ORDER BY kind, id LIMIT ?6",
            )?
            .query_map(
                params![first, last, generation, kind, id, limit],
                GlobalKeyColumns::read,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok(keys)
}

pub(super) fn forget_globals(conn: &Connection, keys: &[GlobalKey]) -> Result<()> {
    let mut stmt = conn.prepare_cached("DELETE FROM global_record WHERE kind = ?1 AND id = ?2")?;
    for key in keys {
        let GlobalKeyColumns { kind, id } = GlobalKeyColumns::encode(*key);
        stmt.execute(params![kind, id])?;
    }
    Ok(())
}

const fn telemetry_code(kind: TelemetryKind) -> i64 {
    match kind {
        TelemetryKind::Span => 0,
        TelemetryKind::Metric => 1,
    }
}

pub(super) fn telemetry_seen(
    conn: &Connection,
    keys: &[(TelemetryKind, u64)],
) -> Result<Vec<bool>> {
    let mut stmt =
        conn.prepare_cached("SELECT 1 FROM telemetry_seen WHERE kind = ?1 AND id = ?2")?;
    let mut seen = Vec::with_capacity(keys.len());
    for (kind, id) in keys {
        seen.push(stmt.exists(params![telemetry_code(*kind), encode_u64(*id)])?);
    }
    Ok(seen)
}

pub(super) fn see_telemetry(conn: &Connection, keys: &[(TelemetryKind, u64)]) -> Result<()> {
    let mut stmt =
        conn.prepare_cached("INSERT OR IGNORE INTO telemetry_seen (kind, id) VALUES (?1, ?2)")?;
    for (kind, id) in keys {
        stmt.execute(params![telemetry_code(*kind), encode_u64(*id)])?;
    }
    Ok(())
}

pub(super) fn prune_telemetry(conn: &Connection, kind: TelemetryKind, window: u64) -> Result<()> {
    let code = telemetry_code(kind);
    let newest: Option<i64> = conn
        .prepare_cached("SELECT MAX(id) FROM telemetry_seen WHERE kind = ?1")?
        .query_row(params![code], |row| row.get(0))?;
    let Some(below) = newest.and_then(|newest| decode_u64(newest).checked_sub(window)) else {
        return Ok(());
    };
    conn.prepare_cached("DELETE FROM telemetry_seen WHERE kind = ?1 AND id < ?2")?
        .execute(params![code, encode_u64(below)])?;
    Ok(())
}

pub(super) const ADD_REPORT: &str = "INSERT INTO report (run_id, severity, category, account_id, object, object_id, message, explains)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
     WHERE ?5 IS NULL OR NOT EXISTS (
       SELECT 1 FROM report WHERE run_id = ?1 AND object = ?5 AND object_id IS ?6
         AND account_id IS ?4 AND severity = ?2 AND category = ?3 AND message = ?7
         AND explains IS ?8)";

pub(super) fn add_reports(conn: &Connection, rows: &[ReportRow]) -> Result<ReportsAdded> {
    let mut stmt = conn.prepare_cached(ADD_REPORT)?;
    let mut added = ReportsAdded::default();
    for row in rows {
        let inserted = stmt.execute(params![
            row.run_id,
            row.severity.as_str(),
            &*row.category,
            row.account_id,
            row.object.as_deref(),
            row.object_id.map(encode_u64),
            &*row.message,
            row.explains.as_ref().map(Explanation::encode),
        ])? as u64;
        added.rows += inserted;
        if row.severity == Severity::Error {
            added.errors += inserted;
        }
    }
    Ok(added)
}

pub(super) fn reports(conn: &Connection, filter: &ReportFilter) -> Result<Vec<ReportRow>> {
    let limit = filter
        .limit
        .and_then(|limit| i64::try_from(limit).ok())
        .unwrap_or(-1);
    conn.prepare_cached(
        "SELECT id, run_id, severity, category, account_id, object, object_id, message, explains FROM report
         WHERE (?1 IS NULL OR run_id = ?1) AND (?2 IS NULL OR severity = ?2)
         AND (?3 IS NULL OR category = ?3) AND (?4 IS NULL OR account_id = ?4)
         AND (?6 = 0 OR account_id IS NULL)
         ORDER BY id LIMIT ?5",
    )?
    .query_map(
        params![
            filter.run_id,
            filter.severity.map(|severity| severity.as_str()),
            filter.category.as_deref(),
            filter.account_id,
            limit,
            filter.scope == ReportScope::Global
        ],
        |row| {
            Ok(ReportRow {
                id: row.get(0)?,
                run_id: row.get(1)?,
                severity: get_severity(row, 2)?,
                category: row.get::<_, String>(3)?.into_boxed_str(),
                account_id: row.get(4)?,
                object: row.get::<_, Option<String>>(5)?.map(String::into_boxed_str),
                object_id: row.get::<_, Option<i64>>(6)?.map(decode_u64),
                message: row.get::<_, String>(7)?.into_boxed_str(),
                explains: row
                    .get::<_, Option<String>>(8)?
                    .and_then(|value| Explanation::parse(&value)),
            })
        },
    )?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Error::from)
}

pub(super) fn report_counts(conn: &Connection, run_id: Option<RunId>) -> Result<Vec<ReportCount>> {
    conn.prepare_cached(
        "SELECT severity, category, COUNT(*) FROM report WHERE (?1 IS NULL OR run_id = ?1)
         GROUP BY severity, category ORDER BY severity, category",
    )?
    .query_map([run_id], |row| {
        Ok(ReportCount {
            severity: get_severity(row, 0)?,
            category: row.get::<_, String>(1)?.into_boxed_str(),
            count: get_u64(row, 2)?,
        })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Error::from)
}

pub(super) fn failed_documents(
    conn: &Connection,
    after_run: RunId,
    from: Option<FailedDocument>,
    limit: u32,
) -> Result<Vec<FailedDocument>> {
    let (account_id, object, document_id) = from.map_or((-1, "", -1), |from| {
        (
            i64::from(from.account_id),
            from.collection.as_str(),
            i64::from(from.document_id),
        )
    });
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT r.account_id, r.object, r.object_id FROM report r
         JOIN account a ON a.account_id = r.account_id
         WHERE r.severity = 'error' AND r.object IS NOT NULL AND r.object_id IS NOT NULL
         AND r.run_id > ?1 AND (a.full_run IS NULL OR r.run_id >= a.full_run)
         AND (r.account_id, r.object, r.object_id) > (?2, ?3, ?4)
         ORDER BY r.account_id, r.object, r.object_id LIMIT ?5",
    )?;
    let mut rows = stmt.query(params![after_run, account_id, object, document_id, limit])?;
    let mut documents = Vec::new();
    while let Some(row) = rows.next()? {
        let object = row.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
        let (Some(collection), Ok(document_id)) = (
            Collection::parse(object),
            u32::try_from(row.get::<_, i64>(2)?),
        ) else {
            return Err(Error::Corrupt(
                format!("report row for object {object} has no valid document id").into_boxed_str(),
            ));
        };
        documents.push(FailedDocument {
            account_id: get_u32(row, 0)?,
            collection,
            document_id,
        });
    }
    Ok(documents)
}

pub(super) fn global_errors(conn: &Connection, runs: Range<RunId>, object: &str) -> Result<u64> {
    conn.prepare_cached(
        "SELECT COUNT(*) FROM report
         WHERE severity = 'error' AND account_id IS NULL AND object = ?3
         AND run_id >= ?1 AND run_id < ?2",
    )?
    .query_row(params![runs.start, runs.end, object], |row| get_u64(row, 0))
    .map_err(Error::from)
}

pub(super) fn account_errors(conn: &Connection, after_run: RunId, kind: IssueKind) -> Result<u64> {
    conn.prepare_cached(
        "SELECT COUNT(*) FROM report r JOIN account a ON a.account_id = r.account_id
         WHERE r.severity = 'error' AND r.object IS NULL AND r.category = ?2
         AND r.run_id > ?1 AND (a.full_run IS NULL OR r.run_id >= a.full_run)",
    )?
    .query_row(params![after_run, kind.as_str()], |row| get_u64(row, 0))
    .map_err(Error::from)
}
