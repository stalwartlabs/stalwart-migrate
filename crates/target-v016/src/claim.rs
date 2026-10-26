/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{ClaimId, TargetClaim, TargetProbe};
use store::{
    Deserialize, SUBSPACE_PROPERTY,
    write::assert::AssertValue,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
    xxhash_rust::xxh3::xxh3_64,
};

use crate::{
    error::{fatal, trc_error},
    store_stage::SCHEMA_KEY,
    target::V016Target,
};

const CLAIM_SUFFIX: u8 = u8::MAX - 1;
const GENERATION_SUFFIX: u8 = u8::MAX - 2;
const OTHER_STATE: &str = "the rollback target was created by another state directory; use the --state that created it, or a new empty target";
const UNKNOWN_SWAP: &str = "the claim generation swap of the rollback target failed although the stored generation still matches; the outcome is unknown, retry with the same generation";
const UNCLAIMED: &str = "the rollback target holds data but was not created by this state directory (no claim is stored); use the --state that created it, or a new empty target";

struct StoredClaim(Option<ClaimId>);

impl Deserialize for StoredClaim {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(StoredClaim(ClaimId::from_slice(bytes)))
    }
}

fn claim_key() -> Vec<u8> {
    vec![SCHEMA_KEY, CLAIM_SUFFIX]
}

fn generation_key() -> Vec<u8> {
    vec![SCHEMA_KEY, GENERATION_SUFFIX]
}

fn property_class(key: Vec<u8>) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_PROPERTY,
        key,
    })
}

impl V016Target {
    async fn stored_id(&self, key: Vec<u8>) -> model::Result<Option<StoredClaim>> {
        self.store
            .get_value::<StoredClaim>(AnyKey {
                subspace: SUBSPACE_PROPERTY,
                key,
            })
            .await
            .map_err(trc_error)
    }

    async fn stored_claim(&self) -> model::Result<Option<StoredClaim>> {
        self.stored_id(claim_key()).await
    }

    pub(crate) fn add_claim(&self, batch: &mut BatchBuilder) {
        if let Some(claim) = self.claim {
            batch.set(property_class(claim_key()), claim.id().as_bytes().to_vec());
        }
    }

    pub(crate) async fn holds_own_claim(&self) -> model::Result<bool> {
        let Some(claim) = self.claim else {
            return Ok(false);
        };
        Ok(matches!(
            self.stored_claim().await?,
            Some(StoredClaim(Some(stored))) if stored == claim.id()
        ))
    }

    pub(crate) async fn stored_generation(&self) -> model::Result<Option<ClaimId>> {
        self.store.invalidate_read_snapshot();
        match self.stored_id(generation_key()).await? {
            None => Ok(None),
            Some(StoredClaim(Some(generation))) => Ok(Some(generation)),
            Some(StoredClaim(None)) => Err(fatal(
                "the rollback target holds a malformed claim generation",
            )),
        }
    }

    pub async fn swap_claim_generation(
        &self,
        expected: Option<ClaimId>,
        next: ClaimId,
    ) -> model::Result<bool> {
        let assertion = match expected {
            Some(expected) => AssertValue::Hash(xxh3_64(expected.as_bytes())),
            None => AssertValue::None,
        };
        let mut batch = BatchBuilder::new();
        batch
            .assert_value(property_class(generation_key()), assertion)
            .set(property_class(generation_key()), next.as_bytes().to_vec());
        match self.store.write(batch.build_all()).await {
            Ok(_) => Ok(true),
            Err(err) if err.is_assertion_failure() => {
                settle_failed_swap(self.stored_generation().await?, expected, next)
            }
            Err(err) => Err(trc_error(err)),
        }
    }

    pub(crate) async fn check_claim(&self, claim: TargetClaim) -> model::Result<()> {
        match (claim, self.stored_claim().await?) {
            (_, Some(StoredClaim(Some(stored)))) if stored == claim.id() => Ok(()),
            (_, Some(_)) => Err(fatal(OTHER_STATE)),
            (TargetClaim::New(_), None) => Ok(()),
            (TargetClaim::Claimed(_), None) => match self.probe_store().await? {
                TargetProbe::Empty => Ok(()),
                TargetProbe::Initialized { .. } | TargetProbe::Foreign => Err(fatal(UNCLAIMED)),
            },
        }
    }

    pub(crate) async fn write_claim(&self) -> model::Result<()> {
        let Some(claim) = self.claim else {
            return Ok(());
        };
        if self.stored_claim().await?.is_some() {
            return self.check_claim(claim).await;
        }
        let mut batch = BatchBuilder::new();
        batch.set(property_class(claim_key()), claim.id().as_bytes().to_vec());
        self.store
            .write(batch.build_all())
            .await
            .map(|_| ())
            .map_err(trc_error)
    }
}

fn settle_failed_swap(
    stored: Option<ClaimId>,
    expected: Option<ClaimId>,
    next: ClaimId,
) -> model::Result<bool> {
    if stored == Some(next) {
        Ok(true)
    } else if stored == expected {
        Err(model::Error::transient(UNKNOWN_SWAP))
    } else {
        Ok(false)
    }
}

#[cfg(feature = "sqlite")]
fn sqlite_sibling(path: &std::path::Path, suffix: &str) -> bool {
    let mut sibling = path.as_os_str().to_owned();
    sibling.push(suffix);
    std::path::Path::new(&sibling).exists()
}

#[cfg(feature = "sqlite")]
fn sqlite_claim_error(path: &str, err: rusqlite::Error) -> model::Error {
    use rusqlite::ErrorCode;

    let reason = match err.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
            "it is in use by another process; stop it before resuming the rollback"
        }
        Some(ErrorCode::ReadOnly) => {
            "it holds an interrupted transaction or a WAL that was not checkpointed, which only a read-write open can recover"
        }
        Some(ErrorCode::NotADatabase) => "it is not a SQLite database",
        _ => "it cannot be read",
    };
    fatal(format!(
        "cannot read the claim of the SQLite rollback target {path}: {reason} ({err})"
    ))
}

#[cfg(feature = "sqlite")]
fn holds_only_empty_store_tables(reader: &rusqlite::Connection, path: &str) -> model::Result<bool> {
    let unreadable = |err: rusqlite::Error| sqlite_claim_error(path, err);
    let mut objects = reader
        .prepare(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        )
        .map_err(unreadable)?;
    let objects = objects
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(unreadable)?;
    for object in objects {
        let (kind, name) = object.map_err(unreadable)?;
        if kind != "table" || !crate::store_stage::is_store_table(&name) {
            return Ok(false);
        }
        let has_rows = reader
            .query_row(
                &format!("SELECT EXISTS (SELECT 1 FROM \"{name}\")"),
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(unreadable)?;
        if has_rows {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(feature = "sqlite")]
pub(crate) fn recover_sqlite(path: &str, claim: ClaimId) -> model::Result<()> {
    use std::time::Duration;

    use rusqlite::{Connection, OpenFlags, OptionalExtension};

    let Ok(canonical) = std::fs::canonicalize(path) else {
        return Ok(());
    };
    let has_wal = sqlite_sibling(&canonical, "-wal");
    if !has_wal && !sqlite_sibling(&canonical, "-journal") {
        return Ok(());
    }
    let without_shm = has_wal && !sqlite_sibling(&canonical, "-shm");
    let unreadable = |err: rusqlite::Error| sqlite_claim_error(path, err);
    let reader = if without_shm {
        let Some(utf8) = canonical.to_str() else {
            return Err(fatal(format!(
                "the SQLite rollback target {path} resolves to a non UTF-8 path"
            )));
        };
        let mut uri = String::with_capacity(utf8.len() + 24);
        uri.push_str("file:");
        for ch in utf8.chars() {
            match ch {
                '%' => uri.push_str("%25"),
                '?' => uri.push_str("%3f"),
                '#' => uri.push_str("%23"),
                ch => uri.push(ch),
            }
        }
        uri.push_str("?immutable=1");
        Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    } else {
        Connection::open_with_flags(
            &canonical,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    }
    .map_err(unreadable)?;
    reader.busy_timeout(Duration::ZERO).map_err(unreadable)?;
    let table = char::from(SUBSPACE_PROPERTY);
    let has_table = reader
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(unreadable)?
        > 0;
    let stored = if has_table {
        reader
            .query_row(
                &format!("SELECT v FROM {table} WHERE k = ?1"),
                [claim_key()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(unreadable)?
    } else {
        None
    };
    let resumable = stored.as_deref() == Some(claim.as_bytes().as_slice())
        || (stored.is_none() && !without_shm && holds_only_empty_store_tables(&reader, path)?);
    drop(reader);
    if !resumable {
        return if without_shm {
            Err(fatal(format!(
                "the SQLite rollback target {path} has a -wal but no -shm file, so its claim cannot be read without changing it; if this state directory created it, open it once with the sqlite3 shell to recover the WAL, then resume"
            )))
        } else {
            Ok(())
        };
    }
    let busy = |err: rusqlite::Error| {
        fatal(format!(
            "the SQLite rollback target {path} is in use by another process ({err}); stop it before resuming the rollback"
        ))
    };
    let connection = Connection::open_with_flags(
        &canonical,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(busy)?;
    connection.busy_timeout(Duration::ZERO).map_err(busy)?;
    connection
        .execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;")
        .map_err(busy)?;
    connection.close().map_err(|(_, err)| busy(err))
}

#[cfg(not(feature = "sqlite"))]
pub(crate) fn recover_sqlite(_: &str, _: ClaimId) -> model::Result<()> {
    Ok(())
}

#[cfg(all(test, feature = "rocks"))]
mod tests {
    use model::{ClaimId, Edition, TargetClaim};

    use crate::{SharedDeletes, TargetConfig, V016Target};

    fn open_config(dir: &std::path::Path) -> TargetConfig {
        let config = dir.join("target.json");
        std::fs::write(
            &config,
            serde_json::json!({"@type": "RocksDb", "path": dir.join("data").to_string_lossy()})
                .to_string(),
        )
        .expect("write config");
        TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        }
    }

    async fn open(dir: &std::path::Path, claim: TargetClaim) -> model::Result<V016Target> {
        V016Target::open_claimed(open_config(dir), claim).await
    }

    #[cfg(feature = "enterprise")]
    const EDITION: Edition = Edition::Enterprise;
    #[cfg(not(feature = "enterprise"))]
    const EDITION: Edition = Edition::Community;
    const OURS: ClaimId = ClaimId::from_bytes([0x11; ClaimId::LEN]);

    // A failed swap counts as won when the store holds the new generation (retried FoundationDB 1021 commit), as unknown when it still holds the expected one (transient read error during the assertion), otherwise as lost.
    #[test]
    fn failed_swap_is_settled_by_the_stored_generation() {
        use super::settle_failed_swap;
        const NEXT: ClaimId = ClaimId::from_bytes([0x22; ClaimId::LEN]);
        const OTHER: ClaimId = ClaimId::from_bytes([0x33; ClaimId::LEN]);
        assert!(settle_failed_swap(Some(NEXT), Some(OURS), NEXT).expect("won"));
        assert!(settle_failed_swap(Some(NEXT), None, NEXT).expect("won"));
        assert!(!settle_failed_swap(Some(OTHER), Some(OURS), NEXT).expect("lost"));
        assert!(!settle_failed_swap(Some(OTHER), None, NEXT).expect("lost"));
        assert!(!settle_failed_swap(None, Some(OURS), NEXT).expect("lost"));
        assert!(matches!(
            settle_failed_swap(Some(OURS), Some(OURS), NEXT),
            Err(model::Error::Transient(_))
        ));
        assert!(matches!(
            settle_failed_swap(None, None, NEXT),
            Err(model::Error::Transient(_))
        ));
    }

    // The schema marker and the claim land in one batch, so a crash right after it leaves a store that resumes under its claim.
    #[tokio::test(flavor = "multi_thread")]
    async fn schema_marker_and_claim_are_one_batch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = open(dir.path(), TargetClaim::New(OURS)).await.expect("new");
        target.prepare(EDITION).await.expect("schema marker");
        assert!(target.holds_own_claim().await.expect("claim"));
        drop(target);
        let resumed = open(dir.path(), TargetClaim::Claimed(OURS))
            .await
            .expect("resume after the first batch");
        assert!(resumed.holds_own_claim().await.expect("claim"));
    }
}
