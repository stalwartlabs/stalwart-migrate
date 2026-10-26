/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(any(feature = "rocks", feature = "sqlite"))]

use std::path::Path;
#[cfg(feature = "sqlite")]
use std::path::PathBuf;

use model::{ClaimId, Edition, Target, TargetClaim};
#[cfg(feature = "sqlite")]
use model::{RegistryKey, RegistryRecord};
use serde_json::{Value, json};
use target_v1::{TargetConfig, V1Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const OURS: ClaimId = ClaimId::from_bytes([0x11; ClaimId::LEN]);
const THEIRS: ClaimId = ClaimId::from_bytes([0x22; ClaimId::LEN]);

fn config(dir: &Path, definition: &Value) -> TargetConfig {
    let config = dir.join("target.json");
    std::fs::write(&config, definition.to_string()).expect("write config");
    TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    }
}

async fn open(dir: &Path, definition: &Value, claim: TargetClaim) -> model::Result<V1Target> {
    V1Target::open_claimed(config(dir, definition), None, claim).await
}

#[cfg(feature = "sqlite")]
fn domain() -> RegistryRecord {
    RegistryRecord {
        key: RegistryKey::new("Domain", 3),
        json: json!({"name": "example.org"}),
    }
}

#[cfg(feature = "sqlite")]
async fn has_domain(target: &V1Target) -> bool {
    target
        .read_registry(&[RegistryKey::new("Domain", 3)])
        .await
        .expect("read")
        .pop()
        .flatten()
        .is_some()
}

// A store claimed by one state directory opens only for that claim; an initialized store without a claim is refused, an empty one is claimed on prepare.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn claim_id_selects_the_state_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let definition = json!({"@type": "RocksDb", "path": dir.path().join("data").to_string_lossy()});
    let target = open(dir.path(), &definition, TargetClaim::New(OURS))
        .await
        .expect("new");
    target.prepare_store(EDITION).await.expect("prepare");
    drop(target);
    for refused in [TargetClaim::Claimed(THEIRS), TargetClaim::New(THEIRS)] {
        assert!(
            open(dir.path(), &definition, refused).await.is_err(),
            "{refused:?} opened a store claimed by another state"
        );
    }
    let target = open(dir.path(), &definition, TargetClaim::Claimed(OURS))
        .await
        .expect("claimed");
    target.prepare_store(EDITION).await.expect("prepare again");
    drop(target);

    let unclaimed = tempfile::tempdir().expect("tempdir");
    let definition =
        json!({"@type": "RocksDb", "path": unclaimed.path().join("data").to_string_lossy()});
    let target = open(unclaimed.path(), &definition, TargetClaim::Claimed(OURS))
        .await
        .expect("empty store with a claim");
    drop(target);
    let target = V1Target::open(config(unclaimed.path(), &definition))
        .await
        .expect("open without claim");
    target.prepare_store(EDITION).await.expect("prepare");
    drop(target);
    assert!(
        open(unclaimed.path(), &definition, TargetClaim::Claimed(OURS))
            .await
            .is_err(),
        "an initialized store without a claim was opened"
    );
}

#[cfg(feature = "sqlite")]
fn crash_image(dir: &Path, data: &Path, name: &str) -> PathBuf {
    let image = dir.join(name);
    std::fs::create_dir(&image).expect("image dir");
    for suffix in ["", "-wal", "-shm"] {
        let name = format!("store.sqlite{suffix}");
        std::fs::copy(data.join(&name), image.join(&name)).expect("copy");
    }
    image.join("store.sqlite")
}

#[cfg(feature = "sqlite")]
fn sqlite(path: &Path) -> Value {
    json!({"@type": "Sqlite", "path": path.to_string_lossy()})
}

// A crash image of our own SQLite target (with its -wal) resumes under its claim, and is refused without it or while another connection holds it.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn claimed_sqlite_crash_image_resumes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let live = open(
        dir.path(),
        &sqlite(&data.join("store.sqlite")),
        TargetClaim::New(OURS),
    )
    .await
    .expect("new");
    live.prepare_store(EDITION).await.expect("prepare");
    let outcome = live.write_registry(&[domain()]).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let image = crash_image(dir.path(), &data, "image");
    let held = crash_image(dir.path(), &data, "held");
    drop(live);
    let definition = sqlite(&image);

    assert!(
        V1Target::open(config(dir.path(), &definition))
            .await
            .is_err(),
        "a crash image was opened without a claim"
    );
    assert!(
        open(dir.path(), &definition, TargetClaim::New(OURS))
            .await
            .is_err(),
        "a crash image was opened as a new claim"
    );
    let holder = rusqlite::Connection::open(&held).expect("holder");
    holder
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("holder read");
    let started = std::time::Instant::now();
    assert!(
        open(dir.path(), &sqlite(&held), TargetClaim::Claimed(OURS))
            .await
            .is_err(),
        "a store held by another connection was opened"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a held store took {:?} to refuse, the lock must not wait",
        started.elapsed()
    );
    drop(holder);
    assert!(image.with_extension("sqlite-wal").exists());
    assert!(
        open(dir.path(), &definition, TargetClaim::Claimed(THEIRS))
            .await
            .is_err(),
        "a crash image was opened under another claim"
    );
    let resumed = open(dir.path(), &definition, TargetClaim::Claimed(OURS))
        .await
        .expect("resume");
    resumed.prepare_store(EDITION).await.expect("prepare");
    assert!(has_domain(&resumed).await);
}

// A foreign SQLite database with a -wal is refused and left untouched, with or without a claim.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn foreign_sqlite_with_wal_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let writer = rusqlite::Connection::open(data.join("store.sqlite")).expect("writer");
    writer
        .execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE unrelated (id INTEGER); INSERT INTO unrelated VALUES (1);")
        .expect("foreign write");
    let image = crash_image(dir.path(), &data, "image");
    drop(writer);
    let definition = sqlite(&image);
    let snapshot = || {
        let mut names = std::fs::read_dir(image.parent().expect("image dir"))
            .expect("list")
            .flatten()
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        names.sort_unstable();
        let bytes = ["sqlite", "sqlite-wal"]
            .map(|extension| std::fs::read(image.with_extension(extension)).expect("read"));
        (names, bytes)
    };
    let before = snapshot();
    for claim in [TargetClaim::New(OURS), TargetClaim::Claimed(OURS)] {
        assert!(
            open(dir.path(), &definition, claim).await.is_err(),
            "{claim:?} opened a foreign store"
        );
        assert_eq!(snapshot(), before, "{claim:?} changed a foreign store");
    }
}

// holds_claim is true only for the claim the target was opened with; the claim generation is stored next to it and replaced by each set.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn claim_generation_is_replaced_and_kept() {
    const FIRST: ClaimId = ClaimId::from_bytes([0x33; ClaimId::LEN]);
    const SECOND: ClaimId = ClaimId::from_bytes([0x44; ClaimId::LEN]);
    let dir = tempfile::tempdir().expect("tempdir");
    let definition = json!({"@type": "RocksDb", "path": dir.path().join("data").to_string_lossy()});
    let target = open(dir.path(), &definition, TargetClaim::New(OURS))
        .await
        .expect("new");
    assert!(!target.holds_claim().await.expect("holds"));
    target.prepare_store(EDITION).await.expect("prepare");
    assert!(target.holds_claim().await.expect("holds"));
    assert_eq!(target.claim_generation().await.expect("generation"), None);
    let mut previous = None;
    for generation in [FIRST, SECOND] {
        assert!(
            target
                .swap_claim_generation(previous, generation)
                .await
                .expect("swap generation")
        );
        previous = Some(generation);
        assert_eq!(
            target.claim_generation().await.expect("generation"),
            Some(generation)
        );
    }
    drop(target);
    let resumed = open(dir.path(), &definition, TargetClaim::Claimed(OURS))
        .await
        .expect("claimed");
    assert!(resumed.holds_claim().await.expect("holds"));
    assert_eq!(
        resumed.claim_generation().await.expect("generation"),
        Some(SECOND)
    );
    drop(resumed);
    let unclaimed = V1Target::open(config(dir.path(), &definition))
        .await
        .expect("open without claim");
    assert!(!unclaimed.holds_claim().await.expect("holds"));
}

// A foreign WAL database whose -shm is missing is refused without creating one, and the main file and -wal stay unchanged.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn foreign_sqlite_without_shm_is_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let writer = rusqlite::Connection::open(data.join("store.sqlite")).expect("writer");
    writer
        .execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0; CREATE TABLE unrelated (id INTEGER); INSERT INTO unrelated VALUES (1);")
        .expect("foreign write");
    let image = crash_image(dir.path(), &data, "image");
    drop(writer);
    std::fs::remove_file(image.with_extension("sqlite-shm")).expect("drop shm");
    let definition = sqlite(&image);
    let snapshot = || {
        let mut names = std::fs::read_dir(image.parent().expect("image dir"))
            .expect("list")
            .flatten()
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        names.sort_unstable();
        let bytes = ["sqlite", "sqlite-wal"]
            .map(|extension| std::fs::read(image.with_extension(extension)).expect("read"));
        (names, bytes)
    };
    let before = snapshot();
    assert_eq!(before.0.len(), 2, "{:?}", before.0);
    for claim in [TargetClaim::New(OURS), TargetClaim::Claimed(OURS)] {
        assert!(
            open(dir.path(), &definition, claim).await.is_err(),
            "{claim:?} opened a foreign store"
        );
        assert_eq!(snapshot(), before, "{claim:?} changed a foreign store");
    }
}

// A file that is not SQLite but has a -wal is refused under a claim as not a SQLite database; with a hot -journal the error names the interrupted transaction.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn non_sqlite_file_is_named_in_the_error() {
    for (suffix, reason) in [
        ("-wal", "it is not a SQLite database"),
        ("-journal", "it holds an interrupted transaction"),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.sqlite");
        std::fs::write(&path, vec![0x5A; 8192]).expect("not sqlite");
        std::fs::write(
            dir.path().join(format!("store.sqlite{suffix}")),
            vec![0x5A; 4096],
        )
        .expect("journal");
        let error = match open(dir.path(), &sqlite(&path), TargetClaim::Claimed(OURS)).await {
            Ok(_) => panic!("{suffix}: a non-SQLite file was opened"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(reason), "{suffix}: {error}");
    }
}

// A SQLite target that crashed after its tables were created but before prepare (a -wal, empty store tables, no claim) resumes under its claim; the same image with a row in a store table is refused.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_tables_without_claim_resume() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let live = open(
        dir.path(),
        &sqlite(&data.join("store.sqlite")),
        TargetClaim::New(OURS),
    )
    .await
    .expect("new");
    let image = crash_image(dir.path(), &data, "image");
    let foreign = crash_image(dir.path(), &data, "foreign");
    drop(live);
    let writer = rusqlite::Connection::open(&foreign).expect("writer");
    writer
        .execute_batch("INSERT INTO p (k, v) VALUES (x'01', x'02')")
        .expect("store row");
    let foreign_image = crash_image(dir.path(), foreign.parent().expect("dir"), "foreign-image");
    drop(writer);
    assert!(
        open(
            dir.path(),
            &sqlite(&foreign_image),
            TargetClaim::Claimed(OURS)
        )
        .await
        .is_err(),
        "a claimless store with rows was resumed"
    );
    assert!(image.with_extension("sqlite-wal").exists());
    let resumed = open(dir.path(), &sqlite(&image), TargetClaim::Claimed(OURS))
        .await
        .expect("resume a store left before prepare");
    resumed.prepare_store(EDITION).await.expect("prepare");
    assert!(resumed.holds_claim().await.expect("holds"));
}

// The claim generation bump is a compare-and-swap: a writer that expects a generation the store no longer holds loses and changes nothing.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn claim_generation_swap_refuses_the_loser() {
    const FIRST: ClaimId = ClaimId::from_bytes([0x55; ClaimId::LEN]);
    const SECOND: ClaimId = ClaimId::from_bytes([0x66; ClaimId::LEN]);
    const THIRD: ClaimId = ClaimId::from_bytes([0x77; ClaimId::LEN]);
    let dir = tempfile::tempdir().expect("tempdir");
    let definition = json!({"@type": "RocksDb", "path": dir.path().join("data").to_string_lossy()});
    let target = open(dir.path(), &definition, TargetClaim::New(OURS))
        .await
        .expect("new");
    target.prepare_store(EDITION).await.expect("prepare");
    for (expected, next, wins) in [
        (None, FIRST, true),
        (None, SECOND, false),
        (Some(SECOND), THIRD, false),
        (Some(FIRST), SECOND, true),
        (Some(FIRST), SECOND, true),
        (Some(FIRST), THIRD, false),
    ] {
        assert_eq!(
            target
                .swap_claim_generation(expected, next)
                .await
                .expect("swap"),
            wins,
            "{expected:?} -> {next:?}"
        );
    }
    assert_eq!(
        target.claim_generation().await.expect("generation"),
        Some(SECOND)
    );
}
