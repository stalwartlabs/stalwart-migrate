/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(any(feature = "rocks", feature = "sqlite"))]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use model::{Edition, Target, TargetProbe};
use registry::schema::structs::DataStore;
use serde_json::{Value, json};
use store::{
    Store, Subspace,
    write::{AnyKey, BatchBuilder, ValueClass, key::SystemKind},
};
use target_v1::{TargetConfig, V1Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.insert(path.clone(), std::fs::read(&path).expect("read file"));
            }
        }
    }
    files
}

fn names(files: &BTreeMap<PathBuf, Vec<u8>>) -> Vec<&PathBuf> {
    files.keys().collect()
}

fn assert_unchanged(before: &BTreeMap<PathBuf, Vec<u8>>, after: &BTreeMap<PathBuf, Vec<u8>>) {
    assert_eq!(names(before), names(after), "files were added or removed");
    for (path, bytes) in before {
        assert!(after.get(path) == Some(bytes), "{} changed", path.display());
    }
}

async fn open(dir: &Path, store: Value) -> model::Result<V1Target> {
    let config = dir.join("target.json");
    std::fs::write(&config, store.to_string()).expect("write config");
    V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
}

fn schema_key() -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: Subspace::System,
        key: vec![SystemKind::SchemaVersion as u8],
    }
}

async fn prepared_target(dir: &Path, definition: Value) {
    let target = open(dir, definition).await.expect("open");
    target.prepare_store(EDITION).await.expect("prepare");
}

async fn assert_read_only(definition: Value, data: &Path) {
    let before = snapshot(data);
    let store = Store::build_read_only(
        serde_json::from_value::<DataStore>(definition).expect("definition"),
    )
    .await
    .expect("read-only open");
    assert!(
        store
            .get_value::<u32>(schema_key())
            .await
            .expect("schema")
            .is_some()
    );
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(store::write::AnyClass {
            subspace: Subspace::System,
            key: vec![u8::MAX],
        }),
        vec![1],
    );
    assert!(store.write_batch(&mut batch).await.is_err());
    drop(store);
    assert_unchanged(&before, &snapshot(data));
}

// A RocksDB store without the v1 column families (a v0.16 store) is refused by open and left byte-identical.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn rocksdb_foreign_store_is_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let families = Subspace::ALL
            .iter()
            .map(|subspace| subspace.name())
            .filter(|name| !matches!(*name, "v" | "c"));
        let db = rocksdb::DB::open_cf(&opts, &data, families).expect("v0.16 store");
        let cf = db.cf_handle("p").expect("cf");
        db.put_cf(&cf, b"\x00", b"\x06\x00\x00\x00").expect("put");
    }
    let before = snapshot(&data);
    let definition = json!({"@type": "RocksDb", "path": data.to_string_lossy()});
    let result = open(dir.path(), definition).await;
    assert!(result.is_err(), "a v0.16 RocksDB store was opened");
    assert_unchanged(&before, &snapshot(&data));
}

// The read-only RocksDB open of a v1 store replays nothing to disk and rejects writes; open accepts the store afterwards.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn rocksdb_read_only_open_is_read_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let definition = json!({"@type": "RocksDb", "path": data.to_string_lossy()});
    prepared_target(dir.path(), definition.clone()).await;
    assert_read_only(definition.clone(), &data).await;
    let target = open(dir.path(), definition).await.expect("reopen");
    assert!(matches!(
        target.probe().await.expect("probe"),
        TargetProbe::Initialized { .. }
    ));
}

// An SQLite file holding an unrelated table is refused by open and left byte-identical, with no journal files.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_foreign_store_is_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let file = data.join("store.sqlite");
    {
        let conn = rusqlite::Connection::open(&file).expect("sqlite");
        conn.execute_batch(
            "CREATE TABLE accounts (name TEXT); INSERT INTO accounts VALUES ('bob');",
        )
        .expect("foreign table");
    }
    let before = snapshot(&data);
    let definition = json!({"@type": "Sqlite", "path": file.to_string_lossy()});
    let result = open(dir.path(), definition).await;
    assert!(result.is_err(), "a foreign SQLite store was opened");
    assert_unchanged(&before, &snapshot(&data));
}

// The read-only SQLite open of a v1 store writes nothing and rejects writes; open accepts the store afterwards.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_read_only_open_is_read_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let file = data.join("store.sqlite");
    let definition = json!({"@type": "Sqlite", "path": file.to_string_lossy()});
    prepared_target(dir.path(), definition.clone()).await;
    assert_read_only(definition.clone(), &data).await;
    let target = open(dir.path(), definition).await.expect("reopen");
    assert!(matches!(
        target.probe().await.expect("probe"),
        TargetProbe::Initialized { .. }
    ));
}

// A target directory holding only lost+found (a volume root) is a new empty store.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn volume_root_with_lost_found_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir_all(data.join("lost+found")).expect("lost+found");
    let target = open(
        dir.path(),
        json!({"@type": "RocksDb", "path": data.to_string_lossy()}),
    )
    .await
    .expect("open");
    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
}

#[cfg(feature = "sqlite")]
fn foreign_sqlite(sql: &str) -> (tempfile::TempDir, PathBuf, Value) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");
    let file = data.join("store.sqlite");
    rusqlite::Connection::open(&file)
        .expect("sqlite")
        .execute_batch(sql)
        .expect("foreign objects");
    let definition = json!({"@type": "Sqlite", "path": file.to_string_lossy()});
    (dir, data, definition)
}

// Tables whose names only look like SQLite internals, and views, make an SQLite file foreign; it is left byte-identical.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_lookalike_table_and_view_are_foreign() {
    for sql in [
        "CREATE TABLE SQLiteStudioData (id INTEGER);",
        "CREATE TABLE sqliteXdata (id INTEGER);",
        "CREATE VIEW recent AS SELECT 1 AS one;",
    ] {
        let (dir, data, definition) = foreign_sqlite(sql);
        let before = snapshot(&data);
        assert!(
            open(dir.path(), definition).await.is_err(),
            "an SQLite store holding {sql} was opened"
        );
        assert_unchanged(&before, &snapshot(&data));
    }
}

async fn probe_store(dir: &Path, definition: Value) -> TargetProbe {
    let config = dir.join("probe.json");
    std::fs::write(&config, definition.to_string()).expect("write config");
    V1Target::probe_store(
        &TargetConfig {
            data_store: config,
            fdb_txn_bytes: 9_000_000,
        },
        None,
    )
    .await
    .expect("probe store")
}

// probe_store tells a missing, an initialized and a foreign RocksDB store apart without creating or changing any file.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn probe_store_is_read_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let definition = json!({"@type": "RocksDb", "path": data.to_string_lossy()});
    assert_eq!(
        probe_store(dir.path(), definition.clone()).await,
        TargetProbe::Empty
    );
    assert!(!data.exists(), "probe_store created the store directory");
    prepared_target(dir.path(), definition.clone()).await;
    let before = snapshot(&data);
    assert!(matches!(
        probe_store(dir.path(), definition).await,
        TargetProbe::Initialized { .. }
    ));
    assert_unchanged(&before, &snapshot(&data));

    let foreign = dir.path().join("foreign");
    {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &foreign).expect("foreign store");
        db.put(b"key", b"value").expect("put");
    }
    let before = snapshot(&foreign);
    assert_eq!(
        probe_store(
            dir.path(),
            json!({"@type": "RocksDb", "path": foreign.to_string_lossy()})
        )
        .await,
        TargetProbe::Foreign
    );
    assert_unchanged(&before, &snapshot(&foreign));
}

// The read-only SQLite open refuses a store with a live -wal or a -journal file, also when reached through a symlink.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_journal_files_refuse_read_only_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real");
    let link = dir.path().join("link");
    std::fs::create_dir(&real).expect("real dir");
    std::fs::create_dir(&link).expect("link dir");
    let file = real.join("store.sqlite");
    let linked = link.join("store.sqlite");
    std::os::unix::fs::symlink(&file, &linked).expect("symlink");
    let definition = |path: &Path| json!({"@type": "Sqlite", "path": path.to_string_lossy()});
    prepared_target(dir.path(), definition(&file)).await;
    let read_only = |path: PathBuf| async move {
        Store::build_read_only(
            serde_json::from_value::<DataStore>(definition(&path)).expect("definition"),
        )
        .await
    };
    assert!(read_only(linked.clone()).await.is_ok());

    let writer = rusqlite::Connection::open(&file).expect("writer");
    writer
        .execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE IF NOT EXISTS wal_probe (id INTEGER); INSERT INTO wal_probe VALUES (1);")
        .expect("wal write");
    assert!(real.join("store.sqlite-wal").exists());
    for path in [file.clone(), linked.clone()] {
        assert!(
            read_only(path.clone()).await.is_err(),
            "{} opened with a live -wal",
            path.display()
        );
    }
    drop(writer);
    assert!(!real.join("store.sqlite-wal").exists());

    std::fs::write(real.join("store.sqlite-journal"), b"hot").expect("journal");
    assert!(
        read_only(linked).await.is_err(),
        "opened with a -journal file"
    );
}

// A RocksDB target directory holding only lost+found and dot entries is a new empty store, and opening it creates the v1 store there.
#[cfg(feature = "rocks")]
#[tokio::test(flavor = "multi_thread")]
async fn rocksdb_dot_entries_are_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir_all(data.join("lost+found")).expect("lost+found");
    std::fs::write(data.join(".DS_Store"), b"finder").expect("dot file");
    let definition = json!({"@type": "RocksDb", "path": data.to_string_lossy()});
    assert_eq!(
        probe_store(dir.path(), definition.clone()).await,
        TargetProbe::Empty
    );
    let target = open(dir.path(), definition).await.expect("open");
    target.prepare_store(EDITION).await.expect("prepare");
}
