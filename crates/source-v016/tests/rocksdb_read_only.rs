/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use registry::schema::{enums::CompressionAlgo, structs};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use store::{
    BlobStore, IterateParams, SUBSPACE_BLOBS, Store, ValueKey,
    backend::rocksdb::{RocksDbOpenMode, RocksDbStore},
    blake3,
    write::{AnyKey, BatchBuilder, ValueClass},
};
use types::collection::Collection;

const BLOB_SIZE: usize = 256 << 10;
const STABLE_BLOBS: u32 = 600;
const CHURN_BLOBS: u32 = 300;
const LATE_BLOBS: u32 = 100;
const CHURN_BASE: u32 = 1_000_000;
const LATE_BASE: u32 = 2_000_000;
const BLOB_RETRY_ATTEMPTS: u32 = 16;

fn config(path: &Path) -> structs::RocksDbStore {
    structs::RocksDbStore {
        path: path.to_string_lossy().into_owned(),
        blob_size: 16384,
        buffer_size: 8 * 1024 * 1024,
        pool_workers: Some(4),
        cache_size: 64 * 1024 * 1024,
    }
}

fn payload(key: u32, generation: u32) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ ((key as u64) << 32) ^ generation as u64;
    let mut out = Vec::with_capacity(BLOB_SIZE);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend((4..BLOB_SIZE).map(|_| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
    }));
    out
}

fn is_payload_of(key: u32, value: &[u8]) -> bool {
    value
        .first_chunk::<4>()
        .is_some_and(|generation| value == payload(key, u32::from_be_bytes(*generation)))
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("source-v016-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn open(path: &Path, mode: RocksDbOpenMode) -> Store {
    RocksDbStore::open_with_mode(config(path), mode)
        .await
        .expect("open rocksdb")
}

async fn put(store: &BlobStore, key: u32, generation: u32) {
    store
        .put_blob(
            &key.to_be_bytes(),
            &payload(key, generation),
            CompressionAlgo::None,
        )
        .await
        .expect("put blob");
}

async fn delete(store: &BlobStore, key: u32) {
    store
        .delete_blob(&key.to_be_bytes())
        .await
        .expect("delete blob");
}

#[derive(Debug, PartialEq, Eq)]
enum Read {
    Valid,
    Missing,
    Corrupt,
    Failed,
}

async fn read(store: &BlobStore, key: u32) -> Read {
    match store.get_blob(&key.to_be_bytes(), 0..usize::MAX).await {
        Ok(Some(value)) if is_payload_of(key, &value) => Read::Valid,
        Ok(Some(_)) => Read::Corrupt,
        Ok(None) => Read::Missing,
        Err(_) => Read::Failed,
    }
}

async fn assert_all_valid(store: &BlobStore, keys: impl Iterator<Item = u32>) {
    for key in keys {
        assert_eq!(read(store, key).await, Read::Valid, "key {key}");
    }
}

// Blob-only and full read-only instances opened after the primary deleted blob files see every live blob (a secondary instance stays pinned to an older version and returns None).
#[tokio::test(flavor = "multi_thread")]
async fn read_only_sees_blobs_after_blob_file_deletion() {
    let dir = scratch_dir("ro-blobs");
    let primary = BlobStore::Store(open(&dir, RocksDbOpenMode::ReadWrite).await);
    for key in 0..STABLE_BLOBS {
        put(&primary, key, 0).await;
    }
    for key in CHURN_BASE..CHURN_BASE + CHURN_BLOBS {
        put(&primary, key, 0).await;
    }
    for key in CHURN_BASE..CHURN_BASE + CHURN_BLOBS {
        delete(&primary, key).await;
    }
    for key in LATE_BASE..LATE_BASE + LATE_BLOBS {
        put(&primary, key, 0).await;
    }
    let BlobStore::Store(primary_store) = &primary else {
        unreachable!()
    };
    primary_store.purge_store().await.expect("purge");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let live = || (0..STABLE_BLOBS).chain(LATE_BASE..LATE_BASE + LATE_BLOBS);
    for mode in [RocksDbOpenMode::BlobsReadOnly, RocksDbOpenMode::ReadOnly] {
        let snapshot = BlobStore::Store(open(&dir, mode).await);
        assert_all_valid(&snapshot, live()).await;
    }
    drop(primary);
    let _ = std::fs::remove_dir_all(&dir);
}

fn property_key() -> ValueKey<ValueClass> {
    ValueKey {
        account_id: 1,
        collection: Collection::Email.into(),
        document_id: 0,
        class: ValueClass::Property(1),
    }
}

fn quota_key() -> ValueKey<ValueClass> {
    ValueKey {
        account_id: 1,
        collection: Collection::Email.into(),
        document_id: 0,
        class: ValueClass::Quota,
    }
}

async fn write_batch(store: &Store, batch_number: u32) {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(1)
        .with_collection(Collection::Email)
        .with_document(0)
        .set(
            ValueClass::Property(1),
            batch_number.to_string().into_bytes(),
        )
        .add(ValueClass::Quota, 1);
    store.write(batch.build_all()).await.expect("write batch");
}

// While the primary writes, deletes and garbage collects blobs, each full read-only snapshot keeps cross column family batches atomic and never misses a stable blob; a blob read that fails on a snapshot succeeds on a fresh blob-only instance.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "stress test; run with --release --ignored and ROCKSDB_STRESS_SECS"]
async fn read_only_under_concurrent_primary() {
    let duration = Duration::from_secs(env_u64("ROCKSDB_STRESS_SECS", 10));
    let write_delay = Duration::from_millis(env_u64("ROCKSDB_STRESS_WRITE_DELAY_MS", 2));
    let dir = scratch_dir("ro-stress");
    let primary_store = open(&dir, RocksDbOpenMode::ReadWrite).await;
    let primary = BlobStore::Store(primary_store.clone());
    for key in 0..STABLE_BLOBS {
        put(&primary, key, 0).await;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let primary = primary.clone();
        let primary_store = primary_store.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let (mut generation, mut batches) = (1u32, 0u32);
            while !stop.load(Ordering::Relaxed) {
                for key in CHURN_BASE..CHURN_BASE + CHURN_BLOBS {
                    put(&primary, key, generation).await;
                    batches += 1;
                    write_batch(&primary_store, batches).await;
                    tokio::time::sleep(write_delay).await;
                }
                for key in CHURN_BASE..CHURN_BASE + CHURN_BLOBS {
                    delete(&primary, key).await;
                }
                for key in (0..STABLE_BLOBS).step_by(7) {
                    put(&primary, key, generation).await;
                }
                primary_store.purge_store().await.expect("purge");
                generation += 1;
            }
            (generation, batches)
        })
    };

    let started = Instant::now();
    let (mut passes, mut failed_reads) = (0u32, 0u32);
    while started.elapsed() < duration {
        let snapshot_store = open(&dir, RocksDbOpenMode::ReadOnly).await;
        let counter = snapshot_store
            .get_counter(quota_key())
            .await
            .expect("counter");
        let property = snapshot_store
            .get_value::<String>(property_key())
            .await
            .expect("property")
            .map(|value| value.parse::<i64>().expect("batch number"))
            .unwrap_or_default();
        assert_eq!(counter, property, "torn batch in pass {passes}");

        let snapshot = BlobStore::Store(snapshot_store);
        for key in 0..STABLE_BLOBS {
            match read(&snapshot, key).await {
                Read::Valid => {}
                Read::Failed => {
                    failed_reads += 1;
                    read_with_fresh_instances(&dir, key).await;
                }
                other => panic!("stable key {key} read as {other:?} in pass {passes}"),
            }
        }
        for key in CHURN_BASE..CHURN_BASE + CHURN_BLOBS {
            assert_ne!(read(&snapshot, key).await, Read::Corrupt, "churn key {key}");
        }
        passes += 1;
    }
    stop.store(true, Ordering::Relaxed);
    let (generations, batches) = writer.await.expect("writer");
    let final_snapshot = open(&dir, RocksDbOpenMode::ReadOnly).await;
    let final_counter = final_snapshot
        .get_counter(quota_key())
        .await
        .expect("counter");
    println!(
        "passes={passes} writer_generations={generations} batches={batches} failed_then_valid={failed_reads}"
    );
    assert_eq!(final_counter, i64::from(batches));
    assert!(passes > 0 && generations > 1);
    drop(final_snapshot);
    drop(primary);
    drop(primary_store);
    let _ = std::fs::remove_dir_all(&dir);
}

async fn read_with_fresh_instances(dir: &Path, key: u32) {
    for attempt in 1..=BLOB_RETRY_ATTEMPTS {
        let fresh = BlobStore::Store(open(dir, RocksDbOpenMode::BlobsReadOnly).await);
        match read(&fresh, key).await {
            Read::Valid => return,
            Read::Corrupt => panic!("stable key {key} corrupt on retry"),
            _ if attempt < BLOB_RETRY_ATTEMPTS => {}
            other => panic!("stable key {key} still {other:?} after {attempt} fresh instances"),
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

// Against a live store written by a stock server (ROCKSDB_LIVE_PATH): every blob listed in a read-only snapshot reads back from the same snapshot with a matching BLAKE3 hash (resource blobs such as the WebUI bundle are not content addressed and must stay byte-identical).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a live v0.16 RocksDB store in ROCKSDB_LIVE_PATH"]
async fn read_only_snapshots_of_live_server() {
    let path = PathBuf::from(std::env::var("ROCKSDB_LIVE_PATH").expect("ROCKSDB_LIVE_PATH"));
    let duration = Duration::from_secs(env_u64("ROCKSDB_STRESS_SECS", 60));
    let started = Instant::now();
    let (mut passes, mut blobs_read, mut failed_reads) = (0u32, 0usize, 0usize);
    let mut keys = Vec::new();
    let mut resources = HashMap::new();
    while started.elapsed() < duration {
        let snapshot = open(&path, RocksDbOpenMode::ReadOnly).await;
        keys.clear();
        snapshot
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace: SUBSPACE_BLOBS,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace: SUBSPACE_BLOBS,
                        key: vec![u8::MAX; 64],
                    },
                )
                .set_values(false),
                |key, _| {
                    keys.push(key.to_vec());
                    Ok(true)
                },
            )
            .await
            .expect("iterate blobs");
        let blobs = BlobStore::Store(snapshot);
        for key in &keys {
            match blobs.get_blob(key, 0..usize::MAX).await {
                Ok(Some(value)) => {
                    let hash = *blake3::hash(&value).as_bytes();
                    if hash.as_slice() != key.as_slice() {
                        let first = *resources.entry(key.clone()).or_insert(hash);
                        assert_eq!(first, hash, "resource blob {key:02x?} changed");
                    }
                    blobs_read += 1;
                }
                Ok(None) => panic!("listed blob {key:02x?} missing from the same snapshot"),
                Err(_) => failed_reads += 1,
            }
        }
        passes += 1;
    }
    println!(
        "passes={passes} blobs_read={blobs_read} failed_reads={failed_reads} last_listing={}",
        keys.len()
    );
    assert!(passes > 0);
}
