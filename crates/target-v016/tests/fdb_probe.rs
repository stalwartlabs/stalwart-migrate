/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "foundation")]

use foundationdb::Database;
use model::{Edition, Target, TargetProbe};
use serde_json::json;
use target_v016::{SharedDeletes, TargetConfig, V016Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const FOREIGN_KEY: &[u8] = b"\x01other-application";

static CLUSTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn exclusive_empty_cluster() -> (String, tokio::sync::MutexGuard<'static, ()>) {
    let guard = CLUSTER.lock().await;
    let cluster_file =
        std::env::var("TARGET_V016_FDB_CLUSTER_FILE").expect("TARGET_V016_FDB_CLUSTER_FILE");
    store::backend::foundationdb::FdbStore::boot_network().expect("fdb network");
    let db = Database::new(Some(&cluster_file)).expect("cluster");
    let trx = db.create_trx().expect("trx");
    trx.clear_range(b"", b"\xff");
    trx.commit().await.expect("clear the cluster");
    (cluster_file, guard)
}

// A FoundationDB cluster that holds keys outside the store subspaces (another application's) is foreign: the probe reports it and open refuses it without writing; without those keys the cluster is empty, and after prepare it is initialized.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
async fn fdb_cluster_shared_with_another_application_is_foreign() {
    let (cluster_file, _cluster) = exclusive_empty_cluster().await;
    let db = Database::new(Some(&cluster_file)).expect("cluster");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "FoundationDb", "clusterFile": cluster_file}).to_string(),
    )
    .expect("write config");
    let write = async |set: bool| {
        let trx = db.create_trx().expect("trx");
        if set {
            trx.set(FOREIGN_KEY, b"1");
        } else {
            trx.clear(FOREIGN_KEY);
        }
        trx.commit().await.expect("commit");
    };
    let keys = async || {
        let trx = db.create_trx().expect("trx");
        trx.get_range(&(&b""[..], &b"\xff"[..]).into(), 1, true)
            .await
            .expect("range")
            .iter()
            .map(|value| value.key().to_vec())
            .collect::<Vec<_>>()
    };
    write(true).await;
    let target_config = || TargetConfig {
        data_store: config.clone(),
        shared_deletes: SharedDeletes::Forbid,
    };
    assert!(V016Target::open(target_config()).await.is_err());
    assert_eq!(keys().await, vec![FOREIGN_KEY.to_vec()]);
    write(false).await;
    let target = V016Target::open(target_config()).await.expect("open");
    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
    target.prepare_store(EDITION).await.expect("prepare");
    drop(target);
    let target = V016Target::open(target_config()).await.expect("reopen");
    assert!(matches!(
        target.probe().await.expect("probe"),
        TargetProbe::Initialized { .. }
    ));
}

// A swap whose commit landed but was reported as a conflict (FoundationDB 1021, here played by a second store) counts as won right after a read, because the re-read does not use the cached read version.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
async fn fdb_swap_landed_elsewhere_is_won_after_a_cached_read() {
    use model::{ClaimId, TargetClaim};

    const G0: ClaimId = ClaimId::from_bytes([0x21; ClaimId::LEN]);
    const NEXT: ClaimId = ClaimId::from_bytes([0x22; ClaimId::LEN]);
    let (cluster_file, _cluster) = exclusive_empty_cluster().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "FoundationDb", "clusterFile": cluster_file}).to_string(),
    )
    .expect("write config");
    let claim = TargetClaim::New(ClaimId::from_bytes([0x11; ClaimId::LEN]));
    let open = async || {
        V016Target::open_claimed(
            TargetConfig {
                data_store: config.clone(),
                shared_deletes: SharedDeletes::Forbid,
            },
            claim,
        )
        .await
        .expect("open")
    };
    let first = open().await;
    first.prepare_store(EDITION).await.expect("prepare");
    let second = open().await;
    assert!(
        first
            .swap_claim_generation(None, G0)
            .await
            .expect("first swap")
    );
    assert_eq!(first.claim_generation().await.expect("read"), Some(G0));
    assert!(
        second
            .swap_claim_generation(Some(G0), NEXT)
            .await
            .expect("landed")
    );
    assert!(
        first
            .swap_claim_generation(Some(G0), NEXT)
            .await
            .expect("retried")
    );
}

// A registry page of linked items larger than a FoundationDB transaction (10 MB) is committed at its commit points instead of failing with transaction_too_large.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
async fn fdb_large_linked_item_page_is_split() {
    use model::{RegistryKey, RegistryRecord};
    use registry::{
        schema::{
            prelude::{Object, ObjectInner},
            structs::{ArchivedEmail, ArchivedItem},
        },
        types::datetime::UTCDateTime,
    };
    use types::{blob::BlobId, blob_hash::BlobHash};

    const ITEMS: u64 = 3_000;
    const SUBJECT_LEN: usize = 4_000;
    let (cluster_file, _cluster) = exclusive_empty_cluster().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "FoundationDb", "clusterFile": cluster_file}).to_string(),
    )
    .expect("write config");
    let target = V016Target::open(TargetConfig {
        data_store: config,
        shared_deletes: SharedDeletes::Forbid,
    })
    .await
    .expect("open");
    target.prepare_store(EDITION).await.expect("prepare");
    let blob_hash = BlobHash(*store::blake3::hash(b"large page").as_bytes());
    let subject = "s".repeat(SUBJECT_LEN);
    let records = (1..=ITEMS)
        .map(|item_id| {
            let item = ArchivedItem::Email(ArchivedEmail {
                account_id: 1u32.into(),
                blob_id: BlobId::new(blob_hash.clone(), Default::default()),
                archived_until: UTCDateTime::from_timestamp(1_924_992_000),
                archived_at: UTCDateTime::from_timestamp(1_906_000_000),
                from: String::new(),
                received_at: UTCDateTime::from_timestamp(1_893_456_000),
                subject: subject.clone(),
                size: 5,
            });
            RegistryRecord {
                key: RegistryKey::new("ArchivedItem", item_id),
                json: serde_json::to_value(
                    Object::new(ObjectInner::ArchivedItem(item)).into_value_with_secrets(),
                )
                .expect("json"),
            }
        })
        .collect::<Vec<_>>();
    let outcome = target.write_registry(&records).await.expect("large page");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let last = RegistryKey::new("ArchivedItem", ITEMS);
    assert!(target.read_registry(&[last]).await.expect("read")[0].is_some());
}

// A generation read right after another target's swap sees the new value, not the read version cached by an earlier read (preflight settles an unknown swap this way).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
async fn fdb_generation_read_after_another_swap_is_fresh() {
    use model::{ClaimId, TargetClaim};

    const G0: ClaimId = ClaimId::from_bytes([0x31; ClaimId::LEN]);
    const NEXT: ClaimId = ClaimId::from_bytes([0x32; ClaimId::LEN]);
    let (cluster_file, _cluster) = exclusive_empty_cluster().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "FoundationDb", "clusterFile": cluster_file}).to_string(),
    )
    .expect("write config");
    let claim = TargetClaim::New(ClaimId::from_bytes([0x11; ClaimId::LEN]));
    let open = async || {
        V016Target::open_claimed(
            TargetConfig {
                data_store: config.clone(),
                shared_deletes: SharedDeletes::Forbid,
            },
            claim,
        )
        .await
        .expect("open")
    };
    let first = open().await;
    first.prepare_store(EDITION).await.expect("prepare");
    let second = open().await;
    assert!(
        first
            .swap_claim_generation(None, G0)
            .await
            .expect("first swap")
    );
    assert_eq!(first.claim_generation().await.expect("read"), Some(G0));
    assert!(
        second
            .swap_claim_generation(Some(G0), NEXT)
            .await
            .expect("second swap")
    );
    assert_eq!(
        first.claim_generation().await.expect("fresh read"),
        Some(NEXT)
    );
}
