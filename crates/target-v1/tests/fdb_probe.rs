/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "foundation")]

use foundationdb::Database;
use model::{Edition, Target, TargetProbe};
use serde_json::json;
use target_v1::{TargetConfig, V1Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const FOREIGN_KEY: &[u8] = b"\x01other-application";

static CLUSTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn exclusive_empty_cluster() -> (String, tokio::sync::MutexGuard<'static, ()>) {
    let guard = CLUSTER.lock().await;
    let cluster_file =
        std::env::var("TARGET_V1_FDB_CLUSTER_FILE").expect("TARGET_V1_FDB_CLUSTER_FILE");
    target_v1::boot_foundationdb_network().expect("fdb network");
    let db = Database::new(Some(&cluster_file)).expect("cluster");
    let trx = db.create_trx().expect("trx");
    trx.clear_range(b"", b"\xff");
    trx.commit().await.expect("clear the cluster");
    (cluster_file, guard)
}

// A FoundationDB cluster that holds keys outside the store subspaces (another application's) is foreign: the probe reports it and open refuses it without writing; without those keys the cluster is empty, and after prepare it is initialized.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
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
        fdb_txn_bytes: 9_000_000,
    };
    assert_eq!(
        V1Target::probe_store(&target_config(), None)
            .await
            .expect("probe"),
        TargetProbe::Foreign
    );
    assert!(V1Target::open(target_config()).await.is_err());
    assert_eq!(keys().await, vec![FOREIGN_KEY.to_vec()]);
    write(false).await;
    assert_eq!(
        V1Target::probe_store(&target_config(), None)
            .await
            .expect("probe"),
        TargetProbe::Empty
    );
    let target = V1Target::open(target_config()).await.expect("open");
    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
    target.prepare_store(EDITION).await.expect("prepare");
    drop(target);
    assert!(matches!(
        V1Target::probe_store(&target_config(), None)
            .await
            .expect("probe"),
        TargetProbe::Initialized { .. }
    ));
}

// Two targets bumping the claim generation from the same expected value race on one FoundationDB cluster: exactly one wins, and a retried unknown commit still reports the winner.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
async fn fdb_concurrent_claim_generation_swap_has_one_winner() {
    use model::{ClaimId, TargetClaim};

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
        V1Target::open_claimed(
            TargetConfig {
                data_store: config.clone(),
                fdb_txn_bytes: 9_000_000,
            },
            None,
            claim,
        )
        .await
        .expect("open")
    };
    let first = open().await;
    first.prepare_store(EDITION).await.expect("prepare");
    let second = open().await;
    for round in 0u8..20 {
        let expected = first.claim_generation().await.expect("generation");
        let (a, b) = tokio::join!(
            first.swap_claim_generation(expected, ClaimId::from_bytes([round; ClaimId::LEN])),
            second
                .swap_claim_generation(expected, ClaimId::from_bytes([round | 0x80; ClaimId::LEN])),
        );
        let winners = [a.expect("first"), b.expect("second")];
        assert_eq!(
            winners.iter().filter(|won| **won).count(),
            1,
            "round {round}: {winners:?}"
        );
    }
}

// A swap whose commit landed but was reported as a conflict (FoundationDB 1021, here played by a second target) counts as won right after a read, because the re-read does not use the cached read version.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
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
        V1Target::open_claimed(
            TargetConfig {
                data_store: config.clone(),
                fdb_txn_bytes: 9_000_000,
            },
            None,
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

// A generation read right after another target's swap sees the new value, not the read version cached by an earlier read (preflight settles an unknown swap this way).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_FDB_CLUSTER_FILE with the path of a cluster file of a FoundationDB 7.4 cluster the tests may clear"]
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
        V1Target::open_claimed(
            TargetConfig {
                data_store: config.clone(),
                fdb_txn_bytes: 9_000_000,
            },
            None,
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
