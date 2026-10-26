/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(any(feature = "postgres", feature = "mysql"))]

use std::time::Duration;

use bytes::Bytes;
use model::{
    BlobHash, Collection, Edition, EmailRecord, MailboxRecord, MailboxUid, RecordBatch,
    RegistryKey, RegistryRecord, Target, WriteMode,
};
use serde_json::{Value, json};
use store::blake3;
use target_v1::{TargetConfig, V1Target};
use types::id::Id;

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const STORE_ENV: &str = "TARGET_V1_SQL_STORE";
const ACCOUNT_ID: u32 = 7;
const POOL_SIZE: u64 = 2;
const EMAILS: u32 = 24;
const WRITE_LIMIT: Duration = Duration::from_secs(120);
const MESSAGE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Pool\r\nMessage-ID: <pool@example.org>\r\n\r\nHello.\r\n";

async fn small_pool_target(dir: &std::path::Path) -> V1Target {
    let store = std::env::var(STORE_ENV).expect("TARGET_V1_SQL_STORE");
    let mut store: Value = serde_json::from_str(&store).expect("store json");
    let Value::Object(map) = &mut store else {
        panic!("store json is not an object");
    };
    map.insert("poolMaxConnections".into(), json!(POOL_SIZE));
    if map.get("@type").and_then(Value::as_str) == Some("MySql") {
        map.insert("poolMinConnections".into(), json!(1));
    }
    let config = dir.join("target.json");
    std::fs::write(&config, store.to_string()).expect("write config");
    let target = V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target");
    target.prepare_store(EDITION).await.expect("prepare");
    let mut records = Vec::new();
    let mut domain = json!({"name": "example.org"});
    let mut account = json!({"@type": "User", "name": "bob", "domainId": Id::new(3).to_string()});
    if cfg!(feature = "enterprise") {
        records.push(RegistryRecord {
            key: RegistryKey::new("Tenant", 1),
            json: json!({"name": "acme"}),
        });
        for object in [&mut domain, &mut account] {
            if let Value::Object(map) = object {
                map.insert("memberTenantId".into(), json!(Id::new(1).to_string()));
            }
        }
    }
    records.push(RegistryRecord {
        key: RegistryKey::new("Domain", 3),
        json: domain,
    });
    records.push(RegistryRecord {
        key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
        json: account,
    });
    let outcome = target.write_registry(&records).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    target
}

// Rewriting more emails than the pool has connections finishes instead of deadlocking on the blob prefetch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn email_replace_with_a_small_pool_finishes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = small_pool_target(dir.path()).await;
    let blob_hash = BlobHash(*blake3::hash(MESSAGE).as_bytes());
    target
        .put_blob(&blob_hash, Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Mailbox(vec![MailboxRecord {
                document_id: 0,
                name: "Inbox".into(),
                role: Some("inbox".into()),
                uid_validity: 1,
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("inbox");
    let emails = RecordBatch::Email(
        (0..EMAILS)
            .map(|document_id| EmailRecord {
                document_id,
                thread_id: document_id,
                change_id: 11,
                received_at: 1_700_000_000,
                keywords: vec!["$seen".into()],
                mailboxes: vec![MailboxUid {
                    mailbox_id: 0,
                    uid: document_id + 1,
                }],
                blob_hash,
                body_offset: 0,
                extra_headers: Box::default(),
                size: MESSAGE.len() as u32,
            })
            .collect(),
    );
    for mode in [WriteMode::Create, WriteMode::Replace, WriteMode::Replace] {
        let outcome = tokio::time::timeout(WRITE_LIMIT, target.upsert(ACCOUNT_ID, &emails, mode))
            .await
            .unwrap_or_else(|_| {
                panic!("{mode:?} of {EMAILS} emails with a pool of {POOL_SIZE} hangs")
            })
            .expect("upsert");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let present = target
        .exists(
            ACCOUNT_ID,
            Collection::Email,
            &(0..EMAILS).collect::<Vec<_>>(),
        )
        .await
        .expect("exists");
    assert_eq!(present.len(), u64::from(EMAILS));
}
