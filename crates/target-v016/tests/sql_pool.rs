/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(all(feature = "rocks", any(feature = "postgres", feature = "mysql")))]

use std::time::Duration;

use model::{Collection, Edition, RecordBatch, Source, Target, WriteMode};
use serde_json::{Value, json};
use source_v016::{SourceConfig, V016Source, testkit};
use target_v016::{SharedDeletes, TargetConfig, V016Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const STORE_ENV: &str = "TARGET_V016_SQL_STORE";
const ACCOUNT: u32 = testkit::ACCOUNT;
const POOL_SIZE: u64 = 2;
const EMAILS: u32 = 24;
const WRITE_LIMIT: Duration = Duration::from_secs(120);

async fn small_pool_target(dir: &std::path::Path) -> V016Target {
    let store = std::env::var(STORE_ENV).expect("TARGET_V016_SQL_STORE");
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
    V016Target::open(TargetConfig {
        data_store: config,
        shared_deletes: SharedDeletes::Forbid,
    })
    .await
    .expect("open target")
}

// Rewriting more emails than the pool has connections finishes instead of deadlocking on the blob prefetch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn email_replace_with_a_small_pool_finishes() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let mut config = SourceConfig::new(testkit::rocks(source_dir.path()));
    config.refresh_interval = Duration::ZERO;
    let source = V016Source::open(config).await.expect("open source");
    let mut registry = Vec::new();
    for name in source.registry_types().await.expect("types") {
        registry.extend(
            source
                .registry_page(&name, None, 1000)
                .await
                .expect("registry page"),
        );
    }
    let mailboxes = source
        .scan(ACCOUNT, Collection::Mailbox, None, 1000)
        .await
        .expect("mailboxes")
        .batch;
    let RecordBatch::Email(seeded) = source
        .scan(ACCOUNT, Collection::Email, None, 1000)
        .await
        .expect("emails")
        .batch
    else {
        panic!("email batch");
    };
    let template = seeded.first().expect("seeded email").clone();
    let blob = source
        .read_blob(&template.blob_hash)
        .await
        .expect("read blob")
        .expect("blob present");

    let dir = tempfile::tempdir().expect("tempdir");
    let target = small_pool_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    let mut pending = registry;
    for _ in 0..3 {
        let outcome = target.write_registry(&pending).await.expect("registry");
        let failed = outcome
            .issues
            .iter()
            .filter_map(|issue| match &issue.subject {
                model::Subject::Registry(key) => Some(key.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        pending.retain(|record| failed.contains(&record.key));
    }
    assert!(
        pending.is_empty(),
        "registry objects not written: {pending:?}"
    );
    target.start_server().await.expect("boot");
    target
        .put_blob(&template.blob_hash, blob)
        .await
        .expect("put blob");
    target
        .upsert(ACCOUNT, &mailboxes, WriteMode::Create)
        .await
        .expect("mailboxes");

    let emails = RecordBatch::from(
        (0..EMAILS)
            .map(|document_id| {
                let mut email = template.clone();
                email.document_id = document_id;
                for mailbox in &mut email.mailboxes {
                    mailbox.uid = document_id + 1;
                }
                email
            })
            .collect::<Vec<_>>(),
    );
    for mode in [WriteMode::Create, WriteMode::Replace, WriteMode::Replace] {
        let outcome = tokio::time::timeout(WRITE_LIMIT, target.upsert(ACCOUNT, &emails, mode))
            .await
            .unwrap_or_else(|_| {
                panic!("{mode:?} of {EMAILS} emails with a pool of {POOL_SIZE} hangs")
            })
            .expect("upsert");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let present = target
        .exists(ACCOUNT, Collection::Email, &(0..EMAILS).collect::<Vec<_>>())
        .await
        .expect("exists");
    assert_eq!(present.len(), u64::from(EMAILS));
}
