/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(any(feature = "postgres", feature = "mysql"))]

use model::{Edition, Target, TargetProbe};
use target_v1::{TargetConfig, V1Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const STORE_ENV: &str = "TARGET_V1_SQL_STORE";

// A fresh SQL database (no internal FTS tables) probes as empty, then as initialized after prepare.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn fresh_sql_store_probes_empty() {
    let store = std::env::var(STORE_ENV).expect("TARGET_V1_SQL_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, store).expect("write config");
    let config = TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    };
    assert_eq!(
        V1Target::probe_store(&config, None)
            .await
            .expect("probe store"),
        TargetProbe::Empty
    );
    let target = V1Target::open(TargetConfig {
        data_store: config.data_store.clone(),
        fdb_txn_bytes: config.fdb_txn_bytes,
    })
    .await
    .expect("open target");
    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
    target.prepare_store(EDITION).await.expect("prepare");
    assert!(matches!(
        target.probe().await.expect("probe"),
        TargetProbe::Initialized { .. }
    ));
    drop(target);
    assert!(matches!(
        V1Target::probe_store(&config, None)
            .await
            .expect("probe store"),
        TargetProbe::Initialized { .. }
    ));
}

// Opening a TLS PostgreSQL store fails cleanly instead of panicking for a missing rustls provider.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn tls_store_open_installs_provider() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(
        &config,
        r#"{"@type":"PostgreSql","host":"127.0.0.1","port":1,"database":"x","authUsername":"x","useTls":true}"#,
    )
    .expect("write config");
    assert!(
        V1Target::open(TargetConfig {
            data_store: config,
            fdb_txn_bytes: 9_000_000,
        })
        .await
        .is_err()
    );
}

async fn table_names(store: &store::Store, query: &str) -> Vec<String> {
    let mut names = store
        .sql_query::<store::Rows>(query, Vec::new())
        .await
        .expect("list tables")
        .rows
        .into_iter()
        .filter_map(|row| match row.values.into_iter().next() {
            Some(store::Value::Text(text)) => Some(text.into_owned()),
            Some(store::Value::Blob(bytes)) => String::from_utf8(bytes.into_owned()).ok(),
            _ => None,
        })
        .collect::<Vec<_>>();
    names.sort_unstable();
    names
}

// A database holding an unrelated table is refused by open before any DDL: no v1 table is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_FOREIGN_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn sql_foreign_database_is_untouched() {
    let json = std::env::var("TARGET_V1_SQL_FOREIGN_STORE").expect("TARGET_V1_SQL_FOREIGN_STORE");
    let definition =
        serde_json::from_str::<registry::schema::structs::DataStore>(&json).expect("definition");
    let query = match definition {
        registry::schema::structs::DataStore::PostgreSql(_) => {
            "SELECT table_name::text FROM information_schema.tables WHERE table_schema = current_schema()"
        }
        _ => "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()",
    };
    let store = store::Store::build(definition).await.expect("connect");
    store
        .sql_query::<usize>("CREATE TABLE IF NOT EXISTS unrelated (id INT)", Vec::new())
        .await
        .expect("unrelated table");
    let before = table_names(&store, query).await;
    assert_eq!(before, vec!["unrelated".to_string()]);
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, json).expect("write config");
    assert!(
        V1Target::open(TargetConfig {
            data_store: config,
            fdb_txn_bytes: 9_000_000,
        })
        .await
        .is_err(),
        "a foreign database was opened"
    );
    assert_eq!(table_names(&store, query).await, before);
}

// Rewrites find the current rows through the batched prefetch on SQL backends: a registry update and a rescheduled task replace their rows.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_PREFETCH_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn sql_prefetch_finds_current_rows() {
    use model::{GlobalBatch, RegistryKey, RegistryRecord, TaskRecord};
    use registry::schema::structs::{Task, TaskDestroyAccount, TaskStatus};
    use serde_json::json;
    use store::{
        ValueKey,
        write::{TaskId, TaskQueueClass, ValueClass},
    };

    let json = std::env::var("TARGET_V1_SQL_PREFETCH_STORE").expect("TARGET_V1_SQL_PREFETCH_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, json).expect("write config");
    let target = V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target");
    target.prepare_store(EDITION).await.expect("prepare");
    for name in ["example.org", "example.net"] {
        let outcome = target
            .write_registry(&[RegistryRecord {
                key: RegistryKey::new("Domain", 3),
                json: json!({"name": name}),
            }])
            .await
            .expect("domain");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let read = target
        .read_registry(&[RegistryKey::new("Domain", 3)])
        .await
        .expect("read");
    assert_eq!(
        read[0].as_ref().expect("domain").json["name"],
        "example.net"
    );

    target.start_server().await.expect("server");
    let due = |at: u64| {
        ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(77),
            typ: registry::schema::enums::TaskType::DestroyAccount,
            due: at,
        }))
    };
    for at in [1_900_000_000u64, 1_900_000_060] {
        let task = Task::DestroyAccount(TaskDestroyAccount {
            account_name: "gone".into(),
            status: TaskStatus::at(at as i64),
            ..Default::default()
        });
        target
            .write_global(&GlobalBatch::Tasks(vec![TaskRecord {
                id: 77,
                json: serde_json::to_value(task).expect("task"),
            }]))
            .await
            .expect("task");
    }
    let store = target.store();
    assert!(!store.key_exists(due(1_900_000_000)).await.expect("old due"));
    assert!(store.key_exists(due(1_900_000_060)).await.expect("new due"));
}

async fn assert_refused_untouched(json: &str, store: &store::Store, query: &str, setup: &[&str]) {
    for statement in setup {
        store
            .sql_query::<usize>(statement, Vec::new())
            .await
            .expect("foreign objects");
    }
    let before = table_names(store, query).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, json).expect("write config");
    assert!(
        V1Target::open(TargetConfig {
            data_store: config,
            fdb_txn_bytes: 9_000_000,
        })
        .await
        .is_err(),
        "a database holding {setup:?} was opened"
    );
    assert_eq!(table_names(store, query).await, before, "{setup:?}");
}

// PostgreSQL: views and relations in another schema on the search path make the database foreign, while extension members and schemas off the search path are ignored; no v1 table is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_RELATION_STORE with the DataStore JSON of an empty PostgreSQL database"]
async fn postgres_foreign_relations_are_refused() {
    use std::panic::AssertUnwindSafe;

    use futures::FutureExt;

    let json = std::env::var("TARGET_V1_SQL_RELATION_STORE").expect("TARGET_V1_SQL_RELATION_STORE");
    let definition =
        serde_json::from_str::<registry::schema::structs::DataStore>(&json).expect("definition");
    let store = store::Store::build(definition).await.expect("connect");
    let query = "SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')";
    let run = async |statements: &[&str]| {
        for statement in statements {
            store
                .sql_query::<usize>(statement, Vec::new())
                .await
                .expect(statement);
        }
    };
    for (setup, cleanup) in [
        (
            &[
                "CREATE SCHEMA other",
                "CREATE TABLE other.b (id INT)",
                "ALTER ROLE CURRENT_USER SET search_path TO public, other",
            ][..],
            &[
                "ALTER ROLE CURRENT_USER RESET search_path",
                "DROP SCHEMA IF EXISTS other CASCADE",
            ][..],
        ),
        (
            &["CREATE VIEW a AS SELECT 1 AS one"],
            &["DROP VIEW IF EXISTS a"],
        ),
        (&["CREATE SEQUENCE a"], &["DROP SEQUENCE IF EXISTS a"]),
        (&["CREATE TYPE a AS (one INT)"], &["DROP TYPE IF EXISTS a"]),
    ] {
        let outcome = AssertUnwindSafe(assert_refused_untouched(&json, &store, query, setup))
            .catch_unwind()
            .await;
        run(cleanup).await;
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, &json).expect("write config");
    let config = TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    };
    for (setup, cleanup) in [
        (
            &["CREATE EXTENSION pg_buffercache"][..],
            &["DROP EXTENSION IF EXISTS pg_buffercache"][..],
        ),
        (
            &["CREATE SCHEMA other", "CREATE TABLE other.a (id INT)"],
            &["DROP SCHEMA IF EXISTS other CASCADE"],
        ),
    ] {
        let outcome = AssertUnwindSafe(async {
            run(setup).await;
            assert_eq!(
                V1Target::probe_store(&config, None)
                    .await
                    .expect("probe store"),
                TargetProbe::Empty,
                "{setup:?}"
            );
        })
        .catch_unwind()
        .await;
        run(cleanup).await;
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
}

// On a MySQL server that folds table names, a foreign table A (listed as a) is refused by its columns; no v1 table is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_FOLDED_STORE with the DataStore JSON of an empty database on a MySQL server with lower_case_table_names=1"]
async fn mysql_folded_table_name_is_refused() {
    let json = std::env::var("TARGET_V1_SQL_FOLDED_STORE").expect("TARGET_V1_SQL_FOLDED_STORE");
    let definition =
        serde_json::from_str::<registry::schema::structs::DataStore>(&json).expect("definition");
    let store = store::Store::build(definition).await.expect("connect");
    let query = "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()";
    assert_refused_untouched(
        &json,
        &store,
        query,
        &["CREATE TABLE A (k VARBINARY(255) NOT NULL, name TEXT, PRIMARY KEY (k))"],
    )
    .await;
    store
        .sql_query::<usize>("DROP TABLE A", Vec::new())
        .await
        .expect("cleanup");
}

// The target reads only from the primary: with a read replica that lags (an empty database with the v1 tables), rewrites find their current rows, probe_store sees the initialized store, and a PostgreSQL blob store with the same replica reads back a blob just written.
#[cfg(all(feature = "postgres", feature = "enterprise"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_REPLICA_STORE with the DataStore JSON of an empty PostgreSQL database whose readReplicas point at another empty database (the test creates the schema there)"]
async fn read_replicas_are_not_used_by_the_target() {
    use model::{RegistryKey, RegistryRecord};
    use serde_json::json;

    let json = std::env::var("TARGET_V1_SQL_REPLICA_STORE").expect("TARGET_V1_SQL_REPLICA_STORE");
    let definition = serde_json::from_str::<serde_json::Value>(&json).expect("definition");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut replica = definition["readReplicas"]["0"].clone();
    replica["@type"] = json!("PostgreSql");
    let replica_config = dir.path().join("replica.json");
    std::fs::write(&replica_config, replica.to_string()).expect("write replica config");
    drop(
        V1Target::open(TargetConfig {
            data_store: replica_config,
            fdb_txn_bytes: 9_000_000,
        })
        .await
        .expect("replica schema"),
    );
    let config = TargetConfig {
        data_store: dir.path().join("target.json"),
        fdb_txn_bytes: 9_000_000,
    };
    std::fs::write(&config.data_store, &json).expect("write config");
    let target = V1Target::open(TargetConfig {
        data_store: config.data_store.clone(),
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target");
    target.prepare_store(EDITION).await.expect("prepare");
    assert!(matches!(
        V1Target::probe_store(&config, None)
            .await
            .expect("probe store"),
        TargetProbe::Initialized { .. }
    ));
    let domain = |name: &str| RegistryRecord {
        key: RegistryKey::new("Domain", 3),
        json: json!({"name": name}),
    };
    for page in [
        &[domain("a.example")][..],
        &[domain("b.example"), domain("c.example")],
    ] {
        let outcome = target.write_registry(page).await.expect("registry");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let read = target
        .read_registry(&[RegistryKey::new("Domain", 3)])
        .await
        .expect("read");
    assert_eq!(read[0].as_ref().expect("domain").json["name"], "c.example");

    let outcome = target
        .write_registry(&[RegistryRecord {
            key: RegistryKey::singleton("BlobStore"),
            json: definition.clone(),
        }])
        .await
        .expect("blob store");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("boot");
    let data = b"stored on the primary";
    let hash = model::BlobHash(*store::blake3::hash(data).as_bytes());
    target
        .put_blob(&hash, bytes::Bytes::from_static(data))
        .await
        .expect("put blob");
    assert_eq!(
        target
            .server()
            .expect("server")
            .blob_store()
            .get_blob(hash.as_bytes(), 0..usize::MAX)
            .await
            .expect("read blob")
            .as_deref(),
        Some(&data[..])
    );
}

// Two processes bumping the claim generation from the same expected value race on one SQL store: exactly one wins.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V1_SQL_CLAIM_STORE with the DataStore JSON of an empty database"]
async fn concurrent_claim_generation_swap_has_one_winner() {
    use model::{ClaimId, TargetClaim};

    let json = std::env::var("TARGET_V1_SQL_CLAIM_STORE").expect("TARGET_V1_SQL_CLAIM_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, json).expect("write config");
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
