/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(any(feature = "postgres", feature = "mysql"))]

use model::{Edition, Target, TargetProbe};
use target_v016::{SharedDeletes, TargetConfig, V016Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const STORE_ENV: &str = "TARGET_V016_SQL_STORE";

// A new SQL rollback target probes empty, is prepared, and wipes an account without touching missing search tables.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn sql_target_prepares_and_wipes() {
    let store = std::env::var(STORE_ENV).expect("TARGET_V016_SQL_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, store).expect("write config");
    let target = V016Target::open(TargetConfig {
        data_store: config,
        shared_deletes: SharedDeletes::Forbid,
    })
    .await
    .expect("open target");
    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
    target.prepare_store(EDITION).await.expect("prepare");
    assert!(matches!(
        target.probe().await.expect("probe"),
        TargetProbe::Initialized { .. }
    ));
    target.start_server().await.expect("boot");
    target.wipe_account(7).await.expect("wipe");
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
        V016Target::open(TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .is_err()
    );
}

// An SQL store holding only the stock v0.16 schema marker is refused by open before any write.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_STOCK_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn sql_stock_store_is_refused() {
    use store::write::{AnyClass, BatchBuilder, ValueClass};

    let store = std::env::var("TARGET_V016_SQL_STOCK_STORE").expect("TARGET_V016_SQL_STOCK_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, store).expect("write config");
    let stock = V016Target::open(TargetConfig {
        data_store: config.clone(),
        shared_deletes: SharedDeletes::Forbid,
    })
    .await
    .expect("open empty");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: store::SUBSPACE_PROPERTY,
            key: vec![0],
        }),
        6u32.to_be_bytes().to_vec(),
    );
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock marker");
    drop(stock);
    assert!(
        V016Target::open(TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .is_err()
    );
}

// An SQL store whose tables exist but cannot be read is refused by open instead of being treated as empty.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_DENIED_STORE with the DataStore JSON of a user that cannot read the existing v0.16 tables"]
async fn sql_unreadable_store_is_refused() {
    let store =
        std::env::var("TARGET_V016_SQL_DENIED_STORE").expect("TARGET_V016_SQL_DENIED_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, store).expect("write config");
    let err = match V016Target::open(TargetConfig {
        data_store: config,
        shared_deletes: SharedDeletes::Forbid,
    })
    .await
    {
        Ok(_) => panic!("an unreadable store was opened"),
        Err(err) => err,
    };
    assert!(
        err.message()
            .contains("cannot check that the rollback target"),
        "{err}"
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

// A database holding an unrelated table is refused by open before any DDL: no v0.16 table is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_FOREIGN_STORE with the DataStore JSON of an empty PostgreSQL or MySQL database"]
async fn sql_foreign_database_is_untouched() {
    let json =
        std::env::var("TARGET_V016_SQL_FOREIGN_STORE").expect("TARGET_V016_SQL_FOREIGN_STORE");
    let definition =
        serde_json::from_str::<registry::schema::structs::DataStore>(&json).expect("definition");
    let query = match definition {
        registry::schema::structs::DataStore::PostgreSql(_) => {
            "SELECT tablename::text FROM pg_catalog.pg_tables WHERE schemaname = current_schema()"
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
        V016Target::open(TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .is_err(),
        "a foreign database was opened"
    );
    assert_eq!(table_names(&store, query).await, before);
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
        V016Target::open(TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .is_err(),
        "a database holding {setup:?} was opened"
    );
    assert_eq!(table_names(store, query).await, before, "{setup:?}");
}

// PostgreSQL: views and relations in another schema on the search path make the database foreign, while extension members and schemas off the search path are ignored; no v0.16 table is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_RELATION_STORE with the DataStore JSON of an empty PostgreSQL database"]
async fn postgres_foreign_relations_are_refused() {
    use std::panic::AssertUnwindSafe;

    use futures::FutureExt;

    let json =
        std::env::var("TARGET_V016_SQL_RELATION_STORE").expect("TARGET_V016_SQL_RELATION_STORE");
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
            let target = V016Target::open(TargetConfig {
                data_store: config.clone(),
                shared_deletes: SharedDeletes::Forbid,
            })
            .await
            .unwrap_or_else(|err| panic!("{setup:?}: {err}"));
            drop(target);
        })
        .catch_unwind()
        .await;
        run(cleanup).await;
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
        run(&["DROP SCHEMA public CASCADE", "CREATE SCHEMA public"]).await;
    }
}

// On a MySQL server that folds table names, a foreign table A (listed as a) is refused by its columns; no v0.16 table is created.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_FOLDED_STORE with the DataStore JSON of an empty database on a MySQL server with lower_case_table_names=1"]
async fn mysql_folded_table_name_is_refused() {
    let json = std::env::var("TARGET_V016_SQL_FOLDED_STORE").expect("TARGET_V016_SQL_FOLDED_STORE");
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

// The rollback target reads only from the primary: with a read replica that lags (an empty database with the tables), rewrites find their current rows and a PostgreSQL blob store with the same replica reads back a blob just written.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs TARGET_V016_SQL_REPLICA_STORE with the DataStore JSON of an empty PostgreSQL database whose readReplicas point at another empty database (the test creates the schema there)"]
async fn read_replicas_are_not_used_by_the_target() {
    use model::{RegistryKey, RegistryRecord};

    let json =
        std::env::var("TARGET_V016_SQL_REPLICA_STORE").expect("TARGET_V016_SQL_REPLICA_STORE");
    let definition = serde_json::from_str::<serde_json::Value>(&json).expect("definition");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut replica = definition["readReplicas"]["0"].clone();
    replica["@type"] = serde_json::json!("PostgreSql");
    let replica_config = dir.path().join("replica.json");
    std::fs::write(&replica_config, replica.to_string()).expect("write replica config");
    drop(
        V016Target::open(TargetConfig {
            data_store: replica_config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .expect("replica schema"),
    );
    let config = dir.path().join("target.json");
    std::fs::write(&config, &json).expect("write config");
    let target = V016Target::open(TargetConfig {
        data_store: config,
        shared_deletes: SharedDeletes::Forbid,
    })
    .await
    .expect("open target");
    target.prepare_store(EDITION).await.expect("prepare");
    let blob_store = |path: &str| RegistryRecord {
        key: RegistryKey::singleton("BlobStore"),
        json: serde_json::json!({"@type": "FileSystem", "path": path}),
    };
    for path in ["/tmp/first", "/tmp/second"] {
        let outcome = target
            .write_registry(&[blob_store(path)])
            .await
            .expect("registry");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let read = target
        .read_registry(&[RegistryKey::singleton("BlobStore")])
        .await
        .expect("read");
    assert_eq!(
        read[0].as_ref().expect("blob store").json["path"],
        "/tmp/second"
    );

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
#[ignore = "needs TARGET_V016_SQL_CLAIM_STORE with the DataStore JSON of an empty database"]
async fn concurrent_claim_generation_swap_has_one_winner() {
    use model::{ClaimId, TargetClaim};

    let json = std::env::var("TARGET_V016_SQL_CLAIM_STORE").expect("TARGET_V016_SQL_CLAIM_STORE");
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("target.json");
    std::fs::write(&config, json).expect("write config");
    let claim = TargetClaim::New(ClaimId::from_bytes([0x11; ClaimId::LEN]));
    let open = async || {
        V016Target::open_claimed(
            TargetConfig {
                data_store: config.clone(),
                shared_deletes: target_v016::SharedDeletes::Forbid,
            },
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
