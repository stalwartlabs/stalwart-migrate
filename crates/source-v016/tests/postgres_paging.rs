/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "postgres")]

use std::time::{Duration, Instant};

use email::mailbox::Mailbox;
use model::{Collection, Source};
use registry::schema::structs::{DataStore, PostgreSqlStore, SecretKeyOptional, SecretKeyValue};
use source_v016::{SourceConfig, V016Source};
use store::{
    IterateParams, Serialize, Store, U32_LEN, ValueKey,
    write::{Archiver, BatchBuilder, ValueClass, key::DeserializeBigEndian},
};
use types::{collection::Collection as V016Collection, field::Field};

const ACCOUNT: u32 = 11;
const DOCUMENTS: u32 = 60_000;
const PAGE: usize = 100;
const ENDPOINT: &str = "STALWART_MIGRATE_TEST_PG";

fn config(endpoint: &str) -> DataStore {
    let (host, port) = endpoint.rsplit_once(':').expect("host:port");
    DataStore::PostgreSql(PostgreSqlStore {
        host: host.into(),
        port: port.parse().expect("port"),
        database: "postgres".into(),
        auth_username: Some("postgres".into()),
        auth_secret: SecretKeyOptional::Value(SecretKeyValue {
            secret: "postgres".into(),
        }),
        ..Default::default()
    })
}

fn archive_key(document_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id: ACCOUNT,
        collection: V016Collection::Mailbox.into(),
        document_id,
        class: ValueClass::Property(Field::ARCHIVE.into()),
    }
}

// Paging a large collection on PostgreSQL reads each row once instead of streaming the remainder per page.
#[tokio::test]
async fn postgres_pages_are_bounded() {
    let Ok(endpoint) = std::env::var(ENDPOINT) else {
        eprintln!("{ENDPOINT} not set, skipping");
        return;
    };
    let store = Store::build(config(&endpoint)).await.expect("store");
    store.create_tables().await.expect("tables");
    let bytes = Archiver::new(Mailbox::new("folder"))
        .serialize()
        .expect("archive");
    for chunk in (0..DOCUMENTS).collect::<Vec<_>>().chunks(1000) {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(ACCOUNT)
            .with_collection(V016Collection::Mailbox);
        for document_id in chunk {
            batch
                .with_document(*document_id)
                .set(Field::ARCHIVE, bytes.clone());
        }
        store.write(batch.build_all()).await.expect("write");
    }

    let source = V016Source::open(SourceConfig::new(config(&endpoint)))
        .await
        .expect("source");
    let started = Instant::now();
    let mut after = None;
    let mut total = 0usize;
    loop {
        let page = source
            .scan(ACCOUNT, Collection::Mailbox, after, PAGE)
            .await
            .expect("scan");
        let Some(last) = page.last_scanned else {
            break;
        };
        total += page.batch.len();
        after = Some(last);
    }
    let bounded = started.elapsed();
    assert_eq!(total, DOCUMENTS as usize);

    let started = Instant::now();
    let mut first = 0u32;
    let mut pages = 0usize;
    while first < DOCUMENTS && started.elapsed() < Duration::from_secs(120) {
        let mut seen = 0usize;
        let mut last = first;
        store
            .iterate(
                IterateParams::new(archive_key(first), archive_key(u32::MAX)).ascending(),
                |key, _| {
                    last = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    seen += 1;
                    Ok(seen < PAGE)
                },
            )
            .await
            .expect("iterate");
        first = last + 1;
        pages += 1;
    }
    let unbounded = started.elapsed();
    eprintln!(
        "{DOCUMENTS} rows in pages of {PAGE}: bounded {bounded:?}, unbounded {unbounded:?} for {pages} pages"
    );
    assert!(
        bounded * 2 < unbounded,
        "bounded {bounded:?} unbounded {unbounded:?}"
    );
}
