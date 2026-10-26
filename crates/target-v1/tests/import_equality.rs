/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::path::Path;

use bytes::Bytes;
use common::auth::AccessToken;
use email::message::{
    ingest::{EmailIngest, IngestEmail, IngestSource},
    messagedata::MessageData,
    metadata::{ExtraHeaders, HeaderId, MessageMetadata},
};
use mail_parser::MessageParser;
use model::{
    BlobHash, Edition, EmailRecord, MailboxRecord, MailboxUid, RecordBatch, RegistryKey,
    RegistryRecord, Target, WriteMode,
};
use serde_json::json;
use store::{
    Serialize, ValueKey, blake3,
    write::{ValueClass, now},
};
use target_v1::{TargetConfig, V1Target};
use types::{
    blob_hash::BlobHash as V1BlobHash, collection::Collection as V1Collection, field::EmailField,
    keyword::Keyword,
};

const ACCOUNT_ID: u32 = 7;
#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const MESSAGE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Re: Equal bytes\r\nMessage-ID: <eq@example.org>\r\nReferences: <parent@example.org>\r\nDate: Mon, 1 Jan 2024 10:00:00 +0000\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nBody text\r\n--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nPDFDATA\r\n--b--\r\n";

// Server-added headers parsed from raw v0.16 bytes build the same metadata as the stock SMTP path that pushes them.
#[test]
fn raw_extra_headers_match_stock_push() {
    let message = MessageParser::new().parse(MESSAGE).expect("parse");
    let hash = V1BlobHash(*blake3::hash(MESSAGE).as_bytes());
    let mut pushed = ExtraHeaders::default();
    pushed
        .push(HeaderId::DELIVERED_TO, "bob@example.org")
        .push(HeaderId::parse(b"X-Spam-Status"), "No, score=-1.2");
    let raw = ExtraHeaders::from_raw(pushed.as_bytes()).expect("raw headers parse");
    assert_eq!(raw.as_bytes(), pushed.as_bytes());

    let stock = MessageMetadata::build(&message, &pushed, hash.clone());
    let imported = MessageMetadata::build(&message, &raw, hash);
    assert_eq!(stock.raw_headers, imported.raw_headers);
    assert_eq!(
        stock.encode().expect("encode stock"),
        imported.encode().expect("encode imported")
    );
    assert!(ExtraHeaders::from_raw(b"not a header line").is_none());
}

// Only complete header blocks starting at a field name and ending with a line break are accepted.
#[test]
fn raw_extra_headers_reject_partial_blocks() {
    for (input, accepted) in [
        (&b""[..], true),
        (b"Received: from a\r\n\tby b\r\n", true),
        (b"X-A: 1\r\nX-A: 2\r\n", true),
        (b"X-A: 1\n", true),
        (b"X-A:1\r\n", true),
        (b"X-A: 1", false),
        (b"X-A: 1\r\nX-B: 2", false),
        (b"NoColonLine\r\nX-B: 2\r\n", false),
        (b"X-B: 2\r\nNoColonLine\r\n", false),
        (b" leading: space\r\n", false),
        (b"\tX-A: 1\r\n", false),
        (b"X-A: 1\r\n\r\n", false),
    ] {
        let parsed = ExtraHeaders::from_raw(input);
        assert_eq!(
            parsed.is_some(),
            accepted,
            "{:?}",
            String::from_utf8_lossy(input)
        );
        if let Some(parsed) = parsed {
            assert_eq!(parsed.as_bytes(), input);
        }
    }
}

async fn open_target(dir: &Path) -> V1Target {
    let config = dir.join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": dir.join("data").to_string_lossy()}).to_string(),
    )
    .expect("write config");
    V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target")
}

// A message imported with explicit ids stores the same metadata, sort keys, threading row and message data as stock Restore ingest.
#[tokio::test(flavor = "multi_thread")]
async fn import_matches_stock_restore_ingest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    target
        .write_registry(&[
            RegistryRecord {
                key: RegistryKey::new("Domain", 3),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
                json: json!({"@type": "User", "name": "bob", "domainId": "d"}),
            },
        ])
        .await
        .expect("registry");
    target.start_server().await.expect("server");
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
        .expect("mailbox");

    let hash = BlobHash(*blake3::hash(MESSAGE).as_bytes());
    target
        .put_blob(&hash, Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    let received_at = now();
    let server = target.server().expect("server");
    let stock = server
        .email_ingest(IngestEmail {
            raw_message: MESSAGE,
            blob_hash: Some(&V1BlobHash(hash.0)),
            message: MessageParser::new().parse(MESSAGE),
            access_token: &AccessToken::from_id_maybe_invalid(ACCOUNT_ID),
            mailbox_ids: vec![0],
            keywords: vec![Keyword::Seen],
            received_at: Some(received_at),
            source: IngestSource::Restore,
            metadata: None,
            session_id: 0,
        })
        .await
        .expect("stock ingest");

    let imported_id = stock.document_id + 100;
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![EmailRecord {
                document_id: imported_id,
                thread_id: stock.thread_id,
                change_id: stock.change_id,
                received_at,
                keywords: vec!["$seen".into()],
                mailboxes: vec![MailboxUid {
                    mailbox_id: 0,
                    uid: stock.imap_uids[0],
                }],
                blob_hash: hash,
                body_offset: 0,
                extra_headers: Box::default(),
                size: MESSAGE.len() as u32,
            }]),
            WriteMode::Create,
        )
        .await
        .expect("import");

    let store = target.store();
    for class in [
        ValueClass::Immutable(EmailField::Metadata.into()),
        ValueClass::Immutable(EmailField::SortKeys.into()),
    ] {
        let read = |document_id| {
            let class = class.clone();
            async move {
                store
                    .get_value::<RawBytes>(ValueKey {
                        account_id: ACCOUNT_ID,
                        collection: V1Collection::Email.into(),
                        document_id,
                        class,
                    })
                    .await
                    .expect("read")
                    .expect("value")
                    .0
            }
        };
        assert_eq!(
            read(stock.document_id).await,
            read(imported_id).await,
            "{class:?} differs between stock ingest and import"
        );
    }
    let stock_data = store
        .get_value::<MessageData>(ValueKey::archive(
            ACCOUNT_ID,
            V1Collection::Email,
            stock.document_id,
        ))
        .await
        .expect("read")
        .expect("stock data");
    let imported_data = store
        .get_value::<MessageData>(ValueKey::archive(
            ACCOUNT_ID,
            V1Collection::Email,
            imported_id,
        ))
        .await
        .expect("read")
        .expect("imported data");
    assert_eq!(
        stock_data.serialize().expect("serialize stock"),
        imported_data.serialize().expect("serialize imported")
    );
}

struct RawBytes(Vec<u8>);

impl store::Deserialize for RawBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawBytes(bytes.to_vec()))
    }
}
