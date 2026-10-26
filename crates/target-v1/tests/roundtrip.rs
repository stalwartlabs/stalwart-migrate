/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::path::Path;

use bytes::Bytes;
use email::message::{messagedata::MessageData, metadata::MetadataRow};
use model::{
    AccountPointers, BlobHash, ChangeLogRecord, Collection, Counters, Edition, EmailRecord,
    IdentityRecord, LogChanges, LogCollection, LogEntry, MailboxRecord, MailboxUid, Pointer,
    RecordBatch, RegistryKey, RegistryRecord, Target, TargetProbe, VanishedRecord, WriteMode,
};
use serde_json::json;
use store::{
    ValueKey, blake3,
    query::log::Query,
    write::{LogCollection as V1LogCollection, ValueClass},
};
use target_v1::{TargetConfig, V1Target};
use types::{
    collection::{Collection as V1Collection, SyncCollection, VanishedCollection},
    field::EmailField,
    keyword::{FLAGGED, SEEN},
};

const ACCOUNT_ID: u32 = 7;
#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const MESSAGE: &[u8] =
    b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Migrated\r\nMessage-ID: <m1@example.org>\r\n\r\nHello there.\r\n";
const EXTRA_HEADERS: &[u8] = b"Delivered-To: bob@example.org\r\nX-Spam-Status: No, score=0.1\r\n";

fn hash(bytes: &[u8]) -> BlobHash {
    BlobHash(*blake3::hash(bytes).as_bytes())
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

fn registry_records() -> Vec<RegistryRecord> {
    vec![
        RegistryRecord {
            key: RegistryKey::new("Domain", 3),
            json: json!({"name": "example.org"}),
        },
        RegistryRecord {
            key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
            json: json!({
                "@type": "User",
                "name": "bob",
                "domainId": "d",
                "credentials": {"0": {"@type": "Password", "credentialId": "b", "secret": "$6$salt$hash"}},
            }),
        },
    ]
}

fn email_record() -> EmailRecord {
    EmailRecord {
        document_id: 4,
        thread_id: 2,
        change_id: 11,
        received_at: 1_700_000_000,
        keywords: vec!["$seen".into(), "$flagged".into(), "project-x".into()],
        mailboxes: vec![MailboxUid {
            mailbox_id: 0,
            uid: 41,
        }],
        blob_hash: hash(MESSAGE),
        body_offset: 0,
        extra_headers: EXTRA_HEADERS.into(),
        size: (MESSAGE.len() + EXTRA_HEADERS.len()) as u32,
    }
}

// One batched registry read answers every key in order: present, missing, unknown and repeated objects, and the DataStore singleton.
#[tokio::test(flavor = "multi_thread")]
async fn registry_reads_answer_every_key_in_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    let outcome = target
        .write_registry(&registry_records())
        .await
        .expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let account = RegistryKey::new("x:Account", u64::from(ACCOUNT_ID));
    let keys = [
        account.clone(),
        RegistryKey::new("NoSuchObject", 1),
        RegistryKey::new("Domain", 99),
        RegistryKey::new("Domain", 3),
        RegistryKey::singleton("DataStore"),
        account.clone(),
    ];
    let read = target.read_registry(&keys).await.expect("read");
    let names: Vec<Option<&str>> = read
        .iter()
        .map(|record| {
            record
                .as_ref()
                .map(|record| record.json["name"].as_str().unwrap_or(""))
        })
        .collect();
    assert_eq!(
        names,
        [
            Some("bob"),
            None,
            None,
            Some("example.org"),
            Some(""),
            Some("bob")
        ]
    );
    for (key, record) in keys.iter().zip(&read) {
        if let Some(record) = record {
            assert_eq!(&record.key, key);
        }
    }
}

// Stores, registry, mail, change log, counters and finalize round trip through the v1 APIs.
#[tokio::test(flavor = "multi_thread")]
async fn target_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;

    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
    target.prepare_store(EDITION).await.expect("prepare");
    assert!(matches!(
        target.probe().await.expect("probe"),
        TargetProbe::Initialized { .. }
    ));

    let records = registry_records();
    let outcome = target.write_registry(&records).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let keys = records.iter().map(|r| r.key.clone()).collect::<Vec<_>>();
    let read = target.read_registry(&keys).await.expect("read registry");
    let account = read[1].as_ref().expect("account");
    assert_eq!(account.json["name"], "bob");
    assert_eq!(account.json["credentials"]["0"]["secret"], "$6$salt$hash");
    let again = target
        .write_registry(&read.iter().flatten().cloned().collect::<Vec<_>>())
        .await
        .expect("rewrite");
    assert!(again.issues.is_empty(), "{:?}", again.issues);
    assert_eq!(
        target.read_registry(&keys).await.expect("read again"),
        read,
        "read_registry is stable across rewrites"
    );

    target.start_server().await.expect("server");
    let store = target.store();

    let mailboxes = RecordBatch::Mailbox(vec![
        MailboxRecord {
            document_id: 0,
            name: "Inbox".into(),
            role: Some("inbox".into()),
            uid_validity: 0xC0FFEE,
            ..Default::default()
        },
        MailboxRecord {
            document_id: 9,
            name: "Projects".into(),
            uid_validity: 77,
            acls: vec![model::AclRecord {
                account_id: 8,
                grants: 1,
            }],
            ..Default::default()
        },
    ]);
    target
        .upsert(ACCOUNT_ID, &mailboxes, WriteMode::Create)
        .await
        .expect("mailboxes");

    let mut shares = 0;
    store
        .iterate(
            store::IterateParams::new(
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::ShareNotification {
                        notification_id: 0,
                        notify_account_id: 8,
                    },
                },
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::ShareNotification {
                        notification_id: u64::MAX,
                        notify_account_id: 8,
                    },
                },
            )
            .no_values(),
            |_, _| {
                shares += 1;
                Ok(true)
            },
        )
        .await
        .expect("share notifications");
    assert_eq!(shares, 0, "import mode wrote share notifications");

    let identities = RecordBatch::Identity(vec![IdentityRecord {
        document_id: 5,
        name: "Bob".into(),
        email: "bob@example.org".into(),
        ..Default::default()
    }]);
    target
        .upsert(ACCOUNT_ID, &identities, WriteMode::Create)
        .await
        .expect("identities");

    let record = email_record();
    assert_eq!(
        target
            .blobs_exist(&[record.blob_hash])
            .await
            .expect("exists"),
        vec![false]
    );
    target
        .put_blob(&record.blob_hash, Bytes::from_static(MESSAGE))
        .await
        .expect("put blob");
    assert_eq!(
        target
            .blobs_exist(&[record.blob_hash])
            .await
            .expect("exists"),
        vec![true]
    );
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![record.clone()]),
            WriteMode::Create,
        )
        .await
        .expect("email");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    let data = store
        .get_value::<MessageData>(ValueKey::archive(ACCOUNT_ID, V1Collection::Email, 4))
        .await
        .expect("read")
        .expect("message data");
    assert_eq!(data.thread_id, 2);
    assert_eq!(data.change_id, 11);
    assert_eq!(data.message_uid(0), Some(41));
    assert_eq!(data.size as usize, MESSAGE.len() + EXTRA_HEADERS.len());
    assert!(data.keywords & (1 << SEEN) != 0 && data.keywords & (1 << FLAGGED) != 0);
    assert_eq!(data.keywords_extra, vec!["project-x".to_string()]);

    let metadata = store
        .get_value::<MetadataRow>(ValueKey {
            account_id: ACCOUNT_ID,
            collection: V1Collection::Email.into(),
            document_id: 4,
            class: ValueClass::Immutable(EmailField::Metadata.into()),
        })
        .await
        .expect("read metadata");
    let raw_headers = metadata
        .expect("metadata row")
        .raw_headers()
        .expect("raw headers")
        .into_owned();
    let header_end = MESSAGE
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header end")
        + 4;
    assert_eq!(
        raw_headers,
        [EXTRA_HEADERS, &MESSAGE[..header_end]].concat(),
        "raw headers are the v0.16 extra headers followed by the message header block"
    );

    let existing = target
        .exists(ACCOUNT_ID, Collection::Email, &[3, 4, 5])
        .await
        .expect("exists");
    assert_eq!(existing.iter().collect::<Vec<_>>(), vec![4]);

    let mut updated = record.clone();
    updated.keywords = vec!["$seen".into()];
    updated.mailboxes = vec![
        MailboxUid {
            mailbox_id: 0,
            uid: 41,
        },
        MailboxUid {
            mailbox_id: 9,
            uid: 3,
        },
    ];
    updated.change_id = 15;
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![updated]),
            WriteMode::Update,
        )
        .await
        .expect("update");
    let data = store
        .get_value::<MessageData>(ValueKey::archive(ACCOUNT_ID, V1Collection::Email, 4))
        .await
        .expect("read")
        .expect("message data");
    assert_eq!(data.change_id, 15);
    assert_eq!(data.message_uid(9), Some(3));
    assert!(data.keywords & (1 << FLAGGED) == 0 && data.keywords & (1 << SEEN) != 0);
    assert!(data.keywords_extra.is_empty());

    let before = store
        .changes(
            ACCOUNT_ID,
            V1LogCollection::Sync(SyncCollection::Email),
            Query::Since(0),
        )
        .await
        .expect("changes before");
    assert_eq!(before.to_change_id, 0, "import mode wrote change log rows");
    assert_eq!(
        store
            .get_counter(ValueKey {
                account_id: ACCOUNT_ID,
                collection: 0,
                document_id: 0,
                class: ValueClass::ChangeId(SyncCollection::Email.change_group()),
            })
            .await
            .expect("change counter"),
        0,
        "import mode allocated change ids"
    );

    let rows = vec![
        ChangeLogRecord {
            collection: LogCollection::Email,
            change_id: 11,
            entry: LogEntry::Changes(LogChanges {
                inserted_items: vec![(2u64 << 32) | 4],
                updated_containers: vec![0],
                ..Default::default()
            }),
        },
        ChangeLogRecord {
            collection: LogCollection::VanishedEmail,
            change_id: 12,
            entry: LogEntry::Vanished(VanishedRecord::Email(vec![MailboxUid {
                mailbox_id: 0,
                uid: 40,
            }])),
        },
        ChangeLogRecord {
            collection: LogCollection::Email,
            change_id: 15,
            entry: LogEntry::Changes(LogChanges {
                updated_items: vec![(2u64 << 32) | 4],
                ..Default::default()
            }),
        },
    ];
    target
        .write_changelog(ACCOUNT_ID, &rows)
        .await
        .expect("changelog");
    let changes = store
        .changes(
            ACCOUNT_ID,
            V1LogCollection::Sync(SyncCollection::Email),
            Query::Since(0),
        )
        .await
        .expect("changes");
    assert_eq!(changes.to_change_id, 15);
    assert!(!changes.is_truncated);
    let vanished = store
        .vanished::<(u32, u32)>(
            ACCOUNT_ID,
            V1LogCollection::Vanished(VanishedCollection::Email),
            Query::Since(0),
        )
        .await
        .expect("vanished");
    assert_eq!(vanished, vec![(0, 40)]);

    let mut counters = Counters {
        change_id: 15,
        mailbox_uids: vec![MailboxUid {
            mailbox_id: 0,
            uid: 45,
        }],
        ..Default::default()
    };
    counters.set_document_id(Collection::Email, 20);
    target
        .raise_counters(ACCOUNT_ID, &counters)
        .await
        .expect("counters");
    target
        .raise_counters(ACCOUNT_ID, &counters)
        .await
        .expect("counters are idempotent");
    let uid_counter = store
        .get_counter(ValueKey {
            account_id: ACCOUNT_ID,
            collection: V1Collection::Mailbox.into(),
            document_id: 0,
            class: ValueClass::MailboxUid,
        })
        .await
        .expect("uid counter");
    assert_eq!(uid_counter, 45);
    let document_counter = store
        .get_counter(ValueKey {
            account_id: ACCOUNT_ID,
            collection: V1Collection::Email.into(),
            document_id: 0,
            class: ValueClass::DocumentId,
        })
        .await
        .expect("document counter");
    assert_eq!(document_counter, 20);

    let pointers = AccountPointers {
        active_script: Pointer::Set(None),
        identity_addresses_hash: Pointer::Set(Some(42)),
        ..Default::default()
    };
    target
        .write_pointers(ACCOUNT_ID, &pointers)
        .await
        .expect("pointers");

    use email::cache::MessageCacheFetch;
    use registry::types::EnumImpl;
    let server = target.server().expect("server");
    let cache = server
        .get_cached_messages(ACCOUNT_ID)
        .await
        .expect("message cache");
    let message = cache.emails.by_id(4).expect("cached message");
    assert_eq!(message.thread_id(), 2);
    assert_eq!(message.uid_in(9), Some(3));
    let id_counter = store
        .get_counter(ValueKey::from(ValueClass::Registry(
            store::write::RegistryClass::IdCounter {
                object_id: registry::schema::prelude::ObjectType::Account.to_id(),
            },
        )))
        .await
        .expect("id counter");
    assert!(id_counter >= i64::from(ACCOUNT_ID));

    target
        .delete(ACCOUNT_ID, Collection::Email, &[4])
        .await
        .expect("delete");
    assert!(
        target
            .exists(ACCOUNT_ID, Collection::Email, &[4])
            .await
            .expect("exists")
            .is_empty()
    );
}

const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:event-1@example.org\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20300101T100000Z\r\nDTEND:20300101T110000Z\r\nSUMMARY:Planning\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:card-1@example.org\r\nFN:Carol Example\r\nEMAIL:carol@example.org\r\nEND:VCARD\r\n";
const SCRIPT: &[u8] = b"require \"fileinto\";\r\nif header :contains \"subject\" \"report\" { fileinto \"Reports\"; }\r\n";

// Calendars, events, notifications, contacts, files, sieve and the DAV finalize entry round trip through the v1 APIs.
#[tokio::test(flavor = "multi_thread")]
async fn groupware_round_trip() {
    use groupware::{
        calendar::{Calendar, CalendarEvent},
        contact::ContactCard,
        file::FileNode,
    };
    use model::{
        AddressBookRecord, CalendarEventRecord, CalendarPreferencesRecord, CalendarRecord,
        ContactRecord, DavNameRecord, DeadPropertyRecord, DeadPropertyTag, EventNotificationRecord,
        FileNodeRecord, FileRecord, SieveRecord, TimeZoneRecord,
    };
    use store::write::{Archive, ArchiveBytes};

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    target
        .write_registry(&registry_records())
        .await
        .expect("registry");
    target.start_server().await.expect("server");

    let calendars = RecordBatch::Calendar(vec![CalendarRecord {
        document_id: 2,
        name: "work".into(),
        preferences: vec![CalendarPreferencesRecord {
            account_id: ACCOUNT_ID,
            name: "Work".into(),
            color: Some("#ff0000".into()),
            time_zone: TimeZoneRecord::Iana("Europe/Madrid".into()),
            ..Default::default()
        }],
        dead_properties: DeadPropertyRecord(vec![
            DeadPropertyTag::ElementStart {
                name: "calendar-color".into(),
                attrs: Some("xmlns=\"http://apple.com/ns/ical/\"".into()),
            },
            DeadPropertyTag::Text("#FF0000FF".into()),
            DeadPropertyTag::ElementEnd,
            DeadPropertyTag::ElementStart {
                name: "notes".into(),
                attrs: Some("xmlns=\"urn:example:ns\" kind=\"plain\"".into()),
            },
            DeadPropertyTag::ElementStart {
                name: "line".into(),
                attrs: Some("xmlns=\"urn:example:ns\"".into()),
            },
            DeadPropertyTag::Text("first".into()),
            DeadPropertyTag::ElementEnd,
            DeadPropertyTag::ElementEnd,
        ]),
        created: 1_600_000_000,
        modified: 1_650_000_000,
        ..Default::default()
    }]);
    let outcome = target
        .upsert(ACCOUNT_ID, &calendars, WriteMode::Create)
        .await
        .expect("calendars");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    let events = RecordBatch::CalendarEvent(vec![CalendarEventRecord {
        document_id: 6,
        names: vec![DavNameRecord {
            name: "event-1.ics".into(),
            parent_id: 2,
        }],
        icalendar: EVENT.into(),
        created: 1_610_000_000,
        modified: 1_620_000_000,
        schedule_tag: Some(3),
        ..Default::default()
    }]);
    let outcome = target
        .upsert(ACCOUNT_ID, &events, WriteMode::Create)
        .await
        .expect("events");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    let notifications = RecordBatch::CalendarEventNotification(vec![EventNotificationRecord {
        document_id: 1,
        icalendar: EVENT.replace("VERSION:2.0\r\n", "VERSION:2.0\r\nMETHOD:REQUEST\r\n"),
        event_id: Some(6),
        created: 1_610_000_000,
        modified: 1_610_000_000,
        ..Default::default()
    }]);
    target
        .upsert(ACCOUNT_ID, &notifications, WriteMode::Create)
        .await
        .expect("notifications");

    let books = RecordBatch::AddressBook(vec![AddressBookRecord {
        document_id: 0,
        name: "default".into(),
        created: 1_600_000_000,
        modified: 1_600_000_000,
        ..Default::default()
    }]);
    target
        .upsert(ACCOUNT_ID, &books, WriteMode::Create)
        .await
        .expect("books");
    let contacts = RecordBatch::ContactCard(vec![ContactRecord {
        document_id: 3,
        names: vec![DavNameRecord {
            name: "card-1.vcf".into(),
            parent_id: 0,
        }],
        vcard: CARD.into(),
        created: 1_600_000_100,
        modified: 1_600_000_200,
        ..Default::default()
    }]);
    let outcome = target
        .upsert(ACCOUNT_ID, &contacts, WriteMode::Create)
        .await
        .expect("contacts");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    let file_bytes = b"file contents";
    let file_hash = hash(file_bytes);
    target
        .put_blob(&file_hash, Bytes::from_static(file_bytes))
        .await
        .expect("file blob");
    let files = RecordBatch::FileNode(vec![
        FileNodeRecord {
            document_id: 0,
            name: "docs".into(),
            created: 1_600_000_000,
            modified: 1_600_000_000,
            ..Default::default()
        },
        FileNodeRecord {
            document_id: 1,
            parent_id: Some(0),
            name: "notes.txt".into(),
            display_name: Some("Meeting notes".into()),
            file: Some(FileRecord {
                blob_hash: file_hash,
                size: file_bytes.len() as u32,
                media_type: Some("text/plain".into()),
                executable: false,
            }),
            created: 1_600_000_000,
            modified: 1_600_000_500,
            ..Default::default()
        },
    ]);
    target
        .upsert(ACCOUNT_ID, &files, WriteMode::Create)
        .await
        .expect("files");

    let mut sieve_blob = SCRIPT.to_vec();
    sieve_blob.extend_from_slice(b"v0.16 compiled tail");
    let sieve_hash = hash(&sieve_blob);
    target
        .put_blob(&sieve_hash, Bytes::from(sieve_blob))
        .await
        .expect("sieve blob");
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::SieveScript(vec![SieveRecord {
                document_id: 0,
                name: "filters".into(),
                blob_hash: sieve_hash,
                size: SCRIPT.len() as u32,
                vacation: None,
            }]),
            WriteMode::Create,
        )
        .await
        .expect("sieve");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target
        .write_pointers(
            ACCOUNT_ID,
            &AccountPointers {
                active_script: Pointer::Set(Some(0)),
                default_calendar: Pointer::Set(Some(2)),
                default_address_book: Pointer::Set(Some(0)),
                ..Default::default()
            },
        )
        .await
        .expect("pointers");

    let store = target.store();
    let read = |collection, document_id| async move {
        store
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                ACCOUNT_ID,
                collection,
                document_id,
            ))
            .await
            .expect("read")
            .expect("archive")
    };
    let calendar = read(V1Collection::Calendar, 2).await;
    let calendar = calendar.deserialize::<Calendar>().expect("calendar");
    assert_eq!(
        (calendar.created, calendar.modified),
        (1_600_000_000, 1_650_000_000)
    );
    assert_eq!(calendar.preferences[0].color.as_deref(), Some("#ff0000"));
    assert_ne!(
        calendar.presence, 0,
        "dead properties set the presence bits"
    );
    let server = target.server().expect("server");
    let container = server
        .metadata_container(ACCOUNT_ID, V1Collection::Calendar, 2)
        .await
        .expect("metadata")
        .expect("calendar metadata container");
    let view = container.view();
    let builder = types::metadata::MetadataBuilder::from_view(&view);
    assert!(
        builder
            .dav(&types::metadata::XmlName::borrowed(
                Some("http://apple.com/ns/ical/"),
                "calendar-color"
            ))
            .is_some()
    );
    assert!(
        builder
            .dav(&types::metadata::XmlName::borrowed(
                Some("urn:example:ns"),
                "notes"
            ))
            .is_some()
    );
    let file_container = server
        .metadata_container(ACCOUNT_ID, V1Collection::FileNode, 1)
        .await
        .expect("metadata")
        .expect("file metadata container");
    let file_view = file_container.view();
    assert!(
        types::metadata::MetadataBuilder::from_view(&file_view)
            .dav(&common::storage::dav::DISPLAY_NAME_PROPERTY)
            .is_some()
    );

    let event = read(V1Collection::CalendarEvent, 6).await;
    let event = event.deserialize::<CalendarEvent>().expect("event");
    assert_eq!(event.uid, "event-1@example.org");
    assert_eq!(event.names[0].name, "event-1.ics");
    assert_eq!(event.schedule_tag, Some(3));
    assert_eq!(
        (event.created, event.modified),
        (1_610_000_000, 1_620_000_000)
    );
    assert_ne!(event.etag, 0);

    let card = read(V1Collection::ContactCard, 3).await;
    let card = card.deserialize::<ContactCard>().expect("card");
    assert_eq!(card.uid, "card-1@example.org");
    assert_eq!(
        (card.created, card.modified),
        (1_600_000_100, 1_600_000_200)
    );

    let file = read(V1Collection::FileNode, 1).await;
    let file = file.deserialize::<FileNode>().expect("file");
    assert_eq!(file.parent_id, 1);
    assert_eq!(
        file.file().map(|file| file.size),
        Some(file_bytes.len() as u32)
    );

    let script = read(V1Collection::SieveScript, 0).await;
    let script = script
        .deserialize::<email::sieve::SieveScript>()
        .expect("script");
    assert_eq!(script.size as usize, SCRIPT.len());
    assert!(!script.script.is_empty());
    assert_eq!(script.blob_hash.0, *blake3::hash(SCRIPT).as_bytes());

    use groupware::cache::GroupwareCache;
    let resources = server
        .fetch_groupware_resources(ACCOUNT_ID, ACCOUNT_ID, SyncCollection::Calendar)
        .await
        .expect("calendar resources");
    assert!(resources.container_resource_by_id(2).is_some());
    assert!(resources.item_by_id(6).is_some());
    assert!(resources.by_path("work/event-1.ics").is_some());
    let books = server
        .fetch_groupware_resources(ACCOUNT_ID, ACCOUNT_ID, SyncCollection::AddressBook)
        .await
        .expect("address book resources");
    assert!(books.by_path("default/card-1.vcf").is_some());
    assert!(
        target
            .exists(ACCOUNT_ID, Collection::Calendar, &[0, 1, 3])
            .await
            .expect("exists")
            .is_empty(),
        "v1 created a default calendar"
    );

    let counters = Counters {
        change_id: 50,
        ..Default::default()
    };
    target
        .finalize_account(ACCOUNT_ID, &counters)
        .await
        .expect("finalize");
    let changes = store
        .changes(
            ACCOUNT_ID,
            V1LogCollection::Sync(SyncCollection::Calendar),
            Query::Since(50),
        )
        .await
        .expect("calendar changes");
    assert_eq!(changes.to_change_id, 51);
    assert_eq!(changes.changes.len(), 2, "{:?}", changes.changes);

    target
        .upsert(ACCOUNT_ID, &events, WriteMode::Replace)
        .await
        .expect("replace event");
    target
        .delete(ACCOUNT_ID, Collection::CalendarEvent, &[6])
        .await
        .expect("delete event");
    target
        .delete(ACCOUNT_ID, Collection::ContactCard, &[3])
        .await
        .expect("delete card");
    target
        .delete(ACCOUNT_ID, Collection::FileNode, &[1])
        .await
        .expect("delete file");
    for (collection, id) in [
        (Collection::CalendarEvent, 6),
        (Collection::ContactCard, 3),
        (Collection::FileNode, 1),
    ] {
        assert!(
            target
                .exists(ACCOUNT_ID, collection, &[id])
                .await
                .expect("exists")
                .is_empty(),
            "{collection} {id} still exists"
        );
    }
    target.wipe_account(ACCOUNT_ID).await.expect("wipe");
    assert!(
        target
            .exists(ACCOUNT_ID, Collection::Calendar, &[2])
            .await
            .expect("exists")
            .is_empty()
    );
}
