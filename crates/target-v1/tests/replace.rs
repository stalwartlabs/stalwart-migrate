/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::{path::Path, time::Duration};

use bytes::Bytes;
use email::message::metadata::MetadataRow;
use groupware::contact::{AddressBook, ContactCardContent};
use model::{
    AclRecord, AddressBookRecord, BlobHash, CalendarEventRecord, CalendarRecord, CategorySet,
    Collection, ContactRecord, Counters, DavNameRecord, DeadPropertyRecord, DeadPropertyTag,
    Edition, EmailRecord, MailboxRecord, MailboxUid, RecordBatch, RegistryCounter, RegistryKey,
    RegistryRecord, Target, WriteMode,
};
use registry::{schema::prelude::ObjectType, types::EnumImpl};
use serde_json::{Value, json};
use services::index_queue::manager::spawn_index_queue_manager;
use store::{
    IterateParams, Subspace, ValueKey, blake3,
    query::acl::AclQuery,
    write::{
        AnyKey, Archive, ArchiveBytes, BatchBuilder, BlobLink, BlobOp, QueueDocumentId,
        RegistryClass, SearchIndex, SearchIndexClass, ValueClass,
    },
};
use target_v1::{TargetConfig, V1Target};
use types::{
    blob_hash::BlobHash as V1BlobHash,
    collection::Collection as V1Collection,
    field::{ContactField, EmailField},
    id::Id,
};

const ACCOUNT_ID: u32 = 7;
const OTHER_ID: u32 = 8;
#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const MESSAGE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Replace\r\nMessage-ID: <r1@example.org>\r\n\r\nHello.\r\n";
const DELETED: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Deleted\r\nMessage-ID: <r2@example.org>\r\n\r\nBye.\r\n";
const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:card-1@example.org\r\nFN:Carol Example\r\nEMAIL:carol@example.org\r\nEND:VCARD\r\n";
const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:event-1@example.org\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20300101T100000Z\r\nDTEND:20300101T110000Z\r\nSUMMARY:Planning\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Reminder\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const REPLACED: u32 = 200;
const DELETED_ID: u32 = 500;
const SEARCH_INDEXES: [SearchIndex; 4] = [
    SearchIndex::Email,
    SearchIndex::Contacts,
    SearchIndex::Calendar,
    SearchIndex::File,
];

fn account(id: u32, name: &str) -> RegistryRecord {
    let mut json = json!({"@type": "User", "name": name, "domainId": Id::new(3).to_string()});
    if cfg!(feature = "enterprise")
        && let Value::Object(map) = &mut json
    {
        map.insert("memberTenantId".into(), json!(Id::new(1).to_string()));
    }
    RegistryRecord {
        key: RegistryKey::new("Account", u64::from(id)),
        json,
    }
}

async fn setup(dir: &Path) -> V1Target {
    let config = dir.join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": dir.join("data").to_string_lossy()}).to_string(),
    )
    .expect("write config");
    let target = V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target");
    target.prepare_store(EDITION).await.expect("prepare");
    let mut records = Vec::new();
    let mut domain = json!({"name": "example.org"});
    if cfg!(feature = "enterprise")
        && let Value::Object(map) = &mut domain
    {
        records.push(RegistryRecord {
            key: RegistryKey::new("Tenant", 1),
            json: json!({"name": "acme"}),
        });
        map.insert("memberTenantId".into(), json!(Id::new(1).to_string()));
    }
    records.push(RegistryRecord {
        key: RegistryKey::new("Domain", 3),
        json: domain,
    });
    records.push(account(ACCOUNT_ID, "bob"));
    records.push(account(OTHER_ID, "carol"));
    let outcome = target.write_registry(&records).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    target
}

fn hash(bytes: &[u8]) -> BlobHash {
    BlobHash(*blake3::hash(bytes).as_bytes())
}

fn email(document_id: u32, message: &[u8], uid: u32) -> EmailRecord {
    EmailRecord {
        document_id,
        thread_id: document_id,
        change_id: 11,
        received_at: 1_700_000_000,
        keywords: vec!["$seen".into()],
        mailboxes: vec![MailboxUid { mailbox_id: 0, uid }],
        blob_hash: hash(message),
        body_offset: 0,
        extra_headers: Box::default(),
        size: message.len() as u32,
    }
}

async fn queue(target: &V1Target, index: SearchIndex, account_id: u32) -> Vec<(u32, u8)> {
    let key = |document_id: u32, created_at: u64| {
        ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
            index,
            id_prefix: account_id,
            id_suffix: QueueDocumentId::Assigned(document_id),
            created_at,
        }))
    };
    let mut items = Vec::new();
    target
        .store()
        .iterate(
            IterateParams::new(key(0, 0), key(u32::MAX, u64::MAX)).ascending(),
            |key, value| {
                let document_id = key
                    .len()
                    .checked_sub(12)
                    .and_then(|start| key.get(start..start + 4))
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u32::from_be_bytes)
                    .expect("queue key");
                items.push((document_id, value.first().copied().unwrap_or(u8::MAX)));
                Ok(true)
            },
        )
        .await
        .expect("queue scan");
    items
}

async fn drain_email_queue(target: &V1Target) {
    let server = target.server().expect("server");
    spawn_index_queue_manager(server.inner.clone());
    for _ in 0..120 {
        if queue(target, SearchIndex::Email, ACCOUNT_ID)
            .await
            .is_empty()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the index queue was not drained");
}

async fn has_metadata(target: &V1Target, document_id: u32) -> bool {
    target
        .store()
        .get_value::<MetadataRow>(ValueKey {
            account_id: ACCOUNT_ID,
            collection: V1Collection::Email.into(),
            document_id,
            class: ValueClass::Immutable(EmailField::Metadata.into()),
        })
        .await
        .expect("metadata")
        .is_some()
}

async fn has_link(target: &V1Target, document_id: u32, message: &[u8]) -> bool {
    target
        .store()
        .key_exists(ValueKey {
            account_id: ACCOUNT_ID,
            collection: V1Collection::Email.into(),
            document_id,
            class: ValueClass::Blob(BlobOp::Link {
                hash: V1BlobHash(*blake3::hash(message).as_bytes()),
                to: BlobLink::Document,
            }),
        })
        .await
        .expect("link")
}

async fn counter(target: &V1Target, account_id: u32, class: ValueClass) -> i64 {
    target
        .store()
        .get_counter(ValueKey {
            account_id,
            collection: 0,
            document_id: 0,
            class,
        })
        .await
        .expect("counter")
}

async fn task_rows(target: &V1Target) -> usize {
    let key = |byte: u8| AnyKey {
        subspace: Subspace::TaskQueue,
        key: vec![byte; 40],
    };
    let mut rows = 0;
    target
        .store()
        .iterate(
            IterateParams::new(key(0), key(u8::MAX)).no_values(),
            |_, _| {
                rows += 1;
                Ok(true)
            },
        )
        .await
        .expect("task scan");
    rows
}

async fn create_inbox(target: &V1Target, account_id: u32) {
    target
        .upsert(
            account_id,
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
}

// Replaced emails keep metadata, blob link and quota after the stock index worker runs; a deleted one is unindexed.
// Many replacements in one upsert make a millisecond boundary between removal and import near certain.
#[tokio::test(flavor = "multi_thread")]
async fn email_replace_survives_index_worker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    create_inbox(&target, ACCOUNT_ID).await;
    for message in [MESSAGE, DELETED] {
        target
            .put_blob(&hash(message), Bytes::from_static(message))
            .await
            .expect("blob");
    }
    let replaced = (1..=REPLACED)
        .map(|id| email(id, MESSAGE, id))
        .collect::<Vec<_>>();
    let mut created = replaced.clone();
    created.push(email(DELETED_ID, DELETED, DELETED_ID));
    target
        .upsert(ACCOUNT_ID, &RecordBatch::Email(created), WriteMode::Create)
        .await
        .expect("create");
    let quota = counter(&target, ACCOUNT_ID, ValueClass::Quota).await;
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(replaced),
            WriteMode::Replace,
        )
        .await
        .expect("replace");
    target
        .delete(ACCOUNT_ID, Collection::Email, &[DELETED_ID])
        .await
        .expect("delete");

    let queued = queue(&target, SearchIndex::Email, ACCOUNT_ID).await;
    assert!(
        queued
            .iter()
            .all(|&(id, value)| id == DELETED_ID || value == 1),
        "{queued:?}"
    );
    assert!(queued.contains(&(DELETED_ID, 0)), "{queued:?}");

    drain_email_queue(&target).await;
    for id in 1..=REPLACED {
        assert!(has_metadata(&target, id).await, "metadata {id}");
        assert!(has_link(&target, id, MESSAGE).await, "link {id}");
    }
    assert!(!has_metadata(&target, DELETED_ID).await);
    assert!(!has_link(&target, DELETED_ID, DELETED).await);
    assert_eq!(
        target
            .exists(ACCOUNT_ID, Collection::Email, &[DELETED_ID])
            .await
            .expect("exists")
            .len(),
        0
    );
    assert_eq!(
        counter(&target, ACCOUNT_ID, ValueClass::Quota).await,
        quota - DELETED.len() as i64
    );
}

// Destroying an email removes its metadata in the same batch, so the stock index queue only drops the search document and never archives the email again (v0.16's archived copy is migrated as a registry object).
#[tokio::test(flavor = "multi_thread")]
async fn destroyed_email_is_not_left_to_the_index_queue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    create_inbox(&target, ACCOUNT_ID).await;
    target
        .put_blob(&hash(DELETED), Bytes::from_static(DELETED))
        .await
        .expect("blob");
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![email(DELETED_ID, DELETED, DELETED_ID)]),
            WriteMode::Create,
        )
        .await
        .expect("create");
    target
        .delete(ACCOUNT_ID, Collection::Email, &[DELETED_ID])
        .await
        .expect("delete");
    assert!(!has_metadata(&target, DELETED_ID).await);
    assert!(!has_link(&target, DELETED_ID, DELETED).await);
    let queued = queue(&target, SearchIndex::Email, ACCOUNT_ID).await;
    assert!(queued.contains(&(DELETED_ID, 0)), "{queued:?}");
}

// Replacing contacts and events updates them in place: no unindex is queued and old alarms are replaced.
#[tokio::test(flavor = "multi_thread")]
async fn groupware_replace_is_in_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::AddressBook(vec![AddressBookRecord {
                document_id: 0,
                name: "default".into(),
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("book");
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Calendar(vec![CalendarRecord {
                document_id: 2,
                name: "work".into(),
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("calendar");
    let contact = |vcard: &str| {
        RecordBatch::ContactCard(vec![ContactRecord {
            document_id: 3,
            names: vec![DavNameRecord {
                name: "c.vcf".into(),
                parent_id: 0,
            }],
            vcard: vcard.into(),
            ..Default::default()
        }])
    };
    let event = |icalendar: &str, dead: &str| {
        RecordBatch::CalendarEvent(vec![CalendarEventRecord {
            document_id: 6,
            names: vec![DavNameRecord {
                name: "event-1.ics".into(),
                parent_id: 2,
            }],
            icalendar: icalendar.into(),
            dead_properties: DeadPropertyRecord(vec![
                DeadPropertyTag::ElementStart {
                    name: "note".into(),
                    attrs: Some("xmlns=\"urn:example:ns\"".into()),
                },
                DeadPropertyTag::Text(dead.into()),
                DeadPropertyTag::ElementEnd,
            ]),
            ..Default::default()
        }])
    };
    target
        .upsert(ACCOUNT_ID, &contact(CARD), WriteMode::Create)
        .await
        .expect("contact");
    target
        .upsert(ACCOUNT_ID, &event(EVENT, "first"), WriteMode::Create)
        .await
        .expect("event");
    let tasks = task_rows(&target).await;
    assert!(tasks > 0);
    tokio::time::sleep(Duration::from_millis(5)).await;

    let renamed = CARD.replace("Carol Example", "Carol Renamed");
    let outcome = target
        .upsert(ACCOUNT_ID, &contact(&renamed), WriteMode::Replace)
        .await
        .expect("replace contact");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let moved = EVENT.replace("20300101T", "20300102T");
    let outcome = target
        .upsert(ACCOUNT_ID, &event(&moved, "second"), WriteMode::Replace)
        .await
        .expect("replace event");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    for index in [SearchIndex::Contacts, SearchIndex::Calendar] {
        let queued = queue(&target, index, ACCOUNT_ID).await;
        assert!(!queued.is_empty());
        assert!(
            queued.iter().all(|&(_, value)| value == 1),
            "{index:?} {queued:?}"
        );
    }
    assert_eq!(task_rows(&target).await, tasks, "stale alarm tasks remain");

    let content = target
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            ACCOUNT_ID,
            V1Collection::ContactCard,
            3,
            ContactField::Content,
        ))
        .await
        .expect("content")
        .expect("contact content");
    let card = content
        .deserialize::<ContactCardContent>()
        .expect("card")
        .card
        .to_string();
    assert!(card.contains("Carol Renamed"), "{card}");
}

// Wiping an account clears its search queues and its own ACL grants but keeps grants other owners gave it.
#[tokio::test(flavor = "multi_thread")]
async fn wipe_account_cleans_queues_and_owned_grants() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let shared_mailbox = |grantee: u32| {
        RecordBatch::Mailbox(vec![
            MailboxRecord {
                document_id: 0,
                name: "Inbox".into(),
                role: Some("inbox".into()),
                uid_validity: 1,
                ..Default::default()
            },
            MailboxRecord {
                document_id: 9,
                name: "Shared".into(),
                uid_validity: 2,
                acls: vec![AclRecord {
                    account_id: grantee,
                    grants: 1,
                }],
                ..Default::default()
            },
        ])
    };
    target
        .upsert(ACCOUNT_ID, &shared_mailbox(OTHER_ID), WriteMode::Create)
        .await
        .expect("own mailboxes");
    target
        .upsert(OTHER_ID, &shared_mailbox(ACCOUNT_ID), WriteMode::Create)
        .await
        .expect("other mailboxes");
    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![email(4, MESSAGE, 1)]),
            WriteMode::Create,
        )
        .await
        .expect("email");
    assert!(
        !queue(&target, SearchIndex::Email, ACCOUNT_ID)
            .await
            .is_empty()
    );
    #[cfg(feature = "enterprise")]
    assert_eq!(
        counter(&target, 0, ValueClass::TenantQuota(1)).await,
        MESSAGE.len() as i64
    );

    target.wipe_account(ACCOUNT_ID).await.expect("wipe");

    for index in SEARCH_INDEXES {
        assert!(
            queue(&target, index, ACCOUNT_ID).await.is_empty(),
            "{index:?}"
        );
    }
    let store = target.store();
    let granted = store
        .acl_query(AclQuery::HasAccess {
            grant_account_id: ACCOUNT_ID,
        })
        .await
        .expect("granted");
    assert_eq!(
        granted
            .iter()
            .map(|item| (item.to_account_id, item.to_document_id))
            .collect::<Vec<_>>(),
        [(OTHER_ID, 9)]
    );
    assert!(
        store
            .acl_query(AclQuery::HasAccess {
                grant_account_id: OTHER_ID,
            })
            .await
            .expect("owned")
            .is_empty()
    );
    assert!(
        target
            .exists(ACCOUNT_ID, Collection::Mailbox, &[0, 9])
            .await
            .expect("exists")
            .is_empty()
    );
    assert_eq!(counter(&target, ACCOUNT_ID, ValueClass::Quota).await, 0);
    #[cfg(feature = "enterprise")]
    assert_eq!(counter(&target, 0, ValueClass::TenantQuota(1)).await, 0);
}

// Registry id counters are raised to at least the source value, never lowered, and unknown or non-sequential types are ignored.
#[tokio::test(flavor = "multi_thread")]
async fn registry_counters_raise_at_least() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let read = || async {
        target
            .store()
            .get_counter(ValueKey::from(ValueClass::Registry(
                RegistryClass::IdCounter {
                    object_id: ObjectType::Account.to_id(),
                },
            )))
            .await
            .expect("counter")
    };
    assert_eq!(read().await, i64::from(OTHER_ID));
    let raise = |value: u64| {
        [
            RegistryCounter {
                object: "Account".into(),
                value,
            },
            RegistryCounter {
                object: "NoSuchObject".into(),
                value: 99,
            },
        ]
    };
    target
        .raise_registry_counters(&raise(40))
        .await
        .expect("raise");
    assert_eq!(read().await, 40);
    target
        .raise_registry_counters(&raise(12))
        .await
        .expect("lower");
    assert_eq!(read().await, 40);
}

// Finalize recalculates the account quota and, on enterprise builds, the tenant quota from the stored data.
#[tokio::test(flavor = "multi_thread")]
async fn finalize_recalculates_quota() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    create_inbox(&target, ACCOUNT_ID).await;
    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![email(4, MESSAGE, 1)]),
            WriteMode::Create,
        )
        .await
        .expect("email");
    let quota = counter(&target, ACCOUNT_ID, ValueClass::Quota).await;
    assert!(quota >= MESSAGE.len() as i64);
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ACCOUNT_ID)
        .add(ValueClass::Quota, 1000);
    #[cfg(feature = "enterprise")]
    batch.add(ValueClass::TenantQuota(1), 1000);
    target.store().write_batch(&mut batch).await.expect("skew");

    target
        .finalize_account(ACCOUNT_ID, &Counters::default())
        .await
        .expect("finalize account");
    assert_eq!(counter(&target, ACCOUNT_ID, ValueClass::Quota).await, quota);
    target
        .finalize_store(CategorySet::default())
        .await
        .expect("finalize store");
    #[cfg(feature = "enterprise")]
    assert_eq!(counter(&target, 0, ValueClass::TenantQuota(1)).await, quota);
}

// A nested dead property as v0.16 stores it keeps its element tree; only the attribute whose prefix v0.16 lost is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn nested_dead_property_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let start = |name: &str, attrs: &str| DeadPropertyTag::ElementStart {
        name: name.into(),
        attrs: (!attrs.is_empty()).then(|| attrs.into()),
    };
    let tags = vec![
        start("nested", "xmlns=\"urn:example:a\" xml:lang=\"fr\""),
        start(
            "child",
            "xmlns=\"urn:example:a\" B:attr=\"v\" plain=\"a &amp; b\" xml:lang=\"de\"",
        ),
        DeadPropertyTag::Text("texte".into()),
        DeadPropertyTag::ElementEnd,
        start("empty", "xmlns=\"urn:example:a\""),
        DeadPropertyTag::ElementEnd,
        start("leaf", "xmlns=\"\""),
        DeadPropertyTag::Text("reset".into()),
        DeadPropertyTag::ElementEnd,
        DeadPropertyTag::ElementEnd,
    ];
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Calendar(vec![CalendarRecord {
                document_id: 2,
                name: "work".into(),
                dead_properties: DeadPropertyRecord(tags),
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("calendar");
    let messages = outcome
        .issues
        .iter()
        .map(|issue| issue.message.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [
            "dead property {urn:example:a}nested: attribute B:attr was dropped, v0.16 did not store the namespace of its prefix"
        ]
    );
}

// A draft event gets no alarm task, as in stock v1.
#[tokio::test(flavor = "multi_thread")]
async fn draft_event_has_no_alarm_task() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Calendar(vec![CalendarRecord {
                document_id: 2,
                name: "work".into(),
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("calendar");
    let before = task_rows(&target).await;
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::CalendarEvent(vec![CalendarEventRecord {
                document_id: 6,
                names: vec![DavNameRecord {
                    name: "event-1.ics".into(),
                    parent_id: 2,
                }],
                icalendar: EVENT.into(),
                flags: groupware::calendar::EVENT_DRAFT,
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("event");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(task_rows(&target).await, before, "draft got an alarm task");
}

// Several counters for one object type raise it to their maximum, not to their sum.
#[tokio::test(flavor = "multi_thread")]
async fn registry_counters_take_max_per_type() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let counters = [40, 50, 45].map(|value| RegistryCounter {
        object: "Account".into(),
        value,
    });
    target
        .raise_registry_counters(&counters)
        .await
        .expect("raise");
    let value = target
        .store()
        .get_counter(ValueKey::from(ValueClass::Registry(
            RegistryClass::IdCounter {
                object_id: ObjectType::Account.to_id(),
            },
        )))
        .await
        .expect("counter");
    assert_eq!(value, 50);
}

// v0.16 keeps a single-quoted attribute value raw between double quotes; the quote inside it does not end the value.
#[tokio::test(flavor = "multi_thread")]
async fn dead_attribute_value_with_quote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Calendar(vec![CalendarRecord {
                document_id: 2,
                name: "work".into(),
                dead_properties: DeadPropertyRecord(vec![
                    DeadPropertyTag::ElementStart {
                        name: "note".into(),
                        attrs: Some(
                            "xmlns=\"urn:example:a\" title=\"say \"hi\" now\" kind=\"plain\""
                                .into(),
                        ),
                    },
                    DeadPropertyTag::Text("body".into()),
                    DeadPropertyTag::ElementEnd,
                ]),
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("calendar");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let container = target
        .server()
        .expect("server")
        .metadata_container(ACCOUNT_ID, V1Collection::Calendar, 2)
        .await
        .expect("metadata")
        .expect("container");
    let view = container.view();
    let builder = types::metadata::MetadataBuilder::from_view(&view);
    let value = builder
        .dav(&types::metadata::XmlName::borrowed(
            Some("urn:example:a"),
            "note",
        ))
        .expect("note property")
        .as_bytes();
    let contains = |needle: &[u8]| value.windows(needle.len()).any(|window| window == needle);
    assert!(contains(b"say \"hi\" now"), "{value:?}");
    assert!(contains(b"plain"), "{value:?}");
}

// BlobStore::has_blob reports stored blobs without reading them whole.
#[tokio::test(flavor = "multi_thread")]
async fn blob_store_has_blob() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    let blobs = target.server().expect("server").blob_store();
    assert!(blobs.has_blob(&hash(MESSAGE).0).await.expect("present"));
    assert!(!blobs.has_blob(&hash(DELETED).0).await.expect("absent"));
}

// A message body passed in the blob cache is imported without reading the blob store; uncached bodies still come from the store.
#[tokio::test(flavor = "multi_thread")]
async fn cached_email_body_skips_blob_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    create_inbox(&target, ACCOUNT_ID).await;
    target
        .put_blob(&hash(DELETED), Bytes::from_static(DELETED))
        .await
        .expect("blob");
    let cache = model::BlobCache::from_entries(vec![(hash(MESSAGE), Bytes::from_static(MESSAGE))]);
    for mode in [WriteMode::Create, WriteMode::Replace] {
        let outcome = target
            .upsert_with_blobs(
                ACCOUNT_ID,
                &RecordBatch::Email(vec![email(1, MESSAGE, 1), email(2, DELETED, 2)]),
                mode,
                &cache,
            )
            .await
            .expect("upsert");
        assert!(outcome.issues.is_empty(), "{mode:?}: {:?}", outcome.issues);
        assert!(has_metadata(&target, 1).await);
        assert!(has_metadata(&target, 2).await);
        assert!(has_link(&target, 1, MESSAGE).await);
    }
    let missing = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![email(3, MESSAGE, 3)]),
            WriteMode::Create,
        )
        .await
        .expect("upsert");
    assert_eq!(missing.issues.len(), 1, "{:?}", missing.issues);
}

// A keyword longer than Email.maxFlagLength (128 bytes by default) is dropped with an explained issue; one at the limit is kept.
#[tokio::test(flavor = "multi_thread")]
async fn long_keyword_is_dropped_with_issue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    create_inbox(&target, ACCOUNT_ID).await;
    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    let long = "k".repeat(129);
    let kept = "k".repeat(128);
    let mut record = email(1, MESSAGE, 1);
    record.keywords = vec![long.as_str().into(), kept.as_str().into()];
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Email(vec![record]),
            WriteMode::Create,
        )
        .await
        .expect("create");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    let issue = &outcome.issues[0];
    assert_eq!(issue.kind, model::IssueKind::Dropped);
    assert_eq!(
        issue.explains,
        Some(model::Explanation::Keyword(long.as_str().into()))
    );
    let data = target
        .store()
        .get_value::<email::message::messagedata::MessageData>(ValueKey::archive(
            ACCOUNT_ID,
            V1Collection::Email,
            1,
        ))
        .await
        .expect("read")
        .expect("message data");
    assert_eq!(data.keywords_extra, vec![kept]);
}

// An address book share with v0.16 mayWrite but not mayDelete keeps its bits and is reported once.
#[tokio::test(flavor = "multi_thread")]
async fn address_book_write_share_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let write_only = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5);
    let write_and_delete = write_only | (1 << 2) | (1 << 6);
    let outcome = target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::AddressBook(vec![AddressBookRecord {
                document_id: 0,
                name: "default".into(),
                acls: vec![
                    AclRecord {
                        account_id: OTHER_ID,
                        grants: write_only,
                    },
                    AclRecord {
                        account_id: 9,
                        grants: write_and_delete,
                    },
                ],
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("book");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    let issue = &outcome.issues[0];
    assert_eq!(issue.severity, model::Severity::Warning);
    assert_eq!(issue.kind, model::IssueKind::Changed);
    assert!(
        issue.message.contains(&format!("account {OTHER_ID}"))
            && issue.message.contains("mayWrite"),
        "{}",
        issue.message
    );
    let book = target
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            ACCOUNT_ID,
            V1Collection::AddressBook,
            0,
        ))
        .await
        .expect("read")
        .expect("address book")
        .deserialize::<AddressBook>()
        .expect("deserialize");
    let grants = book
        .acls
        .iter()
        .map(|grant| (grant.account_id, grant.grants.bitmap))
        .collect::<Vec<_>>();
    assert_eq!(grants, vec![(OTHER_ID, write_only), (9, write_and_delete)]);
}

// A deferred second write of an account in the same page applies after the records that depend on the first one.
#[tokio::test(flavor = "multi_thread")]
async fn registry_duplicate_keys_apply_in_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let stripped = account(9, "dave");
    let mut full = account(9, "dave");
    if let Value::Object(map) = &mut full.json {
        map.insert(
            "encryptionAtRest".into(),
            json!({
                "@type": "Aes256",
                "publicKey": Id::new(5).to_string(),
                "encryptOnAppend": true,
                "allowSpamTraining": false
            }),
        );
    }
    let key = RegistryRecord {
        key: RegistryKey::new("PublicKey", 5),
        json: json!({
            "accountId": Id::new(9).to_string(),
            "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "description": "dave",
            "createdAt": "2026-01-01T00:00:00Z"
        }),
    };
    let outcome = target
        .write_registry(&[stripped, key, full])
        .await
        .expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let stored = target
        .read_registry(&[RegistryKey::new("Account", 9)])
        .await
        .expect("read")
        .pop()
        .flatten()
        .expect("account");
    assert_eq!(
        stored.json["encryptionAtRest"]["publicKey"],
        json!(Id::new(5).to_string()),
        "{}",
        stored.json
    );
}

// The same registry key twice in one page is applied in order, the last write wins and the unique names it replaced are released.
#[tokio::test(flavor = "multi_thread")]
async fn registry_duplicate_key_last_write_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let domain = |id: u64, name: &str| RegistryRecord {
        key: RegistryKey::new("Domain", id),
        json: json!({"name": name}),
    };
    let stored_name = async |id: u64| {
        target
            .read_registry(&[RegistryKey::new("Domain", id)])
            .await
            .expect("read")
            .pop()
            .flatten()
            .expect("domain")
            .json["name"]
            .clone()
    };
    for page in [
        &[domain(4, "first.example"), domain(4, "second.example")][..],
        &[domain(5, "first.example")],
        &[
            domain(8, "a.example"),
            domain(8, "b.example"),
            domain(8, "c.example"),
            domain(8, "a.example"),
        ],
        &[domain(9, "b.example"), domain(10, "c.example")],
    ] {
        let outcome = target.write_registry(page).await.expect("registry");
        assert!(outcome.issues.is_empty(), "{page:?}: {:?}", outcome.issues);
    }
    for (id, name) in [
        (4, "second.example"),
        (5, "first.example"),
        (8, "a.example"),
        (9, "b.example"),
        (10, "c.example"),
    ] {
        assert_eq!(stored_name(id).await, name, "Domain {id}");
    }
}

// Retaining share notifications deletes only the listed account's notifications missing from the keep list.
#[tokio::test(flavor = "multi_thread")]
async fn retain_share_notifications_deletes_only_stale() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let notifications = |ids: &[u64]| {
        ids.iter()
            .map(|id| model::ShareNotificationRecord {
                id: *id,
                payload: vec![*id as u8; 4].into(),
            })
            .collect::<Vec<_>>()
    };
    target
        .write_share_notifications(ACCOUNT_ID, &notifications(&[1, 2, 3]))
        .await
        .expect("own");
    target
        .write_share_notifications(OTHER_ID, &notifications(&[2]))
        .await
        .expect("other");
    target
        .retain_share_notifications(ACCOUNT_ID, &[1, 3, 9])
        .await
        .expect("retain");
    target
        .retain_share_notifications(ACCOUNT_ID, &[1, 3])
        .await
        .expect("retain again");
    for (account_id, id, present) in [
        (ACCOUNT_ID, 1, true),
        (ACCOUNT_ID, 2, false),
        (ACCOUNT_ID, 3, true),
        (OTHER_ID, 2, true),
    ] {
        let value = target
            .store()
            .key_exists(ValueKey::from(ValueClass::ShareNotification {
                notification_id: id,
                notify_account_id: account_id,
            }))
            .await
            .expect("read");
        assert_eq!(value, present, "account {account_id} notification {id}");
    }
}

// Registry write rejections carry their cause: a primary key conflict is Conflict, an object that does not parse or validate is Invalid.
#[tokio::test(flavor = "multi_thread")]
async fn registry_rejections_are_tagged() {
    use model::Rejection;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = setup(dir.path()).await;
    let domain = |id: u64, name: serde_json::Value| RegistryRecord {
        key: model::RegistryKey::new("Domain", id),
        json: serde_json::json!({"name": name}),
    };
    let outcome = target
        .write_registry(&[domain(20, "dup.example".into())])
        .await
        .expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    for (record, rejection) in [
        (domain(21, "dup.example".into()), Rejection::Conflict),
        (domain(22, 5.into()), Rejection::Invalid),
        (domain(23, "".into()), Rejection::Invalid),
    ] {
        let outcome = target
            .write_registry(std::slice::from_ref(&record))
            .await
            .expect("registry");
        assert_eq!(
            outcome
                .issues
                .iter()
                .map(|issue| issue.rejection)
                .collect::<Vec<_>>(),
            vec![Some(rejection)],
            "{}: {:?}",
            record.json,
            outcome.issues
        );
    }
}
