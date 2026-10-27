/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use calcard::{common::timezone::Tz, icalendar::ICalendar, vcard::VCard};
use common::{
    DavName,
    auth::credential::{ApiKey, AppPassword},
    config::{
        mailstore::spamfilter::SpamClassifier,
        smtp::queue::{QueueExpiry, QueueName},
    },
    manager::SPAM_CLASSIFIER_KEY,
};
use directory::core::secret::hash_secret;
use email::{
    identity::Identity,
    mailbox::{Mailbox, UidMailbox},
    message::metadata::{MESSAGE_HAS_ATTACHMENT, MessageData, MessageMetadata},
    push::{PushSubscription, PushSubscriptions},
    sieve::SieveScript,
    submission::EmailSubmission,
};
use groupware::{
    calendar::{
        Calendar, CalendarEvent, CalendarEventData, CalendarPreferences, ParticipantIdentities,
        ParticipantIdentity, Timezone,
    },
    contact::{AddressBook, ContactCard},
    file::{FileNode, FileProperties},
};
use nlp::classifier::{ftrl::Ftrl, train::FhTrainer};
use registry::{
    schema::{
        enums::{CompressionAlgo, PasswordHashAlgorithm},
        prelude::{OBJ_SINGLETON, ObjectInner, ObjectType},
        structs::{self, DataStore},
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, list::List, map::Map},
};
use smtp::queue::{Message, Metadata, Recipient, Schedule, Status};

use crate::SCHEMA_VERSION;
use store::{
    BlobStore, SUBSPACE_PROPERTY, Serialize, SerializeInfallible, Store, rkyv,
    write::{
        AnyClass, Archiver, BatchBuilder, IndexPropertyClass, QueueClass, RegistryClass,
        TelemetryClass, ValueClass,
    },
};
use types::{
    acl::{Acl, AclGrant},
    blob_hash::BlobHash,
    collection::{Collection as V016Collection, SyncCollection, VanishedCollection},
    dead_property::{DeadElementTag, DeadProperty, DeadPropertyTag as V016Tag},
    field::{EmailField, EmailSubmissionField, Field, MailboxField, PrincipalField},
    id::Id,
    keyword::Keyword,
    special_use::SpecialUse,
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

pub const ACCOUNT: u32 = 7;
const CALENDAR_COLOR_ATTRS: &str =
    "xmlns=\"http://apple.com/ns/ical/\" xml:lang=\"en\" note=\"a &amp; b\"";
const MAX_OBJECT_ID: u16 = 1024;
const BROAD_ITEM_ID: u64 = 100;
pub const DOMAIN_ID: u64 = 5;
pub const ACCOUNT_SECRET: &str = "$6$saltsalt$hashhashhash";
pub const BLOB: &[u8] = b"Subject: hello\r\nFrom: a@example.org\r\n\r\nbody text\r\n";
pub const EXTRA: &[u8] = b"Delivered-To: user@example.org\r\n";
pub const BODY_OFFSET: u32 = 39;
pub const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:1\r\nDTSTART:20260101T100000Z\r\nSUMMARY:Meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
pub const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Jane Doe\r\nUID:card-1\r\nEND:VCARD\r\n";

pub const SUBMISSION_SEND_AT: u64 = 1_700_000_100;

pub fn submission_index(send_at: u64) -> ValueClass {
    ValueClass::IndexProperty(IndexPropertyClass::Integer {
        property: EmailSubmissionField::Metadata.into(),
        value: send_at,
    })
}

pub fn rocks(path: &Path) -> DataStore {
    DataStore::RocksDb(structs::RocksDbStore {
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    })
}

pub fn archive<T>(value: T) -> Vec<u8>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    Archiver::new(value).serialize().expect("serialize")
}

fn versioned<T>(value: T, change_id: u64) -> Vec<u8>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    let (offset, mut bytes) = Archiver::new(value)
        .serialize_versioned()
        .expect("serialize");
    let offset = usize::try_from(offset).expect("offset");
    bytes[offset..offset + 8].copy_from_slice(&change_id.to_be_bytes());
    bytes
}

fn tz_id(name: &str) -> u16 {
    (0..2048u16)
        .find(|id| {
            Tz::from_id(*id)
                .and_then(|tz| tz.name())
                .is_some_and(|tz| tz == name)
        })
        .expect("time zone")
}

pub async fn commit(store: &Store, build: impl FnOnce(&mut BatchBuilder)) {
    let mut batch = BatchBuilder::new();
    batch.with_account_id(ACCOUNT);
    build(&mut batch);
    store.write(batch.build_all()).await.expect("write");
}

async fn write_schema_version(store: &Store) {
    let mut schema = BatchBuilder::new();
    schema.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0],
        }),
        SCHEMA_VERSION.serialize(),
    );
    store
        .write(schema.build_all())
        .await
        .expect("schema version");
}

pub async fn create_empty_rocksdb(path: &Path) {
    Store::build(rocks(path))
        .await
        .expect("open writable store");
}

pub async fn create_store(config: &Path) {
    let config = crate::SourceConfig::from_file(config).expect("store config");
    let store = Store::build(config.data_store)
        .await
        .expect("open writable store");
    store.create_tables().await.expect("tables");
    write_schema_version(&store).await;
}

pub async fn seed(path: &Path) {
    seed_with_extra_headers(path, EXTRA).await;
}

pub async fn seed_with_extra_headers(path: &Path, extra: &[u8]) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    write_schema_version(&store).await;
    let blobs = BlobStore::Store(store.clone());
    let hash = BlobHash(*store::blake3::hash(BLOB).as_bytes());
    blobs
        .put_blob(hash.as_slice(), BLOB, CompressionAlgo::Lz4)
        .await
        .expect("blob");

    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Mailbox)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(Mailbox {
                    name: "Inbox".into(),
                    role: SpecialUse::Inbox,
                    parent_id: 0,
                    sort_order: Some(1),
                    uid_validity: 4242,
                    subscribers: vec![ACCOUNT],
                    acls: vec![AclGrant {
                        account_id: 9,
                        grants: Bitmap::from(vec![Acl::Read, Acl::ReadItems]),
                    }],
                }),
            )
            .log_container_insert(SyncCollection::Email)
            .add(ValueClass::DocumentId, 3);
    })
    .await;
    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Mailbox)
            .with_document(3)
            .set(
                Field::ARCHIVE,
                archive(Mailbox {
                    name: "Work".into(),
                    role: SpecialUse::None,
                    parent_id: 1,
                    sort_order: None,
                    uid_validity: 7,
                    subscribers: vec![],
                    acls: vec![],
                }),
            )
            .log_container_insert(SyncCollection::Email);
    })
    .await;

    let mut raw_headers = extra.to_vec();
    raw_headers.extend_from_slice(&BLOB[..BODY_OFFSET as usize]);
    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Mailbox)
            .with_document(0)
            .add(MailboxField::UidCounter, 5)
            .with_collection(V016Collection::Email)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                versioned(
                    MessageData {
                        mailboxes: vec![UidMailbox {
                            mailbox_id: 0,
                            uid: 1,
                        }]
                        .into_boxed_slice(),
                        keywords: vec![Keyword::Seen, Keyword::Other("$custom".into())]
                            .into_boxed_slice(),
                        thread_id: 0,
                        size: (extra.len() + BLOB.len()) as u32,
                    },
                    3,
                ),
            )
            .set(
                EmailField::Metadata,
                archive(MessageMetadata {
                    contents: Box::default(),
                    rcvd_attach: 1_700_000_000 | MESSAGE_HAS_ATTACHMENT,
                    blob_hash: hash.clone(),
                    blob_body_offset: BODY_OFFSET,
                    preview: "body".into(),
                    raw_headers: raw_headers.into_boxed_slice(),
                }),
            )
            .log_item_insert(SyncCollection::Email, Some(0))
            .add(ValueClass::DocumentId, 1);
    })
    .await;

    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::SieveScript)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(SieveScript {
                    name: "main".into(),
                    blob_hash: hash.clone(),
                    size: 10,
                    vacation_response: None,
                }),
            )
            .log_item_insert(SyncCollection::SieveScript, None)
            .with_collection(V016Collection::Identity)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(Identity {
                    name: "Jane".into(),
                    email: "jane@example.org".into(),
                    ..Default::default()
                }),
            )
            .log_item_insert(SyncCollection::Identity, None)
            .with_collection(V016Collection::EmailSubmission)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(EmailSubmission {
                    email_id: 0,
                    identity_id: 0,
                    send_at: SUBMISSION_SEND_AT,
                    ..Default::default()
                }),
            )
            .set(submission_index(SUBMISSION_SEND_AT), Vec::new())
            .log_item_insert(SyncCollection::EmailSubmission, None)
            .with_collection(V016Collection::Principal)
            .with_document(0)
            .set(PrincipalField::ActiveScriptId, 0u32.to_be_bytes().to_vec())
            .set(
                PrincipalField::DefaultCalendarId,
                0u32.to_be_bytes().to_vec(),
            )
            .set(
                PrincipalField::ParticipantIdentities,
                archive(ParticipantIdentities {
                    identities: vec![ParticipantIdentity {
                        id: 1,
                        name: Some("Jane".into()),
                        calendar_address: "mailto:jane@example.org".into(),
                    }],
                    default_name: "Jane".into(),
                    default: 1,
                }),
            )
            .set(
                PrincipalField::PushSubscriptions,
                archive(PushSubscriptions {
                    subscriptions: vec![PushSubscription {
                        id: 2,
                        url: "https://push.example.org/x".into(),
                        expires: 1_800_000_000,
                        verified: true,
                        types: Bitmap::new()
                            .with_item(DataType::Mailbox)
                            .with_item(DataType::Email)
                            .with_item(DataType::CalendarEvent),
                        ..Default::default()
                    }],
                }),
            );
    })
    .await;

    let event = ICalendar::parse(EVENT).expect("event");
    let card = VCard::parse(CARD).expect("card");
    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Calendar)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(Calendar {
                    name: "default".into(),
                    preferences: vec![CalendarPreferences {
                        account_id: ACCOUNT,
                        name: "Default".into(),
                        time_zone: Timezone::IANA(tz_id("Europe/Madrid")),
                        ..Default::default()
                    }],
                    dead_properties: DeadProperty(vec![
                        V016Tag::ElementStart(DeadElementTag {
                            name: "X:color".into(),
                            attrs: None,
                        }),
                        V016Tag::Text("red".into()),
                        V016Tag::ElementEnd,
                        V016Tag::ElementStart(DeadElementTag {
                            name: "calendar-color".into(),
                            attrs: Some(CALENDAR_COLOR_ATTRS.into()),
                        }),
                        V016Tag::Text("#FF0000".into()),
                        V016Tag::ElementEnd,
                    ]),
                    created: 10,
                    modified: 20,
                    ..Default::default()
                }),
            )
            .log_container_insert(SyncCollection::Calendar)
            .with_collection(V016Collection::CalendarEvent)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(CalendarEvent {
                    names: vec![DavName {
                        name: "meeting.ics".into(),
                        parent_id: 0,
                    }],
                    data: CalendarEventData {
                        event,
                        ..Default::default()
                    },
                    size: EVENT.len() as u32,
                    created: 30,
                    modified: 40,
                    schedule_tag: Some(2),
                    ..Default::default()
                }),
            )
            .log_item_insert(SyncCollection::Calendar, None)
            .with_collection(V016Collection::AddressBook)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(AddressBook {
                    name: "contacts".into(),
                    ..Default::default()
                }),
            )
            .log_container_insert(SyncCollection::AddressBook)
            .with_collection(V016Collection::ContactCard)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(ContactCard {
                    names: vec![DavName {
                        name: "jane.vcf".into(),
                        parent_id: 0,
                    }],
                    card,
                    size: CARD.len() as u32,
                    ..Default::default()
                }),
            )
            .log_item_insert(SyncCollection::AddressBook, None)
            .with_collection(V016Collection::FileNode)
            .with_document(0)
            .set(
                Field::ARCHIVE,
                archive(FileNode {
                    parent_id: 0,
                    name: "docs".into(),
                    ..Default::default()
                }),
            )
            .log_container_insert(SyncCollection::FileNode)
            .with_document(1)
            .set(
                Field::ARCHIVE,
                archive(FileNode {
                    parent_id: 1,
                    name: "a.txt".into(),
                    file: Some(FileProperties {
                        blob_hash: hash.clone(),
                        size: BLOB.len() as u32,
                        media_type: Some("text/plain".into()),
                        executable: false,
                    }),
                    ..Default::default()
                }),
            )
            .log_item_insert(SyncCollection::FileNode, None);
    })
    .await;

    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Email)
            .with_document(0)
            .log_item_update(SyncCollection::Email, Some(0))
            .with_collection(V016Collection::Mailbox)
            .with_document(3)
            .clear(Field::ARCHIVE)
            .log_container_delete(SyncCollection::Email)
            .log_vanished_item(VanishedCollection::Email, (0u32, 1u32))
            .set(
                ValueClass::ShareNotification {
                    notification_id: 1 << 60,
                    notify_account_id: ACCOUNT,
                },
                vec![1, 2, 3],
            );
    })
    .await;

    let mut batch = BatchBuilder::new();
    batch
        .set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::Domain.to_id(),
                item_id: DOMAIN_ID,
            }),
            ObjectInner::Domain(structs::Domain {
                name: "example.org".into(),
                ..Default::default()
            })
            .to_pickled_vec(),
        )
        .set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::Http.to_id(),
                item_id: Id::singleton().id(),
            }),
            ObjectInner::Http(structs::Http::default()).to_pickled_vec(),
        );
    let mut credentials = List::default();
    credentials.push(structs::Credential::Password(structs::PasswordCredential {
        credential_id: Id::new(0),
        secret: ACCOUNT_SECRET.into(),
        ..Default::default()
    }));
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: u64::from(ACCOUNT),
        }),
        ObjectInner::Account(structs::Account::User(structs::UserAccount {
            name: "jane".into(),
            domain_id: Id::new(DOMAIN_ID),
            credentials,
            ..Default::default()
        }))
        .to_pickled_vec(),
    );
    store.write(batch.build_all()).await.expect("registry");
}

pub const BULK_FIRST_ID: u32 = 1000;
const BULK_COMMIT: u32 = 200;

pub async fn seed_bulk_emails(path: &Path, count: u32) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let blobs = BlobStore::Store(store.clone());
    let mut first = 0;
    while first < count {
        let last = (first + BULK_COMMIT).min(count);
        let mut messages = Vec::with_capacity((last - first) as usize);
        for index in first..last {
            let header = format!(
                "Subject: bulk {index}\r\nFrom: a@example.org\r\nMessage-ID: <{index}@example.org>\r\n\r\n"
            );
            let raw = format!("{header}body {index}\r\n").into_bytes();
            let hash = BlobHash(*store::blake3::hash(&raw).as_bytes());
            blobs
                .put_blob(hash.as_slice(), &raw, CompressionAlgo::Lz4)
                .await
                .expect("blob");
            messages.push((index, header.len() as u32, raw, hash));
        }
        commit(&store, |batch| {
            batch
                .with_collection(V016Collection::Mailbox)
                .with_document(0)
                .add(MailboxField::UidCounter, i64::from(last - first));
            for (index, body_offset, raw, hash) in &messages {
                let mut raw_headers = EXTRA.to_vec();
                raw_headers.extend_from_slice(&raw[..*body_offset as usize]);
                batch
                    .with_collection(V016Collection::Email)
                    .with_document(BULK_FIRST_ID + index)
                    .set(
                        Field::ARCHIVE,
                        versioned(
                            MessageData {
                                mailboxes: vec![UidMailbox {
                                    mailbox_id: 0,
                                    uid: 10 + index,
                                }]
                                .into_boxed_slice(),
                                keywords: vec![Keyword::Seen].into_boxed_slice(),
                                thread_id: BULK_FIRST_ID + index / 3,
                                size: (EXTRA.len() + raw.len()) as u32,
                            },
                            3,
                        ),
                    )
                    .set(
                        EmailField::Metadata,
                        archive(MessageMetadata {
                            contents: Box::default(),
                            rcvd_attach: 1_700_000_000 + u64::from(*index),
                            blob_hash: hash.clone(),
                            blob_body_offset: *body_offset,
                            preview: "body".into(),
                            raw_headers: raw_headers.into_boxed_slice(),
                        }),
                    )
                    .log_item_insert(SyncCollection::Email, Some(BULK_FIRST_ID + index / 3))
                    .add(ValueClass::DocumentId, 1);
            }
        })
        .await;
        first = last;
    }
}

pub async fn register_account(store: &Store, account_id: u32) {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: u64::from(account_id),
        }),
        ObjectInner::Account(structs::Account::User(structs::UserAccount {
            name: format!("user{account_id}"),
            domain_id: Id::new(DOMAIN_ID),
            ..Default::default()
        }))
        .to_pickled_vec(),
    );
    store
        .write(batch.build_all())
        .await
        .expect("register account");
}

pub async fn seed_every_registry_type(path: &Path, skip: &[&str]) -> Vec<ObjectType> {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let empty = serde_json::Value::Object(Default::default());
    let mut written = Vec::new();
    let mut batch = BatchBuilder::new();
    for id in 0..MAX_OBJECT_ID {
        let Some(object_type) = ObjectType::from_id(id) else {
            continue;
        };
        if skip.contains(&object_type.as_str())
            || matches!(
                object_type,
                ObjectType::Account | ObjectType::Domain | ObjectType::Http
            )
        {
            continue;
        }
        let Ok(inner) = ObjectInner::deserialize(object_type, &empty) else {
            continue;
        };
        let item_id = if object_type.flags() & OBJ_SINGLETON != 0 {
            Id::singleton().id()
        } else {
            BROAD_ITEM_ID
        };
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: object_type.to_id(),
                item_id,
            }),
            inner.to_pickled_vec(),
        );
        written.push(object_type);
    }
    store.write(batch.build_all()).await.expect("registry");
    written
}

pub async fn seed_registry_object(
    path: &Path,
    object: &str,
    item_id: u64,
    json: &serde_json::Value,
) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let object_type = ObjectType::parse(object).expect("object type");
    let inner = ObjectInner::deserialize(object_type, json).expect("valid object");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: object_type.to_id(),
            item_id,
        }),
        inner.to_pickled_vec(),
    );
    store.write(batch.build_all()).await.expect("registry");
}

pub async fn remove_registry_object(path: &Path, object: &str, item_id: u64) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let object_type = ObjectType::parse(object).expect("object type");
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Registry(RegistryClass::Item {
        object_id: object_type.to_id(),
        item_id,
    }));
    store.write(batch.build_all()).await.expect("registry");
}

pub async fn remove_identity(path: &Path, document_id: u32) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Identity)
            .with_document(document_id)
            .clear(Field::ARCHIVE);
    })
    .await;
}

pub async fn rename_identity(path: &Path, document_id: u32, name: &str) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    commit(&store, |batch| {
        batch
            .with_collection(V016Collection::Identity)
            .with_document(document_id)
            .set(
                Field::ARCHIVE,
                archive(Identity {
                    name: name.into(),
                    email: "jane@example.org".into(),
                    ..Default::default()
                }),
            )
            .log_item_update(SyncCollection::Identity, None);
    })
    .await;
}

pub const PASSWORD: &str = "main-password";
pub const OTP_URL: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
const APP_PASSWORD_ID: u32 = 1;
const API_KEY_ID: u32 = 2;
const CREDENTIAL_CREATED_AT: i64 = 1_700_000_000;

pub struct SeededCredentials {
    pub app_password: String,
    pub api_key: String,
}

pub async fn seed_credentials(path: &Path) -> SeededCredentials {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let app = AppPassword {
        credential_id: APP_PASSWORD_ID,
        secret: [7u8; 18],
    };
    let api = ApiKey {
        account_id: ACCOUNT,
        credential_id: API_KEY_ID,
        secret: [9u8; 20],
    };
    let hash = |secret: &[u8]| hash_secret(PasswordHashAlgorithm::Argon2id, secret.to_vec());
    let mut credentials = List::default();
    credentials.push(structs::Credential::Password(structs::PasswordCredential {
        credential_id: Id::new(0),
        secret: hash(PASSWORD.as_bytes()).await.expect("hash"),
        otp_auth: Some(OTP_URL.into()),
        ..Default::default()
    }));
    credentials.push(structs::Credential::AppPassword(
        structs::SecondaryCredential {
            credential_id: Id::new(u64::from(APP_PASSWORD_ID)),
            description: "phone".into(),
            secret: hash(&app.secret).await.expect("hash"),
            created_at: UTCDateTime::from_timestamp(CREDENTIAL_CREATED_AT),
            ..Default::default()
        },
    ));
    credentials.push(structs::Credential::ApiKey(structs::SecondaryCredential {
        credential_id: Id::new(u64::from(API_KEY_ID)),
        description: "ci".into(),
        secret: hash(&api.secret).await.expect("hash"),
        created_at: UTCDateTime::from_timestamp(CREDENTIAL_CREATED_AT),
        ..Default::default()
    }));
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: u64::from(ACCOUNT),
        }),
        ObjectInner::Account(structs::Account::User(structs::UserAccount {
            name: "jane".into(),
            domain_id: Id::new(DOMAIN_ID),
            credentials,
            ..Default::default()
        }))
        .to_pickled_vec(),
    );
    store.write(batch.build_all()).await.expect("registry");
    SeededCredentials {
        app_password: app.build(),
        api_key: api.build(),
    }
}

pub const PUBLIC_KEY_ID: u64 = 3;

pub async fn seed_encryption_at_rest(path: &Path, key: &str) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let email_addresses = Map::new(vec![format!("user{ACCOUNT}@example.org")]);
    let mut batch = BatchBuilder::new();
    batch
        .set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::PublicKey.to_id(),
                item_id: PUBLIC_KEY_ID,
            }),
            ObjectInner::PublicKey(structs::PublicKey {
                account_id: Id::new(u64::from(ACCOUNT)),
                key: key.into(),
                description: "PGP key".into(),
                created_at: UTCDateTime::from_timestamp(CREDENTIAL_CREATED_AT),
                expires_at: None,
                email_addresses,
            })
            .to_pickled_vec(),
        )
        .set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::Account.to_id(),
                item_id: u64::from(ACCOUNT),
            }),
            ObjectInner::Account(structs::Account::User(structs::UserAccount {
                name: format!("user{ACCOUNT}"),
                domain_id: Id::new(DOMAIN_ID),
                encryption_at_rest: structs::EncryptionAtRest::Aes256(
                    structs::EncryptionSettings {
                        public_key: Id::new(PUBLIC_KEY_ID),
                        encrypt_on_append: true,
                        allow_spam_training: true,
                    },
                ),
                ..Default::default()
            }))
            .to_pickled_vec(),
        );
    store.write(batch.build_all()).await.expect("registry");
}

pub async fn delete_account_registry(path: &Path) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Registry(RegistryClass::Item {
        object_id: ObjectType::Account.to_id(),
        item_id: u64::from(ACCOUNT),
    }));
    store.write(batch.build_all()).await.expect("registry");
}

pub const QUEUE_QUOTA: [u8; 32] = [7; 32];

fn queued_message(blob_hash: BlobHash, size: u64, priority: i16) -> Message {
    let created = 1_700_000_000;
    Message {
        created,
        blob_hash,
        return_path: Box::from("sender@example.org"),
        recipients: vec![Recipient {
            address: Box::from("rcpt@example.net"),
            retry: Schedule {
                due: created + 60,
                inner: 0,
            },
            notify: Schedule {
                due: created + 3600,
                inner: 0,
            },
            expires: QueueExpiry::Ttl(created + 86_400),
            queue: QueueName::new("default").expect("queue name"),
            status: Status::Scheduled,
            flags: 0,
            orcpt: None,
        }],
        received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        received_via_port: 25,
        flags: 0,
        env_id: None,
        priority,
        size,
        metadata: vec![Metadata::QueueSize {
            key: Box::from(QUEUE_QUOTA),
            id: 1,
        }]
        .into_boxed_slice(),
    }
}

pub fn queue_blob_hash(body: &[u8]) -> [u8; 32] {
    *store::blake3::hash(body).as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueBlob {
    Stored,
    Missing,
}

pub async fn put_queued_message(
    path: &Path,
    queue_id: u64,
    body: &[u8],
    blob: QueueBlob,
    priority: i16,
) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let hash = BlobHash(queue_blob_hash(body));
    if blob == QueueBlob::Stored {
        BlobStore::Store(store.clone())
            .put_blob(hash.as_slice(), body, CompressionAlgo::Lz4)
            .await
            .expect("blob");
    }
    let size = u64::try_from(body.len()).expect("size");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Queue(QueueClass::Message(queue_id)),
        archive(queued_message(hash, size, priority)),
    );
    store
        .write(batch.build_all())
        .await
        .expect("queued message");
}

pub async fn put_spam_classifier(path: &Path, weight: f32, last_trained_at: u64) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let classifier = FhTrainer::new(Ftrl::new(4).with_initial_weights(weight)).build_classifier();
    BlobStore::Store(store)
        .put_blob(
            SPAM_CLASSIFIER_KEY,
            &archive(SpamClassifier::FhClassifier {
                classifier,
                last_trained_at,
            }),
            CompressionAlgo::None,
        )
        .await
        .expect("spam classifier");
}

pub async fn remove_queued_message(path: &Path, queue_id: u64) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Queue(QueueClass::Message(queue_id)));
    store
        .write(batch.build_all())
        .await
        .expect("queued message");
}

pub async fn put_dmarc_report(path: &Path, item_id: u64, counts: &[u64]) {
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::DmarcInternalReport.to_id(),
            item_id,
        }),
        ObjectInner::DmarcInternalReport(structs::DmarcInternalReport {
            domain: "example.org".into(),
            policy_identifier: item_id,
            report: structs::DmarcReport {
                records: counts
                    .iter()
                    .map(|count| structs::DmarcReportRecord {
                        count: *count,
                        ..Default::default()
                    })
                    .collect::<Vec<_>>()
                    .into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .to_pickled_vec(),
    );
    store.write(batch.build_all()).await.expect("report");
}

pub async fn put_span(path: &Path, span_id: u64, events: &[&str], nested: Option<&str>) {
    let event = |name: &str| trc::EventType::parse(name).expect("v0.16 event type");
    let key_values = |first: bool| -> List<structs::TraceKeyValue> {
        nested
            .filter(|_| first)
            .map(|name| structs::TraceKeyValue {
                key: trc::Key::Details,
                value: structs::TraceValue::Event(structs::TraceValueEvent {
                    event: event(name),
                    value: List::default(),
                }),
            })
            .into_iter()
            .collect::<Vec<_>>()
            .into()
    };
    let trace = structs::Trace {
        events: events
            .iter()
            .enumerate()
            .map(|(index, name)| structs::TraceEvent {
                event: event(name),
                timestamp: UTCDateTime::from_timestamp(1_700_000_000),
                key_values: key_values(index == 0),
            })
            .collect::<Vec<_>>()
            .into(),
    };
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    commit(&store, |batch| {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Span(span_id)),
            trace.to_pickled_vec(),
        );
    })
    .await;
}

pub async fn put_dated_span(path: &Path, span_id: u64, timestamps: &[i64]) {
    let date = |timestamp: i64| {
        structs::TraceValue::UTCDateTime(structs::TraceValueUTCDateTime {
            value: UTCDateTime::from_timestamp(timestamp),
        })
    };
    let trace = structs::Trace {
        events: timestamps
            .iter()
            .map(|&timestamp| structs::TraceEvent {
                event: trc::EventType::Queue(trc::QueueEvent::Rescheduled),
                timestamp: UTCDateTime::from_timestamp(timestamp),
                key_values: vec![
                    structs::TraceKeyValue {
                        key: trc::Key::NextDsn,
                        value: date(timestamp),
                    },
                    structs::TraceKeyValue {
                        key: trc::Key::Details,
                        value: structs::TraceValue::List(structs::TraceValueList {
                            value: vec![date(timestamp)].into(),
                        }),
                    },
                ]
                .into(),
            })
            .collect::<Vec<_>>()
            .into(),
    };
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    commit(&store, |batch| {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Span(span_id)),
            trace.to_pickled_vec(),
        );
    })
    .await;
}

pub async fn put_metric(path: &Path, metric_id: u64, metric: &str, count: u64) {
    let metric = structs::Metric::Counter(structs::MetricCount {
        count,
        metric: trc::MetricType::parse(metric).expect("v0.16 metric type"),
    });
    let store = Store::build(rocks(path))
        .await
        .expect("open writable store");
    commit(&store, |batch| {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Metric(metric_id)),
            metric.to_pickled_vec(),
        );
    })
    .await;
}
