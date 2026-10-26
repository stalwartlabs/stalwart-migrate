/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{num::NonZeroUsize, path::Path};

use calcard::icalendar::{ICalendarProperty, ICalendarValue};
use common::auth::credential::{ApiKey, AppPassword};
use directory::core::{secret::verify_secret_hash, verifier::PasswordVerifier};
use email::{
    mailbox::Mailbox,
    message::{
        messagedata::MessageData,
        metadata::{MessageMetadata, row::MetadataRow},
    },
};
use groupware::calendar::{Calendar, CalendarEventContent};
use model::{RecordBatch, Source};
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs::{self, DataStore},
    },
    types::EnumImpl,
};
use serde_json::{Value, json};
use store::{
    BlobStore, Deserialize, IterateParams, LogKey, Serialize, Store, Subspace, ValueKey,
    write::{
        AnyClass, Archive, ArchiveBytes, Archiver, BatchBuilder, BlobLink, BlobOp, QueueClass,
        RegistryClass, ValueClass, key::SystemKind, serialize::RawValue,
    },
};
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, EmailField, Field, MailboxField, PrincipalField},
    id::Id,
};

use crate::V1Source;

const WRONG_CALENDAR: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corruption {
    EmailKeyword,
    EmailUid,
    EmailHeaders,
    MailboxAcl,
    EventSummary,
    CalendarName,
    ExtraIdentity,
    MailboxUidCounter,
    LastEmailLogRow,
    FirstEmailLogRow,
    ExtraMemberGroup,
    ExtraAllowedIp,
    AdminRole,
    LostSecret,
    ExtraDomain,
    DeletedBlob,
    LostActiveScript,
    WrongDefaultCalendar,
    LostPushSubscriptions,
    LostShareNotification,
}

impl Corruption {
    pub const ALL: [Corruption; 20] = [
        Corruption::EmailKeyword,
        Corruption::EmailUid,
        Corruption::EmailHeaders,
        Corruption::MailboxAcl,
        Corruption::EventSummary,
        Corruption::CalendarName,
        Corruption::ExtraIdentity,
        Corruption::MailboxUidCounter,
        Corruption::LastEmailLogRow,
        Corruption::FirstEmailLogRow,
        Corruption::ExtraMemberGroup,
        Corruption::ExtraAllowedIp,
        Corruption::AdminRole,
        Corruption::LostSecret,
        Corruption::ExtraDomain,
        Corruption::DeletedBlob,
        Corruption::LostActiveScript,
        Corruption::WrongDefaultCalendar,
        Corruption::LostPushSubscriptions,
        Corruption::LostShareNotification,
    ];
}

pub async fn open(path: &Path) -> Store {
    Store::build(DataStore::RocksDb(structs::RocksDbStore {
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await
    .expect("open v1 store")
}

fn archive_class() -> ValueClass {
    ValueClass::Property(Field::ARCHIVE.into())
}

async fn raw(
    store: &Store,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    class: ValueClass,
) -> Vec<u8> {
    store
        .get_value::<RawValue>(ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            class,
        })
        .await
        .expect("get")
        .expect("present")
        .0
}

async fn put(
    store: &Store,
    account_id: u32,
    collection: Collection,
    document_id: u32,
    class: ValueClass,
    bytes: Vec<u8>,
) {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(collection)
        .with_document(document_id)
        .set(class, bytes);
    store.write_batch(&mut batch).await.expect("write");
}

pub async fn logged_identity_copy(store: &Store, account_id: u32, document_id: u32) {
    let bytes = raw(store, account_id, Collection::Identity, 0, archive_class()).await;
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Identity)
        .with_document(document_id)
        .set(archive_class(), bytes)
        .log_item_insert(SyncCollection::Identity, None);
    store.write_batch(&mut batch).await.expect("write");
}

pub async fn logged_calendar_rename(store: &Store, account_id: u32, calendar_id: u32, name: &str) {
    let bytes = raw(
        store,
        account_id,
        Collection::Calendar,
        calendar_id,
        archive_class(),
    )
    .await;
    let mut calendar = unarchive::<Calendar>(&bytes);
    calendar.name = name.into();
    let bytes = Archiver::new(calendar).serialize().expect("serialize");
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Calendar)
        .with_document(calendar_id)
        .set(archive_class(), bytes)
        .log_container_update(SyncCollection::Calendar);
    store.write_batch(&mut batch).await.expect("write");
}

fn unarchive<T>(bytes: &[u8]) -> T
where
    T: store::rkyv::Archive,
    T::Archived: for<'a> store::rkyv::bytecheck::CheckBytes<
            store::rkyv::api::high::HighValidator<'a, store::rkyv::rancor::Error>,
        > + store::rkyv::Deserialize<
            T,
            store::rkyv::api::high::HighDeserializer<store::rkyv::rancor::Error>,
        >,
{
    <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)
        .expect("archive")
        .deserialize::<T>()
        .expect("unarchive")
}

fn registry_key(object_type: ObjectType, item_id: u64) -> ValueClass {
    ValueClass::Registry(RegistryClass::Item {
        object_id: object_type.to_id(),
        item_id,
    })
}

async fn edit_registry(
    store: &Store,
    object_type: ObjectType,
    item_id: u64,
    edit: impl FnOnce(&mut Value),
) {
    let object = store
        .get_value::<Object>(ValueKey::from(registry_key(object_type, item_id)))
        .await
        .expect("registry read")
        .expect("registry object");
    let mut json = serde_json::to_value(&object.inner).expect("json");
    edit(&mut json);
    put_registry(store, object_type, item_id, &json).await;
}

async fn put_registry(store: &Store, object_type: ObjectType, item_id: u64, json: &Value) {
    let inner = ObjectInner::deserialize(object_type, json).expect("valid v1 object");
    let mut batch = BatchBuilder::new();
    batch.set(registry_key(object_type, item_id), inner.to_pickled_vec());
    store.write_batch(&mut batch).await.expect("registry write");
}

fn first_credential(json: &mut Value) -> &mut Value {
    json["credentials"]
        .as_object_mut()
        .and_then(|credentials| credentials.values_mut().next())
        .expect("credential")
}

pub async fn corrupt(store: &Store, account_id: u32, corruption: Corruption) {
    match corruption {
        Corruption::EmailKeyword | Corruption::EmailUid => {
            let bytes = raw(store, account_id, Collection::Email, 0, archive_class()).await;
            let mut data = MessageData::deserialize(&bytes).expect("message data");
            if corruption == Corruption::EmailKeyword {
                data.keywords_extra.clear();
            } else {
                data.mailboxes[0].uid = 99;
            }
            let bytes = data.serialize().expect("serialize");
            put(
                store,
                account_id,
                Collection::Email,
                0,
                archive_class(),
                bytes,
            )
            .await;
        }
        Corruption::EmailHeaders => {
            let class = ValueClass::Immutable(EmailField::Metadata.into());
            let bytes = raw(store, account_id, Collection::Email, 0, class.clone()).await;
            let row = MetadataRow::deserialize(&bytes).expect("metadata row");
            let mut headers = row.raw_headers().expect("headers").into_owned();
            headers[0] = b'X';
            let metadata = store::rkyv::deserialize::<MessageMetadata, store::rkyv::rancor::Error>(
                row.unarchive().expect("unarchive"),
            )
            .expect("metadata");
            let encoded = MetadataRow::encode(metadata, &headers).expect("encode");
            put(store, account_id, Collection::Email, 0, class, encoded).await;
        }
        Corruption::MailboxAcl => {
            let bytes = raw(store, account_id, Collection::Mailbox, 0, archive_class()).await;
            let mut mailbox = unarchive::<Mailbox>(&bytes);
            mailbox.acls.clear();
            let bytes = Archiver::new(mailbox).serialize().expect("serialize");
            put(
                store,
                account_id,
                Collection::Mailbox,
                0,
                archive_class(),
                bytes,
            )
            .await;
        }
        Corruption::EventSummary => {
            let class = ValueClass::Property(CalendarEventField::Content.field().into());
            let bytes = raw(
                store,
                account_id,
                Collection::CalendarEvent,
                0,
                class.clone(),
            )
            .await;
            let mut content = unarchive::<CalendarEventContent>(&bytes);
            for component in content.data.event.components.iter_mut() {
                for entry in component.entries.iter_mut() {
                    if entry.name == ICalendarProperty::Summary {
                        entry.values = vec![ICalendarValue::Text("Changed".into())].into();
                    }
                }
            }
            let bytes = Archiver::new(content).serialize().expect("serialize");
            put(
                store,
                account_id,
                Collection::CalendarEvent,
                0,
                class,
                bytes,
            )
            .await;
        }
        Corruption::CalendarName => {
            let bytes = raw(store, account_id, Collection::Calendar, 0, archive_class()).await;
            let mut calendar = unarchive::<Calendar>(&bytes);
            calendar.name = "hijacked".into();
            calendar.acls.push(AclGrant {
                account_id: 99,
                grants: Default::default(),
            });
            let bytes = Archiver::new(calendar).serialize().expect("serialize");
            put(
                store,
                account_id,
                Collection::Calendar,
                0,
                archive_class(),
                bytes,
            )
            .await;
        }
        Corruption::ExtraIdentity => {
            let bytes = raw(store, account_id, Collection::Identity, 0, archive_class()).await;
            put(
                store,
                account_id,
                Collection::Identity,
                5,
                archive_class(),
                bytes,
            )
            .await;
        }
        Corruption::MailboxUidCounter => {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .with_document(0)
                .add(MailboxField::UidCounter, -3);
            store.write_batch(&mut batch).await.expect("write");
        }
        Corruption::LastEmailLogRow | Corruption::FirstEmailLogRow => {
            let mut keys = Vec::new();
            store
                .iterate(
                    IterateParams::new(
                        LogKey {
                            account_id,
                            collection: 0,
                            change_id: 0,
                        },
                        LogKey {
                            account_id,
                            collection: 0,
                            change_id: u64::MAX,
                        },
                    )
                    .ascending()
                    .no_values(),
                    |key, _| {
                        keys.push(key.to_vec());
                        Ok(true)
                    },
                )
                .await
                .expect("iterate");
            let key = if corruption == Corruption::LastEmailLogRow {
                keys.pop()
            } else {
                keys.into_iter().next()
            }
            .expect("log row");
            let mut batch = BatchBuilder::new();
            batch.clear(ValueClass::Any(AnyClass {
                subspace: Subspace::Logs,
                key,
            }));
            store.write_batch(&mut batch).await.expect("write");
        }
        Corruption::ExtraMemberGroup => {
            edit_registry(store, ObjectType::Account, u64::from(account_id), |json| {
                json["memberGroupIds"]["z"] = Value::Bool(true);
            })
            .await;
        }
        Corruption::ExtraAllowedIp => {
            edit_registry(store, ObjectType::Account, u64::from(account_id), |json| {
                first_credential(json)["allowedIps"]["10.0.0.0/8"] = Value::Bool(true);
            })
            .await;
        }
        Corruption::AdminRole => {
            edit_registry(store, ObjectType::Account, u64::from(account_id), |json| {
                json["roles"] = json!({"@type": "Admin"});
            })
            .await;
        }
        Corruption::LostSecret => {
            edit_registry(store, ObjectType::Account, u64::from(account_id), |json| {
                first_credential(json)["secret"] = Value::String("$6$lost$lost".into());
            })
            .await;
        }
        Corruption::DeletedBlob => {
            let page = V1Source::from_store(store.clone())
                .read(account_id, model::Collection::Email, &[0])
                .await
                .expect("read email");
            let RecordBatch::Email(emails) = page.batch else {
                panic!("email batch");
            };
            let hash = emails.first().expect("email").blob_hash;
            BlobStore::Store(store.clone())
                .delete_blob(hash.as_bytes())
                .await
                .expect("delete blob");
        }
        Corruption::LostActiveScript
        | Corruption::WrongDefaultCalendar
        | Corruption::LostPushSubscriptions => {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);
            match corruption {
                Corruption::LostActiveScript => {
                    batch.clear(PrincipalField::ActiveScriptId);
                }
                Corruption::WrongDefaultCalendar => {
                    batch.set(
                        PrincipalField::DefaultCalendarId,
                        WRONG_CALENDAR.to_be_bytes().to_vec(),
                    );
                }
                _ => {
                    batch.clear(PrincipalField::PushSubscriptions);
                }
            }
            store.write_batch(&mut batch).await.expect("write");
        }
        Corruption::LostShareNotification => {
            let shares = V1Source::from_store(store.clone())
                .share_notifications(account_id, None, 1)
                .await
                .expect("shares");
            let share = shares.first().expect("share notification");
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .clear(ValueClass::ShareNotification {
                    notification_id: share.id,
                    notify_account_id: account_id,
                });
            store.write_batch(&mut batch).await.expect("write");
        }
        Corruption::ExtraDomain => {
            put_registry(
                store,
                ObjectType::Domain,
                77,
                &json!({"name": "extra.example.org"}),
            )
            .await;
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CredentialCheck {
    pub password: bool,
    pub otp_url: Option<String>,
    pub app_password: bool,
    pub api_key: bool,
}

pub async fn check_credentials(
    store: &Store,
    account_id: u32,
    password: &str,
    app_password: &str,
    api_key: &str,
) -> CredentialCheck {
    let object = store
        .get_value::<Object>(ValueKey::from(registry_key(
            ObjectType::Account,
            u64::from(account_id),
        )))
        .await
        .expect("registry read")
        .expect("account");
    let ObjectInner::Account(account) = object.inner else {
        panic!("not an account");
    };
    let account = account.into_user().expect("user account");
    let verifier = PasswordVerifier::new(NonZeroUsize::MIN);
    let mut check = CredentialCheck::default();
    for credential in account.credentials.iter() {
        if let structs::Credential::Password(credential) = credential {
            check.password = verify_secret_hash(&verifier, &credential.secret, password.as_bytes())
                .await
                .expect("verify");
            check.otp_url = credential.otp_url.clone();
        }
    }
    let secondary = |credential_id: u32| {
        account
            .credentials
            .iter()
            .filter_map(|credential| credential.as_secondary_credential())
            .find(|credential| credential.credential_id.document_id() == credential_id)
            .map(|credential| credential.secret.clone())
    };
    if let Some(app) = AppPassword::parse(app_password)
        && let Some(secret) = secondary(app.credential_id)
    {
        check.app_password = verify_secret_hash(&verifier, &secret, &app.secret)
            .await
            .expect("verify");
    }
    if let Some(api) = ApiKey::parse(api_key)
        && let Some(secret) = secondary(api.credential_id)
    {
        check.api_key = verify_secret_hash(&verifier, &secret, &api.secret)
            .await
            .expect("verify");
    }
    check
}

pub async fn put_singleton(store: &Store, object: &str, json: &Value) {
    let object_type = ObjectType::parse(object).expect("object type");
    put_registry(store, object_type, Id::singleton().id(), json).await;
}

pub async fn remove_target_claim(store: &Store) {
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: vec![SystemKind::SchemaVersion as u8, u8::MAX],
    }));
    store
        .write_batch(&mut batch)
        .await
        .expect("remove target claim");
}

pub async fn remove_registry_object(store: &Store, object: &str, id: u64) {
    let object_type = ObjectType::parse(object).expect("object type");
    let mut batch = BatchBuilder::new();
    batch.clear(registry_key(object_type, id));
    store
        .write_batch(&mut batch)
        .await
        .expect("remove registry object");
}

pub async fn account_exists(store: &Store, account_id: u32) -> bool {
    store
        .get_value::<Object>(ValueKey::from(registry_key(
            ObjectType::Account,
            u64::from(account_id),
        )))
        .await
        .expect("registry read")
        .is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedCheck {
    pub message: bool,
    pub blob_link: bool,
    pub quota_size: i64,
}

pub async fn queued_message_state(
    store: &Store,
    queue_id: u64,
    blob_hash: [u8; 32],
    quota_hash: [u8; 32],
) -> QueuedCheck {
    let message = store
        .key_exists(ValueKey::from(ValueClass::Queue(QueueClass::Message(
            queue_id,
        ))))
        .await
        .expect("queued message");
    let blob_link = store
        .key_exists(ValueKey::from(ValueClass::Blob(BlobOp::Link {
            hash: types::blob_hash::BlobHash(blob_hash),
            to: BlobLink::Id { id: queue_id },
        })))
        .await
        .expect("blob link");
    let (quota_key, _) = quota_hash.split_first_chunk::<16>().expect("quota key");
    let quota_size = store
        .get_counter(ValueKey::from(ValueClass::Queue(QueueClass::QuotaSize(
            u128::from_be_bytes(*quota_key).into(),
        ))))
        .await
        .expect("quota");
    QueuedCheck {
        message,
        blob_link,
        quota_size,
    }
}
