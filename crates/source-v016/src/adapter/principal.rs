/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::push::{EmailPush, PushSubscription, PushSubscriptions};
use groupware::calendar::ParticipantIdentities;
use jmap_proto::object::push_subscription::{EmailPushHeaderForm, EmailPushProperty};
use model::{
    AccountPointers, AccountRef, Collection, Counters, EmailPushRecord, MailboxUid,
    ParticipantIdentitiesRecord, ParticipantIdentityRecord, Pointer, PushKeysRecord, PushRecord,
};
use store::{
    IterateParams, SUBSPACE_COUNTER, Store, U32_LEN, ValueKey,
    write::{AlignedBytes, AnyClass, Archive, ValueClass, key::DeserializeBigEndian},
};
use types::{
    field::{MailboxField, PrincipalField},
    type_state::DataType,
};

use tokio::task::JoinSet;
use utils::map::bitmap::BitmapItem;

use super::{
    error::trc_error,
    keys::{archive_key, get_property},
};

const PRINCIPAL: u8 = Collection::Principal.as_u8();
const ACCOUNT_KEY_LEN: usize = U32_LEN;

fn counter_range() -> IterateParams<ValueKey<ValueClass>> {
    let key = |byte: u8, len: usize| {
        ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_COUNTER,
            key: vec![byte; len],
        }))
    };
    IterateParams::new(key(0, 1), key(u8::MAX, 16)).ascending()
}

const COUNTER_CONCURRENCY: usize = 32;
const COUNTER_LEN: usize = 8;

#[allow(unreachable_patterns)]
fn counters_in_values(store: &Store) -> bool {
    match store {
        #[cfg(feature = "rocks")]
        Store::RocksDb(_) => true,
        #[cfg(feature = "foundation")]
        Store::FoundationDb(_) => true,
        _ => false,
    }
}

pub(super) async fn accounts(store: &Store) -> model::Result<Vec<AccountRef>> {
    let in_values = counters_in_values(store);
    let mut accounts = Vec::new();
    let mut invalid = false;
    store
        .iterate(counter_range().set_values(in_values), |key, value| {
            if key.len() == ACCOUNT_KEY_LEN {
                let account_id = key.deserialize_be_u32(0)?;
                let change_counter = if in_values {
                    match value.first_chunk::<COUNTER_LEN>() {
                        Some(bytes) => {
                            u64::try_from(i64::from_le_bytes(*bytes)).unwrap_or_default()
                        }
                        None => {
                            invalid = true;
                            return Ok(false);
                        }
                    }
                } else {
                    0
                };
                accounts.push(AccountRef {
                    account_id,
                    change_counter,
                });
            }
            Ok(true)
        })
        .await
        .map_err(trc_error)?;
    if invalid {
        return Err(model::Error::fatal("invalid change counter value"));
    }
    if !in_values {
        let mut tasks = JoinSet::new();
        let ids: Vec<u32> = accounts.iter().map(|account| account.account_id).collect();
        let mut pending = ids.into_iter().enumerate();
        loop {
            while tasks.len() < COUNTER_CONCURRENCY {
                let Some((position, account_id)) = pending.next() else {
                    break;
                };
                let store = store.clone();
                tasks.spawn(async move { (position, change_counter(&store, account_id).await) });
            }
            let Some(joined) = tasks.join_next().await else {
                break;
            };
            let (position, counter) =
                joined.map_err(|err| model::Error::transient(err.to_string()))?;
            if let Some(account) = accounts.get_mut(position) {
                account.change_counter = counter?;
            }
        }
    }
    Ok(accounts)
}

async fn change_counter(store: &Store, account_id: u32) -> model::Result<u64> {
    store
        .get_counter(ValueKey {
            account_id,
            collection: 0,
            document_id: 0,
            class: ValueClass::ChangeId,
        })
        .await
        .map(|value| u64::try_from(value).unwrap_or_default())
        .map_err(trc_error)
}

pub(super) async fn counters(store: &Store, account_id: u32) -> model::Result<Counters> {
    let mut counters = Counters {
        change_id: change_counter(store, account_id).await?,
        ..Counters::default()
    };
    for collection in Collection::ALL {
        let value = store
            .get_counter(ValueKey {
                account_id,
                collection: collection.as_u8(),
                document_id: 0,
                class: ValueClass::DocumentId,
            })
            .await
            .map_err(trc_error)?;
        if let Ok(value) = u32::try_from(value)
            && value > 0
        {
            counters.set_document_id(collection, value);
        }
    }
    let mut mailboxes = Vec::new();
    let mailbox = Collection::Mailbox.as_u8();
    store
        .iterate(
            IterateParams::new(
                archive_key(account_id, mailbox, 0),
                archive_key(account_id, mailbox, u32::MAX),
            )
            .ascending()
            .no_values(),
            |key, _| {
                mailboxes.push(key.deserialize_be_u32(key.len() - U32_LEN)?);
                Ok(true)
            },
        )
        .await
        .map_err(trc_error)?;
    counters.mailbox_uids.reserve(mailboxes.len());
    for mailbox_id in mailboxes {
        let uid = store
            .get_counter(ValueKey::property(
                account_id,
                mailbox,
                mailbox_id,
                MailboxField::UidCounter,
            ))
            .await
            .map_err(trc_error)?;
        counters.mailbox_uids.push(MailboxUid {
            mailbox_id,
            uid: u32::try_from(uid).unwrap_or_default(),
        });
    }
    Ok(counters)
}

async fn principal_u32(
    store: &Store,
    account_id: u32,
    field: PrincipalField,
) -> model::Result<Option<u32>> {
    get_property::<u32>(store, account_id, PRINCIPAL, 0, field.into()).await
}

async fn principal_archive(
    store: &Store,
    account_id: u32,
    field: PrincipalField,
) -> model::Result<Option<Archive<AlignedBytes>>> {
    get_property::<Archive<AlignedBytes>>(store, account_id, PRINCIPAL, 0, field.into()).await
}

pub(super) async fn pointers(store: &Store, account_id: u32) -> model::Result<AccountPointers> {
    let participant_identities =
        match principal_archive(store, account_id, PrincipalField::ParticipantIdentities).await? {
            Some(archive) => {
                let identities = archive
                    .deserialize::<ParticipantIdentities>()
                    .map_err(trc_error)?;
                Some(ParticipantIdentitiesRecord {
                    identities: identities
                        .identities
                        .into_iter()
                        .map(|identity| ParticipantIdentityRecord {
                            id: identity.id,
                            name: identity.name,
                            calendar_address: identity.calendar_address,
                        })
                        .collect(),
                    default_name: identities.default_name,
                    default: identities.default,
                })
            }
            None => None,
        };
    let push_subscriptions =
        match principal_archive(store, account_id, PrincipalField::PushSubscriptions).await? {
            Some(archive) => archive
                .deserialize::<PushSubscriptions>()
                .map_err(trc_error)?
                .subscriptions
                .into_iter()
                .map(push_record)
                .collect(),
            None => Vec::new(),
        };
    Ok(AccountPointers {
        active_script: Pointer::Set(
            principal_u32(store, account_id, PrincipalField::ActiveScriptId).await?,
        ),
        default_calendar: Pointer::Set(
            principal_u32(store, account_id, PrincipalField::DefaultCalendarId).await?,
        ),
        default_address_book: Pointer::Set(
            principal_u32(store, account_id, PrincipalField::DefaultAddressBookId).await?,
        ),
        identity_addresses_hash: Pointer::Set(
            get_property::<u64>(
                store,
                account_id,
                PRINCIPAL,
                0,
                PrincipalField::IdentityAddresses.into(),
            )
            .await?,
        ),
        participant_identities: Pointer::Set(participant_identities),
        push_subscriptions: Pointer::Set(Some(push_subscriptions)),
    })
}

fn push_record(subscription: PushSubscription) -> PushRecord {
    PushRecord {
        id: subscription.id,
        url: subscription.url,
        device_client_id: subscription.device_client_id,
        expires: subscription.expires,
        verification_code: subscription.verification_code,
        verified: subscription.verified,
        types: data_types(subscription.types.bitmap),
        keys: subscription.keys.map(|keys| PushKeysRecord {
            p256dh: keys.p256dh,
            auth: keys.auth,
        }),
        email_push: subscription
            .email_push
            .into_iter()
            .filter(|push| push.filter.is_empty())
            .map(email_push)
            .collect(),
    }
}

fn data_types(bitmap: u64) -> Vec<Box<str>> {
    let mut types: Vec<Box<str>> = (0..<DataType as BitmapItem>::max())
        .filter(|bit| bitmap & (1u64 << bit) != 0)
        .map(DataType::from)
        .filter(BitmapItem::is_valid)
        .map(|data_type| Box::from(data_type.as_str()))
        .collect();
    types.sort_unstable();
    types
}

fn email_push(push: EmailPush) -> EmailPushRecord {
    EmailPushRecord {
        account_id: push.account_id,
        properties: push.properties.iter().map(property_name).collect(),
        filter: serde_json::Value::Null,
        urgency: push.urgency.as_str().into(),
    }
}

fn property_name(property: &EmailPushProperty) -> Box<str> {
    let name = match property {
        EmailPushProperty::Id => "id",
        EmailPushProperty::BlobId => "blobId",
        EmailPushProperty::ThreadId => "threadId",
        EmailPushProperty::MailboxIds => "mailboxIds",
        EmailPushProperty::Keywords => "keywords",
        EmailPushProperty::Size => "size",
        EmailPushProperty::ReceivedAt => "receivedAt",
        EmailPushProperty::MessageId => "messageId",
        EmailPushProperty::InReplyTo => "inReplyTo",
        EmailPushProperty::References => "references",
        EmailPushProperty::Sender => "sender",
        EmailPushProperty::From => "from",
        EmailPushProperty::To => "to",
        EmailPushProperty::Cc => "cc",
        EmailPushProperty::Bcc => "bcc",
        EmailPushProperty::ReplyTo => "replyTo",
        EmailPushProperty::Subject => "subject",
        EmailPushProperty::SentAt => "sentAt",
        EmailPushProperty::Preview => "preview",
        EmailPushProperty::HasAttachment => "hasAttachment",
        EmailPushProperty::BodyStructure => "bodyStructure",
        EmailPushProperty::BodyValues => "bodyValues",
        EmailPushProperty::TextBody => "textBody",
        EmailPushProperty::HtmlBody => "htmlBody",
        EmailPushProperty::Attachments => "attachments",
        EmailPushProperty::Headers => "headers",
        EmailPushProperty::Header(header) => {
            let form = match header.form {
                EmailPushHeaderForm::Raw => "",
                EmailPushHeaderForm::Text => ":asText",
                EmailPushHeaderForm::Addresses => ":asAddresses",
                EmailPushHeaderForm::GroupedAddresses => ":asGroupedAddresses",
                EmailPushHeaderForm::MessageIds => ":asMessageIds",
                EmailPushHeaderForm::Date => ":asDate",
                EmailPushHeaderForm::Urls => ":asURLs",
            };
            let all = if header.all { ":all" } else { "" };
            return format!("header:{}{form}{all}", header.header).into_boxed_str();
        }
    };
    Box::from(name)
}
