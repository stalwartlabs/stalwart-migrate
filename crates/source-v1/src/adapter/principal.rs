/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::push::{EmailPush, PushSubscription, PushSubscriptions};
use groupware::calendar::ParticipantIdentities;
use jmap_proto::object::email::EmailProperty;
use jmap_tools::Property;
use model::{
    AccountPointers, AccountRef, ChangeBounds, Collection, Counters, EmailPushRecord,
    LogCollection, MailboxUid, ParticipantIdentitiesRecord, ParticipantIdentityRecord, Pointer,
    PushKeysRecord, PushRecord,
};
use store::{
    IterateParams, Store, Subspace, U32_LEN, ValueKey,
    write::{
        AnyKey, Archive, ArchiveBytes, ValueClass,
        key::{CounterKind, DeserializeBigEndian},
    },
};
use types::{
    collection::{Collection as V1Collection, SyncCollection},
    field::PrincipalField,
};

use super::{
    changes::source_log,
    error::trc_error,
    keys::{self, get},
};

const PRINCIPAL_DOCUMENT: u32 = 0;
const ACCOUNT_PREFIX_LEN: usize = 1 + U32_LEN;
const CHANGE_ID_KEY_LEN: usize = ACCOUNT_PREFIX_LEN + 1;
const MAILBOX_UID_KEY_LEN: usize = ACCOUNT_PREFIX_LEN + U32_LEN;
const CHANGE_GROUPS: usize = SyncCollection::MAX_CHANGE_GROUP as usize;

#[derive(Clone, Copy)]
struct ChangeGroups(u32);

impl ChangeGroups {
    fn new() -> Self {
        ChangeGroups(
            (0..SyncCollection::MAX_CHANGE_GROUP).fold(0u32, |mask, value| {
                mask | 1u32
                    .checked_shl(u32::from(
                        SyncCollection::from(value).change_group().to_u8(),
                    ))
                    .unwrap_or_default()
            }),
        )
    }

    fn contains(self, group: u8) -> bool {
        1u32.checked_shl(u32::from(group))
            .is_some_and(|bit| self.0 & bit != 0)
    }
}

fn counter_range(prefix: &[u8], suffix_len: usize) -> IterateParams<AnyKey<Vec<u8>>> {
    let mut end = Vec::with_capacity(prefix.len() + suffix_len);
    end.extend_from_slice(prefix);
    end.resize(prefix.len() + suffix_len, u8::MAX);
    IterateParams::new(
        AnyKey {
            subspace: Subspace::Counter,
            key: prefix.to_vec(),
        },
        AnyKey {
            subspace: Subspace::Counter,
            key: end,
        },
    )
    .ascending()
}

fn account_prefix(kind: CounterKind, account_id: u32) -> [u8; ACCOUNT_PREFIX_LEN] {
    let mut prefix = [0u8; ACCOUNT_PREFIX_LEN];
    let (first, id) = prefix.split_at_mut(1);
    first.fill(kind.byte());
    id.copy_from_slice(&account_id.to_be_bytes());
    prefix
}

fn counter_value(key: &[u8], value: &[u8]) -> trc::Result<i64> {
    <[u8; 8]>::try_from(value)
        .map(i64::from_le_bytes)
        .map_err(|_| trc::Error::corrupted_key(key, value.into(), trc::location!()))
}

#[derive(Default)]
struct AccountCounters {
    groups: [u64; CHANGE_GROUPS],
    document_ids: [Option<u32>; Collection::COUNT],
}

impl AccountCounters {
    async fn read(store: &Store, account_id: u32) -> model::Result<Self> {
        let groups = ChangeGroups::new();
        let mut counters = AccountCounters::default();
        let prefix = account_prefix(CounterKind::ChangeId, account_id);
        store
            .iterate(counter_range(&prefix, 1), |key, value| {
                if let Some(&[group]) = key.strip_prefix(prefix.as_slice())
                    && groups.contains(group)
                    && let Some(slot) = counters.groups.get_mut(usize::from(group))
                {
                    *slot = u64::try_from(counter_value(key, value)?).unwrap_or_default();
                }
                Ok(true)
            })
            .await
            .map_err(trc_error)?;
        let prefix = account_prefix(CounterKind::DocumentId, account_id);
        store
            .iterate(counter_range(&prefix, 1), |key, value| {
                if let Some(&[collection]) = key.strip_prefix(prefix.as_slice())
                    && let Some(slot) = Collection::from_u8(collection).and_then(|collection| {
                        counters
                            .document_ids
                            .get_mut(usize::from(collection.as_u8()))
                    })
                    && let Ok(value) = u32::try_from(counter_value(key, value)?)
                    && value > 0
                {
                    *slot = Some(value);
                }
                Ok(true)
            })
            .await
            .map_err(trc_error)?;
        Ok(counters)
    }

    fn highest(&self) -> u64 {
        self.groups.iter().copied().max().unwrap_or_default()
    }

    fn of(&self, collection: SyncCollection) -> u64 {
        self.groups
            .get(usize::from(collection.change_group().to_u8()))
            .copied()
            .unwrap_or_default()
    }
}

const fn log_sync_collection(collection: LogCollection) -> SyncCollection {
    match collection {
        LogCollection::Email | LogCollection::VanishedEmail => SyncCollection::Email,
        LogCollection::Thread => SyncCollection::Thread,
        LogCollection::Calendar | LogCollection::VanishedCalendar => SyncCollection::Calendar,
        LogCollection::AddressBook | LogCollection::VanishedAddressBook => {
            SyncCollection::AddressBook
        }
        LogCollection::FileNode | LogCollection::VanishedFileNode => SyncCollection::FileNode,
        LogCollection::Identity => SyncCollection::Identity,
        LogCollection::EmailSubmission => SyncCollection::EmailSubmission,
        LogCollection::SieveScript => SyncCollection::SieveScript,
        LogCollection::CalendarEventNotification => SyncCollection::CalendarEventNotification,
        LogCollection::ShareNotification => SyncCollection::ShareNotification,
    }
}

pub(super) async fn change_bounds(store: &Store, account_id: u32) -> model::Result<ChangeBounds> {
    let counters = AccountCounters::read(store, account_id).await?;
    let mut bounds = ChangeBounds::uniform(counters.highest());
    for collection in Collection::ALL {
        if let Some((log, _)) = source_log(collection) {
            bounds.set_collection(collection, counters.of(SyncCollection::from(log)));
        }
    }
    for collection in LogCollection::CHANGES {
        bounds.set_log(collection, counters.of(log_sync_collection(collection)));
    }
    Ok(bounds)
}

pub(super) async fn accounts(store: &Store) -> model::Result<Vec<AccountRef>> {
    let groups = ChangeGroups::new();
    let mut accounts: Vec<AccountRef> = Vec::new();
    store
        .iterate(
            counter_range(&[CounterKind::ChangeId.byte()], CHANGE_ID_KEY_LEN - 1),
            |key, value| {
                if key.len() == CHANGE_ID_KEY_LEN {
                    let account_id = key.deserialize_be_u32(1)?;
                    let change_id = match key.last() {
                        Some(group) if groups.contains(*group) => {
                            u64::try_from(counter_value(key, value)?).unwrap_or_default()
                        }
                        _ => 0,
                    };
                    match accounts.last_mut() {
                        Some(last) if last.account_id == account_id => {
                            last.change_counter = last.change_counter.saturating_add(change_id);
                        }
                        _ => accounts.push(AccountRef {
                            account_id,
                            change_counter: change_id,
                        }),
                    }
                }
                Ok(true)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(accounts)
}

pub(super) async fn counters(store: &Store, account_id: u32) -> model::Result<Counters> {
    let account = AccountCounters::read(store, account_id).await?;
    let mut counters = Counters {
        change_id: account.highest(),
        document_ids: account.document_ids,
        ..Counters::default()
    };
    let mailbox = u8::from(V1Collection::Mailbox);
    let mut mailboxes = Vec::new();
    let mut after = None;
    loop {
        let page = keys::scan(
            store,
            account_id,
            mailbox,
            &ValueClass::Property(types::field::Field::ARCHIVE.into()),
            after,
            1024,
        )
        .await?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(*last);
        mailboxes.extend(page.into_iter().map(|(id, _)| id));
    }
    if mailboxes.is_empty() {
        return Ok(counters);
    }
    let mut uids: Vec<(u32, u32)> = Vec::with_capacity(mailboxes.len());
    let prefix = account_prefix(CounterKind::MailboxUid, account_id);
    store
        .iterate(counter_range(&prefix, U32_LEN), |key, value| {
            if key.len() == MAILBOX_UID_KEY_LEN && key.starts_with(&prefix) {
                let mailbox_id = key.deserialize_be_u32(prefix.len())?;
                let uid = u32::try_from(counter_value(key, value)?).unwrap_or_default();
                uids.push((mailbox_id, uid));
            }
            Ok(true)
        })
        .await
        .map_err(trc_error)?;
    counters.mailbox_uids = mailboxes
        .into_iter()
        .map(|mailbox_id| MailboxUid {
            mailbox_id,
            uid: uids
                .binary_search_by_key(&mailbox_id, |(id, _)| *id)
                .ok()
                .and_then(|index| uids.get(index))
                .map_or(0, |(_, uid)| *uid),
        })
        .collect();
    Ok(counters)
}

fn principal_key(account_id: u32, field: PrincipalField) -> ValueKey<ValueClass> {
    ValueKey::property(
        account_id,
        V1Collection::Principal,
        PRINCIPAL_DOCUMENT,
        field,
    )
}

pub(super) async fn pointers(store: &Store, account_id: u32) -> model::Result<AccountPointers> {
    let participant_identities = match get::<Archive<ArchiveBytes>>(
        store,
        principal_key(account_id, PrincipalField::ParticipantIdentities),
    )
    .await?
    {
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
    let push_subscriptions = match get::<Archive<ArchiveBytes>>(
        store,
        principal_key(account_id, PrincipalField::PushSubscriptions),
    )
    .await?
    {
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
            get::<u32>(
                store,
                principal_key(account_id, PrincipalField::ActiveScriptId),
            )
            .await?,
        ),
        default_calendar: Pointer::Set(
            get::<u32>(
                store,
                principal_key(account_id, PrincipalField::DefaultCalendarId),
            )
            .await?,
        ),
        default_address_book: Pointer::Set(
            get::<u32>(
                store,
                principal_key(account_id, PrincipalField::DefaultAddressBookId),
            )
            .await?,
        ),
        identity_addresses_hash: Pointer::Set(
            get::<u64>(
                store,
                principal_key(account_id, PrincipalField::IdentityAddresses),
            )
            .await?,
        ),
        participant_identities: Pointer::Set(participant_identities),
        push_subscriptions: Pointer::Set(Some(push_subscriptions)),
    })
}

fn push_record(subscription: PushSubscription) -> PushRecord {
    let mut types: Vec<Box<str>> = subscription
        .types
        .map(|data_type| Box::from(data_type.as_str()))
        .collect();
    types.sort_unstable();
    PushRecord {
        id: subscription.id,
        url: subscription.url,
        device_client_id: subscription.device_client_id,
        expires: subscription.expires,
        verification_code: subscription.verification_code,
        verified: subscription.verified,
        types,
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

fn email_push(push: EmailPush) -> EmailPushRecord {
    EmailPushRecord {
        account_id: push.account_id,
        properties: push
            .properties
            .iter()
            .map(|property| {
                EmailProperty::from(property)
                    .to_cow()
                    .into_owned()
                    .into_boxed_str()
            })
            .collect(),
        filter: serde_json::Value::Null,
        urgency: push.urgency.as_str().into(),
    }
}
