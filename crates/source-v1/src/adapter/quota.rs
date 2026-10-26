/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::{message::messagedata::MessageData, sieve::SieveScript};
use groupware::{
    calendar::{Calendar, CalendarEvent, CalendarEventNotification},
    contact::{AddressBook, ContactCard},
    file::FileNode,
};
use model::{ObjectCountUsage, QuotaUsage};
use registry::schema::enums::StorageQuota;
use store::{
    Deserialize, IterateParams, Store, U32_LEN, ValueKey,
    write::{Archive, ArchiveBytes, ValueClass, metadata::MetadataClass},
};
use types::{collection::Collection, field::Field};

use super::error::{corrupt, trc_error};

const SIZED_COLLECTIONS: [Collection; 9] = [
    Collection::Email,
    Collection::Calendar,
    Collection::CalendarEvent,
    Collection::CalendarEventNotification,
    Collection::AddressBook,
    Collection::ContactCard,
    Collection::FileNode,
    Collection::SieveScript,
    Collection::EmailSubmission,
];
const COUNTED: [(StorageQuota, Collection, &str); 4] = [
    (StorageQuota::MaxEmails, Collection::Email, "emails"),
    (
        StorageQuota::MaxEmailSubmissions,
        Collection::EmailSubmission,
        "email submissions",
    ),
    (
        StorageQuota::MaxCalendarEvents,
        Collection::CalendarEvent,
        "calendar events",
    ),
    (
        StorageQuota::MaxCalendarEventNotifications,
        Collection::CalendarEventNotification,
        "calendar event notifications",
    ),
];
const OWNER_KEY_SUFFIX: usize = U32_LEN + 1;

fn key(
    account_id: u32,
    collection: u8,
    document_id: u32,
    class: ValueClass,
) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection,
        document_id,
        class,
    }
}

fn metadata(
    account_id: u32,
    collection: u8,
    document_id: u32,
    class: MetadataClass,
) -> ValueKey<ValueClass> {
    key(
        account_id,
        collection,
        document_id,
        ValueClass::Metadata(class),
    )
}

fn archived_size(collection: Collection, bytes: &[u8]) -> trc::Result<i64> {
    if collection == Collection::Email {
        return Ok(i64::from(MessageData::deserialize(bytes)?.size));
    }
    let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)?;
    Ok(match collection {
        Collection::Calendar => archive.unarchive::<Calendar>()?.size() as i64,
        Collection::CalendarEvent => {
            i64::from(archive.unarchive::<CalendarEvent>()?.size.to_native())
        }
        Collection::CalendarEventNotification => i64::from(
            archive
                .unarchive::<CalendarEventNotification>()?
                .size
                .to_native(),
        ),
        Collection::AddressBook => archive.unarchive::<AddressBook>()?.size() as i64,
        Collection::ContactCard => i64::from(archive.unarchive::<ContactCard>()?.size.to_native()),
        Collection::FileNode => archive.unarchive::<FileNode>()?.size() as i64,
        Collection::SieveScript => i64::from(u32::from(archive.unarchive::<SieveScript>()?.size)),
        _ => 0,
    })
}

async fn value_bytes(
    store: &Store,
    from: ValueKey<ValueClass>,
    to: ValueKey<ValueClass>,
) -> model::Result<i64> {
    let mut total = 0i64;
    store
        .iterate(IterateParams::new(from, to), |_, value| {
            total = total.saturating_add(value.len() as i64);
            Ok(true)
        })
        .await
        .map_err(trc_error)?;
    Ok(total)
}

async fn metadata_bytes(store: &Store, account_id: u32) -> model::Result<i64> {
    let mut total = value_bytes(
        store,
        metadata(account_id, 0, 0, MetadataClass::Shared),
        metadata(account_id, u8::MAX, u32::MAX, MetadataClass::Shared),
    )
    .await?;
    let mut owners = Vec::new();
    store
        .iterate(
            IterateParams::new(
                metadata(account_id, 0, 0, MetadataClass::Owner { owner: 0 }),
                metadata(
                    account_id,
                    u8::MAX,
                    0,
                    MetadataClass::Owner { owner: u32::MAX },
                ),
            )
            .no_values(),
            |key, _| {
                let owner = key
                    .len()
                    .checked_sub(OWNER_KEY_SUFFIX)
                    .and_then(|offset| key.get(offset..))
                    .and_then(|suffix| suffix.split_first_chunk::<U32_LEN>())
                    .and_then(|(owner, collection)| {
                        Some((u32::from_be_bytes(*owner), *collection.first()?))
                    })
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                owners.push(owner);
                Ok(true)
            },
        )
        .await
        .map_err(trc_error)?;
    let viewer = MetadataClass::Private { viewer: account_id };
    for (owner, collection) in owners {
        total = total.saturating_add(
            value_bytes(
                store,
                metadata(owner, collection, 0, viewer),
                metadata(owner, collection, u32::MAX, viewer),
            )
            .await?,
        );
    }
    Ok(total)
}

pub(super) async fn usage(store: &Store, account_id: u32) -> model::Result<QuotaUsage> {
    let stored = store
        .get_counter(key(account_id, 0, 0, ValueClass::Quota))
        .await
        .map_err(trc_error)?;
    let archive_class = ValueClass::Property(Field::ARCHIVE.into());
    let mut computed = 0i64;
    let mut counts = [0i64; COUNTED.len()];
    for collection in SIZED_COLLECTIONS {
        let code = u8::from(collection);
        let counted = COUNTED
            .iter()
            .position(|(_, counted, _)| *counted == collection);
        let mut failure = None;
        let mut objects = 0i64;
        store
            .iterate(
                IterateParams::new(
                    key(account_id, code, 0, archive_class.clone()),
                    key(account_id, code, u32::MAX, archive_class.clone()),
                ),
                |_, value| match archived_size(collection, value) {
                    Ok(size) => {
                        computed = computed.saturating_add(size);
                        objects += 1;
                        Ok(true)
                    }
                    Err(err) => {
                        failure = Some(err);
                        Ok(false)
                    }
                },
            )
            .await
            .map_err(trc_error)?;
        if let Some(err) = failure {
            return Err(corrupt(format!(
                "account {account_id}: cannot size a {collection:?} object: {err}"
            )));
        }
        if let Some(slot) = counted.and_then(|index| counts.get_mut(index)) {
            *slot = objects;
        }
    }
    computed = computed.saturating_add(metadata_bytes(store, account_id).await?);
    let mut objects = [ObjectCountUsage {
        name: "",
        stored: 0,
        computed: 0,
    }; COUNTED.len()];
    for ((usage, (quota, _, name)), computed) in objects.iter_mut().zip(COUNTED).zip(counts) {
        *usage = ObjectCountUsage {
            name,
            stored: store
                .get_counter(key(account_id, 0, 0, ValueClass::ObjectCount(quota)))
                .await
                .map_err(trc_error)?,
            computed,
        };
    }
    Ok(QuotaUsage {
        stored,
        computed,
        objects,
    })
}
