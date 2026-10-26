/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    auth::AccountTenantIds,
    storage::index::{IndexableAndSerializableObject, IndexableObject, ObjectIndexBuilder},
};
use model::WriteMode;
use store::{
    ValueKey,
    rkyv::{
        Archive as RkyvArchive, Deserialize as RkyvDeserialize,
        api::high::{HighDeserializer, HighValidator},
        bytecheck::CheckBytes,
        rancor,
    },
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::collection::Collection;

use crate::{error::trc_error, target::V016Target};

pub(crate) type StoredArchive = Archive<AlignedBytes>;

pub(crate) const IMPORT_CHANGE_ID: u64 = 1;

impl V016Target {
    pub(crate) async fn current_archive(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> model::Result<Option<StoredArchive>> {
        self.store
            .get_value::<StoredArchive>(ValueKey::archive(account_id, collection, document_id))
            .await
            .map_err(trc_error)
    }

    pub(crate) async fn existing(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        mode: WriteMode,
    ) -> model::Result<Option<StoredArchive>> {
        if mode == WriteMode::Create {
            Ok(None)
        } else {
            self.current_archive(account_id, collection, document_id)
                .await
        }
    }
}

pub(crate) fn write_object<T>(
    batch: &mut BatchBuilder,
    collection: Collection,
    document_id: u32,
    current: Option<&StoredArchive>,
    object: T,
    changed_by: AccountTenantIds,
) -> trc::Result<()>
where
    T: IndexableAndSerializableObject + RkyvArchive + 'static,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + RkyvDeserialize<T, HighDeserializer<rancor::Error>>,
    for<'a> &'a T::Archived: IndexableObject,
{
    let change_id = T::is_versioned().then_some(IMPORT_CHANGE_ID);
    batch.with_collection(collection).with_document(document_id);
    match current {
        Some(current) => {
            let current = current.to_unarchived::<T>().caused_by(trc::location!())?;
            batch.custom(
                ObjectIndexBuilder::new()
                    .with_current(current)
                    .with_changes(object)
                    .with_changed_by(changed_by)
                    .with_change_id(change_id),
            )?;
        }
        None => {
            batch.custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(object)
                    .with_changed_by(changed_by)
                    .with_change_id(change_id),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn delete_object<T>(
    batch: &mut BatchBuilder,
    collection: Collection,
    document_id: u32,
    current: &StoredArchive,
    changed_by: AccountTenantIds,
) -> trc::Result<()>
where
    T: RkyvArchive,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + RkyvDeserialize<T, HighDeserializer<rancor::Error>>,
    for<'a> &'a T::Archived: IndexableObject,
{
    let current = current.to_unarchived::<T>().caused_by(trc::location!())?;
    batch
        .with_collection(collection)
        .with_document(document_id)
        .custom(
            ObjectIndexBuilder::<_, ()>::new()
                .with_current(current)
                .with_changed_by(changed_by),
        )?;
    Ok(())
}
