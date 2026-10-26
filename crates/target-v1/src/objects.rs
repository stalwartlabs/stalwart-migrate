/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    auth::ChangedBy,
    storage::index::{
        IndexableAndSerializableObject, IndexableObject, ObjectIndexBuilder, SerializableObject,
    },
};
use store::{
    ValueKey,
    rkyv::{
        Archive as RkyvArchive, Deserialize as RkyvDeserialize,
        api::high::{HighDeserializer, HighValidator},
        bytecheck::CheckBytes,
        rancor,
    },
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use trc::AddContext;
use types::collection::Collection;

use crate::{error::trc_error, target::V1Target};

impl V1Target {
    pub(crate) async fn current_archive(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> model::Result<Option<Archive<ArchiveBytes>>> {
        self.store
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                collection,
                document_id,
            ))
            .await
            .map_err(trc_error)
    }
}

pub(crate) fn write_object<T>(
    batch: &mut BatchBuilder,
    collection: Collection,
    document_id: u32,
    current: Option<&Archive<ArchiveBytes>>,
    object: T,
    changed_by: ChangedBy,
) -> trc::Result<()>
where
    T: IndexableAndSerializableObject + SerializableObject + RkyvArchive + 'static,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + RkyvDeserialize<T, HighDeserializer<rancor::Error>>,
    for<'a> &'a T::Archived: IndexableObject,
{
    batch.with_collection(collection).with_document(document_id);
    match current {
        Some(current) => {
            let current = current.to_unarchived::<T>().caused_by(trc::location!())?;
            batch.custom(
                ObjectIndexBuilder::new()
                    .with_current(current)
                    .with_changes(object)
                    .with_changed_by(changed_by),
            )?;
        }
        None => {
            batch.custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(object)
                    .with_changed_by(changed_by),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn delete_object<T>(
    batch: &mut BatchBuilder,
    collection: Collection,
    document_id: u32,
    current: &Archive<ArchiveBytes>,
    changed_by: ChangedBy,
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
