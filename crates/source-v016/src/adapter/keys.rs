/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    Deserialize, IterateParams, Store, U32_LEN, ValueKey,
    write::{AlignedBytes, Archive, ValueClass, key::DeserializeBigEndian},
};
use tokio::task::JoinSet;
use types::field::Field;

use super::error::trc_error;

pub(super) fn archive_key(
    account_id: u32,
    collection: u8,
    document_id: u32,
) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection,
        document_id,
        class: ValueClass::Property(Field::ARCHIVE.into()),
    }
}

pub(super) type ArchiveResult = model::Result<Archive<AlignedBytes>>;

struct RawBytes(Vec<u8>);

impl Deserialize for RawBytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawBytes(bytes.to_vec()))
    }
}

fn decode_archive(value: &[u8]) -> ArchiveResult {
    <Archive<AlignedBytes> as Deserialize>::deserialize(value).map_err(trc_error)
}

pub(super) async fn scan_archives(
    store: &Store,
    account_id: u32,
    collection: u8,
    after: Option<u32>,
    limit: usize,
) -> model::Result<Vec<(u32, ArchiveResult)>> {
    let first = match after {
        Some(u32::MAX) => return Ok(Vec::new()),
        Some(after) => after + 1,
        None => 0,
    };
    let limit = limit.max(1);
    let mut archives = Vec::with_capacity(limit.min(1024));
    store
        .iterate(
            IterateParams::new(
                archive_key(account_id, collection, first),
                archive_key(account_id, collection, u32::MAX),
            )
            .ascending()
            .with_limit(limit),
            |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                archives.push((document_id, decode_archive(value)));
                Ok(archives.len() < limit)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(archives)
}

pub(super) async fn get_property<T: Deserialize + 'static>(
    store: &Store,
    account_id: u32,
    collection: u8,
    document_id: u32,
    field: u8,
) -> model::Result<Option<T>> {
    store
        .get_value::<T>(ValueKey::property(
            account_id,
            collection,
            document_id,
            field,
        ))
        .await
        .map_err(trc_error)
}

pub(super) async fn scan_property_archives(
    store: &Store,
    account_id: u32,
    collection: u8,
    field: u8,
    first: u32,
    last: u32,
) -> model::Result<Vec<(u32, ArchiveResult)>> {
    let mut archives = Vec::new();
    store
        .iterate(
            IterateParams::new(
                ValueKey::property(account_id, collection, first, field),
                ValueKey::property(account_id, collection, last, field),
            )
            .ascending(),
            |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                archives.push((document_id, decode_archive(value)));
                Ok(true)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(archives)
}

const FETCH_CONCURRENCY: usize = 16;

pub(super) async fn fetch_many(
    store: &Store,
    account_id: u32,
    collection: u8,
    field: u8,
    ids: &[u32],
) -> model::Result<Vec<(u32, ArchiveResult)>> {
    let mut found: Vec<(usize, u32, ArchiveResult)> = Vec::with_capacity(ids.len());
    let mut tasks = JoinSet::new();
    let mut pending = ids.iter().copied().enumerate();
    loop {
        while tasks.len() < FETCH_CONCURRENCY {
            let Some((position, document_id)) = pending.next() else {
                break;
            };
            let store = store.clone();
            tasks.spawn(async move {
                let archive = store
                    .get_value::<RawBytes>(ValueKey::property(
                        account_id,
                        collection,
                        document_id,
                        field,
                    ))
                    .await;
                (position, document_id, archive)
            });
        }
        let Some(joined) = tasks.join_next().await else {
            break;
        };
        let (position, document_id, archive) =
            joined.map_err(|err| model::Error::transient(err.to_string()))?;
        if let Some(bytes) = archive.map_err(trc_error)? {
            found.push((position, document_id, decode_archive(&bytes.0)));
        }
    }
    found.sort_unstable_by_key(|(position, _, _)| *position);
    Ok(found
        .into_iter()
        .map(|(_, document_id, archive)| (document_id, archive))
        .collect())
}
