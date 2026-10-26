/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    IterateParams, Store, U32_LEN, ValueKey,
    write::{ValueClass, key::DeserializeBigEndian, serialize::RawValue},
};
use tokio::task::JoinSet;

use super::error::trc_error;

const FETCH_CONCURRENCY: usize = 16;

pub(super) type RawRows = Vec<(u32, Vec<u8>)>;

fn key(
    account_id: u32,
    collection: u8,
    document_id: u32,
    class: &ValueClass,
) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection,
        document_id,
        class: class.clone(),
    }
}

pub(super) async fn scan(
    store: &Store,
    account_id: u32,
    collection: u8,
    class: &ValueClass,
    after: Option<u32>,
    limit: usize,
) -> model::Result<RawRows> {
    let first = match after {
        Some(u32::MAX) => return Ok(Vec::new()),
        Some(after) => after + 1,
        None => 0,
    };
    let limit = limit.max(1);
    let mut rows = Vec::with_capacity(limit.min(1024));
    store
        .iterate(
            IterateParams::new(
                key(account_id, collection, first, class),
                key(account_id, collection, u32::MAX, class),
            )
            .ascending()
            .limit(limit),
            |key, value| {
                rows.push((key.deserialize_be_u32(key.len() - U32_LEN)?, value.to_vec()));
                Ok(rows.len() < limit)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(rows)
}

pub(super) async fn range(
    store: &Store,
    account_id: u32,
    collection: u8,
    class: &ValueClass,
    first: u32,
    last: u32,
) -> model::Result<RawRows> {
    let mut rows = Vec::new();
    store
        .iterate(
            IterateParams::new(
                key(account_id, collection, first, class),
                key(account_id, collection, last, class),
            )
            .ascending(),
            |key, value| {
                rows.push((key.deserialize_be_u32(key.len() - U32_LEN)?, value.to_vec()));
                Ok(true)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(rows)
}

pub(super) async fn fetch_many(
    store: &Store,
    account_id: u32,
    collection: u8,
    class: &ValueClass,
    ids: &[u32],
) -> model::Result<RawRows> {
    let mut found: Vec<(usize, u32, Vec<u8>)> = Vec::with_capacity(ids.len());
    let mut tasks = JoinSet::new();
    let mut pending = ids.iter().copied().enumerate();
    loop {
        while tasks.len() < FETCH_CONCURRENCY {
            let Some((position, document_id)) = pending.next() else {
                break;
            };
            let store = store.clone();
            let key = key(account_id, collection, document_id, class);
            tasks.spawn(async move {
                let value = store.get_value::<RawValue>(key).await;
                (position, document_id, value)
            });
        }
        let Some(joined) = tasks.join_next().await else {
            break;
        };
        let (position, document_id, value) =
            joined.map_err(|err| model::Error::transient(err.to_string()))?;
        if let Some(RawValue(bytes)) = value.map_err(trc_error)? {
            found.push((position, document_id, bytes));
        }
    }
    found.sort_unstable_by_key(|(position, _, _)| *position);
    Ok(found
        .into_iter()
        .map(|(_, document_id, bytes)| (document_id, bytes))
        .collect())
}

pub(super) async fn get<T: store::Deserialize + 'static>(
    store: &Store,
    key: ValueKey<ValueClass>,
) -> model::Result<Option<T>> {
    store.get_value::<T>(key).await.map_err(trc_error)
}
