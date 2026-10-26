/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::hash::Hash;

use store::{
    Deserialize, IterateParams, Key, Subspace, ValueKey,
    ahash::{AHashMap, AHashSet},
    write::ValueClass,
};

use crate::{error::trc_error, target::V1Target};

pub(crate) struct Prefetched(AHashMap<(Subspace, Vec<u8>), Vec<u8>>);

impl Prefetched {
    pub(crate) fn get<T: Deserialize>(&self, class: ValueClass) -> model::Result<Option<T>> {
        let key = ValueKey::from(class);
        let entry = (key.subspace(), key.serialize(0));
        self.0
            .get(&entry)
            .map(|value| T::deserialize_with_key(&entry.1, value).map_err(trc_error))
            .transpose()
    }

    pub(crate) fn raw(&self, class: ValueClass) -> Option<&[u8]> {
        let key = ValueKey::from(class);
        self.0
            .get(&(key.subspace(), key.serialize(0)))
            .map(Vec::as_slice)
    }
}

pub(crate) fn keep_last<T, K: Eq + Hash>(
    items: impl DoubleEndedIterator<Item = T>,
    key: impl Fn(&T) -> K,
) -> Vec<T> {
    let mut seen = AHashSet::with_capacity(items.size_hint().0);
    let mut kept = items
        .rev()
        .filter(|item| seen.insert(key(item)))
        .collect::<Vec<_>>();
    kept.reverse();
    kept
}

impl V1Target {
    pub(crate) async fn prefetch(
        &self,
        classes: impl Iterator<Item = ValueClass>,
    ) -> model::Result<Prefetched> {
        let mut keys = classes
            .map(|class| {
                let key = ValueKey::from(class);
                ((key.subspace(), key.serialize(0)), key)
            })
            .collect::<Vec<_>>();
        keys.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        keys.dedup_by(|a, b| a.0 == b.0);
        let mut values = AHashMap::with_capacity(keys.len());
        for group in keys.chunk_by(|a, b| a.0.0 == b.0.0) {
            let Some(((subspace, _), _)) = group.first() else {
                continue;
            };
            let subspace = *subspace;
            let ranges = group
                .iter()
                .map(|(_, key)| IterateParams::new(key.clone(), key.clone()))
                .collect();
            self.store
                .iterate_many(ranges, |key, value| {
                    values.insert((subspace, key.to_vec()), value.to_vec());
                    Ok(true)
                })
                .await
                .map_err(trc_error)?;
        }
        Ok(Prefetched(values))
    }
}
