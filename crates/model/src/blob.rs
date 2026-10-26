/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;

use crate::ids::BlobHash;

#[derive(Debug, Clone, Default)]
pub struct BlobCache {
    entries: Vec<(BlobHash, Bytes)>,
    bytes: u64,
}

impl BlobCache {
    pub fn from_entries(mut entries: Vec<(BlobHash, Bytes)>) -> Self {
        entries.sort_unstable_by_key(|(hash, _)| *hash);
        entries.dedup_by_key(|(hash, _)| *hash);
        let bytes = entries.iter().map(|(_, data)| data.len() as u64).sum();
        BlobCache { entries, bytes }
    }

    pub fn get(&self, hash: &BlobHash) -> Option<&Bytes> {
        self.entries
            .binary_search_by_key(hash, |(entry, _)| *entry)
            .ok()
            .and_then(|index| self.entries.get(index))
            .map(|(_, data)| data)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn iter(&self) -> impl Iterator<Item = (&BlobHash, &Bytes)> {
        self.entries.iter().map(|(hash, data)| (hash, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lookups find every kept blob regardless of insertion order, and duplicates are kept once.
    #[test]
    fn blob_cache_finds_kept_blobs() {
        let blob = |byte: u8| {
            (
                BlobHash([byte; 32]),
                Bytes::from(vec![byte; usize::from(byte)]),
            )
        };
        let cache = BlobCache::from_entries(vec![blob(9), blob(3), blob(7), blob(3)]);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.bytes(), 19);
        for byte in [3, 7, 9] {
            assert_eq!(cache.get(&BlobHash([byte; 32])), Some(&blob(byte).1));
        }
        assert!(cache.get(&BlobHash([4; 32])).is_none());
        assert!(BlobCache::default().get(&BlobHash([3; 32])).is_none());
    }
}
