/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{ChangeSet, Collection, FileNodeRecord, RecordBatch, Source, Target, WriteMode};
use rustc_hash::FxHashMap;
use state::StateStore;

use super::{
    AccountJob,
    collection::{Existing, ScanFilter},
    reader::advance,
};
use crate::orchestrator::{RegistryConverter, error::RunError, retry::retry};

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'_, S, T, St, C> {
    pub(super) async fn copy_file_tree(&mut self, existing: Existing) -> Result<(), RunError> {
        let directories = self.read_directories().await?;
        self.write_files(directories, WriteMode::Replace).await?;
        self.scan_collection(Collection::FileNode, ScanFilter::FilesOnly, existing)
            .await
    }

    async fn read_directories(&mut self) -> Result<Vec<FileNodeRecord>, RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let limit = context.options.tuning.batch_ops;
        let mut directories = Vec::new();
        let mut after = None;
        loop {
            context.check_shutdown()?;
            context.rate.acquire(limit).await;
            let page = retry(context.policy(), || {
                context
                    .source
                    .scan(account_id, Collection::FileNode, after, limit)
            })
            .await?;
            let Some(last) = advance(&page, Collection::FileNode, after)? else {
                return Ok(directories);
            };
            after = Some(last);
            let RecordBatch::FileNode(records) = page.batch else {
                return Ok(directories);
            };
            directories.extend(records.into_iter().filter(|record| record.file.is_none()));
        }
    }

    pub(super) async fn apply_file_changes(&mut self, changes: &ChangeSet) -> Result<(), RunError> {
        let changed = &changes.inserted | &changes.updated;
        let mut directories = Vec::new();
        let mut files = Vec::new();
        let mut pending = changed.iter();
        while let Some(batch) = self.read_next(Collection::FileNode, &mut pending).await? {
            if let RecordBatch::FileNode(records) = batch {
                for record in records {
                    if record.file.is_none() {
                        directories.push(record);
                    } else {
                        files.push(record);
                    }
                }
            }
        }
        self.write_files(directories, WriteMode::Replace).await?;
        let mut files = RecordBatch::FileNode(files);
        self.write_chunked(&mut files, WriteMode::Replace).await
    }

    async fn write_files(
        &mut self,
        mut directories: Vec<FileNodeRecord>,
        mode: WriteMode,
    ) -> Result<(), RunError> {
        sort_by_depth(&mut directories);
        let mut batch = RecordBatch::FileNode(directories);
        self.write_chunked(&mut batch, mode).await
    }
}

pub(super) fn sort_by_depth(directories: &mut [FileNodeRecord]) {
    let parents: FxHashMap<u32, Option<u32>> = directories
        .iter()
        .map(|record| (record.document_id, record.parent_id))
        .collect();
    let limit = parents.len();
    let mut depths: FxHashMap<u32, usize> = FxHashMap::default();
    let mut chain = Vec::new();
    for record in directories.iter() {
        chain.clear();
        let mut current = Some(record.document_id);
        let mut base = 0;
        while let Some(id) = current {
            if let Some(depth) = depths.get(&id) {
                base = depth + 1;
                break;
            }
            if chain.len() > limit {
                break;
            }
            chain.push(id);
            current = parents
                .get(&id)
                .copied()
                .flatten()
                .filter(|parent| parents.contains_key(parent));
        }
        for (offset, id) in chain.iter().rev().enumerate() {
            depths.entry(*id).or_insert(base + offset);
        }
    }
    directories.sort_unstable_by_key(|record| {
        (
            depths.get(&record.document_id).copied().unwrap_or_default(),
            record.document_id,
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(id: u32, parent: Option<u32>) -> FileNodeRecord {
        FileNodeRecord {
            document_id: id,
            parent_id: parent,
            ..Default::default()
        }
    }

    #[test]
    fn parents_come_before_children() {
        let mut dirs = vec![
            dir(1, Some(5)),
            dir(2, None),
            dir(5, Some(9)),
            dir(9, None),
            dir(7, Some(1)),
            dir(8, Some(100)),
            dir(3, Some(4)),
            dir(4, Some(3)),
        ];
        sort_by_depth(&mut dirs);
        let position = |id: u32| {
            dirs.iter()
                .position(|record| record.document_id == id)
                .expect("present")
        };
        assert!(position(9) < position(5));
        assert!(position(5) < position(1));
        assert!(position(1) < position(7));
        assert_eq!(dirs.len(), 8);
        assert!(position(2) < position(5));
        assert!(position(8) < position(5));
    }
}
