/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    iter,
    path::{Path, PathBuf},
};

use crate::precheck::has_entries;

const LOST_FOUND: &str = "lost+found";
const SQLITE_SIBLINGS: [&str; 3] = ["-wal", "-shm", "-journal"];

pub(crate) enum OwnedPaths {
    None,
    Directory { path: PathBuf, include_root: bool },
    File(PathBuf),
}

impl OwnedPaths {
    pub(crate) fn directory(path: &Path) -> Self {
        OwnedPaths::Directory {
            path: path.to_path_buf(),
            include_root: !has_entries(path),
        }
    }

    pub(crate) fn file(path: &Path) -> Self {
        OwnedPaths::File(path.to_path_buf())
    }

    pub(crate) fn list(&self) -> Vec<PathBuf> {
        match self {
            OwnedPaths::None => Vec::new(),
            OwnedPaths::Directory {
                path,
                include_root: true,
            } => vec![path.clone()],
            OwnedPaths::Directory {
                path,
                include_root: false,
            } => std::fs::read_dir(path)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|entry| entry.file_name() != LOST_FOUND)
                        .map(|entry| entry.path())
                        .collect()
                })
                .unwrap_or_default(),
            OwnedPaths::File(path) => iter::once(path.clone())
                .chain(SQLITE_SIBLINGS.iter().map(|suffix| {
                    let mut sibling = path.as_os_str().to_owned();
                    sibling.push(suffix);
                    PathBuf::from(sibling)
                }))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedPaths;

    // An existing empty directory (a mounted volume) is owned as a whole; a directory that already holds the store has its entries owned, including files created by later runs, but never itself or lost+found.
    #[test]
    fn owned_paths_follow_the_store_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        std::fs::create_dir(&data).expect("data");
        std::fs::create_dir(data.join("lost+found")).expect("lost+found");
        let empty = OwnedPaths::directory(&data);
        std::fs::write(data.join("CURRENT"), b"MANIFEST-1").expect("current");
        assert_eq!(empty.list(), vec![data.clone()]);

        let populated = OwnedPaths::directory(&data);
        std::fs::write(data.join("000009.sst"), b"sst").expect("sst");
        let mut listed = populated.list();
        listed.sort();
        assert_eq!(listed, vec![data.join("000009.sst"), data.join("CURRENT")]);

        let missing = OwnedPaths::directory(&dir.path().join("missing"));
        assert_eq!(missing.list(), vec![dir.path().join("missing")]);

        let file = OwnedPaths::file(&dir.path().join("target.db"));
        assert_eq!(file.list().len(), 4);
        assert_eq!(file.list()[1], dir.path().join("target.db-wal"));
    }
}
