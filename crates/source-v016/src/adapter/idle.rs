/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{ffi::OsString, fs::Metadata, path::PathBuf, time::SystemTime};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const WAL_SUFFIX: &str = "-wal";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IdleSqlite {
    path: PathBuf,
    wal: PathBuf,
    state: FileState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileState {
    size: u64,
    modified: Option<SystemTime>,
    inode: u64,
}

impl FileState {
    fn of(metadata: &Metadata) -> Self {
        FileState {
            size: metadata.len(),
            modified: metadata.modified().ok(),
            inode: inode(metadata),
        }
    }
}

#[cfg(unix)]
fn inode(metadata: &Metadata) -> u64 {
    metadata.ino()
}

#[cfg(not(unix))]
fn inode(_metadata: &Metadata) -> u64 {
    0
}

const OPEN_ATTEMPTS: usize = 3;

#[cfg(feature = "sqlite")]
pub(super) fn open_sqlite(
    config: registry::schema::structs::SqliteStore,
) -> Result<(store::Store, Option<IdleSqlite>), crate::OpenError> {
    use store::backend::sqlite::{SqliteStore, main::SqliteReadOnlyMode};
    for _ in 0..OPEN_ATTEMPTS {
        let before = IdleSqlite::capture(&config.path);
        let (store, mode) =
            SqliteStore::open_read_only(config.clone()).map_err(crate::OpenError)?;
        match mode {
            SqliteReadOnlyMode::Live => return Ok((store, None)),
            SqliteReadOnlyMode::Immutable => {
                if let Some(before) = before
                    && IdleSqlite::capture(&config.path).as_ref() == Some(&before)
                {
                    return Ok((store, Some(before)));
                }
            }
        }
    }
    Err(crate::OpenError(format!(
        "the SQLite source {} kept changing while it was opened; stop every v0.16 server and rerun",
        config.path
    )))
}

impl IdleSqlite {
    pub(super) fn capture(path: &str) -> Option<Self> {
        let path = std::fs::canonicalize(path).ok()?;
        let mut wal = OsString::from(path.as_os_str());
        wal.push(WAL_SUFFIX);
        let wal = PathBuf::from(wal);
        if wal.exists() {
            return None;
        }
        let state = FileState::of(&std::fs::metadata(&path).ok()?);
        Some(IdleSqlite { path, wal, state })
    }

    pub(super) fn check(&self) -> model::Result<()> {
        let unchanged = !self.wal.exists()
            && std::fs::metadata(&self.path)
                .is_ok_and(|metadata| FileState::of(&metadata) == self.state);
        if unchanged {
            Ok(())
        } else {
            Err(model::Error::fatal(format!(
                "the SQLite source {} changed after it was opened: a v0.16 server started, or another process (sqlite3, a backup tool) opened it and created a -wal file; stop every process using it and rerun",
                self.path.display()
            )))
        }
    }
}
