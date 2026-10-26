/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod codec;
mod ops;
mod schema;
mod writer;

use std::{
    fs::{DirBuilder, File, TryLockError},
    future::Future,
    ops::Range,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::mpsc,
    thread::JoinHandle,
};

use model::{BlobHash, GlobalCategory, GlobalKey, IssueKind, RegistryKey, TelemetryKind};
use rusqlite::{Connection, OpenFlags};
use tokio::sync::oneshot;

use crate::{
    error::{Error, Result},
    store::StateStore,
    types::{
        AccountState, AccountUpdate, CursorMode, CursorRow, FailedDocument, MetaKey, PhaseCount,
        RegistryState, RegistryUpdate, ReportCount, ReportFilter, ReportRow, ReportsAdded, RunId,
        RunMode, RunRecord, RunStart, RunStatus,
    },
};

use writer::{Access, Job, Task};

pub const STATE_FILE: &str = "state.sqlite";
pub const LOCK_FILE: &str = "state.lock";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIR_MODE: u32 = 0o700;

pub struct SqliteState {
    jobs: Option<mpsc::Sender<Box<dyn Job>>>,
    worker: Option<JoinHandle<()>>,
    path: PathBuf,
    lock: Option<File>,
}

impl SqliteState {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(dir.as_ref(), OpenMode::Create)
    }

    pub fn open_existing(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(dir.as_ref(), OpenMode::Existing)
    }

    pub fn open_read_only(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(dir.as_ref(), OpenMode::ReadOnly)
    }

    pub fn open_exclusive(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        create_private_dir(dir)?;
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(PRIVATE_FILE_MODE)
            .open(dir.join(LOCK_FILE))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::Locked(dir.display().to_string().into_boxed_str()));
            }
            Err(TryLockError::Error(err)) => return Err(err.into()),
        }
        let mut state = Self::open_inner(dir, OpenMode::Create)?;
        state.lock = Some(lock);
        Ok(state)
    }

    fn open_inner(dir: &Path, mode: OpenMode) -> Result<Self> {
        let path = dir.join(STATE_FILE);
        let flags = match mode {
            OpenMode::Create => {
                create_private_dir(dir)?;
                File::options()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .mode(PRIVATE_FILE_MODE)
                    .open(&path)?;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            }
            OpenMode::Existing | OpenMode::ReadOnly => {
                if !path.is_file() {
                    return Err(Error::Missing(path.display().to_string().into_boxed_str()));
                }
                match mode {
                    OpenMode::ReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
                    _ => OpenFlags::SQLITE_OPEN_READ_WRITE,
                }
            }
        };
        let (conn, access) = match mode {
            OpenMode::ReadOnly => (open_read_only(&path, flags)?, Access::ReadOnly),
            OpenMode::Create | OpenMode::Existing => {
                let conn =
                    Connection::open_with_flags(&path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
                schema::initialize(&conn)?;
                (conn, Access::ReadWrite)
            }
        };
        let (jobs, receiver) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("state-writer".into())
            .spawn(move || writer::run(conn, receiver, access))?;
        Ok(SqliteState {
            jobs: Some(jobs),
            worker: Some(worker),
            path,
            lock: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn call<R, F>(&self, f: F) -> impl Future<Output = Result<R>> + Send + use<R, F>
    where
        F: FnOnce(&Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let (reply, receiver) = oneshot::channel();
        let sent = match &self.jobs {
            Some(jobs) => jobs
                .send(Box::new(Task::new(f, reply)))
                .map_err(|_| Error::Closed),
            None => Err(Error::Closed),
        };
        async move {
            sent?;
            receiver.await.map_err(|_| Error::Closed)?
        }
    }
}

impl Drop for SqliteState {
    fn drop(&mut self) {
        drop(self.jobs.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        drop(self.lock.take());
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(dir)?;
    }
    Ok(())
}

fn open_read_only(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let shared = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(Error::from)
        .and_then(|conn| schema::check_readable(&conn).map(|()| conn));
    match shared {
        Ok(conn) => Ok(conn),
        Err(Error::Sqlite(_)) => {
            let conn = Connection::open_with_flags(
                immutable_uri(path),
                flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
            )?;
            schema::check_readable(&conn)?;
            Ok(conn)
        }
        Err(err) => Err(err),
    }
}

fn immutable_uri(path: &Path) -> String {
    let text = path.to_string_lossy();
    let mut uri = String::with_capacity(text.len() + 20);
    uri.push_str("file:");
    for ch in text.chars() {
        match ch {
            '?' => uri.push_str("%3f"),
            '#' => uri.push_str("%23"),
            '%' => uri.push_str("%25"),
            _ => uri.push(ch),
        }
    }
    uri.push_str("?immutable=1");
    uri
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenMode {
    Create,
    Existing,
    ReadOnly,
}

impl StateStore for SqliteState {
    fn meta(&self, key: MetaKey) -> impl Future<Output = Result<Option<String>>> + Send {
        self.call(move |conn| ops::meta(conn, key))
    }

    fn set_meta(&self, key: MetaKey, value: String) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::set_meta(conn, key, &value))
    }

    fn remove_meta(&self, key: MetaKey) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::remove_meta(conn, key))
    }

    fn begin_run(&self, mode: RunMode) -> impl Future<Output = Result<RunStart>> + Send {
        self.call(move |conn| ops::begin_run(conn, mode))
    }

    fn finish_run(
        &self,
        run_id: RunId,
        status: RunStatus,
        stats: String,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::finish_run(conn, run_id, status, &stats))
    }

    fn runs(&self, limit: u32) -> impl Future<Output = Result<Vec<RunRecord>>> + Send {
        self.call(move |conn| ops::runs(conn, limit))
    }

    fn last_run_except(
        &self,
        mode: RunMode,
        before: RunId,
    ) -> impl Future<Output = Result<Option<RunRecord>>> + Send {
        self.call(move |conn| ops::last_run_except(conn, mode, before))
    }

    fn account(
        &self,
        account_id: u32,
    ) -> impl Future<Output = Result<Option<AccountState>>> + Send {
        self.call(move |conn| ops::account(conn, account_id))
    }

    fn accounts(&self) -> impl Future<Output = Result<Vec<AccountState>>> + Send {
        self.call(ops::accounts)
    }

    fn phase_counts(&self) -> impl Future<Output = Result<Vec<PhaseCount>>> + Send {
        self.call(ops::phase_counts)
    }

    fn failed_accounts(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AccountState>>> + Send {
        self.call(move |conn| ops::failed_accounts(conn, limit))
    }

    fn update_account(&self, update: AccountUpdate) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::update_account(conn, &update))
    }

    fn cursors(&self, account_id: u32) -> impl Future<Output = Result<Vec<CursorRow>>> + Send {
        self.call(move |conn| ops::cursors(conn, account_id))
    }

    fn set_cursor(
        &self,
        account_id: u32,
        collection: u8,
        mode: CursorMode,
        last_id: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::set_cursor(conn, account_id, collection, mode, last_id))
    }

    fn registry_states(
        &self,
        object: Box<str>,
    ) -> impl Future<Output = Result<Vec<RegistryState>>> + Send {
        self.call(move |conn| ops::registry_states(conn, &object))
    }

    fn registry_objects(&self) -> impl Future<Output = Result<Vec<Box<str>>>> + Send {
        self.call(ops::registry_objects)
    }

    fn registry_sample(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<RegistryState>>> + Send {
        self.call(move |conn| ops::registry_sample(conn, limit))
    }

    fn put_registry(
        &self,
        run_id: RunId,
        updates: Vec<RegistryUpdate>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::put_registry(conn, run_id, &updates))
    }

    fn remove_registry(&self, keys: Vec<RegistryKey>) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::remove_registry(conn, &keys))
    }

    fn registry_source_json(
        &self,
        key: RegistryKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        self.call(move |conn| ops::registry_source_json(conn, &key))
    }

    fn set_registry_fallbacks(
        &self,
        fell_back: Vec<RegistryKey>,
        cleared: Vec<RegistryKey>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::set_registry_fallbacks(conn, &fell_back, &cleared))
    }

    fn registry_fallbacks(&self) -> impl Future<Output = Result<Vec<RegistryKey>>> + Send {
        self.call(ops::registry_fallbacks)
    }

    fn set_registry_pending(
        &self,
        added: Vec<RegistryKey>,
        cleared: Vec<RegistryKey>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::set_registry_pending(conn, &added, &cleared))
    }

    fn registry_pending(&self) -> impl Future<Output = Result<Vec<RegistryKey>>> + Send {
        self.call(ops::registry_pending)
    }

    fn blobs_known(&self, hashes: Vec<BlobHash>) -> impl Future<Output = Result<Vec<bool>>> + Send {
        self.call(move |conn| ops::blobs_known(conn, &hashes))
    }

    fn add_blobs(
        &self,
        run_id: RunId,
        blobs: Vec<(BlobHash, u64)>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::add_blobs(conn, run_id, &blobs))
    }

    fn global_cursor(
        &self,
        name: Box<str>,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        self.call(move |conn| ops::global_cursor(conn, &name))
    }

    fn set_global_cursor(
        &self,
        name: Box<str>,
        value: Vec<u8>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::set_global_cursor(conn, &name, &value))
    }

    fn track_globals(
        &self,
        generation: RunId,
        keys: Vec<GlobalKey>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::track_globals(conn, generation, &keys))
    }

    fn stale_globals(
        &self,
        category: GlobalCategory,
        generation: RunId,
        after: Option<GlobalKey>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<GlobalKey>>> + Send {
        self.call(move |conn| ops::stale_globals(conn, category, generation, after, limit))
    }

    fn forget_globals(&self, keys: Vec<GlobalKey>) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::forget_globals(conn, &keys))
    }

    fn telemetry_seen(
        &self,
        keys: Vec<(TelemetryKind, u64)>,
    ) -> impl Future<Output = Result<Vec<bool>>> + Send {
        self.call(move |conn| ops::telemetry_seen(conn, &keys))
    }

    fn see_telemetry(
        &self,
        keys: Vec<(TelemetryKind, u64)>,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::see_telemetry(conn, &keys))
    }

    fn prune_telemetry(
        &self,
        kind: TelemetryKind,
        window: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        self.call(move |conn| ops::prune_telemetry(conn, kind, window))
    }

    fn add_reports(
        &self,
        rows: Vec<ReportRow>,
    ) -> impl Future<Output = Result<ReportsAdded>> + Send {
        self.call(move |conn| ops::add_reports(conn, &rows))
    }

    fn reports(&self, filter: ReportFilter) -> impl Future<Output = Result<Vec<ReportRow>>> + Send {
        self.call(move |conn| ops::reports(conn, &filter))
    }

    fn report_counts(
        &self,
        run_id: Option<RunId>,
    ) -> impl Future<Output = Result<Vec<ReportCount>>> + Send {
        self.call(move |conn| ops::report_counts(conn, run_id))
    }

    fn failed_documents(
        &self,
        after_run: RunId,
        from: Option<FailedDocument>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<FailedDocument>>> + Send {
        self.call(move |conn| ops::failed_documents(conn, after_run, from, limit))
    }

    fn account_errors(
        &self,
        after_run: RunId,
        kind: IssueKind,
    ) -> impl Future<Output = Result<u64>> + Send {
        self.call(move |conn| ops::account_errors(conn, after_run, kind))
    }

    fn global_errors(
        &self,
        runs: Range<RunId>,
        object: Box<str>,
    ) -> impl Future<Output = Result<u64>> + Send {
        self.call(move |conn| ops::global_errors(conn, runs, &object))
    }
}

#[cfg(test)]
mod tests;
