/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod fake;

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use fake::{
    FakeConverter, FakeReader, FakeSource, FakeSpamBlob, FakeTarget, Fault, FaultOp, SpamBlobs,
    SwapFault, UNLINKED_OBJECT, address_book, calendar, contact, directory, email, event, file,
    identity, internal_report, mailbox, queued_message, sieve,
};
use mapping::ids::JmapId;
use migrate::{
    commands::{EXIT_INTERRUPTED, run::summary_exit_code},
    orchestrator::{
        AfterFinal, BlobMode, ConversionError, Converted, ConvertedRecord, ErrorPolicy,
        Orchestrator, RecordSide, RegistryConverter, RegistryDeletes, RemovalPolicy, RetryPolicy,
        RunDirection, RunError, RunKind, RunOptions, RunSummary, Tuning,
    },
    shutdown::Shutdown,
};
use model::{
    AccountPointers, BlobHash, Category, CategorySet, ChangeLogRecord, Collection, Counters,
    Edition, Error, GlobalBatch, GlobalKey, Issue, IssueKind, LogCollection, Pointer, RecordBatch,
    RegistryCounter, RegistryKey, RegistryRecord, ReportKind, Result, Severity,
    ShareNotificationRecord, SpamClassifierModel, SpamModelChange, SpamModelKind, SpamModelRecord,
    Subject, Target, TargetProbe, WriteMode, WriteOutcome,
};
use roaring::RoaringBitmap;
use state::{MetaKey, ReportFilter, RunStatus, SqliteState, StateStore};

fn options(batch_ops: usize) -> RunOptions {
    let mut options = RunOptions::new(RunKind::Incremental, Edition::Enterprise);
    options.tuning = Tuning {
        concurrency: 1,
        batch_ops,
        batch_bytes: 1 << 20,
        blob_concurrency: 2,
        read_ahead: 2,
        max_ops_per_sec: None,
        account_split: 1,
    };
    options.retry = RetryPolicy {
        max_attempts: 5,
        budget: Duration::from_secs(30),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    options.final_observation = Duration::ZERO;
    options
}

trait Backed: Target {
    fn fake(self: &Arc<Self>) -> Arc<FakeTarget>;
}

impl Backed for FakeTarget {
    fn fake(self: &Arc<Self>) -> Arc<FakeTarget> {
        self.clone()
    }
}

impl Backed for PartialTarget {
    fn fake(self: &Arc<Self>) -> Arc<FakeTarget> {
        self.inner.clone()
    }
}

async fn run_t<T: Backed>(
    source: &Arc<FakeSource>,
    target: &Arc<T>,
    dir: &Path,
    options: RunOptions,
) -> RunSummary {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
    Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target.fake(), source),
        state,
        Arc::new(FakeConverter),
        options,
        Shutdown::default(),
    )
    .run()
    .await
    .expect("run")
}

fn seed(source: &FakeSource, emails: u32) {
    source.put(1, mailbox(0, "Inbox"));
    for id in 0..emails {
        source.put(1, email(id, 0, id + 1, &[]));
    }
    source.put(1, identity(0, "a@example.org"));
    source.set_pointers(1, AccountPointers::default());
}

// Crash after an email chunk commits, then resume with a smaller --batch-ops.
#[tokio::test]
async fn resume_with_smaller_batch_ops_does_not_duplicate_emails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 20);
    *target.crash_after_commits.lock().expect("lock") = Some(3);
    let state = Arc::new(SqliteState::open(dir.path()).expect("open"));
    let orchestrator = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target, &source),
        state,
        Arc::new(FakeConverter),
        options(8),
        Shutdown::default(),
    );
    tokio::select! {
        _ = orchestrator.run() => panic!("no crash"),
        _ = target.crashed.notified() => {}
    }
    *target.crash_after_commits.lock().expect("lock") = None;
    run_t(&source, &target, dir.path(), options(2)).await;
    assert_eq!(source.snapshot(), target.snapshot());
    assert_eq!(
        target.duplicates(),
        0,
        "duplicate email ingests after resume"
    );
}

// Excluding a category for one run must not lose that category's changes.
#[tokio::test]
async fn temporarily_excluded_category_keeps_its_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    run_t(&source, &target, dir.path(), options(8)).await;
    source.put(1, email(50, 0, 51, &[]));
    source.put(1, identity(1, "b@example.org"));
    let mut excluded = options(8);
    excluded.categories.remove(Category::Mail);
    run_t(&source, &target, dir.path(), excluded).await;
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        source.snapshot(),
        target.snapshot(),
        "email 50 never copied"
    );
    let world = target.world.lock().expect("lock");
    assert_eq!(
        world.accounts[&1].changelog.len() as u64,
        source.counter(1),
        "changelog rows of the excluded category were skipped"
    );
}

// A category included only after the first run is copied in full.
#[tokio::test]
async fn category_added_later_is_backfilled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    source.put(1, identity(1, "b@example.org"));
    let mut excluded = options(8);
    excluded.categories.remove(Category::Identities);
    run_t(&source, &target, dir.path(), excluded).await;
    assert!(
        !target.snapshot()[&1]
            .keys()
            .any(|(collection, _)| *collection == Collection::Identity)
    );
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.stats.accounts_delta, 1);
    assert_eq!(source.snapshot(), target.snapshot());
}

struct PartialTarget {
    inner: Arc<FakeTarget>,
    armed: Mutex<bool>,
}

impl Target for PartialTarget {
    async fn probe(&self) -> Result<TargetProbe> {
        self.inner.probe().await
    }
    async fn prepare_store(&self, edition: Edition) -> Result<()> {
        self.inner.prepare_store(edition).await
    }
    async fn claim_generation(&self) -> Result<Option<model::ClaimId>> {
        self.inner.claim_generation().await
    }
    async fn swap_claim_generation(
        &self,
        expected: Option<model::ClaimId>,
        next: model::ClaimId,
    ) -> Result<bool> {
        self.inner.swap_claim_generation(expected, next).await
    }
    async fn read_registry(&self, keys: &[RegistryKey]) -> Result<Vec<Option<RegistryRecord>>> {
        self.inner.read_registry(keys).await
    }
    async fn write_registry(&self, records: &[RegistryRecord]) -> Result<WriteOutcome> {
        self.inner.write_registry(records).await
    }
    async fn delete_registry(&self, keys: &[RegistryKey]) -> Result<()> {
        self.inner.delete_registry(keys).await
    }
    async fn start_server(&self) -> Result<()> {
        self.inner.start_server().await
    }
    async fn write_pointers(
        &self,
        account: u32,
        pointers: &AccountPointers,
    ) -> Result<WriteOutcome> {
        self.inner.write_pointers(account, pointers).await
    }
    async fn upsert(
        &self,
        account: u32,
        batch: &RecordBatch,
        mode: WriteMode,
    ) -> Result<WriteOutcome> {
        let fire = {
            let mut armed = self.armed.lock().expect("lock");
            let fire = *armed
                && mode == WriteMode::Create
                && batch.collection() == Collection::Email
                && batch.len() > 1;
            if fire {
                *armed = false;
            }
            fire
        };
        if fire {
            let mut head = batch.clone();
            let _tail = head.split_off(batch.len() / 2);
            self.inner.upsert(account, &head, mode).await?;
            return Err(Error::too_large(
                "transaction too large after partial commit",
            ));
        }
        self.inner.upsert(account, batch, mode).await
    }
    async fn delete(&self, account: u32, collection: Collection, ids: &[u32]) -> Result<()> {
        self.inner.delete(account, collection, ids).await
    }
    async fn exists(
        &self,
        account: u32,
        collection: Collection,
        ids: &[u32],
    ) -> Result<RoaringBitmap> {
        self.inner.exists(account, collection, ids).await
    }
    async fn wipe_account(&self, account: u32) -> Result<()> {
        self.inner.wipe_account(account).await
    }
    async fn write_changelog(&self, account: u32, rows: &[ChangeLogRecord]) -> Result<()> {
        self.inner.write_changelog(account, rows).await
    }
    async fn write_share_notifications(
        &self,
        account: u32,
        records: &[ShareNotificationRecord],
    ) -> Result<()> {
        self.inner.write_share_notifications(account, records).await
    }
    async fn raise_counters(&self, account: u32, counters: &Counters) -> Result<()> {
        self.inner.raise_counters(account, counters).await
    }
    async fn blobs_exist(&self, hashes: &[BlobHash]) -> Result<Vec<bool>> {
        self.inner.blobs_exist(hashes).await
    }
    async fn stored_blobs_exist(&self, hashes: &[BlobHash]) -> Result<Vec<bool>> {
        self.inner.stored_blobs_exist(hashes).await
    }
    async fn put_blob(&self, hash: &BlobHash, data: Bytes) -> Result<()> {
        self.inner.put_blob(hash, data).await
    }
    async fn write_global(&self, batch: &GlobalBatch) -> Result<WriteOutcome> {
        self.inner.write_global(batch).await
    }
    async fn apply_final_spam_model(&self, changes: &[SpamModelChange]) -> Result<WriteOutcome> {
        self.inner.apply_final_spam_model(changes).await
    }
    async fn finalize_account(&self, account: u32, counters: &Counters) -> Result<WriteOutcome> {
        self.inner.finalize_account(account, counters).await
    }
    async fn finalize_store(&self, categories: CategorySet) -> Result<WriteOutcome> {
        self.inner.finalize_store(categories).await
    }
}

// A TooLarge error after the target committed part of a Create batch.
#[tokio::test]
async fn too_large_after_partial_commit_does_not_duplicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let inner = FakeTarget::new();
    let target = Arc::new(PartialTarget {
        inner: inner.clone(),
        armed: Mutex::new(true),
    });
    seed(&source, 8);
    run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(source.snapshot(), inner.snapshot());
    assert_eq!(inner.duplicates(), 0, "duplicate email ingests after split");
}

// Share notification ids are snowflakes, far above the change counter.
#[tokio::test]
async fn share_notifications_copy_with_snowflake_ids() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    let base = 1u64 << 60;
    for offset in 0..5 {
        source.add_share(1, base + offset);
    }
    let summary = run_t(&source, &target, dir.path(), options(2)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        target.world.lock().expect("lock").accounts[&1].shares.len(),
        5
    );

    source.add_share(1, base + 100);
    source.put(1, email(30, 0, 31, &[]));
    let summary = run_t(&source, &target, dir.path(), options(2)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        target.world.lock().expect("lock").accounts[&1].shares.len(),
        6
    );
}

// Directories are written before their children, in full copies and deltas.
#[tokio::test]
async fn file_tree_parents_before_children() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put(1, file(1, Some(9)));
    source.put(1, directory(2, Some(5)));
    source.put(1, directory(5, Some(9)));
    source.put(1, directory(9, None));
    source.put(1, file(3, Some(2)));
    run_t(&source, &target, dir.path(), options(2)).await;
    assert_eq!(source.snapshot(), target.snapshot());
    assert_eq!(target.world.lock().expect("lock").orphans, 0);

    source.put(1, file(4, Some(12)));
    source.put(1, directory(12, Some(11)));
    source.put(1, directory(11, Some(2)));
    run_t(&source, &target, dir.path(), options(2)).await;
    assert_eq!(source.snapshot(), target.snapshot());
    assert_eq!(target.world.lock().expect("lock").orphans, 0);
}

// Excluded categories leave pointers alone; the active script is set after the scripts exist.
#[tokio::test]
async fn pointers_keep_excluded_fields_and_follow_scripts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put(1, sieve(4, "main"));
    source.set_pointers(
        1,
        AccountPointers {
            active_script: Pointer::Set(Some(4)),
            default_calendar: Pointer::Set(None),
            ..Default::default()
        },
    );
    let mut no_sieve = options(8);
    no_sieve.categories.remove(Category::Sieve);
    run_t(&source, &target, dir.path(), no_sieve).await;
    {
        let world = target.world.lock().expect("lock");
        let pointers = &world.accounts[&1].pointers;
        assert_eq!(pointers.active_script, Pointer::Keep);
        assert_eq!(pointers.default_calendar, Pointer::Set(None));
    }
    run_t(&source, &target, dir.path(), options(8)).await;
    let world = target.world.lock().expect("lock");
    assert_eq!(
        world.accounts[&1].pointers.active_script,
        Pointer::Set(Some(4))
    );
    assert_eq!(world.dangling_scripts, 0);
}

// A source that suddenly lists far fewer accounts must not wipe the target.
#[tokio::test]
async fn mass_removal_is_refused_unless_allowed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for account_id in 1..=12 {
        source.put(account_id, mailbox(0, "Inbox"));
    }
    let mut wide = options(8);
    wide.tuning.concurrency = 4;
    run_t(&source, &target, dir.path(), wide.clone()).await;
    for account_id in 1..=11 {
        source.remove_account(account_id);
    }
    source.put(13, mailbox(0, "Inbox"));
    let summary = run_t(&source, &target, dir.path(), wide.clone()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.errors, 1);
    assert_eq!(summary.stats.accounts_full, 1);
    assert_eq!(summary.stats.accounts_removed, 0);
    assert_eq!(target.snapshot().len(), 13);
    let state = SqliteState::open(dir.path()).expect("open");
    let skipped = state
        .reports(ReportFilter {
            category: Some("skipped".into()),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert_eq!(skipped.len(), 1);
    drop(state);

    source.remove_account(12);
    source.remove_account(13);
    let summary = run_t(&source, &target, dir.path(), wide.clone()).await;
    assert_eq!(summary.stats.accounts_removed, 0);
    assert_eq!(target.snapshot().len(), 13);

    let mut allowed = wide;
    allowed.removals = RemovalPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), allowed).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.accounts_removed, 13);
    assert!(target.snapshot().is_empty());
}

// Removing a single tracked account is not mistaken for a mass removal.
#[tokio::test]
async fn single_account_removal_is_applied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put(1, mailbox(0, "Inbox"));
    source.put(2, mailbox(0, "Inbox"));
    run_t(&source, &target, dir.path(), options(8)).await;
    source.remove_account(2);
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.stats.accounts_removed, 1);
    assert_eq!(target.snapshot().len(), 1);
}

// Finalize records each account, so a failed final run does not finalize twice.
#[tokio::test]
async fn finalize_resumes_per_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for account_id in 1..=3 {
        source.put(account_id, mailbox(0, "Inbox"));
    }
    run_t(&source, &target, dir.path(), options(8)).await;
    target.inject(FaultOp::Finalize, Some(3), Fault::Fatal);
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run.clone()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Ok);
    let world = target.world.lock().expect("lock");
    assert!(
        world
            .accounts
            .values()
            .all(|account| account.finalized == 1)
    );
}

// The final run refuses to start while the source server is still writing, and names that server and the command to repeat in each direction.
#[tokio::test]
async fn final_run_requires_a_quiet_source() {
    for (direction, expected) in [
        (
            RunDirection::Migration,
            "stop every v0.16 node before run --final",
        ),
        (RunDirection::Rollback, "stop every v1 node before rollback"),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        seed(&source, 2);
        run_t(&source, &target, dir.path(), options(8)).await;
        let mut final_run = options(8);
        final_run.kind = RunKind::Final;
        final_run.direction = direction;
        final_run.final_observation = Duration::from_millis(300);
        let writer = source.clone();
        let mutate = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            writer.put(1, email(60, 0, 61, &[]));
        });
        let summary = run_t(&source, &target, dir.path(), final_run).await;
        mutate.await.expect("writer");
        let Some(RunError::Preflight(message)) = &summary.error else {
            panic!("{direction:?}: {:?}", summary.error);
        };
        assert!(message.contains(expected), "{message}");
        assert!(!target.world.lock().expect("lock").store_finalized);
    }
}

// Registry singletons are migrated and conversion issues are reported once.
#[tokio::test]
async fn registry_issues_are_reported_only_for_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put_singleton("Http", serde_json::json!({"useXForwarded": false}));
    source.put_registry("SpamLlm", 9, serde_json::json!({"enable": true}));
    run_t(&source, &target, dir.path(), options(8)).await;
    run_t(&source, &target, dir.path(), options(8)).await;
    assert!(
        target
            .world
            .lock()
            .expect("lock")
            .registry
            .contains_key(&RegistryKey::singleton("Http"))
    );
    let state = SqliteState::open(dir.path()).expect("open");
    let dropped = state
        .reports(ReportFilter {
            category: Some("dropped".into()),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert_eq!(dropped.len(), 1);
}

// Objects in a reference cycle are written without the reference first, then completed.
#[tokio::test]
async fn deferred_registry_updates_are_written_last() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put_registry("Cyclic", 1, serde_json::json!({"name": "a", "ref": 2}));
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        target.world.lock().expect("lock").registry[&RegistryKey::new("Cyclic", 1)],
        serde_json::json!({"name": "a", "ref": 2, "v1": true})
    );
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.stats.registry_written, 0);
}

fn no_mail(batch_ops: usize) -> RunOptions {
    let mut options = options(batch_ops);
    options.categories.remove(Category::Mail);
    options
}

async fn run_crash(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
    after: u64,
) {
    let base = target.world.lock().expect("lock").upserts;
    *target.crash_after_commits.lock().expect("lock") = Some(base + after);
    let state = Arc::new(SqliteState::open(dir).expect("open"));
    let orchestrator = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        state,
        Arc::new(FakeConverter),
        options,
        Shutdown::default(),
    );
    tokio::select! {
        _ = orchestrator.run() => panic!("no crash"),
        _ = target.crashed.notified() => {}
    }
    *target.crash_after_commits.lock().expect("lock") = None;
}

// Interrupted backfill of a newly included category, then a run without it, then with it again.
#[tokio::test]
async fn interrupted_backfill_then_exclusion_does_not_duplicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 20);
    run_t(&source, &target, dir.path(), no_mail(4)).await;
    run_crash(&source, &target, dir.path(), options(4), 2).await;
    run_t(&source, &target, dir.path(), no_mail(4)).await;
    run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(source.snapshot(), target.snapshot());
    assert_eq!(target.duplicates(), 0, "duplicates after re-including mail");
}

// Done accounts without per-collection cursors are rescanned without duplicate ingests.
#[tokio::test]
async fn accounts_without_cursors_rescan_without_duplicates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 20);
    run_t(&source, &target, dir.path(), options(4)).await;
    {
        let conn = rusqlite::Connection::open(dir.path().join("state.sqlite")).expect("conn");
        conn.execute_batch("DELETE FROM cursor; UPDATE account SET synced = 0;")
            .expect("reset");
    }
    run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(source.snapshot(), target.snapshot());
    assert_eq!(target.duplicates(), 0, "duplicates after losing cursors");
}

struct DropConverter {
    shutdown: Shutdown,
    interrupt: AtomicBool,
}

impl RegistryConverter for DropConverter {
    fn category(&self, _object: &str) -> Category {
        Category::Settings
    }

    fn convert(
        &self,
        objects: Vec<RegistryRecord>,
        _categories: CategorySet,
    ) -> std::result::Result<Converted, ConversionError> {
        let mut out = Converted::default();
        for record in objects {
            if record.json.get("drop").is_some() {
                out.dropped.push(record.key);
            } else {
                out.records.push(ConvertedRecord {
                    source: record.key.clone(),
                    record,
                });
            }
        }
        if !out.dropped.is_empty() && self.interrupt.swap(false, Ordering::SeqCst) {
            self.shutdown.request();
        }
        Ok(out)
    }

    fn delete_plan(&self, records: Vec<RegistryRecord>) -> RegistryDeletes {
        RegistryDeletes {
            updates: Vec::new(),
            order: records.into_iter().map(|record| record.key).collect(),
        }
    }

    fn references(&self, _side: RecordSide, _record: &RegistryRecord) -> Vec<RegistryKey> {
        Vec::new()
    }
}

async fn run_dropping(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    interrupt: bool,
) {
    let shutdown = Shutdown::default();
    let converter = Arc::new(DropConverter {
        shutdown: shutdown.clone(),
        interrupt: AtomicBool::new(interrupt),
    });
    let state = Arc::new(SqliteState::open(dir).expect("open"));
    let _ = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        state,
        converter,
        options(8),
        shutdown,
    )
    .run()
    .await;
}

// A registry object that becomes dropped is deleted even if the run stops right after.
#[tokio::test]
async fn dropped_registry_object_survives_interrupted_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put_registry("Setting", 1, serde_json::json!({"a": 1}));
    run_dropping(&source, &target, dir.path(), false).await;
    assert!(
        target
            .world
            .lock()
            .expect("lock")
            .registry
            .contains_key(&RegistryKey::new("Setting", 1))
    );
    source.put_registry("Setting", 1, serde_json::json!({"a": 1, "drop": true}));
    run_dropping(&source, &target, dir.path(), true).await;
    run_dropping(&source, &target, dir.path(), false).await;
    assert!(
        !target
            .world
            .lock()
            .expect("lock")
            .registry
            .contains_key(&RegistryKey::new("Setting", 1)),
        "dropped object still in target"
    );
}

// Deleting an object and creating another with the same unique name works in one run.
#[tokio::test]
async fn registry_recreate_with_same_name_in_one_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put_registry("Domain", 1, serde_json::json!({"name": "a.org"}));
    run_t(&source, &target, dir.path(), options(8)).await;
    source.delete_registry("Domain", 1);
    source.put_registry("Domain", 2, serde_json::json!({"name": "a.org"}));
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    let world = target.world.lock().expect("lock");
    assert!(world.registry.contains_key(&RegistryKey::new("Domain", 2)));
    assert!(!world.registry.contains_key(&RegistryKey::new("Domain", 1)));
}

// Registry deletions are held when a type loses most of its objects or a core type is emptied.
#[tokio::test]
async fn registry_mass_removal_is_refused_unless_allowed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    for id in 1..=12 {
        source.put_registry("Alias", id, serde_json::json!({"name": id}));
    }
    source.put_registry("Domain", 1, serde_json::json!({"name": "a.org"}));
    run_t(&source, &target, dir.path(), options(8)).await;
    for id in 1..=11 {
        source.delete_registry("Alias", id);
    }
    source.delete_registry("Domain", 1);
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.errors, 2);
    assert_eq!(summary.stats.registry_deleted, 0);
    assert_eq!(target.world.lock().expect("lock").registry.len(), 13);

    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.stats.registry_deleted, 0);

    let mut allowed = options(8);
    allowed.removals = RemovalPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), allowed).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.registry_deleted, 12);
    let world = target.world.lock().expect("lock");
    assert_eq!(world.registry.len(), 1);
    assert!(world.registry.contains_key(&RegistryKey::new("Alias", 12)));
}

// A run that reports errors not tied to an object does not finalize.
#[tokio::test]
async fn final_run_refuses_after_objectless_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for account_id in 1..=12 {
        source.put(account_id, mailbox(0, "Inbox"));
    }
    run_t(&source, &target, dir.path(), options(8)).await;
    for account_id in 1..=11 {
        source.remove_account(account_id);
    }
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(summary.verify.is_none());
    let state = SqliteState::open(dir.path()).expect("open");
    assert_eq!(state.meta(MetaKey::FinalDone).await.expect("meta"), None);
}

// Share notifications of an account whose counter did not move are copied on the final run.
#[tokio::test]
async fn final_run_copies_share_notifications_of_unchanged_accounts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    run_t(&source, &target, dir.path(), options(8)).await;
    source.add_share(1, 1 << 50);
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        target.world.lock().expect("lock").accounts[&1].shares.len(),
        1
    );
}

// Share notifications deleted in the source after they were copied are deleted from the target by the final run, which then verifies.
#[tokio::test]
async fn final_run_deletes_share_notifications_gone_from_the_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.add_share(1, 1 << 50);
    source.add_share(1, 1 << 51);
    run_t(&source, &target, dir.path(), options(1)).await;
    assert_eq!(
        target.world.lock().expect("lock").accounts[&1].shares.len(),
        2
    );
    source
        .world
        .lock()
        .expect("lock")
        .accounts
        .get_mut(&1)
        .expect("account")
        .shares
        .remove(&(1 << 50));
    let mut final_run = options(1);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Ok);
    let verify = summary.verify.expect("verify");
    assert_eq!((verify.status, verify.unexplained), (RunStatus::Ok, 0));
    assert_eq!(
        target.world.lock().expect("lock").accounts[&1]
            .shares
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [1 << 51]
    );
}

// A saved cursor above the source counter is treated as a source regression.
#[tokio::test]
async fn cursor_above_counter_forces_full_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    run_t(&source, &target, dir.path(), options(8)).await;
    {
        let conn = rusqlite::Connection::open(dir.path().join("state.sqlite")).expect("conn");
        conn.execute_batch(
            "UPDATE cursor SET last_id = 1000000 WHERE mode = 'checkpoint' AND collection = 1;",
        )
        .expect("bump");
    }
    source.put(1, email(40, 0, 41, &[]));
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.stats.accounts_wiped, 1);
    assert_eq!(source.snapshot(), target.snapshot());
}

// A backfill started in a delta resumes with the counter captured when it started.
#[tokio::test]
async fn interrupted_backfill_keeps_its_start_counter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    for id in 1..=8 {
        source.put(1, identity(id, "x@example.org"));
    }
    let mut no_identities = options(2);
    no_identities.categories.remove(Category::Identities);
    run_t(&source, &target, dir.path(), no_identities).await;
    run_crash(&source, &target, dir.path(), options(2), 2).await;
    source.put(1, identity(1, "changed@example.org"));
    source.delete(1, Collection::Identity, 2);
    let summary = run_t(&source, &target, dir.path(), options(2)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(source.snapshot(), target.snapshot());
}

// A saved backfill start counter above the source counter is treated as a regression.
#[tokio::test]
async fn started_cursor_above_counter_forces_full_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    run_t(&source, &target, dir.path(), options(8)).await;
    {
        let conn = rusqlite::Connection::open(dir.path().join("state.sqlite")).expect("conn");
        conn.execute_batch(
            "INSERT INTO cursor (account_id, collection, mode, last_id) VALUES (1, 3, 'started', 1000000);",
        )
        .expect("insert");
    }
    source.put(1, email(41, 0, 42, &[]));
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.stats.accounts_wiped, 1);
    assert_eq!(source.snapshot(), target.snapshot());
}

// A target that stores registry objects in its own canonical form passes the identity check and is not rewritten.
#[tokio::test]
async fn registry_identity_uses_the_stored_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    target.world.lock().expect("lock").canonical = true;
    source.put_registry("Domain", 3, serde_json::json!({"name": "example.org"}));
    source.put_registry("Account", 9, serde_json::json!({"name": "bob"}));
    source.world.lock().expect("lock").id_counters = vec![RegistryCounter {
        object: "Account".into(),
        value: 40,
    }];
    seed(&source, 1);
    let first = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(first.status, RunStatus::Ok);
    assert_eq!(first.stats.registry_written, 2);
    let second = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(second.status, RunStatus::Ok, "{:?}", second.error);
    assert_eq!(second.stats.registry_written, 0);
    assert_eq!(
        target
            .world
            .lock()
            .expect("lock")
            .id_counters
            .get("Account"),
        Some(&40)
    );
    target
        .world
        .lock()
        .expect("lock")
        .registry
        .values_mut()
        .for_each(|json| json["createdAt"] = 2.into());
    let third = run_t(&source, &target, dir.path(), options(4)).await;
    assert!(matches!(third.error, Some(RunError::Preflight(_))));
}

// A blocked IP that Stalwart deleted from the target after it expired does not fail the preflight of the next run.
#[tokio::test]
async fn expired_ip_removed_from_the_target_passes_preflight() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put_registry("Domain", 3, serde_json::json!({"name": "example.org"}));
    source.put_registry(
        "BlockedIp",
        5,
        serde_json::json!({"address": "192.0.2.1", "expiresAt": "2999-01-01T00:00:00Z"}),
    );
    seed(&source, 1);
    let first = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(first.status, RunStatus::Ok, "{:?}", first.error);
    assert_eq!(first.stats.registry_written, 2);
    target
        .world
        .lock()
        .expect("lock")
        .registry
        .remove(&RegistryKey::new("BlockedIp", 5))
        .expect("blocked ip in the target");
    let second = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(second.status, RunStatus::Ok, "{:?}", second.error);
    target
        .world
        .lock()
        .expect("lock")
        .registry
        .remove(&RegistryKey::new("Domain", 3))
        .expect("domain in the target");
    let third = run_t(&source, &target, dir.path(), options(4)).await;
    assert!(
        matches!(third.error, Some(RunError::Preflight(_))),
        "{:?}",
        third.error
    );
}

// A file-backed certificate whose metadata Stalwart refreshed at startup, or that it deleted once expired, does not fail the preflight of the next run.
#[tokio::test]
async fn refreshed_file_certificate_passes_preflight() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for id in [5, 6] {
        source.put_registry(
            "Certificate",
            id,
            serde_json::json!({"certificate": {"@type": "File", "filePath": "/etc/cert.pem"}, "issuer": "old"}),
        );
    }
    seed(&source, 1);
    let first = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(first.status, RunStatus::Ok, "{:?}", first.error);
    {
        let mut world = target.world.lock().expect("lock");
        world
            .registry
            .get_mut(&RegistryKey::new("Certificate", 5))
            .expect("certificate in the target")["issuer"] = "new".into();
        world
            .registry
            .remove(&RegistryKey::new("Certificate", 6))
            .expect("certificate in the target");
    }
    let second = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(second.status, RunStatus::Ok, "{:?}", second.error);
}

// Registry id counters follow object renames of the conversion and skip excluded categories.
#[tokio::test]
async fn registry_counters_use_target_object_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put_registry("Legacy", 3, serde_json::json!({"name": "old"}));
    source.world.lock().expect("lock").id_counters = vec![
        RegistryCounter {
            object: "Legacy".into(),
            value: 12,
        },
        RegistryCounter {
            object: "Account".into(),
            value: 40,
        },
    ];
    seed(&source, 1);
    let mut excluded = options(4);
    excluded.categories.remove(Category::Principals);
    let summary = run_t(&source, &target, dir.path(), excluded).await;
    assert_eq!(summary.status, RunStatus::Ok, "{:?}", summary.error);
    let world = target.world.lock().expect("lock");
    assert_eq!(world.id_counters.get("Renamed"), Some(&12));
    assert_eq!(world.id_counters.get("Legacy"), None);
    assert_eq!(world.id_counters.get("Account"), None);
}

// A final run refuses to finalize while failed objects are still missing; --allow-errors accepts them.
#[tokio::test]
async fn final_run_requires_failed_objects_to_be_fixed_or_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 10);
    *target.too_large_above.lock().expect("lock") = Some(1);
    target.poison.lock().expect("lock").insert(7);
    let first = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(first.status, RunStatus::Failed);

    let mut final_run = options(4);
    final_run.kind = RunKind::Final;
    let refused = run_t(&source, &target, dir.path(), final_run.clone()).await;
    assert_eq!(refused.status, RunStatus::Failed);
    assert!(refused.verify.is_none(), "finalize must not run");
    assert!(!target.world.lock().expect("lock").store_finalized);
    let state = SqliteState::open(dir.path()).expect("state");
    assert_eq!(state.meta(MetaKey::FinalDone).await.expect("meta"), None);
    drop(state);

    final_run.errors = ErrorPolicy::Allow;
    let accepted = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(accepted.status, RunStatus::Ok, "{:?}", accepted.error);
    let verified = accepted.verify.as_ref().expect("verify after final");
    assert_eq!(verified.status, RunStatus::Ok);
    assert!(verified.mismatches > 0, "the accepted loss is still listed");
    assert!(accepted.succeeded());
    let state = SqliteState::open(dir.path()).expect("state");
    assert!(
        state
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );
    assert!(
        state
            .meta(MetaKey::AcceptedErrors)
            .await
            .expect("meta")
            .is_some()
    );
}

// A registry object the target keeps rejecting is reported once, not on every run.
#[tokio::test]
async fn unchanged_registry_failures_are_not_recounted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put_registry(
        "Domain",
        3,
        serde_json::json!({"name": "a", "invalid": true}),
    );
    seed(&source, 1);
    let first = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(first.stats.errors, 1);
    let second = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(second.status, RunStatus::Ok, "{:?}", second.error);
    assert_eq!(second.stats.errors, 0);

    let mut final_run = options(4);
    final_run.kind = RunKind::Final;
    let refused = run_t(&source, &target, dir.path(), final_run).await;
    assert!(
        refused.verify.is_none(),
        "a failed registry object blocks finalize"
    );
}

// An object read back undecodable is a loss that blocks finalize without --allow-errors.
#[tokio::test]
async fn undecodable_objects_block_finalize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    source
        .world
        .lock()
        .expect("lock")
        .undecodable
        .insert((1, Collection::Email, 1));
    let first = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(first.status, RunStatus::Failed);
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run.clone()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(summary.verify.is_none());
    let state = SqliteState::open(dir.path()).expect("open");
    assert_eq!(state.meta(MetaKey::FinalDone).await.expect("meta"), None);
    drop(state);

    final_run.errors = ErrorPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Ok);
    let state = SqliteState::open(dir.path()).expect("open");
    assert!(
        state
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );
}

// A changelog row too large for the target is skipped; once accepted, verify explains it and the final run completes.
#[tokio::test]
async fn accepted_skipped_changelog_row_reaches_final_done() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    target.inject(FaultOp::Changelog, Some(1), Fault::TooLarge);
    let first = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(first.stats.errors, 1);

    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let refused = run_t(&source, &target, dir.path(), final_run.clone()).await;
    assert_eq!(refused.status, RunStatus::Failed);
    assert!(refused.verify.is_none());

    final_run.errors = ErrorPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Ok);
    let verify = summary.verify.expect("verify");
    assert_eq!(verify.status, RunStatus::Ok);
    assert!(verify.mismatches > 0);
    assert_eq!(verify.unexplained, 0);
    let state = SqliteState::open(dir.path()).expect("open");
    assert!(
        state
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );
}

// Errors reported by finalize itself keep the final run from being marked done.
#[tokio::test]
async fn errors_after_the_finalize_check_are_not_marked_done() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    run_t(&source, &target, dir.path(), options(8)).await;
    target
        .world
        .lock()
        .expect("lock")
        .finalize_issues
        .push(Issue::new(
            Severity::Error,
            IssueKind::Failed,
            Subject::None,
            "quota recalculation failed",
        ));
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    assert_eq!(summary.status, RunStatus::Failed);
    let state = SqliteState::open(dir.path()).expect("open");
    assert_eq!(state.meta(MetaKey::FinalDone).await.expect("meta"), None);
}

// An issue reported twice for one object in a run is counted once in the run summary, as in the report.
#[tokio::test]
async fn run_summary_counts_the_stored_report_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    run_t(&source, &target, dir.path(), options(8)).await;
    let issue = |severity| {
        Issue::new(
            severity,
            IssueKind::Failed,
            Subject::Registry(RegistryKey::new("x:Domain", 5)),
            "rejected",
        )
    };
    target.world.lock().expect("lock").finalize_issues = vec![
        issue(Severity::Error),
        issue(Severity::Error),
        issue(Severity::Warning),
        issue(Severity::Warning),
    ];
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    let state = SqliteState::open(dir.path()).expect("open");
    let stored: u64 = state
        .report_counts(Some(summary.run_id))
        .await
        .expect("counts")
        .iter()
        .map(|count| count.count)
        .sum();
    assert_eq!(summary.stats.issues, stored);
    assert_eq!(summary.stats.errors, 1);
}

// Account objects stay in the registry while the account guard keeps their data, whatever the registry share.
#[tokio::test]
async fn account_guard_also_holds_account_objects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for id in 1..=200 {
        source.put_registry("Account", id, serde_json::json!({"name": id}));
    }
    for account_id in 1..=12 {
        source.put(account_id, mailbox(0, "Inbox"));
    }
    run_t(&source, &target, dir.path(), options(8)).await;
    for account_id in 1..=11 {
        source.remove_account(account_id);
        source.delete_registry("Account", u64::from(account_id));
    }
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.accounts_removed, 0);
    assert_eq!(summary.stats.registry_deleted, 0);
    assert_eq!(target.world.lock().expect("lock").registry.len(), 200);

    let mut allowed = options(8);
    allowed.removals = RemovalPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), allowed).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.accounts_removed, 11);
    assert_eq!(summary.stats.registry_deleted, 11);
}

// A Domain whose accounts the guard keeps is kept too, with a guard row instead of a failed delete.
#[tokio::test]
async fn held_accounts_keep_the_domain_they_link_to() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put_registry("Domain", 1, serde_json::json!({"name": "example.org"}));
    source.put_registry("Domain", 2, serde_json::json!({"name": "other.org"}));
    source.put_registry("Domain", 3, serde_json::json!({"name": "kept.org"}));
    for id in 1..=12 {
        source.put_registry(
            "Account",
            id,
            serde_json::json!({"name": id, "domainId": "b"}),
        );
        source.put(id as u32, mailbox(0, "Inbox"));
    }
    run_t(&source, &target, dir.path(), options(8)).await;
    for account_id in 1..=12 {
        source.remove_account(account_id);
        source.delete_registry("Account", u64::from(account_id));
    }
    source.delete_registry("Domain", 1);
    source.delete_registry("Domain", 2);
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    {
        let world = target.world.lock().expect("lock");
        assert!(world.registry.contains_key(&RegistryKey::new("Domain", 1)));
        assert!(!world.registry.contains_key(&RegistryKey::new("Domain", 2)));
    }
    let rows = SqliteState::open(dir.path())
        .expect("state")
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(
        rows.iter()
            .any(|row| row.message.contains("still links to it")),
        "{rows:#?}"
    );
}

// Blobs referenced by registry objects are copied in copy mode; an object whose blob is gone is not written.
#[tokio::test]
async fn registry_object_blobs_are_copied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_blob(BlobHash([9; 32]), b"sample");
    source.put_registry("SpamTrainingSample", 1, serde_json::json!({"blob": 9}));
    source.put_registry("SpamTrainingSample", 2, serde_json::json!({"blob": 8}));
    let mut copy = options(8);
    copy.blob_mode = BlobMode::Copy;
    let summary = run_t(&source, &target, dir.path(), copy).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.errors, 1);
    {
        let mut world = target.world.lock().expect("lock");
        assert!(world.blobs.contains(&BlobHash([9; 32])));
        assert!(
            world
                .registry
                .contains_key(&RegistryKey::new("SpamTrainingSample", 1))
        );
        assert!(
            !world
                .registry
                .contains_key(&RegistryKey::new("SpamTrainingSample", 2))
        );
        world.lost_blobs.insert(BlobHash([9; 32]));
    }
    let mut final_run = options(8);
    final_run.blob_mode = BlobMode::Copy;
    final_run.kind = RunKind::Final;
    final_run.errors = ErrorPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    let verify = summary.verify.expect("verify");
    assert_eq!(verify.status, RunStatus::Failed);
    assert_eq!(verify.unexplained, 1);
}

// In shared mode an object whose blob is missing from the shared store is skipped like in copy mode, and verify explains it once accepted.
#[tokio::test]
async fn registry_objects_with_missing_shared_blobs_are_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    target
        .world
        .lock()
        .expect("lock")
        .stored_blobs
        .insert(BlobHash([9; 32]));
    source.put_registry("SpamTrainingSample", 1, serde_json::json!({"blob": 9}));
    source.put_registry("SpamTrainingSample", 2, serde_json::json!({"blob": 8}));
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.errors, 1);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.blob_puts, 0);
        assert!(
            world
                .registry
                .contains_key(&RegistryKey::new("SpamTrainingSample", 1))
        );
        assert!(
            !world
                .registry
                .contains_key(&RegistryKey::new("SpamTrainingSample", 2))
        );
    }
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    final_run.errors = ErrorPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    let verify = summary.verify.expect("verify");
    assert_eq!(verify.unexplained, 0);
    assert_eq!(verify.status, RunStatus::Ok);
}

// A skipped last changelog row does not hide the loss of the rows below it in sample verify.
#[tokio::test]
async fn skipped_last_log_row_does_not_hide_tail_loss() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    run_t(&source, &target, dir.path(), options(8)).await;
    source.put(1, email(3, 0, 4, &[]));
    target.inject(FaultOp::Changelog, Some(1), Fault::TooLarge);
    let skipped = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(skipped.status, RunStatus::Failed);
    assert_eq!(skipped.stats.errors, 1);
    {
        let mut world = target.world.lock().expect("lock");
        let changelog = &mut world.accounts.get_mut(&1).expect("account").changelog;
        let tail: Vec<_> = changelog
            .keys()
            .filter(|(collection, _)| *collection == LogCollection::Email)
            .rev()
            .take(2)
            .copied()
            .collect();
        assert_eq!(tail.len(), 2);
        for key in tail {
            changelog.remove(&key);
        }
    }

    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    final_run.errors = ErrorPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), final_run).await;
    let verify = summary.verify.expect("verify");
    assert_eq!(verify.status, RunStatus::Failed);
    assert!(verify.unexplained > 0);
    let state = SqliteState::open(dir.path()).expect("open");
    assert_eq!(state.meta(MetaKey::FinalDone).await.expect("meta"), None);
}

// Wiping an account reports what it leaves in shared services unless shared deletes are allowed.
#[tokio::test]
async fn wipes_report_shared_deletions_unless_allowed() {
    for policy in [model::SharedDeletes::Forbid, model::SharedDeletes::Allow] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        source.put(1, mailbox(0, "Inbox"));
        source.put(2, mailbox(0, "Inbox"));
        run_t(&source, &target, dir.path(), options(8)).await;
        target
            .world
            .lock()
            .expect("lock")
            .shared
            .push(model::SharedDeletion {
                service: model::SharedService::SearchIndex,
                account_id: 0,
                what: "documents in the external index".into(),
            });
        source.remove_account(2);
        let mut removal = options(8);
        removal.shared_deletes = policy;
        let summary = run_t(&source, &target, dir.path(), removal).await;
        assert_eq!(summary.stats.accounts_removed, 1);
        let rows = SqliteState::open(dir.path())
            .expect("open")
            .reports(ReportFilter {
                severity: Some(Severity::Warning),
                ..Default::default()
            })
            .await
            .expect("reports");
        let reported = rows
            .iter()
            .any(|row| row.message.contains("search index of account 2"));
        assert_eq!(
            reported,
            policy == model::SharedDeletes::Forbid,
            "{policy:?}"
        );
    }
}

fn final_queue_options() -> RunOptions {
    let mut last = options(1);
    last.kind = RunKind::Final;
    last.blob_mode = BlobMode::Copy;
    last.categories.insert(Category::Queue);
    last
}

// Queued messages that change or leave the source after a final run that did not finalize are rewritten or deleted by the next final run.
#[tokio::test]
async fn later_final_runs_reread_queued_messages() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_blob(BlobHash([50; 32]), b"message");
    source.put_blob(BlobHash([60; 32]), b"message");
    source.world.lock().expect("lock").queued = [
        (5, queued_message(5, 50)),
        (6, queued_message(6, 60)),
        (7, queued_message(7, 70)),
    ]
    .into();
    let first = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(
        target
            .world
            .lock()
            .expect("lock")
            .queued
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [5, 6]
    );

    let mut changed = queued_message(5, 60);
    changed.priority = 3;
    {
        let mut world = source.world.lock().expect("lock");
        world.queued.remove(&6);
        world.queued.remove(&7);
        world.queued.insert(5, changed.clone());
    }
    let later = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(later.status, RunStatus::Ok);
    assert_eq!(later.stats.global_deleted, 1);
    let verify = later.verify.expect("verify");
    assert_eq!(
        (verify.status, verify.mismatches, verify.unexplained),
        (RunStatus::Ok, 0, 0)
    );
    let world = target.world.lock().expect("lock");
    assert_eq!(world.queued, [(5, changed)].into());
    assert_eq!(world.deleted_globals, [GlobalKey::Queue(6)]);
}

// Internal reports that change or leave the source after a final run that did not finalize are rewritten or deleted by the next final run.
#[tokio::test]
async fn later_final_runs_reread_internal_reports() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    {
        let mut world = source.world.lock().expect("lock");
        world.queued = [(7, queued_message(7, 70))].into();
        world.reports = [
            internal_report(ReportKind::Dmarc, 1, 5),
            internal_report(ReportKind::Dmarc, 4, 1),
            internal_report(ReportKind::Tls, 2, 3),
        ]
        .into_iter()
        .map(|report| ((report.kind, report.id), report))
        .collect();
    }
    let first = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(target.world.lock().expect("lock").reports.len(), 3);

    {
        let mut world = source.world.lock().expect("lock");
        world.queued.clear();
        world.reports.remove(&(ReportKind::Tls, 2));
        for report in [
            internal_report(ReportKind::Dmarc, 1, 9),
            internal_report(ReportKind::Tls, 8, 2),
        ] {
            world.reports.insert((report.kind, report.id), report);
        }
    }
    let later = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(later.status, RunStatus::Ok);
    let verify = later.verify.expect("verify");
    assert_eq!(
        (verify.status, verify.mismatches, verify.unexplained),
        (RunStatus::Ok, 0, 0)
    );
    let expected = source.world.lock().expect("lock").reports.clone();
    let world = target.world.lock().expect("lock");
    assert_eq!(world.reports, expected);
    assert_eq!(
        world.deleted_globals,
        [GlobalKey::Report(ReportKind::Tls, 2)]
    );
}

fn queue_of_four(source: &FakeSource) {
    for byte in 1..=4u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    source.world.lock().expect("lock").queued = (1..=4u8)
        .map(|id| (u64::from(id), queued_message(u64::from(id), id)))
        .collect();
}

fn queued_ids(target: &FakeTarget) -> Vec<u64> {
    target
        .world
        .lock()
        .expect("lock")
        .queued
        .keys()
        .copied()
        .collect()
}

async fn final_done(dir: &Path) -> bool {
    SqliteState::open(dir)
        .expect("open")
        .meta(MetaKey::FinalDone)
        .await
        .expect("meta")
        .is_some()
}

// An undecodable queued message reported by a crashed final run blocks the resumed run, which does not read it again.
#[tokio::test]
async fn resumed_final_run_counts_errors_of_its_interrupted_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    queue_of_four(&source);
    source
        .world
        .lock()
        .expect("lock")
        .undecodable_queued
        .insert(2);
    run_t(&source, &target, dir.path(), options(1)).await;
    run_crash(&source, &target, dir.path(), final_queue_options(), 2).await;
    let resumed = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(resumed.status, RunStatus::Failed);
    assert_eq!(resumed.stats.errors, 1);
    assert!(!final_done(dir.path()).await);
    assert_eq!(queued_ids(&target), [1, 3, 4]);
}

// A queued message committed just before a crash and gone from the source by the resume is deleted by a later final run.
#[tokio::test]
async fn message_committed_before_a_crash_is_swept_later() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    queue_of_four(&source);
    run_t(&source, &target, dir.path(), options(1)).await;
    run_crash(&source, &target, dir.path(), final_queue_options(), 2).await;
    assert_eq!(queued_ids(&target), [1, 2]);
    source.world.lock().expect("lock").queued.remove(&2);
    run_t(&source, &target, dir.path(), final_queue_options()).await;
    let mut forced = final_queue_options();
    forced.after_final = AfterFinal::Force;
    let later = run_t(&source, &target, dir.path(), forced).await;
    assert_eq!(later.status, RunStatus::Ok);
    let verify = later.verify.expect("verify");
    assert_eq!(verify.status, RunStatus::Ok);
    assert_eq!(queued_ids(&target), [1, 3, 4]);
    assert!(
        target
            .world
            .lock()
            .expect("lock")
            .deleted_globals
            .contains(&GlobalKey::Queue(2))
    );
}

// Tasks are re-read in full by a resumed final run, so tasks that left the source since the crash are deleted.
#[tokio::test]
async fn resumed_final_run_deletes_vanished_tasks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.world.lock().expect("lock").queue = vec![10, 20, 30];
    run_t(&source, &target, dir.path(), options(1)).await;
    let mut last = options(1);
    last.kind = RunKind::Final;
    last.categories.insert(Category::Tasks);
    run_crash(&source, &target, dir.path(), last.clone(), 3).await;
    let tasks = |target: &FakeTarget| -> Vec<u64> {
        target
            .world
            .lock()
            .expect("lock")
            .tasks
            .keys()
            .copied()
            .collect()
    };
    assert_eq!(tasks(&target), [0, 1, 2]);
    source.world.lock().expect("lock").queue.truncate(2);
    let resumed = run_t(&source, &target, dir.path(), last).await;
    assert_eq!(resumed.status, RunStatus::Ok);
    assert_eq!(resumed.interrupted_runs.len(), 1);
    assert_eq!(tasks(&target), [0, 1]);
    assert_eq!(
        target.world.lock().expect("lock").deleted_globals,
        [GlobalKey::Task(2)]
    );
}

// Excluding the queue in a later final run deletes the queued messages an earlier final run wrote.
#[tokio::test]
async fn excluded_queue_is_swept_by_a_later_final_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    queue_of_four(&source);
    let first = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(first.status, RunStatus::Ok);
    assert_eq!(queued_ids(&target), [1, 2, 3, 4]);
    let mut forced = final_queue_options();
    forced.after_final = AfterFinal::Force;
    forced.categories.remove(Category::Queue);
    let later = run_t(&source, &target, dir.path(), forced).await;
    assert_eq!(later.status, RunStatus::Ok);
    assert_eq!(later.stats.global_deleted, 4);
    assert!(queued_ids(&target).is_empty());
}

// A v0.16 server that starts during the queue pass of a final run is caught by the catch_up before finalize.
#[tokio::test]
async fn source_started_during_the_final_run_is_not_finalized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    queue_of_four(&source);
    run_t(&source, &target, dir.path(), options(4)).await;
    source.world.lock().expect("lock").starts_on_queue_read = true;
    let last = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(last.status, RunStatus::Failed);
    assert!(!target.world.lock().expect("lock").store_finalized);
    assert!(!final_done(dir.path()).await);
}

fn classifier(bias: f32) -> SpamModelRecord {
    SpamModelRecord::Classifier(SpamClassifierModel::Fh {
        parameters: vec![bias],
        bias,
        last_trained_at: 1,
    })
}

fn final_spam_options() -> RunOptions {
    let mut last = options(1);
    last.kind = RunKind::Final;
    last.categories.insert(Category::SpamModel);
    last
}

// In a shared blob store the spam model is written only by a final run, after its verify passed and before final_done.
#[tokio::test]
async fn shared_store_spam_model_is_written_only_at_finalize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.world.lock().expect("lock").spam = vec![classifier(1.0)];
    {
        let mut world = target.world.lock().expect("lock");
        world.shared_spam_store = true;
        world.spam = vec![classifier(2.0)];
    }
    let mut incremental = options(1);
    incremental.categories.insert(Category::SpamModel);
    let first = run_t(&source, &target, dir.path(), incremental).await;
    assert_eq!(first.status, RunStatus::Ok);
    assert_eq!(target.world.lock().expect("lock").spam_final_writes, 0);

    let last = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(last.succeeded(), "{last:?}");
    assert!(final_done(dir.path()).await);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.spam_final_writes, 1);
        assert_eq!(world.spam, [classifier(1.0)]);
        assert!(
            world
                .spam_written_after_catch_ups
                .is_some_and(|catch_ups| catch_ups > 0)
        );
    }
    let changed = SqliteState::open(dir.path())
        .expect("open")
        .reports(ReportFilter {
            severity: Some(Severity::Info),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert!(
        changed
            .iter()
            .any(|row| row.message.contains("spam model in the shared blob store"))
    );
}

// A final run whose verify fails, or that does not finalize, leaves the spam model alone.
#[tokio::test]
async fn failed_final_runs_do_not_write_the_spam_model() {
    let source = FakeSource::new();
    seed(&source, 0);
    source.world.lock().expect("lock").spam = vec![classifier(1.0)];
    source.put_registry("Domain", 1, serde_json::json!({"name": "example.org"}));

    let dir = tempfile::tempdir().expect("tempdir");
    let target = FakeTarget::new();
    {
        let mut world = target.world.lock().expect("lock");
        world.shared_spam_store = true;
        world.unlisted.insert(RegistryKey::new("Domain", 1));
    }
    let summary = run_t(&source, &target, dir.path(), final_spam_options()).await;
    let verify = summary.verify.expect("verify");
    assert_eq!(verify.status, RunStatus::Failed);
    assert_eq!(target.world.lock().expect("lock").spam_final_writes, 0);
    assert!(!final_done(dir.path()).await);

    let dir = tempfile::tempdir().expect("tempdir");
    let target = FakeTarget::new();
    target.world.lock().expect("lock").shared_spam_store = true;
    target.inject(FaultOp::Upsert, Some(1), Fault::Account);
    let summary = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(summary.verify.is_none());
    assert_eq!(target.world.lock().expect("lock").spam_final_writes, 0);
}

// A source without a spam model removes the one the target holds, at finalize only.
#[tokio::test]
async fn spam_model_reset_is_propagated_at_finalize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    target.world.lock().expect("lock").spam = vec![classifier(2.0)];
    let mut incremental = options(1);
    incremental.categories.insert(Category::SpamModel);
    run_t(&source, &target, dir.path(), incremental).await;
    assert_eq!(target.world.lock().expect("lock").spam, [classifier(2.0)]);

    let last = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(last.succeeded(), "{last:?}");
    assert!(target.world.lock().expect("lock").spam.is_empty());
    assert!(final_done(dir.path()).await);
}

// A spam model the final step did not store is a verify failure and keeps the run open.
#[tokio::test]
async fn unwritten_spam_model_blocks_final_done() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.world.lock().expect("lock").spam = vec![classifier(1.0)];
    {
        let mut world = target.world.lock().expect("lock");
        world.spam_write_ignored = true;
        world.spam = vec![classifier(2.0)];
    }
    let summary = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(!summary.succeeded());
    let verify = summary.verify.expect("verify");
    assert_eq!((verify.status, verify.unexplained), (RunStatus::Failed, 1));
    assert!(!final_done(dir.path()).await);

    let dir = tempfile::tempdir().expect("tempdir");
    let target = FakeTarget::new();
    {
        let mut world = target.world.lock().expect("lock");
        world.spam_write_skipped = true;
        world.spam = vec![classifier(2.0)];
    }
    let summary = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(summary.succeeded(), "{summary:?}");
    assert!(final_done(dir.path()).await);
}

// A restored original the target rejects is written again with its converted value, and verify accepts that value.
#[tokio::test]
async fn rejected_restored_originals_fall_back_to_the_converted_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "example.org", "invalid": true, "fallback": true}),
    );
    let mut last = options(1);
    last.kind = RunKind::Final;
    let summary = run_t(&source, &target, dir.path(), last).await;
    assert!(summary.succeeded(), "{summary:?}");
    assert_eq!(
        target
            .world
            .lock()
            .expect("lock")
            .registry
            .get(&RegistryKey::new("Domain", 1)),
        Some(&serde_json::json!({"name": "example.org", "v1": true}))
    );
    let rows = SqliteState::open(dir.path())
        .expect("open")
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(
        rows.iter().any(|row| row
            .message
            .contains("the converted value is written instead")),
        "{rows:?}"
    );
    assert!(final_done(dir.path()).await);
}

// A recorded fallback is cleared once the original value is written, and a fallback the target also rejects is never recorded.
#[tokio::test]
async fn fallback_rows_follow_the_value_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "example.org", "invalid": true, "fallback": true}),
    );
    source.put_registry(
        "Domain",
        2,
        serde_json::json!({"name": "other.org", "invalid": true, "fallback": true, "ref": "dangling"}),
    );
    run_t(&source, &target, dir.path(), options(1)).await;
    let fallbacks = || async {
        let mut keys = SqliteState::open(dir.path())
            .expect("open")
            .registry_fallbacks()
            .await
            .expect("fallbacks");
        keys.sort();
        keys
    };
    assert_eq!(fallbacks().await, [RegistryKey::new("Domain", 1)]);
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "example.org", "fallback": true}),
    );
    run_t(&source, &target, dir.path(), options(1)).await;
    assert!(fallbacks().await.is_empty());
}

// Held account deletions also hold the Tenant their memberTenantId links to, so v1 does not refuse the Tenant delete.
#[tokio::test]
async fn held_accounts_keep_the_tenant_they_belong_to() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    source.put_registry("Tenant", 1, serde_json::json!({"name": "first"}));
    source.put_registry("Tenant", 2, serde_json::json!({"name": "second"}));
    for id in 1..=12 {
        source.put_registry(
            "Account",
            id,
            serde_json::json!({"name": id, "memberTenantId": "b"}),
        );
        source.put(id as u32, mailbox(0, "Inbox"));
    }
    run_t(&source, &target, dir.path(), options(8)).await;
    for account_id in 1..=12 {
        source.remove_account(account_id);
        source.delete_registry("Account", u64::from(account_id));
    }
    source.delete_registry("Tenant", 1);
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(
        target
            .world
            .lock()
            .expect("lock")
            .registry
            .contains_key(&RegistryKey::new("Tenant", 1))
    );
}

// A server that starts on an idle source while an account is being copied stops the run before that account gets a checkpoint or is marked done.
#[tokio::test]
async fn source_started_during_an_account_copy_is_not_checkpointed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    source.world.lock().expect("lock").starts_on_scan = true;
    let summary = run_t(&source, &target, dir.path(), options(1)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    let state = SqliteState::open(dir.path()).expect("open");
    let account = state
        .accounts()
        .await
        .expect("accounts")
        .into_iter()
        .find(|account| account.account_id == 1);
    assert!(
        account
            .as_ref()
            .is_none_or(|account| account.phase != state::AccountPhase::Done),
        "{account:?}"
    );
    let cursors = state.cursors(1).await.expect("cursors");
    assert!(
        !cursors
            .iter()
            .any(|cursor| cursor.mode == state::CursorMode::Checkpoint),
        "{cursors:?}"
    );
}

fn clear_final_done(dir: &Path) {
    rusqlite::Connection::open(dir.join("state.sqlite"))
        .expect("conn")
        .execute_batch("DELETE FROM meta WHERE key = 'final_done';")
        .expect("clear final_done");
}

fn shared_spam(source: &FakeSource, target: &FakeTarget, blob: FakeSpamBlob) -> SpamBlobs {
    let blobs: SpamBlobs = Arc::new(Mutex::new(
        [(SpamModelKind::Classifier, blob)].into_iter().collect(),
    ));
    source.world.lock().expect("lock").spam_blobs = Some(blobs.clone());
    target.world.lock().expect("lock").spam_blobs = Some(blobs.clone());
    blobs
}

// A final step repeated after it wrote a shared blob store (crash before final_done, forced final) keeps the migrated model.
#[tokio::test]
async fn repeated_final_step_keeps_the_spam_model_in_a_shared_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    let blobs = shared_spam(&source, &target, FakeSpamBlob::Source(classifier(1.0)));
    let first = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(first.succeeded(), "{first:?}");
    let migrated = [(
        SpamModelKind::Classifier,
        FakeSpamBlob::Target(classifier(1.0)),
    )]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(*blobs.lock().expect("lock"), migrated);

    for _ in 0..2 {
        clear_final_done(dir.path());
        let again = run_t(&source, &target, dir.path(), final_spam_options()).await;
        assert!(again.succeeded(), "{again:?}");
        assert_eq!(*blobs.lock().expect("lock"), migrated);
        assert!(final_done(dir.path()).await);
    }
}

// An undecodable source spam model is never deleted or overwritten, and the run still finishes.
#[tokio::test]
async fn undecodable_source_spam_model_is_left_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    let blobs = shared_spam(&source, &target, FakeSpamBlob::Garbage);
    let summary = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(summary.succeeded(), "{summary:?}");
    assert_eq!(
        blobs.lock().expect("lock").get(&SpamModelKind::Classifier),
        Some(&FakeSpamBlob::Garbage)
    );
    assert!(final_done(dir.path()).await);
    let state = SqliteState::open(dir.path()).expect("open");
    let rows = state
        .reports(ReportFilter::default())
        .await
        .expect("report");
    assert!(
        rows.iter()
            .any(|row| row.message.contains("left untouched")),
        "{rows:?}"
    );
}

// A spam model with NaN weights compares equal to its read-back copy.
#[tokio::test]
async fn spam_model_with_nan_weights_reaches_final_done() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.world.lock().expect("lock").spam = vec![classifier(f32::NAN)];
    let summary = run_t(&source, &target, dir.path(), final_spam_options()).await;
    assert!(summary.succeeded(), "{summary:?}");
    assert!(final_done(dir.path()).await);
}

// A crash after the target was prepared and claimed in one batch, before the state recorded its schema version, resumes.
#[tokio::test]
async fn crash_between_prepare_and_schema_version_resumes() {
    let source = FakeSource::new();
    seed(&source, 2);
    let dir = tempfile::tempdir().expect("tempdir");
    let target = FakeTarget::new();
    {
        let mut world = target.world.lock().expect("lock");
        world.schema = Some(fake::SCHEMA_VERSION);
        world.claimed = true;
    }
    let summary = run_t(&source, &target, dir.path(), options(4)).await;
    assert_eq!(summary.status, RunStatus::Ok, "{summary:?}");
    assert_eq!(source.snapshot(), target.snapshot());

    let dir = tempfile::tempdir().expect("tempdir");
    let unclaimed = FakeTarget::new();
    unclaimed.world.lock().expect("lock").schema = Some(fake::SCHEMA_VERSION);
    let summary = run_t(&source, &unclaimed, dir.path(), options(4)).await;
    assert!(
        matches!(summary.error, Some(RunError::Preflight(_))),
        "{summary:?}"
    );
}

fn copy_state(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).expect("state listing") {
        let entry = entry.expect("entry");
        if entry.file_type().expect("type").is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
        }
    }
}

// A copy of a state directory is refused once the original ran again, while a crash inside the generation update is not.
#[tokio::test]
async fn copied_state_directory_is_refused_after_the_original_ran() {
    let source = FakeSource::new();
    seed(&source, 2);
    let target = FakeTarget::new();
    let original = tempfile::tempdir().expect("tempdir");
    let copy = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        run_t(&source, &target, original.path(), options(4))
            .await
            .status,
        RunStatus::Ok
    );
    copy_state(original.path(), copy.path());
    assert_eq!(
        run_t(&source, &target, original.path(), options(4))
            .await
            .status,
        RunStatus::Ok
    );
    let refused = run_t(&source, &target, copy.path(), options(4)).await;
    assert!(
        matches!(&refused.error, Some(RunError::Preflight(message)) if message.contains("another state directory")),
        "{refused:?}"
    );

    let stored = target
        .world
        .lock()
        .expect("lock")
        .claim_generation
        .expect("generation");
    {
        let state = SqliteState::open(original.path()).expect("open");
        state
            .set_meta(MetaKey::ClaimGenerationPending, stored.to_string())
            .await
            .expect("pending");
        state
            .set_meta(
                MetaKey::ClaimGeneration,
                model::ClaimId::random().to_string(),
            )
            .await
            .expect("current");
    }
    assert_eq!(
        run_t(&source, &target, original.path(), options(4))
            .await
            .status,
        RunStatus::Ok
    );
}

// A state that loses the claim swap to another state between its read and its write is refused and leaves the winner's generation.
#[tokio::test]
async fn claim_swap_loser_is_refused() {
    let source = FakeSource::new();
    seed(&source, 2);
    let target = FakeTarget::new();
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        run_t(&source, &target, dir.path(), options(4)).await.status,
        RunStatus::Ok
    );
    let winner = model::ClaimId::random();
    target.world.lock().expect("lock").claim_interloper = Some(winner);
    let refused = run_t(&source, &target, dir.path(), options(4)).await;
    assert!(
        matches!(&refused.error, Some(RunError::Preflight(message)) if message.contains("another state directory")),
        "{refused:?}"
    );
    assert_eq!(
        target.world.lock().expect("lock").claim_generation,
        Some(winner)
    );
}

// An unknown swap outcome is settled by re-reading the generation, and retries reuse the same generation so an ambiguous commit stays recognisable.
#[tokio::test]
async fn unknown_claim_swap_outcome_is_settled_by_a_reread() {
    let source = FakeSource::new();
    seed(&source, 2);
    let target = FakeTarget::new();
    let dir = tempfile::tempdir().expect("tempdir");
    for (faults, expected_swaps) in [
        (vec![SwapFault::UnknownAfterCommit], 1),
        (
            vec![SwapFault::LostBeforeCommit, SwapFault::LostBeforeCommit],
            3,
        ),
        (vec![SwapFault::UnknownAfterCommitStaleRead], 2),
    ] {
        {
            let mut world = target.world.lock().expect("lock");
            world.claim_swaps.clear();
            world.claim_swap_faults = faults.into();
        }
        assert_eq!(
            run_t(&source, &target, dir.path(), options(4)).await.status,
            RunStatus::Ok
        );
        let (swaps, stored) = {
            let world = target.world.lock().expect("lock");
            (world.claim_swaps.clone(), world.claim_generation)
        };
        assert_eq!(swaps.len(), expected_swaps, "{swaps:?}");
        assert!(swaps.windows(2).all(|pair| pair[0] == pair[1]), "{swaps:?}");
        assert_eq!(stored, swaps.last().copied());
        let state = SqliteState::open(dir.path()).expect("open");
        let recorded = state
            .meta(MetaKey::ClaimGeneration)
            .await
            .expect("meta")
            .and_then(|value| model::ClaimId::parse_hex(&value));
        assert_eq!(recorded, stored);
    }
}

// A server that starts after the last collection checkpoint (during the changelog copy) still keeps the account from being marked done.
#[tokio::test]
async fn source_started_after_the_last_checkpoint_is_not_marked_done() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    source.world.lock().expect("lock").starts_on_changelog = true;
    let summary = run_t(&source, &target, dir.path(), options(1)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    let state = SqliteState::open(dir.path()).expect("open");
    let account = state
        .accounts()
        .await
        .expect("accounts")
        .into_iter()
        .find(|account| account.account_id == 1);
    assert!(
        account
            .as_ref()
            .is_none_or(|account| account.phase != state::AccountPhase::Done),
        "{account:?}"
    );
}

async fn report_messages(dir: &Path) -> Vec<String> {
    SqliteState::open(dir)
        .expect("open")
        .reports(ReportFilter::default())
        .await
        .expect("reports")
        .into_iter()
        .map(|row| row.message.into_string())
        .collect()
}

// A restored original that clashed with a name the pass then deleted is retried as itself, not as the converted value.
#[tokio::test]
async fn original_freed_by_a_delete_is_written_without_falling_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry("Domain", 2, serde_json::json!({"name": "a.org"}));
    run_t(&source, &target, dir.path(), options(1)).await;
    source.delete_registry("Domain", 2);
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "a.org", "fallback": true}),
    );
    let summary = run_t(&source, &target, dir.path(), options(1)).await;
    assert_eq!(summary.status, RunStatus::Ok, "{summary:?}");
    assert_eq!(
        target
            .world
            .lock()
            .expect("lock")
            .registry
            .get(&RegistryKey::new("Domain", 1)),
        Some(&serde_json::json!({"name": "a.org", "fallback": true, "v1": true}))
    );
    let messages = report_messages(dir.path()).await;
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("converted value")),
        "{messages:?}"
    );
}

// A unique clash is not retried with the converted value; only a validation rejection falls back, as a Warning naming the fields.
#[tokio::test]
async fn unique_clash_does_not_fall_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry("Domain", 2, serde_json::json!({"name": "a.org"}));
    run_t(&source, &target, dir.path(), options(1)).await;
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "a.org", "fallback": true}),
    );
    source.put_registry(
        "Domain",
        3,
        serde_json::json!({"name": "c.org", "invalid": true, "fallback": true}),
    );
    run_t(&source, &target, dir.path(), options(1)).await;
    let state = SqliteState::open(dir.path()).expect("open");
    let rows = state
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    let subject = |id: u64| {
        rows.iter()
            .filter(move |row| row.object.as_deref() == Some("Domain") && row.object_id == Some(id))
    };
    assert!(
        !subject(1).any(|row| row.message.contains("converted value")),
        "{rows:?}"
    );
    assert!(
        subject(3).any(|row| row.severity == Severity::Warning
            && row.message.contains("drops or changes: fallback, invalid")),
        "{rows:?}"
    );
}

// A unique name moved to another object within one page converges through the conflict retry, without any delete in the run.
#[tokio::test]
async fn unique_name_moved_within_a_page_converges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry("Domain", 1, serde_json::json!({"name": "a.org"}));
    source.put_registry("Domain", 2, serde_json::json!({"name": "b.org"}));
    assert_eq!(
        run_t(&source, &target, dir.path(), options(1)).await.status,
        RunStatus::Ok
    );
    source.put_registry("Domain", 1, serde_json::json!({"name": "b.org"}));
    source.put_registry("Domain", 2, serde_json::json!({"name": "c.org"}));
    let summary = run_t(&source, &target, dir.path(), options(1)).await;
    assert_eq!(summary.status, RunStatus::Ok, "{summary:?}");
    let name = |id: u64| {
        target
            .world
            .lock()
            .expect("lock")
            .registry
            .get(&RegistryKey::new("Domain", id))
            .and_then(|json| json.get("name").cloned())
    };
    assert_eq!(name(1), Some(serde_json::json!("b.org")));
    assert_eq!(name(2), Some(serde_json::json!("c.org")));
}

// A cycle object whose full write is rejected after its placeholder write is an Error row naming the placeholder fields.
#[tokio::test]
async fn rejected_cycle_completion_names_the_placeholder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry(
        "Cyclic",
        1,
        serde_json::json!({"name": "loop", "ref": "dangling"}),
    );
    let summary = run_t(&source, &target, dir.path(), options(1)).await;
    assert_eq!(summary.status, RunStatus::Failed);
    let messages = report_messages(dir.path()).await;
    assert!(
        messages.iter().any(
            |message| message.contains("written with placeholders for ref")
                && message.contains("unknown reference")
        ),
        "{messages:?}"
    );
}

fn mapped_converter(objects: &[RegistryRecord]) -> migrate::converter::MappingConverter {
    use mapping::{
        Answer, Answers, Direction, Mapping, Options, PromptId, SourceObject, ToolQuestions,
    };
    let mapping = Mapping::embedded().expect("mapping");
    let options = Options {
        tool_questions: ToolQuestions::Skip,
        ..Options::default()
    };
    let probe = mapping
        .session(Direction::Forward, &Answers::default(), options.clone())
        .convert_all(
            objects
                .iter()
                .map(|record| SourceObject {
                    key: migrate::converter::object_key(&record.key),
                    value: record.json.clone(),
                })
                .collect(),
        );
    let mut answers = Answers::default();
    for question in &probe.report.questions {
        answers.set(
            question.prompt,
            question.key.clone(),
            question.defaults.clone(),
        );
    }
    if answers.get(PromptId::ChangedDefaults, None).is_none() {
        answers.set(PromptId::ChangedDefaults, None, Answer::new());
    }
    migrate::converter::MappingConverter::new(mapping, answers, options)
}

// v0.16 keeps the archived items of a deleted account: they are dropped with a warning instead of blocking every later run, and their copies are deleted from the target.
#[tokio::test]
async fn archived_items_of_a_deleted_account_do_not_block_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for account_id in 2..=3 {
        source.put(account_id, mailbox(0, "Inbox"));
        source.set_pointers(account_id, AccountPointers::default());
    }
    let archived = |account: &str| serde_json::json!({"@type": "Email", "accountId": account, "archivedAt": "2026-10-22T08:23:21Z", "archivedUntil": "2026-11-21T08:23:21Z", "receivedAt": "2026-10-01T00:00:00Z", "size": 10, "status": "archived"});
    let objects = [
        ("Domain", 7, serde_json::json!({"name": "example.org"})),
        (
            "Account",
            2,
            serde_json::json!({"@type": "User", "name": "john", "domainId": "h"}),
        ),
        (
            "Account",
            3,
            serde_json::json!({"@type": "User", "name": "jane", "domainId": "h"}),
        ),
        ("ArchivedItem", 10, archived("d")),
        ("ArchivedItem", 11, archived("d")),
        ("ArchivedItem", 12, archived("c")),
    ];
    let mut records = Vec::new();
    for (object, id, json) in objects {
        source.put_registry(object, id, json.clone());
        records.push(RegistryRecord {
            key: RegistryKey::new(object, id),
            json,
        });
    }
    let converter = Arc::new(mapped_converter(&records));
    let run = |kind: RunKind| {
        let source = source.clone();
        let target = target.clone();
        let converter = converter.clone();
        let dir = dir.path().to_owned();
        async move {
            let mut options = options(8);
            options.kind = kind;
            Orchestrator::new(
                source.clone(),
                target.clone(),
                FakeReader::new(&target, &source),
                Arc::new(SqliteState::open(&dir).expect("open state")),
                converter,
                options,
                Shutdown::default(),
            )
            .run()
            .await
            .expect("run")
        }
    };
    let archived_in_target = || {
        let world = target.world.lock().expect("lock");
        (10..=12)
            .filter(|id| {
                world
                    .registry
                    .contains_key(&RegistryKey::new("x:ArchivedItem", *id))
            })
            .collect::<Vec<u64>>()
    };
    let summary = run(RunKind::Incremental).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(archived_in_target(), [10, 11, 12]);

    source.remove_account(3);
    source.delete_registry("Account", 3);
    let summary = run(RunKind::Incremental).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(archived_in_target(), [12]);
    assert!(
        !target
            .world
            .lock()
            .expect("lock")
            .registry
            .contains_key(&RegistryKey::new("x:Account", 3))
    );
    let warnings = SqliteState::open(dir.path())
        .expect("open state")
        .reports(ReportFilter {
            severity: Some(Severity::Warning),
            ..Default::default()
        })
        .await
        .expect("reports");
    for id in [10, 11] {
        assert!(
            warnings.iter().any(|row| row.object_id == Some(id)
                && row.message.contains("is not listed by the source")),
            "{warnings:#?}"
        );
    }

    let summary = run(RunKind::Final).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        summary.verify.as_ref().map(|verify| verify.status),
        Some(RunStatus::Ok)
    );
    assert_eq!(archived_in_target(), [12]);
}

// When the mass-removal guard holds account deletions, the objects those accounts own are held too instead of being deleted as orphans (70 more items of a kept account keep the per-type guard quiet).
#[tokio::test]
async fn objects_of_held_accounts_are_not_deleted_as_orphans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    let mut records = vec![RegistryRecord {
        key: RegistryKey::new("Domain", 7),
        json: serde_json::json!({"name": "example.org"}),
    }];
    for account_id in 1..=30u32 {
        source.put(account_id, mailbox(0, "Inbox"));
        source.set_pointers(account_id, AccountPointers::default());
        let jmap = JmapId(u64::from(account_id)).to_string();
        records.push(RegistryRecord {
            key: RegistryKey::new("Account", u64::from(account_id)),
            json: serde_json::json!({"@type": "User", "name": format!("user{account_id}"), "domainId": "h"}),
        });
        records.push(RegistryRecord {
            key: RegistryKey::new("ArchivedItem", 100 + u64::from(account_id)),
            json: serde_json::json!({"@type": "Email", "accountId": jmap, "archivedAt": "2026-10-22T08:23:21Z", "archivedUntil": "2026-11-21T08:23:21Z", "receivedAt": "2026-10-01T00:00:00Z", "size": 10, "status": "archived"}),
        });
    }
    for id in 200..270u64 {
        records.push(RegistryRecord {
            key: RegistryKey::new("ArchivedItem", id),
            json: serde_json::json!({"@type": "Email", "accountId": "b", "archivedAt": "2026-10-22T08:23:21Z", "archivedUntil": "2026-11-21T08:23:21Z", "receivedAt": "2026-10-01T00:00:00Z", "size": 10, "status": "archived"}),
        });
    }
    for record in &records {
        source.put_registry(
            &record.key.object,
            record.key.id.id().expect("id"),
            record.json.clone(),
        );
    }
    let converter = Arc::new(mapped_converter(&records));
    let run = |removals: RemovalPolicy| {
        let source = source.clone();
        let target = target.clone();
        let converter = converter.clone();
        let dir = dir.path().to_owned();
        async move {
            let mut options = options(8);
            options.removals = removals;
            Orchestrator::new(
                source.clone(),
                target.clone(),
                FakeReader::new(&target, &source),
                Arc::new(SqliteState::open(&dir).expect("open state")),
                converter,
                options,
                Shutdown::default(),
            )
            .run()
            .await
            .expect("run")
        }
    };
    let archived = || {
        let world = target.world.lock().expect("lock");
        (101..=130)
            .filter(|id| {
                world
                    .registry
                    .contains_key(&RegistryKey::new("x:ArchivedItem", *id))
            })
            .count()
    };
    assert_eq!(run(RemovalPolicy::Guarded).await.status, RunStatus::Ok);
    assert_eq!(archived(), 30);
    for account_id in 21..=30u32 {
        source.remove_account(account_id);
        source.delete_registry("Account", u64::from(account_id));
    }
    let summary = run(RemovalPolicy::Guarded).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(
        archived(),
        30,
        "archived items of held accounts were deleted"
    );
    let summary = run(RemovalPolicy::Guarded).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(archived(), 30, "a second held run deleted them");
    let summary = run(RemovalPolicy::Allow).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(archived(), 20);
}

// A held domain removal holds the accounts that belong to it, their owned objects (fixpoint) and their mail data, even when the account guard alone would allow the removal.
#[tokio::test]
async fn domain_guard_holds_its_accounts_their_objects_and_their_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    let jmap = |id: u64| JmapId(id).to_string();
    let mut records = Vec::new();
    for domain in 10..=21u64 {
        records.push(RegistryRecord {
            key: RegistryKey::new("Domain", domain),
            json: serde_json::json!({"name": format!("d{domain}.example.org")}),
        });
    }
    for (account_id, domain) in [(1u32, 20u64), (2, 10), (3, 11)] {
        source.put(account_id, mailbox(0, "Inbox"));
        source.put(account_id, email(0, 0, 1, &[]));
        source.set_pointers(account_id, AccountPointers::default());
        records.push(RegistryRecord {
            key: RegistryKey::new("Account", u64::from(account_id)),
            json: serde_json::json!({"@type": "User", "name": format!("user{account_id}"), "domainId": jmap(domain)}),
        });
        records.push(RegistryRecord {
            key: RegistryKey::new("ArchivedItem", 100 + u64::from(account_id)),
            json: serde_json::json!({"@type": "Email", "accountId": jmap(u64::from(account_id)), "archivedAt": "2026-10-22T08:23:21Z", "archivedUntil": "2026-11-21T08:23:21Z", "receivedAt": "2026-10-01T00:00:00Z", "size": 10, "status": "archived"}),
        });
    }
    for record in &records {
        source.put_registry(
            &record.key.object,
            record.key.id.id().expect("id"),
            record.json.clone(),
        );
    }
    let converter = Arc::new(mapped_converter(&records));
    let run = || {
        let source = source.clone();
        let target = target.clone();
        let converter = converter.clone();
        let dir = dir.path().to_owned();
        async move {
            Orchestrator::new(
                source.clone(),
                target.clone(),
                FakeReader::new(&target, &source),
                Arc::new(SqliteState::open(&dir).expect("open state")),
                converter,
                options(8),
                Shutdown::default(),
            )
            .run()
            .await
            .expect("run")
        }
    };
    let present = |object: &str, ids: &[u64]| {
        let world = target.world.lock().expect("lock");
        ids.iter()
            .filter(|id| world.registry.contains_key(&RegistryKey::new(object, **id)))
            .count()
    };
    assert_eq!(run().await.status, RunStatus::Ok);
    assert_eq!(present("x:ArchivedItem", &[101, 102, 103]), 3);
    for domain in 10..=19u64 {
        source.delete_registry("Domain", domain);
    }
    for account_id in [2u32, 3] {
        source.remove_account(account_id);
        source.delete_registry("Account", u64::from(account_id));
    }
    let summary = run().await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(present("x:Domain", &(10..=19).collect::<Vec<_>>()), 10);
    assert_eq!(
        present("x:Account", &[2, 3]),
        2,
        "held accounts were deleted"
    );
    assert_eq!(
        present("x:ArchivedItem", &[101, 102, 103]),
        3,
        "objects of held accounts were deleted"
    );
    let snapshot = target.snapshot();
    assert!(
        snapshot.contains_key(&2) && snapshot.contains_key(&3),
        "the data of held accounts was wiped"
    );
}

// A report rewrite the target refuses as oversized leaves the earlier copy in place; verify explains the difference with the skip row instead of failing the final run.
#[tokio::test]
async fn oversized_report_rewrite_is_explained() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.world.lock().expect("lock").reports = [internal_report(ReportKind::Dmarc, 1, 5)]
        .into_iter()
        .map(|report| ((report.kind, report.id), report))
        .collect();
    let first = run_t(&source, &target, dir.path(), final_queue_options()).await;
    assert_eq!(first.status, RunStatus::Ok);
    {
        let report = internal_report(ReportKind::Dmarc, 1, 9);
        source
            .world
            .lock()
            .expect("lock")
            .reports
            .insert((report.kind, report.id), report);
    }
    target
        .world
        .lock()
        .expect("lock")
        .oversized_reports
        .insert((ReportKind::Dmarc, 1));
    let mut forced = final_queue_options();
    forced.after_final = AfterFinal::Force;
    let later = run_t(&source, &target, dir.path(), forced).await;
    let verify = later.verify.expect("verify");
    assert_eq!(
        (verify.mismatches, verify.unexplained),
        (1, 0),
        "the stale copy differs, explained by the skip row"
    );
}

// A forced final run after v0.16 was reopened removes the "all updated" rows of the earlier finalize before copying (one of them reused by a real change), so the changelog verifies and each DAV log ends like after a single final run.
#[tokio::test]
async fn forced_final_run_replaces_the_earlier_finalize_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put(1, calendar(0, "Work"));
    source.put(1, event(0, 0, "Meeting"));
    source.put(1, address_book(0, "Friends"));
    source.put(1, contact(0, 0, "Alice"));
    run_t(&source, &target, dir.path(), options(8)).await;
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let first = run_t(&source, &target, dir.path(), final_run.clone()).await;
    assert!(first.succeeded(), "{:?}", first.verify);
    source.put(1, event(1, 0, "Reuses the calendar finalize id"));
    source.put(1, identity(1, "b@example.org"));
    source.put(1, identity(2, "c@example.org"));
    let mut forced = final_run;
    forced.after_final = AfterFinal::Force;
    let later = run_t(&source, &target, dir.path(), forced).await;
    assert!(later.succeeded(), "{:?}", later.verify);
    let world = target.world.lock().expect("lock");
    let account = &world.accounts[&1];
    assert_eq!(account.reopened, 1);
    let counter = source.counter(1);
    for log in [LogCollection::Calendar, LogCollection::AddressBook] {
        let source_rows = source.log_rows(1, log);
        let target_rows: Vec<u64> = account
            .changelog
            .keys()
            .filter(|(collection, _)| *collection == log)
            .map(|(_, change_id)| *change_id)
            .collect();
        let (synthetic, copied) = target_rows.split_last().expect("rows");
        assert_eq!(copied, source_rows.as_slice(), "{log:?}");
        assert_eq!(*synthetic, counter + 1, "{log:?}");
    }
}

// A shutdown during finalize leaves the target finalized but unverified: the run ends interrupted (exit 130, not a verify failure), and repeating run --final without --force-after-final verifies and marks it done, without finalizing or reopening the account again.
#[tokio::test]
async fn shutdown_during_finalize_is_an_interrupted_final_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    source.put(1, calendar(0, "Work"));
    source.put(1, event(0, 0, "Meeting"));
    run_t(&source, &target, dir.path(), options(8)).await;
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    let shutdown = Shutdown::default();
    *target.shutdown_on_finalize.lock().expect("lock") = Some(shutdown.clone());
    let state = Arc::new(SqliteState::open(dir.path()).expect("open state"));
    let interrupted = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target, &source),
        state,
        Arc::new(FakeConverter),
        final_run.clone(),
        shutdown,
    )
    .run()
    .await
    .expect("run");
    *target.shutdown_on_finalize.lock().expect("lock") = None;
    assert_eq!(interrupted.status, RunStatus::Interrupted);
    assert_eq!(
        interrupted.verify.as_ref().map(|verify| verify.status),
        Some(RunStatus::Interrupted)
    );
    assert_eq!(summary_exit_code(&interrupted), EXIT_INTERRUPTED);
    {
        let state = SqliteState::open(dir.path()).expect("open state");
        assert_eq!(state.meta(MetaKey::FinalDone).await.expect("meta"), None);
    }
    let again = run_t(&source, &target, dir.path(), final_run).await;
    assert!(again.succeeded(), "{:?}", again.verify);
    let state = SqliteState::open(dir.path()).expect("open state");
    assert!(
        state
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );
    let world = target.world.lock().expect("lock");
    assert_eq!(world.accounts[&1].finalized, 1);
    assert_eq!(world.accounts[&1].reopened, 0);
}

// A forced incremental run writes to the target again, so the completed final run is no longer marked done and v1 must wait for another run --final; a forced run that preflight refuses keeps the mark.
#[tokio::test]
async fn forced_run_removes_the_final_done_mark() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put(1, calendar(0, "Work"));
    let mut final_run = options(8);
    final_run.kind = RunKind::Final;
    final_run.identity.source_def_hash = Some("source".into());
    assert!(
        run_t(&source, &target, dir.path(), final_run.clone())
            .await
            .succeeded()
    );
    source.put(1, identity(1, "b@example.org"));
    let final_done = || async {
        SqliteState::open(dir.path())
            .expect("open state")
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
    };
    let mut forced = options(8);
    forced.after_final = AfterFinal::Force;
    let mut misdirected = forced.clone();
    misdirected.identity.source_def_hash = Some("another source".into());
    let refused = run_t(&source, &target, dir.path(), misdirected).await;
    assert_eq!(refused.status, RunStatus::Failed, "{:?}", refused.error);
    assert!(final_done().await.is_some());
    assert_eq!(
        run_t(&source, &target, dir.path(), forced).await.status,
        RunStatus::Ok
    );
    assert_eq!(final_done().await, None);
    assert!(
        run_t(&source, &target, dir.path(), final_run)
            .await
            .succeeded()
    );
    assert!(final_done().await.is_some());
}

// v0.16 does not record when a retried task first failed and v1 requires it: the copy dates it from the task's creation, never from the migration time.
#[tokio::test]
async fn retried_tasks_date_their_first_failure_from_creation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    let task = serde_json::json!({
        "@type": "SpamFilterMaintenance",
        "maintenanceType": "train",
        "status": {
            "@type": "Retry",
            "createdAt": "2026-01-01T00:00:00Z",
            "due": "2026-01-02T00:00:00Z",
            "attemptNumber": 2,
            "failureReason": "busy"
        }
    });
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = vec![0];
        world.task_json = Some(task.clone());
    }
    let converter = Arc::new(mapped_converter(&[RegistryRecord {
        key: RegistryKey::new("Task", 0),
        json: task,
    }]));
    let mut categories = CategorySet::defaults();
    categories.insert(Category::Tasks);
    let mut options = options(8);
    options.kind = RunKind::Final;
    options.categories = categories;
    let summary = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target, &source),
        Arc::new(SqliteState::open(dir.path()).expect("open state")),
        converter,
        options,
        Shutdown::default(),
    )
    .run()
    .await
    .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok, "{summary:?}");
    let world = target.world.lock().expect("lock");
    let [(_, task)] = world.tasks.iter().collect::<Vec<_>>()[..] else {
        panic!("one task copied: {:?}", world.tasks);
    };
    let status = &task["status"];
    assert_eq!(status["@type"], "Retry", "{status}");
    assert_eq!(status["firstFailedAt"], "2026-01-01T00:00:00Z", "{status}");
    assert_eq!(status["createdAt"], "2026-01-01T00:00:00Z", "{status}");
}

// A task whose required field has no v1 value would run with the default in its place (a v0.16 removeSieveId store maintenance would become reindexAccounts): the conversion drops it with a warning instead.
#[tokio::test]
async fn tasks_without_a_v1_value_for_a_required_field_are_not_copied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    let task = serde_json::json!({
        "@type": "StoreMaintenance",
        "maintenanceType": "removeSieveId",
        "status": {"@type": "Pending", "createdAt": "2026-01-01T00:00:00Z", "due": "2026-01-02T00:00:00Z"}
    });
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = vec![0];
        world.task_json = Some(task.clone());
    }
    let converter = Arc::new(mapped_converter(&[RegistryRecord {
        key: RegistryKey::new("Task", 0),
        json: task,
    }]));
    let mut categories = CategorySet::defaults();
    categories.insert(Category::Tasks);
    let mut options = options(8);
    options.kind = RunKind::Final;
    options.categories = categories;
    let state = Arc::new(SqliteState::open(dir.path()).expect("open state"));
    let summary = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target, &source),
        state.clone(),
        converter,
        options,
        Shutdown::default(),
    )
    .run()
    .await
    .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok, "{summary:?}");
    assert!(target.world.lock().expect("lock").tasks.is_empty());
    let rows = state
        .reports(ReportFilter {
            severity: Some(Severity::Warning),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert!(
        rows.iter().any(|row| row.object.as_deref() == Some("Task")
            && row.object_id == Some(0)
            && row.message.contains("maintenanceType: dropped")),
        "{rows:?}"
    );
}

// Registry objects removed together are deleted in the order their stored references require, after a reference cycle among them is unlinked, so a target that refuses to delete a linked object accepts every delete.
#[tokio::test]
async fn linked_registry_objects_are_deleted_referencing_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "gone.org", "accountId": "c"}),
    );
    source.put_registry("Domain", 9, serde_json::json!({"name": "kept.org"}));
    for (id, domain) in [(2, "b"), (3, "b"), (4, "j")] {
        source.put_registry(
            "Account",
            id,
            serde_json::json!({"name": format!("user{id}"), "domainId": domain}),
        );
    }
    source.put_registry(
        "ApiKey",
        5,
        serde_json::json!({"name": "key", "accountId": "c"}),
    );
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    for (object, id) in [("Domain", 1), ("Account", 2), ("Account", 3), ("ApiKey", 5)] {
        source.delete_registry(object, id);
    }
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.registry_deleted, 4);
    let world = target.world.lock().expect("lock");
    let mut kept: Vec<String> = world.registry.keys().map(ToString::to_string).collect();
    kept.sort();
    assert_eq!(kept, ["Account/4", "Domain/9"]);
}

fn registry_cycles(source: &FakeSource, cycles: &[(u64, u64)]) {
    for &(domain, account) in cycles {
        source.put_registry(
            "Domain",
            domain,
            serde_json::json!({"name": format!("d{domain}.org"), "accountId": JmapId(account).to_string()}),
        );
        source.put_registry(
            "Account",
            account,
            serde_json::json!({"name": format!("user{account}"), "domainId": JmapId(domain).to_string()}),
        );
    }
}

// A rejected unlink write of a reference cycle is in the report even though the delete it was meant to allow then fails the run.
#[tokio::test]
async fn rejected_unlink_is_reported_before_the_deletes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    registry_cycles(&source, &[(1, 2)]);
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    source.delete_registry("Domain", 1);
    source.delete_registry("Account", 2);
    target
        .world
        .lock()
        .expect("lock")
        .rejected_registry
        .insert(RegistryKey::new("Account", 2));
    let mut allowed = options(8);
    allowed.removals = RemovalPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), allowed).await;
    assert_ne!(summary.status, RunStatus::Ok);
    let rows = SqliteState::open(dir.path())
        .expect("state")
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(
        rows.iter()
            .any(|row| row.object.as_deref() == Some("Account")
                && row.object_id == Some(2)
                && row.message.contains("rejected by target validation")),
        "{rows:?}"
    );
}

// Unlink writes that the target finds too large are split like every other registry write.
#[tokio::test]
async fn too_large_unlink_writes_are_split() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    registry_cycles(&source, &[(1, 2), (3, 4)]);
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    for (domain, account) in [(1, 2), (3, 4)] {
        source.delete_registry("Domain", domain);
        source.delete_registry("Account", account);
    }
    target.world.lock().expect("lock").registry_too_large_above = Some(1);
    let mut allowed = options(8);
    allowed.removals = RemovalPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), allowed).await;
    assert_eq!(summary.status, RunStatus::Ok, "{:?}", summary.error);
    assert_eq!(summary.stats.registry_deleted, 4);
    assert!(target.world.lock().expect("lock").registry.is_empty());
}

// The delete plan reads only deleted objects that can link to other deleted objects; the converter names the rest and they are never read for it.
#[tokio::test]
async fn deletes_without_references_are_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    registry_cycles(&source, &[(1, 2)]);
    for id in 1..=40 {
        source.put_registry(UNLINKED_OBJECT, id, serde_json::json!({"value": id}));
    }
    let summary = run_t(&source, &target, dir.path(), options(8)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    source.delete_registry("Domain", 1);
    source.delete_registry("Account", 2);
    for id in 1..=40 {
        source.delete_registry(UNLINKED_OBJECT, id);
    }
    target.world.lock().expect("lock").registry_reads.clear();
    let mut allowed = options(8);
    allowed.removals = RemovalPolicy::Allow;
    let summary = run_t(&source, &target, dir.path(), allowed).await;
    assert_eq!(summary.status, RunStatus::Ok, "{:?}", summary.error);
    assert_eq!(summary.stats.registry_deleted, 42);
    let world = target.world.lock().expect("lock");
    assert!(world.registry.is_empty());
    let unlinked = world
        .registry_reads
        .keys()
        .filter(|key| &*key.object == UNLINKED_OBJECT)
        .count();
    assert!(unlinked <= 16, "{unlinked} deleted settings were read");
    assert!(
        world
            .registry_reads
            .contains_key(&RegistryKey::new("Domain", 1))
    );
    assert!(
        world
            .registry_reads
            .contains_key(&RegistryKey::new("Account", 2))
    );
}

// Telemetry passes reread their lookback window; a record seen by an earlier pass is neither written nor reported again, so a skipped span keeps one report row and each span is written once.
#[tokio::test]
async fn reread_telemetry_is_written_and_reported_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 0);
    source.world.lock().expect("lock").spans = (1..=5)
        .map(|id| (id, serde_json::json!({"events": [id]})))
        .collect();
    target.world.lock().expect("lock").skipped_spans.insert(2);
    let mut telemetry = options(8);
    telemetry.categories.insert(Category::Telemetry);
    let mut written = Vec::new();
    for pass in 0..3 {
        if pass == 2 {
            source
                .world
                .lock()
                .expect("lock")
                .spans
                .insert(6, serde_json::json!({"events": [6]}));
        }
        let summary = run_t(&source, &target, dir.path(), telemetry.clone()).await;
        assert_eq!(summary.status, RunStatus::Ok);
        written.push(summary.stats.global_records);
    }
    assert_eq!(written, [5, 0, 1]);
    assert_eq!(target.world.lock().expect("lock").global, 6);
    let rows = SqliteState::open(dir.path())
        .expect("state")
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert_eq!(
        rows.iter()
            .filter(|row| row.object.as_deref() == Some("span"))
            .count(),
        1,
        "{rows:#?}"
    );
}

// A target write that never completes fails its account with a timeout error instead of hanging the run.
#[tokio::test]
async fn stuck_target_write_times_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    target
        .upsert_delays
        .lock()
        .expect("lock")
        .push((1, 0, Duration::from_secs(3600)));
    let mut options = options(8);
    options.write_timeout = Duration::from_millis(100);
    options.retry.max_attempts = 2;
    let summary = tokio::time::timeout(
        Duration::from_secs(60),
        run_t(&source, &target, dir.path(), options),
    )
    .await
    .expect("the run hangs on a stuck target write");
    assert_eq!(summary.status, RunStatus::Failed, "{summary:?}");
    assert_eq!(summary.stats.accounts_failed, 1, "{summary:?}");
    assert_eq!(
        target.in_flight.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let rows = SqliteState::open(dir.path())
        .expect("state")
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(
        rows.iter()
            .any(|row| row.message.contains("did not finish within")),
        "{rows:#?}"
    );
}
