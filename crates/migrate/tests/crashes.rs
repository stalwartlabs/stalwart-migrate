/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod fake;

use std::{path::Path, sync::Arc, time::Duration};

use fake::{
    CommitKind, CrashPoint, DAV_LOGS, FakeReader, FakeSource, FakeTarget, Fault, FaultOp,
    PrefixedConverter, address_book, calendar, contact, directory, email, event, file, identity,
    lossy_event, mailbox, notification, queued_message, sieve, submission,
};
use mapping::ids::JmapId;
use migrate::{
    orchestrator::{
        AfterFinal, BlobMode, Orchestrator, RemovalPolicy, RetryPolicy, RunError, RunKind,
        RunOptions, RunSummary, Tuning,
    },
    shutdown::Shutdown,
};
use model::{AccountPointers, BlobHash, Category, Collection, Edition, Pointer, RegistryKey};
use state::{AccountPhase, RegistryState, ReportFilter, RunStatus, SqliteState, StateStore};

const ACCOUNTS: u32 = 2;

fn options(kind: RunKind) -> RunOptions {
    let mut options = RunOptions::new(kind, Edition::Enterprise);
    options.tuning = Tuning {
        concurrency: 2,
        batch_ops: 3,
        batch_bytes: 1 << 20,
        blob_concurrency: 2,
        read_ahead: 2,
        max_ops_per_sec: None,
        account_split: 2,
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

fn orchestrator(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
) -> Orchestrator<FakeSource, FakeTarget, FakeReader, SqliteState, PrefixedConverter> {
    Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        Arc::new(SqliteState::open(dir).expect("open state")),
        Arc::new(PrefixedConverter),
        options,
        Shutdown::default(),
    )
}

async fn run(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
) -> RunSummary {
    orchestrator(source, target, dir, options)
        .run()
        .await
        .expect("run succeeds")
}

async fn run_until(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
    point: CrashPoint,
) -> bool {
    *target.crash_at.lock().expect("lock") = Some(CrashPoint {
        after: target.commits(point.kind) + point.after,
        ..point
    });
    let orchestrator = orchestrator(source, target, dir, options);
    let crashed = tokio::select! {
        result = orchestrator.run() => {
            let _: Result<RunSummary, RunError> = result;
            false
        }
        _ = target.crashed.notified() => true,
    };
    *target.crash_at.lock().expect("lock") = None;
    crashed
}

async fn run_until_upsert(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
    after: u64,
) -> bool {
    let base = target.world.lock().expect("lock").upserts;
    *target.crash_after_commits.lock().expect("lock") = Some(base + after);
    let orchestrator = orchestrator(source, target, dir, options);
    let crashed = tokio::select! {
        result = orchestrator.run() => {
            result.expect("run succeeds");
            false
        }
        _ = target.crashed.notified() => true,
    };
    *target.crash_after_commits.lock().expect("lock") = None;
    crashed
}

fn seed_account(source: &FakeSource, account_id: u32) {
    source.put(account_id, mailbox(0, "Inbox"));
    source.put(account_id, mailbox(1, "Archive"));
    for id in 0..6 {
        source.put(account_id, email(id, id % 2, id + 1, &["$seen"]));
    }
    source.put(account_id, identity(0, "user@example.org"));
    source.put(account_id, sieve(3, "main"));
    source.put(account_id, calendar(0, "Personal"));
    source.put(account_id, calendar(1, "Work"));
    for id in 0..5 {
        source.put(account_id, event(id, id % 2, "Meeting"));
    }
    source.put(account_id, address_book(0, "Contacts"));
    for id in 0..4 {
        source.put(account_id, contact(id, 0, "Jane"));
    }
    for id in 0..3 {
        source.put(account_id, notification(id, Some(id)));
    }
    for id in 0..3 {
        source.put(
            account_id,
            submission(id, id, 1_700_000_000 + u64::from(id)),
        );
    }
    source.put(account_id, directory(0, None));
    source.put(account_id, file(1, Some(0)));
    source.put(account_id, directory(2, Some(0)));
    source.put(account_id, file(3, Some(2)));
    source.set_pointers(
        account_id,
        AccountPointers {
            active_script: Pointer::Set(Some(3)),
            default_calendar: Pointer::Set(Some(0)),
            default_address_book: Pointer::Set(Some(0)),
            ..Default::default()
        },
    );
}

fn grouped_source() -> Arc<FakeSource> {
    let source = FakeSource::new();
    source.world.lock().expect("lock").grouped = true;
    source.put_blob(BlobHash([200; 32]), b"keep;stop;");
    source.put_blob(BlobHash([201; 32]), b"file!");
    for byte in 0..7u8 {
        source.put_blob(BlobHash([byte; 32]), b"message body");
    }
    for account_id in 1..=ACCOUNTS {
        seed_account(&source, account_id);
    }
    source.put_registry("Domain", 1, serde_json::json!({"name": "example.org"}));
    for account_id in 1..=ACCOUNTS {
        source.put_registry(
            "Account",
            u64::from(account_id),
            serde_json::json!({"name": format!("user{account_id}")}),
        );
    }
    source
}

fn change_every_collection(source: &FakeSource) {
    source.put(1, mailbox(2, "Projects"));
    source.put(1, mailbox(1, "Old archive"));
    source.put(1, email(10, 2, 1, &[]));
    source.put(1, email(3, 1, 4, &["$seen", "$flagged"]));
    for id in [0, 1, 2, 5] {
        source.delete(1, Collection::Email, id);
    }
    source.put(1, identity(1, "alias@example.org"));
    source.delete(1, Collection::Identity, 0);
    source.put(1, sieve(4, "filters"));
    source.put(1, calendar(1, "Work renamed"));
    source.put(1, calendar(2, "Holidays"));
    source.put(1, event(1, 1, "Moved"));
    source.put(1, event(7, 2, "Holiday"));
    for id in [0, 2, 4] {
        source.delete(1, Collection::CalendarEvent, id);
    }
    source.delete(1, Collection::Calendar, 0);
    source.put(1, address_book(1, "Work contacts"));
    source.put(1, contact(2, 1, "Renamed"));
    source.put(1, contact(9, 1, "New"));
    for id in [0, 1, 3] {
        source.delete(1, Collection::ContactCard, id);
    }
    source.put(1, notification(3, Some(7)));
    source.delete(1, Collection::CalendarEventNotification, 0);
    source.delete(1, Collection::CalendarEventNotification, 1);
    source.put(1, submission(2, 3, 1_800_000_000));
    source.put(1, submission(5, 10, 1_800_000_001));
    source.delete(1, Collection::EmailSubmission, 0);
    source.put(1, directory(4, Some(2)));
    source.put(1, file(5, Some(4)));
    source.delete(1, Collection::FileNode, 1);
    source.delete(1, Collection::FileNode, 3);
    source.put(2, event(9, 0, "Other account"));
    source.delete(2, Collection::ContactCard, 3);
}

fn assert_synced(source: &FakeSource, target: &FakeTarget, case: &str) {
    assert_eq!(source.snapshot(), target.snapshot(), "{case}");
    assert_eq!(target.duplicates(), 0, "duplicate email ingests, {case}");
    assert_eq!(
        target.world.lock().expect("lock").orphans,
        0,
        "file written before its parent, {case}"
    );
}

async fn assert_all_done(source: &FakeSource, dir: &Path, case: &str) {
    let state = SqliteState::open(dir).expect("open state");
    let accounts = state.accounts().await.expect("accounts");
    assert_eq!(accounts.len(), source.snapshot().len(), "{case}");
    for account in accounts {
        assert_eq!(account.phase, AccountPhase::Done, "{case}");
        assert_eq!(
            account.checkpoint,
            Some(source.counter(account.account_id)),
            "{case}"
        );
    }
}

async fn assert_final_verifies(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    case: &str,
) {
    let summary = run(source, target, dir, options(RunKind::Final)).await;
    assert_eq!(summary.status, RunStatus::Ok, "{case}");
    let verify = summary.verify.expect("verify");
    assert_eq!(
        (verify.status, verify.unexplained),
        (RunStatus::Ok, 0),
        "{case}"
    );
    assert_synced(source, target, case);
}

// A crash after any record commit of a first copy of every collection (grouped change counters, like v1) resumes to an exact copy.
#[tokio::test]
async fn every_collection_resumes_after_a_crash_at_any_commit() {
    for after in 1u64.. {
        let case = format!("crash after commit {after}");
        let dir = tempfile::tempdir().expect("tempdir");
        let source = grouped_source();
        let target = FakeTarget::new();
        if !run_until_upsert(
            &source,
            &target,
            dir.path(),
            options(RunKind::Incremental),
            after,
        )
        .await
        {
            assert!(after > 20, "only {after} commits");
            break;
        }
        let summary = run(&source, &target, dir.path(), options(RunKind::Incremental)).await;
        assert_eq!(summary.status, RunStatus::Ok, "{case}");
        assert_synced(&source, &target, &case);
        assert_all_done(&source, dir.path(), &case).await;
        assert_final_verifies(&source, &target, dir.path(), &case).await;
    }
}

fn assert_one_finalize_row(source: &FakeSource, target: &FakeTarget, case: &str) {
    let world = target.world.lock().expect("lock");
    for (account_id, account) in &world.accounts {
        for log in DAV_LOGS {
            let rows: Vec<u64> = account
                .changelog
                .keys()
                .filter(|(collection, _)| *collection == log)
                .map(|(_, change_id)| *change_id)
                .collect();
            let Some((_, copied)) = rows.split_last() else {
                continue;
            };
            assert_eq!(
                copied,
                source.log_rows(*account_id, log).as_slice(),
                "{case}, account {account_id} {log:?}"
            );
        }
    }
}

async fn finalized_then_changed(dir: &Path, case: &str) -> (Arc<FakeSource>, Arc<FakeTarget>) {
    let source = grouped_source();
    let target = FakeTarget::new();
    run(&source, &target, dir, options(RunKind::Incremental)).await;
    let first = run(&source, &target, dir, options(RunKind::Final)).await;
    assert!(first.succeeded(), "{case}: {:?}", first.verify);
    change_every_collection(&source);
    (source, target)
}

fn forced_final() -> RunOptions {
    let mut forced = options(RunKind::Final);
    forced.after_final = AfterFinal::Force;
    forced
}

async fn assert_forced_final_resumes(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    case: &str,
) {
    let summary = run(source, target, dir, forced_final()).await;
    assert!(summary.succeeded(), "{case}: {:?}", summary.verify);
    assert_synced(source, target, case);
    assert_one_finalize_row(source, target, case);
}

// A forced final run after v0.16 was reopened and changed resumes after a crash at any record commit; the earlier finalize rows are gone and each DAV log ends with one finalize row, as after a single final run.
#[tokio::test]
async fn forced_final_run_resumes_after_a_crash_at_any_commit() {
    for after in 1u64.. {
        let case = format!("crash after forced final commit {after}");
        let dir = tempfile::tempdir().expect("tempdir");
        let (source, target) = finalized_then_changed(dir.path(), &case).await;
        if !run_until_upsert(&source, &target, dir.path(), forced_final(), after).await {
            assert!(after > 5, "only {after} forced final commits");
            break;
        }
        assert_forced_final_resumes(&source, &target, dir.path(), &case).await;
    }
}

// A crash at the reopen of an account (after it, or with half of its logs cleared) or after any changelog write that follows it resumes to the same end state.
#[tokio::test]
async fn forced_final_run_resumes_after_a_crash_at_the_reopen_or_a_log_write() {
    for kind in [CommitKind::Reopen, CommitKind::Changelog] {
        for partial in [false, true] {
            for after in 1u64.. {
                let case = format!("crash after {kind:?} {after}, partial {partial}");
                let dir = tempfile::tempdir().expect("tempdir");
                let (source, target) = finalized_then_changed(dir.path(), &case).await;
                let point = CrashPoint {
                    kind,
                    after,
                    partial,
                };
                if !run_until(&source, &target, dir.path(), forced_final(), point).await {
                    assert!(after > 1, "no {kind:?} commit, {case}");
                    break;
                }
                assert_forced_final_resumes(&source, &target, dir.path(), &case).await;
            }
        }
    }
}

// An account revisited only for a newly included category that crashes right after its reopen is still copied and finalized by a next run that excludes the category again, so it does not end without finalize rows.
#[tokio::test]
async fn reopened_account_is_finalized_after_the_category_is_dropped_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = grouped_source();
    let target = FakeTarget::new();
    let without_files = |mut options: RunOptions| {
        options.categories.remove(Category::Files);
        options
    };
    run(
        &source,
        &target,
        dir.path(),
        without_files(options(RunKind::Incremental)),
    )
    .await;
    let first = run(
        &source,
        &target,
        dir.path(),
        without_files(options(RunKind::Final)),
    )
    .await;
    assert!(first.succeeded(), "{:?}", first.verify);
    let point = CrashPoint {
        kind: CommitKind::Reopen,
        after: 1,
        partial: false,
    };
    assert!(run_until(&source, &target, dir.path(), forced_final(), point).await);
    let summary = run(&source, &target, dir.path(), without_files(forced_final())).await;
    assert!(summary.succeeded(), "{:?}", summary.verify);
    assert_one_finalize_row(&source, &target, "category dropped again");
    let world = target.world.lock().expect("lock");
    assert!(
        world
            .accounts
            .values()
            .any(|account| account.finalized == 2)
    );
}

// A transient failure of the reopen is retried and the forced final run completes.
#[tokio::test]
async fn transient_reopen_failure_is_retried() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (source, target) = finalized_then_changed(dir.path(), "transient").await;
    target.inject(FaultOp::Reopen, None, Fault::Transient);
    assert_forced_final_resumes(&source, &target, dir.path(), "transient").await;
    assert!(target.faults.lock().expect("lock").is_empty());
}

async fn changed_world(dir: &Path) -> (Arc<FakeSource>, Arc<FakeTarget>) {
    let source = grouped_source();
    let target = FakeTarget::new();
    let summary = run(&source, &target, dir, options(RunKind::Incremental)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    change_every_collection(&source);
    (source, target)
}

// A crash after any record commit of a delta that creates, updates and deletes in every collection resumes to an exact copy.
#[tokio::test]
async fn every_collection_resumes_after_a_crash_during_a_delta() {
    for after in 1u64.. {
        let case = format!("crash after delta commit {after}");
        let dir = tempfile::tempdir().expect("tempdir");
        let (source, target) = changed_world(dir.path()).await;
        if !run_until_upsert(
            &source,
            &target,
            dir.path(),
            options(RunKind::Incremental),
            after,
        )
        .await
        {
            assert!(after > 5, "only {after} delta commits");
            break;
        }
        run(&source, &target, dir.path(), options(RunKind::Incremental)).await;
        assert_synced(&source, &target, &case);
        assert_all_done(&source, dir.path(), &case).await;
        assert_final_verifies(&source, &target, dir.path(), &case).await;
    }
}

// A crash after any delete batch of a delta, whole or half applied, resumes to an exact copy in every collection.
#[tokio::test]
async fn delta_deletes_resume_after_a_crash() {
    for partial in [false, true] {
        for after in 1u64.. {
            let case = format!("crash after delete {after}, partial {partial}");
            let dir = tempfile::tempdir().expect("tempdir");
            let (source, target) = changed_world(dir.path()).await;
            let point = CrashPoint {
                kind: CommitKind::Delete,
                after,
                partial,
            };
            if !run_until(
                &source,
                &target,
                dir.path(),
                options(RunKind::Incremental),
                point,
            )
            .await
            {
                assert!(after > 8, "only {after} delete batches");
                break;
            }
            run(&source, &target, dir.path(), options(RunKind::Incremental)).await;
            assert_synced(&source, &target, &case);
            assert_all_done(&source, dir.path(), &case).await;
            assert_final_verifies(&source, &target, dir.path(), &case).await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum WipeCause {
    Truncation,
    Regression,
    Removal,
}

// A crash during a wipe (whole, or after half of the records) caused by a truncated changelog, a regressed counter or a removed account is wiped again on resume.
#[tokio::test]
async fn interrupted_wipes_are_repeated() {
    for cause in [
        WipeCause::Truncation,
        WipeCause::Regression,
        WipeCause::Removal,
    ] {
        for partial in [false, true] {
            let case = format!("{cause:?}, partial {partial}");
            let dir = tempfile::tempdir().expect("tempdir");
            let (source, target) = changed_world(dir.path()).await;
            match cause {
                WipeCause::Truncation => source.purge_log(1),
                WipeCause::Regression => {
                    let conn =
                        rusqlite::Connection::open(dir.path().join("state.sqlite")).expect("conn");
                    conn.execute_batch(
                        "UPDATE account SET checkpoint = checkpoint + 1000 WHERE account_id = 1;",
                    )
                    .expect("raise the checkpoint");
                }
                WipeCause::Removal => source.remove_account(2),
            }
            let point = CrashPoint {
                kind: CommitKind::Wipe,
                after: 1,
                partial,
            };
            assert!(
                run_until(
                    &source,
                    &target,
                    dir.path(),
                    options(RunKind::Incremental),
                    point
                )
                .await,
                "no wipe, {case}"
            );
            let summary = run(&source, &target, dir.path(), options(RunKind::Incremental)).await;
            assert_eq!(summary.status, RunStatus::Ok, "{case}");
            match cause {
                WipeCause::Removal => assert_eq!(summary.stats.accounts_removed, 1, "{case}"),
                _ => assert_eq!(summary.stats.accounts_wiped, 1, "{case}"),
            }
            assert_synced(&source, &target, &case);
            assert_all_done(&source, dir.path(), &case).await;
            assert_final_verifies(&source, &target, dir.path(), &case).await;
        }
    }
}

const CYCLE_DOMAIN: u64 = 21;
const CYCLE_ACCOUNT: u64 = 22;

fn registry_source() -> Arc<FakeSource> {
    let source = grouped_source();
    for id in 1..=6 {
        source.put_registry("Setting", id, serde_json::json!({"value": id}));
    }
    source.put_registry("Cyclic", 1, serde_json::json!({"ref": "Setting/1"}));
    source.put_registry(
        "Domain",
        CYCLE_DOMAIN,
        serde_json::json!({"name": "cycle.org", "accountId": JmapId(CYCLE_ACCOUNT).to_string()}),
    );
    source.put_registry(
        "Account",
        CYCLE_ACCOUNT,
        serde_json::json!({"name": "cycle", "domainId": JmapId(CYCLE_DOMAIN).to_string()}),
    );
    source.put_registry("Legacy", 1, serde_json::json!({"old": true}));
    source.put_registry("SpamTrainingSample", 1, serde_json::json!({"blob": 200}));
    source.put_registry("Setting", 11, serde_json::json!({"unconvertible": true}));
    source
}

fn registry_options(kind: RunKind) -> RunOptions {
    let mut options = options(kind);
    options.blob_mode = BlobMode::Copy;
    options
}

fn change_registry(source: &FakeSource) {
    source.put_registry("Setting", 1, serde_json::json!({"value": 10}));
    source.put_registry("Setting", 2, serde_json::json!({"value": 20}));
    source.delete_registry("Setting", 5);
    source.delete_registry("Setting", 6);
    source.delete_registry("Legacy", 1);
    source.delete_registry("Domain", CYCLE_DOMAIN);
    source.delete_registry("Account", CYCLE_ACCOUNT);
    source.put_registry("Setting", 7, serde_json::json!({"value": 7}));
    source.put_registry("Setting", 8, serde_json::json!({"value": 8}));
    source.put_registry("Cyclic", 1, serde_json::json!({"ref": "Setting/2"}));
    source.put_registry("Cyclic", 2, serde_json::json!({"ref": "Setting/7"}));
    source.put_registry("SpamTrainingSample", 1, serde_json::json!({"blob": 201}));
    source.put_registry("SpamTrainingSample", 2, serde_json::json!({"blob": 1}));
}

type RegistryImage = (
    std::collections::BTreeMap<RegistryKey, serde_json::Value>,
    Vec<RegistryState>,
);

async fn registry_image(target: &FakeTarget, dir: &Path) -> RegistryImage {
    let state = SqliteState::open(dir).expect("open state");
    let mut rows = Vec::new();
    for object in state.registry_objects().await.expect("objects") {
        rows.extend(state.registry_states(object).await.expect("states"));
    }
    rows.sort_by(|left, right| left.key.cmp(&right.key));
    (target.world.lock().expect("lock").registry.clone(), rows)
}

async fn registry_reference(changed: bool) -> RegistryImage {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = registry_source();
    let target = FakeTarget::new();
    run(
        &source,
        &target,
        dir.path(),
        registry_options(RunKind::Incremental),
    )
    .await;
    if changed {
        change_registry(&source);
        let summary = run(
            &source,
            &target,
            dir.path(),
            registry_options(RunKind::Incremental),
        )
        .await;
        assert_eq!(summary.status, RunStatus::Ok, "{:?}", summary.error);
        let registry = &target.world.lock().expect("lock").registry;
        assert!(!registry.contains_key(&RegistryKey::new("x:Domain", CYCLE_DOMAIN)));
        assert!(!registry.contains_key(&RegistryKey::new("x:Account", CYCLE_ACCOUNT)));
    }
    registry_image(&target, dir.path()).await
}

async fn assert_nothing_pending(dir: &Path, case: &str) {
    let pending = SqliteState::open(dir)
        .expect("open state")
        .registry_pending()
        .await
        .expect("pending");
    assert!(pending.is_empty(), "{case}: {pending:?}");
}

// A crash after any registry write or delete chunk, whole or half applied, in a first copy or in a later run with changes, deletions and reference cycles, resumes to the registry and state rows of an uninterrupted run.
#[tokio::test]
async fn registry_pass_resumes_after_a_crash_at_any_commit() {
    for changed in [false, true] {
        let expected = registry_reference(changed).await;
        for kind in [CommitKind::RegistryWrite, CommitKind::RegistryDelete] {
            if kind == CommitKind::RegistryDelete && !changed {
                continue;
            }
            for partial in [false, true] {
                for after in 1u64.. {
                    let case = format!(
                        "changed {changed}, crash after {kind:?} {after}, partial {partial}"
                    );
                    let dir = tempfile::tempdir().expect("tempdir");
                    let source = registry_source();
                    let target = FakeTarget::new();
                    if changed {
                        run(
                            &source,
                            &target,
                            dir.path(),
                            registry_options(RunKind::Incremental),
                        )
                        .await;
                        change_registry(&source);
                    }
                    let point = CrashPoint {
                        kind,
                        after,
                        partial,
                    };
                    if !run_until(
                        &source,
                        &target,
                        dir.path(),
                        registry_options(RunKind::Incremental),
                        point,
                    )
                    .await
                    {
                        assert!(after > 1, "no {kind:?} commit, {case}");
                        break;
                    }
                    let summary = run(
                        &source,
                        &target,
                        dir.path(),
                        registry_options(RunKind::Incremental),
                    )
                    .await;
                    assert_eq!(summary.status, RunStatus::Ok, "{case}");
                    assert_eq!(
                        registry_image(&target, dir.path()).await,
                        expected,
                        "{case}"
                    );
                    assert_nothing_pending(dir.path(), &case).await;
                    let summary = run(
                        &source,
                        &target,
                        dir.path(),
                        registry_options(RunKind::Final),
                    )
                    .await;
                    assert_eq!(summary.status, RunStatus::Ok, "{case}");
                    let verify = summary.verify.expect("verify");
                    assert_eq!(verify.unexplained, 0, "{case}");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SourceChange {
    Reverted(&'static str, u64),
    Restored(&'static str, u64),
    UnconvertibleThenRestored(&'static str, u64),
    CreatedThenDeleted(&'static str, u64),
}

impl SourceChange {
    fn before_crash(self, source: &FakeSource) -> CommitKind {
        match self {
            SourceChange::Reverted("SpamTrainingSample", id) => {
                source.put_registry("SpamTrainingSample", id, serde_json::json!({"blob": 201}));
                CommitKind::RegistryWrite
            }
            SourceChange::Reverted(object, id) => {
                source.put_registry(object, id, serde_json::json!({"value": 100}));
                CommitKind::RegistryWrite
            }
            SourceChange::Restored(object, id) => {
                source.delete_registry(object, id);
                CommitKind::RegistryDelete
            }
            SourceChange::UnconvertibleThenRestored(object, id) => {
                source.put_registry(object, id, serde_json::json!({"unconvertible": true}));
                CommitKind::RegistryDelete
            }
            SourceChange::CreatedThenDeleted(object, id) => {
                source.put_registry(object, id, serde_json::json!({"value": 100}));
                CommitKind::RegistryWrite
            }
        }
    }

    fn after_crash(self, original: &FakeSource, source: &FakeSource) {
        match self {
            SourceChange::Reverted(object, id)
            | SourceChange::Restored(object, id)
            | SourceChange::UnconvertibleThenRestored(object, id) => {
                let key = RegistryKey::new(object, id);
                let json = original.world.lock().expect("lock").registry[&key].clone();
                source.put_registry(object, id, json);
            }
            SourceChange::CreatedThenDeleted(object, id) => source.delete_registry(object, id),
        }
    }
}

async fn assert_undone_change_is_repaired(changes: &[SourceChange]) {
    let expected = registry_reference(false).await;
    for &change in changes {
        let case = format!("{change:?}");
        let dir = tempfile::tempdir().expect("tempdir");
        let original = registry_source();
        let source = registry_source();
        let target = FakeTarget::new();
        run(
            &source,
            &target,
            dir.path(),
            registry_options(RunKind::Incremental),
        )
        .await;
        let kind = change.before_crash(&source);
        let point = CrashPoint {
            kind,
            after: 1,
            partial: false,
        };
        assert!(
            run_until(
                &source,
                &target,
                dir.path(),
                registry_options(RunKind::Incremental),
                point,
            )
            .await,
            "no crash, {case}"
        );
        assert_ne!(
            target.world.lock().expect("lock").registry,
            expected.0,
            "the crashed commit changed nothing, {case}"
        );
        change.after_crash(&original, &source);
        let summary = run(
            &source,
            &target,
            dir.path(),
            registry_options(RunKind::Incremental),
        )
        .await;
        assert_eq!(summary.status, RunStatus::Ok, "{case}");
        assert_eq!(
            registry_image(&target, dir.path()).await,
            expected,
            "{case}"
        );
        assert_nothing_pending(dir.path(), &case).await;
        let summary = run(
            &source,
            &target,
            dir.path(),
            registry_options(RunKind::Final),
        )
        .await;
        assert_eq!(summary.status, RunStatus::Ok, "{case}");
        assert_eq!(summary.verify.expect("verify").unexplained, 0, "{case}");
    }
}

// A registry write that crashed before its state commit, whose source change is reverted before the next run, is rewritten with the reverted value, or deleted when the reverted value is unconvertible again (plain and blob-holding objects).
#[tokio::test]
async fn reverted_source_change_after_a_crashed_registry_write_is_repaired() {
    assert_undone_change_is_repaired(&[
        SourceChange::Reverted("Setting", 1),
        SourceChange::Reverted("SpamTrainingSample", 1),
        SourceChange::Reverted("Setting", 11),
    ])
    .await;
}

// A registry delete (source deletion or unconvertible value) that crashed before its state commit, whose object comes back unchanged in the source before the next run, is written again.
#[tokio::test]
async fn restored_source_object_after_a_crashed_registry_delete_is_repaired() {
    assert_undone_change_is_repaired(&[
        SourceChange::Restored("Setting", 5),
        SourceChange::UnconvertibleThenRestored("Setting", 3),
    ])
    .await;
}

// A new registry object written before a crash, before any state row existed, and deleted in the source before the next run, is deleted from the target.
#[tokio::test]
async fn new_registry_object_deleted_after_a_crashed_write_is_removed() {
    assert_undone_change_is_repaired(&[SourceChange::CreatedThenDeleted("Setting", 9)]).await;
}

// Many objects written by a crashed run and gone from the source before the resume trip the mass-removal guard with a message naming them as written by the interrupted run; they stay pending until the removal is allowed.
#[tokio::test]
async fn mass_removal_of_orphans_is_held_and_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = registry_source();
    let target = FakeTarget::new();
    run(
        &source,
        &target,
        dir.path(),
        registry_options(RunKind::Incremental),
    )
    .await;
    for id in 20..32 {
        source.put_registry("Setting", id, serde_json::json!({"value": id}));
    }
    let point = CrashPoint {
        kind: CommitKind::RegistryWrite,
        after: 4,
        partial: false,
    };
    assert!(
        run_until(
            &source,
            &target,
            dir.path(),
            registry_options(RunKind::Incremental),
            point,
        )
        .await
    );
    for id in 20..32 {
        source.delete_registry("Setting", id);
    }
    let summary = run(
        &source,
        &target,
        dir.path(),
        registry_options(RunKind::Incremental),
    )
    .await;
    assert_eq!(summary.status, RunStatus::Failed);
    let state = SqliteState::open(dir.path()).expect("open state");
    let rows = state
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(
        rows.iter().any(|row| row
            .message
            .starts_with("12 x:Setting objects written by an interrupted run")),
        "{rows:#?}"
    );
    assert_eq!(state.registry_pending().await.expect("pending").len(), 12);
    drop(state);
    let mut allowed = registry_options(RunKind::Incremental);
    allowed.removals = RemovalPolicy::Allow;
    let summary = run(&source, &target, dir.path(), allowed).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        registry_image(&target, dir.path()).await,
        registry_reference(false).await
    );
    assert_nothing_pending(dir.path(), "allowed").await;
}

fn final_queue_options() -> RunOptions {
    let mut options = options(RunKind::Final);
    options.tuning.batch_ops = 2;
    options.blob_mode = BlobMode::Copy;
    options.categories.insert(Category::Queue);
    options
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

// A crash after any delete of the final-run sweep of vanished queued messages, whole or half applied, is completed by the resumed final run.
#[tokio::test]
async fn final_sweep_resumes_after_a_crash_at_any_delete() {
    for partial in [false, true] {
        for after in 1u64.. {
            let case = format!("crash after sweep delete {after}, partial {partial}");
            let dir = tempfile::tempdir().expect("tempdir");
            let source = grouped_source();
            let target = FakeTarget::new();
            for id in 1..=5u8 {
                source.put_blob(BlobHash([id; 32]), b"message");
            }
            source.world.lock().expect("lock").queued = (1..=5u8)
                .chain([9])
                .map(|id| (u64::from(id), queued_message(u64::from(id), id)))
                .collect();
            let first = run(&source, &target, dir.path(), final_queue_options()).await;
            assert_eq!(first.status, RunStatus::Failed, "{case}");
            assert_eq!(queued_ids(&target), [1, 2, 3, 4, 5], "{case}");
            {
                let mut world = source.world.lock().expect("lock");
                for id in [2, 3, 4, 9] {
                    world.queued.remove(&id);
                }
            }
            let point = CrashPoint {
                kind: CommitKind::GlobalDelete,
                after,
                partial,
            };
            if !run_until(&source, &target, dir.path(), final_queue_options(), point).await {
                assert!(after > 1, "no sweep, {case}");
                break;
            }
            let resumed = run(&source, &target, dir.path(), final_queue_options()).await;
            assert_eq!(resumed.status, RunStatus::Ok, "{case}");
            let verify = resumed.verify.expect("verify");
            assert_eq!(
                (verify.status, verify.unexplained),
                (RunStatus::Ok, 0),
                "{case}"
            );
            assert_eq!(queued_ids(&target), [1, 5], "{case}");
        }
    }
}

async fn lossy_rows(dir: &Path, account_id: u32) -> usize {
    SqliteState::open(dir)
        .expect("open state")
        .reports(ReportFilter::default())
        .await
        .expect("reports")
        .iter()
        .filter(|row| {
            row.account_id == Some(account_id)
                && row.object_id == Some(10)
                && &*row.message == "dead properties dropped"
        })
        .count()
}

async fn assert_lossy_final_explained(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    case: &str,
) {
    let summary = run(source, target, dir, options(RunKind::Final)).await;
    assert_eq!(summary.status, RunStatus::Ok, "{case}");
    let verify = summary.verify.expect("verify");
    assert_eq!(
        (verify.status, verify.unexplained),
        (RunStatus::Ok, 0),
        "{case}"
    );
}

// A crash after the commit of a chunk whose write reported issues, before the issue rows were stored, reports them again on resume, so verify can explain what the target dropped (crash1, account.complete@1).
#[tokio::test]
async fn issue_rows_of_a_crashed_chunk_are_reported_on_resume() {
    for after in 1u64.. {
        let case = format!("crash after commit {after}");
        let dir = tempfile::tempdir().expect("tempdir");
        let source = grouped_source();
        source.put(1, lossy_event(10, 0));
        let target = FakeTarget::new();
        if !run_until_upsert(
            &source,
            &target,
            dir.path(),
            options(RunKind::Incremental),
            after,
        )
        .await
        {
            assert!(after > 20, "only {after} commits");
            break;
        }
        let summary = run(&source, &target, dir.path(), options(RunKind::Incremental)).await;
        assert_eq!(summary.status, RunStatus::Ok, "{case}");
        assert!(lossy_rows(dir.path(), 1).await >= 1, "{case}");
        assert_all_done(&source, dir.path(), &case).await;
        assert_lossy_final_explained(&source, &target, dir.path(), &case).await;
    }
}

// A write whose commit succeeded but answered an error is retried as a rewrite of the committed objects, so their issue rows are reported.
#[tokio::test]
async fn issue_rows_survive_an_unknown_commit_outcome() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    source.put(3, lossy_event(10, 0));
    source.put(3, event(11, 0, "Plain"));
    source.set_pointers(3, AccountPointers::default());
    let target = FakeTarget::new();
    target.inject(FaultOp::Upsert, Some(3), Fault::TransientAfterCommit);
    let summary = run(&source, &target, dir.path(), options(RunKind::Incremental)).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(lossy_rows(dir.path(), 3).await, 1);
    assert_lossy_final_explained(&source, &target, dir.path(), "unknown commit").await;
}
