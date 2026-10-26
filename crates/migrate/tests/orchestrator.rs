/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod fake;

use std::{path::Path, sync::Arc, time::Duration};

use fake::{
    FakeConverter, FakeReader, FakeSource, FakeTarget, Fault, FaultOp, Rec, SCHEMA_VERSION, email,
    identity, mailbox, queued_message, sieve,
};
use migrate::{
    orchestrator::{
        AfterFinal, BlobMode, ErrorPolicy, GlobalCheck, MIN_SAMPLE_ACCOUNTS, Orchestrator,
        RetryPolicy, RunError, RunKind, RunOptions, RunSummary, StoreIdentity, Tuning,
        VerifyOptions, VerifyScope, verify,
    },
    shutdown::Shutdown,
};
use model::{
    AccountPointers, BlobHash, Category, CategorySet, Collection, Edition, Issue, IssueKind,
    LogCollection, Pointer, RegistryId, RegistryKey, Severity, Subject,
};
use state::{
    AccountPhase, ContentHash, MetaKey, RegistryStatus, ReportFilter, RunStatus, SqliteState,
    StateStore,
};

fn options(kind: RunKind) -> RunOptions {
    let mut options = RunOptions::new(kind, Edition::Enterprise);
    options.tuning = Tuning {
        concurrency: 3,
        batch_ops: 4,
        batch_bytes: 1 << 20,
        blob_concurrency: 2,
        read_ahead: 2,
        max_ops_per_sec: None,
        account_split: 3,
    };
    options.retry = RetryPolicy {
        max_attempts: 5,
        budget: Duration::from_secs(30),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    options.categories.insert(Category::Tasks);
    options.final_observation = Duration::ZERO;
    options
}

async fn run_with(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
    shutdown: Shutdown,
) -> Result<RunSummary, RunError> {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
    Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        state,
        Arc::new(FakeConverter),
        options,
        shutdown,
    )
    .run()
    .await
}

async fn run(source: &Arc<FakeSource>, target: &Arc<FakeTarget>, dir: &Path) -> RunSummary {
    run_with(
        source,
        target,
        dir,
        options(RunKind::Incremental),
        Shutdown::default(),
    )
    .await
    .expect("run succeeds")
}

async fn run_until_crash(source: &Arc<FakeSource>, target: &Arc<FakeTarget>, dir: &Path) -> bool {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
    let orchestrator = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        state,
        Arc::new(FakeConverter),
        options(RunKind::Incremental),
        Shutdown::default(),
    );
    tokio::select! {
        result = orchestrator.run() => {
            result.expect("run succeeds");
            false
        }
        _ = target.crashed.notified() => true,
    }
}

fn state(dir: &Path) -> SqliteState {
    SqliteState::open(dir).expect("open state")
}

fn seed(source: &FakeSource, accounts: u32) {
    source.put_blob(BlobHash([200; 32]), b"keep;stop;");
    for account_id in 1..=accounts {
        source.put(account_id, mailbox(0, "Inbox"));
        source.put(account_id, mailbox(1, "Archive"));
        for id in 0..10 {
            source.put(account_id, email(id, id % 2, id + 1, &["$seen"]));
        }
        source.put(account_id, identity(0, "user@example.org"));
        source.put(account_id, sieve(3, "main"));
        source.set_pointers(
            account_id,
            AccountPointers {
                active_script: Pointer::Set(Some(3)),
                default_calendar: Pointer::Set(Some(1)),
                ..Default::default()
            },
        );
    }
    source.put_registry("Domain", 1, serde_json::json!({"name": "example.org"}));
    source.put_registry("Account", 1, serde_json::json!({"name": "user1"}));
    source.put_registry("Account", 2, serde_json::json!({"name": "user2"}));
    source.put_registry("SpamLlm", 9, serde_json::json!({"enable": true}));
}

fn assert_synced(source: &FakeSource, target: &FakeTarget) {
    assert_eq!(source.snapshot(), target.snapshot());
    assert_eq!(target.duplicates(), 0, "duplicate email ingests");
}

async fn assert_all_done(source: &FakeSource, dir: &Path) {
    let state = state(dir);
    let accounts = state.accounts().await.expect("accounts");
    let expected = source.snapshot().len();
    assert_eq!(accounts.len(), expected);
    for account in accounts {
        assert_eq!(
            account.phase,
            AccountPhase::Done,
            "account {}",
            account.account_id
        );
        assert_eq!(account.checkpoint, Some(source.counter(account.account_id)));
        assert!(
            state
                .cursors(account.account_id)
                .await
                .expect("cursors")
                .iter()
                .all(|cursor| cursor.mode.survives_completion())
        );
    }
}

#[tokio::test]
async fn full_copy_then_incremental_delta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.accounts_full, 3);
    assert_eq!(summary.stats.objects_written, 3 * 14);
    assert_synced(&source, &target);
    assert_all_done(&source, dir.path()).await;
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.schema, Some(SCHEMA_VERSION));
        assert!(world.server_started);
        let account = &world.accounts[&1];
        assert_eq!(account.changelog.len(), 14);
        assert_eq!(account.counters.change_id, 14);
        assert_eq!(account.counters.document_id(Collection::Email), Some(9));
        assert_eq!(account.counters.mailbox_uids.len(), 2);
        assert_eq!(account.pointers.active_script, Pointer::Set(Some(3)));
        assert_eq!(world.dangling_scripts, 0);
    }

    source.put(1, email(10, 0, 11, &[]));
    source.put(1, email(3, 1, 4, &["$seen", "$flagged"]));
    source.delete(1, Collection::Email, 5);
    source.put(1, email(11, 0, 12, &[]));
    source.delete(1, Collection::Email, 11);
    source.put(1, mailbox(2, "Projects"));

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.accounts_delta, 1);
    assert_eq!(summary.stats.accounts_unchanged, 2);
    assert_eq!(summary.stats.objects_deleted, 2);
    assert_synced(&source, &target);
    assert_all_done(&source, dir.path()).await;
    {
        let world = target.world.lock().expect("lock");
        let account = &world.accounts[&1];
        assert_eq!(account.changelog.len(), 20);
        assert_eq!(account.counters.change_id, 20);
        assert!(account.changelog.contains_key(&(LogCollection::Email, 20)));
    }
    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.stats.accounts_unchanged, 3);
    assert_eq!(summary.stats.objects_written, 0);
}

#[tokio::test]
async fn truncated_changelog_forces_wipe_and_full_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    run(&source, &target, dir.path()).await;

    source.delete(1, Collection::Email, 2);
    source.put(1, email(20, 0, 30, &[]));
    source.purge_log(1);

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.accounts_wiped, 1);
    assert_eq!(summary.stats.accounts_full, 1);
    assert_synced(&source, &target);
    assert_all_done(&source, dir.path()).await;
    assert!(
        target.world.lock().expect("lock").accounts[&1]
            .changelog
            .is_empty()
    );
}

#[tokio::test]
async fn removed_source_account_is_wiped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    run(&source, &target, dir.path()).await;

    source.remove_account(2);
    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.stats.accounts_removed, 1);
    assert_synced(&source, &target);
    assert_eq!(state(dir.path()).account(2).await, Ok(None));
}

#[tokio::test]
async fn crash_between_target_commit_and_state_update_resumes_cleanly() {
    for crash_at in 1..=10u64 {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        seed(&source, 2);
        *target.crash_after_commits.lock().expect("lock") = Some(crash_at);
        assert!(
            run_until_crash(&source, &target, dir.path()).await,
            "no crash at commit {crash_at}"
        );
        *target.crash_after_commits.lock().expect("lock") = None;

        let summary = run(&source, &target, dir.path()).await;
        assert_eq!(summary.status, RunStatus::Ok, "crash at {crash_at}");
        assert_eq!(summary.interrupted_runs.len(), 1, "crash at {crash_at}");
        assert_synced(&source, &target);
        assert_all_done(&source, dir.path()).await;
    }
}

#[tokio::test]
async fn crash_during_delta_resumes_cleanly() {
    for crash_at in 1..=2u64 {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        seed(&source, 1);
        run(&source, &target, dir.path()).await;

        for id in 30..38 {
            source.put(1, email(id, 0, id, &[]));
        }
        source.delete(1, Collection::Email, 1);
        let base = target.world.lock().expect("lock").upserts;
        *target.crash_after_commits.lock().expect("lock") = Some(base + crash_at);
        assert!(
            run_until_crash(&source, &target, dir.path()).await,
            "no crash at delta commit {crash_at}"
        );
        *target.crash_after_commits.lock().expect("lock") = None;
        assert_eq!(
            state(dir.path())
                .account(1)
                .await
                .expect("read")
                .map(|account| account.phase),
            Some(AccountPhase::Delta)
        );

        run(&source, &target, dir.path()).await;
        assert_synced(&source, &target);
        assert_all_done(&source, dir.path()).await;
    }
}

#[tokio::test]
async fn transient_errors_are_retried_without_duplicates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    target.inject(FaultOp::Upsert, Some(1), Fault::Transient);
    target.inject(FaultOp::Upsert, Some(1), Fault::TransientAfterCommit);
    target.inject(FaultOp::Upsert, Some(2), Fault::TransientAfterCommit);
    target.inject(FaultOp::Changelog, None, Fault::Transient);
    target.inject(FaultOp::Counters, None, Fault::Transient);
    target.inject(FaultOp::Pointers, None, Fault::Transient);

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_synced(&source, &target);
    assert_all_done(&source, dir.path()).await;
    assert!(target.faults.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn oversized_batches_are_split_and_single_failures_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    *target.too_large_above.lock().expect("lock") = Some(1);
    target.poison.lock().expect("lock").insert(7);

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.errors, 1);
    let mut expected = source.snapshot();
    expected
        .get_mut(&1)
        .expect("account")
        .remove(&(Collection::Email, 7));
    assert_eq!(target.snapshot(), expected);
    assert_all_done(&source, dir.path()).await;

    let reports = state(dir.path())
        .reports(ReportFilter {
            severity: Some(Severity::Error),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].object.as_deref(), Some("email"));
    assert_eq!(reports[0].object_id, Some(7));
    assert_eq!(reports[0].account_id, Some(1));
}

#[tokio::test]
async fn account_errors_do_not_stop_other_accounts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 3);
    target.inject(FaultOp::Upsert, Some(2), Fault::Account);

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.accounts_failed, 1);
    {
        let state = state(dir.path());
        let failed = state.account(2).await.expect("read").expect("present");
        assert_eq!(failed.phase, AccountPhase::Error);
        assert_eq!(failed.attempts, 1);
        assert!(failed.last_error.is_some());
        assert_eq!(
            state
                .account(1)
                .await
                .expect("read")
                .map(|account| account.phase),
            Some(AccountPhase::Done)
        );
    }

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_synced(&source, &target);
    assert_all_done(&source, dir.path()).await;
    assert_eq!(
        state(dir.path())
            .account(2)
            .await
            .expect("read")
            .map(|account| account.attempts),
        Some(0)
    );
}

#[tokio::test]
async fn fatal_errors_abort_the_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    target.inject(FaultOp::Upsert, None, Fault::Fatal);

    let summary = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Incremental),
        Shutdown::default(),
    )
    .await
    .expect("summary");
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(matches!(summary.error, Some(RunError::Data(_))));

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_synced(&source, &target);
}

#[tokio::test]
async fn shutdown_finishes_in_flight_batch_and_resumes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 4);
    let shutdown = Shutdown::default();
    *target.shutdown_after_commits.lock().expect("lock") = Some((3, shutdown.clone()));

    let summary = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Incremental),
        shutdown,
    )
    .await
    .expect("summary");
    assert_eq!(summary.status, RunStatus::Interrupted);
    assert!(summary.stats.objects_written >= 3);
    assert!(summary.stats.objects_written < 4 * 14);
    *target.shutdown_after_commits.lock().expect("lock") = None;
    {
        let state = state(dir.path());
        let runs = state.runs(1).await.expect("runs");
        assert_eq!(runs[0].status, RunStatus::Interrupted);
    }

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert!(summary.interrupted_runs.is_empty());
    assert_synced(&source, &target);
    assert_all_done(&source, dir.path()).await;
}

#[tokio::test]
async fn registry_pass_tracks_changes_drops_and_deletions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put_registry(
        "Domain",
        2,
        serde_json::json!({"name": "bad.org", "invalid": true}),
    );

    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.stats.registry_written, 3);
    assert_eq!(summary.stats.registry_dropped, 1);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(
            world.registry[&RegistryKey::new("Account", 1)],
            serde_json::json!({"name": "user1", "v1": true})
        );
        assert!(!world.registry.contains_key(&RegistryKey::new("SpamLlm", 9)));
        assert!(!world.registry.contains_key(&RegistryKey::new("Domain", 2)));
    }
    {
        let state = state(dir.path());
        let accounts = state
            .registry_states("Account".into())
            .await
            .expect("states");
        assert_eq!(accounts.len(), 2);
        let original = state
            .registry_source_json(RegistryKey::new("Account", 2))
            .await
            .expect("json")
            .expect("present");
        assert_eq!(original, br#"{"name":"user2"}"#);
        let domains = state
            .registry_states("Domain".into())
            .await
            .expect("states");
        let invalid = domains
            .iter()
            .find(|entry| entry.key.id == RegistryId::Id(2))
            .expect("invalid domain");
        assert_eq!(invalid.status, RegistryStatus::Error);
        let dropped = state
            .registry_states("SpamLlm".into())
            .await
            .expect("states");
        assert_eq!(dropped[0].status, RegistryStatus::Dropped);
        assert_eq!(
            dropped[0].source_hash,
            ContentHash::of(br#"{"enable":true}"#)
        );
    }

    source.put_registry("Account", 1, serde_json::json!({"name": "renamed"}));
    source.delete_registry("Account", 2);
    source.delete_registry("SpamLlm", 9);
    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.stats.registry_written, 1);
    assert_eq!(summary.stats.registry_deleted, 1);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(
            world.registry[&RegistryKey::new("Account", 1)],
            serde_json::json!({"name": "renamed", "v1": true})
        );
        assert!(!world.registry.contains_key(&RegistryKey::new("Account", 2)));
    }
    let state = state(dir.path());
    assert!(
        state
            .registry_states("SpamLlm".into())
            .await
            .expect("states")
            .is_empty()
    );
    assert_eq!(
        state
            .registry_states("Account".into())
            .await
            .expect("states")
            .len(),
        1
    );
}

#[tokio::test]
async fn blob_copy_mode_copies_each_blob_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    for byte in 0..6u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    let mut copy = options(RunKind::Incremental);
    copy.blob_mode = BlobMode::Copy;
    copy.tuning.account_split = 1;

    let summary = run_with(
        &source,
        &target,
        dir.path(),
        copy.clone(),
        Shutdown::default(),
    )
    .await
    .expect("run");
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.errors, 2);
    assert_eq!(summary.stats.blobs_copied, 7);
    assert_eq!(target.world.lock().expect("lock").blob_puts, 7);
    assert_eq!(
        target.world.lock().expect("lock").blobs_passed,
        (0..6u8)
            .chain([200])
            .map(|byte| BlobHash([byte; 32]))
            .collect(),
        "copied blobs are passed to the target with the chunk"
    );
    let reports = state(dir.path())
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    let skipped: Vec<_> = reports
        .iter()
        .filter(|row| row.object.as_deref() == Some("email") && row.category.as_ref() == "skipped")
        .collect();
    assert_eq!(skipped.len(), 2);
    assert!(skipped.iter().all(|row| row.object_id == Some(6)));
    assert!(
        !target.snapshot()[&1].contains_key(&(Collection::Email, 6)),
        "object with a missing blob was copied"
    );

    source.put(1, email(40, 0, 41, &[]));
    let summary = run_with(&source, &target, dir.path(), copy, Shutdown::default())
        .await
        .expect("run");
    assert_eq!(summary.stats.blobs_copied, 0);
    assert_eq!(target.world.lock().expect("lock").blob_puts, 7);
}

#[tokio::test]
async fn final_run_finalizes_and_blocks_later_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    source.world.lock().expect("lock").queue = (0..9).collect();
    run(&source, &target, dir.path()).await;

    source.set_pointers(
        1,
        AccountPointers {
            active_script: Pointer::Set(Some(8)),
            ..Default::default()
        },
    );
    let summary = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Final),
        Shutdown::default(),
    )
    .await
    .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.global_records, 9);
    let verified = summary.verify.as_ref().expect("verify after final");
    assert_eq!(verified.status, RunStatus::Ok);
    assert!(summary.succeeded());
    {
        let world = target.world.lock().expect("lock");
        assert!(world.store_finalized);
        assert!(
            world
                .accounts
                .values()
                .all(|account| account.finalized == 1)
        );
        assert_eq!(world.global, 9);
        assert_eq!(
            world.accounts[&1].pointers.active_script,
            Pointer::Set(Some(8))
        );
    }
    assert!(
        state(dir.path())
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );

    let summary = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Incremental),
        Shutdown::default(),
    )
    .await
    .expect("summary");
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(matches!(summary.error, Some(RunError::Preflight(_))));

    let mut forced = options(RunKind::Incremental);
    forced.after_final = AfterFinal::Force;
    let summary = run_with(&source, &target, dir.path(), forced, Shutdown::default())
        .await
        .expect("forced run");
    assert_eq!(summary.status, RunStatus::Ok);
}

#[tokio::test]
async fn final_run_refuses_to_finalize_with_failed_accounts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    source.world.lock().expect("lock").queue = (0..9).collect();
    target.inject(FaultOp::Upsert, Some(1), Fault::Account);
    let summary = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Final),
        Shutdown::default(),
    )
    .await
    .expect("final run");
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(summary.verify.is_none());
    assert!(!target.world.lock().expect("lock").store_finalized);
    assert_eq!(target.world.lock().expect("lock").global, 0);
    assert!(
        state(dir.path())
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_none()
    );
}

#[tokio::test]
async fn target_identity_is_checked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    run(&source, &target, dir.path()).await;

    let other = FakeTarget::new();
    let summary = run_with(
        &source,
        &other,
        dir.path(),
        options(RunKind::Incremental),
        Shutdown::default(),
    )
    .await
    .expect("summary");
    assert!(matches!(summary.error, Some(RunError::Preflight(_))));

    target.world.lock().expect("lock").registry.insert(
        RegistryKey::new("Account", 1),
        serde_json::json!({"name": "other"}),
    );
    let mut found_mismatch = false;
    for _ in 0..8 {
        let summary = run_with(
            &source,
            &target,
            dir.path(),
            options(RunKind::Incremental),
            Shutdown::default(),
        )
        .await
        .expect("summary");
        if matches!(summary.error, Some(RunError::Preflight(_))) {
            found_mismatch = true;
            break;
        }
    }
    assert!(found_mismatch);

    let fresh_dir = tempfile::tempdir().expect("tempdir");
    let summary = run_with(
        &source,
        &target,
        fresh_dir.path(),
        options(RunKind::Incremental),
        Shutdown::default(),
    )
    .await
    .expect("summary");
    assert!(matches!(summary.error, Some(RunError::Preflight(_))));

    let mut identity = options(RunKind::Incremental);
    identity.identity = StoreIdentity {
        source_def_hash: Some("a".into()),
        target_def_hash: None,
        source_store: None,
    };
    let edition_dir = tempfile::tempdir().expect("tempdir");
    let fresh_target = FakeTarget::new();
    run_with(
        &source,
        &fresh_target,
        edition_dir.path(),
        identity.clone(),
        Shutdown::default(),
    )
    .await
    .expect("run");
    identity.identity.source_def_hash = Some("b".into());
    let summary = run_with(
        &source,
        &fresh_target,
        edition_dir.path(),
        identity,
        Shutdown::default(),
    )
    .await
    .expect("summary");
    assert!(matches!(summary.error, Some(RunError::Preflight(_))));

    let mut community = options(RunKind::Incremental);
    community.edition = Edition::Community;
    let summary = run_with(
        &source,
        &fresh_target,
        edition_dir.path(),
        community,
        Shutdown::default(),
    )
    .await
    .expect("summary");
    assert!(matches!(summary.error, Some(RunError::Preflight(_))));
}

#[tokio::test]
async fn excluded_categories_are_not_copied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    let mut no_identities = options(RunKind::Incremental);
    no_identities.categories = CategorySet::defaults();
    no_identities.categories.remove(Category::Identities);
    run_with(
        &source,
        &target,
        dir.path(),
        no_identities,
        Shutdown::default(),
    )
    .await
    .expect("run");
    let records = &target.snapshot()[&1];
    assert!(
        !records
            .keys()
            .any(|(collection, _)| *collection == Collection::Identity)
    );
    assert!(
        records
            .keys()
            .any(|(collection, _)| *collection == Collection::Email)
    );
}

#[tokio::test]
async fn verify_reports_missing_documents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    run(&source, &target, dir.path()).await;
    target
        .world
        .lock()
        .expect("lock")
        .accounts
        .get_mut(&2)
        .expect("account")
        .typed
        .remove(&(Collection::Email, 4));

    let verify_options = VerifyOptions {
        scope: VerifyScope::Full,
        min_sample: MIN_SAMPLE_ACCOUNTS,
        categories: CategorySet::defaults(),
        globals: GlobalCheck::Final,
        tuning: options(RunKind::Incremental).tuning,
        retry: RetryPolicy::default(),
    };
    let state = Arc::new(state(dir.path()));
    let summary = verify(
        source.clone(),
        FakeReader::new(&target, &source),
        state.clone(),
        Arc::new(FakeConverter),
        verify_options,
        Shutdown::default(),
    )
    .await
    .expect("verify");
    assert_eq!(summary.accounts_checked, 2);
    assert_eq!(summary.mismatches, 1);
    assert_eq!(summary.status, RunStatus::Failed);
    let rows = state
        .reports(ReportFilter {
            run_id: Some(summary.run_id),
            severity: Some(Severity::Verify),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].account_id, Some(2));
    assert_eq!(rows[0].object_id, Some(4));
}

fn verify_options(globals: GlobalCheck, categories: CategorySet) -> VerifyOptions {
    VerifyOptions {
        scope: VerifyScope::Full,
        min_sample: MIN_SAMPLE_ACCOUNTS,
        categories,
        globals,
        tuning: options(RunKind::Incremental).tuning,
        retry: RetryPolicy::default(),
    }
}

// Telemetry follows every run, the queue only the final one with its blobs; verify compares both.
#[tokio::test]
async fn global_categories_are_copied_and_verified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    for byte in 0..=60u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    source
        .world
        .lock()
        .expect("lock")
        .blobs
        .remove(&BlobHash([60; 32]));
    {
        let mut world = source.world.lock().expect("lock");
        world.spans = (1..=9)
            .map(|id| (id, serde_json::json!({"events": [id]})))
            .collect();
        world.queued = [(5, queued_message(5, 50)), (6, queued_message(6, 60))].into();
    }
    let mut incremental = options(RunKind::Incremental);
    incremental.blob_mode = BlobMode::Copy;
    incremental.categories.insert(Category::Telemetry);
    incremental.categories.insert(Category::Queue);
    let categories = incremental.categories;
    run_with(
        &source,
        &target,
        dir.path(),
        incremental.clone(),
        Shutdown::default(),
    )
    .await
    .expect("run");
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.spans.len(), 9);
        assert!(world.queued.is_empty());
    }

    let mut last = incremental;
    last.kind = RunKind::Final;
    let summary = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("final run");
    assert_eq!(summary.status, RunStatus::Failed);
    let verified = summary.verify.as_ref().expect("verify after final");
    assert_eq!(verified.status, RunStatus::Failed);
    assert_eq!(verified.mismatches, 1);
    assert_eq!(verified.unexplained, 1);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.queued.keys().copied().collect::<Vec<_>>(), [5]);
        assert!(world.blobs.contains(&BlobHash([50; 32])));
    }
    let skipped = state(dir.path())
        .reports(ReportFilter {
            severity: Some(Severity::Error),
            ..Default::default()
        })
        .await
        .expect("reports");
    assert!(
        skipped
            .iter()
            .any(|row| row.object.as_deref() == Some("queuedMessage") && row.object_id == Some(6))
    );

    {
        let mut world = target.world.lock().expect("lock");
        world.spans.insert(2, serde_json::json!({"events": []}));
        world.spans.remove(&3);
        world.queued.insert(7, queued_message(7, 50));
    }
    let state = Arc::new(state(dir.path()));
    let check = |globals| {
        verify(
            source.clone(),
            FakeReader::new(&target, &source),
            state.clone(),
            Arc::new(FakeConverter),
            verify_options(globals, categories),
            Shutdown::default(),
        )
    };
    let shared = check(GlobalCheck::Shared).await.expect("verify");
    assert_eq!((shared.mismatches, shared.unexplained), (1, 1));
    let full = check(GlobalCheck::Final).await.expect("verify");
    assert_eq!((full.mismatches, full.unexplained), (4, 4));
}

// Tasks are converted with the registry graph; tasks v1 rebuilds or the target recreates are counted, not copied.
#[tokio::test]
async fn tasks_are_converted_with_the_registry_graph() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = (0..6).collect();
        world.task_types = vec![
            "IndexDocument",
            "CalendarAlarmEmail",
            "DmarcReport",
            "Maintenance",
            "DestroyAccount",
            "IndexTrace",
        ];
    }
    run(&source, &target, dir.path()).await;
    let registry_writes = target.world.lock().expect("lock").registry.len();
    let summary = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Final),
        Shutdown::default(),
    )
    .await
    .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.global_records, 2);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.tasks.keys().copied().collect::<Vec<_>>(), [3, 4]);
        assert!(world.tasks.values().all(|task| task["v1"] == true));
        assert_eq!(world.tasks[&4]["@type"], "DestroyAccount");
        assert_eq!(world.registry.len(), registry_writes);
    }
    let info = state(dir.path())
        .reports(ReportFilter {
            severity: Some(Severity::Info),
            ..Default::default()
        })
        .await
        .expect("reports");
    let messages: Vec<&str> = info.iter().map(|row| &*row.message).collect();
    assert!(
        messages
            .contains(&"2 search indexing tasks were not copied; v1 indexes from its own queue")
    );
    assert!(
        messages
            .iter()
            .any(|message| message.starts_with("1 calendar alarm"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.starts_with("1 internal report"))
    );
}

// Tasks take their deferred full form; tasks the conversion drops are reported, and report tasks name the excluded category.
#[tokio::test]
async fn deferred_and_dropped_tasks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = (0..3).collect();
        world.task_types = vec!["Linked", "Obsolete", "DmarcReport"];
    }
    let mut final_run = options(RunKind::Final);
    final_run.categories.remove(Category::Queue);
    let summary = run_with(&source, &target, dir.path(), final_run, Shutdown::default())
        .await
        .expect("final run");
    assert_eq!(summary.stats.global_records, 1);
    {
        let world = target.world.lock().expect("lock");
        assert_eq!(world.tasks.keys().copied().collect::<Vec<_>>(), [0]);
        assert_eq!(world.tasks[&0]["link"], true);
    }
    let rows = state(dir.path())
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(rows.iter().any(|row| row.severity == Severity::Warning
        && row.object.as_deref() == Some("Task")
        && row.object_id == Some(1)));
    assert!(rows.iter().any(|row| {
        row.message
            .ends_with("the queue category, which holds the internal reports, is excluded")
    }));
}

// A queued message lost with an Error row keeps every later final run from finishing until it is accepted.
#[tokio::test]
async fn lost_queued_message_blocks_later_final_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    for byte in 0..=50u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    source.world.lock().expect("lock").queued =
        [(5, queued_message(5, 50)), (6, queued_message(6, 60))].into();
    let mut last = options(RunKind::Final);
    last.blob_mode = BlobMode::Copy;
    last.categories.insert(Category::Queue);
    last.tuning.batch_ops = 1;
    let first = run_with(
        &source,
        &target,
        dir.path(),
        last.clone(),
        Shutdown::default(),
    )
    .await
    .expect("first final run");
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(first.stats.errors, 1);
    let second = run_with(
        &source,
        &target,
        dir.path(),
        last.clone(),
        Shutdown::default(),
    )
    .await
    .expect("second final run");
    assert_eq!(second.status, RunStatus::Failed);
    assert!(
        second
            .verify
            .as_ref()
            .is_none_or(|verify| verify.status == RunStatus::Failed)
    );
    assert_eq!(
        state(dir.path())
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta"),
        None
    );
    last.errors = ErrorPolicy::Allow;
    let accepted = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("accepted final run");
    assert_eq!(accepted.status, RunStatus::Ok);
    assert!(
        state(dir.path())
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );
}

// A final run that crashed during the queue pass is resumed from its cursor, without deleting what it already wrote.
#[tokio::test]
async fn crashed_final_run_resumes_its_queue_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    for byte in 1..=4u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    source.world.lock().expect("lock").queued = (1..=4u8)
        .map(|id| (u64::from(id), queued_message(u64::from(id), id)))
        .collect();
    run(&source, &target, dir.path()).await;
    let mut last = options(RunKind::Final);
    last.blob_mode = BlobMode::Copy;
    last.categories.insert(Category::Queue);
    last.tuning.batch_ops = 1;
    let base = target.world.lock().expect("lock").upserts;
    *target.crash_after_commits.lock().expect("lock") = Some(base + 2);
    let orchestrator = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target, &source),
        Arc::new(state(dir.path())),
        Arc::new(FakeConverter),
        last.clone(),
        Shutdown::default(),
    );
    let crashed = tokio::select! {
        result = orchestrator.run() => {
            result.expect("run");
            false
        }
        _ = target.crashed.notified() => true,
    };
    assert!(crashed);
    *target.crash_after_commits.lock().expect("lock") = None;
    assert_eq!(target.world.lock().expect("lock").queued.len(), 2);

    let resumed = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("resumed final run");
    assert_eq!(resumed.status, RunStatus::Ok);
    assert_eq!(resumed.interrupted_runs.len(), 1);
    assert_eq!(resumed.stats.global_records, 3);
    assert_eq!(resumed.stats.global_deleted, 0);
    let world = target.world.lock().expect("lock");
    assert_eq!(world.queued.len(), 4);
    assert!(world.deleted_globals.is_empty());
}

// The resume cursor a source returns on its last telemetry page is stored and handed back on the next run.
#[tokio::test]
async fn telemetry_resume_cursor_is_stored_and_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    let resume = vec![9u8, 9];
    {
        let mut world = source.world.lock().expect("lock");
        world.spans = [
            (1, serde_json::json!({"n": 1})),
            (2, serde_json::json!({"n": 2})),
        ]
        .into();
        world.span_resume = Some(resume.clone());
    }
    let mut incremental = options(RunKind::Incremental);
    incremental.categories.insert(Category::Telemetry);
    let first = run_with(
        &source,
        &target,
        dir.path(),
        incremental.clone(),
        Shutdown::default(),
    )
    .await
    .expect("first run");
    assert_eq!(first.status, RunStatus::Ok);
    assert_eq!(
        state(dir.path()).global_cursor("telemetry".into()).await,
        Ok(Some(resume.clone()))
    );
    source.world.lock().expect("lock").span_cursors.clear();
    run_with(
        &source,
        &target,
        dir.path(),
        incremental,
        Shutdown::default(),
    )
    .await
    .expect("second run");
    assert_eq!(
        source.world.lock().expect("lock").span_cursors.first(),
        Some(&Some(resume))
    );
}

// Tasks written by a final run that did not finalize and gone from the source by the next final run are deleted from the target.
#[tokio::test]
async fn later_final_runs_delete_vanished_tasks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    for byte in 0..=50u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = vec![10, 20, 30];
        world.queued = [(6, queued_message(6, 60))].into();
    }
    let mut last = options(RunKind::Final);
    last.blob_mode = BlobMode::Copy;
    last.categories.insert(Category::Queue);
    let first = run_with(
        &source,
        &target,
        dir.path(),
        last.clone(),
        Shutdown::default(),
    )
    .await
    .expect("first final run");
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(
        target
            .world
            .lock()
            .expect("lock")
            .tasks
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );

    {
        let mut world = source.world.lock().expect("lock");
        world.queue.truncate(2);
        world.queued.clear();
    }
    let later = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("later final run");
    assert_eq!(later.status, RunStatus::Ok);
    assert_eq!(later.stats.global_deleted, 1);
    let world = target.world.lock().expect("lock");
    assert_eq!(world.tasks.keys().copied().collect::<Vec<_>>(), [0, 1]);
    assert_eq!(world.deleted_globals, [model::GlobalKey::Task(2)]);
}

// A singleton task is stored under its singleton key; when v0.16 completes it before the next final run, the sweep deletes it by that key and the verify is clean.
#[tokio::test]
async fn completed_singleton_tasks_are_deleted_by_their_singleton_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    for byte in 0..=50u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    let singleton = serde_json::json!({
        "@type": "DkimManagement",
        "domainId": "h",
        "status": {"@type": "Pending", "createdAt": "2026-01-01T00:00:00Z", "due": "2026-01-02T00:00:00Z"}
    });
    let singleton_id = source_v1::singleton_task_id(&singleton).expect("singleton");
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = vec![10];
        world.task_json = Some(singleton);
        world.queued = [(6, queued_message(6, 60))].into();
    }
    let mut last = options(RunKind::Final);
    last.blob_mode = BlobMode::Copy;
    last.categories.insert(Category::Queue);
    let first = run_with(
        &source,
        &target,
        dir.path(),
        last.clone(),
        Shutdown::default(),
    )
    .await
    .expect("first final run");
    assert_eq!(first.status, RunStatus::Failed);
    assert_eq!(
        target
            .world
            .lock()
            .expect("lock")
            .tasks
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [singleton_id]
    );
    {
        let mut world = source.world.lock().expect("lock");
        world.queue.clear();
        world.queued.clear();
    }
    let later = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("later final run");
    assert_eq!(later.status, RunStatus::Ok);
    assert_eq!(
        later
            .verify
            .map(|verify| (verify.status, verify.unexplained)),
        Some((RunStatus::Ok, 0))
    );
    assert!(target.world.lock().expect("lock").tasks.is_empty());
}

// A telemetry record the target rejected is not re-read by later runs, so its error blocks the final run until accepted.
#[tokio::test]
async fn rejected_telemetry_blocks_the_final_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.world.lock().expect("lock").spans = (1..=3)
        .map(|id| (id, serde_json::json!({"events": [id]})))
        .collect();
    target.world.lock().expect("lock").telemetry_issues = vec![Issue::new(
        Severity::Error,
        IssueKind::Failed,
        Subject::Registry(RegistryKey::new("span", 2)),
        "rejected by the target",
    )];
    let mut incremental = options(RunKind::Incremental);
    incremental.categories.insert(Category::Telemetry);
    let first = run_with(
        &source,
        &target,
        dir.path(),
        incremental.clone(),
        Shutdown::default(),
    )
    .await
    .expect("incremental run");
    assert_eq!(first.stats.errors, 1);

    let mut last = incremental;
    last.kind = RunKind::Final;
    let refused = run_with(
        &source,
        &target,
        dir.path(),
        last.clone(),
        Shutdown::default(),
    )
    .await
    .expect("final run");
    assert_eq!(refused.status, RunStatus::Failed);
    assert_eq!(
        state(dir.path())
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta"),
        None
    );
    last.errors = ErrorPolicy::Allow;
    let accepted = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("accepted final run");
    assert_eq!(accepted.status, RunStatus::Ok);
    assert!(
        state(dir.path())
            .meta(MetaKey::FinalDone)
            .await
            .expect("meta")
            .is_some()
    );
}

// The tasks pass converts bounded chunks while it streams the source, and drops thread merge tasks with one summary row.
#[tokio::test]
async fn tasks_are_streamed_in_bounded_chunks() {
    const MERGES: usize = 5_000;
    const COPIED: usize = 25_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = (0..(MERGES + COPIED) as u64).collect();
        world.task_types = vec!["MergeThreads"; MERGES];
        world.task_account = Some("b");
    }
    let mut last = options(RunKind::Final);
    last.tuning.batch_ops = 1000;
    let summary = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(target.world.lock().expect("lock").tasks.len(), COPIED);
    let max = fake::MAX_TASKS_PER_CONVERSION.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        max > 0 && max <= 10_000 + 1_000,
        "{max} tasks in one conversion"
    );
    let rows = state(dir.path())
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    let merges: Vec<(Severity, Option<u32>, &str)> = rows
        .iter()
        .filter(|row| row.message.contains("thread merge tasks"))
        .map(|row| (row.severity, row.account_id, row.message.as_ref()))
        .collect();
    assert_eq!(
        merges,
        [(
            Severity::Warning,
            Some(1),
            format!("{MERGES} thread merge tasks were not copied: v1 cannot use the v0.16 thread and message hashes they carry, so the conversations v0.16 was about to merge stay split in v1").as_str()
        )]
    );
}

// Each task chunk is converted with the registry objects its tasks reference, transitively, not with the whole registry.
#[tokio::test]
async fn task_chunks_convert_only_the_objects_they_reference() {
    const TASKS: u64 = 25_000;
    const UNREFERENCED: u64 = 2_000;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    source.put_registry(
        "Account",
        1,
        serde_json::json!({"name": "a", "domainId": "c"}),
    );
    source.put_registry("Domain", 2, serde_json::json!({"name": "a.org"}));
    for id in 10..10 + UNREFERENCED {
        source.put_registry(
            "Domain",
            id,
            serde_json::json!({"name": format!("d{id}.org")}),
        );
    }
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = (0..TASKS).collect();
        world.task_account = Some("b");
    }
    let mut last = options(RunKind::Final);
    last.tuning.batch_ops = 1000;
    let summary = run_with(&source, &target, dir.path(), last, Shutdown::default())
        .await
        .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        target.world.lock().expect("lock").tasks.len(),
        TASKS as usize
    );
    assert_eq!(
        fake::MAX_REGISTRY_WITH_TASKS.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

fn sized_emails(source: &FakeSource, account_id: u32, emails: std::ops::Range<u32>, size: u32) {
    source.put(account_id, mailbox(0, "Inbox"));
    for id in emails {
        let Rec::Email(mut record) = email(id, 0, id + 1, &[]) else {
            unreachable!("email record");
        };
        record.size = size;
        source.put(account_id, Rec::Email(record));
    }
    source.set_pointers(account_id, AccountPointers::default());
}

fn large_account(source: &FakeSource, account_id: u32, emails: std::ops::Range<u32>) {
    source.put(account_id, mailbox(0, "Inbox"));
    for id in emails {
        source.put(account_id, email(id, 0, id + 1, &[]));
    }
    source.set_pointers(account_id, AccountPointers::default());
}

fn delay_email_chunks(
    target: &FakeTarget,
    account_id: u32,
    emails: std::ops::Range<u32>,
    delay: Duration,
) {
    let mut delays = target.upsert_delays.lock().expect("lock");
    delays.extend(emails.step_by(4).map(|first| (account_id, first, delay)));
}

// A slow first chunk completes after later ones; a crash in between must not move the scan cursor past it, and the resume loses or duplicates nothing.
#[tokio::test]
async fn out_of_order_slot_completion_survives_a_crash() {
    for crash_after in 2..=5u64 {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        large_account(&source, 1, 10..50);
        target
            .upsert_delays
            .lock()
            .expect("lock")
            .push((1, 10, Duration::from_millis(60)));
        *target.crash_after_commits.lock().expect("lock") = Some(crash_after);
        assert!(run_until_crash(&source, &target, dir.path()).await);
        let full = state(dir.path())
            .cursors(1)
            .await
            .expect("cursors")
            .into_iter()
            .find(|cursor| {
                cursor.collection == Collection::Email.as_u8()
                    && cursor.mode == state::CursorMode::Full
            });
        assert!(
            full.is_none_or(|cursor| cursor.last_id < 13),
            "crash after {crash_after}: {full:?}"
        );
        *target.crash_after_commits.lock().expect("lock") = None;
        target.upsert_delays.lock().expect("lock").clear();
        run(&source, &target, dir.path()).await;
        assert_eq!(
            source.snapshot(),
            target.snapshot(),
            "crash after {crash_after}"
        );
        assert_eq!(target.duplicates(), 0, "crash after {crash_after}");
    }
}

// One large account spreads over idle write slots, and the pass never has more batches in flight than --concurrency.
#[tokio::test]
async fn write_slots_bound_the_account_split() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    large_account(&source, 1, 10..50);
    delay_email_chunks(&target, 1, 10..50, Duration::from_millis(5));
    run(&source, &target, dir.path()).await;
    let peak = target
        .peak_in_flight
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!((2..=3).contains(&peak), "peak {peak}");
    assert_eq!(source.snapshot(), target.snapshot());

    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for account_id in 1..=4 {
        large_account(&source, account_id, 10..50);
        delay_email_chunks(&target, account_id, 10..50, Duration::from_millis(2));
    }
    run(&source, &target, dir.path()).await;
    let peak = target
        .peak_in_flight
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(peak <= 3, "peak {peak}");
    assert_eq!(source.snapshot(), target.snapshot());
}

// --account-split 1 writes one batch at a time per account, as before the split existed.
#[tokio::test]
async fn account_split_one_keeps_a_single_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    large_account(&source, 1, 10..50);
    delay_email_chunks(&target, 1, 10..50, Duration::from_millis(5));
    let mut single = options(RunKind::Incremental);
    single.tuning.account_split = 1;
    run_with(&source, &target, dir.path(), single, Shutdown::default())
        .await
        .expect("run");
    assert_eq!(
        target
            .peak_in_flight
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let emails: Vec<u32> = target
        .upsert_log
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, first)| *first >= 10)
        .map(|(_, first)| *first)
        .collect();
    assert!(emails.is_sorted(), "{emails:?}");
    assert_eq!(source.snapshot(), target.snapshot());
}

// Accounts with the most pending changes start first.
#[tokio::test]
async fn largest_accounts_are_scheduled_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    large_account(&source, 1, 10..12);
    large_account(&source, 2, 10..40);
    large_account(&source, 3, 10..20);
    let mut serial = options(RunKind::Incremental);
    serial.tuning.concurrency = 1;
    run_with(&source, &target, dir.path(), serial, Shutdown::default())
        .await
        .expect("run");
    let mut order = Vec::new();
    for (account, _) in target.upsert_log.lock().expect("lock").iter() {
        if !order.contains(account) {
            order.push(*account);
        }
    }
    assert_eq!(order, [2, 3, 1]);
}

// A delta applies its deletes, then inserts and updates in parallel slots; the result equals the source.
#[tokio::test]
async fn delta_deletes_then_parallel_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    large_account(&source, 1, 10..50);
    run(&source, &target, dir.path()).await;
    for id in [12, 25, 33] {
        source.delete(1, Collection::Email, id);
    }
    for id in 60..80 {
        source.put(1, email(id, 0, id + 1, &[]));
    }
    for id in 40..50 {
        source.put(1, email(id, 0, id + 1, &["$seen"]));
    }
    delay_email_chunks(&target, 1, 40..80, Duration::from_millis(3));
    target.write_order.lock().expect("lock").clear();
    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.stats.accounts_delta, 1);
    assert_eq!(source.snapshot(), target.snapshot());
    let order: Vec<fake::WriteKind> = target
        .write_order
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, collection)| *collection == Collection::Email)
        .map(|(kind, _)| *kind)
        .collect();
    let first_upsert = order
        .iter()
        .position(|kind| *kind == fake::WriteKind::Upsert)
        .expect("upserts");
    assert!(
        order.contains(&fake::WriteKind::Delete)
            && order[first_upsert..]
                .iter()
                .all(|kind| *kind == fake::WriteKind::Upsert),
        "{order:?}"
    );
    assert!(
        target
            .peak_in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 2
    );
}

// A chunk redone after a crash never lowers pending, so a third run still filters every id the first run may have written.
#[tokio::test]
async fn pending_never_shrinks_across_resumed_runs() {
    for crash_after in 2..=6u64 {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        large_account(&source, 1, 10..50);
        target
            .upsert_delays
            .lock()
            .expect("lock")
            .push((1, 10, Duration::from_millis(80)));
        *target.crash_after_commits.lock().expect("lock") = Some(crash_after);
        assert!(run_until_crash(&source, &target, dir.path()).await);
        *target.crash_after_commits.lock().expect("lock") = None;
        target.upsert_delays.lock().expect("lock").clear();
        target.inject(FaultOp::Upsert, Some(1), Fault::Account);
        let _ = run(&source, &target, dir.path()).await;
        run(&source, &target, dir.path()).await;
        assert_eq!(source.snapshot(), target.snapshot(), "crash {crash_after}");
        assert_eq!(target.duplicates(), 0, "crash after {crash_after}");
    }
}

struct StressRng(u64);

impl StressRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

async fn run_once(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
) -> String {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
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
        result = orchestrator.run() => format!("{:?}", result.map(|summary| summary.status)),
        _ = target.crashed.notified() => "crashed".into(),
    }
}

// Random tunings, delays, faults, crashes and source changes over several runs: every email is written once and the target converges (STRESS_SEEDS overrides the seed count).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_slots_survive_random_faults() {
    let seeds: u64 = std::env::var("STRESS_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let mut failures = Vec::new();
    let only: Option<u64> = std::env::var("STRESS_ONLY")
        .ok()
        .and_then(|v| v.parse().ok());
    for seed in 1..=seeds {
        if only.is_some_and(|only| only != seed) {
            continue;
        }
        let mut rng = StressRng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        let accounts = 1 + rng.below(3) as u32;
        let mut next_id = Vec::new();
        for account in 1..=accounts {
            let n = 5 + rng.below(80) as u32;
            large_account(&source, account, 10..10 + n);
            next_id.push(10 + n);
        }
        let mut opts = options(RunKind::Incremental);
        opts.tuning.concurrency = 1 + rng.below(5) as usize;
        opts.tuning.account_split = 1 + rng.below(6) as usize;
        opts.tuning.batch_ops = 1 + rng.below(6) as usize;
        let mut log = Vec::new();
        for _round in 0..(1 + rng.below(5)) {
            {
                let mut delays = target.upsert_delays.lock().expect("lock");
                delays.clear();
                for account in 1..=accounts {
                    for id in 10..next_id[(account - 1) as usize] {
                        if rng.below(3) == 0 {
                            delays.push((account, id, Duration::from_millis(rng.below(6))));
                        }
                    }
                }
            }
            target.faults.lock().expect("lock").clear();
            for _ in 0..rng.below(4) {
                let fault = match rng.below(6) {
                    0 => Fault::Transient,
                    1 => Fault::TransientAfterCommit,
                    2 => Fault::Account,
                    3 => Fault::TransientAfterCommit,
                    4 => Fault::Panic,
                    _ => Fault::Transient,
                };
                let account = 1 + rng.below(u64::from(accounts)) as u32;
                target.inject(FaultOp::Upsert, Some(account), fault);
            }
            let commits = target.world.lock().expect("lock").upserts;
            *target.crash_after_commits.lock().expect("lock") =
                (rng.below(2) == 0).then(|| commits + 1 + rng.below(25));
            let outcome = run_once(&source, &target, dir.path(), opts.clone()).await;
            log.push(outcome);
            for account in 1..=accounts {
                let slot = &mut next_id[(account - 1) as usize];
                for _ in 0..rng.below(6) {
                    source.put(account, email(*slot, 0, *slot + 1, &[]));
                    *slot += 1;
                }
                for _ in 0..rng.below(3) {
                    let id = 10 + rng.below(u64::from(*slot - 10)) as u32;
                    source.delete(account, Collection::Email, id);
                }
                for _ in 0..rng.below(3) {
                    let id = 10 + rng.below(u64::from(*slot - 10)) as u32;
                    source.put(account, email(id, 0, id + 1, &["$seen"]));
                }
            }
        }
        target.faults.lock().expect("lock").clear();
        target.upsert_delays.lock().expect("lock").clear();
        *target.crash_after_commits.lock().expect("lock") = None;
        for _ in 0..2 {
            log.push(run_once(&source, &target, dir.path(), opts.clone()).await);
        }
        let duplicates = target.duplicates();
        let equal = source.snapshot() == target.snapshot();
        if !equal && only.is_some() {
            let a = source.snapshot();
            let b = target.snapshot();
            for (account, records) in &a {
                let other = b.get(account).cloned().unwrap_or_default();
                for (key, value) in records {
                    if other.get(key) != Some(value) {
                        eprintln!(
                            "account {account} {key:?}: source {value} target {:?}",
                            other.get(key)
                        );
                    }
                }
                for (key, value) in &other {
                    if !records.contains_key(key) {
                        eprintln!("account {account} {key:?}: extra in target {value}");
                    }
                }
            }
            let reports = state(dir.path())
                .reports(ReportFilter::default())
                .await
                .expect("reports");
            for row in reports.iter().filter(|row| row.severity == Severity::Error) {
                eprintln!("report: {row:?}");
            }
        }
        if duplicates != 0 || !equal {
            failures.push(format!(
                "seed {seed}: duplicates {duplicates}, equal {equal}, tuning c{} s{} b{}, runs {log:?}",
                opts.tuning.concurrency, opts.tuning.account_split, opts.tuning.batch_ops
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// A shutdown drains the chunks already being written instead of aborting them.
#[tokio::test]
async fn shutdown_drains_in_flight_chunks() {
    for split in [1usize, 3] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        large_account(&source, 1, 10..50);
        target
            .upsert_delays
            .lock()
            .expect("lock")
            .push((1, 14, Duration::from_millis(150)));
        let shutdown = Shutdown::default();
        let commits = target.world.lock().expect("lock").upserts;
        *target.shutdown_after_commits.lock().expect("lock") =
            Some((commits + 3, shutdown.clone()));
        let mut opts = options(RunKind::Incremental);
        opts.tuning.account_split = split;
        let _ = run_with(&source, &target, dir.path(), opts, shutdown).await;
        assert_eq!(
            target.in_flight.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "split {split}: a write was aborted mid-flight"
        );
        let has14 = target
            .snapshot()
            .get(&1)
            .is_some_and(|records| records.contains_key(&(Collection::Email, 14)));
        assert!(
            has14,
            "split {split}: the in-flight chunk was not committed"
        );
    }
}

// A shutdown during a split delta drains the delta chunks already being written instead of aborting them.
#[tokio::test]
async fn shutdown_drains_in_flight_delta_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    large_account(&source, 1, 10..50);
    run(&source, &target, dir.path()).await;
    for id in 10..50 {
        source.put(1, email(id, 0, id + 1, &["$seen"]));
    }
    target
        .upsert_delays
        .lock()
        .expect("lock")
        .push((1, 14, Duration::from_millis(150)));
    let shutdown = Shutdown::default();
    let commits = target.world.lock().expect("lock").upserts;
    *target.shutdown_after_commits.lock().expect("lock") = Some((commits + 2, shutdown.clone()));
    let _ = run_with(
        &source,
        &target,
        dir.path(),
        options(RunKind::Incremental),
        shutdown,
    )
    .await;
    assert_eq!(
        target.in_flight.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a delta write was aborted mid-flight"
    );
    let key = (Collection::Email, 14);
    assert_eq!(
        target.snapshot()[&1].get(&key),
        source.snapshot()[&1].get(&key),
        "the in-flight delta chunk was not committed"
    );
}

// Copied bodies kept for a chunk write count against the blob memory budget: parallel chunk writes never hold more than it, and the cache is still used.
#[tokio::test]
async fn kept_blob_bodies_stay_within_the_memory_budget() {
    const BODY: usize = 6 << 20;
    const BUDGET: u64 = 16 << 20;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    sized_emails(&source, 1, 0..7, BODY as u32);
    for byte in 0..7u8 {
        source.put_blob(
            BlobHash([byte; 32]),
            Box::leak(vec![byte; BODY].into_boxed_slice()),
        );
    }
    target
        .upsert_delays
        .lock()
        .expect("lock")
        .extend((0..7).map(|id| (1, id, Duration::from_millis(100))));
    let mut opts = options(RunKind::Incremental);
    opts.blob_mode = BlobMode::Copy;
    opts.tuning.batch_ops = 1;
    opts.tuning.blob_concurrency = 1;
    let summary = run_with(&source, &target, dir.path(), opts, Shutdown::default())
        .await
        .expect("run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert!(
        target
            .peak_in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 2
    );
    let peak = target.peak_cached.load(std::sync::atomic::Ordering::SeqCst);
    assert!(peak <= BUDGET, "{peak} cached bytes in flight");
    assert!(peak >= BODY as u64, "the cache was never used");
}

// An account whose full copy stopped after every collection checkpointed catches up on the source changes made since when it resumes, in incremental and final runs.
#[tokio::test]
async fn resumed_full_copy_catches_up_before_it_is_done() {
    for kind in [RunKind::Incremental, RunKind::Final] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        seed(&source, 1);
        target.inject(FaultOp::Changelog, Some(1), Fault::Account);
        let summary = run(&source, &target, dir.path()).await;
        assert_eq!(summary.status, RunStatus::Failed, "{kind:?}");
        source.put(1, email(30, 0, 31, &["$seen"]));
        source.delete(1, Collection::Email, 2);
        source.put(1, mailbox(2, "Later"));
        let summary = run_with(
            &source,
            &target,
            dir.path(),
            options(kind),
            Shutdown::default(),
        )
        .await
        .expect("resumed run");
        assert_eq!(summary.status, RunStatus::Ok, "{kind:?}");
        assert_eq!(
            (summary.stats.accounts_full, summary.stats.accounts_delta),
            (1, 0),
            "{kind:?}: a resumed full copy is counted once"
        );
        if kind == RunKind::Final {
            assert_eq!(
                summary.verify.as_ref().map(|verify| verify.unexplained),
                Some(0),
                "{kind:?}"
            );
        }
        assert_synced(&source, &target);
        let account = state(dir.path())
            .account(1)
            .await
            .expect("account")
            .expect("state");
        assert_eq!(account.checkpoint, Some(source.counter(1)), "{kind:?}");
    }
}

// Copied bodies hold their blob memory permit until they are dropped or moved into the write cache, so bodies alive at once never exceed the budget.
#[tokio::test]
async fn copied_blob_bodies_never_exceed_the_memory_budget() {
    const BODY: usize = 6 << 20;
    const BUDGET: u64 = 16 << 20;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    sized_emails(&source, 1, 0..7, BODY as u32);
    for byte in 0..7u8 {
        source.put_blob(
            BlobHash([byte; 32]),
            Box::leak(vec![byte; BODY].into_boxed_slice()),
        );
    }
    source
        .live_blobs
        .tracking
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut opts = options(RunKind::Incremental);
    opts.blob_mode = BlobMode::Copy;
    opts.tuning.batch_ops = 7;
    opts.tuning.batch_bytes = 1 << 30;
    opts.tuning.blob_concurrency = 1;
    opts.tuning.account_split = 1;
    let summary = run_with(&source, &target, dir.path(), opts, Shutdown::default())
        .await
        .expect("run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.blobs_copied, 7);
    let peak = source
        .live_blobs
        .peak
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(peak <= BUDGET, "{peak} copied bytes alive at once");
}

fn blob_emails(source: &FakeSource, account_id: u32, emails: u32, size: u32, first_blob: u8) {
    source.put(account_id, mailbox(0, "Inbox"));
    for id in 0..emails {
        let Rec::Email(mut record) = email(id, 0, id + 1, &[]) else {
            unreachable!("email record");
        };
        record.size = size;
        record.blob_hash = BlobHash([first_blob.wrapping_add(id as u8); 32]);
        source.put(account_id, Rec::Email(record));
    }
    source.set_pointers(account_id, AccountPointers::default());
}

fn blob_pool() -> &'static [u8] {
    Box::leak(vec![7u8; 12 << 20].into_boxed_slice())
}

async fn run_within(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    options: RunOptions,
) -> RunSummary {
    tokio::time::timeout(
        Duration::from_secs(60),
        run_with(source, target, dir, options, Shutdown::default()),
    )
    .await
    .expect("the blob copy deadlocked")
    .expect("run")
}

fn deadlock_tuning() -> RunOptions {
    let mut opts = options(RunKind::Incremental);
    opts.blob_mode = BlobMode::Copy;
    opts.tuning.concurrency = 2;
    opts.tuning.account_split = 1;
    opts.tuning.batch_ops = 7;
    opts.tuning.batch_bytes = 1 << 30;
    opts.tuning.blob_concurrency = 1;
    opts
}

// Two accounts copying 6 MiB bodies through one blob slot and a 16 MiB budget never wait on each other forever (reviewer repro, shared and distinct blobs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blob_slot_and_memory_waits_never_deadlock() {
    const BODY: u32 = 6 << 20;
    let pool = blob_pool();
    for distinct in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        for account_id in 1..=2u32 {
            let first = if distinct { account_id as u8 * 8 } else { 0 };
            blob_emails(&source, account_id, 7, BODY, first);
            for id in 0..7u8 {
                source.put_blob(BlobHash([first + id; 32]), &pool[..BODY as usize]);
            }
        }
        let summary = run_within(&source, &target, dir.path(), deadlock_tuning()).await;
        assert_eq!(summary.status, RunStatus::Ok, "distinct {distinct}");
        assert_synced(&source, &target);
        assert_eq!(
            target.world.lock().expect("lock").blob_puts,
            if distinct { 14 } else { 7 }
        );
    }
}

// Random blob sizes, sharing and tunings: the blob copy always finishes, copies each blob once and never lets a chunk read a blob that is still being written (STRESS_SEEDS overrides the seed count).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blob_copies_survive_random_tunings() {
    let seeds: u64 = std::env::var("STRESS_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    let pool = blob_pool();
    for seed in 1..=seeds {
        let mut rng = StressRng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        let shared = rng.below(2) == 0;
        let accounts = 2 + rng.below(3) as u32;
        let mut hashes = std::collections::BTreeSet::new();
        let size = 1 + rng.below(6 << 20) as u32;
        for account_id in 1..=accounts {
            let emails = 2 + rng.below(7) as u32;
            let first = if shared { 0 } else { account_id as u8 * 16 };
            blob_emails(&source, account_id, emails, size, first);
            for id in 0..emails as u8 {
                let hash = BlobHash([first + id; 32]);
                if hashes.insert(hash) {
                    source.put_blob(hash, &pool[..size as usize]);
                }
            }
        }
        source
            .live_blobs
            .tracking
            .store(true, std::sync::atomic::Ordering::SeqCst);
        *target.put_blob_delay.lock().expect("lock") = Some(Duration::from_micros(rng.below(3000)));
        let mut opts = deadlock_tuning();
        opts.tuning.concurrency = 1 + rng.below(4) as usize;
        opts.tuning.account_split = 1 + rng.below(3) as usize;
        opts.tuning.batch_ops = 1 + rng.below(7) as usize;
        opts.tuning.blob_concurrency = 1 + rng.below(3) as usize;
        let budget = opts.tuning.blob_concurrency as u64 * (16 << 20);
        let summary = run_within(&source, &target, dir.path(), opts).await;
        assert_eq!(summary.status, RunStatus::Ok, "seed {seed}");
        assert_synced(&source, &target);
        let world = target.world.lock().expect("lock");
        assert_eq!(world.blob_puts, hashes.len() as u64, "seed {seed}");
        assert_eq!(world.peak_blob_writers, 1, "seed {seed}");
        assert_eq!(world.torn_blob_reads, 0, "seed {seed}");
        let peak = source
            .live_blobs
            .peak
            .load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            peak <= budget,
            "seed {seed}: {peak} copied bytes alive at once"
        );
    }
}

// Chunks and accounts sharing blobs copy each blob once, one writer at a time, and no chunk is written before its blob is complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_blobs_are_copied_once_by_one_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    for account_id in 1..=3 {
        sized_emails(&source, account_id, 0..14, 1000);
    }
    for byte in 0..7u8 {
        source.put_blob(BlobHash([byte; 32]), b"message");
    }
    *target.put_blob_delay.lock().expect("lock") = Some(Duration::from_millis(30));
    let mut opts = options(RunKind::Incremental);
    opts.blob_mode = BlobMode::Copy;
    opts.tuning.concurrency = 3;
    opts.tuning.account_split = 3;
    opts.tuning.batch_ops = 2;
    opts.tuning.blob_concurrency = 6;
    let summary = run_within(&source, &target, dir.path(), opts).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_synced(&source, &target);
    let world = target.world.lock().expect("lock");
    assert_eq!(world.blob_puts, 7, "a shared blob was copied twice");
    assert_eq!(world.peak_blob_writers, 1, "two copies of one blob at once");
    assert_eq!(
        world.torn_blob_reads, 0,
        "a chunk read a blob being written"
    );
    assert_eq!(summary.stats.blobs_copied, 7);
}

// A resumed full copy whose source counter went below its target (source restored from an older backup) wipes the account and copies it again, like a delta does.
#[tokio::test]
async fn resumed_full_copy_below_its_target_copies_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 1);
    target.inject(FaultOp::Changelog, Some(1), Fault::Account);
    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    {
        let conn = rusqlite::Connection::open(dir.path().join("state.sqlite")).expect("conn");
        conn.execute_batch(
            "UPDATE account SET full_target = full_target + 1000 WHERE account_id = 1;",
        )
        .expect("raise the full copy target");
    }
    let summary = run(&source, &target, dir.path()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(summary.stats.accounts_wiped, 1);
    assert_eq!(summary.stats.accounts_full, 1);
    assert_synced(&source, &target);
    let account = state(dir.path())
        .account(1)
        .await
        .expect("account")
        .expect("state");
    assert_eq!(account.checkpoint, Some(source.counter(1)));
    let reports = state(dir.path())
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    assert!(
        reports
            .iter()
            .any(|row| row.message.contains("below the target"))
    );
}

// An account that keeps copied bodies while it waits for another account's copy of a shared blob gives the memory back, so that copy can start (both accounts would wait forever otherwise).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_with_kept_bodies_lets_the_leader_copy() {
    const BODY: u32 = 9 << 20;
    let pool = blob_pool();
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    let shared = BlobHash([100; 32]);
    for account_id in 1..=2u32 {
        source.put(account_id, mailbox(0, "Inbox"));
        let own = BlobHash([100 + account_id as u8; 32]);
        for (id, hash) in [shared, own].into_iter().enumerate() {
            let Rec::Email(mut record) = email(id as u32, 0, id as u32 + 1, &[]) else {
                unreachable!("email record");
            };
            record.size = BODY;
            record.blob_hash = hash;
            source.put(account_id, Rec::Email(record));
            source.put_blob(hash, &pool[..BODY as usize]);
        }
        source.set_pointers(account_id, AccountPointers::default());
    }
    *target.blobs_exist_delay.lock().expect("lock") = Some((shared, Duration::from_millis(300)));
    let summary = run_within(&source, &target, dir.path(), deadlock_tuning()).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_synced(&source, &target);
    assert_eq!(target.world.lock().expect("lock").blob_puts, 3);
}

// A leader whose copy of a shared blob fails (account error) hands the hash to the account that was following it, which copies the blob itself and keeps its records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_leader_hands_the_blob_copy_to_its_follower() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    let shared = BlobHash([90; 32]);
    source.put_blob(shared, b"shared body");
    for account_id in 1..=2u32 {
        source.put(account_id, mailbox(0, "Inbox"));
        let Rec::Email(mut record) = email(0, 0, 1, &[]) else {
            unreachable!("email record");
        };
        record.blob_hash = shared;
        record.size = 11;
        source.put(account_id, Rec::Email(record));
        source.set_pointers(account_id, AccountPointers::default());
    }
    *target.blobs_exist_delay.lock().expect("lock") = Some((shared, Duration::from_millis(300)));
    target
        .upsert_delays
        .lock()
        .expect("lock")
        .push((2, 0, Duration::from_millis(100)));
    target
        .put_blob_faults
        .lock()
        .expect("lock")
        .push((shared, Fault::Account));
    let mut opts = options(RunKind::Incremental);
    opts.blob_mode = BlobMode::Copy;
    opts.tuning.concurrency = 2;
    opts.tuning.account_split = 1;
    opts.tuning.blob_concurrency = 2;
    let summary = run_within(&source, &target, dir.path(), opts.clone()).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.stats.accounts_failed, 1);
    let state = state(dir.path());
    let leader = state.account(1).await.expect("account").expect("state");
    assert_eq!(leader.phase, AccountPhase::Error);
    let follower = state.account(2).await.expect("account").expect("state");
    assert_eq!(follower.phase, AccountPhase::Done);
    assert_eq!(
        source.snapshot().get(&2),
        target.snapshot().get(&2),
        "the follower lost its records"
    );
    {
        let world = target.world.lock().expect("lock");
        assert!(
            world.blobs.contains(&shared),
            "the shared blob was never copied"
        );
        assert!(world.blob_puts_by_hash.get(&shared).copied().unwrap_or(0) >= 1);
    }
    let summary = run_within(&source, &target, dir.path(), opts).await;
    assert_eq!(summary.status, RunStatus::Ok);
    assert_synced(&source, &target);
}

// Sources that count change ids per change group (v1): an account killed after every collection checkpointed resumes and applies a change of a group below its highest one, and a later run finds such a change although the highest group did not move.
#[tokio::test]
async fn changes_in_lower_change_groups_are_applied() {
    for kind in [RunKind::Incremental, RunKind::Final] {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::new();
        let target = FakeTarget::new();
        source.world.lock().expect("lock").grouped = true;
        seed(&source, 1);
        target.inject(FaultOp::Changelog, Some(1), Fault::Account);
        let summary = run(&source, &target, dir.path()).await;
        assert_eq!(summary.status, RunStatus::Failed, "{kind:?}");
        source.put(1, identity(1, "late@example.org"));
        source.put(1, sieve(4, "late"));
        let summary = run_with(
            &source,
            &target,
            dir.path(),
            options(kind),
            Shutdown::default(),
        )
        .await
        .expect("resumed run");
        assert_eq!(summary.status, RunStatus::Ok, "{kind:?}");
        if kind == RunKind::Final {
            assert_eq!(
                summary.verify.as_ref().map(|verify| verify.unexplained),
                Some(0),
                "{kind:?}"
            );
        }
        assert_synced(&source, &target);
        if kind == RunKind::Incremental {
            source.put(1, identity(2, "later@example.org"));
            let summary = run_with(
                &source,
                &target,
                dir.path(),
                options(RunKind::Final),
                Shutdown::default(),
            )
            .await
            .expect("later run");
            assert_eq!(summary.status, RunStatus::Ok);
            assert_eq!(
                (summary.stats.accounts_delta, summary.stats.accounts_wiped),
                (1, 0)
            );
            assert_eq!(
                summary.verify.as_ref().map(|verify| verify.unexplained),
                Some(0)
            );
            assert_synced(&source, &target);
        }
    }
}
