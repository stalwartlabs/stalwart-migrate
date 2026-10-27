/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod fake;

use std::{path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use fake::{
    FakeConverter, FakeReader, FakeSource, FakeTarget, Rec, email, identity, mailbox, sieve,
};
use migrate::{
    orchestrator::{
        GlobalCheck, Orchestrator, RetryPolicy, RunKind, RunOptions, Tuning, VerifyOptions,
        VerifyScope, VerifySummary, verify,
    },
    shutdown::Shutdown,
};
use model::{
    AccountPointers, BlobHash, Category, CategorySet, Collection, Edition, Explanation, GlobalKey,
    LogChanges, LogCollection, LogEntry, Pointer, RegistryKey, Severity,
};
use state::{ReportFilter, ReportRow, RunStatus, SqliteState, StateStore};

fn options() -> RunOptions {
    let mut options = RunOptions::new(RunKind::Incremental, Edition::Enterprise);
    options.tuning = Tuning {
        concurrency: 2,
        batch_ops: 3,
        batch_bytes: 1 << 20,
        blob_concurrency: 2,
        read_ahead: 2,
        max_ops_per_sec: None,
        account_split: 1,
    };
    options.retry = RetryPolicy {
        max_attempts: 3,
        budget: Duration::from_secs(10),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    options.final_observation = Duration::ZERO;
    options
}

fn seed(source: &FakeSource) {
    source.put_blob(BlobHash([200; 32]), b"keep;stop;");
    source.put_registry("Domain", 3, serde_json::json!({"name": "example.org"}));
    source.put_registry("Account", 1, serde_json::json!({"name": "bob"}));
    for account_id in 1..=2 {
        source.put(account_id, mailbox(0, "Inbox"));
        for id in 0..5 {
            source.put(account_id, email(id, 0, id + 1, &["$seen"]));
        }
        source.put(account_id, identity(0, "user@example.org"));
        source.put(account_id, sieve(3, "main"));
        source.set_pointers(
            account_id,
            AccountPointers {
                active_script: Pointer::Set(Some(3)),
                ..Default::default()
            },
        );
    }
}

async fn migrate(source: &Arc<FakeSource>, target: &Arc<FakeTarget>, dir: &Path) {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
    let summary = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        state,
        Arc::new(FakeConverter),
        options(),
        Shutdown::default(),
    )
    .run()
    .await
    .expect("run");
    assert_eq!(summary.status, RunStatus::Ok);
}

async fn check(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    scope: VerifyScope,
) -> (VerifySummary, Vec<ReportRow>) {
    check_min(source, target, dir, scope, 0).await
}

async fn check_min(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    scope: VerifyScope,
    min_sample: usize,
) -> (VerifySummary, Vec<ReportRow>) {
    check_categories(
        source,
        target,
        dir,
        scope,
        min_sample,
        CategorySet::defaults(),
    )
    .await
}

async fn check_categories(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    scope: VerifyScope,
    min_sample: usize,
    categories: CategorySet,
) -> (VerifySummary, Vec<ReportRow>) {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
    let summary = verify(
        source.clone(),
        FakeReader::new(target, source),
        state.clone(),
        Arc::new(FakeConverter),
        VerifyOptions {
            scope,
            min_sample,
            categories,
            globals: GlobalCheck::Final,
            tuning: options().tuning,
            retry: options().retry,
        },
        Shutdown::default(),
    )
    .await
    .expect("verify");
    let rows = state
        .reports(ReportFilter {
            run_id: Some(summary.run_id),
            severity: Some(Severity::Verify),
            ..Default::default()
        })
        .await
        .expect("reports");
    (summary, rows)
}

fn messages(rows: &[ReportRow]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            format!(
                "{:?}/{:?}/{:?}: {}",
                row.account_id, row.object, row.object_id, row.message
            )
        })
        .collect()
}

fn typed_email(target: &FakeTarget, account_id: u32, id: u32) -> model::EmailRecord {
    match &target.world.lock().expect("lock").accounts[&account_id].typed[&(Collection::Email, id)]
    {
        Rec::Email(record) => record.clone(),
        _ => panic!("email record"),
    }
}

// A faithful copy verifies clean in full mode.
#[tokio::test]
async fn clean_copy_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    let catch_ups = target.world.lock().expect("lock").reader_catch_ups;
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.status, RunStatus::Ok, "{:?}", messages(&rows));
    assert_eq!(summary.accounts_checked, 2);
    assert_eq!(summary.mismatches, 0);
    assert!(
        target.world.lock().expect("lock").reader_catch_ups > catch_ups,
        "verify must refresh the target reader before reading it"
    );
}

// Field differences, extra objects, registry, changelog and counter problems are reported.
#[tokio::test]
async fn mismatches_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    source.put_registry("SpamLlm", 4, serde_json::json!({"name": "llm"}));
    migrate(&source, &target, dir.path()).await;
    {
        let mut world = target.world.lock().expect("lock");
        world.registry.insert(
            RegistryKey::new("x:SpamLlm", 4),
            serde_json::json!({"name": "llm"}),
        );
        let account = world.accounts.get_mut(&1).expect("account");
        let Some(Rec::Email(record)) = account.typed.get_mut(&(Collection::Email, 2)) else {
            panic!("email");
        };
        record.keywords.push("$flagged".into());
        account
            .typed
            .insert((Collection::Identity, 9), identity(9, "extra@example.org"));
        let row = account
            .changelog
            .values_mut()
            .find(|row| row.collection == LogCollection::Email)
            .expect("log row");
        row.entry = LogEntry::Changes(LogChanges {
            inserted_items: vec![999],
            ..Default::default()
        });
        account.counters.change_id = 1;
        world
            .registry
            .get_mut(&RegistryKey::new("Account", 1))
            .expect("account object")["name"] = "eve".into();
        world.registry.insert(
            RegistryKey::new("Domain", 77),
            serde_json::json!({"name": "stray.example"}),
        );
        world.unlisted.insert(RegistryKey::new("Domain", 77));
        world.unlisted.insert(RegistryKey::new("Account", 1));
    }
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    let text = messages(&rows);
    assert_eq!(summary.status, RunStatus::Failed);
    let expect = [
        "Some(1)/Some(\"email\")/Some(2): differs in the target: keywords",
        "Some(1)/Some(\"identity\")/Some(9): present in the target but not in the source",
        "None/Some(\"Account\")/Some(1): the target object differs from the converted source object",
        "None/Some(\"Domain\")/Some(77): the target holds an object that is not in the source",
        "None/Some(\"x:SpamLlm\")/Some(4): the object was dropped by the conversion but exists in the target",
        "None/Some(\"Account\")/Some(1): the target stores the object but v1 cannot list or find it: its index entries are missing",
        "None/Some(\"Domain\")/Some(77): the target stores the object but v1 cannot list or find it: its index entries are missing",
    ];
    for expected in expect {
        assert!(
            text.iter().any(|line| line == expected),
            "{expected} not in {text:#?}"
        );
    }
    assert!(
        text.iter()
            .any(|line| line.starts_with("Some(1)/None/None: changelog Email: row")),
        "{text:#?}"
    );
    assert!(
        text.iter()
            .any(|line| line.contains("change counter 1 in the target is below")),
        "{text:#?}"
    );
    assert_eq!(summary.unexplained, summary.mismatches);

    let (sample, rows) = check(
        &source,
        &target,
        dir.path(),
        VerifyScope::Sample { percent: 100 },
    )
    .await;
    assert!(
        !messages(&rows)
            .iter()
            .any(|line| line.contains("changelog Email: row")),
        "sample mode compares only the last change id"
    );
    assert!(sample.mismatches < summary.mismatches);
}

// A difference explained by an earlier report row does not fail verification.
#[tokio::test]
async fn reported_differences_are_explained() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    let mut record = typed_email(&target, 2, 1);
    record.keywords.clear();
    target
        .world
        .lock()
        .expect("lock")
        .accounts
        .get_mut(&2)
        .expect("account")
        .typed
        .insert((Collection::Email, 1), Rec::Email(record));
    let report = |severity, category: &str, explains| ReportRow {
        id: None,
        run_id: 1,
        severity,
        category: category.into(),
        account_id: Some(2),
        object: Some("email".into()),
        object_id: Some(1),
        message: "message".into(),
        explains,
    };
    let state = SqliteState::open(dir.path()).expect("state");
    state
        .add_reports(vec![
            report(Severity::Info, "truncated", Some(Explanation::Keywords(0))),
            report(Severity::Error, "failed", None),
            report(
                Severity::Warning,
                "dropped",
                Some(Explanation::ExtraHeaders),
            ),
            report(
                Severity::Warning,
                "truncated",
                Some(Explanation::Keywords(1)),
            ),
        ])
        .await
        .expect("report");
    drop(state);
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.mismatches, 1, "{:?}", messages(&rows));
    assert_eq!(
        summary.unexplained, 1,
        "info, failed, other-field and wrong-limit rows explain nothing"
    );

    let state = SqliteState::open(dir.path()).expect("state");
    state
        .add_reports(vec![report(
            Severity::Warning,
            "truncated",
            Some(Explanation::Keywords(0)),
        )])
        .await
        .expect("report");
    drop(state);
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.mismatches, 1, "{:?}", messages(&rows));
    assert_eq!(summary.unexplained, 0);
    assert_eq!(summary.status, RunStatus::Ok);

    target
        .world
        .lock()
        .expect("lock")
        .accounts
        .get_mut(&2)
        .expect("account")
        .typed
        .remove(&(Collection::Email, 1));
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(
        summary.unexplained,
        1,
        "a truncation does not explain a missing object: {:?}",
        messages(&rows)
    );
}

// Sample mode always includes the accounts touched by the last run.
#[tokio::test]
async fn sample_includes_accounts_touched_by_the_last_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    let none = VerifyScope::Sample { percent: 0 };
    let (summary, _) = check(&source, &target, dir.path(), none).await;
    assert_eq!(summary.accounts_checked, 2);

    source.put(2, email(9, 0, 10, &[]));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    migrate(&source, &target, dir.path()).await;
    let (summary, rows) = check(&source, &target, dir.path(), none).await;
    assert_eq!(summary.accounts_checked, 1, "{:?}", messages(&rows));
    assert_eq!(summary.status, RunStatus::Ok);

    let (summary, _) = check_min(&source, &target, dir.path(), none, 16).await;
    assert_eq!(summary.accounts_checked, 2);

    for _ in 0..20 {
        let (summary, _) = check(&source, &target, dir.path(), VerifyScope::Full).await;
        assert_eq!(summary.status, RunStatus::Ok);
    }
    let (summary, _) = check(&source, &target, dir.path(), none).await;
    assert_eq!(
        summary.accounts_checked, 1,
        "touched accounts survive many verify runs"
    );
}

// Accounts that exist only in the target are reported.
#[tokio::test]
async fn extra_target_accounts_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    target
        .world
        .lock()
        .expect("lock")
        .accounts
        .entry(42)
        .or_default()
        .typed
        .insert((Collection::Mailbox, 0), mailbox(0, "Inbox"));
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert!(
        messages(&rows)
            .iter()
            .any(|line| line.contains("account 42 exists in the target but not in the source"))
    );
}

// A registry object whose type no longer exists in the source at all is still reported as an extra in the target.
#[tokio::test]
async fn extras_of_vanished_registry_types_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    source.delete_registry("Domain", 3);
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.status, RunStatus::Failed, "{:?}", messages(&rows));
    assert!(
        messages(&rows)
            .iter()
            .any(|row| row.contains("\"Domain\"") && row.contains("not in the source")),
        "{:?}",
        messages(&rows)
    );
}

// A sieve blob holds the script followed by its compiled form; only the script part is compared.
#[tokio::test]
async fn sieve_scripts_compare_only_the_script_part() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    let set_target_blob = |data: &'static [u8]| {
        target
            .world
            .lock()
            .expect("lock")
            .blob_data
            .insert(BlobHash([200; 32]), Bytes::from_static(data));
    };
    set_target_blob(b"keep;stop;compiled-by-the-target");
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.mismatches, 0, "{:?}", messages(&rows));
    set_target_blob(b"keep;stoq;compiled-by-the-target");
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.unexplained, 2, "{:?}", messages(&rows));
}

// Verify accepts the converted value only for objects that actually fell back to it.
#[tokio::test]
async fn converted_value_is_accepted_only_for_recorded_fallbacks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    source.put_registry(
        "Domain",
        1,
        serde_json::json!({"name": "a.org", "fallback": true}),
    );
    migrate(&source, &target, dir.path()).await;
    let (summary, _) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.unexplained, 0, "{summary:?}");
    target.world.lock().expect("lock").registry.insert(
        model::RegistryKey::new("Domain", 1),
        serde_json::json!({"name": "a.org", "v1": true}),
    );
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.unexplained, 1, "{:?}", messages(&rows));
}

// Share notifications are compared by id across pages, one row per differing id.
#[tokio::test]
async fn share_notifications_differ_per_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    for id in 1..=8 {
        source.add_share(1, id);
    }
    migrate(&source, &target, dir.path()).await;
    {
        let mut world = target.world.lock().expect("lock");
        let shares = &mut world.accounts.get_mut(&1).expect("account").shares;
        shares.remove(&2);
        shares.insert(5, Bytes::from_static(b"changed"));
        shares.insert(9, Bytes::from_static(b"extra"));
        shares.insert(10, Bytes::from_static(b"extra"));
    }
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    let mut shares: Vec<String> = rows
        .iter()
        .filter(|row| row.account_id == Some(1) && row.message.starts_with("share notification"))
        .map(|row| row.message.to_string())
        .collect();
    shares.sort();
    assert_eq!(
        shares,
        [
            "share notification 10 is present in the target but not in the source",
            "share notification 2 is missing in the target",
            "share notification 5 differs in the target",
            "share notification 9 is present in the target but not in the source",
        ],
        "{:?}",
        messages(&rows)
    );
    assert_eq!(summary.unexplained, 4, "{:?}", messages(&rows));
}

async fn check_globals(
    source: &Arc<FakeSource>,
    target: &Arc<FakeTarget>,
    dir: &Path,
    globals: GlobalCheck,
) -> (VerifySummary, Vec<ReportRow>) {
    let state = Arc::new(SqliteState::open(dir).expect("open state"));
    let summary = verify(
        source.clone(),
        FakeReader::new(target, source),
        state.clone(),
        Arc::new(FakeConverter),
        VerifyOptions {
            scope: VerifyScope::Full,
            min_sample: 0,
            categories: CategorySet::defaults(),
            globals,
            tuning: options().tuning,
            retry: options().retry,
        },
        Shutdown::default(),
    )
    .await
    .expect("verify");
    let rows = state
        .reports(ReportFilter {
            run_id: Some(summary.run_id),
            severity: Some(Severity::Verify),
            ..Default::default()
        })
        .await
        .expect("reports");
    (summary, rows)
}

// Only the final run removes share notifications v0.16 deleted, so before it a target-only notification is expected; missing and changed ones count either way.
#[tokio::test]
async fn share_notifications_removed_in_the_source_count_only_after_the_final_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    for id in 1..=4 {
        source.add_share(1, id);
    }
    migrate(&source, &target, dir.path()).await;
    let (summary, rows) = check_globals(&source, &target, dir.path(), GlobalCheck::Shared).await;
    assert_eq!(summary.unexplained, 0, "{:?}", messages(&rows));
    {
        let mut world = source.world.lock().expect("lock");
        world
            .accounts
            .get_mut(&1)
            .expect("account")
            .shares
            .remove(&3);
    }
    target
        .world
        .lock()
        .expect("lock")
        .accounts
        .get_mut(&1)
        .expect("account")
        .shares
        .insert(2, Bytes::from_static(b"changed"));
    let (summary, rows) = check_globals(&source, &target, dir.path(), GlobalCheck::Shared).await;
    assert_eq!(
        messages(&rows),
        ["Some(1)/None/None: share notification 2 differs in the target"]
    );
    assert_eq!(summary.unexplained, 1);
    let (summary, rows) = check_globals(&source, &target, dir.path(), GlobalCheck::Final).await;
    assert_eq!(summary.unexplained, 2, "{:?}", messages(&rows));
}

// Copied tasks are compared with the converted source tasks: a lost, an altered and a stale copied task are unexplained, and so is a singleton the tool migrated that the source no longer has; task types the tool never copies, singletons v1 scheduled itself and tasks v1 schedules under its own derived ids (share revoke cleanups) are not reported.
#[tokio::test]
async fn tasks_are_compared_with_the_converted_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    {
        let mut world = source.world.lock().expect("lock");
        world.queue = (0..5).collect();
        world.task_types = vec![
            "IndexDocument",
            "Maintenance",
            "DestroyAccount",
            "Linked",
            "Obsolete",
        ];
    }
    let mut categories = CategorySet::defaults();
    categories.insert(Category::Tasks);
    let summary = Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(&target, &source),
        Arc::new(SqliteState::open(dir.path()).expect("open state")),
        Arc::new(FakeConverter),
        RunOptions {
            kind: RunKind::Final,
            categories,
            ..options()
        },
        Shutdown::default(),
    )
    .run()
    .await
    .expect("final run");
    assert_eq!(summary.status, RunStatus::Ok);
    assert_eq!(
        summary.verify.as_ref().map(|verify| verify.status),
        Some(RunStatus::Ok)
    );
    {
        let mut world = target.world.lock().expect("lock");
        assert_eq!(world.tasks.keys().copied().collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(world.tasks[&3]["link"], true);
        world.tasks.remove(&1);
        world.tasks.insert(
            2,
            serde_json::json!({"@type": "DestroyAccount", "due": 99, "v1": true}),
        );
        world
            .tasks
            .insert(77, serde_json::json!({"@type": "CalendarAlarmEmail"}));
        world.tasks.insert(
            78,
            serde_json::json!({"@type": "DestroyAccount", "v1": true}),
        );
        let singleton = serde_json::json!({
            "@type": "AccountMaintenance",
            "accountId": "b",
            "maintenanceType": "purge",
            "status": {"@type": "Pending", "createdAt": "2026-01-01T00:00:00Z", "due": "2026-01-02T00:00:00Z"}
        });
        assert!(source_v1::is_singleton_task(&singleton));
        world.tasks.insert(79, singleton);
        world.tasks.insert(
            (0b11 << 62) | 5,
            serde_json::json!({"@type": "ShareRevokeCleanup", "accountId": "b", "documentId": "c", "objectType": "mailbox"}),
        );
        world.tasks.insert(
            (0b11 << 62) | 6,
            serde_json::json!({"@type": "DestroyAccount", "v1": true}),
        );
    }
    let stale = serde_json::json!({
        "@type": "DkimManagement",
        "domainId": "h",
        "status": {"@type": "Pending", "createdAt": "2026-01-01T00:00:00Z", "due": "2026-01-02T00:00:00Z"}
    });
    let stale_id = source_v1::singleton_task_id(&stale).expect("singleton");
    target
        .world
        .lock()
        .expect("lock")
        .tasks
        .insert(stale_id, stale);
    SqliteState::open(dir.path())
        .expect("open state")
        .track_globals(1, vec![GlobalKey::Task(stale_id)])
        .await
        .expect("track");
    let (summary, rows) = check_categories(
        &source,
        &target,
        dir.path(),
        VerifyScope::Full,
        0,
        categories,
    )
    .await;
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.unexplained, 4, "{:?}", messages(&rows));
    assert!(
        messages(&rows).contains(&format!(
            "None/Some(\"Task\")/Some({stale_id}): present in the target but not in the source"
        )),
        "{:?}",
        messages(&rows)
    );
    let messages = messages(&rows);
    assert!(
        messages.contains(
            &"None/Some(\"Task\")/Some(78): present in the target but not in the source".to_owned()
        ),
        "{messages:?}"
    );
    assert!(
        messages.contains(
            &"None/Some(\"Task\")/Some(1): present in the source but missing in the target"
                .to_owned()
        ),
        "{messages:?}"
    );
    assert!(
        messages.contains(&"None/Some(\"Task\")/Some(2): differs in the target".to_owned()),
        "{messages:?}"
    );
}

// After a final run, a finalized account whose stored quota usage differs from the sizes of its objects is an unexplained mismatch; an account that is not done (an --allow-errors final run) is not checked.
#[tokio::test]
async fn drifted_quota_usage_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    migrate(&source, &target, dir.path()).await;
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.status, RunStatus::Ok, "{:?}", messages(&rows));
    target
        .world
        .lock()
        .expect("lock")
        .quota_drift
        .insert(2, -10);
    target.world.lock().expect("lock").quota_drift.insert(1, 5);
    target
        .world
        .lock()
        .expect("lock")
        .email_count_drift
        .insert(2, 1);
    SqliteState::open(dir.path())
        .expect("open state")
        .update_account(state::AccountUpdate::SetPhase {
            account_id: 1,
            phase: state::AccountPhase::Full,
        })
        .await
        .expect("phase");
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.unexplained, 2, "{:?}", messages(&rows));
    assert!(
        messages(&rows).iter().any(|message| message
            .starts_with("Some(2)/None/None: the target counts 2 emails, but holds 1")),
        "{:?}",
        messages(&rows)
    );
    assert!(
        messages(&rows).iter().any(|message| message.starts_with("Some(2)/None/None: quota usage is 4086 bytes in the target, but its objects add up to 4096 bytes")),
        "{:?}",
        messages(&rows)
    );
}

// Unreadable source registry entries yield one warning per run, no errors and no verify mismatches.
#[tokio::test]
async fn unreadable_registry_entries_are_warnings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source);
    source.put_registry(
        "WebHook",
        2,
        serde_json::json!({"url": "https://a.example"}),
    );
    source.put_registry(
        "WebHook",
        9,
        serde_json::json!({"url": "https://b.example"}),
    );
    source
        .world
        .lock()
        .expect("lock")
        .unreadable_registry
        .insert(RegistryKey::new("WebHook", 9));
    migrate(&source, &target, dir.path()).await;
    migrate(&source, &target, dir.path()).await;
    {
        let world = target.world.lock().expect("lock");
        assert!(world.registry.contains_key(&RegistryKey::new("WebHook", 2)));
        assert!(!world.registry.contains_key(&RegistryKey::new("WebHook", 9)));
    }
    let state = SqliteState::open(dir.path()).expect("open state");
    let rows = state
        .reports(ReportFilter::default())
        .await
        .expect("reports");
    let warnings: Vec<&ReportRow> = rows
        .iter()
        .filter(|row| row.object.as_deref() == Some("WebHook") && row.object_id == Some(9))
        .collect();
    assert_eq!(warnings.len(), 2, "{:#?}", messages(&rows));
    assert!(warnings.iter().all(|row| {
        row.severity == Severity::Warning
            && &*row.category == "skipped"
            && row.message.contains("ignored by v0.16.27")
    }));
    assert_ne!(warnings[0].run_id, warnings[1].run_id);
    assert!(
        rows.iter().all(|row| row.severity != Severity::Error),
        "{:#?}",
        messages(&rows)
    );
    drop(state);
    let (summary, rows) = check(&source, &target, dir.path(), VerifyScope::Full).await;
    assert_eq!(summary.status, RunStatus::Ok, "{:#?}", messages(&rows));
    assert_eq!(summary.mismatches, 0);
}
