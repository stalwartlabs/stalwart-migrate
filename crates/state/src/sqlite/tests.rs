/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use model::{
    BlobHash, CategorySet, Collection, Explanation, GlobalCategory, GlobalKey, IssueKind,
    RegistryId, RegistryKey, ReportKind, Severity,
};

use super::SqliteState;
use crate::{
    error::Error,
    store::StateStore,
    types::{
        AccountPhase, AccountUpdate, ContentHash, CursorMode, CursorRow, FailedDocument, MetaKey,
        RegistryState, RegistryStatus, RegistryUpdate, ReportCount, ReportFilter, ReportRow,
        ReportScope, ReportsAdded, RunMode, RunStatus,
    },
};

fn report(run_id: i64, severity: Severity, category: &str, account_id: Option<u32>) -> ReportRow {
    ReportRow {
        id: None,
        run_id,
        severity,
        category: category.into(),
        account_id,
        object: Some("email".into()),
        object_id: Some(u64::MAX),
        message: "message".into(),
        explains: Some(Explanation::Keywords(100)),
    }
}

fn registry_update(object: &str, id: u64, json: &str, status: RegistryStatus) -> RegistryUpdate {
    RegistryUpdate {
        key: RegistryKey::new(object, id),
        source_hash: ContentHash::of(json.as_bytes()),
        target_hash: Some(ContentHash::of(b"target")),
        stored_hash: Some(ContentHash::of(b"stored")),
        source_json: json.as_bytes().to_vec(),
        status,
    }
}

#[tokio::test]
async fn open_existing_requires_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        SqliteState::open_existing(dir.path()),
        Err(Error::Missing(_))
    ));
    drop(SqliteState::open(dir.path()).expect("create"));
    assert!(SqliteState::open_existing(dir.path()).is_ok());
}

#[tokio::test]
async fn exclusive_open_rejects_second_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = SqliteState::open_exclusive(dir.path()).expect("first");
    assert!(matches!(
        SqliteState::open_exclusive(dir.path()),
        Err(Error::Locked(_))
    ));
    assert!(SqliteState::open_existing(dir.path()).is_ok());
    drop(first);
    assert!(SqliteState::open_exclusive(dir.path()).is_ok());
}

#[tokio::test]
async fn meta_round_trip_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let state = SqliteState::open(dir.path()).expect("open");
        assert_eq!(state.meta(MetaKey::Edition).await, Ok(None));
        state
            .set_meta(MetaKey::Edition, "enterprise".into())
            .await
            .expect("set");
        state
            .set_meta(MetaKey::Edition, "community".into())
            .await
            .expect("overwrite");
    }
    let state = SqliteState::open(dir.path()).expect("reopen");
    assert_eq!(
        state.meta(MetaKey::Edition).await,
        Ok(Some("community".into()))
    );
}

#[tokio::test]
async fn running_runs_are_marked_interrupted_on_next_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = {
        let state = SqliteState::open(dir.path()).expect("open");
        let start = state.begin_run(RunMode::Incremental).await.expect("begin");
        assert!(start.interrupted.is_empty());
        start.run_id
    };
    let state = SqliteState::open(dir.path()).expect("reopen");
    let second = state.begin_run(RunMode::Final).await.expect("begin");
    assert_eq!(second.interrupted, [first]);
    state
        .finish_run(second.run_id, RunStatus::Ok, "{\"objects\":1}".into())
        .await
        .expect("finish");
    let third = state.begin_run(RunMode::Incremental).await.expect("begin");
    assert!(third.interrupted.is_empty());

    let runs = state.runs(10).await.expect("runs");
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].id, third.run_id);
    assert_eq!(runs[0].status, RunStatus::Running);
    assert_eq!(runs[1].status, RunStatus::Ok);
    assert_eq!(runs[1].mode, RunMode::Final);
    assert_eq!(runs[1].stats.as_deref(), Some("{\"objects\":1}"));
    assert!(runs[1].finished_at.is_some());
    assert_eq!(runs[2].status, RunStatus::Interrupted);

    let mut verify = Vec::new();
    for _ in 0..20 {
        verify.push(
            state
                .begin_run(RunMode::Verify)
                .await
                .expect("verify")
                .run_id,
        );
    }
    let last = verify.last().copied().expect("verify run");
    let found = state
        .last_run_except(RunMode::Verify, last + 1)
        .await
        .expect("last run")
        .expect("data run");
    assert_eq!(found.id, third.run_id);
    assert_eq!(
        state
            .last_run_except(RunMode::Verify, third.run_id)
            .await
            .expect("last run")
            .map(|run| run.id),
        Some(second.run_id)
    );
    assert_eq!(
        state
            .last_run_except(RunMode::Verify, first)
            .await
            .expect("last run"),
        None
    );
}

#[tokio::test]
async fn account_lifecycle_transitions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    assert_eq!(state.account(7).await, Ok(None));

    state
        .update_account(AccountUpdate::StartFull {
            account_id: 7,
            full_target: 40,
            run_id: 3,
        })
        .await
        .expect("start");
    let account = state.account(7).await.expect("read").expect("present");
    assert_eq!(account.phase, AccountPhase::Containers);
    assert_eq!(account.full_target, Some(40));
    assert_eq!(account.full_run, Some(3));
    assert_eq!(account.checkpoint, None);

    state
        .set_cursor(7, 0, CursorMode::Full, 1000)
        .await
        .expect("cursor");
    state
        .set_cursor(7, 0, CursorMode::Full, 2000)
        .await
        .expect("cursor");
    state
        .set_cursor(7, 2, CursorMode::Log, u64::MAX - 1)
        .await
        .expect("cursor");
    state
        .update_account(AccountUpdate::SetPhase {
            account_id: 7,
            phase: AccountPhase::Full,
        })
        .await
        .expect("phase");
    assert_eq!(
        state.cursors(7).await.expect("cursors"),
        [
            CursorRow {
                collection: 0,
                mode: CursorMode::Full,
                last_id: 2000
            },
            CursorRow {
                collection: 2,
                mode: CursorMode::Log,
                last_id: u64::MAX - 1
            }
        ]
    );

    state
        .update_account(AccountUpdate::Fail {
            account_id: 7,
            error: "boom".into(),
        })
        .await
        .expect("fail");
    state
        .update_account(AccountUpdate::Fail {
            account_id: 7,
            error: "boom again".into(),
        })
        .await
        .expect("fail");
    let account = state.account(7).await.expect("read").expect("present");
    assert_eq!(account.phase, AccountPhase::Error);
    assert_eq!(account.attempts, 2);
    assert_eq!(account.last_error.as_deref(), Some("boom again"));
    assert_eq!(account.full_target, Some(40));
    assert_eq!(state.cursors(7).await.expect("cursors").len(), 2);
    assert_eq!(state.failed_accounts(10).await.expect("failed").len(), 1);

    state
        .set_cursor(7, 3, CursorMode::Pending, 9)
        .await
        .expect("cursor");
    state
        .set_cursor(7, 1, CursorMode::Checkpoint, 40)
        .await
        .expect("cursor");
    state
        .update_account(AccountUpdate::Complete {
            account_id: 7,
            checkpoint: 40,
            synced: CategorySet::defaults(),
        })
        .await
        .expect("complete");
    let account = state.account(7).await.expect("read").expect("present");
    assert_eq!(account.phase, AccountPhase::Done);
    assert_eq!(account.checkpoint, Some(40));
    assert_eq!(account.full_target, None);
    assert_eq!(account.attempts, 0);
    assert_eq!(account.last_error, None);
    assert_eq!(account.synced, CategorySet::defaults());
    assert_eq!(
        state.cursors(7).await.expect("cursors"),
        [
            CursorRow {
                collection: 1,
                mode: CursorMode::Checkpoint,
                last_id: 40
            },
            CursorRow {
                collection: 2,
                mode: CursorMode::Log,
                last_id: u64::MAX - 1
            }
        ]
    );
    state
        .update_account(AccountUpdate::Wiped {
            account_id: 7,
            run_id: 5,
        })
        .await
        .expect("wipe");
    let account = state.account(7).await.expect("read").expect("present");
    assert_eq!(account.phase, AccountPhase::Wiped);
    assert_eq!(account.full_run, Some(5));
    assert_eq!(account.checkpoint, None);
    assert_eq!(account.synced, CategorySet::empty());
    assert!(state.cursors(7).await.expect("cursors").is_empty());

    state
        .update_account(AccountUpdate::Remove { account_id: 7 })
        .await
        .expect("remove");
    assert_eq!(state.account(7).await, Ok(None));
}

#[tokio::test]
async fn interrupted_full_copy_resumes_from_persisted_cursors() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let state = SqliteState::open(dir.path()).expect("open");
        state.begin_run(RunMode::Incremental).await.expect("begin");
        state
            .update_account(AccountUpdate::StartFull {
                account_id: 1,
                full_target: 99,
                run_id: 1,
            })
            .await
            .expect("start");
        state
            .update_account(AccountUpdate::SetPhase {
                account_id: 1,
                phase: AccountPhase::Full,
            })
            .await
            .expect("phase");
        state
            .set_cursor(1, 0, CursorMode::Full, 512)
            .await
            .expect("cursor");
    }
    let state = SqliteState::open(dir.path()).expect("reopen");
    let start = state.begin_run(RunMode::Incremental).await.expect("begin");
    assert_eq!(start.interrupted.len(), 1);
    let account = state.account(1).await.expect("read").expect("present");
    assert_eq!(account.phase, AccountPhase::Full);
    assert_eq!(account.full_target, Some(99));
    assert_eq!(account.checkpoint, None);
    assert_eq!(
        state.cursors(1).await.expect("cursors"),
        [CursorRow {
            collection: 0,
            mode: CursorMode::Full,
            last_id: 512
        }]
    );

    state
        .update_account(AccountUpdate::StartFull {
            account_id: 1,
            full_target: 120,
            run_id: 1,
        })
        .await
        .expect("restart");
    assert!(state.cursors(1).await.expect("cursors").is_empty());
    let counts = state.phase_counts().await.expect("counts");
    assert_eq!(counts.len(), 1);
    assert_eq!(counts[0].phase, AccountPhase::Containers);
    assert_eq!(counts[0].count, 1);
}

#[tokio::test]
async fn registry_rows_keep_compressed_source_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let big = format!("{{\"value\":\"{}\"}}", "x".repeat(10_000));
    state
        .put_registry(
            1,
            vec![
                registry_update("Domain", 1, "{\"name\":\"a.org\"}", RegistryStatus::Ok),
                registry_update("Domain", u64::MAX, &big, RegistryStatus::Ok),
                registry_update("Account", 5, "{}", RegistryStatus::Dropped),
            ],
        )
        .await
        .expect("put");

    let mut domains = state
        .registry_states("Domain".into())
        .await
        .expect("states");
    domains.sort_by_key(|state| state.key.id);
    assert_eq!(domains.len(), 2);
    assert_eq!(domains[1].key.id, RegistryId::Id(u64::MAX));
    assert_eq!(domains[1].source_hash, ContentHash::of(big.as_bytes()));
    assert_eq!(domains[1].target_hash, Some(ContentHash::of(b"target")));
    assert_eq!(domains[1].stored_hash, Some(ContentHash::of(b"stored")));
    assert_eq!(
        state
            .registry_source_json(RegistryKey::new("Domain", u64::MAX))
            .await
            .expect("json"),
        Some(big.into_bytes())
    );
    assert_eq!(
        state.registry_objects().await.expect("objects"),
        [Box::from("Account"), Box::from("Domain")]
    );

    let sample = state.registry_sample(10).await.expect("sample");
    assert_eq!(sample.len(), 2);
    assert!(
        sample
            .iter()
            .all(|state| state.status == RegistryStatus::Ok)
    );

    state
        .put_registry(
            2,
            vec![registry_update(
                "Domain",
                1,
                "{\"name\":\"b.org\"}",
                RegistryStatus::Error,
            )],
        )
        .await
        .expect("update");
    let domain = state
        .registry_states("Domain".into())
        .await
        .expect("states")
        .into_iter()
        .find(|state| state.key.id == RegistryId::Id(1))
        .expect("present");
    assert_eq!(domain.status, RegistryStatus::Error);
    assert_eq!(domain.source_hash, ContentHash::of(b"{\"name\":\"b.org\"}"));

    state
        .remove_registry(vec![RegistryKey::new("Domain", 1)])
        .await
        .expect("remove");
    assert_eq!(
        state
            .registry_states("Domain".into())
            .await
            .expect("states")
            .len(),
        1
    );
    assert_eq!(
        state
            .registry_source_json(RegistryKey::new("Domain", 1))
            .await
            .expect("json"),
        None
    );
}

#[tokio::test]
async fn blob_cache_and_global_cursors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let a = BlobHash([1; 32]);
    let b = BlobHash([2; 32]);
    assert_eq!(state.blobs_known(vec![a, b]).await, Ok(vec![false, false]));
    state
        .add_blobs(1, vec![(a, 10), (a, 10)])
        .await
        .expect("add");
    assert_eq!(state.blobs_known(vec![a, b]).await, Ok(vec![true, false]));

    assert_eq!(state.global_cursor("queue".into()).await, Ok(None));
    state
        .set_global_cursor("queue".into(), vec![1, 2, 3])
        .await
        .expect("set");
    state
        .set_global_cursor("queue".into(), vec![4])
        .await
        .expect("set");
    assert_eq!(state.global_cursor("queue".into()).await, Ok(Some(vec![4])));
}

// Records written in an older final generation are stale, paged in key order per category, and forgotten.
#[tokio::test]
async fn global_records_track_generations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let high = u64::MAX - 1;
    state
        .track_globals(
            3,
            vec![
                GlobalKey::Queue(5),
                GlobalKey::Queue(high),
                GlobalKey::Queue(6),
                GlobalKey::Report(ReportKind::Tls, 1),
                GlobalKey::Report(ReportKind::Dmarc, 9),
                GlobalKey::Task(2),
            ],
        )
        .await
        .expect("track");
    state
        .track_globals(4, vec![GlobalKey::Queue(6)])
        .await
        .expect("track");
    let mut all = state
        .stale_globals(GlobalCategory::Queue, 4, None, 10)
        .await
        .expect("stale");
    all.sort_unstable();
    assert_eq!(all, [GlobalKey::Queue(5), GlobalKey::Queue(high)]);
    let first = state
        .stale_globals(GlobalCategory::Queue, 4, None, 1)
        .await
        .expect("stale");
    assert_eq!(first.len(), 1);
    let rest = state
        .stale_globals(GlobalCategory::Queue, 4, first.last().copied(), 10)
        .await
        .expect("stale");
    let mut queue: Vec<GlobalKey> = first.into_iter().chain(rest).collect();
    queue.sort_unstable();
    assert_eq!(queue, [GlobalKey::Queue(5), GlobalKey::Queue(high)]);
    assert_eq!(
        state
            .stale_globals(GlobalCategory::Reports, 4, None, 10)
            .await,
        Ok(vec![
            GlobalKey::Report(ReportKind::Dmarc, 9),
            GlobalKey::Report(ReportKind::Tls, 1)
        ])
    );
    assert_eq!(
        state
            .stale_globals(GlobalCategory::Tasks, 4, None, 10)
            .await,
        Ok(vec![GlobalKey::Task(2)])
    );
    assert_eq!(
        state
            .stale_globals(GlobalCategory::Telemetry, 4, None, 10)
            .await,
        Ok(Vec::new())
    );
    state.forget_globals(queue).await.expect("forget");
    assert_eq!(
        state
            .stale_globals(GlobalCategory::Queue, 5, None, 10)
            .await,
        Ok(vec![GlobalKey::Queue(6)])
    );
}

#[tokio::test]
async fn reports_filter_and_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    state
        .add_reports(vec![
            report(1, Severity::Error, "failed", Some(1)),
            report(1, Severity::Warning, "truncated", Some(1)),
            report(1, Severity::Warning, "truncated", Some(2)),
            report(2, Severity::Warning, "truncated", None),
        ])
        .await
        .expect("add");

    let all = state.reports(ReportFilter::default()).await.expect("all");
    assert_eq!(all.len(), 4);
    assert_eq!(all[0].object_id, Some(u64::MAX));
    assert_eq!(all[0].explains, Some(Explanation::Keywords(100)));
    assert!(all.windows(2).all(|pair| pair[0].id < pair[1].id));

    let filtered = state
        .reports(ReportFilter {
            run_id: Some(1),
            severity: Some(Severity::Warning),
            account_id: Some(2),
            ..Default::default()
        })
        .await
        .expect("filtered");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].account_id, Some(2));

    let limited = state
        .reports(ReportFilter {
            category: Some("truncated".into()),
            limit: Some(2),
            ..Default::default()
        })
        .await
        .expect("limited");
    assert_eq!(limited.len(), 2);

    let global = state
        .reports(ReportFilter {
            scope: ReportScope::Global,
            ..Default::default()
        })
        .await
        .expect("global");
    assert_eq!(global.len(), 1);
    assert_eq!(global[0].account_id, None);

    let counts = state.report_counts(Some(1)).await.expect("counts");
    assert_eq!(counts.len(), 2);
    assert_eq!(counts[0].severity, Severity::Error);
    assert_eq!(counts[1].count, 2);
    let total: u64 = state
        .report_counts(None)
        .await
        .expect("counts")
        .iter()
        .map(|count| count.count)
        .sum();
    assert_eq!(total, 4);
}

// An issue reported again for the same object within a run (a retried or rewritten write) is stored once; a later run, and object-less summary rows, keep their own rows.
#[tokio::test]
async fn repeated_issue_rows_are_stored_once_per_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let rows = || {
        vec![
            error_row(1, Some(1), "failed", Some(("email", 7))),
            error_row(2, Some(1), "failed", Some(("email", 7))),
            error_row(2, Some(1), "failed", Some(("email", 7))),
            error_row(2, Some(1), "failed", Some(("email", 8))),
            error_row(2, None, "failed", Some(("span", 8))),
            error_row(2, None, "failed", None),
            error_row(2, None, "failed", None),
        ]
    };
    assert_eq!(
        state.add_reports(rows()).await.expect("add"),
        ReportsAdded { rows: 6, errors: 6 }
    );
    assert_eq!(
        state.add_reports(rows()).await.expect("add again"),
        ReportsAdded { rows: 2, errors: 2 }
    );
    let counts = |counts: Vec<ReportCount>| -> Vec<u64> {
        counts.into_iter().map(|count| count.count).collect()
    };
    assert_eq!(
        counts(state.report_counts(Some(2)).await.expect("run")),
        [7]
    );
    assert_eq!(
        counts(state.report_counts(Some(1)).await.expect("run")),
        [1]
    );
    assert_eq!(counts(state.report_counts(None).await.expect("all")), [8]);
}

// The duplicate lookup of a report row seeks by account too, also in a state database created with the older index.
#[tokio::test]
async fn report_dedup_seeks_by_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(SqliteState::open(dir.path()).expect("open"));
    let path = dir.path().join(super::STATE_FILE);
    {
        let conn = rusqlite::Connection::open(&path).expect("conn");
        conn.execute_batch(
            "DROP INDEX report_subject_account;
             CREATE INDEX report_subject ON report (run_id, object, object_id) WHERE object IS NOT NULL;",
        )
        .expect("old index");
    }
    let state = SqliteState::open(dir.path()).expect("reopen");
    let rows = (0..2000)
        .map(|account| error_row(1, Some(account), "failed", Some(("email", 1))))
        .collect::<Vec<_>>();
    state.add_reports(rows.clone()).await.expect("add");
    state.add_reports(rows).await.expect("add again");
    assert_eq!(
        state.report_counts(Some(1)).await.expect("counts")[0].count,
        2000
    );
    drop(state);
    let conn = rusqlite::Connection::open(&path).expect("conn");
    let indexes = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'report_subject%'",
        )
        .expect("prepare")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    assert_eq!(indexes, ["report_subject_account"]);
    let plan = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {}", super::ops::ADD_REPORT))
        .expect("prepare")
        .query_map(
            rusqlite::params![
                1,
                "error",
                "failed",
                7,
                "email",
                1,
                "message",
                None::<String>
            ],
            |row| row.get::<_, String>(3),
        )
        .expect("plan")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    assert!(
        plan.iter().any(|step| step.contains(
            "USING INDEX report_subject_account (run_id=? AND object=? AND object_id=? AND account_id=?)"
        )),
        "{plan:?}"
    );
}

fn error_row(
    run_id: i64,
    account_id: Option<u32>,
    category: &str,
    document: Option<(&str, u64)>,
) -> ReportRow {
    ReportRow {
        id: None,
        run_id,
        severity: Severity::Error,
        category: category.into(),
        account_id,
        object: document.map(|(object, _)| object.into()),
        object_id: document.map(|(_, id)| id),
        message: "message".into(),
        explains: None,
    }
}

// Failed documents and object-less account errors count only after the accepted run and since the last full copy.
#[tokio::test]
async fn failed_documents_page_since_full_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    for (account_id, run_id) in [(1, 2), (2, 1)] {
        state
            .update_account(AccountUpdate::StartFull {
                account_id,
                full_target: 1,
                run_id,
            })
            .await
            .expect("start");
    }
    state
        .add_reports(vec![
            error_row(1, Some(1), "failed", Some(("email", 5))),
            error_row(2, Some(1), "failed", Some(("email", 7))),
            error_row(3, Some(1), "failed", Some(("email", 7))),
            error_row(3, Some(1), "skipped", Some(("mailbox", 2))),
            error_row(3, Some(2), "failed", Some(("email", 1))),
            error_row(1, Some(2), "failed", Some(("email", 3))),
            error_row(3, Some(9), "failed", Some(("email", 4))),
            error_row(3, None, "failed", Some(("x:Domain", 4))),
            error_row(2, Some(1), "skipped", None),
            error_row(3, Some(2), "skipped", None),
            error_row(3, Some(2), "failed", None),
            error_row(1, Some(1), "skipped", None),
        ])
        .await
        .expect("add");

    let document = |account_id, collection, document_id| FailedDocument {
        account_id,
        collection,
        document_id,
    };
    let mut paged = Vec::new();
    let mut from = None;
    loop {
        let page = state.failed_documents(0, from, 1).await.expect("page");
        let Some(last) = page.last() else {
            break;
        };
        from = Some(*last);
        paged.extend(page);
    }
    assert_eq!(
        paged,
        [
            document(1, Collection::Email, 7),
            document(1, Collection::Mailbox, 2),
            document(2, Collection::Email, 1),
            document(2, Collection::Email, 3),
        ]
    );
    assert_eq!(
        state.failed_documents(2, None, 10).await.expect("accepted"),
        [
            document(1, Collection::Email, 7),
            document(1, Collection::Mailbox, 2),
            document(2, Collection::Email, 1),
        ]
    );
    assert_eq!(
        state
            .account_errors(0, IssueKind::Skipped)
            .await
            .expect("count"),
        2
    );
    assert_eq!(
        state
            .account_errors(2, IssueKind::Skipped)
            .await
            .expect("count"),
        1
    );
}

// Global error rows are counted per object within a half-open run range.
#[tokio::test]
async fn global_errors_count_a_run_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    state
        .add_reports(vec![
            error_row(1, None, "skipped", Some(("queuedMessage", 1))),
            error_row(2, None, "skipped", Some(("queuedMessage", 2))),
            error_row(3, None, "failed", Some(("queuedMessage", 3))),
            error_row(2, None, "skipped", Some(("dmarcReport", 4))),
            error_row(2, Some(1), "skipped", Some(("queuedMessage", 5))),
        ])
        .await
        .expect("add");
    let count = |runs| state.global_errors(runs, "queuedMessage".into());
    assert_eq!(count(2..3).await, Ok(1));
    assert_eq!(count(2..4).await, Ok(2));
    assert_eq!(count(1..i64::MAX).await, Ok(3));
    assert_eq!(count(4..i64::MAX).await, Ok(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_are_group_committed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(SqliteState::open(dir.path()).expect("open"));
    let mut tasks = tokio::task::JoinSet::new();
    for account_id in 0..64u32 {
        let state = state.clone();
        tasks.spawn(async move {
            for last_id in 0..20u64 {
                state
                    .set_cursor(account_id, 0, CursorMode::Full, last_id)
                    .await?;
            }
            state
                .update_account(AccountUpdate::Complete {
                    account_id,
                    checkpoint: u64::from(account_id),
                    synced: CategorySet::empty(),
                })
                .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("join").expect("write");
    }
    let accounts = state.accounts().await.expect("accounts");
    assert_eq!(accounts.len(), 64);
    assert!(
        accounts
            .iter()
            .all(|account| account.checkpoint == Some(u64::from(account.account_id)))
    );
}

#[tokio::test]
async fn failed_job_does_not_affect_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let bad = state.call(|conn| {
        conn.execute("INSERT INTO meta (key, value) VALUES ('x', 'y')", [])?;
        conn.execute("INSERT INTO no_such_table VALUES (1)", [])?;
        Ok(())
    });
    let good = state.set_meta(MetaKey::CreatedAt, "1".into());
    let (bad, good) = tokio::join!(bad, good);
    assert!(bad.is_err());
    assert!(good.is_ok());
    let leaked = state
        .call(|conn| {
            conn.query_row("SELECT COUNT(*) FROM meta WHERE key = 'x'", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(Error::from)
        })
        .await
        .expect("count");
    assert_eq!(leaked, 0);
    assert_eq!(state.meta(MetaKey::CreatedAt).await, Ok(Some("1".into())));
}

#[tokio::test]
async fn singleton_registry_keys_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let mut singleton = registry_update("x:Http", 0, "{}", RegistryStatus::Ok);
    singleton.key = RegistryKey::singleton("x:Http");
    state.put_registry(1, vec![singleton]).await.expect("put");
    let states = state
        .registry_states("x:Http".into())
        .await
        .expect("states");
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].key, RegistryKey::singleton("x:Http"));
    assert!(
        state
            .registry_source_json(RegistryKey::singleton("x:Http"))
            .await
            .expect("json")
            .is_some()
    );
}

#[tokio::test]
async fn read_only_open_does_not_block_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        SqliteState::open_read_only(dir.path()),
        Err(Error::Missing(_))
    ));
    let writer = SqliteState::open_exclusive(dir.path()).expect("writer");
    writer
        .add_reports(vec![report(1, Severity::Error, "failed", Some(1))])
        .await
        .expect("reports");
    let reader = SqliteState::open_read_only(dir.path()).expect("reader");
    assert_eq!(
        reader
            .reports(ReportFilter::default())
            .await
            .expect("read")
            .len(),
        1
    );
    assert!(
        reader
            .set_meta(MetaKey::CreatedAt, "1".into())
            .await
            .is_err()
    );
    writer
        .set_meta(MetaKey::CreatedAt, "2".into())
        .await
        .expect("writer not blocked");
    assert_eq!(reader.meta(MetaKey::CreatedAt).await, Ok(Some("2".into())));
}

#[tokio::test]
async fn savepoint_failure_fails_the_whole_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let release_breaker = state.call(|conn| {
        conn.execute_batch("RELEASE job")?;
        Ok(())
    });
    let other = state.set_meta(MetaKey::CreatedAt, "1".into());
    let (breaker, other) = tokio::join!(release_breaker, other);
    assert!(breaker.is_err());
    drop(other);
    let after = state.set_meta(MetaKey::Edition, "x".into()).await;
    assert!(after.is_ok());
}

#[tokio::test]
async fn new_state_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().expect("tempdir");
    let dir = parent.path().join("state");
    drop(SqliteState::open_exclusive(&dir).expect("open"));
    let mode = |path: &std::path::Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(super::STATE_FILE)), 0o600);
}

#[tokio::test]
async fn read_only_open_works_in_read_only_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let state = SqliteState::open(dir.path()).expect("open");
        state
            .set_meta(MetaKey::Edition, "enterprise".into())
            .await
            .expect("meta");
    }
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let result = SqliteState::open_read_only(dir.path());
    let meta = match &result {
        Ok(state) => state.meta(MetaKey::Edition).await,
        Err(err) => Err(err.clone()),
    };
    drop(result);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert_eq!(meta, Ok(Some("enterprise".into())));
}

#[tokio::test]
async fn development_schema_versions_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(SqliteState::open(dir.path()).expect("open"));
    {
        let conn = rusqlite::Connection::open(dir.path().join(super::STATE_FILE)).expect("conn");
        conn.pragma_update(None, "user_version", 1)
            .expect("version");
    }
    assert!(matches!(
        SqliteState::open(dir.path()),
        Err(Error::Corrupt(_))
    ));
}

#[tokio::test]
async fn unversioned_database_with_tables_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let conn = rusqlite::Connection::open(dir.path().join(super::STATE_FILE)).expect("conn");
        conn.execute_batch("CREATE TABLE other (x INTEGER);")
            .expect("table");
    }
    assert!(matches!(
        SqliteState::open(dir.path()),
        Err(Error::Corrupt(_))
    ));
}

// A failed write keeps the hash of the last version written, so the history shows the object reached the target; a drop clears it.
#[tokio::test]
async fn failed_registry_writes_keep_the_last_stored_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let stored = |status| {
        let mut update = registry_update("x:Domain", 4, "{}", status);
        update.stored_hash = None;
        update
    };
    state
        .put_registry(
            1,
            vec![registry_update("x:Domain", 4, "{}", RegistryStatus::Ok)],
        )
        .await
        .expect("ok row");
    state
        .put_registry(2, vec![stored(RegistryStatus::Error)])
        .await
        .expect("error row");
    let rows = state
        .registry_states("x:Domain".into())
        .await
        .expect("rows");
    assert_eq!(rows[0].status, RegistryStatus::Error);
    assert_eq!(rows[0].stored_hash, Some(ContentHash::of(b"stored")));
    state
        .put_registry(3, vec![stored(RegistryStatus::Dropped)])
        .await
        .expect("dropped row");
    let rows = state
        .registry_states("x:Domain".into())
        .await
        .expect("rows");
    assert_eq!(rows[0].stored_hash, None);
    state
        .put_registry(4, vec![stored(RegistryStatus::Error)])
        .await
        .expect("error row");
    let rows = state
        .registry_states("x:Domain".into())
        .await
        .expect("rows");
    assert_eq!(rows[0].stored_hash, None);
}

// Fallback rows are cleared by a later original write and by removing the registry object.
#[tokio::test]
async fn registry_fallbacks_are_cleared() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    let first = RegistryKey::new("x:Domain", 1);
    let second = RegistryKey::new("x:Domain", 2);
    let singleton = RegistryKey::singleton("x:SystemSettings");
    state
        .set_registry_fallbacks(
            vec![first.clone(), second.clone(), singleton.clone()],
            Vec::new(),
        )
        .await
        .expect("record");
    let sorted = |mut keys: Vec<RegistryKey>| {
        keys.sort();
        keys
    };
    state
        .set_registry_fallbacks(Vec::new(), vec![first.clone()])
        .await
        .expect("clear");
    assert_eq!(
        sorted(state.registry_fallbacks().await.expect("list")),
        sorted(vec![second.clone(), singleton.clone()])
    );
    state
        .remove_registry(vec![second, singleton])
        .await
        .expect("remove");
    assert!(state.registry_fallbacks().await.expect("list").is_empty());
}

// Registry objects a pass is writing or deleting are left out of the identity sample until the pass records them, and come back once cleared.
#[tokio::test]
async fn pending_registry_objects_are_not_sampled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    state
        .put_registry(
            1,
            (1..=3)
                .map(|id| registry_update("x:Domain", id, "{}", RegistryStatus::Ok))
                .collect(),
        )
        .await
        .expect("put");
    let sampled = |sample: Vec<RegistryState>| {
        let mut ids: Vec<RegistryId> = sample.into_iter().map(|state| state.key.id).collect();
        ids.sort();
        ids
    };
    let pending = vec![
        RegistryKey::new("x:Domain", 1),
        RegistryKey::new("x:Domain", 3),
    ];
    state
        .set_registry_pending(pending.clone(), Vec::new())
        .await
        .expect("mark");
    assert_eq!(
        sampled(state.registry_sample(10).await.expect("sample")),
        [RegistryId::Id(2)]
    );
    state
        .set_registry_pending(Vec::new(), pending)
        .await
        .expect("clear");
    assert_eq!(
        sampled(state.registry_sample(10).await.expect("sample")),
        [RegistryId::Id(1), RegistryId::Id(2), RegistryId::Id(3)]
    );
}

// The pending cursor only rises, so a resumed run never shrinks the range the exists filter covers.
#[tokio::test]
async fn pending_cursor_never_moves_backwards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = SqliteState::open(dir.path()).expect("open");
    for (mode, last_id) in [
        (CursorMode::Pending, 25),
        (CursorMode::Pending, 13),
        (CursorMode::Full, 25),
        (CursorMode::Full, 13),
    ] {
        state.set_cursor(1, 0, mode, last_id).await.expect("set");
    }
    let cursors = state.cursors(1).await.expect("cursors");
    let last = |mode| {
        cursors
            .iter()
            .find(|cursor| cursor.mode == mode)
            .map(|cursor| cursor.last_id)
    };
    assert_eq!(last(CursorMode::Pending), Some(25));
    assert_eq!(last(CursorMode::Full), Some(13));
}
