/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::{path::Path, time::Duration};

use common::manager::SPAM_TRAINER_KEY;
use model::{
    AccountPointers, ChangeLogRecord, Collection, Counters, Edition, LogCollection, LogEntry,
    LogRange, RecordBatch, RegistryRecord, Severity, ShareNotificationRecord, Source, Target,
    TargetProbe, WriteMode,
};
use model::{SpamModelChange, SpamModelKind};
use registry::schema::enums::CompressionAlgo;
use serde_json::json;
use source_v016::{SourceConfig, V016Source, testkit};
use target_v016::{SharedDeletes, SharedService, TargetConfig, V016Target};
use types::{blob_hash::BlobHash as AppBlobHash, id::Id};

const ACCOUNT: u32 = testkit::ACCOUNT;
const PAGE: usize = 1000;
const ORDER: [Collection; 11] = [
    Collection::Mailbox,
    Collection::Calendar,
    Collection::AddressBook,
    Collection::FileNode,
    Collection::Identity,
    Collection::SieveScript,
    Collection::Email,
    Collection::EmailSubmission,
    Collection::CalendarEvent,
    Collection::CalendarEventNotification,
    Collection::ContactCard,
];

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;

struct Snapshot {
    registry: Vec<RegistryRecord>,
    batches: Vec<RecordBatch>,
    pointers: AccountPointers,
    counters: Counters,
    changelog: Vec<ChangeLogRecord>,
    shares: Vec<ShareNotificationRecord>,
}

async fn source(path: &Path) -> V016Source {
    let mut config = SourceConfig::new(testkit::rocks(path));
    config.refresh_interval = Duration::ZERO;
    V016Source::open(config).await.expect("open source")
}

async fn target(dir: &Path, shared_deletes: SharedDeletes) -> V016Target {
    let config = dir.join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": dir.join("data").to_string_lossy()}).to_string(),
    )
    .expect("write config");
    V016Target::open(TargetConfig {
        data_store: config,
        shared_deletes,
    })
    .await
    .expect("open target")
}

async fn snapshot(source: &V016Source) -> Snapshot {
    let mut registry = Vec::new();
    for name in source.registry_types().await.expect("types") {
        registry.extend(
            source
                .registry_page(&name, None, PAGE)
                .await
                .expect("registry page")
                .records,
        );
    }
    let mut batches = Vec::new();
    for collection in ORDER {
        let page = source
            .scan(ACCOUNT, collection, None, PAGE)
            .await
            .expect("scan");
        assert!(page.issues.is_empty(), "{:?}", page.issues);
        batches.push(page.batch);
    }
    let mut changelog = Vec::new();
    for collection in LogCollection::CHANGES {
        changelog.extend(
            source
                .changelog(
                    ACCOUNT,
                    collection,
                    LogRange {
                        after: 0,
                        up_to: u64::MAX,
                    },
                    PAGE,
                )
                .await
                .expect("changelog"),
        );
    }
    Snapshot {
        registry,
        batches,
        pointers: source.pointers(ACCOUNT).await.expect("pointers"),
        counters: source.counters(ACCOUNT).await.expect("counters"),
        changelog,
        shares: source
            .share_notifications(ACCOUNT, None, PAGE)
            .await
            .expect("shares"),
    }
}

async fn copy(source: &V016Source, snapshot: &Snapshot, target: &V016Target) {
    let mut pending = snapshot.registry.clone();
    for _ in 0..3 {
        let outcome = target.write_registry(&pending).await.expect("registry");
        let failed = outcome
            .issues
            .iter()
            .filter_map(|issue| match &issue.subject {
                model::Subject::Registry(key) => Some(key.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        pending.retain(|record| failed.contains(&record.key));
    }
    assert!(
        pending.is_empty(),
        "registry objects not written: {pending:?}"
    );
    target
        .raise_registry_counters(&source.registry_id_counters().await.expect("id counters"))
        .await
        .expect("id counters");
    target.start_server().await.expect("boot");
    for batch in &snapshot.batches {
        let mut blobs = Vec::new();
        batch.collect_blobs(&mut blobs);
        for (hash, _) in blobs {
            let data = source
                .read_blob(&hash)
                .await
                .expect("read blob")
                .expect("blob present");
            target.put_blob(&hash, data).await.expect("put blob");
        }
        let outcome = target
            .upsert(ACCOUNT, batch, WriteMode::Create)
            .await
            .expect("upsert");
        assert!(
            outcome
                .issues
                .iter()
                .all(|issue| issue.severity == Severity::Warning
                    && batch.collection() == Collection::SieveScript),
            "{:?}",
            outcome.issues
        );
    }
    target
        .write_pointers(ACCOUNT, &snapshot.pointers)
        .await
        .expect("pointers");
    target
        .write_changelog(ACCOUNT, &snapshot.changelog)
        .await
        .expect("changelog");
    target
        .write_share_notifications(ACCOUNT, &snapshot.shares)
        .await
        .expect("shares");
    target
        .raise_counters(ACCOUNT, &snapshot.counters)
        .await
        .expect("counters");
}

fn without_sieve_blobs(mut batches: Vec<RecordBatch>) -> Vec<RecordBatch> {
    for batch in &mut batches {
        if let RecordBatch::SieveScript(scripts) = batch {
            for script in scripts {
                script.blob_hash = model::BlobHash::default();
            }
        }
    }
    batches
}

// A v0.16 store copied record by record through the rollback writer reads back identically.
#[tokio::test(flavor = "multi_thread")]
async fn v016_store_round_trips() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;
    let empty = expected
        .batches
        .iter()
        .filter(|batch| batch.is_empty())
        .map(RecordBatch::collection)
        .collect::<Vec<_>>();
    assert_eq!(empty, [Collection::CalendarEventNotification]);

    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    assert_eq!(rollback.probe().await.expect("probe"), TargetProbe::Empty);
    rollback.prepare_store(EDITION).await.expect("prepare");
    assert!(matches!(
        rollback.probe().await.expect("probe"),
        TargetProbe::Initialized { schema_version: 6 }
    ));
    copy(&original, &expected, &rollback).await;
    let exists = rollback
        .exists(ACCOUNT, Collection::Email, &[0, 1, 2])
        .await
        .expect("exists");
    assert_eq!(exists.iter().collect::<Vec<_>>(), [0]);
    drop(rollback);

    let copied = source(&target_dir.path().join("data")).await;
    let actual = snapshot(&copied).await;
    assert_eq!(actual.registry, expected.registry);
    assert_eq!(
        without_sieve_blobs(actual.batches),
        without_sieve_blobs(expected.batches)
    );
    assert_eq!(actual.pointers, expected.pointers);
    assert_eq!(actual.counters, expected.counters);
    assert_eq!(actual.changelog, expected.changelog);
    assert_eq!(actual.shares, expected.shares);
    drop(copied);

    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.start_server().await.expect("boot");
    rollback
        .finalize_account(ACCOUNT, &expected.counters)
        .await
        .expect("finalize");
    drop(rollback);
    let copied = source(&target_dir.path().join("data")).await;
    let counters = copied.counters(ACCOUNT).await.expect("counters");
    assert_eq!(counters.change_id, expected.counters.change_id + 1);
    let rows = copied
        .changelog(
            ACCOUNT,
            LogCollection::Calendar,
            LogRange {
                after: expected.counters.change_id,
                up_to: u64::MAX,
            },
            PAGE,
        )
        .await
        .expect("changelog");
    let [row] = rows.as_slice() else {
        panic!("one synthetic calendar row expected: {rows:?}");
    };
    let LogEntry::Changes(changes) = &row.entry else {
        panic!("changes row expected");
    };
    assert_eq!(changes.updated_items, [0]);
    assert_eq!(changes.updated_containers, [0]);
}

// Reopening a finalized account removes the finalize rows above each copied log cursor and keeps every copied row; a second reopen with nothing above the cursors changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn reopen_removes_only_the_finalize_rows() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;
    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    copy(&original, &expected, &rollback).await;
    rollback.start_server().await.expect("boot");
    rollback
        .finalize_account(ACCOUNT, &expected.counters)
        .await
        .expect("finalize");
    let mut copied: Vec<(LogCollection, u64)> = Vec::new();
    for row in &expected.changelog {
        match copied.iter_mut().find(|(log, _)| *log == row.collection) {
            Some((_, last)) => *last = (*last).max(row.change_id),
            None => copied.push((row.collection, row.change_id)),
        }
    }
    for _ in 0..2 {
        rollback
            .reopen_account(ACCOUNT, &copied)
            .await
            .expect("reopen");
    }
    drop(rollback);
    let reader = source(&target_dir.path().join("data")).await;
    let mut rows = Vec::new();
    for log in LogCollection::CHANGES {
        rows.extend(
            reader
                .changelog(
                    ACCOUNT,
                    log,
                    LogRange {
                        after: 0,
                        up_to: u64::MAX,
                    },
                    PAGE,
                )
                .await
                .expect("changelog"),
        );
    }
    let key = |row: &ChangeLogRecord| (row.collection.as_u8(), row.change_id);
    rows.sort_by_key(key);
    let mut expected_rows = expected.changelog.clone();
    expected_rows.sort_by_key(key);
    assert_eq!(rows, expected_rows);
}

// Wiping an account removes its documents, logs and counters but keeps the store usable for a recopy.
#[tokio::test(flavor = "multi_thread")]
async fn wipe_then_recopy() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;

    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    copy(&original, &expected, &rollback).await;
    rollback.wipe_account(ACCOUNT).await.expect("wipe");
    for collection in ORDER {
        let page = V016Target::exists(&rollback, ACCOUNT, collection, &[0, 1, 2, 3])
            .await
            .expect("exists");
        assert!(page.is_empty(), "{collection} survived the wipe");
    }
    for batch in &expected.batches {
        rollback
            .upsert(ACCOUNT, batch, WriteMode::Create)
            .await
            .expect("recopy");
    }
    rollback
        .write_pointers(ACCOUNT, &expected.pointers)
        .await
        .expect("pointers");
    rollback
        .write_changelog(ACCOUNT, &expected.changelog)
        .await
        .expect("changelog");
    rollback
        .write_share_notifications(ACCOUNT, &expected.shares)
        .await
        .expect("shares");
    rollback
        .raise_counters(ACCOUNT, &expected.counters)
        .await
        .expect("counters");
    drop(rollback);
    let copied = source(&target_dir.path().join("data")).await;
    let actual = snapshot(&copied).await;
    assert_eq!(
        without_sieve_blobs(actual.batches),
        without_sieve_blobs(expected.batches)
    );
    assert_eq!(actual.counters, expected.counters);
    assert_eq!(actual.changelog, expected.changelog);
}

// Replacing existing documents rewrites them in place with the same result as a fresh copy.
#[tokio::test(flavor = "multi_thread")]
async fn replace_and_update_are_idempotent() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;

    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    copy(&original, &expected, &rollback).await;
    for mode in [WriteMode::Replace, WriteMode::Update] {
        for batch in &expected.batches {
            rollback
                .upsert(ACCOUNT, batch, mode)
                .await
                .expect("rewrite");
        }
    }
    drop(rollback);
    let copied = source(&target_dir.path().join("data")).await;
    let actual = snapshot(&copied).await;
    assert_eq!(
        without_sieve_blobs(actual.batches),
        without_sieve_blobs(expected.batches)
    );
}

// An existing store without the rollback marker is refused before any write, so its files stay unchanged; deletes remove documents.
#[tokio::test(flavor = "multi_thread")]
async fn probe_foreign_and_delete() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;
    drop(original);
    let config_dir = tempfile::tempdir().expect("tempdir");
    let config = config_dir.path().join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": source_dir.path().to_string_lossy()}).to_string(),
    )
    .expect("write config");
    let files = store_files(source_dir.path());
    assert!(
        V016Target::open(TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .is_err()
    );
    assert_eq!(store_files(source_dir.path()), files);

    let original = source(source_dir.path()).await;
    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    copy(&original, &expected, &rollback).await;
    for collection in ORDER {
        rollback
            .delete(ACCOUNT, collection, &[0, 1, 2, 3])
            .await
            .expect("delete");
        assert!(
            rollback
                .exists(ACCOUNT, collection, &[0, 1, 2, 3])
                .await
                .expect("exists")
                .is_empty(),
            "{collection} survived the delete"
        );
    }
}

// An external search store is reported as a shared deletion and is not contacted when deletes are forbidden.
#[tokio::test(flavor = "multi_thread")]
async fn external_search_store_is_shared() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;

    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    assert!(
        rollback
            .shared_deletions(ACCOUNT)
            .await
            .expect("shared")
            .is_empty()
    );
    let outcome = rollback
        .write_registry(&[RegistryRecord {
            key: model::RegistryKey::singleton("SearchStore"),
            json: json!({"@type": "ElasticSearch", "url": "http://127.0.0.1:9"}),
        }])
        .await
        .expect("search store");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let shared = rollback.shared_deletions(ACCOUNT).await.expect("shared");
    let [deletion] = shared.as_slice() else {
        panic!("one shared deletion expected: {shared:?}");
    };
    assert_eq!(deletion.service, SharedService::SearchIndex);
    assert_eq!(deletion.account_id, ACCOUNT);
    copy(&original, &expected, &rollback).await;
    tokio::time::timeout(Duration::from_secs(20), rollback.wipe_account(ACCOUNT))
        .await
        .expect("wipe does not contact the external search store")
        .expect("wipe");
}

// Every v0.16 registry object type read by the source is written back unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn every_registry_type_round_trips() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let seeded = testkit::seed_every_registry_type(source_dir.path(), &[]).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;
    assert!(expected.registry.len() > seeded.len());

    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let mut failed = Vec::new();
    let mut written = Vec::new();
    for record in &expected.registry {
        let outcome = rollback
            .write_registry(std::slice::from_ref(record))
            .await
            .expect("registry");
        match outcome.issues.first() {
            None => written.push(record),
            Some(issue) if issue.message.starts_with("rejected by v0.16") => {}
            Some(issue) => failed.push(format!("{}: {}", record.key, issue.message)),
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
    assert!(written.len() > 10, "{}", written.len());
    let keys = written
        .iter()
        .map(|record| record.key.clone())
        .collect::<Vec<_>>();
    let read = rollback.read_registry(&keys).await.expect("read");
    for (record, read) in written.iter().zip(read) {
        assert_eq!(read.as_ref(), Some(*record), "{}", record.key);
    }
}

const SCRIPT: &[u8] = b"require \"fileinto\";\r\nfileinto \"Junk\";\r\n";
const ALARM_EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:alarm-1\r\nDTSTART:20991231T100000Z\r\nSUMMARY:Later\r\nBEGIN:VALARM\r\nACTION:EMAIL\r\nTRIGGER:-PT15M\r\nSUMMARY:Reminder\r\nDESCRIPTION:Reminder\r\nATTENDEE:mailto:jane@example.org\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

async fn alarm_tasks(target: &V016Target) -> usize {
    tasks_of(
        target,
        registry::schema::enums::TaskType::CalendarAlarmEmail,
    )
    .await
}

async fn tasks_of(target: &V016Target, task_type: registry::schema::enums::TaskType) -> usize {
    use registry::types::EnumImpl;
    use store::SerializeInfallible;
    let alarm = task_type.to_id().serialize();
    let mut rows = 0;
    target
        .store()
        .iterate(
            store::IterateParams::new(
                store::write::AnyKey {
                    subspace: store::SUBSPACE_TASK_QUEUE,
                    key: vec![0u8],
                },
                store::write::AnyKey {
                    subspace: store::SUBSPACE_TASK_QUEUE,
                    key: vec![u8::MAX; 32],
                },
            ),
            |_, value| {
                if value == alarm.as_slice() {
                    rows += 1;
                }
                Ok(true)
            },
        )
        .await
        .expect("scan");
    rows
}

// Sieve scripts are stored as raw source followed by the compiled v0.16 form, and event alarm tasks follow replaces and deletes.
#[tokio::test(flavor = "multi_thread")]
async fn sieve_and_event_alarms() {
    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;

    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    copy(&original, &expected, &rollback).await;

    let hash = model::BlobHash(*store::blake3::hash(SCRIPT).as_bytes());
    rollback
        .put_blob(&hash, bytes::Bytes::from_static(SCRIPT))
        .await
        .expect("script blob");
    let script = model::SieveRecord {
        document_id: 5,
        name: "junk".into(),
        blob_hash: hash,
        size: SCRIPT.len() as u32,
        vacation: None,
    };
    let outcome = rollback
        .upsert(ACCOUNT, &RecordBatch::from(vec![script]), WriteMode::Create)
        .await
        .expect("sieve");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let RecordBatch::SieveScript(stored) =
        scan_store(&target_dir.path().join("data"), Collection::SieveScript).await
    else {
        panic!("sieve batch");
    };
    let stored = stored
        .iter()
        .find(|script| script.document_id == 5)
        .expect("stored script");
    assert_eq!(stored.size as usize, SCRIPT.len());
    let blob = rollback
        .server()
        .expect("server")
        .blob_store()
        .get_blob(stored.blob_hash.as_bytes(), 0..usize::MAX)
        .await
        .expect("read")
        .expect("present");
    assert!(blob.starts_with(SCRIPT) && blob.len() > SCRIPT.len());

    assert_eq!(alarm_tasks(&rollback).await, 0);
    let event = model::CalendarEventRecord {
        document_id: 9,
        names: vec![model::DavNameRecord {
            name: "alarm.ics".into(),
            parent_id: 0,
        }],
        icalendar: ALARM_EVENT.into(),
        size: ALARM_EVENT.len() as u32,
        ..Default::default()
    };
    let batch = RecordBatch::from(vec![event]);
    rollback
        .upsert(ACCOUNT, &batch, WriteMode::Create)
        .await
        .expect("event");
    assert_eq!(alarm_tasks(&rollback).await, 1);
    rollback
        .upsert(ACCOUNT, &batch, WriteMode::Replace)
        .await
        .expect("replace");
    assert_eq!(alarm_tasks(&rollback).await, 1);
    rollback
        .delete(ACCOUNT, Collection::CalendarEvent, &[9])
        .await
        .expect("delete");
    assert_eq!(alarm_tasks(&rollback).await, 0);
}

async fn scan_store(path: &Path, collection: Collection) -> RecordBatch {
    source(path)
        .await
        .scan(ACCOUNT, collection, None, PAGE)
        .await
        .expect("scan")
        .batch
}

fn spam_model() -> Vec<model::SpamModelRecord> {
    use model::{
        BlobHash, Ftrl, FtrlWeight, SampleReservoir, SpamClassifierModel, SpamModelRecord,
        SpamOptimizer, SpamTrainerModel, TrainingSample,
    };
    let ftrl = |z: f32| Ftrl {
        alpha: 0.1,
        beta: 1.0,
        l1_ratio: 0.001,
        l2_ratio: 0.0001,
        zn: vec![FtrlWeight { z, n: 2.0 }; 3],
        zn_bias: FtrlWeight { z: -z, n: 1.0 },
    };
    vec![
        SpamModelRecord::Trainer(Box::new(SpamTrainerModel {
            optimizer: SpamOptimizer::Ccfh {
                weights: ftrl(0.5),
                indicators: ftrl(0.25),
            },
            spam: SampleReservoir {
                samples: vec![TrainingSample {
                    blob_hash: BlobHash([7; 32]),
                    account_id: 3,
                }],
                total_seen: 4,
            },
            ham: SampleReservoir::default(),
            last_id: 12,
        })),
        SpamModelRecord::Classifier(SpamClassifierModel::Ccfh {
            parameters: vec![0.5, -1.0],
            indicators: vec![0.25, 0.75],
            bias: 0.1,
            last_trained_at: 1_700_000_000,
        }),
    ]
}

async fn spam_page(dir: &Path) -> Vec<model::SpamModelRecord> {
    use model::{GlobalBatch, GlobalCategory};

    let source = source(&dir.join("data")).await;
    let page = source
        .global_page(GlobalCategory::SpamModel, None, 10)
        .await
        .expect("page");
    assert!(page.issues.is_empty(), "{:?}", page.issues);
    let GlobalBatch::SpamModel(mut read) = page.batch else {
        panic!("not a spam page");
    };
    read.sort_by_key(|record| record.as_str());
    read
}

fn spam_writes(records: &[model::SpamModelRecord]) -> Vec<SpamModelChange> {
    records
        .iter()
        .cloned()
        .map(SpamModelChange::Write)
        .collect()
}

async fn shared_blob_rollback(dir: &Path, shared_deletes: SharedDeletes) -> V016Target {
    let rollback = target(dir, shared_deletes).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let outcome = rollback
        .write_registry(&[RegistryRecord {
            key: model::RegistryKey::singleton("BlobStore"),
            json: json!({"@type": "FileSystem", "path": dir.join("blobs").to_string_lossy()}),
        }])
        .await
        .expect("blob store");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    rollback.start_server().await.expect("boot");
    rollback
}

fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .flat_map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                files_under(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

// The spam model is written in the v0.16 layout only by the final step, which deletes a kind the source no longer has.
#[tokio::test(flavor = "multi_thread")]
async fn spam_model_round_trip() {
    use model::GlobalBatch;

    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    rollback.start_server().await.expect("boot");
    let mut records = spam_model();
    records.sort_by_key(|record| record.as_str());
    let outcome = rollback
        .write_global(&GlobalBatch::SpamModel(records.clone()))
        .await
        .expect("global spam");
    assert_eq!(outcome.issues.len(), 2, "{:?}", outcome.issues);
    for _ in 0..2 {
        let outcome = rollback
            .apply_final_spam_model(&spam_writes(&records))
            .await
            .expect("spam");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    drop(rollback);
    assert_eq!(spam_page(dir.path()).await, records);

    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.start_server().await.expect("boot");
    let outcome = rollback
        .apply_final_spam_model(&[
            SpamModelChange::Write(records[0].clone()),
            SpamModelChange::Delete(SpamModelKind::Trainer),
        ])
        .await
        .expect("reset");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let blob_store = rollback.server().expect("server").blob_store().clone();
    let foreign = b"not a spam trainer".to_vec();
    blob_store
        .put_blob(SPAM_TRAINER_KEY, &foreign, Default::default())
        .await
        .expect("foreign trainer");
    for changes in [vec![SpamModelChange::Write(records[0].clone())], Vec::new()] {
        let outcome = rollback
            .apply_final_spam_model(&changes)
            .await
            .expect("classifier only");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        assert_eq!(
            blob_store
                .get_blob(SPAM_TRAINER_KEY, 0..usize::MAX)
                .await
                .expect("read trainer"),
            Some(foreign.clone())
        );
    }
    blob_store
        .delete_blob(SPAM_TRAINER_KEY)
        .await
        .expect("drop foreign trainer");
    drop(rollback);
    assert_eq!(spam_page(dir.path()).await, records[..1]);
}

// In a blob store that may be shared with v1, only the final step with --allow-shared-deletes changes the spam model keys; without it nothing is written or deleted.
#[tokio::test(flavor = "multi_thread")]
async fn shared_spam_model_needs_allow_and_final_step() {
    use model::{GlobalBatch, IssueKind};

    let records = spam_model();
    let shared = tempfile::tempdir().expect("tempdir");
    let blobs = shared.path().join("blobs");
    let rollback = shared_blob_rollback(shared.path(), SharedDeletes::Allow).await;
    let outcome = rollback
        .write_global(&GlobalBatch::SpamModel(records.clone()))
        .await
        .expect("global spam");
    assert_eq!(outcome.issues.len(), 2, "{:?}", outcome.issues);
    assert_eq!(files_under(&blobs), Vec::<std::path::PathBuf>::new());
    let mut files = Vec::new();
    let mut written = Vec::new();
    for round in 0..2 {
        let outcome = rollback
            .apply_final_spam_model(&spam_writes(&records))
            .await
            .expect("final spam");
        assert_eq!(outcome.issues.len(), 2, "{:?}", outcome.issues);
        assert!(
            outcome
                .issues
                .iter()
                .all(|issue| issue.kind == IssueKind::Changed
                    && issue.severity == Severity::Info
                    && issue.explains.is_none())
        );
        files = files_under(&blobs);
        files.sort_unstable();
        assert_eq!(files.len(), 2, "{files:?}");
        let contents = files
            .iter()
            .map(|file| std::fs::read(file).expect("read"))
            .collect::<Vec<_>>();
        if round == 0 {
            for (file, data) in files.iter().zip(&contents) {
                std::fs::write(file, vec![0xA5; data.len()]).expect("stale model");
            }
            written = contents;
        } else {
            assert_eq!(contents, written, "a same-length stale model was kept");
        }
    }
    drop(rollback);

    let rollback = target(shared.path(), SharedDeletes::Forbid).await;
    rollback.start_server().await.expect("boot");
    let before = files
        .iter()
        .map(|file| std::fs::read(file).expect("read"))
        .collect::<Vec<_>>();
    for batch in [
        spam_writes(&records),
        SpamModelKind::ALL.map(SpamModelChange::Delete).to_vec(),
    ] {
        let outcome = rollback
            .apply_final_spam_model(&batch)
            .await
            .expect("forbidden spam");
        assert_eq!(outcome.issues.len(), 2, "{:?}", outcome.issues);
        assert!(
            outcome
                .issues
                .iter()
                .all(|issue| issue.kind == IssueKind::Skipped
                    && issue.explains == Some(model::Explanation::Missing))
        );
        let after = files
            .iter()
            .map(|file| std::fs::read(file).expect("unchanged"))
            .collect::<Vec<_>>();
        assert_eq!(after, before);
    }
}

// A store holding only the stock v0.16 schema marker is an existing v0.16 store: foreign, and prepare refuses it.
#[tokio::test(flavor = "multi_thread")]
async fn stock_schema_marker_is_foreign() {
    use store::write::{AnyClass, BatchBuilder, ValueClass};

    let dir = tempfile::tempdir().expect("tempdir");
    let stock = target(dir.path(), SharedDeletes::Forbid).await;
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: store::SUBSPACE_PROPERTY,
            key: vec![0],
        }),
        6u32.to_be_bytes().to_vec(),
    );
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock marker");
    assert_eq!(stock.probe().await.expect("probe"), TargetProbe::Foreign);
    assert!(stock.prepare_store(EDITION).await.is_err());
    drop(stock);
    assert!(
        V016Target::open(TargetConfig {
            data_store: dir.path().join("target.json"),
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .is_err()
    );

    let fresh = tempfile::tempdir().expect("tempdir");
    let rollback = target(fresh.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    rollback
        .prepare_store(EDITION)
        .await
        .expect("prepare again");
    assert_eq!(
        rollback.probe().await.expect("probe"),
        TargetProbe::Initialized { schema_version: 6 }
    );
}

// Deleting emails clears their metadata directly and queues no unindex task that a later v0.16 would run against a shared search index.
#[tokio::test(flavor = "multi_thread")]
async fn email_delete_queues_no_unindex() {
    use registry::schema::enums::TaskType;

    let source_dir = tempfile::tempdir().expect("tempdir");
    testkit::seed(source_dir.path()).await;
    let original = source(source_dir.path()).await;
    let expected = snapshot(&original).await;
    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    copy(&original, &expected, &rollback).await;
    let emails = V016Target::exists(&rollback, ACCOUNT, Collection::Email, &[0, 1, 2, 3])
        .await
        .expect("exists");
    assert!(!emails.is_empty());
    let before = tasks_of(&rollback, TaskType::UnindexDocument).await;
    rollback
        .delete(ACCOUNT, Collection::Email, &[0, 1, 2, 3])
        .await
        .expect("delete");
    assert!(
        V016Target::exists(&rollback, ACCOUNT, Collection::Email, &[0, 1, 2, 3])
            .await
            .expect("exists")
            .is_empty()
    );
    assert_eq!(tasks_of(&rollback, TaskType::UnindexDocument).await, before);
}

fn store_files(path: &Path) -> Vec<(std::ffi::OsString, u64, std::time::SystemTime)> {
    let mut files = std::fs::read_dir(path)
        .expect("read dir")
        .map(|entry| {
            let entry = entry.expect("entry");
            let metadata = entry.metadata().expect("metadata");
            (
                entry.file_name(),
                metadata.len(),
                metadata.modified().expect("modified"),
            )
        })
        .collect::<Vec<_>>();
    files.sort_unstable();
    files
}

// A target directory holding only lost+found (a volume root) is a new empty store, accepted without the read-only retries.
#[tokio::test(flavor = "multi_thread")]
async fn volume_root_with_lost_found_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("data").join("lost+found")).expect("lost+found");
    let started = std::time::Instant::now();
    let target = target(dir.path(), SharedDeletes::Forbid).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(target.probe().await.expect("probe"), TargetProbe::Empty);
}

// The shared-change plan comes from the settings rollback will write: external search and blob stores are listed, defaults are not.
#[tokio::test(flavor = "multi_thread")]
async fn shared_plan_from_settings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    assert!(
        rollback
            .planned_shared_changes(&[])
            .await
            .expect("empty plan")
            .is_empty()
    );
    let plan = rollback
        .planned_shared_changes(&[
            RegistryRecord {
                key: model::RegistryKey::singleton("SearchStore"),
                json: json!({"@type": "Meilisearch", "url": "http://127.0.0.1:1"}),
            },
            RegistryRecord {
                key: model::RegistryKey::singleton("BlobStore"),
                json: json!({"@type": "FileSystem", "path": dir.path().join("blobs").to_string_lossy()}),
            },
        ])
        .await
        .expect("plan");
    assert_eq!(plan.deletions.len(), 1, "{plan:?}");
    assert_eq!(plan.deletions[0].service, SharedService::SearchIndex);
    assert_eq!(plan.overwrites.len(), 1, "{plan:?}");
    assert_eq!(plan.overwrites[0].service, SharedService::BlobStore);
    let plan = rollback
        .planned_shared_changes(&[RegistryRecord {
            key: model::RegistryKey::singleton("BlobStore"),
            json: json!({"@type": "Default"}),
        }])
        .await
        .expect("default plan");
    assert!(plan.is_empty(), "{plan:?}");
}

// Retaining share notifications deletes only the listed account's notifications missing from the keep list.
#[tokio::test(flavor = "multi_thread")]
async fn retain_share_notifications_deletes_only_stale() {
    let target_dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(target_dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let notifications = |ids: &[u64]| {
        ids.iter()
            .map(|id| ShareNotificationRecord {
                id: *id,
                payload: vec![1, 2, 3, 4].into(),
            })
            .collect::<Vec<_>>()
    };
    rollback
        .write_share_notifications(ACCOUNT, &notifications(&[1, 2, 3]))
        .await
        .expect("own");
    rollback
        .write_share_notifications(ACCOUNT + 1, &notifications(&[2]))
        .await
        .expect("other");
    for keep in [&[1, 3, 9][..], &[1, 3][..]] {
        rollback
            .retain_share_notifications(ACCOUNT, keep)
            .await
            .expect("retain");
    }
    drop(rollback);
    let copied = source(&target_dir.path().join("data")).await;
    for (account_id, expected) in [(ACCOUNT, vec![1, 3]), (ACCOUNT + 1, vec![2])] {
        let ids = copied
            .share_notifications(account_id, None, PAGE)
            .await
            .expect("shares")
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();
        assert_eq!(ids, expected, "account {account_id}");
    }
}

// A RocksDB rollback target directory holding only lost+found and dot entries is a new empty store.
#[tokio::test(flavor = "multi_thread")]
async fn rocksdb_dot_entries_are_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir_all(data.join("lost+found")).expect("lost+found");
    std::fs::write(data.join(".DS_Store"), b"finder").expect("dot file");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
}

async fn raw_rows(store: &store::Store) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    use store::{IterateParams, write::AnyKey};

    let mut rows = Vec::new();
    for subspace in b'a'..=b'z' {
        store
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: Vec::new(),
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; 64],
                    },
                ),
                |key, value| {
                    rows.push((subspace, key.to_vec(), value.to_vec()));
                    Ok(true)
                },
            )
            .await
            .expect("iterate");
    }
    rows
}

// An archived draft with an empty from is written with exactly the rows of the stock v0.16 archiver, read back, rewritten and deleted.
#[tokio::test(flavor = "multi_thread")]
async fn archived_draft_without_from_is_stored_like_stock() {
    use registry::{
        schema::{
            prelude::{Object, ObjectInner, ObjectType, Property},
            structs::{ArchivedEmail, ArchivedItem},
        },
        types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
    };
    use store::{
        SerializeInfallible,
        write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass},
    };
    use types::{blob::BlobId, blob_hash::BlobHash};

    const ITEM_ID: u64 = 0x0123_4567_89ab_cdef;
    const UNTIL: u64 = 1_924_992_000;
    let blob_hash = BlobHash(*store::blake3::hash(b"draft").as_bytes());
    let item = ArchivedItem::Email(ArchivedEmail {
        account_id: ACCOUNT.into(),
        blob_id: BlobId::new(blob_hash.clone(), Default::default()),
        archived_until: UTCDateTime::from_timestamp(UNTIL as i64),
        archived_at: UTCDateTime::from_timestamp(1_906_000_000),
        from: String::new(),
        received_at: UTCDateTime::from_timestamp(1_893_456_000),
        subject: String::new(),
        size: 5,
    });

    let stock_dir = tempfile::tempdir().expect("tempdir");
    let stock = target(stock_dir.path(), SharedDeletes::Forbid).await;
    stock.prepare_store(EDITION).await.expect("prepare");
    let object_id = ObjectType::ArchivedItem.to_id();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ACCOUNT)
        .set(
            BlobOp::Link {
                hash: blob_hash.clone(),
                to: BlobLink::Temporary { until: UNTIL },
            },
            ObjectId::new(ObjectType::ArchivedItem, ITEM_ID.into()).serialize(),
        )
        .set(
            ValueClass::Registry(RegistryClass::Index {
                index_id: Property::AccountId.to_id(),
                object_id,
                item_id: ITEM_ID,
                key: (ACCOUNT as u64).serialize(),
            }),
            vec![],
        )
        .set(
            ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: ITEM_ID,
            }),
            item.to_pickled_vec(),
        );
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock archive");
    let expected = raw_rows(stock.store()).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let empty = raw_rows(rollback.store()).await;
    let record = RegistryRecord {
        key: model::RegistryKey::new("ArchivedItem", ITEM_ID),
        json: serde_json::to_value(
            Object::new(ObjectInner::ArchivedItem(item)).into_value_with_secrets(),
        )
        .expect("json"),
    };
    assert_eq!(
        rollback.registry_blob(&record),
        Some(model::BlobHash(blob_hash.0))
    );
    for _ in 0..2 {
        let outcome = rollback
            .write_registry(std::slice::from_ref(&record))
            .await
            .expect("archived item");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        assert_eq!(raw_rows(rollback.store()).await, expected);
    }
    assert_eq!(
        rollback
            .read_registry(std::slice::from_ref(&record.key))
            .await
            .expect("read"),
        vec![Some(record.clone())]
    );
    rollback
        .delete_registry(std::slice::from_ref(&record.key))
        .await
        .expect("delete");
    assert_eq!(raw_rows(rollback.store()).await, empty);
}

// Registry write rejections carry their cause: a primary key conflict is Conflict, an object that does not parse or validate is Invalid.
#[tokio::test(flavor = "multi_thread")]
async fn registry_rejections_are_tagged() {
    use model::Rejection;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = {
        let target = target(dir.path(), SharedDeletes::Forbid).await;
        target.prepare_store(EDITION).await.expect("prepare");
        target
    };
    let domain = |id: u64, name: serde_json::Value| RegistryRecord {
        key: model::RegistryKey::new("Domain", id),
        json: serde_json::json!({"name": name}),
    };
    let outcome = target
        .write_registry(&[domain(20, "dup.example".into())])
        .await
        .expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    for (record, rejection) in [
        (domain(21, "dup.example".into()), Rejection::Conflict),
        (domain(22, 5.into()), Rejection::Invalid),
        (domain(23, "".into()), Rejection::Invalid),
    ] {
        let outcome = target
            .write_registry(std::slice::from_ref(&record))
            .await
            .expect("registry");
        assert_eq!(
            outcome
                .issues
                .iter()
                .map(|issue| issue.rejection)
                .collect::<Vec<_>>(),
            vec![Some(rejection)],
            "{}: {:?}",
            record.json,
            outcome.issues
        );
    }
}

// Spam training samples, with and without an account, are written with exactly the rows of the stock v0.16 writers (queue spool and ingest), read back, rewritten and deleted.
#[tokio::test(flavor = "multi_thread")]
async fn spam_samples_are_stored_like_stock() {
    use registry::{
        schema::{
            prelude::{Object, ObjectInner, ObjectType, Property},
            structs::SpamTrainingSample,
        },
        types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
    };
    use store::{
        SerializeInfallible,
        write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass},
    };
    use types::{blob::BlobId, blob_hash::BlobHash};

    const UNTIL: u64 = 1_924_992_000;
    let samples = [
        (0x0123_4567_89ab_0001u64, None, b"queued".as_slice()),
        (0x0123_4567_89ab_0002, Some(ACCOUNT), b"ingested".as_slice()),
    ]
    .map(|(item_id, account_id, body)| {
        let blob_hash = BlobHash(*store::blake3::hash(body).as_bytes());
        let sample = SpamTrainingSample {
            account_id: account_id.map(types::id::Id::from),
            blob_id: BlobId::new(blob_hash.clone(), Default::default()),
            delete_after_use: account_id.is_some(),
            expires_at: UTCDateTime::from_timestamp(UNTIL as i64),
            from: String::new(),
            is_spam: true,
            subject: "Offer".into(),
        };
        (item_id, account_id.unwrap_or(u32::MAX), blob_hash, sample)
    });

    let stock_dir = tempfile::tempdir().expect("tempdir");
    let stock = target(stock_dir.path(), SharedDeletes::Forbid).await;
    stock.prepare_store(EDITION).await.expect("prepare");
    let object_id = ObjectType::SpamTrainingSample.to_id();
    let mut batch = BatchBuilder::new();
    for (item_id, account_id, blob_hash, sample) in &samples {
        batch
            .with_account_id(*account_id)
            .set(
                BlobOp::Link {
                    hash: blob_hash.clone(),
                    to: BlobLink::Temporary { until: UNTIL },
                },
                ObjectId::new(ObjectType::SpamTrainingSample, (*item_id).into()).serialize(),
            )
            .set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id: *item_id,
                }),
                sample.to_pickled_vec(),
            )
            .set(
                ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id: *item_id,
                    key: (*account_id as u64).serialize(),
                }),
                vec![],
            );
    }
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock samples");
    let expected = raw_rows(stock.store()).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let empty = raw_rows(rollback.store()).await;
    let records = samples
        .iter()
        .map(|(item_id, _, _, sample)| RegistryRecord {
            key: model::RegistryKey::new("SpamTrainingSample", *item_id),
            json: serde_json::to_value(
                Object::new(ObjectInner::SpamTrainingSample(sample.clone()))
                    .into_value_with_secrets(),
            )
            .expect("json"),
        })
        .collect::<Vec<_>>();
    for (record, (_, _, blob_hash, _)) in records.iter().zip(&samples) {
        assert_eq!(
            rollback.registry_blob(record),
            Some(model::BlobHash(blob_hash.0))
        );
    }
    for _ in 0..2 {
        let outcome = rollback.write_registry(&records).await.expect("samples");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        assert_eq!(raw_rows(rollback.store()).await, expected);
    }
    let keys = records
        .iter()
        .map(|record| record.key.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        rollback.read_registry(&keys).await.expect("read"),
        records.iter().cloned().map(Some).collect::<Vec<_>>()
    );
    rollback.delete_registry(&keys).await.expect("delete");
    assert_eq!(raw_rows(rollback.store()).await, empty);
}

async fn stock_archive_rows(
    item_id: u64,
    item: &registry::schema::structs::ArchivedItem,
) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    use registry::{
        schema::prelude::{ObjectType, Property},
        types::{EnumImpl, ObjectImpl, id::ObjectId},
    };
    use store::{
        SerializeInfallible,
        write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass},
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let stock = target(dir.path(), SharedDeletes::Forbid).await;
    stock.prepare_store(EDITION).await.expect("prepare");
    let account_id = item.account_id().document_id();
    let object_id = ObjectType::ArchivedItem.to_id();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .set(
            BlobOp::Link {
                hash: item.blob_id().hash.clone(),
                to: BlobLink::Temporary {
                    until: item.archived_until().timestamp() as u64,
                },
            },
            ObjectId::new(ObjectType::ArchivedItem, item_id.into()).serialize(),
        )
        .set(
            ValueClass::Registry(RegistryClass::Index {
                index_id: Property::AccountId.to_id(),
                object_id,
                item_id,
                key: (account_id as u64).serialize(),
            }),
            vec![],
        )
        .set(
            ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
            item.to_pickled_vec(),
        );
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock archive");
    raw_rows(stock.store()).await
}

// Rewriting an archived item with another expiry or account moves its Temporary link and index row, also twice within one page: the store holds exactly the stock rows of the last version, with no stale link a purge could act on.
#[tokio::test(flavor = "multi_thread")]
async fn archived_item_rewrite_moves_link_like_stock() {
    use registry::{
        schema::{
            prelude::{Object, ObjectInner},
            structs::{ArchivedEmail, ArchivedItem},
        },
        types::datetime::UTCDateTime,
    };
    use types::{blob::BlobId, blob_hash::BlobHash};

    const ITEM_ID: u64 = 0x0123_4567_89ab_0101;
    let item = |account_id: u32, until: i64| {
        ArchivedItem::Email(ArchivedEmail {
            account_id: account_id.into(),
            blob_id: BlobId::new(
                BlobHash(*store::blake3::hash(b"moved").as_bytes()),
                Default::default(),
            ),
            archived_until: UTCDateTime::from_timestamp(until),
            archived_at: UTCDateTime::from_timestamp(1_906_000_000),
            from: "a@example.org".into(),
            received_at: UTCDateTime::from_timestamp(1_893_456_000),
            subject: "Moved".into(),
            size: 5,
        })
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    for version in [
        item(ACCOUNT, 1_924_992_000),
        item(ACCOUNT, 1_956_528_000),
        item(ACCOUNT + 1, 1_956_528_000),
    ] {
        let record = RegistryRecord {
            key: model::RegistryKey::new("ArchivedItem", ITEM_ID),
            json: serde_json::to_value(
                Object::new(ObjectInner::ArchivedItem(version.clone())).into_value_with_secrets(),
            )
            .expect("json"),
        };
        let outcome = rollback
            .write_registry(std::slice::from_ref(&record))
            .await
            .expect("archived item");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        assert_eq!(
            raw_rows(rollback.store()).await,
            stock_archive_rows(ITEM_ID, &version).await
        );
    }
    let page = [
        item(ACCOUNT, 1_924_992_000),
        item(ACCOUNT + 2, 1_988_064_000),
    ]
    .map(|version| RegistryRecord {
        key: model::RegistryKey::new("ArchivedItem", ITEM_ID),
        json: serde_json::to_value(
            Object::new(ObjectInner::ArchivedItem(version)).into_value_with_secrets(),
        )
        .expect("json"),
    });
    let outcome = rollback.write_registry(&page).await.expect("one page");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(
        raw_rows(rollback.store()).await,
        stock_archive_rows(ITEM_ID, &item(ACCOUNT + 2, 1_988_064_000)).await
    );
}

// External reports written by the rollback carry the stock v0.16 index rows, so the stock listing (ExpiresAt) finds them; rewrites and deletes keep the rows equal to the stock writer's.
#[tokio::test(flavor = "multi_thread")]
async fn external_reports_are_listed_like_stock() {
    use registry::{
        schema::{
            prelude::{Object, ObjectInner, ObjectType, Property},
            structs::{
                ArfExternalReport, DmarcExternalReport, DmarcReportRecord, TlsExternalReport,
                TlsReportPolicy,
            },
        },
        types::datetime::UTCDateTime,
    };
    use smtp::reporting::index::ExternalReportIndex;
    use store::{registry::RegistryQuery, write::BatchBuilder};
    use types::id::Id;

    const DMARC_ID: u64 = 0x41;
    const TLS_ID: u64 = 0x42;
    const ARF_ID: u64 = 0x43;
    let received_at = UTCDateTime::from_timestamp(1_893_456_000);
    let expires_at = UTCDateTime::from_timestamp(1_924_992_000);
    let mut dmarc = DmarcExternalReport {
        from: "dmarc@example.com".into(),
        subject: "DMARC report".into(),
        received_at,
        expires_at,
        ..Default::default()
    };
    dmarc.report.org_name = "Example".into();
    dmarc.report.report_id = "dmarc-1".into();
    dmarc.report.policy_domain = "example.org".into();
    dmarc.report.date_range_begin = UTCDateTime::from_timestamp(1_893_000_000);
    dmarc.report.date_range_end = UTCDateTime::from_timestamp(1_893_086_400);
    dmarc.member_tenant_id = Some(Id::new(3));
    dmarc.report.records.push(DmarcReportRecord {
        count: 7,
        header_from: "example.org".into(),
        envelope_from: "bounce.example.org".into(),
        ..Default::default()
    });
    let mut tls = TlsExternalReport {
        from: "tls@example.com".into(),
        subject: "TLS report".into(),
        received_at,
        expires_at,
        ..Default::default()
    };
    tls.report.organization_name = Some("Example".into());
    tls.report.report_id = "tls-1".into();
    tls.report.date_range_start = UTCDateTime::from_timestamp(1_893_000_000);
    tls.report.date_range_end = UTCDateTime::from_timestamp(1_893_086_400);
    tls.member_tenant_id = Some(Id::new(3));
    tls.report.policies.push(TlsReportPolicy {
        policy_domain: "example.org".into(),
        total_successful_sessions: 5,
        total_failed_sessions: 2,
        ..Default::default()
    });
    let mut arf = ArfExternalReport {
        from: "abuse@example.com".into(),
        subject: "Abuse report".into(),
        received_at,
        expires_at,
        member_tenant_id: Some(Id::new(3)),
        ..Default::default()
    };
    arf.report.incidents = 2;

    let stock_dir = tempfile::tempdir().expect("tempdir");
    let stock = target(stock_dir.path(), SharedDeletes::Forbid).await;
    stock.prepare_store(EDITION).await.expect("prepare");
    let mut batch = BatchBuilder::new();
    dmarc.write_ops(&mut batch, DMARC_ID, true);
    tls.write_ops(&mut batch, TLS_ID, true);
    arf.write_ops(&mut batch, ARF_ID, true);
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock reports");
    let expected = raw_rows(stock.store()).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let empty = raw_rows(rollback.store()).await;
    let record = |name: &str, id: u64, inner: ObjectInner| RegistryRecord {
        key: model::RegistryKey::new(name, id),
        json: serde_json::to_value(Object::new(inner).into_value_with_secrets()).expect("json"),
    };
    let records = [
        record(
            "x:DmarcExternalReport",
            DMARC_ID,
            ObjectInner::DmarcExternalReport(dmarc),
        ),
        record(
            "x:TlsExternalReport",
            TLS_ID,
            ObjectInner::TlsExternalReport(tls),
        ),
        record(
            "x:ArfExternalReport",
            ARF_ID,
            ObjectInner::ArfExternalReport(arf),
        ),
    ];
    for _ in 0..2 {
        let outcome = rollback
            .write_registry(&records)
            .await
            .expect("external reports");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        assert_eq!(raw_rows(rollback.store()).await, expected);
    }
    for (object_type, id) in [
        (ObjectType::DmarcExternalReport, DMARC_ID),
        (ObjectType::TlsExternalReport, TLS_ID),
        (ObjectType::ArfExternalReport, ARF_ID),
    ] {
        let listed = rollback
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(object_type).greater_than(Property::ExpiresAt, 0u64),
            )
            .await
            .expect("stock listing");
        assert_eq!(listed, vec![Id::new(id)], "{object_type:?}");
    }
    let duplicate = RegistryRecord {
        key: model::RegistryKey::new("x:DmarcExternalReport", DMARC_ID + 0x10),
        json: records[0].json.clone(),
    };
    let outcome = rollback
        .write_registry(std::slice::from_ref(&duplicate))
        .await
        .expect("duplicate report id");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert_eq!(
        outcome.issues[0].rejection,
        Some(model::Rejection::Conflict)
    );
    assert_eq!(raw_rows(rollback.store()).await, expected);
    let keys = records
        .iter()
        .map(|record| record.key.clone())
        .collect::<Vec<_>>();
    rollback.delete_registry(&keys).await.expect("delete");
    assert_eq!(raw_rows(rollback.store()).await, empty);
}

fn dmarc_with_id(report_id: &str) -> registry::schema::structs::DmarcExternalReport {
    use registry::types::datetime::UTCDateTime;

    let mut report = registry::schema::structs::DmarcExternalReport {
        from: "dmarc@example.com".into(),
        subject: format!("DMARC {report_id}"),
        received_at: UTCDateTime::from_timestamp(1_893_456_000),
        expires_at: UTCDateTime::from_timestamp(1_924_992_000),
        ..Default::default()
    };
    report.report.org_name = "Example".into();
    report.report.report_id = report_id.into();
    report.report.policy_domain = "example.org".into();
    report.report.date_range_begin = UTCDateTime::from_timestamp(1_893_000_000);
    report.report.date_range_end = UTCDateTime::from_timestamp(1_893_086_400);
    report
}

fn dmarc_record(id: u64, report_id: &str) -> RegistryRecord {
    use registry::schema::prelude::{Object, ObjectInner};

    RegistryRecord {
        key: model::RegistryKey::new("x:DmarcExternalReport", id),
        json: serde_json::to_value(
            Object::new(ObjectInner::DmarcExternalReport(dmarc_with_id(report_id)))
                .into_value_with_secrets(),
        )
        .expect("json"),
    }
}

async fn stock_dmarc_rows(reports: &[(u64, &str)]) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    use smtp::reporting::index::ExternalReportIndex;

    let dir = tempfile::tempdir().expect("tempdir");
    let stock = target(dir.path(), SharedDeletes::Forbid).await;
    stock.prepare_store(EDITION).await.expect("prepare");
    let mut batch = store::write::BatchBuilder::new();
    for (id, report_id) in reports {
        dmarc_with_id(report_id).write_ops(&mut batch, *id, true);
    }
    stock
        .store()
        .write(batch.build_all())
        .await
        .expect("stock reports");
    raw_rows(stock.store()).await
}

fn conflicts(outcome: &model::WriteOutcome) -> Vec<model::RegistryKey> {
    outcome
        .issues
        .iter()
        .filter(|issue| issue.rejection == Some(model::Rejection::Conflict))
        .filter_map(|issue| match &issue.subject {
            model::Subject::Registry(key) => Some(key.clone()),
            _ => None,
        })
        .collect()
}

// Report ids are tracked across one page: a duplicate is one Conflict, an id freed earlier in the page can be taken, a rejected record does not lose the item's pending version, and a primary key row left without its item is rewritten.
#[tokio::test(flavor = "multi_thread")]
async fn external_report_ids_within_a_page() {
    let key = |id: u64| model::RegistryKey::new("x:DmarcExternalReport", id);
    let write = async |target: &V016Target, records: &[RegistryRecord]| {
        target.write_registry(records).await.expect("page")
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = target(dir.path(), SharedDeletes::Forbid).await;
    rollback.prepare_store(EDITION).await.expect("prepare");
    let outcome = write(
        &rollback,
        &[dmarc_record(0x51, "x"), dmarc_record(0x52, "x")],
    )
    .await;
    assert_eq!(conflicts(&outcome), vec![key(0x52)], "{:?}", outcome.issues);
    assert_eq!(outcome.issues.len(), 1);
    assert_eq!(
        raw_rows(rollback.store()).await,
        stock_dmarc_rows(&[(0x51, "x")]).await
    );

    let outcome = write(
        &rollback,
        &[
            dmarc_record(0x51, "y"),
            dmarc_record(0x52, "x"),
            dmarc_record(0x51, "z"),
        ],
    )
    .await;
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let outcome = write(&rollback, &[dmarc_record(0x53, "y")]).await;
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(
        raw_rows(rollback.store()).await,
        stock_dmarc_rows(&[(0x51, "z"), (0x52, "x"), (0x53, "y")]).await
    );

    let outcome = write(
        &rollback,
        &[
            dmarc_record(0x53, "r"),
            dmarc_record(0x53, "z"),
            dmarc_record(0x53, "s"),
        ],
    )
    .await;
    assert_eq!(conflicts(&outcome), vec![key(0x53)], "{:?}", outcome.issues);
    assert_eq!(
        raw_rows(rollback.store()).await,
        stock_dmarc_rows(&[(0x51, "z"), (0x52, "x"), (0x53, "s")]).await
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let corrupt = target(dir.path(), SharedDeletes::Forbid).await;
    corrupt.prepare_store(EDITION).await.expect("prepare");
    let mut batch = store::write::BatchBuilder::new();
    {
        use smtp::reporting::index::ExternalReportIndex;
        dmarc_with_id("x").write_ops(&mut batch, 0x51, true);
    }
    batch.clear(store::write::ValueClass::Registry(
        store::write::RegistryClass::Item {
            object_id: {
                use registry::types::EnumImpl;
                registry::schema::prelude::ObjectType::DmarcExternalReport.to_id()
            },
            item_id: 0x51,
        },
    ));
    corrupt
        .store()
        .write(batch.build_all())
        .await
        .expect("orphan primary key");
    let outcome = write(&corrupt, &[dmarc_record(0x51, "x")]).await;
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(
        raw_rows(corrupt.store()).await,
        stock_dmarc_rows(&[(0x51, "x")]).await
    );
}

// Rollback's final step deletes the cached bundle of every Application from an external blob store, so v0.16 downloads its own instead of v1's.
#[tokio::test(flavor = "multi_thread")]
async fn final_step_discards_cached_app_bundles_in_shared_blob_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rollback = shared_blob_rollback(dir.path(), SharedDeletes::Forbid).await;
    let outcome = rollback
        .write_registry(&[RegistryRecord {
            key: model::RegistryKey::new("Application", 4),
            json: json!({"enable": true, "description": "web", "resourceUrl": "https://example.org/webui.zip", "urlPrefix": {"admin": true}}),
        }])
        .await
        .expect("application");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let blob_store = rollback.server().expect("server").blob_store();
    let bundle = AppBlobHash::generate(format!("STALWART_APP_{}", Id::new(4)).as_bytes());
    let other = AppBlobHash::generate(b"STALWART_APP_unrelated");
    for key in [&bundle, &other] {
        blob_store
            .put_blob(key.as_slice(), b"stale bundle", CompressionAlgo::None)
            .await
            .expect("cached bundle");
    }
    let outcome = rollback
        .finalize_store(model::CategorySet::defaults())
        .await
        .expect("finalize store");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert!(
        outcome.issues[0].message.contains("cached bundle"),
        "{:?}",
        outcome.issues
    );
    assert!(
        blob_store
            .get_blob(bundle.as_slice(), 0..usize::MAX)
            .await
            .expect("bundle")
            .is_none()
    );
    assert!(
        blob_store
            .get_blob(other.as_slice(), 0..usize::MAX)
            .await
            .expect("other")
            .is_some()
    );
}
