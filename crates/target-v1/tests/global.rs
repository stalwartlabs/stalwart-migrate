/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use bytes::Bytes;
use model::{
    BlobHash, DeliveryStatus, Edition, Ftrl, FtrlWeight, GlobalBatch, GlobalCategory,
    InternalReportRecord, IssueKind, QueueExpiry, QueueMetadata, QueueName, QueueQuotaKey,
    QueueRecipient, QueueSchedule, QueuedMessageRecord, RegistryKey, RegistryRecord, ReportKind,
    SampleReservoir, Source, SpamClassifierModel, SpamModelChange, SpamModelKind, SpamModelRecord,
    SpamOptimizer, SpamTrainerModel, Subject, Target, TaskRecord, TrainingSample,
};
use registry::{
    schema::{
        enums::{DmarcActionDisposition, TaskType, TlsPolicyType, TlsResultType},
        structs::{
            DmarcInternalReport, DmarcReportRecord, Task, TaskAccountMaintenance,
            TaskDestroyAccount, TaskStatus, TlsFailureDetails, TlsInternalReport, TlsReportPolicy,
        },
    },
    types::{datetime::UTCDateTime, ipaddr::IpAddr as RegistryIp},
};
use serde_json::json;
use source_v1::V1Source;
use store::{
    Store, ValueKey, blake3,
    write::{BlobLink, BlobOp, QueueClass, QueueEvent, TaskId, TaskQueueClass, ValueClass},
};
use target_v1::{TargetConfig, V1Target};
use types::{blob::BlobId, blob_hash::BlobHash as V1BlobHash};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const QUEUE_ID: u64 = 0x0123_4567_89ab_cdef;
const DMARC_ID: u64 = 0x1111_2222_3333_4444;
const TLS_ID: u64 = 0x1111_2222_3333_5555;
const TASK_ID: u64 = 0x2222_3333_4444_5555;
const NOW: u64 = 1_900_000_000;
const QUOTA_KEY: u128 = 0xfeed_beef;
const MESSAGE: &[u8] =
    b"From: a@example.org\r\nTo: b@example.net\r\nSubject: queued\r\n\r\nHi.\r\n";

fn hash(bytes: &[u8]) -> BlobHash {
    BlobHash(*blake3::hash(bytes).as_bytes())
}

async fn open_target(dir: &Path) -> V1Target {
    let config = dir.join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": dir.join("data").to_string_lossy()}).to_string(),
    )
    .expect("write config");
    let target = V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target");
    target.prepare_store(EDITION).await.expect("prepare");
    target
}

async fn page(store: &Store, category: GlobalCategory) -> GlobalBatch {
    let source = V1Source::from_store(store.clone());
    let page = source
        .global_page(category, None, 1000)
        .await
        .expect("global page");
    assert!(page.issues.is_empty(), "{:?}", page.issues);
    page.batch
}

fn queued_message(due: u64) -> QueuedMessageRecord {
    let recipient = |address: &str| QueueRecipient {
        address: address.into(),
        retry: QueueSchedule { due, attempt: 1 },
        notify: QueueSchedule {
            due: due + 3600,
            attempt: 0,
        },
        expires: QueueExpiry::Ttl(86_400),
        queue: QueueName(*b"default\0"),
        status: DeliveryStatus::Scheduled,
        flags: 0,
        orcpt: None,
    };
    QueuedMessageRecord {
        queue_id: QUEUE_ID,
        created: NOW,
        blob_hash: hash(MESSAGE),
        size: MESSAGE.len() as u64,
        return_path: "a@example.org".into(),
        recipients: vec![recipient("b@example.net"), recipient("c@example.net")],
        received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        received_via_port: 25,
        flags: 0,
        env_id: Some("env-1".into()),
        priority: 0,
        metadata: vec![
            QueueMetadata::QuotaSize {
                key: QueueQuotaKey(QUOTA_KEY),
                id: 1,
            },
            QueueMetadata::QuotaCount {
                key: QueueQuotaKey(QUOTA_KEY),
                id: 2,
            },
        ],
    }
}

fn event_key(due: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
        due,
        queue_id: QUEUE_ID,
        queue_name: *b"default\0",
    })))
}

async fn counter(store: &Store, class: ValueClass) -> i64 {
    store
        .get_counter(ValueKey::from(class))
        .await
        .expect("counter")
}

fn spam_records() -> Vec<SpamModelRecord> {
    let ftrl = Ftrl {
        alpha: 0.1,
        beta: 1.0,
        l1_ratio: 0.001,
        l2_ratio: 0.0001,
        zn: vec![FtrlWeight { z: 0.5, n: 2.0 }; 4],
        zn_bias: FtrlWeight { z: -0.25, n: 1.0 },
    };
    vec![
        SpamModelRecord::Trainer(Box::new(SpamTrainerModel {
            optimizer: SpamOptimizer::Fh(ftrl),
            spam: SampleReservoir {
                samples: vec![TrainingSample {
                    blob_hash: hash(b"spam"),
                    account_id: 7,
                }],
                total_seen: 3,
            },
            ham: SampleReservoir::default(),
            last_id: 99,
        })),
        SpamModelRecord::Classifier(SpamClassifierModel::Fh {
            parameters: vec![0.25, -0.5, 1.0],
            bias: 0.125,
            last_trained_at: NOW,
        }),
    ]
}

fn dmarc_report(count: u64) -> InternalReportRecord {
    let mut report = DmarcInternalReport {
        domain: "example.net".into(),
        policy_identifier: 42,
        created_at: UTCDateTime::from_timestamp(NOW as i64),
        deliver_at: UTCDateTime::from_timestamp(NOW as i64 + 86_400),
        ..Default::default()
    };
    report.report.report_id = "r1".into();
    report.report.date_range_end = UTCDateTime::from_timestamp(NOW as i64 + 86_000);
    for (ip, disposition) in [
        (Ipv4Addr::new(192, 0, 2, 1), DmarcActionDisposition::Pass),
        (Ipv4Addr::new(192, 0, 2, 2), DmarcActionDisposition::Reject),
    ] {
        report.report.records.push(DmarcReportRecord {
            source_ip: Some(RegistryIp(IpAddr::V4(ip))),
            count,
            evaluated_disposition: disposition,
            header_from: "example.net".into(),
            ..Default::default()
        });
    }
    InternalReportRecord {
        kind: ReportKind::Dmarc,
        id: DMARC_ID,
        json: serde_json::to_value(report).expect("dmarc json"),
    }
}

fn tls_report() -> InternalReportRecord {
    let mut report = TlsInternalReport {
        domain: "example.net".into(),
        created_at: UTCDateTime::from_timestamp(NOW as i64),
        deliver_at: UTCDateTime::from_timestamp(NOW as i64 + 86_400),
        ..Default::default()
    };
    report.report.report_id = "t1".into();
    report.report.date_range_end = UTCDateTime::from_timestamp(NOW as i64 + 86_000);
    let mut policy = TlsReportPolicy {
        policy_type: TlsPolicyType::Sts,
        policy_domain: "example.net".into(),
        total_successful_sessions: 10,
        total_failed_sessions: 3,
        ..Default::default()
    };
    policy.failure_details.push(TlsFailureDetails {
        result_type: TlsResultType::CertificateExpired,
        receiving_mx_hostname: Some("mx.example.net".into()),
        failed_session_count: 3,
        ..Default::default()
    });
    report.report.policies.push(policy);
    report.policy_identifiers.push(77);
    InternalReportRecord {
        kind: ReportKind::Tls,
        id: TLS_ID,
        json: serde_json::to_value(report).expect("tls json"),
    }
}

fn dmarc_counts(batch: &GlobalBatch) -> (usize, u64) {
    let GlobalBatch::Reports(records) = batch else {
        panic!("not a report page");
    };
    let report = records
        .iter()
        .find(|record| record.id == DMARC_ID)
        .expect("dmarc report");
    let entries = report.json["report"]["records"]
        .as_object()
        .map(|records| records.values().collect::<Vec<_>>())
        .or_else(|| {
            report.json["report"]["records"]
                .as_array()
                .map(|records| records.iter().collect())
        })
        .expect("records");
    let total = entries
        .iter()
        .map(|record| record["count"].as_u64().expect("count"))
        .sum();
    (entries.len(), total)
}

fn tls_totals(batch: &GlobalBatch) -> (u64, u64) {
    let GlobalBatch::Reports(records) = batch else {
        panic!("not a report page");
    };
    let report = records
        .iter()
        .find(|record| record.id == TLS_ID)
        .expect("tls report");
    let report =
        <TlsInternalReport as serde::Deserialize>::deserialize(&report.json).expect("tls json");
    report
        .report
        .policies
        .iter()
        .fold((0, 0), |(ok, failed), policy| {
            (
                ok + policy.total_successful_sessions,
                failed + policy.total_failed_sessions,
            )
        })
}

async fn task_exists(store: &Store, id: u64, typ: TaskType, due: u64) -> bool {
    store
        .key_exists(ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
            id: TaskId::Assigned(id),
            typ,
            due,
        })))
        .await
        .expect("due")
}

fn task_record(id: u64, task: Task) -> TaskRecord {
    TaskRecord {
        id,
        json: serde_json::to_value(task).expect("task json"),
    }
}

fn destroy_task(due: i64) -> Task {
    Task::DestroyAccount(TaskDestroyAccount {
        account_name: "gone".into(),
        status: TaskStatus::at(due),
        ..Default::default()
    })
}

// Spam model, queue, internal reports and tasks are written idempotently and read back unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn global_categories_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let store = target.store().clone();

    let spam = spam_records();
    for _ in 0..2 {
        let outcome = target
            .apply_final_spam_model(&spam_writes(&spam))
            .await
            .expect("spam");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let GlobalBatch::SpamModel(mut read) = page(&store, GlobalCategory::SpamModel).await else {
        panic!("not a spam page");
    };
    read.sort_by_key(|record| record.as_str());
    let mut expected = spam;
    expected.sort_by_key(|record| record.as_str());
    assert_eq!(read, expected);

    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    let first = queued_message(NOW + 60);
    for _ in 0..2 {
        let outcome = target
            .write_global(&GlobalBatch::Queue(vec![first.clone()]))
            .await
            .expect("queue");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let moved = queued_message(NOW + 600);
    target
        .write_global(&GlobalBatch::Queue(vec![moved.clone()]))
        .await
        .expect("queue update");
    assert_eq!(
        page(&store, GlobalCategory::Queue).await,
        GlobalBatch::Queue(vec![moved])
    );
    assert!(
        !store
            .key_exists(event_key(NOW + 60))
            .await
            .expect("old event")
    );
    assert!(
        store
            .key_exists(event_key(NOW + 600))
            .await
            .expect("new event")
    );
    let quota_key = QUOTA_KEY.into();
    assert_eq!(
        counter(&store, ValueClass::Queue(QueueClass::QuotaCount(quota_key))).await,
        1
    );
    assert_eq!(
        counter(&store, ValueClass::Queue(QueueClass::QuotaSize(quota_key))).await,
        MESSAGE.len() as i64
    );
    assert!(
        store
            .key_exists(ValueKey::from(ValueClass::Blob(BlobOp::Link {
                hash: V1BlobHash(hash(MESSAGE).0),
                to: BlobLink::Id { id: QUEUE_ID },
            })))
            .await
            .expect("queue blob link")
    );

    let reports = vec![dmarc_report(4), tls_report()];
    for _ in 0..2 {
        let outcome = target
            .write_global(&GlobalBatch::Reports(reports.clone()))
            .await
            .expect("reports");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let read = page(&store, GlobalCategory::Reports).await;
    assert_eq!(dmarc_counts(&read), (2, 8));
    assert_eq!(tls_totals(&read), (10, 3));
    let deliver_at = NOW + 86_400;
    assert!(task_exists(&store, DMARC_ID, TaskType::DmarcReport, deliver_at).await);
    assert!(task_exists(&store, TLS_ID, TaskType::TlsReport, deliver_at).await);
    let outcome = target
        .write_global(&GlobalBatch::Reports(vec![dmarc_report(1)]))
        .await
        .expect("report update");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(
        dmarc_counts(&page(&store, GlobalCategory::Reports).await),
        (2, 2)
    );

    let maintenance = Task::AccountMaintenance(TaskAccountMaintenance {
        status: TaskStatus::at(NOW as i64),
        ..Default::default()
    });
    let singleton = TaskId::singleton_of(&maintenance).expect("singleton");
    let records = vec![
        task_record(TASK_ID, destroy_task(NOW as i64)),
        task_record(1, maintenance.clone()),
        TaskRecord {
            id: 2,
            json: json!({"@type": "NoSuchTask"}),
        },
    ];
    let outcome = target
        .write_global(&GlobalBatch::Tasks(records))
        .await
        .expect("tasks");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert_eq!(
        outcome.issues[0].subject,
        Subject::Registry(RegistryKey::new(TaskRecord::OBJECT, 2))
    );
    assert_eq!(outcome.issues[0].kind, IssueKind::Skipped);
    assert!(task_exists(&store, TASK_ID, TaskType::DestroyAccount, NOW).await);
    assert!(task_exists(&store, singleton, TaskType::AccountMaintenance, NOW).await);
    target
        .write_global(&GlobalBatch::Tasks(vec![task_record(
            TASK_ID,
            destroy_task(NOW as i64 + 60),
        )]))
        .await
        .expect("task update");
    assert!(!task_exists(&store, TASK_ID, TaskType::DestroyAccount, NOW).await);
    assert!(task_exists(&store, TASK_ID, TaskType::DestroyAccount, NOW + 60).await);
}

fn sample(expires_at: &str) -> RegistryRecord {
    let blob_id = BlobId::new(V1BlobHash(hash(b"sample").0), Default::default());
    RegistryRecord {
        key: RegistryKey::new("SpamTrainingSample", 5),
        json: json!({
            "from": "spammer@example.com",
            "subject": "buy now",
            "blobId": serde_json::to_value(blob_id).expect("blob id"),
            "isSpam": true,
            "expiresAt": expires_at,
        }),
    }
}

fn temporary_link(until: u64) -> ValueKey<ValueClass> {
    ValueKey {
        account_id: u32::MAX,
        collection: 0,
        document_id: 0,
        class: ValueClass::Blob(BlobOp::Link {
            hash: V1BlobHash(hash(b"sample").0),
            to: BlobLink::Temporary { until },
        }),
    }
}

// Spam training samples carry a temporary blob link that follows updates and deletes.
#[tokio::test(flavor = "multi_thread")]
async fn registry_blob_links() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    let first = sample("2031-01-01T00:00:00Z");
    assert_eq!(target.registry_blob(&first), Some(hash(b"sample")));
    assert_eq!(
        target.registry_blob(&RegistryRecord {
            key: RegistryKey::new("Domain", 3),
            json: json!({"name": "example.org"}),
        }),
        None
    );
    let first_until = 1_924_992_000;
    let second_until = 1_956_528_000;
    let outcome = target.write_registry(&[first]).await.expect("sample");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let store = target.store();
    assert!(
        store
            .key_exists(temporary_link(first_until))
            .await
            .expect("link")
    );
    let outcome = target
        .write_registry(&[sample("2032-01-01T00:00:00Z")])
        .await
        .expect("sample update");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert!(
        !store
            .key_exists(temporary_link(first_until))
            .await
            .expect("old link")
    );
    assert!(
        store
            .key_exists(temporary_link(second_until))
            .await
            .expect("new link")
    );
    target
        .delete_registry(&[RegistryKey::new("SpamTrainingSample", 5)])
        .await
        .expect("delete");
    assert!(
        !store
            .key_exists(temporary_link(second_until))
            .await
            .expect("deleted link")
    );
}

// A spam training sample commits its blob, so a blob in a shared blob store counts as present.
#[tokio::test(flavor = "multi_thread")]
async fn registry_blob_is_committed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    let sample_hash = hash(b"sample");
    assert_eq!(
        target.blobs_exist(&[sample_hash]).await.expect("exists"),
        [false]
    );
    let outcome = target
        .write_registry(&[sample("2031-01-01T00:00:00Z")])
        .await
        .expect("sample");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(
        target.blobs_exist(&[sample_hash]).await.expect("exists"),
        [true]
    );
    target.start_server().await.expect("server");
    let stored = hash(b"stored");
    target
        .put_blob(&stored, Bytes::from_static(b"stored"))
        .await
        .expect("put");
    assert_eq!(
        target
            .stored_blobs_exist(&[stored, sample_hash])
            .await
            .expect("stored"),
        [true, false]
    );
}

#[cfg(feature = "enterprise")]
fn telemetry_records() -> Vec<model::TelemetryRecord> {
    use model::{TelemetryKind, TelemetryRecord};
    use registry::{
        schema::structs::{Metric, MetricCount, Trace, TraceEvent},
        types::list::List,
    };

    let mut trace = Trace::default();
    trace.events.push(TraceEvent {
        event: trc::EventType::Queue(trc::QueueEvent::MessageQueued),
        timestamp: UTCDateTime::from_timestamp(NOW as i64),
        key_values: List::default(),
    });
    vec![
        TelemetryRecord {
            kind: TelemetryKind::Span,
            id: 101,
            json: serde_json::to_value(trace).expect("trace"),
        },
        TelemetryRecord {
            kind: TelemetryKind::Metric,
            id: 102,
            json: serde_json::to_value(Metric::Counter(MetricCount {
                count: 5,
                ..Default::default()
            }))
            .expect("metric"),
        },
    ]
}

// Telemetry is written only when the v1 tracing and metrics stores are the target data store.
#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread")]
async fn telemetry_isolation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let records = telemetry_records();
    let batch = GlobalBatch::Telemetry(records.clone());

    let outcome = target.write_global(&batch).await.expect("disabled");
    assert_eq!(outcome.issues.len(), 2, "{:?}", outcome.issues);
    assert!(
        outcome
            .issues
            .iter()
            .all(|issue| issue.explains == Some(model::Explanation::Missing))
    );

    let stores = [
        (
            "TracingStore",
            json!({"@type": "PostgreSql", "host": "db", "port": 5432, "database": "x"}),
        ),
        ("MetricsStore", json!({"@type": "Default"})),
    ];
    let outcome = target
        .write_registry(
            &stores
                .iter()
                .map(|(name, json)| RegistryRecord {
                    key: RegistryKey::singleton(*name),
                    json: json.clone(),
                })
                .collect::<Vec<_>>(),
        )
        .await
        .expect("stores");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let outcome = target.write_global(&batch).await.expect("external");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert_eq!(
        outcome.issues[0].subject,
        Subject::Registry(RegistryKey::new("span", 101))
    );

    target
        .write_registry(&[RegistryRecord {
            key: RegistryKey::singleton("TracingStore"),
            json: json!({"@type": "Default"}),
        }])
        .await
        .expect("tracing default");
    let outcome = target.write_global(&batch).await.expect("default");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let GlobalBatch::Telemetry(read) = page(target.store(), GlobalCategory::Telemetry).await else {
        panic!("not a telemetry page");
    };
    let normalize = |json: &serde_json::Value| {
        let mut json = json.clone();
        if let Some(object) = json.as_object_mut()
            && object.get("nodeId").and_then(serde_json::Value::as_u64) == Some(0)
        {
            object.remove("nodeId");
        }
        json
    };
    assert_eq!(
        read.iter()
            .map(|r| (r.id, normalize(&r.json)))
            .collect::<Vec<_>>(),
        records
            .iter()
            .map(|r| (r.id, normalize(&r.json)))
            .collect::<Vec<_>>()
    );
}

// Deleting queued messages and internal reports removes every row they own and releases the queue quota; deleting again is a no-op.
#[tokio::test(flavor = "multi_thread")]
async fn global_delete_removes_owned_rows() {
    use model::GlobalKey;
    use smtp::reporting::index::InternalReportIndex;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let store = target.store().clone();
    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    target
        .write_global(&GlobalBatch::Queue(vec![queued_message(NOW + 60)]))
        .await
        .expect("queue");
    target
        .write_global(&GlobalBatch::Reports(vec![dmarc_report(4), tls_report()]))
        .await
        .expect("reports");

    assert!(report_rows(&store).await > 0);
    let keys = [
        GlobalKey::Queue(QUEUE_ID),
        GlobalKey::Report(ReportKind::Dmarc, DMARC_ID),
        GlobalKey::Report(ReportKind::Tls, TLS_ID),
        GlobalKey::Queue(QUEUE_ID + 1),
    ];
    for _ in 0..2 {
        let outcome = target.delete_global(&keys).await.expect("delete");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    assert_eq!(
        page(&store, GlobalCategory::Queue).await,
        GlobalBatch::Queue(Vec::new())
    );
    assert_eq!(
        page(&store, GlobalCategory::Reports).await,
        GlobalBatch::Reports(Vec::new())
    );
    assert!(!store.key_exists(event_key(NOW + 60)).await.expect("event"));
    let quota_key = QUOTA_KEY.into();
    assert_eq!(
        counter(&store, ValueClass::Queue(QueueClass::QuotaCount(quota_key))).await,
        0
    );
    assert_eq!(
        counter(&store, ValueClass::Queue(QueueClass::QuotaSize(quota_key))).await,
        0
    );
    assert!(
        !store
            .key_exists(ValueKey::from(ValueClass::Blob(BlobOp::Link {
                hash: V1BlobHash(hash(MESSAGE).0),
                to: BlobLink::Id { id: QUEUE_ID },
            })))
            .await
            .expect("queue blob link")
    );
    let deliver_at = NOW + 86_400;
    assert!(!task_exists(&store, DMARC_ID, TaskType::DmarcReport, deliver_at).await);
    assert!(!task_exists(&store, TLS_ID, TaskType::TlsReport, deliver_at).await);
    assert_eq!(report_rows(&store).await, 0, "report rows survived");
    let dmarc = <DmarcInternalReport as serde::Deserialize>::deserialize(&dmarc_report(4).json)
        .expect("dmarc report");
    let tls = <TlsInternalReport as serde::Deserialize>::deserialize(&tls_report().json)
        .expect("tls report");
    for (key, what) in [
        (dmarc.primary_key(), "DMARC primary key"),
        (tls.primary_key(), "TLS primary key"),
        (
            ValueClass::TaskQueue(TaskQueueClass::Task {
                id: TaskId::Assigned(DMARC_ID),
            }),
            "DMARC task",
        ),
        (
            ValueClass::TaskQueue(TaskQueueClass::Task {
                id: TaskId::Assigned(TLS_ID),
            }),
            "TLS task",
        ),
    ] {
        assert!(
            !store.key_exists(ValueKey::from(key)).await.expect("key"),
            "{what} survived"
        );
    }
}

// A report that no longer fits the v1 row limit after an earlier copy is skipped and its stale copy removed, so the target holds no outdated report.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_rewrite_removes_the_stale_report() {
    use smtp::reporting::index::InternalReportIndex;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let store = target.store().clone();
    target
        .write_global(&GlobalBatch::Reports(vec![dmarc_report(4)]))
        .await
        .expect("report");
    assert!(report_rows(&store).await > 0);
    let mut oversized = dmarc_report(4);
    let first = match &mut oversized.json["report"]["records"] {
        serde_json::Value::Object(records) => records.values_mut().next(),
        serde_json::Value::Array(records) => records.first_mut(),
        _ => None,
    }
    .expect("first record");
    first["headerFrom"] = "x".repeat(400).into();
    let outcome = target
        .write_global(&GlobalBatch::Reports(vec![oversized]))
        .await
        .expect("oversized report");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert_eq!(outcome.issues[0].kind, model::IssueKind::Skipped);
    assert_eq!(
        page(&store, GlobalCategory::Reports).await,
        GlobalBatch::Reports(Vec::new())
    );
    assert_eq!(report_rows(&store).await, 0, "report rows survived");
    let dmarc = <DmarcInternalReport as serde::Deserialize>::deserialize(&dmarc_report(4).json)
        .expect("dmarc report");
    assert!(
        !store
            .key_exists(ValueKey::from(dmarc.primary_key()))
            .await
            .expect("primary key")
    );
    assert!(!task_exists(&store, DMARC_ID, TaskType::DmarcReport, NOW + 86_400).await);
}

async fn report_rows(store: &Store) -> usize {
    let mut rows = 0;
    for subspace in [store::Subspace::Counter, store::Subspace::ReportOut] {
        store
            .iterate(
                store::IterateParams::new(
                    store::write::AnyKey {
                        subspace,
                        key: vec![0u8],
                    },
                    store::write::AnyKey {
                        subspace,
                        key: vec![u8::MAX; 32],
                    },
                ),
                |key, _| {
                    if key.windows(8).any(|window| {
                        window == DMARC_ID.to_be_bytes() || window == TLS_ID.to_be_bytes()
                    }) {
                        rows += 1;
                    }
                    Ok(true)
                },
            )
            .await
            .expect("scan");
    }
    rows
}

// Deleting a task key clears its task and due rows, also of a singleton stored under its singleton key, and is a no-op when missing.
#[tokio::test(flavor = "multi_thread")]
async fn global_delete_removes_stale_tasks() {
    use model::GlobalKey;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let store = target.store().clone();
    let maintenance = Task::AccountMaintenance(TaskAccountMaintenance {
        status: TaskStatus::at(NOW as i64),
        ..Default::default()
    });
    let singleton = TaskId::singleton_of(&maintenance).expect("singleton");
    let outcome = target
        .write_global(&GlobalBatch::Tasks(vec![
            task_record(TASK_ID, destroy_task(NOW as i64)),
            task_record(TASK_ID + 1, destroy_task(NOW as i64)),
            task_record(1, maintenance),
        ]))
        .await
        .expect("tasks");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    let keys = [
        GlobalKey::Task(TASK_ID),
        GlobalKey::Task(singleton),
        GlobalKey::Task(1),
        GlobalKey::Task(TASK_ID + 2),
    ];
    for _ in 0..2 {
        let outcome = target.delete_global(&keys).await.expect("delete");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let task_row = |id| {
        ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
            id: TaskId::Assigned(id),
        }))
    };
    assert!(!task_exists(&store, TASK_ID, TaskType::DestroyAccount, NOW).await);
    assert!(!store.key_exists(task_row(TASK_ID)).await.expect("task"));
    assert!(task_exists(&store, TASK_ID + 1, TaskType::DestroyAccount, NOW).await);
    assert!(store.key_exists(task_row(TASK_ID + 1)).await.expect("task"));
    assert!(!task_exists(&store, singleton, TaskType::AccountMaintenance, NOW).await);
    assert!(
        !store
            .key_exists(task_row(singleton))
            .await
            .expect("singleton")
    );
}

// TLS policies keep their own policy hash after the JSON round trip (identifier keys come back in string order), read through the stock reader.
#[tokio::test(flavor = "multi_thread")]
async fn tls_policies_keep_their_hashes() {
    use smtp::reporting::aggregate::read_tls_policies;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let mut report = TlsInternalReport {
        domain: "example.net".into(),
        created_at: UTCDateTime::from_timestamp(NOW as i64),
        deliver_at: UTCDateTime::from_timestamp(NOW as i64 + 86_400),
        ..Default::default()
    };
    report.report.report_id = "t2".into();
    for (policy_type, successes) in [(TlsPolicyType::Sts, 5), (TlsPolicyType::Tlsa, 7)] {
        report.report.policies.push(TlsReportPolicy {
            policy_type,
            policy_domain: "example.net".into(),
            total_successful_sessions: successes,
            ..Default::default()
        });
    }
    report.policy_identifiers.push(9);
    report.policy_identifiers.push(10);
    let outcome = target
        .write_global(&GlobalBatch::Reports(vec![InternalReportRecord {
            kind: ReportKind::Tls,
            id: TLS_ID,
            json: serde_json::to_value(report).expect("tls json"),
        }]))
        .await
        .expect("tls report");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);

    let mut stored = TlsInternalReport::default();
    read_tls_policies(target.store(), TLS_ID, &mut stored, usize::MAX)
        .await
        .expect("stock read");
    let pairs = stored
        .policy_identifiers
        .iter()
        .zip(stored.report.policies.iter())
        .map(|(hash, policy)| (*hash, policy.policy_type, policy.total_successful_sessions))
        .collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![(9, TlsPolicyType::Sts, 5), (10, TlsPolicyType::Tlsa, 7)]
    );
}

// TLS policy identifiers that do not pair one to one with the policies are dropped with an issue (every policy keeps its own sessions under a content hash), and a report without identifiers is written without one.
#[tokio::test(flavor = "multi_thread")]
async fn tls_unpaired_policy_identifiers_are_dropped() {
    use model::IssueKind;
    use smtp::reporting::aggregate::read_tls_policies;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let mut report = TlsInternalReport {
        domain: "example.net".into(),
        created_at: UTCDateTime::from_timestamp(NOW as i64),
        deliver_at: UTCDateTime::from_timestamp(NOW as i64 + 86_400),
        ..Default::default()
    };
    report.report.report_id = "t3".into();
    for (policy_type, successes) in [(TlsPolicyType::Sts, 5), (TlsPolicyType::Tlsa, 7)] {
        report.report.policies.push(TlsReportPolicy {
            policy_type,
            policy_domain: "example.net".into(),
            total_successful_sessions: successes,
            ..Default::default()
        });
    }
    let outcome = target
        .write_global(&GlobalBatch::Reports(vec![InternalReportRecord {
            kind: ReportKind::Tls,
            id: TLS_ID,
            json: serde_json::to_value(&report).expect("tls json"),
        }]))
        .await
        .expect("tls report without identifiers");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    report.policy_identifiers.push(10);
    let outcome = target
        .write_global(&GlobalBatch::Reports(vec![InternalReportRecord {
            kind: ReportKind::Tls,
            id: TLS_ID,
            json: serde_json::to_value(report).expect("tls json"),
        }]))
        .await
        .expect("tls report");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert_eq!(outcome.issues[0].kind, IssueKind::Changed);

    let mut stored = TlsInternalReport::default();
    read_tls_policies(target.store(), TLS_ID, &mut stored, usize::MAX)
        .await
        .expect("stock read");
    assert!(!stored.policy_identifiers.iter().any(|hash| *hash == 10));
    let mut policies = stored
        .report
        .policies
        .iter()
        .map(|policy| (policy.policy_type, policy.total_successful_sessions))
        .collect::<Vec<_>>();
    policies.sort_unstable_by_key(|(_, successes)| *successes);
    assert_eq!(
        policies,
        vec![(TlsPolicyType::Sts, 5), (TlsPolicyType::Tlsa, 7)]
    );
}

// Duplicate ids in one batch keep the last record only: one Due row per singleton task, queue quota counted once, report rows counted once.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_records_in_one_batch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let store = target.store().clone();
    let maintenance = |due: u64| {
        Task::AccountMaintenance(TaskAccountMaintenance {
            status: TaskStatus::at(due as i64),
            ..Default::default()
        })
    };
    let singleton = TaskId::singleton_of(&maintenance(NOW)).expect("singleton");
    target
        .write_global(&GlobalBatch::Tasks(vec![
            task_record(1, maintenance(NOW)),
            task_record(2, maintenance(NOW + 60)),
        ]))
        .await
        .expect("tasks");
    assert!(!task_exists(&store, singleton, TaskType::AccountMaintenance, NOW).await);
    assert!(task_exists(&store, singleton, TaskType::AccountMaintenance, NOW + 60).await);

    target
        .put_blob(&hash(MESSAGE), Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    target
        .write_global(&GlobalBatch::Queue(vec![
            queued_message(NOW + 60),
            queued_message(NOW + 60),
        ]))
        .await
        .expect("queue");
    let quota_key = QUOTA_KEY.into();
    assert_eq!(
        counter(&store, ValueClass::Queue(QueueClass::QuotaCount(quota_key))).await,
        1
    );

    target
        .write_global(&GlobalBatch::Reports(vec![
            dmarc_report(4),
            dmarc_report(4),
        ]))
        .await
        .expect("reports");
    assert_eq!(
        dmarc_counts(&page(&store, GlobalCategory::Reports).await),
        (2, 8)
    );
}

// Account-owned spam samples and archived items link their blob under the owning account, with the object id and size in the link value.
#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread")]
async fn registry_blob_link_values() {
    use registry::{schema::prelude::ObjectType, types::id::ObjectId};
    use store::write::blob::BlobLinkValue;
    use types::id::Id;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    let blob_id = |bytes: &[u8]| {
        serde_json::to_value(BlobId::new(V1BlobHash(hash(bytes).0), Default::default()))
            .expect("blob id")
    };
    let account = Id::new(7).to_string();
    let outcome = target
        .write_registry(&[
            RegistryRecord {
                key: RegistryKey::new("Domain", 3),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Account", 7),
                json: json!({"@type": "User", "name": "bob", "domainId": Id::new(3).to_string()}),
            },
        ])
        .await
        .expect("account");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let records = [
        RegistryRecord {
            key: RegistryKey::new("SpamTrainingSample", 6),
            json: json!({
                "from": "spammer@example.com",
                "subject": "buy now",
                "blobId": blob_id(b"owned sample"),
                "isSpam": true,
                "accountId": account,
                "expiresAt": "2031-01-01T00:00:00Z",
            }),
        },
        RegistryRecord {
            key: RegistryKey::new("ArchivedItem", 8),
            json: json!({
                "@type": "Email",
                "from": "alice@example.org",
                "subject": "archived",
                "receivedAt": "2030-01-01T00:00:00Z",
                "size": 1234,
                "accountId": account,
                "archivedAt": "2030-06-01T00:00:00Z",
                "archivedUntil": "2031-01-01T00:00:00Z",
                "blobId": blob_id(b"archived item"),
            }),
        },
    ];
    for record in &records {
        assert!(target.registry_blob(record).is_some());
    }
    let outcome = target.write_registry(&records).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let until = 1_924_992_000;
    for (bytes, object, id, size) in [
        (&b"owned sample"[..], ObjectType::SpamTrainingSample, 6, 0),
        (&b"archived item"[..], ObjectType::ArchivedItem, 8, 1234),
    ] {
        let value = target
            .store()
            .get_value::<BlobLinkValue>(ValueKey {
                account_id: 7,
                collection: 0,
                document_id: 0,
                class: ValueClass::Blob(BlobOp::Link {
                    hash: V1BlobHash(hash(bytes).0),
                    to: BlobLink::Temporary { until },
                }),
            })
            .await
            .expect("link value");
        assert_eq!(
            value,
            Some(BlobLinkValue {
                size,
                object_id: Some(ObjectId::new(object, Id::new(id))),
            }),
            "{object:?}"
        );
    }
}

fn spam_writes(records: &[SpamModelRecord]) -> Vec<SpamModelChange> {
    records
        .iter()
        .cloned()
        .map(SpamModelChange::Write)
        .collect()
}

// The final spam model step deletes the key of a kind the source no longer has, and the global pass never writes the model.
#[tokio::test(flavor = "multi_thread")]
async fn final_spam_model_deletes_absent_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let store = target.store().clone();

    let spam = spam_records();
    let outcome = target
        .write_global(&GlobalBatch::SpamModel(spam.clone()))
        .await
        .expect("global spam");
    assert_eq!(outcome.issues.len(), spam.len(), "{:?}", outcome.issues);
    let GlobalBatch::SpamModel(read) = page(&store, GlobalCategory::SpamModel).await else {
        panic!("not a spam page");
    };
    assert_eq!(read, Vec::new());

    target
        .apply_final_spam_model(&spam_writes(&spam))
        .await
        .expect("spam");
    let classifier = spam
        .into_iter()
        .filter(|record| matches!(record, SpamModelRecord::Classifier(_)))
        .collect::<Vec<_>>();
    for _ in 0..2 {
        let outcome = target
            .apply_final_spam_model(&[
                SpamModelChange::Write(classifier[0].clone()),
                SpamModelChange::Delete(SpamModelKind::Trainer),
            ])
            .await
            .expect("reset trainer");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    let GlobalBatch::SpamModel(read) = page(&store, GlobalCategory::SpamModel).await else {
        panic!("not a spam page");
    };
    assert_eq!(read, classifier);

    target
        .apply_final_spam_model(&SpamModelKind::ALL.map(SpamModelChange::Delete))
        .await
        .expect("reset all");
    let GlobalBatch::SpamModel(read) = page(&store, GlobalCategory::SpamModel).await else {
        panic!("not a spam page");
    };
    assert_eq!(read, Vec::new());
}

// A kind left out of the final spam model changes is neither written nor deleted, even when its key holds bytes no reader can decode.
#[tokio::test(flavor = "multi_thread")]
async fn omitted_spam_kind_is_left_untouched() {
    use source_v1::spam_archive::SpamBlob;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.start_server().await.expect("server");
    let spam = spam_records();
    let blob_store = target.server().expect("server").blob_store().clone();
    let foreign = b"not a spam trainer".to_vec();
    blob_store
        .put_blob(SpamBlob::Trainer.key(), &foreign, Default::default())
        .await
        .expect("foreign trainer");
    let classifier = spam
        .iter()
        .find(|record| matches!(record, SpamModelRecord::Classifier(_)))
        .cloned()
        .expect("classifier");
    for _ in 0..2 {
        let outcome = target
            .apply_final_spam_model(&[SpamModelChange::Write(classifier.clone())])
            .await
            .expect("classifier only");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        assert_eq!(
            blob_store
                .get_blob(SpamBlob::Trainer.key(), 0..usize::MAX)
                .await
                .expect("read trainer"),
            Some(foreign.clone())
        );
    }
    let outcome = target.apply_final_spam_model(&[]).await.expect("nothing");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert!(
        blob_store
            .has_blob(SpamBlob::Classifier.key())
            .await
            .expect("has classifier")
    );
}
