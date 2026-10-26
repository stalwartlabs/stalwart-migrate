/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, Ipv6Addr};

use common::{
    config::{
        mailstore::spamfilter::SpamClassifier,
        smtp::queue::{QueueExpiry, QueueName},
    },
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use model::{
    BlobHash, DeliveryStatus, GlobalBatch, GlobalCategory, GlobalPage, IssueKind, QueueMetadata,
    QueueQuotaKey, QueuedMessageRecord, RegistryKey, ReportKind, Severity, Source, SpamModelRecord,
    SpamOptimizer, Subject,
};
use nlp::classifier::{
    ftrl::Ftrl,
    reservoir::{SampleReservoir, SampleReservoirClass},
    train::{CcfhTrainer, FhTrainer},
};
use registry::{
    schema::{
        enums::CompressionAlgo,
        prelude::{ObjectInner, ObjectType},
        structs::{DataStore, RocksDbStore},
    },
    types::EnumImpl,
};
use smtp::queue::{ErrorDetails, Message, Metadata, Recipient, Schedule, Status};
use spam_filter::modules::classifier::{SpamTrainer, SpamTrainerClass, TrainingSample};
use store::{
    BlobStore, Serialize, Store,
    rkyv::{self, rancor},
    write::{Archiver, BatchBuilder, QueueClass, RegistryClass, ValueClass},
};
use types::blob_hash::BlobHash as V1BlobHash;

use super::V1Source;
use crate::spam_archive::{self, SpamBlob};

async fn store(path: &std::path::Path) -> Store {
    Store::build(DataStore::RocksDb(RocksDbStore {
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await
    .expect("store")
}

async fn write(store: &Store, build: impl FnOnce(&mut BatchBuilder)) {
    let mut batch = BatchBuilder::new();
    build(&mut batch);
    store.write_batch(&mut batch).await.expect("write");
}

async fn pages(source: &V1Source, category: GlobalCategory, limit: usize) -> Vec<GlobalPage> {
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let page = source
            .global_page(category, cursor.as_deref(), limit)
            .await
            .expect("page");
        cursor = page.next.clone();
        pages.push(page);
        if cursor.is_none() {
            return pages;
        }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize)]
#[rkyv(crate = rkyv)]
struct SampleSeed {
    hash: V1BlobHash,
    account_id: u32,
}

fn sample(byte: u8, account_id: u32) -> TrainingSample {
    let bytes = rkyv::to_bytes::<rancor::Error>(&SampleSeed {
        hash: V1BlobHash([byte; 32]),
        account_id,
    })
    .expect("sample bytes");
    rkyv::from_bytes::<TrainingSample, rancor::Error>(&bytes).expect("sample")
}

fn reservoir(buffer: Vec<TrainingSample>, total_seen: u64) -> SampleReservoirClass<TrainingSample> {
    SampleReservoirClass { buffer, total_seen }
}

// The mirrors decode real v1 archives and re-encode them to identical bytes.
#[tokio::test(flavor = "multi_thread")]
async fn spam_archive_mirrors_match_the_v1_types() {
    let fh = FhTrainer::new(
        Ftrl::new(8)
            .with_hyperparams(3.0, 1.5, 0.01, 0.02)
            .with_initial_weights(0.25),
    );
    let classifier = Archiver::new(SpamClassifier::FhClassifier {
        classifier: fh.build_classifier(),
        last_trained_at: 99,
    })
    .serialize()
    .expect("classifier");
    let trainers = [
        SpamTrainer {
            trainer: SpamTrainerClass::FtrlFh(Box::new(fh)),
            reservoir: SampleReservoir {
                spam: reservoir(vec![sample(1, 10)], 3),
                ham: reservoir(Vec::new(), 0),
            },
            last_id: 5,
        },
        SpamTrainer {
            trainer: SpamTrainerClass::FtrlCfh(Box::new(CcfhTrainer::new(
                Ftrl::new(2),
                Ftrl::new(4).with_initial_weights(0.5),
            ))),
            reservoir: SampleReservoir {
                spam: reservoir(vec![sample(2, 11), sample(3, 12)], 8),
                ham: reservoir(vec![sample(4, 13)], 9),
            },
            last_id: 6,
        },
    ];

    let decoded = spam_archive::decode(SpamBlob::Classifier, &classifier).expect("decode");
    assert!(
        matches!(&decoded, SpamModelRecord::Classifier(model::SpamClassifierModel::Fh {
        parameters,
        last_trained_at: 99,
        ..
    }) if parameters.len() == 8)
    );
    assert_eq!(spam_archive::encode(&decoded).expect("encode"), classifier);

    for trainer in trainers {
        let bytes = Archiver::new(trainer).serialize().expect("trainer");
        let decoded = spam_archive::decode(SpamBlob::Trainer, &bytes).expect("decode");
        assert_eq!(spam_archive::encode(&decoded).expect("encode"), bytes);
        let SpamModelRecord::Trainer(model) = &decoded else {
            panic!("trainer");
        };
        if let SpamOptimizer::Ccfh { indicators, .. } = &model.optimizer {
            assert_eq!(indicators.zn.len(), 4);
            assert!(indicators.zn.iter().all(|zn| zn.z == 0.5));
            assert_eq!(model.spam.samples[1].blob_hash, BlobHash([3; 32]));
            assert_eq!(model.ham.total_seen, 9);
        }
    }
}

// The spam model is read from the v1 blob store.
#[tokio::test(flavor = "multi_thread")]
async fn spam_model_is_read_from_the_blob_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path()).await;
    let blob = BlobStore::Store(store.clone());
    let classifier = SpamModelRecord::Classifier(model::SpamClassifierModel::Ccfh {
        parameters: vec![0.5, -0.5],
        indicators: vec![1.0],
        bias: 0.25,
        last_trained_at: 7,
    });
    blob.put_blob(
        SPAM_CLASSIFIER_KEY,
        &spam_archive::encode(&classifier).expect("encode"),
        CompressionAlgo::None,
    )
    .await
    .expect("put");
    blob.put_blob(SPAM_TRAINER_KEY, b"garbage", CompressionAlgo::None)
        .await
        .expect("put");
    let source = V1Source::from_store(store);
    let [page] = pages(&source, GlobalCategory::SpamModel, 10)
        .await
        .try_into()
        .expect("one page");
    assert_eq!(page.batch, GlobalBatch::SpamModel(vec![classifier]));
    assert_eq!(page.issues.len(), 1);
}

fn message(created: u64) -> Message {
    Message {
        created,
        blob_hash: V1BlobHash([4; 32]),
        return_path: Box::from(""),
        recipients: vec![Recipient {
            address: Box::from("rcpt@example.net"),
            retry: Schedule {
                due: created + 10,
                inner: 0,
            },
            notify: Schedule {
                due: created + 20,
                inner: 0,
            },
            expires: QueueExpiry::Attempts(5),
            queue: QueueName::new("remote").expect("queue name"),
            status: Status::PermanentFailure(Box::new(ErrorDetails {
                entity: Box::from("mx"),
                details: smtp::queue::Error::Io(Box::from("reset")),
            })),
            flags: 0,
            orcpt: None,
        }],
        received_from_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        received_via_port: 587,
        flags: 0,
        env_id: None,
        priority: 0,
        size: 10,
        metadata: vec![Metadata::QueueCount { key: 42, id: 1 }].into_boxed_slice(),
        #[cfg(feature = "enterprise")]
        tenant_ids: Box::new([3]),
    }
}

// Queued messages read from v1 carry the u128 quota keys unchanged; an undecodable one is an Error row.
#[tokio::test(flavor = "multi_thread")]
async fn queued_messages_are_typed_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path()).await;
    write(&store, |batch| {
        for queue_id in [2u64, 3] {
            batch.set(
                ValueClass::Queue(QueueClass::Message(queue_id)),
                Archiver::new(message(queue_id * 100))
                    .serialize()
                    .expect("message"),
            );
        }
        batch.set(
            ValueClass::Queue(QueueClass::Message(4)),
            b"not an archive".to_vec(),
        );
    })
    .await;
    let source = V1Source::from_store(store);
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for page in pages(&source, GlobalCategory::Queue, 1).await {
        issues.extend(page.issues);
        let GlobalBatch::Queue(batch) = page.batch else {
            panic!("queue batch");
        };
        records.extend(batch);
    }
    assert_eq!(issues.len(), 1);
    assert_eq!(
        (issues[0].severity, issues[0].kind, &issues[0].subject),
        (
            Severity::Error,
            IssueKind::Skipped,
            &Subject::Registry(RegistryKey::new(QueuedMessageRecord::OBJECT, 4))
        )
    );
    assert_eq!(records.len(), 2);
    let record = &records[1];
    assert_eq!((record.queue_id, record.created), (3, 300));
    assert_eq!(
        record.metadata,
        [QueueMetadata::QuotaCount {
            key: QueueQuotaKey(42),
            id: 1
        }]
    );
    assert_eq!(&record.recipients[0].queue.0, b"remote\0\0");
    assert!(matches!(
        record.recipients[0].status,
        DeliveryStatus::PermanentFailure(_)
    ));
}

// Report headers are read with their (here empty) aggregate rows.
#[tokio::test(flavor = "multi_thread")]
async fn internal_report_headers_are_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path()).await;
    write(&store, |batch| {
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::TlsInternalReport.to_id(),
                item_id: 12,
            }),
            ObjectInner::from(registry::schema::structs::TlsInternalReport {
                domain: "example.org".into(),
                ..Default::default()
            })
            .to_pickled_vec(),
        );
    })
    .await;
    let source = V1Source::from_store(store);
    let [page] = pages(&source, GlobalCategory::Reports, 10)
        .await
        .try_into()
        .expect("one page");
    let GlobalBatch::Reports(records) = page.batch else {
        panic!("reports batch");
    };
    assert_eq!(records.len(), 1);
    assert_eq!((records[0].kind, records[0].id), (ReportKind::Tls, 12));
    assert_eq!(records[0].json["domain"], "example.org");
}

#[cfg(feature = "enterprise")]
mod telemetry {
    use model::{GlobalBatch, GlobalCategory, Source, TelemetryKind};
    use registry::{schema::structs, types::ObjectImpl};
    use store::write::{TelemetryClass, ValueClass};

    use super::{V1Source, pages, store, write};

    // Metrics drop a zero nodeId so they compare with the v0.16 shape.
    #[tokio::test(flavor = "multi_thread")]
    async fn telemetry_is_read_with_the_neutral_metric_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path()).await;
        write(&store, |batch| {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Span(4)),
                structs::Trace::default().to_pickled_vec(),
            );
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Metric(8)),
                structs::Metric::Counter(structs::MetricCount {
                    count: 3,
                    ..Default::default()
                })
                .to_pickled_vec(),
            );
        })
        .await;
        let source = V1Source::from_store(store);
        let mut records = Vec::new();
        for page in pages(&source, GlobalCategory::Telemetry, 1).await {
            let GlobalBatch::Telemetry(batch) = page.batch else {
                panic!("telemetry batch");
            };
            records.extend(batch);
        }
        assert_eq!(
            records
                .iter()
                .map(|record| (record.kind, record.id))
                .collect::<Vec<_>>(),
            [(TelemetryKind::Span, 4), (TelemetryKind::Metric, 8)]
        );
        assert_eq!(records[1].json["count"], 3);
        assert!(records[1].json.get("nodeId").is_none());
    }

    // A pass that ended in metrics resumes at the spans written since.
    #[tokio::test(flavor = "multi_thread")]
    async fn telemetry_resume_finds_new_spans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path()).await;
        write(&store, |batch| {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Span(10)),
                structs::Trace::default().to_pickled_vec(),
            );
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Metric(20)),
                structs::Metric::Counter(structs::MetricCount::default()).to_pickled_vec(),
            );
        })
        .await;
        let source = V1Source::from_store(store.clone());
        let resume = pages(&source, GlobalCategory::Telemetry, 1)
            .await
            .last()
            .and_then(|page| page.resume.clone())
            .expect("resume");
        write(&store, |batch| {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Span(30)),
                structs::Trace::default().to_pickled_vec(),
            );
        })
        .await;
        let page = source
            .global_page(GlobalCategory::Telemetry, Some(&resume), 10)
            .await
            .expect("page");
        let GlobalBatch::Telemetry(batch) = page.batch else {
            panic!("telemetry batch");
        };
        assert_eq!(
            batch
                .iter()
                .map(|record| (record.kind, record.id))
                .collect::<Vec<_>>(),
            [(TelemetryKind::Span, 30)]
        );
    }
}

// Tasks are paged in id order from the v1 task queue, and an undecodable task is an Error row.
#[tokio::test(flavor = "multi_thread")]
async fn tasks_are_read_from_the_task_queue() {
    use registry::schema::structs::{Task, TaskDestroyAccount, TaskStatus};
    use store::write::{TaskId, TaskQueueClass};

    let task = |name: &str| {
        Task::DestroyAccount(TaskDestroyAccount {
            account_name: name.into(),
            status: TaskStatus::at(1_700_000_000),
            ..Default::default()
        })
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path()).await;
    write(&store, |batch| {
        batch
            .schedule_task_with_id(9, task("nine"))
            .schedule_task_with_id(3, task("three"))
            .schedule_task_with_id(5, task("five"));
        batch.set(
            ValueClass::TaskQueue(TaskQueueClass::Task {
                id: TaskId::Assigned(7),
            }),
            b"not a task".to_vec(),
        );
    })
    .await;
    let source = V1Source::from_store(store);
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for page in pages(&source, GlobalCategory::Tasks, 2).await {
        issues.extend(page.issues);
        let GlobalBatch::Tasks(batch) = page.batch else {
            panic!("task batch");
        };
        records.extend(batch);
    }
    let names: Vec<(u64, &serde_json::Value)> = records
        .iter()
        .map(|record| (record.id, &record.json["accountName"]))
        .collect();
    assert_eq!(
        names,
        [
            (3, &serde_json::json!("three")),
            (5, &serde_json::json!("five")),
            (9, &serde_json::json!("nine"))
        ]
    );
    assert_eq!(
        records[0].json,
        serde_json::to_value(task("three")).expect("task json")
    );
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(
        (issues[0].severity, &issues[0].subject),
        (
            Severity::Error,
            &Subject::Registry(RegistryKey::new(model::TaskRecord::OBJECT, 7))
        )
    );
}

// Canonical task keys are the ids v1 stores them under: singleton tasks move to their singleton id, others keep theirs.
#[tokio::test(flavor = "multi_thread")]
async fn singleton_tasks_are_keyed_like_the_task_queue() {
    use registry::schema::{
        enums::TaskAccountMaintenanceType,
        structs::{Task, TaskAccountMaintenance, TaskDestroyAccount, TaskStatus},
    };
    use types::id::Id;

    let maintenance = Task::AccountMaintenance(TaskAccountMaintenance {
        account_id: Id::new(4),
        maintenance_type: TaskAccountMaintenanceType::Purge,
        status: TaskStatus::at(1_700_000_000),
    });
    let destroy = Task::DestroyAccount(TaskDestroyAccount {
        account_name: "four".into(),
        status: TaskStatus::at(1_700_000_000),
        ..Default::default()
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let store = store(dir.path()).await;
    let (maintenance_json, destroy_json) = (
        serde_json::to_value(&maintenance).expect("task json"),
        serde_json::to_value(&destroy).expect("task json"),
    );
    write(&store, |batch| {
        batch
            .schedule_task(maintenance)
            .schedule_task_with_id(11, destroy);
    })
    .await;
    let source = V1Source::from_store(store);
    let mut stored = Vec::new();
    for page in pages(&source, GlobalCategory::Tasks, 10).await {
        let GlobalBatch::Tasks(batch) = page.batch else {
            panic!("task batch");
        };
        stored.extend(batch.into_iter().map(|record| (record.id, record.json)));
    }
    let singleton = stored
        .iter()
        .find(|(id, _)| *id != 11)
        .map(|(id, _)| *id)
        .expect("singleton task");
    let canonical = |id: u64, json: serde_json::Value| {
        source
            .canonical_registry(model::RegistryRecord {
                key: RegistryKey::new("x:Task", id),
                json,
            })
            .expect("canonical task")
    };
    let record = canonical(2, maintenance_json.clone());
    assert_eq!(record.key, RegistryKey::new("x:Task", singleton));
    assert_eq!(record.json, maintenance_json);
    assert!(crate::is_singleton_task(&maintenance_json));
    assert!(!crate::is_singleton_task(&destroy_json));
    let record = canonical(11, destroy_json);
    assert_eq!(record.key, RegistryKey::new("x:Task", 11));
}

// Ids v1 derives for its own tasks (singleton, per-document target, shared-object cleanup) are recognised; snowflake and per-document ids are not.
#[test]
fn derived_task_ids_are_recognised() {
    use registry::schema::enums::TaskType;
    use store::write::TaskId;
    use types::{collection::Collection, id::Id};

    for id in [
        TaskId::singleton(TaskType::AccountMaintenance, 1, 4),
        TaskId::document_target(4, 7, 9),
        TaskId::shared_object(4, Collection::Mailbox, 7, 123),
        TaskId::shared_object(u32::MAX >> 2, Collection::FileNode, u32::MAX, u64::MAX),
    ] {
        assert!(crate::is_derived_task_id(id), "{id:#x}");
    }
    assert!(crate::is_singleton_task_id(TaskId::singleton(
        TaskType::AccountMaintenance,
        1,
        4
    )));
    for id in [
        TaskId::document_target(4, 7, 9),
        TaskId::shared_object(4, Collection::Mailbox, 7, 123),
        11,
    ] {
        assert!(!crate::is_singleton_task_id(id), "{id:#x}");
    }
    for id in [0, 11, Id::from_parts((1 << 30) - 1, u32::MAX).id(), 1 << 61] {
        assert!(!crate::is_derived_task_id(id), "{id:#x}");
    }
}
