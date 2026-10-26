/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, Ipv4Addr};

use common::{
    config::{
        mailstore::spamfilter::SpamClassifier,
        smtp::queue::{QueueExpiry, QueueName},
    },
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use model::{
    BlobHash, DeliveryError, DeliveryStatus, GlobalBatch, GlobalCategory, GlobalPage,
    QueueMetadata, QueueQuotaKey, ReportKind, Severity, Source, SpamClassifierModel,
    SpamModelRecord, SpamOptimizer, TelemetryKind,
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
        structs,
    },
    types::{EnumImpl, ObjectImpl},
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse, Message, Metadata, Recipient, Schedule, Status,
};
use smtp_proto::Response;
use spam_filter::modules::classifier::{SpamTrainer, SpamTrainerClass, TrainingSample};
use store::{
    Store,
    rkyv::{self, rancor},
    write::{BatchBuilder, QueueClass, RegistryClass, TelemetryClass, ValueClass},
};
use types::{blob_hash::BlobHash as V016BlobHash, id::Id};

use super::tests::source;
use crate::testkit::{archive, rocks};

const QUOTA_HASH: [u8; 32] = [7; 32];

async fn write(path: &std::path::Path, build: impl FnOnce(&mut BatchBuilder)) {
    let store = Store::build(rocks(path)).await.expect("writer");
    let mut batch = BatchBuilder::new();
    build(&mut batch);
    store.write(batch.build_all()).await.expect("write");
}

async fn pages(source: &impl Source, category: GlobalCategory, limit: usize) -> Vec<GlobalPage> {
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
    hash: V016BlobHash,
    account_id: u32,
}

fn sample(byte: u8, account_id: u32) -> TrainingSample {
    let bytes = rkyv::to_bytes::<rancor::Error>(&SampleSeed {
        hash: V016BlobHash([byte; 32]),
        account_id,
    })
    .expect("sample bytes");
    rkyv::from_bytes::<TrainingSample, rancor::Error>(&bytes).expect("sample")
}

// The spam model mirrors decode archives written with the real v0.16 types.
#[tokio::test]
async fn spam_model_mirrors_match_the_v016_types() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fh = FhTrainer::new(
        Ftrl::new(4)
            .with_hyperparams(3.0, 1.5, 0.01, 0.02)
            .with_initial_weights(0.25),
    );
    let classifier = fh.build_classifier();
    let parameters = classifier.parameters().to_vec();
    let bias = classifier.bias();
    let ccfh = CcfhTrainer::new(
        Ftrl::new(2).with_initial_weights(0.5),
        Ftrl::new(3).with_initial_weights(-0.5),
    );
    let trainer = SpamTrainer {
        trainer: SpamTrainerClass::FtrlCfh(Box::new(ccfh)),
        reservoir: SampleReservoir {
            spam: SampleReservoirClass {
                buffer: vec![sample(1, 10), sample(2, 11)],
                total_seen: 5,
            },
            ham: SampleReservoirClass {
                buffer: vec![sample(3, 12)],
                total_seen: 9,
            },
        },
        last_id: 77,
    };
    let fh_trainer = SpamTrainer {
        trainer: SpamTrainerClass::FtrlFh(Box::new(fh)),
        reservoir: SampleReservoir {
            spam: SampleReservoirClass {
                buffer: Vec::new(),
                total_seen: 0,
            },
            ham: SampleReservoirClass {
                buffer: Vec::new(),
                total_seen: 0,
            },
        },
        last_id: 1,
    };
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let blob = store::BlobStore::Store(store.clone());
        blob.put_blob(
            SPAM_CLASSIFIER_KEY,
            &archive(SpamClassifier::FhClassifier {
                classifier,
                last_trained_at: 1234,
            }),
            CompressionAlgo::None,
        )
        .await
        .expect("classifier");
        blob.put_blob(SPAM_TRAINER_KEY, &archive(trainer), CompressionAlgo::None)
            .await
            .expect("trainer");
    }
    let source = source(dir.path()).await;
    let [page] = pages(&source, GlobalCategory::SpamModel, 10)
        .await
        .try_into()
        .expect("one page");
    assert!(page.issues.is_empty(), "{:?}", page.issues);
    let GlobalBatch::SpamModel(records) = page.batch else {
        panic!("spam model batch");
    };
    let [
        SpamModelRecord::Trainer(trainer),
        SpamModelRecord::Classifier(classifier),
    ] = records.as_slice()
    else {
        panic!("trainer and classifier: {records:?}");
    };
    assert_eq!(
        classifier,
        &SpamClassifierModel::Fh {
            parameters,
            bias,
            last_trained_at: 1234,
        }
    );
    let SpamOptimizer::Ccfh {
        weights,
        indicators,
    } = &trainer.optimizer
    else {
        panic!("ccfh trainer");
    };
    assert_eq!((weights.alpha, weights.beta), (2.0, 1.0));
    assert_eq!(weights.zn.len(), 2);
    assert!(weights.zn.iter().all(|zn| zn.z == 0.5 && zn.n == 0.0));
    assert_eq!(indicators.zn.len(), 3);
    assert!(indicators.zn.iter().all(|zn| zn.z == -0.5));
    assert_eq!(trainer.last_id, 77);
    assert_eq!(trainer.spam.total_seen, 5);
    assert_eq!(trainer.ham.total_seen, 9);
    assert_eq!(
        trainer
            .spam
            .samples
            .iter()
            .map(|sample| (sample.blob_hash, sample.account_id))
            .collect::<Vec<_>>(),
        [(BlobHash([1; 32]), 10), (BlobHash([2; 32]), 11)]
    );
    assert_eq!(trainer.ham.samples[0].blob_hash, BlobHash([3; 32]));

    let model = super::global::spam::decode_trainer(&archive(fh_trainer)).expect("fh trainer");
    let SpamModelRecord::Trainer(model) = model else {
        panic!("trainer");
    };
    let SpamOptimizer::Fh(ftrl) = &model.optimizer else {
        panic!("fh trainer");
    };
    assert_eq!(
        (ftrl.alpha, ftrl.beta, ftrl.l1_ratio, ftrl.l2_ratio),
        (3.0, 1.5, 0.01, 0.02)
    );
    assert!(ftrl.zn.iter().all(|zn| zn.z == 0.25));
}

// An unreadable spam model is a warning and v1 retrains.
#[tokio::test]
async fn undecodable_spam_model_is_an_issue() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        store::BlobStore::Store(store)
            .put_blob(SPAM_CLASSIFIER_KEY, b"garbage", CompressionAlgo::None)
            .await
            .expect("classifier");
    }
    let source = source(dir.path()).await;
    let page = source
        .global_page(GlobalCategory::SpamModel, None, 10)
        .await
        .expect("page");
    assert!(page.batch.is_empty());
    assert_eq!(page.issues.len(), 1);
}

fn message(created: u64) -> Message {
    let response = |message: &str| Response {
        code: 250,
        esc: [2, 0, 0],
        message: Box::from(message),
    };
    let recipient = |address: &str, status| Recipient {
        address: Box::from(address),
        retry: Schedule {
            due: created + 60,
            inner: 2,
        },
        notify: Schedule {
            due: created + 3600,
            inner: 1,
        },
        expires: QueueExpiry::Ttl(created + 86400),
        queue: QueueName::new("default").expect("queue name"),
        status,
        flags: 4,
        orcpt: Some(Box::from("rfc822;x@example.org")),
    };
    Message {
        created,
        blob_hash: V016BlobHash([9; 32]),
        return_path: Box::from("sender@example.org"),
        recipients: vec![
            recipient("a@example.net", Status::Scheduled),
            recipient(
                "b@example.net",
                Status::Completed(HostResponse {
                    hostname: Box::from("mx.example.net"),
                    response: response("ok"),
                }),
            ),
            recipient(
                "c@example.net",
                Status::TemporaryFailure(ErrorDetails {
                    entity: Box::from("mx.example.net"),
                    details: Error::UnexpectedResponse(smtp::queue::UnexpectedResponse {
                        command: Box::from("RCPT TO"),
                        response: response("busy"),
                    }),
                }),
            ),
        ],
        received_from_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        received_via_port: 25,
        flags: 1 << 32,
        env_id: Some(Box::from("env")),
        priority: -1,
        size: 1234,
        metadata: vec![
            Metadata::QueueSize {
                key: Box::from(QUOTA_HASH),
                id: 3,
            },
            Metadata::Headers {
                value: Box::from(&b"X-Test: 1\r\n"[..]),
                id: 4,
            },
        ]
        .into_boxed_slice(),
    }
}

// Queued messages are paged by queue id; undecodable ones become issues.
#[tokio::test]
async fn queued_messages_are_typed_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        for queue_id in [5u64, 9, 11] {
            batch.set(
                ValueClass::Queue(QueueClass::Message(queue_id)),
                archive(message(1_000 + queue_id)),
            );
        }
        batch.set(
            ValueClass::Queue(QueueClass::Message(7)),
            b"not an archive".to_vec(),
        );
    })
    .await;
    let source = source(dir.path()).await;
    let pages = pages(&source, GlobalCategory::Queue, 2).await;
    assert_eq!(pages.len(), 3);
    let mut records = Vec::new();
    let mut issues = Vec::new();
    for page in pages {
        let GlobalBatch::Queue(batch) = page.batch else {
            panic!("queue batch");
        };
        records.extend(batch);
        issues.extend(page.issues);
    }
    assert_eq!(
        records
            .iter()
            .map(|record| record.queue_id)
            .collect::<Vec<_>>(),
        [5, 9, 11]
    );
    assert_eq!(issues.len(), 1);
    assert!(issues.iter().all(|issue| issue.severity == Severity::Error));
    let record = &records[0];
    assert_eq!(record.created, 1_005);
    assert_eq!(record.blob_hash, BlobHash([9; 32]));
    assert_eq!(record.size, 1234);
    assert_eq!(&*record.return_path, "sender@example.org");
    assert_eq!(record.priority, -1);
    assert_eq!(record.env_id.as_deref(), Some("env"));
    assert_eq!(
        record.metadata[0],
        QueueMetadata::QuotaSize {
            key: QueueQuotaKey(u128::from_be_bytes([7; 16])),
            id: 3,
        }
    );
    let [scheduled, completed, failed] = record.recipients.as_slice() else {
        panic!("three recipients");
    };
    assert_eq!(scheduled.status, DeliveryStatus::Scheduled);
    assert_eq!(scheduled.retry.due, 1_065);
    assert_eq!(scheduled.retry.attempt, 2);
    assert_eq!(&scheduled.queue.0, b"default\0");
    assert_eq!(scheduled.expires, model::QueueExpiry::Ttl(87_405));
    let DeliveryStatus::Completed(host) = &completed.status else {
        panic!("completed");
    };
    assert_eq!(&*host.hostname, "mx.example.net");
    assert_eq!(host.response.esc, [2, 0, 0]);
    let DeliveryStatus::TemporaryFailure(failure) = &failed.status else {
        panic!("temporary failure");
    };
    assert!(matches!(
        &failure.error,
        DeliveryError::UnexpectedResponse { command, .. } if &**command == "RCPT TO"
    ));
}

// Internal DMARC and TLS reports are read from the registry, DMARC first; TLS policies and their identifiers (9, 10, 2: neither numeric nor string order) come out paired and in numeric order.
#[tokio::test]
async fn internal_reports_are_paged_by_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        for item_id in [3u64, 4] {
            batch.set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: ObjectType::DmarcInternalReport.to_id(),
                    item_id,
                }),
                ObjectInner::DmarcInternalReport(structs::DmarcInternalReport {
                    domain: format!("d{item_id}.example.org"),
                    policy_identifier: item_id,
                    report: structs::DmarcReport {
                        records: vec![
                            structs::DmarcReportRecord {
                                count: 5,
                                ..Default::default()
                            },
                            structs::DmarcReportRecord {
                                count: 7,
                                ..Default::default()
                            },
                        ]
                        .into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .to_pickled_vec(),
            );
        }
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::TlsInternalReport.to_id(),
                item_id: 2,
            }),
            ObjectInner::TlsInternalReport(structs::TlsInternalReport {
                domain: "tls.example.org".into(),
                policy_identifiers: registry::types::map::Map::new(TLS_POLICIES.to_vec()),
                report: structs::TlsReport {
                    policies: TLS_POLICIES
                        .iter()
                        .map(|identifier| structs::TlsReportPolicy {
                            policy_domain: format!("p{identifier}"),
                            ..Default::default()
                        })
                        .collect::<Vec<_>>()
                        .into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .to_pickled_vec(),
        );
    })
    .await;
    let source = source(dir.path()).await;
    let mut records = Vec::new();
    for page in pages(&source, GlobalCategory::Reports, 1).await {
        let GlobalBatch::Reports(batch) = page.batch else {
            panic!("reports batch");
        };
        records.extend(batch);
    }
    assert_eq!(
        records
            .iter()
            .map(|record| (record.kind, record.id))
            .collect::<Vec<_>>(),
        [
            (ReportKind::Dmarc, 3),
            (ReportKind::Dmarc, 4),
            (ReportKind::Tls, 2)
        ]
    );
    assert_eq!(records[0].json["domain"], "d3.example.org");
    assert_eq!(records[0].json["report"]["records"]["1"]["count"], 7);
    assert_eq!(records[2].json["domain"], "tls.example.org");
    let mut ordered = TLS_POLICIES;
    ordered.sort_unstable();
    let mut identifiers: Vec<u64> = records[2].json["policyIdentifiers"]
        .as_object()
        .expect("identifier set")
        .keys()
        .map(|identifier| identifier.parse().expect("numeric identifier"))
        .collect();
    identifiers.sort_unstable();
    assert_eq!(identifiers, ordered);
    for (index, identifier) in ordered.iter().enumerate() {
        assert_eq!(
            records[2].json["report"]["policies"][index.to_string()]["policyDomain"],
            format!("p{identifier}"),
            "{}",
            records[2].json
        );
    }
}

const TLS_POLICIES: [u64; 3] = [9, 10, 2];

// Spans then metrics, paged across the kind boundary with exact cursors.
#[tokio::test]
async fn telemetry_pages_cross_from_spans_to_metrics() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        for id in [1u64, 2, 3] {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Span(id)),
                structs::Trace::default().to_pickled_vec(),
            );
        }
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Span(u64::MAX)),
            b"bad".to_vec(),
        );
        for id in [10u64, 20] {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Metric(id)),
                structs::Metric::Counter(structs::MetricCount {
                    count: id,
                    ..Default::default()
                })
                .to_pickled_vec(),
            );
        }
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::TracingStore.to_id(),
                item_id: Id::singleton().id(),
            }),
            ObjectInner::TracingStore(structs::TracingStore::Default).to_pickled_vec(),
        );
    })
    .await;
    let source = source(dir.path()).await;
    let mut seen = Vec::new();
    let mut issues = 0;
    for limit in [1, 2, 3, 100] {
        seen.clear();
        issues = 0;
        for page in pages(&source, GlobalCategory::Telemetry, limit).await {
            let GlobalBatch::Telemetry(batch) = page.batch else {
                panic!("telemetry batch");
            };
            seen.extend(batch.into_iter().map(|record| (record.kind, record.id)));
            issues += page.issues.len();
        }
        assert_eq!(
            seen,
            [
                (TelemetryKind::Span, 1),
                (TelemetryKind::Span, 2),
                (TelemetryKind::Span, 3),
                (TelemetryKind::Metric, 10),
                (TelemetryKind::Metric, 20),
            ],
            "limit {limit}"
        );
        assert_eq!(issues, 1, "limit {limit}");
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(issues, 1);
}

// Task rows are read with their own id and the registry JSON of the task.
#[tokio::test]
async fn tasks_are_read_as_registry_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        for id in [4u64, 9] {
            batch.schedule_task_with_id(
                id,
                structs::Task::AccountMaintenance(structs::TaskAccountMaintenance {
                    account_id: Id::new(id + 100),
                    maintenance_type: Default::default(),
                    status: structs::TaskStatus::at(1_700_000_000),
                }),
            );
        }
        batch.set(
            ValueClass::TaskQueue(store::write::TaskQueueClass::Task { id: 6 }),
            b"bad".to_vec(),
        );
    })
    .await;
    let source = source(dir.path()).await;
    let mut records = Vec::new();
    let mut issues = 0;
    for page in pages(&source, GlobalCategory::Tasks, 2).await {
        let GlobalBatch::Tasks(batch) = page.batch else {
            panic!("tasks batch");
        };
        records.extend(batch);
        assert!(
            page.issues
                .iter()
                .all(|issue| issue.severity == Severity::Error)
        );
        issues += page.issues.len();
    }
    assert_eq!(issues, 1);
    assert_eq!(
        records.iter().map(|record| record.id).collect::<Vec<_>>(),
        [4, 9]
    );
    assert_eq!(records[0].task_type(), Some("AccountMaintenance"));
    assert_eq!(records[1].json["status"]["@type"], "Pending");
}

// An unreachable external tracing store only fails the telemetry category.
#[tokio::test]
async fn telemetry_store_opens_only_for_telemetry() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::TracingStore.to_id(),
                item_id: Id::singleton().id(),
            }),
            ObjectInner::TracingStore(structs::TracingStore::PostgreSql(
                structs::PostgreSqlStore {
                    host: "127.0.0.1".into(),
                    port: 1,
                    ..Default::default()
                },
            ))
            .to_pickled_vec(),
        );
    })
    .await;
    let source = source(dir.path()).await;
    for category in [
        GlobalCategory::Queue,
        GlobalCategory::Reports,
        GlobalCategory::Tasks,
        GlobalCategory::SpamModel,
    ] {
        source
            .global_page(category, None, 10)
            .await
            .expect("category without telemetry");
    }
    assert!(
        source
            .global_page(GlobalCategory::Telemetry, None, 10)
            .await
            .is_err()
    );
}

// The cursor stored at the end of a pass revisits spans after the pass ended in metrics (the recent span 10 and metric 20 are read again within their lookbacks).
#[tokio::test]
async fn telemetry_resume_finds_new_spans() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
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
    let resume = {
        let source = source(dir.path()).await;
        let pages = pages(&source, GlobalCategory::Telemetry, 1).await;
        pages
            .last()
            .and_then(|page| page.resume.clone())
            .expect("resume")
    };
    write(dir.path(), |batch| {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Span(30)),
            structs::Trace::default().to_pickled_vec(),
        );
    })
    .await;
    let source = source(dir.path()).await;
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
        [
            (TelemetryKind::Span, 10),
            (TelemetryKind::Span, 30),
            (TelemetryKind::Metric, 20)
        ]
    );
}

fn span_id(millis: u64) -> u64 {
    millis << 21
}

async fn resumed_ids(
    dir: &std::path::Path,
    resume: &[u8],
    kind: TelemetryKind,
) -> (Vec<u64>, Vec<u8>) {
    let source = source(dir).await;
    let mut cursor = Some(resume.to_vec());
    let mut ids = Vec::new();
    loop {
        let page = source
            .global_page(GlobalCategory::Telemetry, cursor.as_deref(), 2)
            .await
            .expect("page");
        let GlobalBatch::Telemetry(batch) = page.batch else {
            panic!("telemetry batch");
        };
        ids.extend(
            batch
                .iter()
                .filter(|record| record.kind == kind)
                .map(|record| record.id),
        );
        match page.next {
            Some(next) => cursor = Some(next),
            None => return (ids, page.resume.expect("resume")),
        }
    }
}

// A metric id is taken before its batch commits, so a slow commit can store a smaller id after a larger one was read: the next pass looks back ten minutes of metric ids.
#[tokio::test]
async fn late_metrics_below_the_resume_cursor_are_found() {
    const MINUTE: u64 = 60_000;
    let metric = || structs::Metric::Counter(structs::MetricCount::default()).to_pickled_vec();
    let start = 1_000 * MINUTE;
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Metric(span_id(start))),
            metric(),
        );
    })
    .await;
    let resume = {
        let source = source(dir.path()).await;
        let pages = pages(&source, GlobalCategory::Telemetry, 2).await;
        pages
            .last()
            .and_then(|page| page.resume.clone())
            .expect("resume")
    };
    let late = span_id(start - 5 * MINUTE);
    let too_late = span_id(start - 20 * MINUTE);
    write(dir.path(), |batch| {
        for id in [late, too_late] {
            batch.set(ValueClass::Telemetry(TelemetryClass::Metric(id)), metric());
        }
    })
    .await;
    let (ids, _) = resumed_ids(dir.path(), &resume, TelemetryKind::Metric).await;
    assert_eq!(ids, [late, span_id(start)]);
}

// v0.16 stores a span when it ends, under the id it got when it started, so a span stored after a pass can sort below the resume cursor: the next pass looks back six hours of span ids.
#[tokio::test]
async fn late_spans_below_the_resume_cursor_are_found() {
    const HOUR: u64 = 3_600_000;
    assert_eq!(
        utils::snowflake::SnowflakeIdGenerator::to_timestamp(TelemetryKind::Span.lookback())
            - utils::snowflake::SnowflakeIdGenerator::to_timestamp(0),
        6 * 3600
    );
    let start = 100 * HOUR;
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), |batch| {
        for millis in [start, start + 8 * HOUR] {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Span(span_id(millis))),
                structs::Trace::default().to_pickled_vec(),
            );
        }
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Metric(20)),
            structs::Metric::Counter(structs::MetricCount::default()).to_pickled_vec(),
        );
    })
    .await;
    let resume = {
        let source = source(dir.path()).await;
        let pages = pages(&source, GlobalCategory::Telemetry, 2).await;
        pages
            .last()
            .and_then(|page| page.resume.clone())
            .expect("resume")
    };
    let late = span_id(start + 8 * HOUR - 30 * 60_000);
    let too_late = span_id(start + HOUR);
    let newer = span_id(start + 9 * HOUR);
    write(dir.path(), |batch| {
        for id in [late, too_late, newer] {
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Span(id)),
                structs::Trace::default().to_pickled_vec(),
            );
        }
    })
    .await;
    let (ids, resume) = resumed_ids(dir.path(), &resume, TelemetryKind::Span).await;
    assert_eq!(ids, [late, span_id(start + 8 * HOUR), newer]);
    let (ids, _) = resumed_ids(dir.path(), &resume, TelemetryKind::Span).await;
    assert_eq!(ids, [late, span_id(start + 8 * HOUR), newer]);
}
