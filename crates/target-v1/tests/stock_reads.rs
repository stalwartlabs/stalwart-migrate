/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::path::Path;

use common::auth::AccessToken;
use jmap::{
    calendar_event_notification::get::CalendarEventNotificationGet, registry::get::RegistryGet,
};
use jmap_proto::{
    method::get::GetRequest,
    request::reference::{MaybeIdReference, MaybeResultReference},
};
use model::{
    CalendarEventRecord, CalendarRecord, DavNameRecord, Edition, EventNotificationRecord,
    GlobalBatch, InternalReportRecord, RecordBatch, RegistryKey, RegistryRecord, ReportKind,
    Target, WriteMode,
};
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{DmarcInternalReport, TlsInternalReport},
    },
    types::datetime::UTCDateTime,
};
use serde_json::{Value, json};
use target_v1::{TargetConfig, V1Target};
use types::id::Id;

const ACCOUNT_ID: u32 = 7;
#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const INVITE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:invite-1@example.org\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20300101T100000Z\r\nDTEND:20300101T110000Z\r\nSUMMARY:Planning\r\nORGANIZER:mailto:alice@example.org\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

async fn booted_target(dir: &Path) -> V1Target {
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
    let outcome = target
        .write_registry(&[
            RegistryRecord {
                key: RegistryKey::new("Domain", 3),
                json: json!({"name": "example.org"}),
            },
            RegistryRecord {
                key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
                json: json!({"@type": "User", "name": "bob", "domainId": "d"}),
            },
        ])
        .await
        .expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    target
}

async fn upsert(target: &V1Target, batch: RecordBatch) {
    let outcome = target
        .upsert(ACCOUNT_ID, &batch, WriteMode::Create)
        .await
        .expect("upsert");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
}

const REPLY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:invite-1@example.org\r\nDTSTAMP:20260102T000000Z\r\nORGANIZER:mailto:alice@example.org\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const CANCEL: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nMETHOD:CANCEL\r\nBEGIN:VEVENT\r\nUID:invite-1@example.org\r\nDTSTAMP:20260103T000000Z\r\nSEQUENCE:1\r\nORGANIZER:mailto:alice@example.org\r\nATTENDEE:mailto:bob@example.org\r\nSTATUS:CANCELLED\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

// Migrated scheduling notifications show their event through the stock JMAP CalendarEventNotification/get: for a message that updated an existing event (REPLY, CANCEL, or any change notification) that is the stored event, as stock v1 keeps the merged event; a new-event REQUEST shows its own message.
#[tokio::test(flavor = "multi_thread")]
async fn notification_event_is_served_by_stock_get() {
    const IS_CHANGE: u16 = 1 << 1;
    let moved = INVITE.replace("SUMMARY:Planning", "SUMMARY:Moved");
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    upsert(
        &target,
        RecordBatch::Calendar(vec![CalendarRecord {
            document_id: 2,
            name: "default".into(),
            created: 1_600_000_000,
            modified: 1_600_000_000,
            ..Default::default()
        }]),
    )
    .await;
    upsert(
        &target,
        RecordBatch::CalendarEvent(vec![CalendarEventRecord {
            document_id: 6,
            names: vec![DavNameRecord {
                name: "invite-1.ics".into(),
                parent_id: 2,
            }],
            icalendar: INVITE.replace("METHOD:REQUEST\r\n", ""),
            created: 1_610_000_000,
            modified: 1_610_000_000,
            ..Default::default()
        }]),
    )
    .await;
    upsert(
        &target,
        RecordBatch::CalendarEventNotification(
            [
                (INVITE.to_string(), 0),
                (REPLY.to_string(), 0),
                (CANCEL.to_string(), 0),
                (moved.clone(), IS_CHANGE),
                (moved, 0),
            ]
            .into_iter()
            .zip(1..)
            .map(
                |((icalendar, flags), document_id)| EventNotificationRecord {
                    document_id,
                    icalendar,
                    event_id: Some(6),
                    flags,
                    created: 1_610_000_000,
                    modified: 1_610_000_000,
                    ..Default::default()
                },
            )
            .collect(),
        ),
    )
    .await;
    let server = target.server().expect("server");
    let response = server
        .calendar_event_notification_get(
            GetRequest {
                account_id: Id::from(ACCOUNT_ID),
                ids: None,
                properties: None,
                arguments: Default::default(),
            },
            &AccessToken::from_id_maybe_invalid(ACCOUNT_ID),
        )
        .await
        .expect("get");
    let response = serde_json::to_value(&response).expect("json");
    let list = response["list"].as_array().expect("list");
    assert_eq!(list.len(), 5, "{response}");
    for notification in list {
        let event = &notification["event"];
        assert_ne!(event, &Value::Null, "{response}");
        let expected = if notification["id"] == Id::from(5u32).to_string() {
            "Moved"
        } else {
            "Planning"
        };
        assert_eq!(event["title"], expected, "{notification}");
        if notification["id"] == Id::from(4u32).to_string() {
            assert_eq!(notification["eventPatch"], json!({}), "{notification}");
        }
    }
}

const NOW: i64 = 1_900_000_000;
const INTERNAL_ID: u64 = 0x1111_2222_3333_4444;
const EXTERNAL_ID: u64 = 0x0000_0000_0000_0042;
const TLS_ID: u64 = 0x1111_2222_3333_5555;

async fn registry_get(target: &V1Target, object: ObjectType, id: Option<u64>) -> Value {
    let ids = id.map(|id| MaybeResultReference::Value(vec![MaybeIdReference::Id(Id::from(id))]));
    let response = target
        .server()
        .expect("server")
        .registry_get(
            object,
            GetRequest {
                account_id: Id::from(ACCOUNT_ID),
                ids,
                properties: None,
                arguments: Default::default(),
            },
            &AccessToken::from_id_maybe_invalid(ACCOUNT_ID),
        )
        .await
        .expect("registry get");
    serde_json::to_value(&response).expect("json")
}

fn listed_ids(response: &Value) -> Vec<String> {
    response["list"]
        .as_array()
        .expect("list")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_string())
        .collect()
}

// Migrated internal and external reports are listed and fetched by id through the stock JMAP registry get.
#[tokio::test(flavor = "multi_thread")]
async fn reports_are_served_by_stock_get() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let mut internal = DmarcInternalReport {
        domain: "example.net".into(),
        policy_identifier: 42,
        created_at: UTCDateTime::from_timestamp(NOW),
        deliver_at: UTCDateTime::from_timestamp(NOW + 86_400),
        ..Default::default()
    };
    internal.report.report_id = "r1".into();
    internal.report.date_range_end = UTCDateTime::from_timestamp(NOW + 86_000);
    let mut tls = TlsInternalReport {
        domain: "example.net".into(),
        policy_identifiers: vec![7u64].into(),
        created_at: UTCDateTime::from_timestamp(NOW),
        deliver_at: UTCDateTime::from_timestamp(NOW + 86_400),
        ..Default::default()
    };
    tls.report.report_id = "t1".into();
    tls.report.date_range_end = UTCDateTime::from_timestamp(NOW + 86_000);
    let outcome = target
        .write_global(&GlobalBatch::Reports(vec![
            InternalReportRecord {
                kind: ReportKind::Dmarc,
                id: INTERNAL_ID,
                json: serde_json::to_value(internal).expect("internal json"),
            },
            InternalReportRecord {
                kind: ReportKind::Tls,
                id: TLS_ID,
                json: serde_json::to_value(tls).expect("tls json"),
            },
        ]))
        .await
        .expect("internal report");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    for expires in ["2030-06-01T00:00:00Z", "2031-01-01T00:00:00Z"] {
        let outcome = target
            .write_registry(&[external_report(expires)])
            .await
            .expect("external report");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }

    for (object, id) in [
        (ObjectType::DmarcInternalReport, INTERNAL_ID),
        (ObjectType::TlsInternalReport, TLS_ID),
        (ObjectType::DmarcExternalReport, EXTERNAL_ID),
    ] {
        let expected = vec![Id::from(id).to_string()];
        let by_id = registry_get(&target, object, Some(id)).await;
        assert_eq!(listed_ids(&by_id), expected, "{object:?} by id: {by_id}");
        let all = registry_get(&target, object, None).await;
        assert_eq!(listed_ids(&all), expected, "{object:?} listing: {all}");
    }
    let external = registry_get(&target, ObjectType::DmarcExternalReport, None).await;
    assert_eq!(
        external["list"][0]["expiresAt"], "2031-01-01T00:00:00Z",
        "{external}"
    );
    target
        .delete_registry(&[RegistryKey::new("DmarcExternalReport", EXTERNAL_ID)])
        .await
        .expect("delete");
    let all = registry_get(&target, ObjectType::DmarcExternalReport, None).await;
    assert_eq!(listed_ids(&all), Vec::<String>::new(), "{all}");

    let outcome = target
        .write_registry(&[
            external_report("2030-06-01T00:00:00Z"),
            external_report("2031-01-01T00:00:00Z"),
        ])
        .await
        .expect("external report twice");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let all = registry_get(&target, ObjectType::DmarcExternalReport, None).await;
    assert_eq!(
        listed_ids(&all),
        vec![Id::from(EXTERNAL_ID).to_string()],
        "{all}"
    );
    assert_eq!(all["list"][0]["expiresAt"], "2031-01-01T00:00:00Z", "{all}");
}

fn external_report(expires_at: &str) -> RegistryRecord {
    RegistryRecord {
        key: RegistryKey::new("DmarcExternalReport", EXTERNAL_ID),
        json: json!({
            "from": "noreply@example.com",
            "subject": "Report",
            "receivedAt": "2030-01-01T00:00:00Z",
            "expiresAt": expires_at,
            "report": {"reportId": "x1", "email": "dmarc@example.com", "orgName": "Example", "policyDomain": "example.org"},
        }),
    }
}

fn external_report_with(id: u64, report_id: &str) -> RegistryRecord {
    let mut record = external_report("2030-06-01T00:00:00Z");
    record.key = RegistryKey::new("DmarcExternalReport", id);
    record.json["report"]["reportId"] = report_id.into();
    record
}

// A report whose report id is held by another stored report fails alone with a record issue, and is written once the other report is deleted or moves to a new report id.
#[tokio::test(flavor = "multi_thread")]
async fn report_id_clash_is_a_record_issue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let listed = async || {
        let all = registry_get(&target, ObjectType::DmarcExternalReport, None).await;
        let mut ids = listed_ids(&all);
        ids.sort_unstable();
        ids
    };
    let clashing = |outcome: &model::WriteOutcome, id: u64| {
        assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
        assert_eq!(
            outcome.issues[0].subject,
            model::Subject::Registry(RegistryKey::new("DmarcExternalReport", id))
        );
        assert_eq!(outcome.issues[0].severity, model::Severity::Error);
        assert_eq!(
            outcome.issues[0].rejection,
            Some(model::Rejection::Conflict)
        );
    };
    let first = external_report_with(EXTERNAL_ID, "x1");
    let second = external_report_with(EXTERNAL_ID + 1, "x1");
    let outcome = target
        .write_registry(&[first.clone(), second.clone()])
        .await
        .expect("same page");
    clashing(&outcome, EXTERNAL_ID + 1);
    let outcome = target
        .write_registry(std::slice::from_ref(&second))
        .await
        .expect("later page");
    clashing(&outcome, EXTERNAL_ID + 1);
    assert_eq!(listed().await, vec![Id::from(EXTERNAL_ID).to_string()]);

    target
        .delete_registry(&[RegistryKey::new("DmarcExternalReport", EXTERNAL_ID)])
        .await
        .expect("delete");
    let outcome = target
        .write_registry(std::slice::from_ref(&second))
        .await
        .expect("after delete");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    assert_eq!(listed().await, vec![Id::from(EXTERNAL_ID + 1).to_string()]);

    let outcome = target
        .write_registry(&[
            external_report_with(EXTERNAL_ID + 1, "x2"),
            external_report_with(EXTERNAL_ID + 2, "x1"),
        ])
        .await
        .expect("moved report id");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let mut expected = vec![
        Id::from(EXTERNAL_ID + 1).to_string(),
        Id::from(EXTERNAL_ID + 2).to_string(),
    ];
    expected.sort_unstable();
    assert_eq!(listed().await, expected);
}

// An archived email without From or Subject (a draft) is stored as stock v1 archives it, read and listed through the stock registry paths, and deleted.
#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread")]
async fn archived_draft_without_from_is_stored_like_stock() {
    use registry::{
        schema::prelude::{Object, ObjectInner, Property},
        types::EnumImpl,
    };
    use store::{
        ValueKey,
        registry::RegistryQuery,
        write::{RegistryClass, ValueClass},
    };

    const ARCHIVED_ID: u64 = 0x0000_0000_0000_0077;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let blob_id = types::blob::BlobId::new(
        types::blob_hash::BlobHash(*store::blake3::hash(b"draft").as_bytes()),
        Default::default(),
    );
    let record = |subject: &str| RegistryRecord {
        key: RegistryKey::new("ArchivedItem", ARCHIVED_ID),
        json: json!({
            "@type": "Email",
            "from": "",
            "subject": subject,
            "receivedAt": "2030-01-01T00:00:00Z",
            "size": 5,
            "accountId": Id::from(ACCOUNT_ID).to_string(),
            "archivedAt": "2030-06-01T00:00:00Z",
            "archivedUntil": "2031-01-01T00:00:00Z",
            "blobId": serde_json::to_value(&blob_id).expect("blob id"),
        }),
    };
    let item_key = ValueKey::from(ValueClass::Registry(RegistryClass::Item {
        object_id: ObjectType::ArchivedItem.to_id(),
        item_id: ARCHIVED_ID,
    }));
    let listed = || async {
        target
            .server()
            .expect("server")
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::ArchivedItem)
                    .greater_than_or_equal(Property::AccountId, 0u64),
            )
            .await
            .expect("query")
    };
    for subject in ["", "Autosave"] {
        let outcome = target
            .write_registry(&[record(subject)])
            .await
            .expect("archived item");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        let stored = target
            .store()
            .get_value::<Object>(item_key.clone())
            .await
            .expect("read")
            .expect("archived item");
        let ObjectInner::ArchivedItem(item) = &stored.inner else {
            panic!("not an archived item: {stored:?}");
        };
        let json = serde_json::to_value(item).expect("json");
        assert_eq!(
            (json["from"].as_str(), json["subject"].as_str()),
            (Some(""), Some(subject))
        );
        assert_eq!(listed().await, vec![Id::from(ARCHIVED_ID)]);
    }
    target
        .delete_registry(&[RegistryKey::new("ArchivedItem", ARCHIVED_ID)])
        .await
        .expect("delete");
    assert!(listed().await.is_empty());
    assert!(
        target
            .store()
            .get_value::<Object>(item_key)
            .await
            .expect("read")
            .is_none()
    );
}

// Rewriting an archived item under another account moves its AccountId index row, so the stock query lists it only under the new account.
#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread")]
async fn archived_item_account_change_moves_index() {
    use registry::schema::prelude::Property;
    use store::registry::RegistryQuery;

    const ARCHIVED_ID: u64 = 0x0000_0000_0000_0078;
    const OTHER_ACCOUNT: u32 = ACCOUNT_ID + 1;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let blob_id = types::blob::BlobId::new(
        types::blob_hash::BlobHash(*store::blake3::hash(b"moved").as_bytes()),
        Default::default(),
    );
    let record = |account_id: u32| RegistryRecord {
        key: RegistryKey::new("ArchivedItem", ARCHIVED_ID),
        json: json!({
            "@type": "Email",
            "from": "alice@example.org",
            "subject": "Moved",
            "receivedAt": "2030-01-01T00:00:00Z",
            "size": 5,
            "accountId": Id::from(account_id).to_string(),
            "archivedAt": "2030-06-01T00:00:00Z",
            "archivedUntil": "2031-01-01T00:00:00Z",
            "blobId": serde_json::to_value(&blob_id).expect("blob id"),
        }),
    };
    let listed = async |account_id: u32| {
        target
            .server()
            .expect("server")
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::ArchivedItem)
                    .equal(Property::AccountId, u64::from(account_id)),
            )
            .await
            .expect("query")
    };
    for account_id in [ACCOUNT_ID, OTHER_ACCOUNT] {
        let outcome = target
            .write_registry(&[record(account_id)])
            .await
            .expect("archived item");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    assert_eq!(listed(ACCOUNT_ID).await, Vec::<Id>::new());
    assert_eq!(listed(OTHER_ACCOUNT).await, vec![Id::from(ARCHIVED_ID)]);
}

async fn subspace_rows(target: &V1Target, subspace: store::Subspace) -> Vec<Vec<u8>> {
    use store::{IterateParams, write::AnyKey};

    let mut rows = Vec::new();
    target
        .store()
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: Vec::new(),
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; 512],
                },
            )
            .no_values(),
            |key, _| {
                rows.push(key.to_vec());
                Ok(true)
            },
        )
        .await
        .expect("scan");
    rows
}

// Deleting an external report removes every registry index and primary key row its write created.
#[tokio::test(flavor = "multi_thread")]
async fn external_report_delete_leaves_no_index_rows() {
    use store::Subspace;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let subspaces = [Subspace::RegistryIndex, Subspace::RegistryPrimaryKey];
    let mut before = Vec::new();
    for subspace in subspaces {
        before.push(subspace_rows(&target, subspace).await);
    }
    let outcome = target
        .write_registry(&[external_report("2030-06-01T00:00:00Z")])
        .await
        .expect("external report");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let mut written = Vec::new();
    for subspace in subspaces {
        written.push(subspace_rows(&target, subspace).await);
    }
    assert!(
        written
            .iter()
            .zip(&before)
            .all(|(after, before)| after.len() > before.len()),
        "the report wrote no index or primary key rows"
    );
    target
        .delete_registry(&[RegistryKey::new("DmarcExternalReport", EXTERNAL_ID)])
        .await
        .expect("delete");
    for (subspace, before) in subspaces.into_iter().zip(&before) {
        assert_eq!(
            &subspace_rows(&target, subspace).await,
            before,
            "{subspace:?}"
        );
    }
}

// Migrated TLS and ARF external reports are fetched by id and listed through the stock JMAP registry get.
#[tokio::test(flavor = "multi_thread")]
async fn tls_and_arf_external_reports_are_served_by_stock_get() {
    use registry::schema::structs::{ArfExternalReport, TlsExternalReport};

    const TLS_EXTERNAL_ID: u64 = 0x0000_0000_0000_0051;
    const ARF_EXTERNAL_ID: u64 = 0x0000_0000_0000_0052;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let mut tls = TlsExternalReport {
        from: "tls-reports@example.com".into(),
        subject: "TLS report".into(),
        received_at: UTCDateTime::from_timestamp(NOW),
        expires_at: UTCDateTime::from_timestamp(NOW + 86_400),
        ..Default::default()
    };
    tls.report.report_id = "tls-1".into();
    tls.report.organization_name = Some("Example".into());
    let arf = ArfExternalReport {
        from: "abuse@example.com".into(),
        subject: "Abuse report".into(),
        received_at: UTCDateTime::from_timestamp(NOW),
        expires_at: UTCDateTime::from_timestamp(NOW + 86_400),
        ..Default::default()
    };
    let outcome = target
        .write_registry(&[
            RegistryRecord {
                key: RegistryKey::new("TlsExternalReport", TLS_EXTERNAL_ID),
                json: serde_json::to_value(tls).expect("tls json"),
            },
            RegistryRecord {
                key: RegistryKey::new("ArfExternalReport", ARF_EXTERNAL_ID),
                json: serde_json::to_value(arf).expect("arf json"),
            },
        ])
        .await
        .expect("external reports");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    for (object, id) in [
        (ObjectType::TlsExternalReport, TLS_EXTERNAL_ID),
        (ObjectType::ArfExternalReport, ARF_EXTERNAL_ID),
    ] {
        let expected = vec![Id::from(id).to_string()];
        let by_id = registry_get(&target, object, Some(id)).await;
        assert_eq!(listed_ids(&by_id), expected, "{object:?} by id: {by_id}");
        let all = registry_get(&target, object, None).await;
        assert_eq!(listed_ids(&all), expected, "{object:?} listing: {all}");
    }
}

// Spam training samples, with or without an account, From or Subject, are stored as stock v1 writes them, listed by the stock query and deleted without leftover index rows.
#[tokio::test(flavor = "multi_thread")]
async fn spam_samples_are_stored_like_stock() {
    use registry::{
        schema::prelude::{Object, ObjectInner, Property},
        types::EnumImpl,
    };
    use store::{
        Subspace, ValueKey,
        registry::RegistryQuery,
        write::{RegistryClass, ValueClass},
    };

    const OWNED_ID: u64 = 0x0000_0000_0000_0091;
    const UNOWNED_ID: u64 = 0x0000_0000_0000_0092;
    const COMPLETE_ID: u64 = 0x0000_0000_0000_0093;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = booted_target(dir.path()).await;
    let index_rows = subspace_rows(&target, Subspace::RegistryIndex).await;
    let blob_id = types::blob::BlobId::new(
        types::blob_hash::BlobHash(*store::blake3::hash(b"bounce").as_bytes()),
        Default::default(),
    );
    let record = |id: u64, from: &str, subject: &str, account: Option<u32>| RegistryRecord {
        key: RegistryKey::new("SpamTrainingSample", id),
        json: json!({
            "from": from,
            "subject": subject,
            "blobId": serde_json::to_value(&blob_id).expect("blob id"),
            "isSpam": true,
            "expiresAt": "2031-01-01T00:00:00Z",
            "accountId": account.map(|id| Id::from(id).to_string()),
        }),
    };
    let item_key = |item_id: u64| {
        ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::SpamTrainingSample.to_id(),
            item_id,
        }))
    };
    let outcome = target
        .write_registry(&[
            record(OWNED_ID, "", "Undelivered Mail", Some(ACCOUNT_ID)),
            record(UNOWNED_ID, "sender@example.com", "", None),
            record(COMPLETE_ID, "sender@example.com", "Offer", None),
        ])
        .await
        .expect("samples");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    for (item_id, from, subject) in [
        (OWNED_ID, "", "Undelivered Mail"),
        (UNOWNED_ID, "sender@example.com", ""),
        (COMPLETE_ID, "sender@example.com", "Offer"),
    ] {
        let stored = target
            .store()
            .get_value::<Object>(item_key(item_id))
            .await
            .expect("read")
            .expect("sample");
        let ObjectInner::SpamTrainingSample(sample) = &stored.inner else {
            panic!("not a spam training sample: {stored:?}");
        };
        assert_eq!(
            (sample.from.as_str(), sample.subject.as_str()),
            (from, subject)
        );
    }
    let registry = target.server().expect("server").registry();
    let owned = registry
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::SpamTrainingSample)
                .equal(Property::AccountId, u64::from(ACCOUNT_ID)),
        )
        .await
        .expect("query");
    assert_eq!(owned, vec![Id::from(OWNED_ID)]);
    let mut listed = registry
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::SpamTrainingSample)
                .greater_than_or_equal(Property::AccountId, 0u64),
        )
        .await
        .expect("query");
    listed.sort_unstable();
    assert_eq!(
        listed,
        vec![
            Id::from(OWNED_ID),
            Id::from(UNOWNED_ID),
            Id::from(COMPLETE_ID)
        ]
    );
    target
        .delete_registry(&[
            RegistryKey::new("SpamTrainingSample", OWNED_ID),
            RegistryKey::new("SpamTrainingSample", UNOWNED_ID),
            RegistryKey::new("SpamTrainingSample", COMPLETE_ID),
        ])
        .await
        .expect("delete");
    for item_id in [OWNED_ID, UNOWNED_ID, COMPLETE_ID] {
        assert!(
            target
                .store()
                .get_value::<Object>(item_key(item_id))
                .await
                .expect("read")
                .is_none()
        );
    }
    assert_eq!(
        subspace_rows(&target, Subspace::RegistryIndex).await,
        index_rows
    );
}
