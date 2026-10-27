/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{path::Path, time::Duration};

use email::identity::Identity;
use model::{
    Changes, Collection, DeadPropertyTag, LogCollection, LogEntry, LogRange, Pointer, RecordBatch,
    RegistryId, Source, TimeZoneRecord, VanishedRecord,
};
use store::{
    SUBSPACE_LOGS, Store,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use types::{
    collection::{Collection as V016Collection, SyncCollection},
    field::Field,
};

use super::{SourceConfig, V016Source};
use crate::testkit::{ACCOUNT, BLOB, BODY_OFFSET, EXTRA, archive, commit, rocks, seed};

pub(super) async fn source(path: &Path) -> V016Source {
    let mut config = SourceConfig::new(rocks(path));
    config.refresh_interval = Duration::ZERO;
    V016Source::open(config)
        .await
        .expect("open read-only source")
}

#[tokio::test]
async fn reads_a_v016_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    let source = source(dir.path()).await;

    let accounts = source.accounts().await.expect("accounts");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id, ACCOUNT);
    let counter = accounts[0].change_counter;
    assert!(counter >= 6, "counter {counter}");

    let RecordBatch::Mailbox(mailboxes) = source
        .scan(ACCOUNT, Collection::Mailbox, None, 10)
        .await
        .expect("mailboxes")
        .batch
    else {
        panic!("mailbox batch");
    };
    assert_eq!(mailboxes.len(), 1);
    assert_eq!(mailboxes[0].name, "Inbox");
    assert_eq!(mailboxes[0].role.as_deref(), Some("inbox"));
    assert_eq!(mailboxes[0].parent_id, None);
    assert_eq!(mailboxes[0].acls[0].account_id, 9);

    let RecordBatch::Email(emails) = source
        .read(ACCOUNT, Collection::Email, &[0, 99])
        .await
        .expect("emails")
        .batch
    else {
        panic!("email batch");
    };
    assert_eq!(emails.len(), 1);
    let email = &emails[0];
    assert_eq!(email.change_id, 3);
    assert_eq!(email.received_at, 1_700_000_000);
    assert_eq!(&*email.extra_headers, EXTRA);
    assert_eq!(email.body_offset, BODY_OFFSET);
    assert_eq!(email.keywords, [Box::from("$seen"), Box::from("$custom")]);
    assert_eq!(email.mailboxes[0].uid, 1);
    let blob = source
        .read_blob(&email.blob_hash)
        .await
        .expect("blob")
        .expect("present");
    assert_eq!(&blob[..], BLOB);

    let RecordBatch::Calendar(calendars) = source
        .scan(ACCOUNT, Collection::Calendar, None, 10)
        .await
        .expect("calendars")
        .batch
    else {
        panic!("calendar batch");
    };
    assert_eq!(
        calendars[0].preferences[0].time_zone,
        TimeZoneRecord::Iana("Europe/Madrid".into())
    );
    assert!(matches!(
        &calendars[0].dead_properties.0[0],
        DeadPropertyTag::ElementStart { name, .. } if &**name == "X:color"
    ));
    let RecordBatch::CalendarEvent(events) = source
        .scan(ACCOUNT, Collection::CalendarEvent, None, 10)
        .await
        .expect("events")
        .batch
    else {
        panic!("event batch");
    };
    assert!(events[0].icalendar.contains("SUMMARY:Meeting"));
    assert_eq!(events[0].names[0].name, "meeting.ics");
    assert_eq!(events[0].schedule_tag, Some(2));
    let RecordBatch::ContactCard(cards) = source
        .scan(ACCOUNT, Collection::ContactCard, None, 10)
        .await
        .expect("cards")
        .batch
    else {
        panic!("card batch");
    };
    assert!(cards[0].vcard.contains("FN:Jane Doe"));
    let RecordBatch::FileNode(files) = source
        .scan(ACCOUNT, Collection::FileNode, None, 10)
        .await
        .expect("files")
        .batch
    else {
        panic!("file batch");
    };
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].parent_id, None);
    assert_eq!(files[1].parent_id, Some(0));
    assert!(files[1].file.is_some());
    let RecordBatch::FileNode(page) = source
        .scan(ACCOUNT, Collection::FileNode, Some(0), 10)
        .await
        .expect("page")
        .batch
    else {
        panic!("file batch");
    };
    assert_eq!(page.len(), 1);

    for collection in [
        Collection::Identity,
        Collection::SieveScript,
        Collection::EmailSubmission,
        Collection::AddressBook,
    ] {
        let batch = source
            .scan(ACCOUNT, collection, None, 10)
            .await
            .expect("scan")
            .batch;
        assert_eq!(batch.len(), 1, "{collection}");
    }

    let pointers = source.pointers(ACCOUNT).await.expect("pointers");
    assert_eq!(pointers.active_script, Pointer::Set(Some(0)));
    assert_eq!(pointers.default_calendar, Pointer::Set(Some(0)));
    assert_eq!(pointers.default_address_book, Pointer::Set(None));
    let Pointer::Set(Some(identities)) = &pointers.participant_identities else {
        panic!("participant identities");
    };
    assert_eq!(
        identities.identities[0].calendar_address,
        "mailto:jane@example.org"
    );
    let Pointer::Set(Some(push)) = &pointers.push_subscriptions else {
        panic!("push subscriptions");
    };
    assert_eq!(push[0].url, "https://push.example.org/x");
    assert_eq!(
        push[0].types,
        [
            Box::from("CalendarEvent"),
            Box::from("Email"),
            Box::from("Mailbox")
        ]
    );

    let counters = source.counters(ACCOUNT).await.expect("counters");
    assert_eq!(counters.change_id, counter);
    assert_eq!(counters.document_id(Collection::Mailbox), Some(3));
    assert_eq!(counters.document_id(Collection::Email), Some(1));
    assert_eq!(counters.mailbox_uids.len(), 1);
    assert_eq!(counters.mailbox_uids[0].uid, 5);
}

#[tokio::test]
async fn reads_changes_changelog_and_share_notifications() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    let source = source(dir.path()).await;
    let counter = source.accounts().await.expect("accounts")[0].change_counter;

    let Changes::Delta(mailboxes) = source
        .changes(ACCOUNT, Collection::Mailbox, 0)
        .await
        .expect("changes")
    else {
        panic!("delta");
    };
    assert!(mailboxes.inserted.contains(0));
    assert!(!mailboxes.inserted.contains(3));
    assert!(mailboxes.deleted.contains(3));

    let Changes::Delta(since_two) = source
        .changes(ACCOUNT, Collection::Mailbox, 2)
        .await
        .expect("changes")
    else {
        panic!("delta");
    };
    assert!(since_two.deleted.contains(3));

    let Changes::Delta(emails) = source
        .changes(ACCOUNT, Collection::Email, 3)
        .await
        .expect("changes")
    else {
        panic!("delta");
    };
    assert!(emails.updated.contains(0));
    assert!(emails.inserted.is_empty());

    let rows = source
        .changelog(
            ACCOUNT,
            LogCollection::Email,
            LogRange {
                after: 0,
                up_to: counter,
            },
            100,
        )
        .await
        .expect("changelog");
    assert!(rows.len() >= 4);
    assert!(
        rows.windows(2)
            .all(|pair| pair[0].change_id < pair[1].change_id)
    );
    assert!(rows.iter().any(|row| matches!(
        &row.entry,
        LogEntry::Changes(changes) if changes.inserted_items == [0]
    )));
    let limited = source
        .changelog(
            ACCOUNT,
            LogCollection::Email,
            LogRange {
                after: rows[0].change_id,
                up_to: counter,
            },
            1,
        )
        .await
        .expect("changelog");
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].change_id, rows[1].change_id);
    let last = rows.last().map(|row| row.change_id);
    assert_eq!(
        source
            .last_change_id(ACCOUNT, LogCollection::Email, counter)
            .await
            .expect("last change id"),
        last
    );
    assert_eq!(
        source
            .last_change_id(ACCOUNT, LogCollection::Email, rows[1].change_id)
            .await
            .expect("last change id"),
        Some(rows[1].change_id)
    );

    let vanished = source
        .changelog(
            ACCOUNT,
            LogCollection::VanishedEmail,
            LogRange {
                after: 0,
                up_to: counter,
            },
            100,
        )
        .await
        .expect("vanished");
    assert!(matches!(
        &vanished[0].entry,
        LogEntry::Vanished(VanishedRecord::Email(uids)) if uids[0].uid == 1
    ));

    let shares = source
        .share_notifications(ACCOUNT, None, 10)
        .await
        .expect("shares");
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].id, 1 << 60);
    assert_eq!(&shares[0].payload[..], &[1, 2, 3]);
    assert!(
        source
            .share_notifications(ACCOUNT, Some(1 << 60), 10)
            .await
            .expect("shares")
            .is_empty()
    );
}

#[tokio::test]
async fn reads_registry_objects_as_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    let source = source(dir.path()).await;
    let types = source.registry_types().await.expect("types");
    assert!(types.iter().any(|name| &**name == "Domain"));
    assert!(types.iter().any(|name| &**name == "Http"));
    let domains = source
        .registry_page("Domain", None, 10)
        .await
        .expect("domains")
        .records;
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].key.id, RegistryId::Id(5));
    assert_eq!(domains[0].json["name"], "example.org");
    assert!(
        source
            .registry_page("Domain", Some(5), 10)
            .await
            .expect("page")
            .records
            .is_empty()
    );
    let http = source
        .registry_page("x:Http", None, 10)
        .await
        .expect("http")
        .records;
    assert_eq!(http[0].key.id, RegistryId::Singleton);
}

#[tokio::test]
async fn refresh_sees_new_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    let source = source(dir.path()).await;
    let before = source.accounts().await.expect("accounts")[0].change_counter;
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        commit(&store, |batch| {
            batch
                .with_collection(V016Collection::Identity)
                .with_document(1)
                .set(Field::ARCHIVE, archive(Identity::default()))
                .log_item_insert(SyncCollection::Identity, None);
        })
        .await;
    }
    source.catch_up().await.expect("refresh");
    let after = source.accounts().await.expect("accounts")[0].change_counter;
    assert_eq!(after, before + 1);
}

#[tokio::test]
async fn truncated_changelog_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let mut key = ACCOUNT.to_be_bytes().to_vec();
        key.push(u8::from(SyncCollection::Email));
        key.extend_from_slice(&2u64.to_be_bytes());
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Any(AnyClass {
                subspace: SUBSPACE_LOGS,
                key,
            }),
            Vec::new(),
        );
        store.write(batch.build_all()).await.expect("marker");
    }
    let source = source(dir.path()).await;
    assert_eq!(
        source
            .changes(ACCOUNT, Collection::Email, 1)
            .await
            .expect("changes"),
        Changes::Truncated
    );
    assert!(matches!(
        source
            .changes(ACCOUNT, Collection::Email, 2)
            .await
            .expect("changes"),
        Changes::Delta(_)
    ));
    let rows = source
        .changelog(
            ACCOUNT,
            LogCollection::Email,
            LogRange { after: 1, up_to: 2 },
            10,
        )
        .await
        .expect("changelog");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].entry, LogEntry::Truncated);
}

// Canonical registry JSON drops explicit nulls of absent optional fields and keeps stored objects unchanged.
#[tokio::test]
async fn canonical_registry_round_trips_through_v016_types() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    crate::testkit::seed_credentials(dir.path()).await;
    let source = source(dir.path()).await;
    let accounts = source
        .registry_page("Account", None, 10)
        .await
        .expect("accounts")
        .records;
    let stored = accounts.first().expect("account").clone();
    assert_eq!(
        source
            .canonical_registry(stored.clone())
            .expect("canonical"),
        stored
    );
    let mut null_otp = stored.clone();
    null_otp.json["credentials"]["0"]["otpAuth"] = serde_json::Value::Null;
    let mut missing_otp = null_otp.clone();
    missing_otp.json["credentials"]["0"]
        .as_object_mut()
        .expect("credential")
        .remove("otpAuth");
    let mut bogus = stored.clone();
    bogus.json["bogusField"] = serde_json::json!("lost");
    bogus.json["credentials"]["0"]["bogusNested"] = serde_json::json!(1);
    let err = source
        .canonical_registry(bogus)
        .expect_err("unknown fields are reported");
    assert!(err.to_string().contains("bogusField"), "{err}");
    assert!(
        err.to_string().contains("credentials.0.bogusNested"),
        "{err}"
    );
    let null_otp = source.canonical_registry(null_otp).expect("canonical");
    let missing_otp = source.canonical_registry(missing_otp).expect("canonical");
    assert_eq!(null_otp, missing_otp);
    assert!(
        source
            .canonical_registry(model::RegistryRecord {
                key: stored.key.clone(),
                json: serde_json::json!({"@type": "NoSuchVariant"}),
            })
            .is_err()
    );
}
