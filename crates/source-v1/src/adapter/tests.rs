/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::Path;

use bytes::Bytes;
use calcard::{icalendar::ICalendar, vcard::VCard};
use model::{
    AccountPointers, AclRecord, AddressBookPreferencesRecord, AddressBookRecord, BlobHash,
    CalendarEventRecord, CalendarPreferencesRecord, CalendarRecord, ChangeLogRecord,
    ChangedByRecord, Changes, Collection, ContactRecord, Counters, DavNameRecord,
    DeadPropertyRecord, DeadPropertyTag, DefaultAlertRecord, Edition, EmailRecord,
    EventNotificationRecord, EventPreferencesRecord, FileNodeRecord, FileRecord, IdentityRecord,
    LogChanges, LogCollection, LogEntry, LogRange, MailboxRecord, MailboxUid,
    ParticipantIdentitiesRecord, ParticipantIdentityRecord, Pointer, PushRecord, RecordBatch,
    RegistryKey, RegistryRecord, ShareNotificationRecord, SieveRecord, Source, SubmissionRecord,
    Target, TimeZoneRecord, VacationRecord, VanishedRecord, WriteMode,
};
use registry::schema::structs::{DataStore, RocksDbStore};
use serde_json::json;
use store::blake3;
use target_v1::{TargetConfig, V1Target};

use super::{SourceConfig, V1Source};

const ACCOUNT_ID: u32 = 7;
#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const MESSAGE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Migrated\r\nMessage-ID: <m1@example.org>\r\n\r\nHello there.\r\n";
const EXTRA_HEADERS: &[u8] = b"Delivered-To: bob@example.org\r\nX-Spam-Status: No, score=0.1\r\n";
const MESSAGE_BODY_OFFSET: u32 = 105;
const SCRIPT: &[u8] = b"require \"fileinto\";\r\nfileinto \"Projects\";\r\n";
const FILE: &[u8] = b"file contents";
const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:e1@example.org\r\nDTSTAMP:20240101T000000Z\r\nDTSTART:20240102T100000Z\r\nDTEND:20240102T110000Z\r\nSUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const INVITE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:e2@example.org\r\nDTSTAMP:20240101T000000Z\r\nDTSTART:20240103T100000Z\r\nSUMMARY:Invite\r\nORGANIZER:mailto:alice@example.org\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c1@example.org\r\nFN:Jane Doe\r\nEMAIL:jane@example.org\r\nEND:VCARD\r\n";

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
    V1Target::open(TargetConfig {
        data_store: config,
        fdb_txn_bytes: 9_000_000,
    })
    .await
    .expect("open target")
}

fn dead(name: &str, namespace: &str, text: &str) -> Vec<DeadPropertyTag> {
    vec![
        DeadPropertyTag::ElementStart {
            name: name.into(),
            attrs: Some(format!("xmlns=\"{namespace}\"").into_boxed_str()),
        },
        DeadPropertyTag::Text(text.into()),
        DeadPropertyTag::ElementEnd,
    ]
}

async fn upsert(target: &V1Target, batch: RecordBatch) {
    let outcome = target
        .upsert(ACCOUNT_ID, &batch, WriteMode::Create)
        .await
        .expect("upsert");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
}

async fn scan(source: &V1Source, collection: Collection) -> RecordBatch {
    let page = source
        .scan(ACCOUNT_ID, collection, None, 100)
        .await
        .expect("scan");
    assert!(page.issues.is_empty(), "{:?}", page.issues);
    let ids: Vec<u32> = {
        let mut ids = Vec::new();
        page.batch.collect_ids(&mut ids);
        ids
    };
    let read = source
        .read(ACCOUNT_ID, collection, &ids)
        .await
        .expect("read");
    assert_eq!(
        read.batch, page.batch,
        "read and scan agree for {collection}"
    );
    page.batch
}

fn mailboxes() -> Vec<MailboxRecord> {
    vec![
        MailboxRecord {
            document_id: 0,
            name: "Inbox".into(),
            role: Some("inbox".into()),
            uid_validity: 0xC0FFEE,
            subscribers: vec![ACCOUNT_ID],
            ..Default::default()
        },
        MailboxRecord {
            document_id: 9,
            name: "Projects".into(),
            parent_id: Some(0),
            sort_order: Some(4),
            uid_validity: 77,
            acls: vec![AclRecord {
                account_id: 8,
                grants: 0b101,
            }],
            ..Default::default()
        },
    ]
}

fn email() -> EmailRecord {
    EmailRecord {
        document_id: 4,
        thread_id: 2,
        change_id: 11,
        received_at: 1_700_000_000,
        keywords: vec!["$seen".into(), "$flagged".into(), "project-x".into()],
        mailboxes: vec![
            MailboxUid {
                mailbox_id: 0,
                uid: 41,
            },
            MailboxUid {
                mailbox_id: 9,
                uid: 3,
            },
        ],
        blob_hash: hash(MESSAGE),
        body_offset: MESSAGE_BODY_OFFSET,
        extra_headers: EXTRA_HEADERS.into(),
        size: (MESSAGE.len() + EXTRA_HEADERS.len()) as u32,
    }
}

fn calendar() -> CalendarRecord {
    CalendarRecord {
        document_id: 2,
        name: "work".into(),
        preferences: vec![CalendarPreferencesRecord {
            account_id: ACCOUNT_ID,
            name: "Work".into(),
            description: Some("Office".into()),
            sort_order: 1,
            color: Some("#ff0000".into()),
            flags: CalendarPreferencesRecord::SUBSCRIBED,
            time_zone: TimeZoneRecord::Iana("Europe/Madrid".into()),
            default_alerts: vec![DefaultAlertRecord {
                id: "a1".into(),
                offset: "-PT15M".into(),
                flags: DefaultAlertRecord::WITH_TIME,
            }],
        }],
        acls: vec![AclRecord {
            account_id: 8,
            grants: 1,
        }],
        supported_components: 3,
        dead_properties: DeadPropertyRecord(dead(
            "calendar-color",
            "http://apple.com/ns/ical/",
            "#FF0000",
        )),
        created: 1_600_000_000,
        modified: 1_600_000_500,
    }
}

fn event() -> CalendarEventRecord {
    CalendarEventRecord {
        document_id: 5,
        names: vec![DavNameRecord {
            name: "e1.ics".into(),
            parent_id: 2,
        }],
        display_name: Some("Planning".into()),
        icalendar: EVENT.into(),
        preferences: vec![EventPreferencesRecord {
            account_id: ACCOUNT_ID,
            flags: EventPreferencesRecord::USE_DEFAULT_ALERTS,
            properties: String::new(),
            alerts: String::new(),
        }],
        flags: CalendarEventRecord::INVITE_OTHERS,
        dead_properties: DeadPropertyRecord(dead("tag", "urn:x", "v")),
        size: EVENT.len() as u32,
        created: 1_600_000_100,
        modified: 1_600_000_200,
        schedule_tag: Some(3),
    }
}

fn notification() -> EventNotificationRecord {
    EventNotificationRecord {
        document_id: 1,
        icalendar: INVITE.into(),
        event_id: Some(5),
        changed_by: ChangedByRecord::CalendarAddress("mailto:alice@example.org".into()),
        flags: EventNotificationRecord::IS_CHANGE,
        size: INVITE.len() as u32,
        created: 1_600_000_300,
        modified: 1_600_000_300,
    }
}

fn address_book() -> AddressBookRecord {
    AddressBookRecord {
        document_id: 0,
        name: "default".into(),
        preferences: vec![AddressBookPreferencesRecord {
            account_id: ACCOUNT_ID,
            name: "Contacts".into(),
            description: None,
            sort_order: 0,
        }],
        subscribers: vec![ACCOUNT_ID],
        dead_properties: DeadPropertyRecord(dead("note", "urn:y", "hello")),
        acls: Vec::new(),
        created: 1_500_000_000,
        modified: 1_500_000_001,
    }
}

fn contact() -> ContactRecord {
    ContactRecord {
        document_id: 3,
        names: vec![DavNameRecord {
            name: "c1.vcf".into(),
            parent_id: 0,
        }],
        display_name: None,
        vcard: CARD.into(),
        dead_properties: DeadPropertyRecord::default(),
        created: 1_500_000_100,
        modified: 1_500_000_200,
        size: CARD.len() as u32,
    }
}

fn file_nodes() -> Vec<FileNodeRecord> {
    vec![
        FileNodeRecord {
            document_id: 0,
            parent_id: None,
            name: "docs".into(),
            display_name: Some("Documents".into()),
            created: 1_400_000_000,
            modified: 1_400_000_001,
            ..Default::default()
        },
        FileNodeRecord {
            document_id: 1,
            parent_id: Some(0),
            name: "a.txt".into(),
            file: Some(FileRecord {
                blob_hash: hash(FILE),
                size: FILE.len() as u32,
                media_type: Some("text/plain".into()),
                executable: true,
            }),
            created: 1_400_000_100,
            modified: 1_400_000_200,
            dead_properties: DeadPropertyRecord(dead("owner", "urn:z", "bob")),
            ..Default::default()
        },
    ]
}

fn changelog() -> Vec<ChangeLogRecord> {
    vec![
        ChangeLogRecord {
            collection: LogCollection::Email,
            change_id: 11,
            entry: LogEntry::Changes(LogChanges {
                inserted_items: vec![(2u64 << 32) | 4],
                updated_containers: vec![0, 9],
                ..Default::default()
            }),
        },
        ChangeLogRecord {
            collection: LogCollection::VanishedEmail,
            change_id: 12,
            entry: LogEntry::Vanished(VanishedRecord::Email(vec![
                MailboxUid {
                    mailbox_id: 0,
                    uid: 40,
                },
                MailboxUid {
                    mailbox_id: 9,
                    uid: 2,
                },
            ])),
        },
        ChangeLogRecord {
            collection: LogCollection::Calendar,
            change_id: 13,
            entry: LogEntry::Changes(LogChanges {
                inserted_containers: vec![2],
                inserted_items: vec![5],
                deleted_items: vec![6],
                ..Default::default()
            }),
        },
        ChangeLogRecord {
            collection: LogCollection::VanishedCalendar,
            change_id: 14,
            entry: LogEntry::Vanished(VanishedRecord::Paths(vec![
                "work/old.ics".into(),
                "work/older.ics".into(),
            ])),
        },
        ChangeLogRecord {
            collection: LogCollection::Email,
            change_id: 15,
            entry: LogEntry::Changes(LogChanges {
                deleted_items: vec![(2u64 << 32) | 8],
                inserted_items: vec![(3u64 << 32) | 8],
                ..Default::default()
            }),
        },
        ChangeLogRecord {
            collection: LogCollection::Email,
            change_id: 16,
            entry: LogEntry::Changes(LogChanges {
                inserted_items: vec![(3u64 << 32) | 12],
                ..Default::default()
            }),
        },
        ChangeLogRecord {
            collection: LogCollection::Email,
            change_id: 17,
            entry: LogEntry::Changes(LogChanges {
                deleted_items: vec![(3u64 << 32) | 12],
                ..Default::default()
            }),
        },
        ChangeLogRecord {
            collection: LogCollection::Identity,
            change_id: 3,
            entry: LogEntry::Truncated,
        },
    ]
}

// Records written through the v1 target read back unchanged through the v1 source.
#[tokio::test(flavor = "multi_thread")]
async fn source_reads_what_the_target_wrote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    let registry = vec![
        RegistryRecord {
            key: RegistryKey::new("Domain", 3),
            json: json!({"name": "example.org"}),
        },
        RegistryRecord {
            key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
            json: json!({
                "@type": "User",
                "name": "bob",
                "domainId": "d",
                "createdAt": "2024-01-01T00:00:00Z",
                "credentials": {"0": {"@type": "Password", "credentialId": "b", "secret": "$6$salt$hash"}},
            }),
        },
    ];
    let outcome = target.write_registry(&registry).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    for (blob, data) in [
        (hash(MESSAGE), MESSAGE),
        (hash(SCRIPT), SCRIPT),
        (hash(FILE), FILE),
    ] {
        target
            .put_blob(&blob, Bytes::from_static(data))
            .await
            .expect("blob");
    }

    upsert(&target, RecordBatch::Mailbox(mailboxes())).await;
    upsert(&target, RecordBatch::Calendar(vec![calendar()])).await;
    upsert(&target, RecordBatch::AddressBook(vec![address_book()])).await;
    upsert(&target, RecordBatch::FileNode(file_nodes())).await;
    let identity = IdentityRecord {
        document_id: 5,
        name: "Bob".into(),
        email: "bob@example.org".into(),
        reply_to: Some(vec![model::EmailAddressRecord {
            name: Some("Bob".into()),
            email: "reply@example.org".into(),
        }]),
        bcc: None,
        text_signature: "-- Bob".into(),
        html_signature: String::new(),
    };
    upsert(&target, RecordBatch::Identity(vec![identity.clone()])).await;
    let sieve = SieveRecord {
        document_id: 2,
        name: "vacation".into(),
        blob_hash: hash(SCRIPT),
        size: SCRIPT.len() as u32,
        vacation: Some(VacationRecord {
            from_date: Some(1),
            to_date: None,
            subject: Some("Away".into()),
            text_body: Some("Back soon".into()),
            html_body: None,
        }),
    };
    upsert(&target, RecordBatch::SieveScript(vec![sieve.clone()])).await;
    upsert(&target, RecordBatch::Email(vec![email()])).await;
    let submission = SubmissionRecord {
        document_id: 1,
        email_id: 4,
        thread_id: 2,
        identity_id: 5,
        send_at: 1_700_000_100,
        queue_id: Some(99),
        undo_status: model::UndoStatus::Final,
        envelope: model::EnvelopeRecord {
            mail_from: model::SmtpAddressRecord {
                email: "bob@example.org".into(),
                parameters: None,
            },
            rcpt_to: vec![model::SmtpAddressRecord {
                email: "alice@example.org".into(),
                parameters: Some(vec![("NOTIFY".into(), Some("SUCCESS".into()))]),
            }],
        },
        delivery_status: vec![(
            "alice@example.org".into(),
            model::DeliveryStatusRecord {
                smtp_reply: "250 OK".into(),
                delivered: model::Delivered::Yes,
                displayed: false,
            },
        )],
    };
    upsert(
        &target,
        RecordBatch::EmailSubmission(vec![submission.clone()]),
    )
    .await;
    upsert(&target, RecordBatch::CalendarEvent(vec![event()])).await;
    upsert(
        &target,
        RecordBatch::CalendarEventNotification(vec![notification()]),
    )
    .await;
    upsert(&target, RecordBatch::ContactCard(vec![contact()])).await;

    target
        .write_changelog(ACCOUNT_ID, &changelog())
        .await
        .expect("changelog");
    let shares = vec![
        ShareNotificationRecord {
            id: 1_000_001,
            payload: Bytes::from_static(b"first"),
        },
        ShareNotificationRecord {
            id: 1_000_002,
            payload: Bytes::from_static(b"second"),
        },
    ];
    target
        .write_share_notifications(ACCOUNT_ID, &shares)
        .await
        .expect("shares");
    let mut counters = Counters {
        change_id: 15,
        mailbox_uids: vec![
            MailboxUid {
                mailbox_id: 0,
                uid: 45,
            },
            MailboxUid {
                mailbox_id: 9,
                uid: 3,
            },
        ],
        ..Default::default()
    };
    counters.set_document_id(Collection::Email, 20);
    counters.set_document_id(Collection::Mailbox, 9);
    target
        .raise_counters(ACCOUNT_ID, &counters)
        .await
        .expect("counters");
    let pointers = AccountPointers {
        active_script: Pointer::Set(Some(2)),
        default_calendar: Pointer::Set(Some(2)),
        default_address_book: Pointer::Set(Some(0)),
        identity_addresses_hash: Pointer::Set(Some(42)),
        participant_identities: Pointer::Set(Some(ParticipantIdentitiesRecord {
            identities: vec![ParticipantIdentityRecord {
                id: 1,
                name: Some("Bob".into()),
                calendar_address: "mailto:bob@example.org".into(),
            }],
            default_name: "Bob".into(),
            default: 1,
        })),
        push_subscriptions: Pointer::Set(Some(vec![PushRecord {
            id: 3,
            url: "https://push.example.org/y".into(),
            device_client_id: "device".into(),
            expires: 1_800_000_000,
            verification_code: "code".into(),
            verified: true,
            types: ["CalendarEvent", "Email", "Mailbox"].map(Box::from).into(),
            keys: None,
            email_push: Vec::new(),
        }])),
    };
    target
        .write_pointers(ACCOUNT_ID, &pointers)
        .await
        .expect("pointers");

    let source = V1Source::from_store(target.store().clone());

    let types = source.registry_types().await.expect("types");
    assert!(types.iter().any(|name| &**name == "x:Account"));
    assert!(types.iter().all(|name| name.starts_with("x:")));
    let accounts = source
        .registry_page("Account", None, 10)
        .await
        .expect("accounts page")
        .records;
    let written = target
        .read_registry(&[RegistryKey::new("x:Account", u64::from(ACCOUNT_ID))])
        .await
        .expect("read registry");
    assert_eq!(accounts.first(), written[0].as_ref());
    let canonical = source
        .canonical_registry(registry[1].clone())
        .expect("canonical");
    assert_eq!(Some(&canonical), accounts.first());
    assert!(
        source
            .canonical_registry(RegistryRecord {
                key: RegistryKey::new("x:Account", 1),
                json: json!({"@type": "User", "name": 5}),
            })
            .is_err()
    );

    let counters_read = source.registry_id_counters().await.expect("id counters");
    assert!(
        counters_read.iter().any(
            |counter| &*counter.object == "x:Account" && counter.value == u64::from(ACCOUNT_ID)
        ),
        "{counters_read:?}"
    );

    let listed = source.accounts().await.expect("accounts");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].account_id, ACCOUNT_ID);
    assert_eq!(
        listed[0].change_counter, 135,
        "sum of the change group counters"
    );
    assert_eq!(
        source
            .counters(ACCOUNT_ID)
            .await
            .expect("counters")
            .change_id,
        15,
        "highest change group counter"
    );

    assert_eq!(
        scan(&source, Collection::Mailbox).await,
        RecordBatch::Mailbox(mailboxes())
    );
    let RecordBatch::Email(mut emails) = scan(&source, Collection::Email).await else {
        panic!("email batch");
    };
    emails[0].keywords.sort_unstable();
    let mut expected = email();
    expected.keywords.sort_unstable();
    assert_eq!(emails, [expected]);
    assert_eq!(
        scan(&source, Collection::Identity).await,
        RecordBatch::Identity(vec![identity])
    );
    assert_eq!(
        scan(&source, Collection::EmailSubmission).await,
        RecordBatch::EmailSubmission(vec![submission])
    );
    let RecordBatch::SieveScript(scripts) = scan(&source, Collection::SieveScript).await else {
        panic!("sieve batch");
    };
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].name, sieve.name);
    assert_eq!(scripts[0].vacation, sieve.vacation);
    let raw = source
        .read_blob(&scripts[0].blob_hash)
        .await
        .expect("blob")
        .expect("script blob");
    assert_eq!(&raw[..], SCRIPT);
    assert_eq!(
        scan(&source, Collection::Calendar).await,
        RecordBatch::Calendar(vec![calendar()])
    );
    assert_eq!(
        scan(&source, Collection::AddressBook).await,
        RecordBatch::AddressBook(vec![address_book()])
    );
    assert_eq!(
        scan(&source, Collection::FileNode).await,
        RecordBatch::FileNode(file_nodes())
    );

    let RecordBatch::CalendarEvent(events) = scan(&source, Collection::CalendarEvent).await else {
        panic!("event batch");
    };
    let mut expected = event();
    assert_eq!(
        ICalendar::parse(&events[0].icalendar).expect("event parses"),
        ICalendar::parse(&expected.icalendar).expect("expected parses")
    );
    expected.icalendar.clone_from(&events[0].icalendar);
    expected.size = events[0].size;
    assert_eq!(events[0], expected);

    let RecordBatch::CalendarEventNotification(notifications) =
        scan(&source, Collection::CalendarEventNotification).await
    else {
        panic!("notification batch");
    };
    let mut expected = notification();
    assert_eq!(
        ICalendar::parse(&notifications[0].icalendar).expect("notification parses"),
        ICalendar::parse(&expected.icalendar).expect("expected parses")
    );
    expected.icalendar.clone_from(&notifications[0].icalendar);
    expected.size = notifications[0].size;
    assert_eq!(notifications[0], expected);

    let RecordBatch::ContactCard(cards) = scan(&source, Collection::ContactCard).await else {
        panic!("contact batch");
    };
    let mut expected = contact();
    assert_eq!(
        VCard::parse(&cards[0].vcard).expect("card parses"),
        VCard::parse(&expected.vcard).expect("expected parses")
    );
    expected.vcard.clone_from(&cards[0].vcard);
    expected.size = cards[0].size;
    assert_eq!(cards[0], expected);

    let missing = source
        .read(ACCOUNT_ID, Collection::Email, &[3, 4, 99])
        .await
        .expect("read missing");
    assert_eq!(missing.batch.len(), 1);

    let mut rows = Vec::new();
    for collection in LogCollection::CHANGES {
        rows.extend(
            source
                .changelog(
                    ACCOUNT_ID,
                    collection,
                    LogRange {
                        after: 0,
                        up_to: u64::MAX,
                    },
                    100,
                )
                .await
                .expect("changelog"),
        );
    }
    let mut expected = changelog();
    expected.sort_by_key(|row| (row.collection, row.change_id));
    assert_eq!(rows, expected);
    let limited = source
        .changelog(
            ACCOUNT_ID,
            LogCollection::Email,
            LogRange {
                after: 11,
                up_to: 15,
            },
            1,
        )
        .await
        .expect("limited changelog");
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].change_id, 15);
    for collection in LogCollection::CHANGES {
        for up_to in [u64::MAX, 14, 1] {
            let last = expected
                .iter()
                .filter(|row| row.collection == collection && row.change_id <= up_to)
                .map(|row| row.change_id)
                .max();
            assert_eq!(
                source
                    .last_change_id(ACCOUNT_ID, collection, up_to)
                    .await
                    .expect("last change id"),
                last,
                "{collection:?} up to {up_to}"
            );
        }
    }

    let Changes::Delta(delta) = source
        .changes(ACCOUNT_ID, Collection::Email, 0)
        .await
        .expect("changes")
    else {
        panic!("email changes are not truncated");
    };
    assert_eq!(delta.inserted.iter().collect::<Vec<_>>(), [4, 8]);
    assert!(
        delta.deleted.contains(12),
        "an email created and deleted after the checkpoint is deleted"
    );
    let Changes::Delta(delta) = source
        .changes(ACCOUNT_ID, Collection::Mailbox, 0)
        .await
        .expect("changes")
    else {
        panic!("mailbox changes are not truncated");
    };
    assert_eq!(delta.updated.iter().collect::<Vec<_>>(), [0, 9]);
    assert_eq!(
        source
            .changes(ACCOUNT_ID, Collection::Identity, 0)
            .await
            .expect("identity changes"),
        Changes::Truncated
    );

    assert_eq!(
        source
            .share_notifications(ACCOUNT_ID, None, 10)
            .await
            .expect("shares"),
        shares
    );
    assert_eq!(
        source
            .share_notifications(ACCOUNT_ID, Some(1_000_001), 10)
            .await
            .expect("shares after"),
        shares[1..]
    );

    let read_pointers = source.pointers(ACCOUNT_ID).await.expect("pointers");
    assert_eq!(read_pointers, pointers);

    let read_counters = source.counters(ACCOUNT_ID).await.expect("counters");
    assert_eq!(read_counters.change_id, 15);
    assert_eq!(read_counters.document_id(Collection::Email), Some(20));
    assert_eq!(read_counters.document_id(Collection::Mailbox), Some(9));
    assert_eq!(read_counters.mailbox_uids, counters.mailbox_uids);

    {
        use registry::{schema::prelude::ObjectType, types::EnumImpl};
        use store::write::{BatchBuilder, RegistryClass, ValueClass};
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: u64::from(ACCOUNT_ID),
        }));
        source
            .data()
            .write_batch(&mut batch)
            .await
            .expect("remove account");
    }
    assert!(
        source.accounts().await.expect("accounts").is_empty(),
        "an account deleted from the registry but not destroyed yet is not listed"
    );
}

// The quota usage v1 stores after finalize equals the sizes of the account's objects, computed like v1 recalculate_quota; a drifted counter shows the difference.
#[tokio::test(flavor = "multi_thread")]
async fn quota_usage_matches_the_finalize_recalculation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    let registry = vec![
        RegistryRecord {
            key: RegistryKey::new("Domain", 3),
            json: json!({"name": "example.org"}),
        },
        RegistryRecord {
            key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
            json: json!({"@type": "User", "name": "bob", "domainId": "d", "createdAt": "2024-01-01T00:00:00Z"}),
        },
    ];
    let outcome = target.write_registry(&registry).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    for (blob, data) in [
        (hash(MESSAGE), MESSAGE),
        (hash(SCRIPT), SCRIPT),
        (hash(FILE), FILE),
    ] {
        target
            .put_blob(&blob, Bytes::from_static(data))
            .await
            .expect("blob");
    }
    upsert(&target, RecordBatch::Mailbox(mailboxes())).await;
    upsert(&target, RecordBatch::Calendar(vec![calendar()])).await;
    upsert(&target, RecordBatch::AddressBook(vec![address_book()])).await;
    upsert(&target, RecordBatch::FileNode(file_nodes())).await;
    upsert(&target, RecordBatch::Email(vec![email()])).await;
    upsert(&target, RecordBatch::CalendarEvent(vec![event()])).await;
    upsert(
        &target,
        RecordBatch::CalendarEventNotification(vec![notification()]),
    )
    .await;
    upsert(&target, RecordBatch::ContactCard(vec![contact()])).await;
    target
        .finalize_account(ACCOUNT_ID, &Counters::default())
        .await
        .expect("finalize");

    let source = V1Source::from_store(target.store().clone());
    let usage = source
        .quota_usage(ACCOUNT_ID)
        .await
        .expect("quota")
        .expect("v1 reports quota usage");
    assert_eq!(usage.stored, usage.computed);
    assert!(usage.computed > MESSAGE.len() as i64, "{usage:?}");
    for object in usage.objects {
        assert_eq!(object.stored, object.computed, "{object:?}");
    }
    assert_eq!(
        usage.objects.map(|object| object.computed),
        [1, 0, 1, 1],
        "{usage:?}"
    );
    {
        use registry::schema::enums::StorageQuota;
        use store::write::{BatchBuilder, ValueClass};
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(ACCOUNT_ID)
            .add(ValueClass::Quota, 7)
            .add(ValueClass::ObjectCount(StorageQuota::MaxEmails), 2);
        source.data().write_batch(&mut batch).await.expect("drift");
    }
    let drifted = source
        .quota_usage(ACCOUNT_ID)
        .await
        .expect("quota")
        .expect("v1 reports quota usage");
    assert_eq!(drifted.stored - drifted.computed, 7);
    assert_eq!(drifted.computed, usage.computed);
    assert_eq!(drifted.objects[0].stored - drifted.objects[0].computed, 2);
}

// The replay of a report through v1's row encoding equals what V1Target stores and V1Source reads back: long human fields compact and merge, TLS failure details come back in key order.
#[tokio::test(flavor = "multi_thread")]
async fn stored_reports_match_what_v1_reads_back() {
    use model::{GlobalBatch, GlobalCategory, InternalReportRecord, ReportKind};
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    let record = |human: &str, count: u64| {
        json!({
            "sourceIp": "192.0.2.1",
            "count": count,
            "envelopeFrom": "sender.example",
            "headerFrom": "sender.example",
            "dkimResults": {"0": {"domain": "sender.example", "selector": "s1", "humanResult": human.repeat(300)}}
        })
    };
    let reports = vec![
        InternalReportRecord {
            kind: ReportKind::Dmarc,
            id: 3,
            json: json!({
                "domain": "example.org",
                "policyIdentifier": 3,
                "createdAt": "2026-10-01T00:00:00Z",
                "deliverAt": "2026-10-02T00:00:00Z",
                "report": {"orgName": "example.org", "reportId": "dmarc-3", "dateRangeBegin": "2026-10-01T00:00:00Z", "dateRangeEnd": "2026-10-02T00:00:00Z", "records": {"0": record("a", 2), "1": record("b", 3), "2": record("c", 0)}}
            }),
        },
        InternalReportRecord {
            kind: ReportKind::Tls,
            id: 4,
            json: json!({
                "domain": "example.org",
                "createdAt": "2026-10-01T00:00:00Z",
                "deliverAt": "2026-10-02T00:00:00Z",
                "report": {"reportId": "tls-4", "dateRangeStart": "2026-10-01T00:00:00Z", "dateRangeEnd": "2026-10-02T00:00:00Z", "policies": {"0": {
                    "policyDomain": "example.org",
                    "totalSuccessfulSessions": 5,
                    "totalFailedSessions": 3,
                    "failureDetails": {
                        "0": {"resultType": "certificateExpired", "failedSessionCount": 2},
                        "1": {"resultType": "startTlsNotSupported", "failedSessionCount": 1}
                    }
                }}}
            }),
        },
    ];
    let outcome = target
        .write_global(&GlobalBatch::Reports(reports.clone()))
        .await
        .expect("write reports");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let source = V1Source::from_store(target.store().clone());
    let GlobalBatch::Reports(stored) = source
        .global_page(GlobalCategory::Reports, None, 10)
        .await
        .expect("reports")
        .batch
    else {
        panic!("reports batch");
    };
    assert_eq!(stored.len(), 2);
    for (original, stored) in reports.into_iter().zip(stored) {
        let replayed = source.stored_report(original).await.expect("replay");
        assert_eq!(replayed, stored);
    }
}

// Opening a v1 store that does not exist fails without creating it.
#[tokio::test(flavor = "multi_thread")]
async fn open_refuses_a_missing_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing");
    let config = SourceConfig::new(DataStore::RocksDb(RocksDbStore {
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    }));
    assert!(V1Source::open(config).await.is_err());
    assert!(!path.exists());
}

// An external report whose stock index entries are missing is unlisted: stock v1 cannot list it.
#[tokio::test]
async fn external_reports_without_index_entries_are_unlisted() {
    use registry::schema::{
        prelude::{ObjectInner, ObjectType},
        structs::DmarcExternalReport,
    };
    use registry::types::{EnumImpl, datetime::UTCDateTime};
    use smtp::reporting::index::ExternalReportIndex;
    use store::{
        ValueKey,
        write::{BatchBuilder, Operation, RegistryClass, ValueClass, ValueOp},
    };

    const LISTED: u64 = 3;
    const UNLISTED: u64 = 4;
    const NO_PRIMARY_KEY: u64 = 5;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    let store = target.store().clone();
    let report = |item_id: u64| {
        let mut report = DmarcExternalReport {
            from: "reports@example.org".into(),
            expires_at: UTCDateTime::from_timestamp(4_000_000_000),
            ..Default::default()
        };
        report.report.report_id = format!("report-{item_id}");
        report
    };
    let mut batch = BatchBuilder::new();
    for item_id in [LISTED, UNLISTED, NO_PRIMARY_KEY] {
        report(item_id).write_ops(&mut batch, item_id, true);
    }
    store.write_batch(&mut batch).await.expect("write reports");
    let mut stock = BatchBuilder::new();
    report(UNLISTED).write_ops(&mut stock, UNLISTED, true);
    let mut remove = BatchBuilder::new();
    for operation in stock.ops() {
        if let Operation::Value {
            class: class @ ValueClass::Registry(RegistryClass::Index { .. }),
            op: ValueOp::Set(_),
        } = operation
        {
            remove.clear(class.clone());
            break;
        }
    }
    let mut stock = BatchBuilder::new();
    report(NO_PRIMARY_KEY).write_ops(&mut stock, NO_PRIMARY_KEY, true);
    let mut primary_keys = 0;
    for operation in stock.ops() {
        if let Operation::Value {
            class: class @ ValueClass::Registry(RegistryClass::PrimaryKey { .. }),
            op: ValueOp::Set(_),
        } = operation
        {
            remove.clear(class.clone());
            primary_keys += 1;
        }
    }
    assert!(primary_keys > 0, "external reports write a primary key");
    store.write_batch(&mut remove).await.expect("remove index");
    assert!(
        store
            .key_exists(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::DmarcExternalReport.to_id(),
                item_id: UNLISTED,
            })))
            .await
            .expect("exists")
    );

    let source = V1Source::from_store(store);
    let records = source
        .registry_page("x:DmarcExternalReport", None, 10)
        .await
        .expect("reports")
        .records;
    assert_eq!(records.len(), 3);
    assert!(matches!(
        ObjectInner::deserialize(ObjectType::DmarcExternalReport, &records[0].json),
        Ok(ObjectInner::DmarcExternalReport(_))
    ));
    assert_eq!(
        source.unlisted_registry(&records).await.expect("unlisted"),
        [
            model::RegistryKey::new("x:DmarcExternalReport", UNLISTED),
            model::RegistryKey::new("x:DmarcExternalReport", NO_PRIMARY_KEY)
        ]
    );
}

// Archived items and spam training samples report the blob they hold; other registry objects hold none.
#[cfg(feature = "enterprise")]
#[test]
fn registry_blobs_of_archived_items() {
    use registry::schema::structs::{ArchivedEmail, ArchivedItem, ArchivedSieveScript};

    let record = |object: &str, json: serde_json::Value| model::RegistryRecord {
        key: model::RegistryKey::new(object, 1),
        json,
    };
    for (byte, mut item) in [
        (7u8, ArchivedItem::Email(ArchivedEmail::default())),
        (
            9u8,
            ArchivedItem::SieveScript(ArchivedSieveScript::default()),
        ),
    ] {
        item.blob_id_mut().hash.0 = [byte; 32];
        let json = serde_json::to_value(&item).expect("json");
        assert_eq!(
            super::registry::blob(&record("x:ArchivedItem", json)),
            Some(BlobHash([byte; 32]))
        );
    }
    assert_eq!(
        super::registry::blob(&record(
            "x:Domain",
            serde_json::json!({"name": "example.org"})
        )),
        None
    );
}

// The range reads of the account counters return what point reads of every counter key return (accounts, change bounds, counters), with neighbouring accounts, negative values and stray keys around.
#[tokio::test(flavor = "multi_thread")]
async fn account_counters_match_point_reads() {
    use model::AccountRef;
    use std::collections::BTreeSet;
    use store::{
        Store, ValueKey,
        write::{BatchBuilder, ValueClass},
    };
    use types::collection::{Collection as V1Collection, SyncCollection};

    async fn point(
        store: &Store,
        account_id: u32,
        collection: u8,
        document_id: u32,
        class: ValueClass,
    ) -> i64 {
        store
            .get_counter(ValueKey {
                account_id,
                collection,
                document_id,
                class,
            })
            .await
            .expect("counter")
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    target.prepare_store(EDITION).await.expect("prepare");
    let registry = [
        RegistryRecord {
            key: RegistryKey::new("Domain", 3),
            json: json!({"name": "example.org"}),
        },
        RegistryRecord {
            key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
            json: json!({
                "@type": "User",
                "name": "bob",
                "domainId": "d",
                "createdAt": "2024-01-01T00:00:00Z",
            }),
        },
    ];
    let outcome = target.write_registry(&registry).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    upsert(&target, RecordBatch::Mailbox(mailboxes())).await;
    let store = target.store().clone();

    let accounts = [1u32, 6, ACCOUNT_ID, 8, 300, 0x0100_0000];
    let mut batch = BatchBuilder::new();
    for (index, account_id) in accounts.into_iter().enumerate() {
        let index = index as i64;
        batch.with_account_id(account_id);
        if account_id != 8 {
            for value in 0..SyncCollection::MAX_CHANGE_GROUP {
                let amount = match (account_id, value) {
                    (300, 5) => -5,
                    _ => index * 100 + i64::from(value) * 3 + 1,
                };
                batch.add(
                    ValueClass::ChangeId(SyncCollection::from(value).change_group()),
                    amount,
                );
            }
        }
        for collection in 0..16u8 {
            let amount = match collection {
                3 => -1,
                4 => 0,
                _ => index * 50 + i64::from(collection),
            };
            batch
                .with_collection(V1Collection::from(collection))
                .add(ValueClass::DocumentId, amount);
        }
        batch.add(ValueClass::Quota, 4096 + index);
        for mailbox_id in [0u32, 9, 50] {
            if account_id == ACCOUNT_ID && mailbox_id == 9 {
                continue;
            }
            batch
                .with_collection(V1Collection::Mailbox)
                .with_document(mailbox_id)
                .add(
                    ValueClass::MailboxUid,
                    index * 10 + i64::from(mailbox_id) + 1,
                );
        }
    }
    store.write_batch(&mut batch).await.expect("counters");

    let groups: BTreeSet<u8> = (0..SyncCollection::MAX_CHANGE_GROUP)
        .map(|value| SyncCollection::from(value).change_group().to_u8())
        .collect();
    let group_value = async |account_id: u32, group: u8| {
        u64::try_from(
            point(
                &store,
                account_id,
                0,
                0,
                ValueClass::ChangeId(SyncCollection::from(group).change_group()),
            )
            .await,
        )
        .unwrap_or_default()
    };

    let listed = super::principal::accounts(&store).await.expect("accounts");
    let mut expected = Vec::new();
    for account_id in accounts.into_iter().filter(|account_id| *account_id != 8) {
        let mut sum = 0u64;
        for group in &groups {
            sum += group_value(account_id, *group).await;
        }
        expected.push(AccountRef {
            account_id,
            change_counter: sum,
        });
    }
    assert_eq!(listed, expected);

    for account_id in accounts {
        let mut highest = 0u64;
        for group in &groups {
            highest = highest.max(group_value(account_id, *group).await);
        }
        let bounds = super::principal::change_bounds(&store, account_id)
            .await
            .expect("bounds");
        for collection in Collection::ALL {
            let expected = match collection {
                Collection::Thread | Collection::Principal | Collection::PushSubscription => {
                    highest
                }
                collection => {
                    group_value(
                        account_id,
                        V1Collection::from(collection.as_u8())
                            .change_group()
                            .to_u8(),
                    )
                    .await
                }
            };
            assert_eq!(
                bounds.collection(collection),
                expected,
                "{account_id} {collection}"
            );
        }
        for log in LogCollection::CHANGES {
            let base = match log {
                LogCollection::VanishedEmail => LogCollection::Email,
                LogCollection::VanishedCalendar => LogCollection::Calendar,
                LogCollection::VanishedAddressBook => LogCollection::AddressBook,
                LogCollection::VanishedFileNode => LogCollection::FileNode,
                log => log,
            };
            let group = SyncCollection::from(base.as_u8()).change_group().to_u8();
            assert_eq!(
                bounds.log(log),
                group_value(account_id, group).await,
                "{account_id} {log:?}"
            );
        }

        let counters = super::principal::counters(&store, account_id)
            .await
            .expect("counters");
        let mut reference = Counters {
            change_id: highest,
            ..Counters::default()
        };
        for collection in Collection::ALL {
            let value = point(
                &store,
                account_id,
                collection.as_u8(),
                0,
                ValueClass::DocumentId,
            )
            .await;
            if let Ok(value) = u32::try_from(value)
                && value > 0
            {
                reference.set_document_id(collection, value);
            }
        }
        if account_id == ACCOUNT_ID {
            for mailbox in mailboxes() {
                let uid = point(
                    &store,
                    account_id,
                    u8::from(V1Collection::Mailbox),
                    mailbox.document_id,
                    ValueClass::MailboxUid,
                )
                .await;
                reference.mailbox_uids.push(MailboxUid {
                    mailbox_id: mailbox.document_id,
                    uid: u32::try_from(uid).unwrap_or_default(),
                });
            }
        }
        assert_eq!(counters, reference, "{account_id}");
    }
    let counters = super::principal::counters(&store, ACCOUNT_ID)
        .await
        .expect("counters");
    assert_eq!(
        counters.mailbox_uids,
        [
            MailboxUid {
                mailbox_id: 0,
                uid: 21
            },
            MailboxUid {
                mailbox_id: 9,
                uid: 0
            }
        ]
    );
}

// Certificates expire on notValidAfter unless file-backed, whose metadata Stalwart refreshes from the file when it starts.
#[test]
fn certificate_expiry_and_refresh() {
    let certificate = |certificate: serde_json::Value| RegistryRecord {
        key: RegistryKey::new("x:Certificate", 3),
        json: json!({"certificate": certificate, "privateKey": {"@type": "Text", "secret": "key"}, "notValidAfter": "2024-01-01T00:00:00Z"}),
    };
    let text = certificate(json!({"@type": "Text", "value": "pem"}));
    let file = certificate(json!({"@type": "File", "filePath": "/etc/cert.pem"}));
    assert_eq!(
        super::registry_object_expired_at(&text),
        Some("2024-01-01T00:00:00Z")
    );
    assert!(!super::registry_object_refreshed_on_start(
        &text.key.object,
        &text.json
    ));
    assert_eq!(super::registry_object_expired_at(&file), None);
    assert!(super::registry_object_refreshed_on_start(
        &file.key.object,
        &file.json
    ));
    let ip = RegistryRecord {
        key: RegistryKey::new("x:BlockedIp", 4),
        json: json!({"notValidAfter": "2024-01-01T00:00:00Z", "expiresAt": "2999-01-01T00:00:00Z"}),
    };
    assert_eq!(super::registry_object_expired_at(&ip), None);
}
