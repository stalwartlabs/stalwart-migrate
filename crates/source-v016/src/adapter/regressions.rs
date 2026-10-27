/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::ObjectIndexBuilder;
use email::{
    mailbox::{Mailbox, UidMailbox},
    message::metadata::MessageData,
};
use model::{BlobHash, Changes, Collection, IssueKind, RegistryId, Source, Subject};
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs,
    },
    types::EnumImpl,
};
use store::{
    Deserialize, Store, ValueKey,
    write::{AlignedBytes, Archive, BatchBuilder, RegistryClass, ValueClass},
};
use trc::Key;
use types::{collection::Collection as V016Collection, field::Field, id::Id, keyword::Keyword};

use super::{SourceConfig, V016Source, error::trc_error, tests::source};
use crate::testkit::{ACCOUNT, archive, commit, register_account, rocks, seed};

fn message(thread_id: u32, uid: u32, keywords: Vec<Keyword>) -> MessageData {
    MessageData {
        mailboxes: vec![UidMailbox { mailbox_id: 0, uid }].into_boxed_slice(),
        keywords: keywords.into_boxed_slice(),
        thread_id,
        size: 100,
    }
}

async fn insert_email(store: &Store, document_id: u32, thread_id: u32) {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ACCOUNT)
        .with_collection(V016Collection::Email)
        .with_document(document_id)
        .custom(
            ObjectIndexBuilder::<(), MessageData>::new().with_changes(message(
                thread_id,
                document_id,
                vec![],
            )),
        )
        .expect("insert");
    store.write(batch.build_all()).await.expect("write");
}

async fn update_emails(store: &Store, updates: &[(u32, Option<u32>, Vec<Keyword>)]) {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ACCOUNT)
        .with_collection(V016Collection::Email);
    for (document_id, thread, keywords) in updates {
        let archive = store
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                ACCOUNT,
                V016Collection::Email,
                *document_id,
            ))
            .await
            .expect("get")
            .expect("exists");
        let current = archive.to_unarchived::<MessageData>().expect("unarchive");
        let mut data = archive.deserialize::<MessageData>().expect("deserialize");
        if let Some(thread) = thread {
            data.thread_id = *thread;
        }
        data.keywords = keywords.clone().into_boxed_slice();
        batch
            .with_document(*document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(current)
                    .with_changes(data),
            )
            .expect("update");
    }
    store.write(batch.build_all()).await.expect("write");
}

// An account deleted in v0.16 whose data awaits destruction has no registry Account and is not listed.
#[tokio::test]
async fn accounts_pending_destruction_are_not_listed() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(ACCOUNT + 4)
            .with_collection(V016Collection::Mailbox)
            .with_document(0)
            .set(Field::ARCHIVE, archive(Mailbox::new("Inbox")))
            .log_container_insert(types::collection::SyncCollection::Email);
        store.write(batch.build_all()).await.expect("write");
    }
    let accounts = source(dir.path()).await.accounts().await.expect("accounts");
    assert_eq!(
        accounts
            .iter()
            .map(|account| account.account_id)
            .collect::<Vec<_>>(),
        [ACCOUNT]
    );
}

// A thread merge logs delete(old thread prefix) and insert(new prefix) for the same email in one row.
#[tokio::test]
async fn thread_merges_are_reinserts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let checkpoint = {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        register_account(&store, ACCOUNT).await;
        insert_email(&store, 1, 1).await;
        insert_email(&store, 2, 2).await;
        let checkpoint =
            source(dir.path()).await.accounts().await.expect("accounts")[0].change_counter;
        insert_email(&store, 3, 3).await;
        update_emails(&store, &[(2, None, vec![Keyword::Seen])]).await;
        update_emails(
            &store,
            &[
                (1, Some(9), vec![]),
                (2, Some(9), vec![Keyword::Seen]),
                (3, Some(9), vec![]),
            ],
        )
        .await;
        checkpoint
    };
    let source = source(dir.path()).await;
    let Changes::Delta(set) = source
        .changes(ACCOUNT, Collection::Email, checkpoint)
        .await
        .expect("changes")
    else {
        panic!("expected a delta");
    };
    assert_eq!(set.inserted.iter().collect::<Vec<_>>(), [1, 2, 3]);
    assert!(set.updated.is_empty());
    assert!(set.deleted.is_empty());
    let page = source
        .read(ACCOUNT, Collection::Email, &[1, 2, 3])
        .await
        .expect("read");
    let model::RecordBatch::Email(emails) = page.batch else {
        panic!("email batch");
    };
    assert!(emails.iter().all(|email| email.thread_id == 9));
}

// Registry secrets are exported in clear, not masked.
#[tokio::test]
async fn registry_secrets_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let account = structs::Account::User(structs::UserAccount {
            name: "jane".into(),
            credentials: vec![structs::Credential::Password(structs::PasswordCredential {
                credential_id: Id::new(0),
                secret: hash.into(),
                otp_auth: Some("otpauth://totp/x?secret=ABC".into()),
                expires_at: None,
                allowed_ips: Default::default(),
            })]
            .into(),
            ..Default::default()
        });
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::Account.to_id(),
                item_id: u64::from(ACCOUNT),
            }),
            ObjectInner::Account(account).to_pickled_vec(),
        );
        batch.add(
            ValueClass::Registry(RegistryClass::IdCounter {
                object_id: ObjectType::Account.to_id(),
            }),
            40,
        );
        store.write(batch.build_all()).await.expect("registry");
    }
    let source = source(dir.path()).await;
    assert_eq!(
        source.registry_id_counters().await.expect("counters"),
        [model::RegistryCounter {
            object: "Account".into(),
            value: 40,
        }]
    );
    let accounts = source
        .registry_page("Account", None, 10)
        .await
        .expect("page")
        .records;
    let json = accounts[0].json.to_string();
    assert!(json.contains(hash), "{json}");
    assert!(json.contains("otpauth://totp/x?secret=ABC"), "{json}");
    assert!(!json.contains("****"), "{json}");
}

// One undecodable object is skipped and reported; the rest of the page is returned.
#[tokio::test]
async fn undecodable_objects_become_issues() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        commit(&store, |batch| {
            batch
                .with_collection(V016Collection::Mailbox)
                .with_document(9)
                .set(Field::ARCHIVE, vec![0x13, 0x37, 0x00])
                .with_document(10)
                .set(
                    Field::ARCHIVE,
                    archive(Mailbox {
                        name: "Later".into(),
                        ..Mailbox::new("Later")
                    }),
                );
        })
        .await;
    }
    let source = source(dir.path()).await;
    let page = source
        .scan(ACCOUNT, Collection::Mailbox, None, 10)
        .await
        .expect("scan");
    let mut ids = Vec::new();
    page.batch.collect_ids(&mut ids);
    assert_eq!(ids, [0, 10]);
    assert_eq!(page.last_scanned, Some(10));
    assert_eq!(page.issues.len(), 1);
    assert_eq!(page.issues[0].kind, IssueKind::Skipped);
    assert_eq!(
        page.issues[0].subject,
        Subject::Document {
            collection: Collection::Mailbox,
            document_id: 9
        }
    );
    let page = source
        .read(ACCOUNT, Collection::Mailbox, &[9])
        .await
        .expect("read");
    assert!(page.batch.is_empty());
    assert_eq!(page.issues.len(), 1);
}

// A data-store blob still missing after fresh reads is reported absent, so the caller re-checks the object.
#[tokio::test]
async fn missing_data_store_blob_is_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    let source = source(dir.path()).await;
    let result = source.read_blob(&BlobHash([0xEE; 32])).await;
    assert!(matches!(result, Ok(None)), "{result:?}");
}

// An email whose metadata is missing while the email still exists is skipped and reported.
#[tokio::test]
async fn email_without_metadata_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        commit(&store, |batch| {
            batch
                .with_collection(V016Collection::Email)
                .with_document(5)
                .set(Field::ARCHIVE, archive(message(5, 9, vec![])));
        })
        .await;
    }
    let source = source(dir.path()).await;
    let page = source
        .read(ACCOUNT, Collection::Email, &[0, 5])
        .await
        .expect("read");
    assert_eq!(page.batch.len(), 1);
    assert_eq!(page.issues.len(), 1);
    assert_eq!(
        page.issues[0].subject,
        Subject::Document {
            collection: Collection::Email,
            document_id: 5
        }
    );
}

// A file system blob store that does not exist is an open error, never an empty store.
#[tokio::test]
async fn missing_file_system_blob_store_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: ObjectType::BlobStore.to_id(),
                item_id: Id::singleton().id(),
            }),
            ObjectInner::BlobStore(structs::BlobStore::FileSystem(structs::FileSystemStore {
                path: dir.path().join("missing").to_string_lossy().into_owned(),
                ..Default::default()
            }))
            .to_pickled_vec(),
        );
        store.write(batch.build_all()).await.expect("registry");
    }
    assert!(
        V016Source::open(SourceConfig::new(rocks(dir.path())))
            .await
            .is_err()
    );
    assert!(!dir.path().join("missing").exists());
}

#[cfg(feature = "enterprise")]
async fn write_blob_store(path: &std::path::Path, config: structs::BlobStore) {
    let store = Store::build(rocks(path)).await.expect("writer");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::BlobStore.to_id(),
            item_id: Id::singleton().id(),
        }),
        ObjectInner::BlobStore(config).to_pickled_vec(),
    );
    store.write(batch.build_all()).await.expect("registry");
}

#[cfg(feature = "enterprise")]
fn file_system_shard(path: &str) -> structs::BlobStoreBase {
    structs::BlobStoreBase::FileSystem(structs::FileSystemStore {
        path: path.into(),
        ..Default::default()
    })
}

// Every file system shard is rewritten, listed for the overlap check, and must exist.
#[cfg(feature = "enterprise")]
#[tokio::test]
async fn sharded_file_system_blob_stores_are_listed_and_checked() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed(dir.path()).await;
    std::fs::create_dir_all(dir.path().join("shard-a")).expect("shard");
    std::fs::create_dir_all(dir.path().join("shard-b")).expect("shard");
    write_blob_store(
        dir.path(),
        structs::BlobStore::Sharded(structs::ShardedBlobStore {
            stores: vec![
                file_system_shard("/old/shard-a"),
                file_system_shard("/old/shard-b"),
            ]
            .into(),
        }),
    )
    .await;
    let root = dir.path().display().to_string();
    let mut config = SourceConfig::new(rocks(dir.path()));
    config.path_rewrite = Some(Box::new(move |path: &str| path.replace("/old", &root)));
    let source = V016Source::open(config).await.expect("open");
    let paths: Vec<&str> = source.file_system_blob_paths().collect();
    let expected = [dir.path().join("shard-a"), dir.path().join("shard-b")];
    assert_eq!(
        paths,
        expected
            .iter()
            .map(|path| path.to_str().expect("utf-8"))
            .collect::<Vec<_>>()
    );
    drop(source);

    std::fs::remove_dir(dir.path().join("shard-b")).expect("remove shard");
    let mut config = SourceConfig::new(rocks(dir.path()));
    let root = dir.path().display().to_string();
    config.path_rewrite = Some(Box::new(move |path: &str| path.replace("/old", &root)));
    assert!(V016Source::open(config).await.is_err());
    assert!(!dir.path().join("shard-b").exists());
}

// Registry pages with a small limit return every object once, in id order.
#[tokio::test]
async fn registry_pages_are_exact() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let mut batch = BatchBuilder::new();
        for id in 1..=10u64 {
            batch.set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: ObjectType::Domain.to_id(),
                    item_id: id * 1000,
                }),
                ObjectInner::Domain(structs::Domain {
                    name: format!("d{id}.org"),
                    ..Default::default()
                })
                .to_pickled_vec(),
            );
        }
        store.write(batch.build_all()).await.expect("registry");
    }
    let source = source(dir.path()).await;
    let mut after = None;
    let mut seen = Vec::new();
    loop {
        let page = source
            .registry_page("Domain", after, 3)
            .await
            .expect("page")
            .records;
        let Some(last) = page.last() else {
            break;
        };
        assert!(page.len() <= 3);
        let RegistryId::Id(last) = last.key.id else {
            panic!("expected ids");
        };
        after = Some(last);
        seen.extend(page.into_iter().map(|record| record.key.id));
    }
    assert_eq!(seen.len(), 10);
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use std::path::Path;

    use email::mailbox::Mailbox;
    use model::{Collection, Source};
    use registry::schema::structs;
    use store::Store;
    use types::{
        collection::{Collection as V016Collection, SyncCollection},
        field::Field,
    };

    use crate::{
        StoreSchema,
        adapter::{SourceConfig, V016Source},
        testkit::{ACCOUNT, archive, commit, register_account},
    };

    #[tokio::test]
    async fn sqlite_source_is_never_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.sqlite");
        let config = registry::schema::structs::DataStore::Sqlite(structs::SqliteStore {
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        });
        {
            let store = Store::build(config.clone()).await.expect("writer");
            store.create_tables().await.expect("tables");
            register_account(&store, ACCOUNT).await;
            commit(&store, |batch| {
                batch
                    .with_collection(V016Collection::Mailbox)
                    .with_document(0)
                    .set(Field::ARCHIVE, archive(Mailbox::new("Inbox")))
                    .log_container_insert(SyncCollection::Email);
            })
            .await;
        }
        {
            let conn = rusqlite_connection(&path);
            conn.pragma_update(None, "journal_mode", "DELETE")
                .expect("journal mode");
        }
        let before = std::fs::read(&path).expect("read");
        let source = V016Source::open(SourceConfig::new(config))
            .await
            .expect("open read-only");
        assert_eq!(source.accounts().await.expect("accounts").len(), 1);
        let page = source
            .scan(ACCOUNT, Collection::Mailbox, None, 10)
            .await
            .expect("scan");
        assert_eq!(page.batch.len(), 1);
        drop(source);
        assert_eq!(std::fs::read(&path).expect("read"), before);
        assert!(!Path::new(&format!("{}-wal", path.display())).exists());
        let missing = registry::schema::structs::DataStore::Sqlite(structs::SqliteStore {
            path: dir
                .path()
                .join("nope.sqlite")
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        });
        assert!(V016Source::open(SourceConfig::new(missing)).await.is_err());
        assert!(!dir.path().join("nope.sqlite").exists());
    }

    fn listing(dir: &Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| {
                let entry = entry.expect("entry");
                (
                    entry.file_name(),
                    std::fs::read(entry.path()).expect("read"),
                )
            })
            .collect();
        files.sort();
        files
    }

    // A v0.16 server that starts writing after the source opened an idle SQLite database fails catch_up instead of leaving a stale snapshot.
    #[tokio::test]
    async fn idle_sqlite_source_detects_a_started_server() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = registry::schema::structs::DataStore::Sqlite(structs::SqliteStore {
            path: dir
                .path()
                .join("data.sqlite")
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        });
        let mailbox = |id| {
            move |batch: &mut store::write::BatchBuilder| {
                batch
                    .with_collection(V016Collection::Mailbox)
                    .with_document(id)
                    .set(Field::ARCHIVE, archive(Mailbox::new("Inbox")))
                    .log_container_insert(SyncCollection::Email);
            }
        };
        {
            let store = Store::build(config.clone()).await.expect("writer");
            store.create_tables().await.expect("tables");
            register_account(&store, ACCOUNT).await;
            commit(&store, mailbox(0)).await;
        }
        let source = V016Source::open(SourceConfig::new(config.clone()))
            .await
            .expect("open read-only");
        source.catch_up().await.expect("idle catch up");
        let writer = Store::build(config).await.expect("writer");
        commit(&writer, mailbox(1)).await;
        let err = source
            .catch_up()
            .await
            .expect_err("a started server is detected");
        assert!(err.to_string().contains("a v0.16 server started"), "{err}");
        assert!(
            err.to_string().contains("another process (sqlite3"),
            "{err}"
        );
        drop(writer);
        assert!(source.catch_up().await.is_err());
    }

    // A cleanly closed WAL-mode v0.16 database gets no -wal or -shm files from the read-only source; a live one is still read.
    #[tokio::test]
    async fn wal_mode_sqlite_source_creates_no_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("a b%20?x#y");
        std::fs::create_dir(&dir).expect("dir");
        let dir = dir.as_path();
        let path = dir.join("data.sqlite");
        let config = registry::schema::structs::DataStore::Sqlite(structs::SqliteStore {
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        });
        {
            let store = Store::build(config.clone()).await.expect("writer");
            store.create_tables().await.expect("tables");
            register_account(&store, ACCOUNT).await;
            commit(&store, |batch| {
                batch
                    .with_collection(V016Collection::Mailbox)
                    .with_document(0)
                    .set(Field::ARCHIVE, archive(Mailbox::new("Inbox")))
                    .log_container_insert(SyncCollection::Email);
            })
            .await;
        }
        let before = listing(dir);
        let source = V016Source::open(SourceConfig::new(config.clone()))
            .await
            .expect("open read-only");
        assert_eq!(source.accounts().await.expect("accounts").len(), 1);
        drop(source);
        assert_eq!(listing(dir), before);
        let probe = SourceConfig::new(config.clone());
        assert!(matches!(
            V016Source::probe_schema(&probe).await,
            Ok(StoreSchema::V016(_) | StoreSchema::Missing)
        ));
        assert!(
            V016Source::configured_file_system_blob_paths(&probe)
                .await
                .expect("blob paths")
                .is_empty()
        );
        assert_eq!(listing(dir), before);

        let live = Store::build(config.clone()).await.expect("writer");
        commit(&live, |batch| {
            batch
                .with_collection(V016Collection::Mailbox)
                .with_document(1)
                .set(Field::ARCHIVE, archive(Mailbox::new("Inbox")))
                .log_container_insert(SyncCollection::Email);
        })
        .await;
        assert!(dir.join("data.sqlite-wal").exists());
        let source = V016Source::open(SourceConfig::new(config))
            .await
            .expect("open read-only");
        let page = source
            .scan(ACCOUNT, Collection::Mailbox, None, 10)
            .await
            .expect("scan");
        assert_eq!(page.batch.len(), 2);
        drop(source);

        let links = tempfile::tempdir().expect("link dir");
        let link = links.path().join("link.sqlite");
        std::os::unix::fs::symlink(dir.join("data.sqlite"), &link).expect("symlink");
        let linked = registry::schema::structs::DataStore::Sqlite(structs::SqliteStore {
            path: link.to_string_lossy().into_owned(),
            ..Default::default()
        });
        let source = V016Source::open(SourceConfig::new(linked))
            .await
            .expect("open through the symlink");
        let page = source
            .scan(ACCOUNT, Collection::Mailbox, None, 10)
            .await
            .expect("scan");
        assert_eq!(
            page.batch.len(),
            2,
            "the live -wal next to the real file is read"
        );
        drop(live);
    }

    fn rusqlite_connection(path: &Path) -> rusqlite::Connection {
        rusqlite::Connection::open(path).expect("connection")
    }
}

// A reader sharing the rollback target's store picks up a blob store configured after it was built only through catch_up.
#[tokio::test]
async fn shared_reader_rereads_the_blob_store_on_catch_up() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = tempfile::tempdir().expect("blob dir");
    seed(dir.path()).await;
    let store = Store::build(rocks(dir.path())).await.expect("writer");
    let reader = V016Source::from_store(store.clone())
        .await
        .expect("shared reader");
    let hash = [BlobHash(
        *store::blake3::hash(crate::testkit::BLOB).as_bytes(),
    )];
    assert_eq!(reader.blobs_exist(&hash).await.expect("exists"), [true]);
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::BlobStore.to_id(),
            item_id: Id::singleton().id(),
        }),
        ObjectInner::BlobStore(structs::BlobStore::FileSystem(structs::FileSystemStore {
            path: blobs.path().to_string_lossy().into_owned(),
            ..Default::default()
        }))
        .to_pickled_vec(),
    );
    store.write(batch.build_all()).await.expect("registry");
    assert_eq!(reader.blobs_exist(&hash).await.expect("exists"), [true]);
    reader.catch_up().await.expect("catch up");
    assert_eq!(reader.blobs_exist(&hash).await.expect("exists"), [false]);
}

// Undecodable registry entries are skipped and reported without stalling or ending pagination.
#[tokio::test]
async fn registry_pages_skip_unreadable_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let singleton = Id::singleton().id();
    let bad: [u64; 6] = [2, 4, 5, 6, 10, singleton];
    {
        let store = Store::build(rocks(dir.path())).await.expect("writer");
        let mut batch = BatchBuilder::new();
        for id in (1..=10u64).chain([singleton]) {
            let value = if bad.contains(&id) {
                b"\xffnot a pickled registry object".to_vec()
            } else {
                ObjectInner::Domain(structs::Domain {
                    name: format!("d{id}.org"),
                    ..Default::default()
                })
                .to_pickled_vec()
            };
            batch.set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: ObjectType::Domain.to_id(),
                    item_id: id,
                }),
                value,
            );
        }
        store.write(batch.build_all()).await.expect("registry");
    }
    let source = source(dir.path()).await;
    let mut after = None;
    let mut pages = Vec::new();
    loop {
        let page = source
            .registry_page("Domain", after, 2)
            .await
            .expect("page");
        let ids: Vec<RegistryId> = page.records.iter().map(|record| record.key.id).collect();
        let unreadable: Vec<RegistryId> = page.unreadable.iter().map(|key| key.id).collect();
        let Some(&RegistryId::Id(last)) = ids.last() else {
            pages.push((ids, unreadable));
            break;
        };
        after = Some(last);
        pages.push((ids, unreadable));
    }
    let id = RegistryId::Id;
    assert_eq!(
        pages,
        [
            (vec![id(1), id(3)], vec![id(2)]),
            (vec![id(7), id(8)], vec![id(4), id(5), id(6)]),
            (vec![id(9)], vec![id(10), RegistryId::Singleton]),
            (vec![], vec![id(10), RegistryId::Singleton]),
        ]
    );
}

// Registry decode errors do not leak the raw stored value into the message.
#[test]
fn trc_error_omits_the_stored_value() {
    let key = [
        ObjectType::Domain.to_id().to_be_bytes().as_slice(),
        &1u64.to_be_bytes(),
    ]
    .concat();
    let err = <Object as Deserialize>::deserialize_with_key(&key, b"\xffprivate key material")
        .expect_err("undecodable");
    let shown = err.value(Key::Value).expect("value").to_string();
    assert!(shown.len() > 8 && err.to_string().contains(&shown));
    let message = trc_error(err).to_string();
    assert!(!message.contains(&shown), "{message}");
    assert!(
        message.contains("registry.deserialization-error"),
        "{message}"
    );
}
