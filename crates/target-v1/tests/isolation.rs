/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::{
    io::ErrorKind,
    net::TcpListener,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use model::{
    BlobHash, Edition, EmailRecord, Ftrl, FtrlWeight, GlobalBatch, IssueKind, MailboxRecord,
    MailboxUid, RecordBatch, RegistryKey, RegistryRecord, SampleReservoir, Severity,
    SpamClassifierModel, SpamModelChange, SpamModelKind, SpamModelRecord, SpamOptimizer,
    SpamTrainerModel, Target, WriteMode,
};
use registry::schema::enums::CompressionAlgo;
use serde_json::{Value, json};
use source_v1::spam_archive::{self, SpamBlob};
use store::{blake3, dispatch::lookup::KeyValue};
use target_v1::{TargetConfig, V1Target};
use types::{blob_hash::BlobHash as AppBlobHash, id::Id};

const ACCOUNT_ID: u32 = 7;
const BOOT_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const MESSAGE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Isolation\r\nMessage-ID: <iso@example.org>\r\n\r\nHello.\r\n";

struct Service {
    name: &'static str,
    listener: TcpListener,
}

impl Service {
    fn new(name: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        Service { name, listener }
    }

    fn address(&self) -> String {
        self.listener.local_addr().expect("address").to_string()
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().expect("address").port()
    }

    fn was_contacted(&self) -> bool {
        match self.listener.accept() {
            Ok(_) => true,
            Err(err) if err.kind() == ErrorKind::WouldBlock => false,
            Err(err) => panic!("{}: {err}", self.name),
        }
    }
}

fn record(object: &str, id: Option<u64>, json: Value) -> RegistryRecord {
    RegistryRecord {
        key: match id {
            Some(id) => RegistryKey::new(object, id),
            None => RegistryKey::singleton(object),
        },
        json,
    }
}

fn tenant(mut json: Value) -> Value {
    if cfg!(feature = "enterprise")
        && let Value::Object(map) = &mut json
    {
        map.insert("memberTenantId".into(), json!(Id::new(1).to_string()));
    }
    json
}

fn path(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

fn shared_services(dir: &Path, services: &mut Vec<Service>) -> Vec<RegistryRecord> {
    let mut add = |name: &'static str| {
        let service = Service::new(name);
        let address = service.address();
        let port = service.port();
        services.push(service);
        (address, port)
    };
    let (search, _) = add("search store");
    let (ldap, _) = add("ldap directory");
    let (oidc, _) = add("oidc directory");
    let (http_lookup, _) = add("http lookup");
    let (webhook, _) = add("webhook");
    let (otel, _) = add("otel tracer");
    #[cfg_attr(
        not(any(
            feature = "redis",
            feature = "sqlite",
            all(feature = "enterprise", feature = "postgres")
        )),
        allow(unused_mut)
    )]
    let mut records = vec![
        record(
            "SearchStore",
            None,
            json!({"@type": "Meilisearch", "url": format!("http://{search}")}),
        ),
        record(
            "Directory",
            Some(1),
            json!({"@type": "Ldap", "description": "ldap", "url": format!("ldap://{ldap}"), "baseDn": "dc=example,dc=org", "filterLogin": "(uid=?)", "filterRecipient": "(mail=?)", "groupClass": "group"}),
        ),
        record(
            "Directory",
            Some(2),
            json!({"@type": "Oidc", "description": "oidc", "issuerUrl": format!("http://{oidc}")}),
        ),
        record(
            "Authentication",
            None,
            json!({"directoryId": Id::new(1).to_string()}),
        ),
        record(
            "HttpLookup",
            Some(1),
            json!({"namespace": "http", "enable": true, "url": format!("http://{http_lookup}/list")}),
        ),
        record(
            "WebHook",
            Some(1),
            json!({"enable": true, "url": format!("http://{webhook}/hook")}),
        ),
        record(
            "Tracer",
            Some(1),
            json!({"@type": "OtelHttp", "enable": true, "url": format!("http://{otel}/otel")}),
        ),
        record(
            "Tracer",
            Some(2),
            json!({"@type": "Log", "enable": true, "path": path(dir, "logs")}),
        ),
    ];
    #[cfg(feature = "redis")]
    {
        let (redis, _) = add("redis");
        records.extend([
            record(
                "InMemoryStore",
                None,
                json!({"@type": "Redis", "url": format!("redis://{redis}")}),
            ),
            record(
                "Coordinator",
                None,
                json!({"@type": "Redis", "url": format!("redis://{redis}")}),
            ),
            record(
                "StoreLookup",
                Some(1),
                json!({"namespace": "shared", "store": {"@type": "Redis", "url": format!("redis://{redis}")}}),
            ),
        ]);
    }
    #[cfg(feature = "sqlite")]
    records.push(record(
        "StoreLookup",
        Some(2),
        json!({"namespace": "sqlite", "store": {"@type": "Sqlite", "path": path(dir, "lookup.sqlite")}}),
    ));
    #[cfg(all(feature = "enterprise", feature = "postgres"))]
    {
        let (_, tracing) = add("tracing store");
        let (_, metrics) = add("metrics store");
        records.extend([
            record(
                "TracingStore",
                None,
                json!({"@type": "PostgreSql", "host": "127.0.0.1", "port": tracing, "database": "x", "authUsername": "x"}),
            ),
            record(
                "MetricsStore",
                None,
                json!({"@type": "PostgreSql", "host": "127.0.0.1", "port": metrics, "database": "x", "authUsername": "x"}),
            ),
        ]);
    }
    records
}

async fn open_target(dir: &Path) -> V1Target {
    let config = dir.join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": path(dir, "data")}).to_string(),
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

fn base_records() -> Vec<RegistryRecord> {
    let mut records = Vec::new();
    if cfg!(feature = "enterprise") {
        records.push(record("Tenant", Some(1), json!({"name": "acme"})));
    }
    records.push(record(
        "Domain",
        Some(3),
        tenant(json!({"name": "example.org"})),
    ));
    records.push(record(
        "Account",
        Some(u64::from(ACCOUNT_ID)),
        tenant(json!({"@type": "User", "name": "bob", "domainId": Id::new(3).to_string()})),
    ));
    records
}

// Shared services configured in the migrated registry are never contacted or created while the target boots, writes, wipes and finalizes.
#[tokio::test(flavor = "multi_thread")]
async fn shared_services_are_never_contacted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = open_target(dir.path()).await;
    let mut services = Vec::new();
    let records = base_records()
        .into_iter()
        .chain(shared_services(dir.path(), &mut services))
        .collect::<Vec<_>>();
    let outcome = target.write_registry(&records).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    tokio::time::timeout(BOOT_TIMEOUT, target.start_server())
        .await
        .expect("the boot blocked on a shared service")
        .expect("server");
    let server = target.server().expect("server");
    assert!(server.core.storage.coordinator.is_none());
    assert!(server.get_lookup_store("http").is_none());
    let memory = server.in_memory_store();
    memory
        .key_set(KeyValue::new(b"isolation".to_vec(), b"local".to_vec()))
        .await
        .expect("in-memory write");
    assert_eq!(
        memory
            .key_get::<String>(b"isolation".to_vec())
            .await
            .expect("in-memory read")
            .as_deref(),
        Some("local")
    );
    let hash = BlobHash(*blake3::hash(MESSAGE).as_bytes());
    target
        .put_blob(&hash, Bytes::from_static(MESSAGE))
        .await
        .expect("blob");
    target
        .upsert(
            ACCOUNT_ID,
            &RecordBatch::Mailbox(vec![MailboxRecord {
                document_id: 0,
                name: "Inbox".into(),
                role: Some("inbox".into()),
                uid_validity: 1,
                ..Default::default()
            }]),
            WriteMode::Create,
        )
        .await
        .expect("mailbox");
    let email = RecordBatch::Email(vec![EmailRecord {
        document_id: 1,
        thread_id: 1,
        change_id: 11,
        received_at: 1_700_000_000,
        keywords: vec!["$seen".into()],
        mailboxes: vec![MailboxUid {
            mailbox_id: 0,
            uid: 1,
        }],
        blob_hash: hash,
        body_offset: 0,
        extra_headers: Box::default(),
        size: MESSAGE.len() as u32,
    }]);
    for mode in [WriteMode::Create, WriteMode::Replace] {
        let outcome = target
            .upsert(ACCOUNT_ID, &email, mode)
            .await
            .expect("email");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    }
    target.wipe_account(ACCOUNT_ID).await.expect("wipe");
    target
        .finalize_account(ACCOUNT_ID, &model::Counters::default())
        .await
        .expect("finalize account");
    target
        .finalize_store(model::CategorySet::defaults())
        .await
        .expect("finalize store");
    assert!(server.search_store().internal_fts().is_some());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let contacted = services
        .iter()
        .filter(|service| service.was_contacted())
        .map(|service| service.name)
        .collect::<Vec<_>>();
    assert!(contacted.is_empty(), "contacted: {contacted:?}");
    let created = ["lookup.sqlite", "logs"]
        .into_iter()
        .map(|name| dir.path().join(name))
        .filter(|path| path.exists())
        .collect::<Vec<PathBuf>>();
    assert!(created.is_empty(), "created: {created:?}");
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
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

async fn shared_blob_target(dir: &Path) -> V1Target {
    let target = open_target(dir).await;
    let records = base_records()
        .into_iter()
        .chain([RegistryRecord {
            key: RegistryKey::singleton("BlobStore"),
            json: json!({"@type": "FileSystem", "path": path(dir, "blobs"), "depth": 2}),
        }])
        .collect::<Vec<_>>();
    let outcome = target.write_registry(&records).await.expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    target
}

fn spam_writes(records: &[SpamModelRecord]) -> Vec<SpamModelChange> {
    records
        .iter()
        .cloned()
        .map(SpamModelChange::Write)
        .collect()
}

fn spam_models() -> Vec<SpamModelRecord> {
    vec![
        SpamModelRecord::Classifier(SpamClassifierModel::Fh {
            parameters: vec![0.25, -0.5],
            bias: 0.125,
            last_trained_at: 1_700_000_000,
        }),
        SpamModelRecord::Trainer(Box::new(SpamTrainerModel {
            optimizer: SpamOptimizer::Fh(Ftrl {
                alpha: 0.1,
                beta: 1.0,
                l1_ratio: 0.001,
                l2_ratio: 0.0001,
                zn: vec![FtrlWeight { z: 0.5, n: 2.0 }; 4],
                zn_bias: FtrlWeight { z: -0.25, n: 1.0 },
            }),
            spam: SampleReservoir::default(),
            ham: SampleReservoir::default(),
            last_id: 99,
        })),
    ]
}

// No path other than the final spam model step writes the spam model keys into an external blob store, which may be v0.16's.
#[tokio::test(flavor = "multi_thread")]
async fn spam_model_skips_shared_blob_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = shared_blob_target(dir.path()).await;
    let blobs = dir.path().join("blobs");
    let models = spam_models();
    let outcome = target
        .write_global(&GlobalBatch::SpamModel(models.clone()))
        .await
        .expect("spam model");
    assert_eq!(outcome.issues.len(), models.len(), "{:?}", outcome.issues);
    assert!(
        outcome
            .issues
            .iter()
            .all(|issue| issue.kind == IssueKind::Skipped)
    );
    target
        .finalize_account(ACCOUNT_ID, &model::Counters::default())
        .await
        .expect("finalize account");
    target
        .finalize_store(model::CategorySet::defaults())
        .await
        .expect("finalize store");
    assert_eq!(files_under(&blobs), Vec::<PathBuf>::new());
}

// The final step overwrites both keys in an external blob store in the v1 layout, even over a file of the same length, reports each change, and deletes a kind the source no longer has.
#[tokio::test(flavor = "multi_thread")]
async fn final_spam_model_overwrites_shared_blob_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = shared_blob_target(dir.path()).await;
    let blobs = dir.path().join("blobs");
    let models = spam_models();
    let outcome = target
        .apply_final_spam_model(&spam_writes(&models))
        .await
        .expect("final spam model");
    assert_eq!(outcome.issues.len(), 2, "{:?}", outcome.issues);
    assert!(
        outcome
            .issues
            .iter()
            .all(|issue| issue.kind == IssueKind::Changed
                && issue.severity == Severity::Info
                && issue.explains.is_none())
    );
    let files = files_under(&blobs);
    assert_eq!(files.len(), 2, "{files:?}");
    for file in &files {
        let len = std::fs::metadata(file).expect("metadata").len();
        std::fs::write(file, vec![0xA5; len as usize]).expect("stale model");
    }
    target
        .apply_final_spam_model(&spam_writes(&models))
        .await
        .expect("final spam model again");
    let blob_store = target.server().expect("server").blob_store();
    for model in &models {
        let blob = SpamBlob::of(model);
        let data = blob_store
            .get_blob(blob.key(), 0..usize::MAX)
            .await
            .expect("read model")
            .expect("model present");
        assert_eq!(&spam_archive::decode(blob, &data).expect("decode"), model);
    }

    let outcome = target
        .apply_final_spam_model(&[SpamModelChange::Delete(SpamModelKind::Trainer)])
        .await
        .expect("trainer reset");
    assert!(
        outcome
            .issues
            .iter()
            .any(|issue| issue.message.contains("spamTrainer") && issue.message.contains("deleted")),
        "{:?}",
        outcome.issues
    );
    assert_eq!(files_under(&blobs).len(), 1);
    assert!(
        !blob_store
            .has_blob(SpamBlob::Trainer.key())
            .await
            .expect("has trainer")
    );
}

// The final step deletes the cached bundle of every migrated Application from an external blob store, so v1 downloads its own instead of v0.16's.
#[tokio::test(flavor = "multi_thread")]
async fn final_step_discards_cached_app_bundles_in_shared_blob_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = shared_blob_target(dir.path()).await;
    let outcome = target
        .write_registry(&[record(
            "Application",
            Some(4),
            json!({"enable": true, "description": "web", "resourceUrl": "https://example.org/webui.zip", "urlPrefix": {"admin": true}}),
        )])
        .await
        .expect("application");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    let blob_store = target.server().expect("server").blob_store();
    let bundle = AppBlobHash::generate(format!("STALWART_APP_{}", Id::new(4)).as_bytes());
    let other = AppBlobHash::generate(b"STALWART_APP_unrelated");
    for key in [&bundle, &other] {
        blob_store
            .put_blob(key.as_slice(), b"stale bundle", CompressionAlgo::None)
            .await
            .expect("cached bundle");
    }
    let outcome = target
        .finalize_store(model::CategorySet::defaults())
        .await
        .expect("finalize store");
    assert_eq!(outcome.issues.len(), 1, "{:?}", outcome.issues);
    assert!(
        outcome.issues[0].severity == Severity::Info
            && outcome.issues[0].kind == IssueKind::Changed
            && outcome.issues[0].message.contains("cached bundle"),
        "{:?}",
        outcome.issues
    );
    assert!(
        !blob_store
            .has_blob(bundle.as_slice())
            .await
            .expect("has bundle")
    );
    assert!(
        blob_store
            .has_blob(other.as_slice())
            .await
            .expect("has other")
    );
    let outcome = target
        .finalize_store(model::CategorySet::defaults())
        .await
        .expect("finalize store again");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
}
