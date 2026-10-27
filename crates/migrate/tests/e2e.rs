/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use model::{
    Collection, GlobalBatch, GlobalCategory, LogCollection, LogRange, RecordBatch, ReportKind,
    Source,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use source_v1::{
    V1Source,
    testkit::{
        Corruption, QueuedCheck, account_exists, check_credentials, corrupt,
        logged_calendar_rename, logged_identity_copy, open, put_singleton, queued_message_state,
        remove_registry_object,
    },
};
use source_v016::{
    SourceConfig, V016Source,
    testkit::{
        ACCOUNT, DOMAIN_ID, EXTRA, OTP_URL, PASSWORD, PUBLIC_KEY_ID, QUEUE_QUOTA, QueueBlob,
        create_empty_rocksdb, delete_account_registry, put_dmarc_report, put_queued_message,
        put_spam_classifier, queue_blob_hash, remove_identity, remove_queued_message,
        remove_registry_object as remove_v016_registry_object, rename_identity, seed_credentials,
        seed_encryption_at_rest, seed_every_registry_type, seed_registry_object,
        seed_with_extra_headers,
    },
};
use state::{MetaKey, StateStore};
use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_stalwart-migrate");
const SOURCE_ROOT: &str = "/srv/stalwart-v016";
const TARGET_ROOT: &str = "/srv/stalwart-v1";
const EXIT_OK: i32 = 0;
const INCOMPLETE_ALONE: [&str; 7] = [
    "AiModel",
    "OidcProvider",
    "MailingList",
    "MaskedEmail",
    "MtaDeliverySchedule",
    "PublicKey",
    "SystemSettings",
];
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;
const LOST_ID: u64 = 41;

type ReportLine = (Option<String>, Option<i64>, String);

struct Scenario {
    dir: TempDir,
}

struct Verified {
    code: i32,
    unexplained: u64,
    accounts_checked: u64,
    rows: Vec<ReportLine>,
}

impl Scenario {
    async fn migrated() -> Self {
        let scenario = Self::seeded(false).await;
        let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
        assert_eq!(code, EXIT_OK, "prepare: {output}");
        let (code, output) = scenario.cli(&["run"], true);
        assert_eq!(code, EXIT_OK, "run: {output}");
        scenario
    }

    async fn seeded(every_registry_type: bool) -> Self {
        Self::seeded_with(every_registry_type, EXTRA).await
    }

    async fn seeded_with(every_registry_type: bool, extra_headers: &[u8]) -> Self {
        let scenario = Scenario {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        seed_with_extra_headers(&scenario.path("src"), extra_headers).await;
        if every_registry_type {
            seed_every_registry_type(&scenario.path("src"), &INCOMPLETE_ALONE).await;
        }
        std::fs::create_dir_all(scenario.path("state")).expect("state dir");
        std::fs::write(
            scenario.path("source.json"),
            format!("{{\"@type\":\"RocksDb\",\"path\":\"{SOURCE_ROOT}/data\"}}"),
        )
        .expect("source config");
        std::fs::write(
            scenario.path("target.json"),
            format!("{{\"@type\":\"RocksDb\",\"path\":\"{TARGET_ROOT}/data\"}}"),
        )
        .expect("target config");
        std::fs::write(scenario.path("state/answers.toml"), answers()).expect("answers");
        scenario
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn cli(&self, args: &[&str], target: bool) -> (i32, String) {
        let (command, rest) = args.split_first().expect("command");
        let mut cmd = Command::new(BINARY);
        cmd.arg(command)
            .arg("--source")
            .arg(self.path("source.json"))
            .arg("--state")
            .arg(self.path("state"))
            .arg("--path-map")
            .arg(format!("{SOURCE_ROOT}/data={}", self.path("src").display()));
        if target {
            cmd.arg("--target")
                .arg(self.path("target.json"))
                .arg("--target-path-map")
                .arg(format!("{TARGET_ROOT}/data={}", self.path("dst").display()));
        }
        let output = cmd.args(rest).output().expect("run stalwart-migrate");
        (
            output.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    }

    fn verify(&self) -> Verified {
        let (code, output) = self.cli(&["verify", "--full"], true);
        let (unexplained, accounts_checked, rows) = self.last_verify();
        assert!(
            code == EXIT_OK || code == EXIT_FAILURE,
            "verify crashed: {output}"
        );
        Verified {
            code,
            unexplained,
            accounts_checked,
            rows,
        }
    }

    fn last_verify(&self) -> (u64, u64, Vec<ReportLine>) {
        let conn = Connection::open_with_flags(
            self.path("state/state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("state");
        let (run_id, stats): (i64, String) = conn
            .query_row(
                "SELECT id, stats FROM run WHERE mode = 'verify' ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("verify run");
        let stats: Value = serde_json::from_str(&stats).expect("stats");
        let mut statement = conn
            .prepare("SELECT object, object_id, message FROM report WHERE run_id = ?1")
            .expect("query");
        let rows = statement
            .query_map([run_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("rows")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("rows");
        (
            stats["unexplained"].as_u64().expect("unexplained"),
            stats["accounts_checked"].as_u64().expect("accounts"),
            rows,
        )
    }

    fn final_done(&self) -> bool {
        let conn = Connection::open_with_flags(
            self.path("state/state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("state");
        conn.query_row(
            "SELECT COUNT(*) FROM meta WHERE key = 'final_done'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("meta")
            == 1
    }

    fn mark_registry_error(&self, object: &str, id: u64) {
        let conn = Connection::open(self.path("state/state.sqlite")).expect("state");
        let updated = conn
            .execute(
                "UPDATE registry_object SET status = 'error', stored_hash = NULL WHERE object = ?1 AND id = ?2",
                rusqlite::params![object, i64::try_from(id).expect("id")],
            )
            .expect("update");
        assert_eq!(updated, 1, "{object}/{id} is not in the forward state");
    }

    fn unconverted_registry(&self) -> Vec<(String, u64)> {
        let conn = Connection::open_with_flags(
            self.path("state/state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("state");
        let mut statement = conn
            .prepare("SELECT object, id FROM registry_object WHERE status IN ('dropped', 'error') AND singleton = 0 AND length(source_json) > 0")
            .expect("query");
        statement
            .query_map([], |row| {
                let object: String = row.get(0)?;
                let id: i64 = row.get(1)?;
                Ok((
                    object.strip_prefix("x:").unwrap_or(&object).to_string(),
                    u64::try_from(id).expect("id"),
                ))
            })
            .expect("rows")
            .collect::<rusqlite::Result<Vec<(String, u64)>>>()
            .expect("rows")
            .into_iter()
            .filter(|(object, _)| source_v1::registry_object_is_stored(object))
            .collect()
    }

    fn run_rows(&self, severity: &str) -> Vec<String> {
        let conn = Connection::open_with_flags(
            self.path("state/state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("state");
        let mut statement = conn
            .prepare("SELECT message FROM report WHERE severity = ?1")
            .expect("query");
        statement
            .query_map([severity], |row| row.get(0))
            .expect("rows")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("rows")
    }
}

fn answers() -> String {
    let (edition, enterprise_on_oss) = if cfg!(feature = "enterprise") {
        ("enterprise", "")
    } else {
        ("oss", "[global.enterprise_on_oss]\naction = \"drop\"\n")
    };
    format!(
        "version = 1\n\
         [global.target_store]\n\
         store = {{ \"@type\" = \"RocksDb\", path = \"{TARGET_ROOT}/data\" }}\n\
         [global.blob_store]\n\
         mode = \"reuse\"\n\
         [global.edition]\n\
         edition = \"{edition}\"\n\
         [global.categories]\n\
         include = [\"settings\", \"principals\", \"mail\", \"calendars\", \"contacts\", \"files\", \"sieve\", \"identities\", \"push_subscriptions\", \"spam_samples\", \"reports\", \"archive\", \"spam_model\"]\n\
         [global.changed_defaults]\n\
         policy = \"recommended\"\n\
         overrides = {{}}\n\
         {enterprise_on_oss}"
    )
}

fn describe(rows: &[ReportLine]) -> Vec<String> {
    rows.iter()
        .map(|(object, id, message)| format!("{object:?}/{id:?}: {message}"))
        .collect()
}

// A clean migration verifies, explains only the reported dead property drop, and finalizes.
#[tokio::test(flavor = "multi_thread")]
async fn clean_migration_verifies_and_finalizes() {
    let scenario = Scenario::migrated().await;
    assert!(
        scenario.run_rows("error").is_empty(),
        "{:?}",
        scenario.run_rows("error")
    );
    let verified = scenario.verify();
    assert_eq!(verified.code, EXIT_OK, "{:#?}", describe(&verified.rows));
    assert_eq!(verified.unexplained, 0);
    assert_eq!(verified.accounts_checked, 1);
    assert_eq!(
        describe(&verified.rows),
        ["Some(\"calendar\")/Some(0): differs in the target: deadProperties"]
    );

    let (code, output) = scenario.cli(&["run", "--exclude", "calendars"], true);
    assert_eq!(code, EXIT_OK, "{output}");
    assert!(
        output.contains("data categories changed since the previous run; newly included categories are copied for every account by this run, and data of excluded categories stays in the target as last copied"),
        "{output}"
    );
    let verified = scenario.verify();
    assert_eq!(verified.code, EXIT_OK, "{:#?}", describe(&verified.rows));
    assert!(verified.rows.is_empty(), "{:#?}", describe(&verified.rows));

    std::fs::create_dir(scenario.path("state/final-report.txt")).expect("blocking directory");
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "{output}");
    assert!(output.contains("could not be written"), "{output}");
    std::fs::remove_dir(scenario.path("state/final-report.txt")).expect("remove directory");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--force-after-final",
        ],
        true,
    );
    assert_eq!(code, EXIT_OK, "{output}");
    let (unexplained, accounts_checked, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert_eq!(accounts_checked, 1);
    assert!(output.contains("Cutover checklist"), "{output}");
    let report =
        std::fs::read_to_string(scenario.path("state/final-report.txt")).expect("final report");
    assert!(
        report.contains("Verification mismatches of this run: 1"),
        "{report}"
    );
    assert!(report.contains("Cutover checklist"), "{report}");

    std::fs::remove_file(scenario.path("state/final-report.txt")).expect("remove report");
    {
        let store = open(&scenario.path("dst")).await;
        corrupt(&store, ACCOUNT, Corruption::EmailKeyword).await;
    }
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--force-after-final",
            "--verify-full",
        ],
        true,
    );
    assert_ne!(code, EXIT_OK, "{output}");
    assert!(!output.contains("Cutover checklist"), "{output}");
    assert!(!scenario.path("state/final-report.txt").exists());
}

async fn calendar_log_rows(scenario: &Scenario) -> Vec<u64> {
    let store = open(&scenario.path("dst")).await;
    V1Source::from_store(store)
        .changelog(
            ACCOUNT,
            LogCollection::Calendar,
            LogRange {
                after: 0,
                up_to: u64::MAX,
            },
            10_000,
        )
        .await
        .expect("changelog")
        .into_iter()
        .map(|row| row.change_id)
        .collect()
}

// v0.16 reopened after the final run and changed again: the forced final run replaces the "all updated" rows of the first finalize, verifies, and leaves one such row per DAV log.
#[tokio::test(flavor = "multi_thread")]
async fn forced_final_run_after_new_source_changes_verifies() {
    let scenario = Scenario::migrated().await;
    let final_run = ["run", "--final", "--yes", "--final-observation", "0"];
    let (code, output) = scenario.cli(&final_run, true);
    assert_eq!(code, EXIT_OK, "{output}");
    let first = calendar_log_rows(&scenario).await;
    rename_identity(&scenario.path("src"), 0, "Reopened").await;
    rename_identity(&scenario.path("src"), 0, "Reopened again").await;
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--force-after-final",
            "--verify-full",
        ],
        true,
    );
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(code, EXIT_OK, "{output}\n{:#?}", describe(&rows));
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    let later = calendar_log_rows(&scenario).await;
    assert_eq!(later.len(), first.len(), "{first:?} {later:?}");
    assert_eq!(later[..later.len() - 1], first[..first.len() - 1]);
    assert!(later.last() > first.last(), "{first:?} {later:?}");
}

// Server-added headers v1 cannot parse are dropped and explain both the headers and the size.
#[tokio::test(flavor = "multi_thread")]
async fn dropped_extra_headers_are_explained() {
    let scenario = Scenario::seeded_with(false, b"garbage line without colon\r\n").await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    let verified = scenario.verify();
    let rows = describe(&verified.rows);
    assert_eq!(verified.code, EXIT_OK, "{rows:#?}");
    assert!(
        rows.iter()
            .any(|row| row.contains("email") && row.contains("headers") && row.contains("size")),
        "{rows:#?}"
    );
}

fn listing(dir: &std::path::Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|entry| {
            let entry = entry.expect("entry");
            let metadata = entry.metadata().expect("metadata");
            (
                entry.path(),
                metadata.len(),
                metadata.modified().expect("modified"),
            )
        })
        .collect();
    files.sort();
    files
}

// Reading the v0.16 RocksDB store (prepare, runs, the final run and verify) leaves its directory untouched, info LOG files included.
#[tokio::test(flavor = "multi_thread")]
async fn reading_the_source_leaves_its_directory_untouched() {
    let scenario = Scenario::seeded(false).await;
    let before = listing(&scenario.path("src"));
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "second run: {output}");
    let verified = scenario.verify();
    assert_eq!(verified.code, EXIT_OK, "{:#?}", describe(&verified.rows));
    assert_eq!(listing(&scenario.path("src")), before);
}

// A target that is, or lies inside, the v0.16 store is refused before any store is opened.
#[tokio::test(flavor = "multi_thread")]
async fn target_overlapping_the_source_is_refused() {
    let scenario = Scenario::seeded(false).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let before = listing(&scenario.path("src"));
    let source = scenario.path("src").display().to_string();
    let alias = format!("/srv/alias/data={source}");
    let symlink = scenario.path("symlink");
    std::os::unix::fs::symlink(scenario.path("src"), &symlink).expect("symlink");
    for (kind, target, refusal) in [
        ("RocksDb", source.clone(), "overlaps"),
        ("RocksDb", format!("{source}/nested"), "overlaps"),
        ("RocksDb", "/srv/alias/data".to_string(), "overlaps"),
        (
            "RocksDb",
            format!("{}/nonexistent/../src", scenario.dir.path().display()),
            "overlaps",
        ),
        (
            "RocksDb",
            format!("{source}/./nested/../../src"),
            "overlaps",
        ),
        (
            "RocksDb",
            format!("{}/nested", symlink.display()),
            "overlaps",
        ),
        ("Sqlite", format!("file:{source}/CURRENT"), "SQLite URI"),
    ] {
        std::fs::write(
            scenario.path("target.json"),
            format!("{{\"@type\":\"{kind}\",\"path\":\"{target}\"}}"),
        )
        .expect("target config");
        let (code, output) = scenario.cli(&["run", "--target-path-map", alias.as_str()], true);
        assert_eq!(code, EXIT_USAGE, "{target}: {output}");
        assert!(output.contains(refusal), "{output}");
        assert_eq!(
            listing(&scenario.path("src")),
            before,
            "the source was modified"
        );
    }
}

const PGP_KEY: &str = include_str!("fixtures/cert_pgp.pem");

// An account with encryption at rest is written stripped, then completed by a deferred write after its public key; at any --batch-ops both must survive.
#[tokio::test(flavor = "multi_thread")]
async fn encryption_at_rest_survives_every_batch_size() {
    for batch_ops in ["1", "2", "3", "4", "8", "64", "1000"] {
        let scenario = Scenario::seeded(false).await;
        seed_encryption_at_rest(&scenario.path("src"), PGP_KEY).await;
        let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
        assert_eq!(code, EXIT_OK, "prepare: {output}");
        let (code, output) = scenario.cli(&["run", "--batch-ops", batch_ops], true);
        assert_eq!(code, EXIT_OK, "run --batch-ops {batch_ops}: {output}");
        let verified = scenario.verify();
        assert_eq!(
            (verified.code, verified.unexplained),
            (EXIT_OK, 0),
            "--batch-ops {batch_ops}: {:#?}",
            describe(&verified.rows)
        );
    }
}

// An account and the public key it encrypts with link to each other; when both leave the source, the next run unlinks the account and deletes the key before it, which v1 accepts only in that order.
#[tokio::test(flavor = "multi_thread")]
async fn deleted_account_and_its_public_key_are_unlinked_and_deleted() {
    let scenario = Scenario::seeded(false).await;
    seed_encryption_at_rest(&scenario.path("src"), PGP_KEY).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    delete_account_registry(&scenario.path("src")).await;
    remove_v016_registry_object(&scenario.path("src"), "PublicKey", PUBLIC_KEY_ID).await;
    let (code, output) = scenario.cli(&["run", "--allow-mass-removal"], true);
    assert_eq!(code, EXIT_OK, "{output}");
    let store = open(&scenario.path("dst")).await;
    assert!(!account_exists(&store, ACCOUNT).await);
}

// A v1 store this state did not create is refused before it is opened for writing, and so is a target other than the recorded one.
#[tokio::test(flavor = "multi_thread")]
async fn unowned_v1_target_is_refused_before_it_is_opened() {
    let scenario = Scenario::migrated().await;
    let before = listing(&scenario.path("dst"));
    std::fs::create_dir_all(scenario.path("fresh-state")).expect("fresh state");
    std::fs::copy(
        scenario.path("state/answers.toml"),
        scenario.path("fresh-state/answers.toml"),
    )
    .expect("answers");
    let output = Command::new(BINARY)
        .arg("run")
        .arg("--source")
        .arg(scenario.path("source.json"))
        .arg("--state")
        .arg(scenario.path("fresh-state"))
        .args([
            "--path-map",
            &format!("{SOURCE_ROOT}/data={}", scenario.path("src").display()),
            "--target-path-map",
            &format!("{TARGET_ROOT}/data={}", scenario.path("dst").display()),
        ])
        .arg("--target")
        .arg(scenario.path("target.json"))
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(text.contains("did not create"), "{text}");
    assert_eq!(listing(&scenario.path("dst")), before);

    std::fs::write(
        scenario.path("target.json"),
        format!("{{\"@type\":\"RocksDb\",\"path\":\"{TARGET_ROOT}/other\"}}"),
    )
    .expect("target config");
    let output = Command::new(BINARY)
        .arg("run")
        .arg("--source")
        .arg(scenario.path("source.json"))
        .arg("--state")
        .arg(scenario.path("state"))
        .args([
            "--path-map",
            &format!("{SOURCE_ROOT}/data={}", scenario.path("src").display()),
            "--target-path-map",
            &format!("{TARGET_ROOT}/other={}", scenario.path("other").display()),
        ])
        .arg("--target")
        .arg(scenario.path("target.json"))
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(text.contains("differs from the one recorded"), "{text}");
    assert!(!scenario.path("other").exists());
}

const SINGLETON_ID: u64 = 20080258862541;

// A --state inside the v0.16 file system blob store, or inside the v1 one the target path map makes of it, is refused before it is created.
#[tokio::test(flavor = "multi_thread")]
async fn state_inside_a_file_system_blob_store_is_refused() {
    let scenario = Scenario::seeded(false).await;
    seed_registry_object(
        &scenario.path("src"),
        "BlobStore",
        SINGLETON_ID,
        &serde_json::json!({"@type": "FileSystem", "path": "/srv/blobs"}),
    )
    .await;
    std::fs::create_dir_all(scenario.path("v016-blobs")).expect("blobs");
    let source_map = format!("{SOURCE_ROOT}/data={}", scenario.path("src").display());
    let blob_map = format!("/srv/blobs={}", scenario.path("v016-blobs").display());
    let target_map = format!("{TARGET_ROOT}/data={}", scenario.path("dst").display());
    let v1_blob_map = format!("/srv/blobs={}", scenario.path("v1-blobs").display());
    let before = listing(&scenario.path("v016-blobs"));
    for (command, state, refusal) in [
        (
            "prepare",
            "v016-blobs/state",
            "v0.16 file system blob store",
        ),
        ("run", "v016-blobs/state", "v0.16 file system blob store"),
        ("run", "V1-BLOBS/state", "v1 file system blob store"),
        ("verify", "v1-blobs/state", "v1 file system blob store"),
    ] {
        let mut cmd = Command::new(BINARY);
        cmd.arg(command)
            .arg("--source")
            .arg(scenario.path("source.json"))
            .arg("--state")
            .arg(scenario.path(state))
            .args(["--path-map", &source_map, "--path-map", &blob_map]);
        if command == "prepare" {
            cmd.arg("--non-interactive");
        } else {
            cmd.arg("--target")
                .arg(scenario.path("target.json"))
                .args(["--target-path-map", &target_map]);
            cmd.args(["--target-path-map", &v1_blob_map]);
        }
        let output = cmd.output().expect("run stalwart-migrate");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.status.code(),
            Some(EXIT_USAGE),
            "{command} {state}: {text}"
        );
        assert!(text.contains(refusal), "{command} {state}: {text}");
        assert!(!scenario.path(state).exists(), "{state} was created");
    }
    assert_eq!(listing(&scenario.path("v016-blobs")), before);
    assert!(!scenario.path("v1-blobs").exists());
}

// A rollback --state inside the v1 file system blob store is refused before it is created.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_state_inside_the_v1_blob_store_is_refused() {
    let scenario = Scenario::migrated().await;
    let blobs = scenario.path("v1-blobs");
    std::fs::create_dir_all(&blobs).expect("blobs");
    {
        let store = open(&scenario.path("dst")).await;
        put_singleton(
            &store,
            "BlobStore",
            &serde_json::json!({"@type": "FileSystem", "path": blobs.display().to_string()}),
        )
        .await;
    }
    std::fs::write(
        scenario.path("back.json"),
        format!(
            "{{\"@type\":\"RocksDb\",\"path\":\"{}\"}}",
            scenario.path("back").display()
        ),
    )
    .expect("rollback target");
    let state = blobs.join("rollback-state");
    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--yes")
        .arg("--source")
        .arg(scenario.path("target.json"))
        .args([
            "--path-map",
            &format!("{TARGET_ROOT}/data={}", scenario.path("dst").display()),
        ])
        .arg("--target")
        .arg(scenario.path("back.json"))
        .arg("--state")
        .arg(&state)
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(text.contains("v1 file system blob store"), "{text}");
    assert!(!state.exists());
    assert!(!scenario.path("back").exists());
}

// A rollback into a blob store shared with v1 is refused before it writes anything unless the spam model decision is explicit.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_into_a_shared_blob_store_needs_a_spam_model_decision() {
    let scenario = Scenario::migrated().await;
    let blobs = scenario.path("v1-blobs");
    std::fs::create_dir_all(&blobs).expect("blobs");
    std::fs::write(blobs.join("marker"), b"v1").expect("marker");
    {
        let store = open(&scenario.path("dst")).await;
        put_singleton(
            &store,
            "BlobStore",
            &serde_json::json!({"@type": "FileSystem", "path": blobs.display().to_string()}),
        )
        .await;
    }
    std::fs::write(
        scenario.path("back.json"),
        format!(
            "{{\"@type\":\"RocksDb\",\"path\":\"{}\"}}",
            scenario.path("back").display()
        ),
    )
    .expect("rollback target");
    let listing = |dir: &Path| {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("listing")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort_unstable();
        names
    };
    let before = listing(&blobs);
    let rollback = |extra: &[&str]| {
        let output = Command::new(BINARY)
            .arg("rollback")
            .arg("--yes")
            .arg("--source")
            .arg(scenario.path("target.json"))
            .args([
                "--path-map",
                &format!("{TARGET_ROOT}/data={}", scenario.path("dst").display()),
            ])
            .arg("--target")
            .arg(scenario.path("back.json"))
            .arg("--state")
            .arg(scenario.path("rollback-state"))
            .args(["--final-observation", "0"])
            .args(extra)
            .output()
            .expect("run stalwart-migrate");
        (
            output.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    let (code, text) = rollback(&[]);
    assert_eq!(code, Some(EXIT_USAGE), "{text}");
    assert!(text.contains("--keep-v1-spam-model"), "{text}");
    assert_eq!(listing(&blobs), before);
    assert!(!scenario.path("back").exists());
    {
        let state = state::SqliteState::open(scenario.path("rollback-state")).expect("state");
        assert_eq!(
            state.meta(MetaKey::TargetDefHash).await.expect("meta"),
            None
        );
        assert_eq!(state.meta(MetaKey::TargetClaim).await.expect("meta"), None);
    }

    let (code, text) = rollback(&["--keep-v1-spam-model", "--allow-errors"]);
    assert_eq!(code, Some(EXIT_OK), "{text}");
    assert!(!text.contains("blob store in the blob store"), "{text}");
    assert!(
        !text.contains("pass --allow-shared-deletes to write"),
        "{text}"
    );
    assert!(
        text.contains("as v1 wrote them (--keep-v1-spam-model)"),
        "{text}"
    );

    let (code, text) = rollback(&["--keep-v1-spam-model", "--allow-shared-deletes"]);
    assert_eq!(code, Some(EXIT_USAGE), "{text}");
}

// rollback asks for the same confirmation as run --final and refuses without a terminal unless --yes is given.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_requires_a_confirmation() {
    let scenario = Scenario::migrated().await;
    std::fs::write(
        scenario.path("back.json"),
        format!(
            "{{\"@type\":\"RocksDb\",\"path\":\"{}\"}}",
            scenario.path("back").display()
        ),
    )
    .expect("rollback target");
    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--source")
        .arg(scenario.path("target.json"))
        .arg("--target")
        .arg(scenario.path("back.json"))
        .arg("--state")
        .arg(scenario.path("rollback-state"))
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(
        text.contains("rollback needs an interactive confirmation"),
        "{text}"
    );
    assert!(!scenario.path("back").exists());
}

// A rollback whose verify fails tells the operator to repeat the rollback with the same state, not to run --final.
#[tokio::test(flavor = "multi_thread")]
async fn failed_rollback_verify_names_the_rollback_command() {
    let scenario = Scenario::migrated().await;
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    {
        let store = open(&scenario.path("dst")).await;
        corrupt(&store, ACCOUNT, Corruption::DeletedBlob).await;
    }
    for (name, path) in [("v1.json", "dst"), ("back.json", "back")] {
        std::fs::write(
            scenario.path(name),
            serde_json::json!({"@type": "RocksDb", "path": scenario.path(path)}).to_string(),
        )
        .expect("rollback config");
    }
    let rollback = |extra: &[&str]| {
        let output = Command::new(BINARY)
            .arg("rollback")
            .arg("--yes")
            .arg("--source")
            .arg(scenario.path("v1.json"))
            .arg("--target")
            .arg(scenario.path("back.json"))
            .arg("--state")
            .arg(scenario.path("rollback-state"))
            .args(["--final-observation", "0"])
            .args(extra)
            .output()
            .expect("run stalwart-migrate");
        (
            output.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    let (code, output) = rollback(&[]);
    assert_eq!(
        code, EXIT_FAILURE,
        "the lost blob blocks the rollback finalize: {output}"
    );
    assert!(!output.contains("verify:"), "{output}");
    remove_identity(&scenario.path("back"), 0).await;
    let (code, output) = rollback(&["--allow-errors"]);
    assert_eq!(code, EXIT_FAILURE, "{output}");
    assert!(output.contains("verify:"), "{output}");
    assert!(
        output.contains("run stalwart-migrate rollback again with the same --state"),
        "{output}"
    );
    assert!(!output.contains("run --final again"), "{output}");
}

// A rollback killed after an account checkpointed every collection (no account done) resumes and applies the v1 changes made since, also when their change ids are below the highest change id the killed run saw (tests8 run 14: v1 counts change ids per change group).
#[tokio::test(flavor = "multi_thread")]
async fn resumed_rollback_applies_changes_of_lower_change_groups() {
    const NEW_IDENTITY: u32 = 7;
    const RENAMED: &str = "renamed in v1";
    let scenario = Scenario::migrated().await;
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    for (name, path) in [("v1.json", "dst"), ("back.json", "back")] {
        std::fs::write(
            scenario.path(name),
            serde_json::json!({"@type": "RocksDb", "path": scenario.path(path)}).to_string(),
        )
        .expect("rollback config");
    }
    let rollback = || {
        let output = Command::new(BINARY)
            .arg("rollback")
            .arg("--yes")
            .arg("--source")
            .arg(scenario.path("v1.json"))
            .arg("--target")
            .arg(scenario.path("back.json"))
            .arg("--state")
            .arg(scenario.path("rollback-state"))
            .args(["--final-observation", "0", "--verify-full"])
            .output()
            .expect("run stalwart-migrate");
        (
            output.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    let account = async |reader: &V1Source| {
        reader
            .accounts()
            .await
            .expect("accounts")
            .into_iter()
            .find(|account| account.account_id == ACCOUNT)
            .expect("account")
    };
    {
        let store = open(&scenario.path("dst")).await;
        let reader = V1Source::from_store(store.clone());
        loop {
            logged_identity_copy(&store, ACCOUNT, NEW_IDENTITY).await;
            let bounds = reader
                .change_bounds(account(&reader).await)
                .await
                .expect("bounds");
            if bounds.collection(Collection::Identity) > bounds.collection(Collection::Calendar) {
                break;
            }
        }
    }
    let (code, output) = rollback();
    assert_eq!(code, EXIT_OK, "rollback: {output}");
    {
        let conn = Connection::open(scenario.path("rollback-state/state.sqlite")).expect("state");
        conn.execute_batch(&format!(
            "DELETE FROM meta WHERE key = 'final_done';
             UPDATE account SET phase = 'full', full_target = checkpoint, checkpoint = NULL WHERE account_id = {ACCOUNT};
             DELETE FROM cursor WHERE account_id = {ACCOUNT} AND mode <> 'checkpoint';"
        ))
        .expect("rewind to the killed rollback");
    }
    {
        let store = open(&scenario.path("dst")).await;
        let reader = V1Source::from_store(store.clone());
        let before = account(&reader).await;
        let highest = reader.counters(ACCOUNT).await.expect("counters").change_id;
        logged_calendar_rename(&store, ACCOUNT, 0, RENAMED).await;
        let after = account(&reader).await;
        assert!(
            after.change_counter > before.change_counter,
            "a change in any group moves the account counter"
        );
        let bounds = reader.change_bounds(after).await.expect("bounds");
        assert!(
            bounds.collection(Collection::Calendar) <= highest,
            "the calendar change id must not exceed the highest id the first rollback saw"
        );
    }
    let (code, output) = rollback();
    assert_eq!(code, EXIT_OK, "resumed rollback: {output}");
    let recopied: i64 = Connection::open(scenario.path("rollback-state/state.sqlite"))
        .expect("state")
        .query_row(
            "SELECT COUNT(*) FROM report WHERE message LIKE '%copying the account again%'",
            [],
            |row| row.get(0),
        )
        .expect("report");
    assert_eq!(
        recopied, 0,
        "the resumed account must catch up, not be copied again"
    );
    let page =
        V016Source::open(SourceConfig::from_file(scenario.path("back.json")).expect("config"))
            .await
            .expect("open the rolled back store")
            .read(ACCOUNT, Collection::Calendar, &[0])
            .await
            .expect("read");
    let RecordBatch::Calendar(calendars) = page.batch else {
        panic!("calendar batch");
    };
    assert_eq!(
        calendars.first().map(|calendar| &*calendar.name),
        Some(RENAMED),
        "the v1 change was not rolled back"
    );
}

const BULK_EMAILS: u32 = 3000;

async fn large_account_copy(target_config: Option<&Path>) {
    let scenario = Scenario::seeded(false).await;
    source_v016::testkit::seed_bulk_emails(&scenario.path("src"), BULK_EMAILS).await;
    if let Some(config) = target_config {
        std::fs::copy(config, scenario.path("target.json")).expect("target config");
    }
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--account-split",
            "8",
            "--concurrency",
            "8",
            "--batch-ops",
            "50",
        ],
        true,
    );
    assert_eq!(code, EXIT_OK, "run: {output}");
    assert!(
        output.contains(&format!("\"emails_written\":{}", BULK_EMAILS + 1)),
        "{output}"
    );
    let verified = scenario.verify();
    assert_eq!(verified.code, EXIT_OK, "{:#?}", describe(&verified.rows));
    assert_eq!(verified.unexplained, 0);
}

// One account of a few thousand emails is copied with eight write slots and verifies in full.
#[tokio::test(flavor = "multi_thread")]
async fn large_account_is_copied_with_parallel_slots() {
    large_account_copy(None).await;
}

async fn assert_unexplained(corruption: Corruption, object: Option<&str>, needle: &str) {
    let scenario = Scenario::migrated().await;
    let store = open(&scenario.path("dst")).await;
    corrupt(&store, ACCOUNT, corruption).await;
    drop(store);
    let verified = scenario.verify();
    let rows = describe(&verified.rows);
    assert_eq!(verified.code, EXIT_FAILURE, "{corruption:?}: {rows:#?}");
    assert!(verified.unexplained > 0, "{corruption:?}: {rows:#?}");
    assert!(
        verified
            .rows
            .iter()
            .any(|(row_object, _, message)| row_object.as_deref() == object
                && message.contains(needle)),
        "{corruption:?}: {rows:#?}"
    );
}

macro_rules! corruption_tests {
    ($($name:ident => $corruption:ident, $object:expr, $needle:literal;)*) => {
        $(
            // The corruption is reported as an unexplained verify mismatch.
            #[tokio::test(flavor = "multi_thread")]
            async fn $name() {
                assert_unexplained(Corruption::$corruption, $object, $needle).await;
            }
        )*

        #[test]
        fn every_corruption_is_tested() {
            let tested = [$(Corruption::$corruption),*];
            assert!(Corruption::ALL.iter().all(|corruption| tested.contains(corruption)));
        }
    };
}

corruption_tests! {
    email_keyword => EmailKeyword, Some("email"), "keywords";
    email_uid => EmailUid, Some("email"), "mailboxes";
    email_headers => EmailHeaders, Some("email"), "headers";
    mailbox_acl => MailboxAcl, Some("mailbox"), "acls";
    event_summary => EventSummary, Some("calendarEvent"), "icalendar";
    calendar_name => CalendarName, Some("calendar"), "name";
    extra_identity => ExtraIdentity, Some("identity"), "present in the target but not in the source";
    mailbox_uid_counter => MailboxUidCounter, None, "UID counter";
    last_email_log_row => LastEmailLogRow, None, "changelog Email";
    first_email_log_row => FirstEmailLogRow, None, "is missing in the target";
    extra_member_group => ExtraMemberGroup, Some("x:Account"), "differs";
    extra_allowed_ip => ExtraAllowedIp, Some("x:Account"), "differs";
    admin_role => AdminRole, Some("x:Account"), "differs";
    lost_secret => LostSecret, Some("x:Account"), "differs";
    extra_domain => ExtraDomain, Some("x:Domain"), "not in the source";
    deleted_blob => DeletedBlob, Some("email"), "blob";
    lost_active_script => LostActiveScript, None, "activeScript";
    wrong_default_calendar => WrongDefaultCalendar, None, "defaultCalendar";
    lost_push_subscriptions => LostPushSubscriptions, None, "pushSubscriptions";
    lost_share_notification => LostShareNotification, None, "share notification";
}

// Objects v1 rejects fail the first run only, block the final run, and are accepted with --allow-errors.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_settings_block_finalize_until_accepted() {
    let scenario = Scenario::seeded(true).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_FAILURE, "run: {output}");
    let errors = scenario.run_rows("error");
    assert!(!errors.is_empty());
    assert!(
        errors.iter().all(|row| !row.contains("not supported")),
        "{errors:#?}"
    );

    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(
        code, EXIT_OK,
        "unchanged rejections are not recounted: {output}"
    );
    assert_eq!(scenario.run_rows("error").len(), errors.len());

    let final_run = ["run", "--final", "--yes", "--final-observation", "0"];
    let (code, output) = scenario.cli(&final_run, true);
    assert_eq!(code, EXIT_FAILURE, "{output}");
    assert!(
        !output.contains("verify:"),
        "finalize must not run: {output}"
    );
    assert!(!scenario.final_done());

    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--allow-errors",
        ],
        true,
    );
    assert_eq!(code, EXIT_OK, "{output}");
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert!(rows.len() > errors.len() / 2, "accepted losses stay listed");
    assert!(scenario.final_done());

    let (code, output) = scenario.cli(&["run"], true);
    assert_ne!(
        code, EXIT_OK,
        "runs after the final run are refused: {output}"
    );
}

// Expired blocked and allowed IPs, which v1 deletes when it starts, are dropped instead of failing the next run and the final verify.
#[tokio::test(flavor = "multi_thread")]
async fn expired_ip_objects_are_dropped_and_verify() {
    const KEPT_ID: u64 = LOST_ID + 2;
    let scenario = Scenario::seeded(false).await;
    for (object, id, expires) in [
        ("BlockedIp", LOST_ID, "2024-01-01T01:00:00Z"),
        ("AllowedIp", LOST_ID + 1, "2024-01-01T01:00:00Z"),
        ("BlockedIp", KEPT_ID, "2999-01-01T00:00:00Z"),
    ] {
        seed_registry_object(
            &scenario.path("src"),
            object,
            id,
            &serde_json::json!({"address": format!("192.0.2.{id}"), "createdAt": "2024-01-01T00:00:00Z", "expiresAt": expires}),
        )
        .await;
    }
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    for _ in 0..2 {
        let (code, output) = scenario.cli(&["run"], true);
        assert_eq!(code, EXIT_OK, "run: {output}");
    }
    let mut dropped = scenario.unconverted_registry();
    dropped.sort_unstable();
    assert_eq!(
        dropped,
        [
            ("AllowedIp".to_string(), LOST_ID + 1),
            ("BlockedIp".to_string(), LOST_ID)
        ]
    );
    seed_registry_object(
        &scenario.path("src"),
        "BlockedIp",
        KEPT_ID,
        &serde_json::json!({"address": format!("192.0.2.{KEPT_ID}"), "createdAt": "2024-01-01T00:00:00Z", "expiresAt": "2024-01-01T01:00:00Z"}),
    )
    .await;
    let verified = scenario.verify();
    assert_eq!(verified.unexplained, 0, "{:#?}", describe(&verified.rows));
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert!(scenario.final_done());
}

// An expired certificate nothing refers to, which v1 deletes when it starts, is dropped instead of failing the next run and the final verify.
#[tokio::test(flavor = "multi_thread")]
async fn expired_certificate_is_dropped_and_verifies() {
    let scenario = Scenario::seeded(false).await;
    seed_registry_object(
        &scenario.path("src"),
        "Certificate",
        LOST_ID,
        &serde_json::json!({"certificate": {"@type": "Text", "value": "-----BEGIN CERTIFICATE-----"}, "privateKey": {"@type": "Text", "secret": "key"}, "subjectAlternativeNames": {"old.example.org": true}, "notValidAfter": "2024-01-01T00:00:00Z", "notValidBefore": "2023-01-01T00:00:00Z", "issuer": "CA"}),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    for _ in 0..2 {
        let (code, output) = scenario.cli(&["run"], true);
        assert_eq!(code, EXIT_OK, "run: {output}");
    }
    assert!(
        scenario
            .unconverted_registry()
            .contains(&("Certificate".to_string(), LOST_ID))
    );
    let verified = scenario.verify();
    assert_eq!(verified.unexplained, 0, "{:#?}", describe(&verified.rows));
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
}

// Password, OTP, app password and API key credentials survive inside the account object.
#[tokio::test(flavor = "multi_thread")]
async fn credentials_survive_the_migration() {
    let scenario = Scenario::seeded(false).await;
    let seeded = seed_credentials(&scenario.path("src")).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    let store = open(&scenario.path("dst")).await;
    let check = check_credentials(
        &store,
        ACCOUNT,
        PASSWORD,
        &seeded.app_password,
        &seeded.api_key,
    )
    .await;
    drop(store);
    assert!(check.password, "{check:?}");
    assert_eq!(check.otp_url.as_deref(), Some(OTP_URL));
    assert!(check.app_password, "{check:?}");
    assert!(check.api_key, "{check:?}");
    let verified = scenario.verify();
    assert_eq!(verified.code, EXIT_OK, "{:#?}", describe(&verified.rows));
}

// An account vanishing from the source registry trips both removal guards and blocks the final run.
#[tokio::test(flavor = "multi_thread")]
async fn vanished_accounts_are_kept_and_block_finalize() {
    let scenario = Scenario::migrated().await;
    delete_account_registry(&scenario.path("src")).await;
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_FAILURE, "{output}");
    assert!(
        !output.contains("verify:"),
        "finalize must not run: {output}"
    );
    assert!(!scenario.final_done());
    let errors = scenario.run_rows("error");
    assert!(
        errors.iter().any(|row| row.contains("fewer accounts")),
        "{errors:#?}"
    );
    assert!(
        errors
            .iter()
            .any(|row| row.contains("fewer x:Account objects")),
        "{errors:#?}"
    );
    let store = open(&scenario.path("dst")).await;
    assert!(account_exists(&store, ACCOUNT).await);
    drop(store);

    let (code, output) = scenario.cli(&["run", "--allow-mass-removal"], true);
    assert_eq!(code, EXIT_OK, "{output}");
    let store = open(&scenario.path("dst")).await;
    assert!(!account_exists(&store, ACCOUNT).await);
}

// Account data left in v1 after its Account object was deleted (the wipe did not run) is reported by verify as an extra account.
#[tokio::test(flavor = "multi_thread")]
async fn unwiped_account_without_its_object_is_an_extra() {
    let scenario = Scenario::migrated().await;
    delete_account_registry(&scenario.path("src")).await;
    {
        let store = open(&scenario.path("dst")).await;
        remove_registry_object(&store, "Account", u64::from(ACCOUNT)).await;
    }
    let verified = scenario.verify();
    let extra = format!("account {ACCOUNT} exists in the target but not in the source");
    assert!(
        verified
            .rows
            .iter()
            .any(|(_, _, message)| message.contains(&extra)),
        "{:#?}",
        describe(&verified.rows)
    );
}

// The v1 target records the claim id of the state that created it; a state with another claim id is refused.
#[tokio::test(flavor = "multi_thread")]
async fn target_claimed_by_another_state_is_refused() {
    let scenario = Scenario::migrated().await;
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "the owning state resumes: {output}");
    let claim;
    {
        let state = state::SqliteState::open(scenario.path("state")).expect("state");
        let recorded = state.meta(MetaKey::TargetClaim).await.expect("meta");
        claim = recorded
            .as_deref()
            .and_then(model::ClaimId::parse_hex)
            .expect("recorded claim");
        state
            .set_meta(
                MetaKey::TargetClaim,
                model::ClaimId::from_bytes([7; model::ClaimId::LEN]).to_string(),
            )
            .await
            .expect("meta");
    }
    let (code, output) = scenario.cli(&["run"], true);
    assert_ne!(code, EXIT_OK, "{output}");
    assert!(
        output.contains("created by another state directory"),
        "{output}"
    );

    {
        let state = state::SqliteState::open(scenario.path("state")).expect("state");
        state
            .set_meta(MetaKey::TargetClaim, claim.to_string())
            .await
            .expect("meta");
    }
    {
        let store = open(&scenario.path("dst")).await;
        source_v1::testkit::remove_target_claim(&store).await;
    }
    let (code, output) = scenario.cli(&["run"], true);
    assert_ne!(code, EXIT_OK, "{output}");
    assert!(output.contains("no claim"), "{output}");
}

// v0.16 to v1, changes made in v1, then rollback into a new v0.16 store that keeps them.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_round_trip_keeps_v1_changes() {
    const SPAM_TRAINED_AT: u64 = 1234;
    let scenario = Scenario::seeded(false).await;
    seed_registry_object(
        &scenario.path("src"),
        "ApiKey",
        LOST_ID,
        &serde_json::json!({}),
    )
    .await;
    seed_registry_object(
        &scenario.path("src"),
        "AllowedIp",
        LOST_ID,
        &serde_json::json!({"address": "192.0.2.1", "createdAt": "2024-01-01T00:00:00Z"}),
    )
    .await;
    put_spam_classifier(&scenario.path("src"), 0.25, SPAM_TRAINED_AT).await;
    let direct = scenario.path("direct.json");
    std::fs::write(
        &direct,
        serde_json::json!({"@type": "RocksDb", "path": scenario.path("src")}).to_string(),
    )
    .expect("config");
    let GlobalBatch::SpamModel(original_spam) =
        V016Source::open(SourceConfig::from_file(&direct).expect("config"))
            .await
            .expect("open source")
            .global_page(GlobalCategory::SpamModel, None, 10)
            .await
            .expect("source spam model")
            .batch
    else {
        panic!("spam model batch");
    };
    assert_eq!(original_spam.len(), 1);
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--allow-errors",
        ],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    {
        let store = open(&scenario.path("dst")).await;
        let GlobalBatch::SpamModel(migrated_spam) = global_page(
            &V1Source::from_store(store.clone()),
            GlobalCategory::SpamModel,
        )
        .await
        else {
            panic!("spam model batch");
        };
        assert_eq!(migrated_spam, original_spam);
        for change in [
            Corruption::EmailKeyword,
            Corruption::ExtraIdentity,
            Corruption::ExtraDomain,
        ] {
            corrupt(&store, ACCOUNT, change).await;
        }
        remove_registry_object(&store, "AllowedIp", LOST_ID).await;
        put_singleton(
            &store,
            "SearchStore",
            &serde_json::json!({"@type": "ElasticSearch", "url": "http://127.0.0.1:1"}),
        )
        .await;
    }
    scenario.mark_registry_error("x:AllowedIp", LOST_ID);
    let config = |name: &str, path: PathBuf| {
        let file = scenario.path(name);
        std::fs::write(
            &file,
            serde_json::json!({"@type": "RocksDb", "path": path}).to_string(),
        )
        .expect("config");
        file
    };
    let v1 = config("v1.json", scenario.path("dst"));
    let back = config("back.json", scenario.path("back"));
    let original = config("original.json", scenario.path("src"));
    let rollback_with = |source: &PathBuf, target: &PathBuf, state: &str, extra: &[&str]| {
        let output = Command::new(BINARY)
            .arg("rollback")
            .arg("--yes")
            .arg("--source")
            .arg(source)
            .arg("--target")
            .arg(target)
            .arg("--state")
            .arg(scenario.path(state))
            .arg("--forward-state")
            .arg(scenario.path("state"))
            .args(["--final-observation", "0"])
            .args(extra)
            .output()
            .expect("run stalwart-migrate");
        (
            output.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    let rollback_to =
        |target: &PathBuf, state: &str, extra: &[&str]| rollback_with(&v1, target, state, extra);
    let rollback = |extra: &[&str]| rollback_to(&back, "rollback-state", extra);
    let (code, output) = rollback_to(&v1, "refused-state", &[]);
    assert_eq!(code, EXIT_USAGE, "rollback into the v1 store: {output}");
    let before = listing(&scenario.path("src"));
    let (code, output) = rollback_to(&original, "refused-state", &[]);
    assert_eq!(
        code, EXIT_USAGE,
        "rollback into the original v0.16 store: {output}"
    );
    assert!(output.contains("overlaps"), "{output}");
    assert_eq!(listing(&scenario.path("src")), before);
    let (code, output) = rollback_to(&scenario.path("source.json"), "refused-state", &[]);
    assert_eq!(code, EXIT_USAGE, "{output}");
    assert!(
        output.contains("the v0.16 store the migration read from"),
        "{output}"
    );
    let (code, output) = rollback_with(
        &original,
        &config("unused.json", scenario.path("unused")),
        "refused-source-state",
        &[],
    );
    assert_eq!(code, EXIT_USAGE, "rollback from the v0.16 store: {output}");
    assert!(output.contains("overlaps"), "{output}");
    assert_eq!(listing(&scenario.path("src")), before);
    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--yes")
        .arg("--source")
        .arg(&original)
        .arg("--target")
        .arg(config("unused.json", scenario.path("unused")))
        .arg("--state")
        .arg(scenario.path("unforwarded-state"))
        .args(["--final-observation", "0"])
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(text.contains("is a v0.16 store"), "{text}");
    assert_eq!(listing(&scenario.path("src")), before);
    std::fs::create_dir_all(scenario.path("unused")).expect("unused");
    std::fs::write(scenario.path("unused/occupied"), b"data").expect("occupied");
    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--yes")
        .arg("--source")
        .arg(&v1)
        .arg("--target")
        .arg(config("unused.json", scenario.path("unused")))
        .arg("--state")
        .arg(scenario.path("unforwarded-state"))
        .args(["--final-observation", "0"])
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(text.contains("already exists"), "{text}");
    std::fs::remove_dir_all(scenario.path("unused")).expect("unused");
    let (code, output) = rollback_with(
        &scenario.path("source.json"),
        &config("unused.json", scenario.path("unused")),
        "refused-source-state",
        &[],
    );
    assert_eq!(code, EXIT_USAGE, "{output}");
    assert!(
        output.contains("the rollback source is the v0.16 store the migration read from"),
        "{output}"
    );
    let migrated = listing(&scenario.path("dst"));
    for state in [
        "dst/rollback-state",
        "src/rollback-state",
        "back/rollback-state",
    ] {
        let (code, output) = rollback_to(&back, state, &[]);
        assert_eq!(code, EXIT_USAGE, "state {state}: {output}");
        assert!(output.contains("overlaps"), "{output}");
        assert!(!scenario.path(state).exists(), "{state} was created");
    }
    for state in ["state", "src/../state"] {
        let (code, output) = rollback_to(&back, state, &[]);
        assert_eq!(code, EXIT_USAGE, "state {state}: {output}");
        assert!(output.contains("overlaps the --forward-state"), "{output}");
    }
    assert_eq!(listing(&scenario.path("dst")), migrated);
    assert_eq!(listing(&scenario.path("src")), before);
    assert!(!scenario.path("back").exists());
    let output = Command::new(BINARY)
        .arg("prepare")
        .arg("--non-interactive")
        .arg("--source")
        .arg(&original)
        .arg("--state")
        .arg(scenario.path("src/prepare-state"))
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{text}");
    assert!(text.contains("overlaps"), "{text}");
    assert_eq!(listing(&scenario.path("src")), before);
    let output = Command::new(BINARY)
        .arg("prepare")
        .arg("--non-interactive")
        .arg("--source")
        .arg(&v1)
        .arg("--state")
        .arg(scenario.path("forward-state"))
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(output.status.code(), Some(EXIT_OK), "{text}");
    assert!(text.contains("is a v1 store"), "{text}");
    assert_eq!(listing(&scenario.path("dst")), migrated);

    let (code, output) = rollback(&[]);
    let rolled_back = Scenario {
        dir: tempfile::tempdir().expect("tempdir"),
    };
    std::fs::create_dir_all(rolled_back.path("state")).expect("state");
    std::fs::copy(
        scenario.path("rollback-state/state.sqlite"),
        rolled_back.path("state/state.sqlite"),
    )
    .expect("copy state");
    let (_, _, rows) = rolled_back.last_verify();
    assert_eq!(code, EXIT_OK, "rollback: {output}\n{:#?}", describe(&rows));
    assert!(
        output.contains(
            "an account that must be recopied leaves its search index in place (email, calendar and contact documents in the external ElasticSearch search store)"
        ),
        "{output}"
    );
    assert!(
        !output.contains("rollback deletes nothing outside the new v0.16 store"),
        "{output}"
    );
    assert_eq!(listing(&scenario.path("dst")), migrated);

    let lost = scenario.unconverted_registry();
    assert!(!lost.is_empty(), "the forward run dropped nothing");
    let restored = rolled_back.run_rows("info");
    let source = V016Source::open(SourceConfig::from_file(&back).expect("config"))
        .await
        .expect("open rolled back store");
    let GlobalBatch::SpamModel(rolled_back_spam) = source
        .global_page(GlobalCategory::SpamModel, None, 10)
        .await
        .expect("rolled back spam model")
        .batch
    else {
        panic!("spam model batch");
    };
    assert_eq!(rolled_back_spam, original_spam);
    for (object, id) in &lost {
        let page = source
            .registry_page(object, id.checked_sub(1), 1)
            .await
            .expect("registry page")
            .records;
        assert!(
            page.first()
                .is_some_and(|record| record.key.id == model::RegistryId::Id(*id)),
            "{object}/{id} was not restored: {page:?}"
        );
    }
    assert!(
        restored
            .iter()
            .filter(|message| message.contains("restored from the --forward-state"))
            .count()
            >= lost.len(),
        "{restored:#?}"
    );
    let page = source
        .read(ACCOUNT, Collection::Identity, &[0, 5])
        .await
        .expect("identities");
    let RecordBatch::Identity(identities) = page.batch else {
        panic!("identity batch");
    };
    assert_eq!(identities.len(), 2);
    let page = source
        .read(ACCOUNT, Collection::Email, &[0])
        .await
        .expect("email");
    let RecordBatch::Email(emails) = page.batch else {
        panic!("email batch");
    };
    assert!(
        emails.first().is_some_and(|email| email
            .keywords
            .iter()
            .all(|keyword| keyword.starts_with('$'))),
        "{emails:?}"
    );
    let domains = source
        .registry_page("Domain", None, 100)
        .await
        .expect("domains")
        .records;
    assert!(
        domains
            .iter()
            .any(|record| record.json["name"] == "extra.example.org"),
        "{domains:?}"
    );
    drop(source);

    let (code, output) = rollback(&[]);
    assert_ne!(code, EXIT_OK, "repeated rollback: {output}");
    assert!(output.contains("already completed"), "{output}");

    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--yes")
        .arg("--source")
        .arg(&v1)
        .arg("--target")
        .arg(config("reverse.json", scenario.path("reverse")))
        .arg("--state")
        .arg(scenario.path("reverse-state"))
        .args(["--final-observation", "0"])
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::copy(
        scenario.path("reverse-state/state.sqlite"),
        rolled_back.path("state/state.sqlite"),
    )
    .expect("copy state");
    let (unexplained, _, rows) = rolled_back.last_verify();
    assert_eq!(
        output.status.code(),
        Some(EXIT_OK),
        "{text}\n{:#?}",
        describe(&rows)
    );
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert!(text.contains("no --forward-state"), "{text}");

    let claimed = config("claimed.json", scenario.path("claimed"));
    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--yes")
        .arg("--source")
        .arg(&original)
        .arg("--target")
        .arg(&claimed)
        .arg("--state")
        .arg(scenario.path("claimed-state"))
        .output()
        .expect("run stalwart-migrate");
    assert_eq!(output.status.code(), Some(EXIT_USAGE), "{output:?}");
    assert!(!scenario.path("claimed").exists());
    {
        let state = state::SqliteState::open(scenario.path("claimed-state")).expect("state");
        assert_eq!(
            state.meta(MetaKey::TargetDefHash).await.expect("meta"),
            None,
            "a refused rollback must not claim its target"
        );
        let definition: Value =
            serde_json::from_slice(&std::fs::read(&claimed).expect("config")).expect("json");
        let hash = state::ContentHash::of(&serde_json::to_vec(&definition).expect("json"));
        let hex: String = hash
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        state
            .set_meta(MetaKey::TargetDefHash, hex)
            .await
            .expect("claim");
    }
    create_empty_rocksdb(&scenario.path("claimed")).await;
    let (code, output) = rollback_with(&v1, &claimed, "other-state", &[]);
    assert_eq!(code, EXIT_USAGE, "{output}");
    assert!(output.contains("already exists"), "{output}");
    let elsewhere = config("elsewhere.json", scenario.path("elsewhere"));
    let (code, output) = rollback_with(&v1, &elsewhere, "claimed-state", &[]);
    assert_eq!(code, EXIT_USAGE, "{output}");
    assert!(
        output.contains("differs from the one this --state"),
        "{output}"
    );
    assert!(!scenario.path("elsewhere").exists());
    let (code, output) = rollback_with(&v1, &claimed, "claimed-state", &[]);
    assert_eq!(
        code, EXIT_OK,
        "a crash after the target was created must resume: {output}"
    );
    assert!(
        rolled_back
            .run_rows("warning")
            .iter()
            .any(|message| message.contains("cannot be restored")),
        "the rollback report does not say that dropped settings are lost"
    );
    assert!(
        rolled_back
            .run_rows("warning")
            .iter()
            .any(|message| message.contains("tasks and telemetry are not rolled back")),
        "the rollback report does not say what is not rolled back"
    );
    assert!(output.contains("are not rolled back"), "{output}");
}

async fn global_page(source: &V1Source, category: GlobalCategory) -> GlobalBatch {
    source
        .global_page(category, None, 100)
        .await
        .expect("global page")
        .batch
}

// Internal reports verify against what v1 can store: DMARC rows whose long human fields v1 compacts merge with summed counts, and TLS failure details come back in v1 key order.
#[tokio::test(flavor = "multi_thread")]
async fn compacted_report_rows_verify_after_the_final_run() {
    let scenario = Scenario::seeded(false).await;
    let src = scenario.path("src");
    let record = |human: &str, count: u64| {
        serde_json::json!({
            "sourceIp": "192.0.2.1",
            "count": count,
            "envelopeFrom": "sender.example",
            "headerFrom": "sender.example",
            "dkimResults": {"0": {"domain": "sender.example", "selector": "s1", "humanResult": human.repeat(300)}}
        })
    };
    seed_registry_object(
        &src,
        "DmarcInternalReport",
        3,
        &serde_json::json!({
            "domain": "example.org",
            "policyIdentifier": 3,
            "report": {"orgName": "example.org", "reportId": "dmarc-3", "records": {"0": record("a", 2), "1": record("b", 3)}}
        }),
    )
    .await;
    seed_registry_object(
        &src,
        "TlsInternalReport",
        4,
        &serde_json::json!({
            "domain": "example.org",
            "report": {"reportId": "tls-4", "policies": {"0": {
                "policyDomain": "example.org",
                "totalSuccessfulSessions": 5,
                "totalFailedSessions": 3,
                "failureDetails": {
                    "0": {"resultType": "certificateExpired", "failedSessionCount": 2},
                    "1": {"resultType": "startTlsNotSupported", "failedSessionCount": 1}
                }
            }}}
        }),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--verify-full",
            "--include",
            "queue",
        ],
        true,
    );
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{output}\n{:#?}", describe(&rows));
    assert_eq!(code, EXIT_OK, "{output}");
    assert!(scenario.final_done());
    let store = open(&scenario.path("dst")).await;
    let GlobalBatch::Reports(reports) = global_page(
        &V1Source::from_store(store.clone()),
        GlobalCategory::Reports,
    )
    .await
    else {
        panic!("reports page");
    };
    let dmarc = reports
        .iter()
        .find(|report| report.kind == ReportKind::Dmarc)
        .expect("dmarc report");
    let records = dmarc.json["report"]["records"]
        .as_array()
        .cloned()
        .or_else(|| {
            dmarc.json["report"]["records"]
                .as_object()
                .map(|rows| rows.values().cloned().collect())
        })
        .unwrap_or_default();
    assert_eq!(
        records.len(),
        1,
        "v1 compacts both rows into one: {records:?}"
    );
    assert_eq!(records[0]["count"], 5);
}

// v1 names the DMARC date range start dateRangeStart (v0.16 dateRangeBegin): both internal report kinds keep their date ranges instead of taking the migration time.
#[tokio::test(flavor = "multi_thread")]
async fn internal_report_date_ranges_survive_the_final_run() {
    const BEGIN: &str = "2020-01-01T00:00:00Z";
    const END: &str = "2020-01-02T00:00:00Z";
    let scenario = Scenario::seeded(false).await;
    let src = scenario.path("src");
    seed_registry_object(
        &src,
        "DmarcInternalReport",
        3,
        &serde_json::json!({
            "domain": "example.org",
            "policyIdentifier": 3,
            "createdAt": BEGIN,
            "deliverAt": END,
            "report": {
                "orgName": "example.org",
                "reportId": "dmarc-3",
                "dateRangeBegin": BEGIN,
                "dateRangeEnd": END,
                "records": {"0": {"sourceIp": "192.0.2.1", "count": 2, "envelopeFrom": "sender.example", "headerFrom": "sender.example"}}
            }
        }),
    )
    .await;
    seed_registry_object(
        &src,
        "TlsInternalReport",
        4,
        &serde_json::json!({
            "domain": "example.org",
            "createdAt": BEGIN,
            "deliverAt": END,
            "report": {"reportId": "tls-4", "dateRangeStart": BEGIN, "dateRangeEnd": END, "policies": {"0": {"policyDomain": "example.org", "totalSuccessfulSessions": 5}}}
        }),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--verify-full",
            "--include",
            "queue",
        ],
        true,
    );
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{output}\n{:#?}", describe(&rows));
    assert_eq!(code, EXIT_OK, "{output}");
    let store = open(&scenario.path("dst")).await;
    let GlobalBatch::Reports(reports) = global_page(
        &V1Source::from_store(store.clone()),
        GlobalCategory::Reports,
    )
    .await
    else {
        panic!("reports page");
    };
    assert_eq!(reports.len(), 2, "{reports:?}");
    for report in &reports {
        assert_eq!(
            report.json["report"]["dateRangeStart"], BEGIN,
            "{}",
            report.json
        );
        assert_eq!(
            report.json["report"]["dateRangeEnd"], END,
            "{}",
            report.json
        );
        assert_eq!(report.json["createdAt"], BEGIN, "{}", report.json);
    }
}

// v1 renamed or folded many event and metric types: spans (nested event values too) and metrics are copied under their v1 names, and a span or metric whose type v1 dropped is skipped with an explained warning instead of being stored with a defaulted type.
#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread")]
async fn telemetry_event_and_metric_types_take_their_v1_names() {
    use source_v016::testkit::{put_metric, put_span};
    const SINGLETON: u64 = 20_080_258_862_541;
    let span_events = |json: &serde_json::Value| -> Vec<String> {
        let events = &json["events"];
        events
            .as_array()
            .into_iter()
            .flatten()
            .chain(events.as_object().into_iter().flat_map(|map| map.values()))
            .filter_map(|event| event["event"].as_str().map(str::to_owned))
            .collect()
    };
    let scenario = Scenario::seeded(false).await;
    let src = scenario.path("src");
    for object in ["TracingStore", "MetricsStore"] {
        seed_registry_object(
            &src,
            object,
            SINGLETON,
            &serde_json::json!({"@type": "Default"}),
        )
        .await;
    }
    put_span(
        &src,
        10,
        &[
            "smtp.connection-start",
            "store.cache-hit",
            "dkim.failed-verification",
        ],
        Some("arc.broken-chain"),
    )
    .await;
    put_span(&src, 11, &["smtp.connection-start", "dkim.modified"], None).await;
    put_metric(&src, 20, "message-ingest.index-time", 3).await;
    put_metric(&src, 21, "dkim.modified", 1).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--verify-full",
            "--include",
            "telemetry",
        ],
        true,
    );
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{output}\n{:#?}", describe(&rows));
    assert_eq!(code, EXIT_OK, "{output}");
    let store = open(&scenario.path("dst")).await;
    let GlobalBatch::Telemetry(records) = global_page(
        &V1Source::from_store(store.clone()),
        GlobalCategory::Telemetry,
    )
    .await
    else {
        panic!("telemetry page");
    };
    let ids: Vec<(model::TelemetryKind, u64)> = records
        .iter()
        .map(|record| (record.kind, record.id))
        .collect();
    assert_eq!(
        ids,
        [
            (model::TelemetryKind::Span, 10),
            (model::TelemetryKind::Metric, 20)
        ],
        "{records:?}"
    );
    assert_eq!(
        span_events(&records[0].json),
        [
            "smtp.connection-start",
            "cache.hit",
            "dkim.verification-failed"
        ],
        "{}",
        records[0].json
    );
    assert!(
        records[0]
            .json
            .to_string()
            .contains("\"arc.chain-invalid\""),
        "{}",
        records[0].json
    );
    assert_eq!(
        records[1].json["metric"], "search-index.index-time",
        "{}",
        records[1].json
    );
}

// Span timestamps outside the RFC 3339 range (the unset -1 of queue.rescheduled, i64::MAX) are copied unchanged and pass verification.
#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread")]
async fn span_timestamps_outside_the_text_range_round_trip() {
    use source_v016::testkit::put_dated_span;
    const SINGLETON: u64 = 20_080_258_862_541;
    let scenario = Scenario::seeded(false).await;
    let src = scenario.path("src");
    seed_registry_object(
        &src,
        "TracingStore",
        SINGLETON,
        &serde_json::json!({"@type": "Default"}),
    )
    .await;
    put_dated_span(&src, 10, &[-1, 1_700_000_000]).await;
    put_dated_span(&src, 11, &[i64::MAX]).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(
        &[
            "run",
            "--final",
            "--yes",
            "--final-observation",
            "0",
            "--verify-full",
            "--include",
            "telemetry",
        ],
        true,
    );
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{output}\n{:#?}", describe(&rows));
    assert_eq!(code, EXIT_OK, "{output}");
    let store = open(&scenario.path("dst")).await;
    let GlobalBatch::Telemetry(records) = global_page(
        &V1Source::from_store(store.clone()),
        GlobalCategory::Telemetry,
    )
    .await
    else {
        panic!("telemetry page");
    };
    let [first, second] = records.as_slice() else {
        panic!("{records:?}");
    };
    for (record, event, expected) in [
        (first, "0", serde_json::json!(-1)),
        (first, "1", serde_json::json!("2023-11-14T22:13:20Z")),
        (second, "0", serde_json::json!(i64::MAX)),
    ] {
        let event = &record.json["events"][event];
        assert_eq!(event["timestamp"], expected, "{}", record.json);
        assert_eq!(
            event["keyValues"]["0"]["value"]["value"], expected,
            "{}",
            record.json
        );
        assert_eq!(
            event["keyValues"]["1"]["value"]["value"]["0"]["value"], expected,
            "{}",
            record.json
        );
    }
}

// A final run that does not finalize, then a changed and a removed queued message and a grown report: the next final run rewrites and deletes them.
#[tokio::test(flavor = "multi_thread")]
async fn later_final_run_rewrites_and_deletes_queue_and_reports() {
    const KEPT: &[u8] = b"Subject: kept\r\n\r\nkept\r\n";
    const REMOVED: &[u8] = b"Subject: removed\r\n\r\nremoved\r\n";
    const LOST: &[u8] = b"Subject: lost\r\n\r\nlost\r\n";
    let final_run = [
        "run",
        "--final",
        "--yes",
        "--final-observation",
        "0",
        "--verify-full",
        "--include",
        "queue",
    ];
    let scenario = Scenario::seeded(false).await;
    let src = scenario.path("src");
    put_queued_message(&src, 5, KEPT, QueueBlob::Stored, 0).await;
    put_queued_message(&src, 6, REMOVED, QueueBlob::Stored, 0).await;
    put_queued_message(&src, 7, LOST, QueueBlob::Missing, 0).await;
    put_dmarc_report(&src, 3, &[5]).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&final_run, true);
    assert_eq!(code, EXIT_FAILURE, "{output}");
    assert!(!scenario.final_done());
    let store = open(&scenario.path("dst")).await;
    let removed = queued_message_state(&store, 6, queue_blob_hash(REMOVED), QUEUE_QUOTA).await;
    assert_eq!(
        removed,
        QueuedCheck {
            message: true,
            blob_link: true,
            quota_size: i64::try_from(KEPT.len() + REMOVED.len()).expect("size"),
        }
    );
    drop(store);

    remove_queued_message(&src, 6).await;
    remove_queued_message(&src, 7).await;
    put_queued_message(&src, 5, KEPT, QueueBlob::Stored, 3).await;
    put_dmarc_report(&src, 3, &[5, 4]).await;
    let (code, output) = scenario.cli(&final_run, true);
    if code != EXIT_OK {
        let verify = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (unexplained, _, rows) = scenario.last_verify();
            (unexplained, describe(&rows))
        }));
        panic!("exit code {code}\n{output}\nlast verify: {verify:#?}");
    }
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert!(scenario.final_done());

    let store = open(&scenario.path("dst")).await;
    assert_eq!(
        queued_message_state(&store, 6, queue_blob_hash(REMOVED), QUEUE_QUOTA).await,
        QueuedCheck {
            message: false,
            blob_link: false,
            quota_size: i64::try_from(KEPT.len()).expect("size"),
        }
    );
    let reader = V1Source::from_store(store.clone());
    let GlobalBatch::Queue(queued) = global_page(&reader, GlobalCategory::Queue).await else {
        panic!("queue page");
    };
    assert_eq!(
        queued
            .iter()
            .map(|message| (message.queue_id, message.priority))
            .collect::<Vec<_>>(),
        [(5, 3)]
    );
    let GlobalBatch::Reports(reports) = global_page(&reader, GlobalCategory::Reports).await else {
        panic!("reports page");
    };
    assert_eq!(reports.len(), 1);
    let records = &reports[0].json["report"]["records"];
    let count: u64 = records
        .as_object()
        .into_iter()
        .flat_map(|rows| rows.values())
        .chain(records.as_array().into_iter().flatten())
        .filter_map(|row| row["count"].as_u64())
        .sum();
    assert_eq!(count, 9, "{records}");
    drop(reader);
    drop(store);
    let verified = scenario.verify();
    assert_eq!(verified.code, EXIT_OK);
    assert_eq!(verified.unexplained, 0, "{:#?}", describe(&verified.rows));
}

// Two rustls providers are compiled in with s3 (ring), so a TLS store opened before the v1 target must find the default the binary installs.
#[cfg(all(feature = "s3", feature = "postgres"))]
#[test]
fn tls_source_store_opens_with_both_crypto_providers() {
    const EXIT_PANIC: i32 = 101;
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source.json");
    std::fs::write(
        &source,
        r#"{"@type":"PostgreSql","host":"127.0.0.1","port":1,"database":"stalwart","useTls":true,"allowInvalidCerts":true}"#,
    )
    .expect("source config");
    let output = Command::new(BINARY)
        .arg("prepare")
        .arg("--non-interactive")
        .arg("--source")
        .arg(&source)
        .arg("--state")
        .arg(dir.path().join("state"))
        .output()
        .expect("run stalwart-migrate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(output.status.code(), Some(EXIT_PANIC), "{text}");
    assert!(!text.contains("CryptoProvider"), "{text}");
    assert!(text.contains("Connection refused"), "{text}");
}

#[cfg(any(feature = "postgres", feature = "foundation", feature = "mysql"))]
fn rollback(source: &PathBuf, target: &PathBuf, state: PathBuf) -> (i32, String) {
    let output = Command::new(BINARY)
        .arg("rollback")
        .arg("--yes")
        .arg("--source")
        .arg(source)
        .arg("--target")
        .arg(target)
        .arg("--state")
        .arg(state)
        .args(["--final-observation", "0"])
        .output()
        .expect("run stalwart-migrate");
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[cfg(any(feature = "postgres", feature = "foundation", feature = "mysql"))]
const PROBE_EDITION: model::Edition = if cfg!(feature = "enterprise") {
    model::Edition::Enterprise
} else {
    model::Edition::Community
};

#[cfg(any(feature = "postgres", feature = "foundation", feature = "mysql"))]
async fn create_v1_store(config: &std::path::Path) {
    use model::Target;
    let target = target_v1::V1Target::open(target_v1::TargetConfig {
        data_store: config.to_path_buf(),
        fdb_txn_bytes: 1,
    })
    .await
    .expect("v1 target");
    target
        .prepare_store(PROBE_EDITION)
        .await
        .expect("schema version");
}

#[cfg(any(feature = "postgres", feature = "foundation", feature = "mysql"))]
async fn probe_scenario() -> (Scenario, PathBuf) {
    let scenario = Scenario::seeded(false).await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let back = scenario.path("back.json");
    std::fs::write(
        &back,
        serde_json::json!({"@type": "RocksDb", "path": scenario.path("back")}).to_string(),
    )
    .expect("back config");
    (scenario, back)
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use tokio_postgres::{Client, NoTls};

    const ENDPOINT: &str = "STALWART_MIGRATE_TEST_PG";
    const ADMIN_DATABASE: &str = "postgres";

    async fn connect(endpoint: &str, database: &str) -> Client {
        let (host, port) = endpoint.rsplit_once(':').expect("host:port");
        let (client, connection) = tokio_postgres::connect(
            &format!("host={host} port={port} user=postgres password=postgres dbname={database}"),
            NoTls,
        )
        .await
        .expect("connect");
        tokio::spawn(connection);
        client
    }

    async fn fresh_database(endpoint: &str, dir: &std::path::Path, name: &str) -> PathBuf {
        let admin = connect(endpoint, ADMIN_DATABASE).await;
        for statement in [
            format!("DROP DATABASE IF EXISTS {name}"),
            format!("CREATE DATABASE {name}"),
        ] {
            admin
                .batch_execute(&statement)
                .await
                .expect("create database");
        }
        let (host, port) = endpoint.rsplit_once(':').expect("host:port");
        let config = dir.join(format!("{name}.json"));
        std::fs::write(
            &config,
            serde_json::json!({
                "@type": "PostgreSql",
                "host": host,
                "port": port.parse::<u16>().expect("port"),
                "database": name,
                "authUsername": "postgres",
                "authSecret": {"@type": "Value", "secret": "postgres"},
            })
            .to_string(),
        )
        .expect("config");
        config
    }

    async fn read_only_config(
        endpoint: &str,
        dir: &std::path::Path,
        database: &str,
        role: &str,
    ) -> PathBuf {
        let admin = connect(endpoint, ADMIN_DATABASE).await;
        admin
            .batch_execute(&format!(
                "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN CREATE ROLE {role} LOGIN PASSWORD 'reader'; END IF; END $$; GRANT CONNECT ON DATABASE {database} TO {role}"
            ))
            .await
            .expect("read-only role");
        connect(endpoint, database)
            .await
            .batch_execute(&format!(
                "GRANT USAGE ON SCHEMA public TO {role}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}; REVOKE CREATE ON SCHEMA public FROM PUBLIC"
            ))
            .await
            .expect("grant select");
        let (host, port) = endpoint.rsplit_once(':').expect("host:port");
        let config = dir.join(format!("{database}-read-only.json"));
        std::fs::write(
            &config,
            serde_json::json!({
                "@type": "PostgreSql",
                "host": host,
                "port": port.parse::<u16>().expect("port"),
                "database": database,
                "authUsername": role,
                "authSecret": {"@type": "Value", "secret": "reader"},
            })
            .to_string(),
        )
        .expect("config");
        config
    }

    async fn snapshot(endpoint: &str, database: &str) -> Vec<(String, i64)> {
        let client = connect(endpoint, database).await;
        let tables = client
            .query(
                "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1",
                &[],
            )
            .await
            .expect("tables");
        let mut snapshot = Vec::with_capacity(tables.len());
        for table in tables {
            let name: String = table.get(0);
            let rows: i64 = client
                .query_one(&format!("SELECT COUNT(*) FROM \"{name}\""), &[])
                .await
                .expect("count")
                .get(0);
            snapshot.push((name, rows));
        }
        snapshot
    }

    // A large account copied into PostgreSQL with eight write slots verifies in full.
    #[tokio::test(flavor = "multi_thread")]
    async fn large_account_is_copied_into_postgres_with_parallel_slots() {
        let Ok(endpoint) = std::env::var(ENDPOINT) else {
            eprintln!("{ENDPOINT} not set, skipping");
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let name = format!("split_v1_{}", std::process::id());
        let config = fresh_database(&endpoint, dir.path(), &name).await;
        large_account_copy(Some(&config)).await;
    }

    // Through a SELECT-only role, a v0.16 PostgreSQL store is refused as rollback source and as forward target, and a v1 one is rolled back, so no probe writes.
    #[tokio::test(flavor = "multi_thread")]
    async fn postgres_stores_are_probed_without_writes() {
        let Ok(endpoint) = std::env::var(ENDPOINT) else {
            eprintln!("{ENDPOINT} not set, skipping");
            return;
        };
        let (scenario, back) = probe_scenario().await;
        let role = format!("probe_reader_{}", std::process::id());
        let v016_name = format!("probe_v016_{}", std::process::id());
        let v016 = fresh_database(&endpoint, scenario.dir.path(), &v016_name).await;
        source_v016::testkit::create_store(&v016).await;
        let v016 = read_only_config(&endpoint, scenario.dir.path(), &v016_name, &role).await;
        let before = snapshot(&endpoint, &v016_name).await;
        let (code, output) = rollback(&v016, &back, scenario.path("rollback-v016"));
        assert_eq!(code, EXIT_USAGE, "{output}");
        assert!(output.contains("is a v0.16 store"), "{output}");
        assert_eq!(snapshot(&endpoint, &v016_name).await, before);
        std::fs::copy(&v016, scenario.path("target.json")).expect("target config");
        let (code, output) = scenario.cli(&["run"], true);
        assert_eq!(code, EXIT_USAGE, "{output}");
        assert!(output.contains("is a v0.16 store"), "{output}");
        assert_eq!(snapshot(&endpoint, &v016_name).await, before);
        assert!(!scenario.path("back").exists());

        let v1_name = format!("probe_v1_{}", std::process::id());
        let v1 = fresh_database(&endpoint, scenario.dir.path(), &v1_name).await;
        create_v1_store(&v1).await;
        let v1 = read_only_config(&endpoint, scenario.dir.path(), &v1_name, &role).await;
        let before = snapshot(&endpoint, &v1_name).await;
        let (code, output) = rollback(&v1, &back, scenario.path("rollback-v1"));
        assert_eq!(code, EXIT_OK, "{output}");
        assert_eq!(snapshot(&endpoint, &v1_name).await, before);

        let admin = connect(&endpoint, ADMIN_DATABASE).await;
        for name in [v016_name, v1_name] {
            admin
                .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
                .await
                .expect("drop database");
        }
        admin
            .batch_execute(&format!("DROP ROLE {role}"))
            .await
            .expect("drop role");
    }
}

#[cfg(feature = "foundation")]
mod foundation {
    use super::*;

    const CLUSTER_FILE: &str = "STALWART_MIGRATE_TEST_FDB";
    const WHOLE_KEYSPACE: &str = "getrange \"\" \\xff 1000000";

    fn fdbcli(cluster_file: &str, command: &str) -> String {
        let output = Command::new("fdbcli")
            .args(["-C", cluster_file, "--timeout", "30", "--exec", command])
            .output()
            .expect("run fdbcli");
        assert!(output.status.success(), "fdbcli {command}: {output:?}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn clear(cluster_file: &str) {
        fdbcli(cluster_file, "writemode on; clearrange \"\" \\xff");
    }

    // A v0.16 FoundationDB store is refused as rollback source and as forward target without writes; a v1 one is read without writes.
    #[tokio::test(flavor = "multi_thread")]
    async fn foundationdb_stores_are_probed_without_writes() {
        let Ok(cluster_file) = std::env::var(CLUSTER_FILE) else {
            eprintln!("{CLUSTER_FILE} not set, skipping");
            return;
        };
        target_v1::boot_foundationdb_network().expect("fdb network");
        source_v016::use_external_foundationdb_network();
        let (scenario, back) = probe_scenario().await;
        let config = scenario.path("fdb.json");
        std::fs::write(
            &config,
            serde_json::json!({"@type": "FoundationDb", "clusterFile": cluster_file}).to_string(),
        )
        .expect("fdb config");

        clear(&cluster_file);
        source_v016::testkit::create_store(&config).await;
        let before = fdbcli(&cluster_file, WHOLE_KEYSPACE);
        let (code, output) = rollback(&config, &back, scenario.path("rollback-v016"));
        assert_eq!(code, EXIT_USAGE, "{output}");
        assert!(output.contains("is a v0.16 store"), "{output}");
        assert_eq!(fdbcli(&cluster_file, WHOLE_KEYSPACE), before);
        std::fs::copy(&config, scenario.path("target.json")).expect("target config");
        let (code, output) = scenario.cli(&["run"], true);
        assert_eq!(code, EXIT_USAGE, "{output}");
        assert!(output.contains("is a v0.16 store"), "{output}");
        assert_eq!(fdbcli(&cluster_file, WHOLE_KEYSPACE), before);
        assert!(!scenario.path("back").exists());

        clear(&cluster_file);
        create_v1_store(&config).await;
        let before = fdbcli(&cluster_file, WHOLE_KEYSPACE);
        let (code, output) = rollback(&config, &back, scenario.path("rollback-v1"));
        assert_eq!(code, EXIT_OK, "{output}");
        assert_eq!(fdbcli(&cluster_file, WHOLE_KEYSPACE), before);
        clear(&cluster_file);
    }
}

#[cfg(feature = "mysql")]
mod mysql {
    use mysql_async::{Conn, Opts, prelude::Queryable};

    use super::*;

    const ENDPOINT: &str = "STALWART_MIGRATE_TEST_MYSQL";
    const READER_SECRET: &str = "reader";

    async fn connect(endpoint: &str) -> Conn {
        Conn::new(Opts::from_url(&format!("mysql://root:root@{endpoint}")).expect("mysql url"))
            .await
            .expect("connect")
    }

    fn config(dir: &std::path::Path, endpoint: &str, database: &str, user: &str) -> PathBuf {
        let (host, port) = endpoint.rsplit_once(':').expect("host:port");
        let secret = if user == "root" {
            "root"
        } else {
            READER_SECRET
        };
        let config = dir.join(format!("{database}-{user}.json"));
        std::fs::write(
            &config,
            serde_json::json!({
                "@type": "MySql",
                "host": host,
                "port": port.parse::<u16>().expect("port"),
                "database": database,
                "authUsername": user,
                "authSecret": {"@type": "Value", "secret": secret},
            })
            .to_string(),
        )
        .expect("config");
        config
    }

    async fn fresh_database(conn: &mut Conn, database: &str, reader: &str) {
        for statement in [
            format!("DROP DATABASE IF EXISTS {database}"),
            format!("CREATE DATABASE {database}"),
            format!("CREATE USER IF NOT EXISTS '{reader}'@'%' IDENTIFIED BY '{READER_SECRET}'"),
            format!("GRANT SELECT ON {database}.* TO '{reader}'@'%'"),
        ] {
            conn.query_drop(statement).await.expect("setup");
        }
    }

    async fn snapshot(conn: &mut Conn, database: &str) -> Vec<(String, u64)> {
        let tables: Vec<String> = conn
            .query(format!(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = '{database}' ORDER BY 1"
            ))
            .await
            .expect("tables");
        let mut snapshot = Vec::with_capacity(tables.len());
        for table in tables {
            let rows: Option<u64> = conn
                .query_first(format!("SELECT COUNT(*) FROM {database}.`{table}`"))
                .await
                .expect("count");
            snapshot.push((table, rows.unwrap_or(0)));
        }
        snapshot
    }

    // Through a SELECT-only user, a v0.16 MySQL store is refused as rollback source and as forward target, and a v1 one is rolled back, so no probe writes.
    #[tokio::test(flavor = "multi_thread")]
    async fn mysql_stores_are_probed_without_writes() {
        let Ok(endpoint) = std::env::var(ENDPOINT) else {
            eprintln!("{ENDPOINT} not set, skipping");
            return;
        };
        let (scenario, back) = probe_scenario().await;
        let dir = scenario.dir.path();
        let reader = format!("probe_reader_{}", std::process::id());
        let mut conn = connect(&endpoint).await;

        let v016_name = format!("probe_v016_{}", std::process::id());
        fresh_database(&mut conn, &v016_name, &reader).await;
        source_v016::testkit::create_store(&config(dir, &endpoint, &v016_name, "root")).await;
        let v016 = config(dir, &endpoint, &v016_name, &reader);
        let before = snapshot(&mut conn, &v016_name).await;
        let (code, output) = rollback(&v016, &back, scenario.path("rollback-v016"));
        assert_eq!(code, EXIT_USAGE, "{output}");
        assert!(output.contains("is a v0.16 store"), "{output}");
        assert_eq!(snapshot(&mut conn, &v016_name).await, before);
        std::fs::copy(&v016, scenario.path("target.json")).expect("target config");
        let (code, output) = scenario.cli(&["run"], true);
        assert_eq!(code, EXIT_USAGE, "{output}");
        assert!(output.contains("is a v0.16 store"), "{output}");
        assert_eq!(snapshot(&mut conn, &v016_name).await, before);
        assert!(!scenario.path("back").exists());

        let v1_name = format!("probe_v1_{}", std::process::id());
        fresh_database(&mut conn, &v1_name, &reader).await;
        create_v1_store(&config(dir, &endpoint, &v1_name, "root")).await;
        let v1 = config(dir, &endpoint, &v1_name, &reader);
        let before = snapshot(&mut conn, &v1_name).await;
        let (code, output) = rollback(&v1, &back, scenario.path("rollback-v1"));
        assert_eq!(code, EXIT_OK, "{output}");
        assert_eq!(snapshot(&mut conn, &v1_name).await, before);

        for statement in [
            format!("DROP DATABASE {v016_name}"),
            format!("DROP DATABASE {v1_name}"),
            format!("DROP USER '{reader}'@'%'"),
        ] {
            conn.query_drop(statement).await.expect("cleanup");
        }
    }
}

fn dmarc_report(report_id: &str) -> Value {
    serde_json::json!({
        "expiresAt": "2036-11-20T14:53:05Z",
        "from": "noreply-dmarc@reporter.example.com",
        "receivedAt": "2026-10-21T14:53:05Z",
        "report": {
            "dateRangeBegin": "2024-06-01T00:00:00Z",
            "dateRangeEnd": "2024-06-01T23:59:59Z",
            "email": "noreply-dmarc@reporter.example.com",
            "orgName": "reporter.example.com",
            "policyAdkim": "relaxed",
            "policyAspf": "relaxed",
            "policyDisposition": "none",
            "policyDomain": "example.org",
            "policySubdomainDisposition": "none",
            "records": {
                "0": {
                    "count": 3,
                    "envelopeFrom": "example.org",
                    "evaluatedDisposition": "none",
                    "evaluatedDkim": "pass",
                    "evaluatedSpf": "pass",
                    "headerFrom": "example.org",
                    "sourceIp": "192.0.2.10"
                }
            },
            "reportId": report_id
        },
        "subject": "Report Domain: example.org",
        "to": {"postmaster@example.org": true}
    })
}

// A v0.16 external report deleted and delivered again under the same ReportId is migrated by the next run instead of looping on the unique ReportId.
#[tokio::test(flavor = "multi_thread")]
async fn redelivered_report_with_the_same_report_id_converges() {
    const FIRST: u64 = 900;
    const SECOND: u64 = 901;
    let scenario = Scenario::seeded(false).await;
    let src = scenario.path("src");
    seed_registry_object(
        &src,
        "DmarcExternalReport",
        FIRST,
        &dmarc_report("redelivered"),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    remove_v016_registry_object(&src, "DmarcExternalReport", FIRST).await;
    seed_registry_object(
        &src,
        "DmarcExternalReport",
        SECOND,
        &dmarc_report("redelivered"),
    )
    .await;
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run after the redelivery: {output}");
    let store = open(&scenario.path("dst")).await;
    let ids: Vec<model::RegistryId> = V1Source::from_store(store)
        .registry_page("x:DmarcExternalReport", None, 100)
        .await
        .expect("reports")
        .records
        .into_iter()
        .map(|record| record.key.id)
        .collect();
    assert_eq!(ids, [model::RegistryId::Id(SECOND)]);
}

// A received DMARC report whose first record and first DKIM result are dropped verifies clean and lets the final run finish (mail-ie).
#[tokio::test(flavor = "multi_thread")]
async fn dmarc_report_with_dropped_list_elements_verifies() {
    const REPORT: u64 = 910;
    let scenario = Scenario::seeded(false).await;
    let mut report = dmarc_report("dropped-elements");
    report["report"]["records"] = serde_json::json!({
        "0": {
            "count": 1,
            "envelopeFrom": "example.org",
            "evaluatedDisposition": "none",
            "evaluatedDkim": "pass",
            "evaluatedSpf": "pass",
            "headerFrom": "",
            "sourceIp": "192.0.2.11"
        },
        "1": {
            "count": 2,
            "envelopeFrom": "",
            "evaluatedDisposition": "none",
            "evaluatedDkim": "fail",
            "evaluatedSpf": "fail",
            "headerFrom": "example.org",
            "sourceIp": "192.0.2.12",
            "dkimResults": {
                "0": {"domain": "", "selector": "", "result": "none"},
                "1": {"domain": "example.org", "selector": "ed2026", "result": "fail"}
            }
        },
        "2": {
            "count": 3,
            "envelopeFrom": "example.org",
            "evaluatedDisposition": "none",
            "evaluatedDkim": "pass",
            "evaluatedSpf": "pass",
            "headerFrom": "example.org",
            "sourceIp": "192.0.2.13"
        }
    });
    seed_registry_object(
        &scenario.path("src"),
        "DmarcExternalReport",
        REPORT,
        &report,
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_OK, "run: {output}");
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert!(scenario.final_done());
    let store = open(&scenario.path("dst")).await;
    let records = V1Source::from_store(store)
        .registry_page("x:DmarcExternalReport", None, 100)
        .await
        .expect("reports")
        .records;
    let [stored] = records.as_slice() else {
        panic!("one report expected: {records:?}");
    };
    let records = &stored.json["report"]["records"];
    assert_eq!(records["0"]["envelopeFrom"], "");
    assert_eq!(records["0"]["dkimResults"]["0"]["domain"], "example.org");
    assert_eq!(records["1"]["count"], 3);
    assert!(records.get("2").is_none(), "{records}");
}

// Two v0.16 received DMARC reports with the same v1 unique key migrate as one, with a warning instead of an error, and the final run finishes (mail-ie).
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_dmarc_reports_migrate_once() {
    const FIRST: u64 = 920;
    const SECOND: u64 = 921;
    let scenario = Scenario::seeded(false).await;
    for id in [FIRST, SECOND] {
        seed_registry_object(
            &scenario.path("src"),
            "DmarcExternalReport",
            id,
            &dmarc_report("duplicate"),
        )
        .await;
    }
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(
        &["run", "--final", "--yes", "--final-observation", "0"],
        true,
    );
    assert_eq!(code, EXIT_OK, "final: {output}");
    assert!(
        scenario.run_rows("error").is_empty(),
        "{:#?}",
        scenario.run_rows("error")
    );
    let (unexplained, _, rows) = scenario.last_verify();
    assert_eq!(unexplained, 0, "{:#?}", describe(&rows));
    assert!(scenario.final_done());
    let store = open(&scenario.path("dst")).await;
    let ids: Vec<model::RegistryId> = V1Source::from_store(store)
        .registry_page("x:DmarcExternalReport", None, 100)
        .await
        .expect("reports")
        .records
        .into_iter()
        .map(|record| record.key.id)
        .collect();
    assert_eq!(ids, [model::RegistryId::Id(FIRST)]);
}

// The final run renames stale stock spam tags, drops LLM_* tags and adds the missing stock tags once.
#[tokio::test(flavor = "multi_thread")]
async fn final_run_completes_the_stock_spam_tags() {
    let scenario = Scenario::seeded(false).await;
    for (id, tag, score) in [
        (11, "DISPOSABLE_REPLYTO", 0.0),
        (12, "LLM_COMMERCIAL_HIGH", 3.0),
        (13, "AI_MALWARE_HIGH", 9.0),
    ] {
        seed_registry_object(
            &scenario.path("src"),
            "SpamTag",
            id,
            &serde_json::json!({"@type": "Score", "tag": tag, "score": score}),
        )
        .await;
    }
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let final_run = ["run", "--final", "--yes", "--final-observation", "0"];
    let (code, output) = scenario.cli(&final_run, true);
    assert_eq!(code, EXIT_OK, "final run: {output}");
    let tags = || async {
        let store = open(&scenario.path("dst")).await;
        let mut tags: Vec<(String, f64)> = V1Source::from_store(store)
            .registry_page("x:SpamTag", None, 100)
            .await
            .expect("spam tags")
            .records
            .into_iter()
            .map(|record| {
                (
                    record.json["tag"].as_str().expect("tag").to_string(),
                    record.json["score"].as_f64().expect("score"),
                )
            })
            .collect();
        tags.sort_by(|a, b| a.0.cmp(&b.0));
        tags
    };
    let first = tags().await;
    let names: Vec<&str> = first.iter().map(|(tag, _)| tag.as_str()).collect();
    assert_eq!(first.len(), 36, "{names:?}");
    assert!(
        !names.iter().any(|tag| tag.starts_with("LLM_")),
        "{names:?}"
    );
    assert!(!names.contains(&"DISPOSABLE_REPLYTO"), "{names:?}");
    assert!(
        first.contains(&("AI_MALWARE_HIGH".to_string(), 9.0)),
        "{first:?}"
    );
    assert!(
        first.contains(&("DISPOSABLE_REPLY_TO".to_string(), 0.0)),
        "{first:?}"
    );
    assert!(
        first.contains(&("MIME_LIMIT_EXCEEDED".to_string(), 8.0)),
        "{first:?}"
    );
    assert!(
        scenario
            .run_rows("info")
            .iter()
            .any(|row| row.contains("stock spam filter tag MIME_LIMIT_EXCEEDED added")),
        "{:?}",
        scenario.run_rows("info")
    );

    let mut forced = final_run.to_vec();
    forced.push("--force-after-final");
    let (code, output) = scenario.cli(&forced, true);
    assert_eq!(code, EXIT_OK, "forced final run: {output}");
    assert_eq!(tags().await, first);
}

// An ACME provider stored by v0.16 (description computed, not stored) is migrated with the v0.16 label, so the domain that uses it and the accounts in that domain are copied.
#[tokio::test(flavor = "multi_thread")]
async fn stored_acme_provider_gets_its_v016_description() {
    let scenario = Scenario::seeded(false).await;
    const ACME_ID: u64 = 21;
    const ACME_KEY: &str = "v";
    seed_registry_object(
        &scenario.path("src"),
        "AcmeProvider",
        ACME_ID,
        &serde_json::json!({
            "directory": "https://acme.example.org/directory",
            "challengeType": "TlsAlpn01",
            "contact": {"postmaster@example.org": true},
            "accountUri": "https://acme.example.org/acct/42",
            "accountKey": "test-account-key",
        }),
    )
    .await;
    seed_registry_object(
        &scenario.path("src"),
        "Domain",
        DOMAIN_ID,
        &serde_json::json!({
            "name": "example.org",
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": ACME_KEY,
            },
        }),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let final_run = ["run", "--final", "--yes", "--final-observation", "0"];
    let (code, output) = scenario.cli(&final_run, true);
    assert_eq!(
        code,
        EXIT_OK,
        "final run: {output}\nerrors: {:?}",
        scenario.run_rows("error")
    );
    let source = V1Source::from_store(open(&scenario.path("dst")).await);
    let providers = source
        .registry_page("x:AcmeProvider", None, 10)
        .await
        .expect("acme providers")
        .records;
    let descriptions: Vec<&str> = providers
        .iter()
        .filter_map(|record| record.json["description"].as_str())
        .collect();
    assert_eq!(
        descriptions,
        ["https://acme.example.org/directory (42)"],
        "{providers:?}"
    );
    let domains = source
        .registry_page("x:Domain", None, 10)
        .await
        .expect("domains")
        .records;
    assert!(
        domains
            .iter()
            .any(|record| record.json["name"] == "example.org"),
        "{domains:?}"
    );
    assert!(
        scenario.run_rows("error").is_empty(),
        "{:?}",
        scenario.run_rows("error")
    );
}

// A tenant domain whose ACME provider belongs to no tenant is migrated with manual certificates, so v1 accepts it and the accounts in that domain are copied.
#[tokio::test(flavor = "multi_thread")]
async fn tenant_domain_with_a_global_acme_provider_is_migrated() {
    let scenario = Scenario::seeded(false).await;
    const ACME_ID: u64 = 307264283016692224;
    seed_registry_object(
        &scenario.path("src"),
        "Tenant",
        1,
        &serde_json::json!({"name": "example"}),
    )
    .await;
    seed_registry_object(
        &scenario.path("src"),
        "AcmeProvider",
        ACME_ID,
        &serde_json::json!({
            "directory": "https://acme.example.org/directory",
            "challengeType": "TlsAlpn01",
            "contact": {"postmaster@example.org": true},
            "accountUri": "https://acme.example.org/acct/42",
            "accountKey": "test-account-key",
        }),
    )
    .await;
    seed_registry_object(
        &scenario.path("src"),
        "Domain",
        DOMAIN_ID,
        &serde_json::json!({
            "name": "example.org",
            "memberTenantId": "b",
            "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": "iq23htewaaqa",
            },
        }),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let final_run = ["run", "--final", "--yes", "--final-observation", "0"];
    let (code, output) = scenario.cli(&final_run, true);
    assert_eq!(
        code,
        EXIT_OK,
        "final run: {output}\nerrors: {:?}",
        scenario.run_rows("error")
    );
    let source = V1Source::from_store(open(&scenario.path("dst")).await);
    let domains = source
        .registry_page("x:Domain", None, 10)
        .await
        .expect("domains")
        .records;
    assert!(
        domains
            .iter()
            .any(|record| record.json["name"] == "example.org"
                && record.json["certificateManagement"] == serde_json::json!({"@type": "Manual"})),
        "{domains:?}"
    );
    assert!(
        scenario
            .run_rows("warning")
            .iter()
            .any(|row| row.contains("not in the same tenant")),
        "{:?}",
        scenario.run_rows("warning")
    );
}

// An account whose Account object v1 rejected fails with an error that points at the registry, not with a transient "Account not found".
#[tokio::test(flavor = "multi_thread")]
async fn account_missing_in_v1_fails_with_a_registry_hint() {
    let scenario = Scenario::seeded(false).await;
    seed_registry_object(
        &scenario.path("src"),
        "Domain",
        DOMAIN_ID,
        &serde_json::json!({"name": "example\u{0}.org"}),
    )
    .await;
    let (code, output) = scenario.cli(&["prepare", "--non-interactive"], false);
    assert_eq!(code, EXIT_OK, "prepare: {output}");
    let (code, output) = scenario.cli(&["run"], true);
    assert_eq!(code, EXIT_FAILURE, "run: {output}");
    let errors = scenario.run_rows("error");
    assert!(
        errors
            .iter()
            .any(|row| row.contains(&format!("account {ACCOUNT} does not exist in v1"))),
        "{errors:?}"
    );
    assert!(
        !errors.iter().any(|row| row.contains("Account not found")),
        "{errors:?}"
    );
}
