/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod fake;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use fake::{FakeConverter, FakeReader, FakeSource, FakeTarget, email, mailbox};
use migrate::{
    orchestrator::{Orchestrator, RetryPolicy, RunKind, RunOptions, RunSummary, Tuning},
    shutdown::Shutdown,
};
use model::{Collection, Edition};
use state::{RunStatus, SqliteState, StateStore};
use tracing_subscriber::{Layer, filter::LevelFilter, layer::SubscriberExt};

async fn run(source: &Arc<FakeSource>, target: &Arc<FakeTarget>, dir: &Path) -> RunSummary {
    let mut options = RunOptions::new(RunKind::Incremental, Edition::Enterprise);
    options.tuning = Tuning {
        concurrency: 2,
        batch_ops: 4,
        batch_bytes: 1 << 20,
        blob_concurrency: 2,
        read_ahead: 2,
        max_ops_per_sec: None,
        account_split: 2,
    };
    options.retry = RetryPolicy {
        max_attempts: 3,
        budget: Duration::from_secs(10),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    options.final_observation = Duration::ZERO;
    Orchestrator::new(
        source.clone(),
        target.clone(),
        FakeReader::new(target, source),
        Arc::new(SqliteState::open(dir).expect("open state")),
        Arc::new(FakeConverter),
        options,
        Shutdown::default(),
    )
    .run()
    .await
    .expect("run succeeds")
}

fn seed(source: &FakeSource, accounts: u32) {
    for account_id in 1..=accounts {
        source.put(account_id, mailbox(0, "Inbox"));
        for id in 0..6 {
            source.put(account_id, email(id, 0, id + 1, &["$seen"]));
        }
    }
    source.put_registry("Account", 1, serde_json::json!({"name": "user1"}));
    source.put_registry("Account", 2, serde_json::json!({"name": "user2"}));
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    fn events(&self) -> Vec<serde_json::Value> {
        let buf = std::mem::take(&mut *self.0.lock().expect("lock"));
        buf.split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("json log line"))
            .collect()
    }
}

fn logged<'a>(
    events: &'a [serde_json::Value],
    level: &'a str,
    message: &'a str,
) -> impl Iterator<Item = &'a serde_json::Value> + 'a {
    events
        .iter()
        .filter(move |event| event["level"] == level && event["fields"]["message"] == message)
        .map(|event| &event["fields"])
}

// Alone in its own test binary, because tracing caches callsite interest process-wide. The harness contract: INFO "account done" (account_id, checkpoint), DEBUG "collection checkpoint" (account_id, collection, code, checkpoint) and DEBUG "delta" (account_id), in the JSON log format.
#[tokio::test]
async fn log_events_follow_the_harness_contract() {
    let capture = LogCapture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(move || writer.clone())
            .with_filter(LevelFilter::DEBUG),
    );
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempfile::tempdir().expect("tempdir");
    let source = FakeSource::new();
    let target = FakeTarget::new();
    seed(&source, 2);
    assert_eq!(
        run(&source, &target, dir.path()).await.status,
        RunStatus::Ok
    );
    let events = capture.events();
    let accounts = SqliteState::open(dir.path())
        .expect("open state")
        .accounts()
        .await
        .expect("accounts");
    for account in &accounts {
        let checkpoint = account.checkpoint.expect("checkpoint");
        let done: Vec<_> = logged(&events, "INFO", "account done")
            .filter(|fields| fields["account_id"] == account.account_id)
            .collect();
        assert_eq!(done.len(), 1, "{events:#?}");
        assert_eq!(done[0]["checkpoint"], checkpoint, "{done:?}");
        let email = logged(&events, "DEBUG", "collection checkpoint")
            .find(|fields| {
                fields["account_id"] == account.account_id && fields["collection"] == "email"
            })
            .expect("email checkpoint");
        assert_eq!(email["code"], Collection::Email.as_u8());
        assert_eq!(email["checkpoint"], checkpoint);
    }

    source.put(1, email(10, 0, 11, &[]));
    assert_eq!(
        run(&source, &target, dir.path()).await.status,
        RunStatus::Ok
    );
    let events = capture.events();
    assert!(
        logged(&events, "DEBUG", "delta").any(|fields| fields["account_id"] == 1),
        "{events:#?}"
    );
    let done: Vec<_> = logged(&events, "INFO", "account done").collect();
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0]["account_id"], 1);
}
