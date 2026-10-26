/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, sync::Arc, time::Duration};

use model::{Issue, Source, Subject, Target};
use state::{AccountPhase, ReportRow, RunId, RunStart, StateStore};
use tokio::sync::Semaphore;

use super::{
    RegistryConverter, RunOptions, WRITE_FLOOR_BYTES_PER_SEC,
    blobs::BlobPermits,
    error::RunError,
    rate::RateLimiter,
    retry::{RetryPolicy, retry},
    stats::{RunStats, add},
};
use crate::shutdown::Shutdown;

pub(crate) struct Context<S, T, St, C> {
    pub(crate) source: Arc<S>,
    pub(crate) target: Arc<T>,
    pub(crate) state: Arc<St>,
    pub(crate) converter: Arc<C>,
    pub(crate) options: RunOptions,
    pub(crate) shutdown: Shutdown,
    pub(crate) stats: RunStats,
    pub(crate) run_id: RunId,
    pub(crate) interrupted: Vec<RunId>,
    pub(crate) blob_permits: BlobPermits,
    pub(crate) write_slots: Arc<Semaphore>,
    pub(crate) rate: Arc<RateLimiter>,
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(crate) fn new(
        source: Arc<S>,
        target: Arc<T>,
        state: Arc<St>,
        converter: Arc<C>,
        options: RunOptions,
        shutdown: Shutdown,
        start: RunStart,
    ) -> Self {
        Context {
            blob_permits: BlobPermits::new(options.tuning.blob_concurrency),
            write_slots: Arc::new(Semaphore::new(options.tuning.concurrency.max(1))),
            rate: Arc::new(RateLimiter::new(options.tuning.max_ops_per_sec)),
            source,
            target,
            state,
            converter,
            options,
            shutdown,
            stats: RunStats::default(),
            run_id: start.run_id,
            interrupted: start.interrupted,
        }
    }

    pub(crate) fn check_shutdown(&self) -> Result<(), RunError> {
        if self.shutdown.is_requested() {
            Err(RunError::Interrupted)
        } else {
            Ok(())
        }
    }

    pub(crate) fn batch_bytes(&self) -> u64 {
        let configured = self.options.tuning.batch_bytes.max(1);
        self.target
            .max_batch_bytes()
            .map_or(configured, |limit| configured.min(limit.max(1)))
    }

    pub(crate) const fn policy(&self) -> RetryPolicy {
        self.options.retry
    }

    pub(crate) async fn retry<R, F, Fut>(&self, op: F) -> Result<R, RunError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = model::Result<R>>,
    {
        retry(self.options.retry, op).await.map_err(RunError::from)
    }

    pub(crate) async fn bounded<R>(
        &self,
        bytes: u64,
        op: impl Future<Output = model::Result<R>>,
    ) -> model::Result<R> {
        let limit = write_limit(self.options.write_timeout, bytes);
        tokio::time::timeout(limit, op).await.unwrap_or_else(|_| {
            Err(model::Error::transient(format!(
                "a target operation did not finish within {:.3} seconds: the target store is unresponsive or its connection pool is exhausted",
                limit.as_secs_f64()
            )))
        })
    }

    pub(crate) async fn report(
        &self,
        account_id: Option<u32>,
        issues: Vec<Issue>,
    ) -> Result<(), RunError> {
        if issues.is_empty() {
            return Ok(());
        }
        let rows = issues
            .into_iter()
            .map(|issue| issue_row(self.run_id, account_id, issue))
            .collect();
        let added = self.state.add_reports(rows).await?;
        add(&self.stats.issues, added.rows);
        add(&self.stats.errors, added.errors);
        Ok(())
    }

    pub(crate) async fn failed_accounts(&self) -> Result<u64, RunError> {
        Ok(self
            .state
            .phase_counts()
            .await?
            .into_iter()
            .find(|count| count.phase == AccountPhase::Error)
            .map_or(0, |count| count.count))
    }
}

fn write_limit(minimum: Duration, bytes: u64) -> Duration {
    minimum.max(Duration::from_secs(bytes / WRITE_FLOOR_BYTES_PER_SEC))
}

pub(crate) fn issue_row(run_id: RunId, account_id: Option<u32>, issue: Issue) -> ReportRow {
    let Issue {
        severity,
        kind,
        subject,
        message,
        explains,
        ..
    } = issue;
    let (object, object_id, message) = match subject {
        Subject::None => (None, None, message),
        Subject::Document {
            collection,
            document_id,
        } => (
            Some(collection.as_str().into()),
            Some(u64::from(document_id)),
            message,
        ),
        Subject::Registry(key) => (Some(key.object), key.id.id(), message),
        Subject::Blob(hash) => (
            Some("blob".into()),
            None,
            format!("{hash}: {message}").into_boxed_str(),
        ),
    };
    ReportRow {
        id: None,
        run_id,
        severity,
        category: kind.as_str().into(),
        account_id,
        object,
        object_id,
        message,
        explains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_limit_grows_with_the_batch_size() {
        let minimum = Duration::from_secs(900);
        assert_eq!(write_limit(minimum, 0), minimum);
        assert_eq!(write_limit(minimum, 5 * 1024 * 1024), minimum);
        assert_eq!(
            write_limit(minimum, 2_000 * WRITE_FLOOR_BYTES_PER_SEC),
            Duration::from_secs(2_000)
        );
        assert_eq!(
            write_limit(Duration::from_millis(100), 0),
            Duration::from_millis(100)
        );
    }
}
