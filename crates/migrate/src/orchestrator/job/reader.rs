/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use model::{Collection, RecordPage, Source};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    orchestrator::{
        error::RunError,
        rate::RateLimiter,
        retry::{RetryPolicy, retry},
    },
    shutdown::Shutdown,
};

pub(super) struct AbortOnDrop(pub(super) JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) struct Reader<S> {
    pub(super) source: Arc<S>,
    pub(super) rate: Arc<RateLimiter>,
    pub(super) policy: RetryPolicy,
    pub(super) shutdown: Shutdown,
    pub(super) account_id: u32,
    pub(super) collection: Collection,
    pub(super) limit: usize,
}

impl<S: Source> Reader<S> {
    pub(super) fn spawn(
        self,
        after: Option<u32>,
        sender: mpsc::Sender<Result<RecordPage, RunError>>,
    ) -> AbortOnDrop {
        AbortOnDrop(tokio::spawn(self.run(after, sender)))
    }

    async fn run(self, mut after: Option<u32>, sender: mpsc::Sender<Result<RecordPage, RunError>>) {
        let collection = self.collection;
        loop {
            if self.shutdown.is_requested() {
                let _ = sender.send(Err(RunError::Interrupted)).await;
                return;
            }
            self.rate.acquire(self.limit).await;
            let result = retry(self.policy, || {
                self.source
                    .scan(self.account_id, collection, after, self.limit)
            })
            .await;
            let message = match result {
                Ok(page) => match advance(&page, collection, after) {
                    Ok(None) => return,
                    Ok(Some(last)) => {
                        after = Some(last);
                        Ok(page)
                    }
                    Err(err) => Err(err),
                },
                Err(err) => Err(RunError::Data(err)),
            };
            let stop = message.is_err();
            if sender.send(message).await.is_err() || stop {
                return;
            }
        }
    }
}

pub(crate) fn advance(
    page: &RecordPage,
    collection: Collection,
    after: Option<u32>,
) -> Result<Option<u32>, RunError> {
    let Some(last) = page.last_scanned else {
        return Ok(None);
    };
    let batch = &page.batch;
    let in_range = |id: u32| after.is_none_or(|after| id > after) && id <= last;
    if batch.collection() != collection {
        return Err(RunError::Data(model::Error::account(format!(
            "source returned {} records when {collection} was requested",
            batch.collection()
        ))));
    }
    let valid = after.is_none_or(|after| last > after)
        && batch.first_id().is_none_or(in_range)
        && batch.last_id().is_none_or(in_range);
    if valid {
        Ok(Some(last))
    } else {
        Err(RunError::Data(model::Error::account(format!(
            "source scan of {collection} did not advance past {after:?}"
        ))))
    }
}
