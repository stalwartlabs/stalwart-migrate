/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::ChangedBy};
use store::{Store, write::BatchBuilder};

use crate::{error::trc_error, target::V1Target};

pub(crate) const IMPORT_CHANGE_ID: u64 = 1;
const DEFAULT_COMMIT_BYTES: u64 = 4_000_000;
pub(crate) const BLOB_CONCURRENCY: usize = 16;

pub(crate) struct ImportBatch {
    pub(crate) batch: BatchBuilder,
    bytes: u64,
    limit: u64,
    records: usize,
}

impl ImportBatch {
    pub(crate) fn new(account_id: u32, limit: Option<u64>) -> Self {
        let mut batch = BatchBuilder::new();
        batch
            .set_import_mode(IMPORT_CHANGE_ID)
            .with_account_id(account_id);
        ImportBatch {
            batch,
            bytes: 0,
            limit: limit.unwrap_or(DEFAULT_COMMIT_BYTES).max(1),
            records: 0,
        }
    }

    pub(crate) fn global(limit: Option<u64>) -> Self {
        ImportBatch {
            batch: BatchBuilder::new(),
            bytes: 0,
            limit: limit.unwrap_or(DEFAULT_COMMIT_BYTES).max(1),
            records: 0,
        }
    }

    pub(crate) fn record_done(&mut self, weight: u64) {
        self.records += 1;
        self.bytes = self.bytes.saturating_add(weight);
        if self.bytes >= self.limit {
            self.batch.add_commit_point();
            self.bytes = 0;
        } else {
            self.batch.commit_point();
        }
    }

    pub(crate) async fn commit(mut self, store: &Store) -> model::Result<()> {
        if self.records == 0 {
            return Ok(());
        }
        store
            .write_batch(&mut self.batch)
            .await
            .map(|_| ())
            .map_err(trc_error)
    }
}

pub(crate) struct AccountContext {
    pub(crate) changed_by: ChangedBy,
    #[cfg(feature = "enterprise")]
    pub(crate) tenant_id: Option<u32>,
}

impl V1Target {
    pub(crate) fn import_batch(&self, account_id: u32) -> ImportBatch {
        ImportBatch::new(account_id, self.batch_limit())
    }

    pub(crate) fn global_batch(&self) -> ImportBatch {
        ImportBatch::global(self.batch_limit())
    }

    pub(crate) async fn account_context(
        &self,
        server: &Server,
        account_id: u32,
    ) -> model::Result<AccountContext> {
        let account = server.account(account_id).await.map_err(trc_error)?;
        Ok(AccountContext {
            changed_by: account.changed_by(),
            #[cfg(feature = "enterprise")]
            tenant_id: account.tenant_id(),
        })
    }
}
