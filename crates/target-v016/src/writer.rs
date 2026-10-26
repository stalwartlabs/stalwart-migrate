/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccountTenantIds};
use store::{Store, write::BatchBuilder};

use crate::{error::trc_error, target::V016Target};

pub(crate) const BLOB_CONCURRENCY: usize = 16;

pub(crate) struct ImportBatch {
    pub(crate) batch: BatchBuilder,
    records: usize,
}

impl ImportBatch {
    pub(crate) fn new(account_id: u32) -> Self {
        let mut batch = BatchBuilder::new();
        batch.set_import_mode().with_account_id(account_id);
        ImportBatch { batch, records: 0 }
    }

    pub(crate) fn record_done(&mut self) {
        self.records += 1;
        self.batch.commit_point();
    }

    pub(crate) async fn commit(mut self, store: &Store) -> model::Result<()> {
        if self.records == 0 {
            return Ok(());
        }
        let mut points = self.batch.commit_points();
        for point in points.iter() {
            store
                .write(self.batch.build_one(point))
                .await
                .map_err(trc_error)?;
        }
        Ok(())
    }
}

impl V016Target {
    pub(crate) async fn account_context(
        &self,
        server: &Server,
        account_id: u32,
    ) -> model::Result<AccountTenantIds> {
        let account = server.account(account_id).await.map_err(trc_error)?;
        Ok(AccountTenantIds {
            account_id,
            tenant_id: account.id_tenant,
        })
    }
}
