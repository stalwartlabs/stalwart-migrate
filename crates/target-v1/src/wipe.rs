/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
#[cfg(feature = "enterprise")]
use registry::{schema::prelude::ObjectType, types::id::ObjectId};
#[cfg(any(feature = "postgres", feature = "mysql"))]
use std::sync::Arc;

use services::task_manager::tasks::destroy_account::destroy_account_blobs;
use store::{
    SearchStore, Store, Subspace, U32_LEN,
    ahash::AHashSet,
    search::SearchQuery,
    write::{
        AnyKey, SearchIndex,
        key::{CounterKind, KeySerializer},
    },
};
#[cfg(feature = "enterprise")]
use store::{
    ValueKey,
    write::{BatchBuilder, ValueClass},
};
#[cfg(feature = "enterprise")]
use types::id::Id;

use crate::{error::trc_error, target::V1Target};

const SEARCH_INDEXES: [SearchIndex; 4] = [
    SearchIndex::Email,
    SearchIndex::Contacts,
    SearchIndex::Calendar,
    SearchIndex::File,
];

const ACCOUNT_SUBSPACES: [Subspace; 5] = [
    Subspace::Logs,
    Subspace::Indexes,
    Subspace::Property,
    Subspace::Immutable,
    Subspace::IndexProperty,
];

impl V1Target {
    pub(crate) async fn wipe(&self, account_id: u32) -> model::Result<()> {
        let server = self.server()?;
        #[cfg(feature = "enterprise")]
        self.release_tenant_quota(account_id).await?;
        failpoint!("wipe.step", "quota");
        let search = server.search_store();
        let unindex = search_in_data_store(search, &self.store);
        for index in SEARCH_INDEXES {
            if unindex {
                match search.internal_fts() {
                    Some(fts) => fts.unindex_account(index, account_id).await,
                    None => search
                        .unindex(SearchQuery::new(index).with_account_id(account_id))
                        .await
                        .map(|_| ()),
                }
                .map_err(trc_error)?;
            }
            self.store
                .clear_search_index_queue(index, account_id)
                .await
                .map_err(trc_error)?;
            failpoint!("wipe.step", "search");
        }
        destroy_account_blobs(server, account_id)
            .await
            .map_err(trc_error)?;
        failpoint!("wipe.step", "blobs");
        let grantees: AHashSet<u32> = self
            .store
            .acl_owned(account_id)
            .await
            .map_err(trc_error)?
            .into_iter()
            .map(|(grantee_id, _)| grantee_id)
            .collect();
        self.store
            .acl_revoke_owner(account_id, &grantees)
            .await
            .map_err(trc_error)?;
        failpoint!("wipe.step", "acl");
        self.destroy_account_rows(account_id).await
    }

    async fn destroy_account_rows(&self, account_id: u32) -> model::Result<()> {
        let next_account = account_id.saturating_add(1);
        for kind in CounterKind::ACCOUNT_KINDS {
            let key = |id: u32| AnyKey {
                subspace: Subspace::Counter,
                key: KeySerializer::new(U32_LEN + 1)
                    .write(kind.byte())
                    .write(id)
                    .finalize(),
            };
            self.store
                .delete_range(key(account_id), key(next_account))
                .await
                .map_err(trc_error)?;
            failpoint!("wipe.step", "counters");
        }
        for subspace in ACCOUNT_SUBSPACES {
            let key = |id: u32| AnyKey {
                subspace,
                key: KeySerializer::new(U32_LEN).write(id).finalize(),
            };
            self.store
                .delete_range(key(account_id), key(next_account))
                .await
                .map_err(trc_error)?;
            failpoint!("wipe.step", "rows");
        }
        Ok(())
    }

    #[cfg(feature = "enterprise")]
    async fn release_tenant_quota(&self, account_id: u32) -> model::Result<()> {
        let Some(tenant_id) = self
            .registry
            .get(ObjectId::new(
                ObjectType::Account,
                Id::new(u64::from(account_id)),
            ))
            .await
            .map_err(trc_error)?
            .and_then(|object| object.inner.member_tenant_id())
        else {
            return Ok(());
        };
        let used = self
            .store
            .get_counter(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Quota,
            })
            .await
            .map_err(trc_error)?;
        if used == 0 {
            return Ok(());
        }
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .add(ValueClass::Quota, -used)
            .add(ValueClass::TenantQuota(tenant_id.document_id()), -used);
        self.store
            .write_batch(&mut batch)
            .await
            .map(|_| ())
            .map_err(trc_error)
    }
}

fn search_in_data_store(search: &SearchStore, data: &Store) -> bool {
    match (search, data) {
        (SearchStore::Store(search), data) => search.is_same(data),
        #[cfg(feature = "postgres")]
        (SearchStore::PostgreSQL(search), Store::PostgreSQL(data)) => Arc::ptr_eq(search, data),
        #[cfg(feature = "mysql")]
        (SearchStore::MySQL(search), Store::MySQL(data)) => Arc::ptr_eq(search, data),
        #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
        (SearchStore::SQLReadReplica(search), Store::SQLReadReplica(data)) => {
            Arc::ptr_eq(search, data)
        }
        _ => false,
    }
}
