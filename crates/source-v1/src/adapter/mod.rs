/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod blob;
mod changes;
mod dead;
mod error;
mod global;
mod keys;
mod principal;
mod quota;
mod records;
mod registry;

use std::path::Path;

use ::registry::schema::structs::DataStore;
use bytes::Bytes;
use model::{
    AccountPointers, AccountRef, BlobHash, ChangeBounds, ChangeLogRecord, Changes, Collection,
    Counters, GlobalCategory, GlobalPage, InternalReportRecord, LogCollection, LogRange,
    QuotaUsage, RecordPage, RegistryCounter, RegistryEntries, RegistryKey, RegistryRecord,
    ShareNotificationRecord, Source,
};
use store::{BlobStore, Store};
use tokio::sync::OnceCell;

pub use error::{OpenError, trc_error};
pub use global::{is_derived_task_id, is_singleton_task, is_singleton_task_id, singleton_task_id};
pub use registry::{
    expired_at as registry_object_expired_at, expires_on_start as registry_object_expires_on_start,
    is_certificate as registry_object_is_certificate, is_stored as registry_object_is_stored,
    refreshed_on_start as registry_object_refreshed_on_start,
};

pub type PathRewrite = Box<dyn Fn(&str) -> String + Send + Sync>;

const ROCKSDB_MARKER: &str = "CURRENT";

pub struct SourceConfig {
    pub data_store: DataStore,
    pub path_rewrite: Option<PathRewrite>,
}

impl SourceConfig {
    pub fn new(data_store: DataStore) -> Self {
        SourceConfig {
            data_store,
            path_rewrite: None,
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|err| OpenError(format!("cannot read {}: {err}", path.display())))?;
        let data_store = serde_json::from_str::<DataStore>(&contents)
            .map_err(|err| OpenError(format!("cannot parse {}: {err}", path.display())))?;
        Ok(SourceConfig::new(data_store))
    }
}

pub struct V1Source {
    data: Store,
    blob: OnceCell<BlobStore>,
    #[cfg(feature = "enterprise")]
    telemetry: OnceCell<global::TelemetryStores>,
    rewrite: Option<PathRewrite>,
}

impl V1Source {
    pub async fn open(config: SourceConfig) -> Result<Self, OpenError> {
        let data_store =
            rewrite_data_store(config.data_store.clone(), config.path_rewrite.as_ref());
        require_existing(&data_store)?;
        let data = Store::build_read_only(data_store)
            .await
            .map_err(OpenError)?;
        Ok(Self::from_store_with_rewrite(data, config.path_rewrite))
    }

    pub async fn configured_file_system_blob_paths(
        config: &SourceConfig,
    ) -> Result<Vec<String>, OpenError> {
        let data_store =
            rewrite_data_store(config.data_store.clone(), config.path_rewrite.as_ref());
        require_existing(&data_store)?;
        let data = Store::build_read_only(data_store)
            .await
            .map_err(OpenError)?;
        let config = blob::blob_store_config(&data)
            .await
            .map_err(|err| OpenError(format!("cannot read the blob store settings: {err}")))?;
        Ok(config
            .as_ref()
            .map(blob::file_system_paths)
            .unwrap_or_default())
    }

    pub fn from_store(data: Store) -> Self {
        Self::from_store_with_rewrite(data, None)
    }

    pub fn from_store_with_rewrite(data: Store, rewrite: Option<PathRewrite>) -> Self {
        V1Source {
            data,
            blob: OnceCell::new(),
            #[cfg(feature = "enterprise")]
            telemetry: OnceCell::new(),
            rewrite,
        }
    }

    pub fn data(&self) -> &Store {
        &self.data
    }

    async fn blob_store(&self) -> model::Result<&BlobStore> {
        self.blob
            .get_or_try_init(|| async {
                let config = blob::blob_store_config(&self.data)
                    .await
                    .map_err(trc_error)?
                    .map(|config| blob::rewrite_blob_store(config, self.rewrite.as_deref()));
                blob::open_blob_store(config, &self.data)
                    .await
                    .map_err(|err| model::Error::fatal(err.0))
            })
            .await
    }
}

#[cfg(feature = "enterprise")]
impl V1Source {
    async fn telemetry_stores(&self) -> model::Result<&global::TelemetryStores> {
        self.telemetry
            .get_or_try_init(|| global::TelemetryStores::open(&self.data, self.rewrite.as_ref()))
            .await
    }
}

fn rewrite_data_store(data_store: DataStore, rewrite: Option<&PathRewrite>) -> DataStore {
    let Some(rewrite) = rewrite else {
        return data_store;
    };
    match data_store {
        DataStore::RocksDb(mut store) => {
            store.path = rewrite(&store.path);
            DataStore::RocksDb(store)
        }
        DataStore::Sqlite(mut store) => {
            store.path = rewrite(&store.path);
            DataStore::Sqlite(store)
        }
        DataStore::FoundationDb(mut store) => {
            store.cluster_file = store.cluster_file.map(|file| rewrite(&file));
            DataStore::FoundationDb(store)
        }
        other => other,
    }
}

fn require_existing(data_store: &DataStore) -> Result<(), OpenError> {
    let (path, marker) = match data_store {
        DataStore::RocksDb(store) => (Path::new(&store.path), Some(ROCKSDB_MARKER)),
        DataStore::Sqlite(store) => (Path::new(&store.path), None),
        _ => return Ok(()),
    };
    let exists = match marker {
        Some(marker) => path.join(marker).is_file(),
        None => path.is_file(),
    };
    if exists {
        Ok(())
    } else {
        Err(OpenError(format!(
            "the v1 store {} does not exist",
            path.display()
        )))
    }
}

impl Source for V1Source {
    async fn catch_up(&self) -> model::Result<()> {
        self.data.invalidate_read_snapshot();
        Ok(())
    }

    async fn registry_types(&self) -> model::Result<Vec<Box<str>>> {
        registry::types(&self.data).await
    }

    async fn registry_page(
        &self,
        object: &str,
        after: Option<u64>,
        limit: usize,
    ) -> model::Result<RegistryEntries> {
        registry::page(&self.data, object, after, limit).await
    }

    async fn registry_id_counters(&self) -> model::Result<Vec<RegistryCounter>> {
        registry::id_counters(&self.data).await
    }

    fn canonical_registry(&self, record: RegistryRecord) -> model::Result<RegistryRecord> {
        registry::canonical(record)
    }

    fn registry_blob(&self, record: &RegistryRecord) -> Option<BlobHash> {
        registry::blob(record)
    }

    async fn unlisted_registry(
        &self,
        records: &[RegistryRecord],
    ) -> model::Result<Vec<RegistryKey>> {
        registry::unlisted(&self.data, records).await
    }

    async fn accounts(&self) -> model::Result<Vec<AccountRef>> {
        let mut accounts = principal::accounts(&self.data).await?;
        let registered = registry::account_ids(&self.data).await?;
        accounts.retain(|account| registered.contains(account.account_id));
        Ok(accounts)
    }

    async fn stored_accounts(&self) -> model::Result<Vec<AccountRef>> {
        principal::accounts(&self.data).await
    }

    async fn change_bounds(&self, account: AccountRef) -> model::Result<ChangeBounds> {
        principal::change_bounds(&self.data, account.account_id).await
    }

    async fn changes(
        &self,
        account_id: u32,
        collection: Collection,
        since: u64,
    ) -> model::Result<Changes> {
        changes::changes(&self.data, account_id, collection, since).await
    }

    async fn changelog(
        &self,
        account_id: u32,
        collection: LogCollection,
        range: LogRange,
        limit: usize,
    ) -> model::Result<Vec<ChangeLogRecord>> {
        changes::changelog(&self.data, account_id, collection, range, limit).await
    }

    async fn last_change_id(
        &self,
        account_id: u32,
        collection: LogCollection,
        up_to: u64,
    ) -> model::Result<Option<u64>> {
        changes::last_change_id(&self.data, account_id, collection, up_to).await
    }

    async fn scan(
        &self,
        account_id: u32,
        collection: Collection,
        after: Option<u32>,
        limit: usize,
    ) -> model::Result<RecordPage> {
        records::scan(&self.data, account_id, collection, after, limit).await
    }

    async fn read(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> model::Result<RecordPage> {
        records::read(&self.data, account_id, collection, ids).await
    }

    async fn share_notifications(
        &self,
        account_id: u32,
        after: Option<u64>,
        limit: usize,
    ) -> model::Result<Vec<ShareNotificationRecord>> {
        changes::share_notifications(&self.data, account_id, after, limit).await
    }

    async fn read_blob(&self, hash: &BlobHash) -> model::Result<Option<Bytes>> {
        blob::read(self.blob_store().await?, hash).await
    }

    async fn blobs_exist(&self, hashes: &[BlobHash]) -> model::Result<Vec<bool>> {
        blob::exist(self.blob_store().await?, hashes).await
    }

    async fn pointers(&self, account_id: u32) -> model::Result<AccountPointers> {
        principal::pointers(&self.data, account_id).await
    }

    async fn counters(&self, account_id: u32) -> model::Result<Counters> {
        principal::counters(&self.data, account_id).await
    }

    async fn stored_report(
        &self,
        record: InternalReportRecord,
    ) -> model::Result<InternalReportRecord> {
        global::stored_report(record).await
    }

    async fn quota_usage(&self, account_id: u32) -> model::Result<Option<QuotaUsage>> {
        quota::usage(&self.data, account_id).await.map(Some)
    }

    async fn global_page(
        &self,
        category: GlobalCategory,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> model::Result<GlobalPage> {
        global::page(self, category, cursor, limit).await
    }
}

#[cfg(all(test, feature = "rocks"))]
mod global_tests;
#[cfg(all(test, feature = "rocks"))]
mod tests;
