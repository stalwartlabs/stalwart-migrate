/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod blob;
mod changes;
mod error;
mod global;
#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
mod idle;
mod keys;
mod principal;
mod records;
mod registry;

use std::{
    future::Future,
    path::Path,
    sync::{PoisonError, RwLock},
    time::{Duration, Instant},
};

use ::registry::schema::structs::{self, DataStore};
use bytes::Bytes;
use model::{
    AccountPointers, AccountRef, BlobHash, ChangeLogRecord, Changes, Collection, Counters,
    GlobalCategory, GlobalPage, LogCollection, LogRange, RecordPage, RegistryCounter,
    RegistryEntries, RegistryRecord, ShareNotificationRecord, Source,
};
use store::{BlobStore, Store};
use tokio::{
    runtime::Handle,
    sync::{Mutex as AsyncMutex, OnceCell},
};

use crate::open::{OpenError, SCHEMA_VERSION, SourceScope, StoreSchema, open_data_store};
pub use error::trc_error;
use global::{TelemetryConfig, TelemetryStores};
use idle::IdleSqlite;

pub type PathRewrite = Box<dyn Fn(&str) -> String + Send + Sync>;

pub const DEFAULT_REFRESH: Duration = Duration::from_secs(30);

pub struct SourceConfig {
    pub data_store: DataStore,
    pub path_rewrite: Option<PathRewrite>,
    pub refresh_interval: Duration,
}

impl SourceConfig {
    pub fn new(data_store: DataStore) -> Self {
        SourceConfig {
            data_store,
            path_rewrite: None,
            refresh_interval: DEFAULT_REFRESH,
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

    fn rewrite(&self, path: &str) -> String {
        match &self.path_rewrite {
            Some(rewrite) => rewrite(path),
            None => path.to_string(),
        }
    }
}

struct Stores {
    data: Store,
    blob: BlobStore,
}

pub struct V016Source {
    stores: RwLock<Stores>,
    origin: Origin,
    blob_store: Option<structs::BlobStore>,
    refreshed: AsyncMutex<Instant>,
    refresh_interval: Duration,
    telemetry_config: TelemetryConfig,
    telemetry: OnceCell<TelemetryStores>,
}

enum Origin {
    Snapshot(Box<DataStore>),
    Live,
    Idle(IdleSqlite),
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refresh {
    Throttled,
    OlderThan(Duration),
}

const BLOB_READ_ATTEMPTS: u32 = 4;
const BLOB_RETRY_DELAY: Duration = Duration::from_millis(50);
const BLOB_REFRESH_AGE: Duration = Duration::from_secs(1);

impl V016Source {
    pub async fn open(config: SourceConfig) -> Result<Self, OpenError> {
        let data_store = rewrite_data_store(config.data_store.clone(), &config);
        let (data, idle) = match &data_store {
            #[cfg(feature = "sqlite")]
            DataStore::Sqlite(store) => idle::open_sqlite(store.clone())?,
            _ => (
                open_data_store(data_store.clone(), SourceScope::Full).await?,
                None,
            ),
        };
        match StoreSchema::read(&data).await? {
            StoreSchema::V016(SCHEMA_VERSION) | StoreSchema::Missing => {}
            StoreSchema::V016(version) => {
                return Err(OpenError(format!(
                    "the source holds v0.16 schema version {version}, this build reads {SCHEMA_VERSION}"
                )));
            }
            StoreSchema::V1(version) => {
                return Err(OpenError(format!(
                    "the source is a v1 store (schema version {version}), not a v0.16 store"
                )));
            }
        }
        let origin = match (data_store, idle) {
            (data_store @ DataStore::RocksDb(_), _) => Origin::Snapshot(Box::new(data_store)),
            (_, Some(idle)) => Origin::Idle(idle),
            _ => Origin::Live,
        };
        let blob_store = blob::blob_store_config(&data)
            .await
            .map_err(|err| OpenError(format!("cannot read the blob store settings: {err}")))?
            .map(|config_value| blob::rewrite_blob_store(config_value, &config));
        let blob = blob::open_blob_store(blob_store.clone(), &data).await?;
        let telemetry_config =
            TelemetryConfig::read(&data, |store| rewrite_data_store(store, &config))
                .await
                .map_err(|err| {
                    OpenError(format!("cannot read the telemetry store settings: {err}"))
                })?;
        Ok(V016Source {
            stores: RwLock::new(Stores { data, blob }),
            origin,
            blob_store,
            refreshed: AsyncMutex::new(Instant::now()),
            refresh_interval: config.refresh_interval,
            telemetry_config,
            telemetry: OnceCell::new(),
        })
    }

    pub async fn probe_schema(config: &SourceConfig) -> Result<StoreSchema, OpenError> {
        StoreSchema::probe(rewrite_data_store(config.data_store.clone(), config)).await
    }

    pub async fn from_store(data: Store) -> Result<Self, OpenError> {
        let blob_store = blob::blob_store_config(&data)
            .await
            .map_err(|err| OpenError(format!("cannot read the blob store settings: {err}")))?;
        let blob = blob::open_blob_store(blob_store.clone(), &data).await?;
        let telemetry_config = TelemetryConfig::read(&data, |store| store)
            .await
            .map_err(|err| OpenError(format!("cannot read the telemetry store settings: {err}")))?;
        Ok(V016Source {
            stores: RwLock::new(Stores { data, blob }),
            origin: Origin::Shared,
            blob_store,
            refreshed: AsyncMutex::new(Instant::now()),
            refresh_interval: Duration::ZERO,
            telemetry_config,
            telemetry: OnceCell::new(),
        })
    }

    pub fn data(&self) -> Store {
        self.stores
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .data
            .clone()
    }

    fn blob(&self) -> BlobStore {
        self.stores
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .blob
            .clone()
    }

    async fn refresh(&self, mode: Refresh) -> model::Result<()> {
        let data_store = match &self.origin {
            Origin::Snapshot(data_store) => data_store,
            Origin::Live => {
                self.data().invalidate_read_snapshot();
                return Ok(());
            }
            Origin::Idle(idle) => return idle.check(),
            Origin::Shared => {
                let data = self.data();
                let config = blob::blob_store_config(&data).await.map_err(trc_error)?;
                let blob = blob::open_blob_store(config, &data)
                    .await
                    .map_err(|err| model::Error::fatal(err.to_string()))?;
                self.stores
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .blob = blob;
                return Ok(());
            }
        };
        let mut refreshed = self.refreshed.lock().await;
        let minimum_age = match mode {
            Refresh::Throttled => self.refresh_interval,
            Refresh::OlderThan(age) => age,
        };
        if refreshed.elapsed() < minimum_age {
            return Ok(());
        }
        let data_store = (**data_store).clone();
        let blob_store = self.blob_store.clone();
        let handle = Handle::current();
        let stores = tokio::task::spawn_blocking(move || {
            handle.block_on(async move {
                let data = open_data_store(data_store, SourceScope::Full).await?;
                let blob = blob::open_blob_store(blob_store, &data).await?;
                Ok::<_, OpenError>(Stores { data, blob })
            })
        })
        .await
        .map_err(|err| model::Error::transient(err.to_string()))?
        .map_err(|err| model::Error::transient(err.to_string()))?;
        *self.stores.write().unwrap_or_else(PoisonError::into_inner) = stores;
        *refreshed = Instant::now();
        Ok(())
    }

    pub fn file_system_blob_paths(&self) -> impl Iterator<Item = &str> {
        blob::file_system_paths(self.blob_store.as_ref())
    }

    pub async fn configured_file_system_blob_paths(
        config: &SourceConfig,
    ) -> Result<Vec<String>, OpenError> {
        let data = open_data_store(
            rewrite_data_store(config.data_store.clone(), config),
            SourceScope::Full,
        )
        .await?;
        let blob_store = blob::blob_store_config(&data)
            .await
            .map_err(|err| OpenError(format!("cannot read the blob store settings: {err}")))?;
        Ok(blob::file_system_paths(blob_store.as_ref())
            .map(str::to_owned)
            .collect())
    }

    pub fn blobs_in_data_store(&self) -> bool {
        matches!(self.blob_store, None | Some(structs::BlobStore::Default))
    }

    async fn read_blob_checked(&self, hash: &BlobHash) -> model::Result<Option<Bytes>> {
        let mut last_error = None;
        for attempt in 1..=BLOB_READ_ATTEMPTS {
            match blob::read(&self.blob(), hash).await {
                Ok(Some(data)) => return Ok(Some(data)),
                Ok(None) => last_error = None,
                Err(err) => last_error = Some(err),
            }
            if attempt == BLOB_READ_ATTEMPTS {
                break;
            }
            if matches!(self.origin, Origin::Snapshot(_)) && self.blobs_in_data_store() {
                self.refresh(Refresh::OlderThan(BLOB_REFRESH_AGE)).await?;
            }
            tokio::time::sleep(BLOB_RETRY_DELAY).await;
        }
        match last_error {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }
}

fn rewrite_data_store(data_store: DataStore, config: &SourceConfig) -> DataStore {
    match data_store {
        DataStore::RocksDb(mut store) => {
            store.path = config.rewrite(&store.path);
            DataStore::RocksDb(store)
        }
        DataStore::Sqlite(mut store) => {
            store.path = config.rewrite(&store.path);
            DataStore::Sqlite(store)
        }
        DataStore::FoundationDb(mut store) => {
            store.cluster_file = store.cluster_file.map(|file| config.rewrite(&file));
            DataStore::FoundationDb(store)
        }
        other => other,
    }
}

impl Source for V016Source {
    fn catch_up(&self) -> impl Future<Output = model::Result<()>> + Send {
        self.refresh(Refresh::Throttled)
    }

    fn check_unchanged(&self) -> model::Result<()> {
        match &self.origin {
            Origin::Idle(idle) => idle.check(),
            _ => Ok(()),
        }
    }

    async fn registry_types(&self) -> model::Result<Vec<Box<str>>> {
        registry::types(&self.data()).await
    }

    async fn registry_page(
        &self,
        object: &str,
        after: Option<u64>,
        limit: usize,
    ) -> model::Result<RegistryEntries> {
        registry::page(&self.data(), object, after, limit).await
    }

    async fn registry_id_counters(&self) -> model::Result<Vec<RegistryCounter>> {
        registry::id_counters(&self.data()).await
    }

    fn canonical_registry(&self, record: RegistryRecord) -> model::Result<RegistryRecord> {
        registry::canonical(record)
    }

    async fn accounts(&self) -> model::Result<Vec<AccountRef>> {
        let data = self.data();
        let mut accounts = principal::accounts(&data).await?;
        let registered = registry::account_ids(&data).await?;
        accounts.retain(|account| registered.contains(account.account_id));
        Ok(accounts)
    }

    async fn changes(
        &self,
        account_id: u32,
        collection: Collection,
        since: u64,
    ) -> model::Result<Changes> {
        changes::changes(&self.data(), account_id, collection, since).await
    }

    async fn changelog(
        &self,
        account_id: u32,
        collection: LogCollection,
        range: LogRange,
        limit: usize,
    ) -> model::Result<Vec<ChangeLogRecord>> {
        changes::changelog(&self.data(), account_id, collection, range, limit).await
    }

    async fn last_change_id(
        &self,
        account_id: u32,
        collection: LogCollection,
        up_to: u64,
    ) -> model::Result<Option<u64>> {
        changes::last_change_id(&self.data(), account_id, collection, up_to).await
    }

    async fn scan(
        &self,
        account_id: u32,
        collection: Collection,
        after: Option<u32>,
        limit: usize,
    ) -> model::Result<RecordPage> {
        records::scan(&self.data(), account_id, collection, after, limit).await
    }

    async fn read(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> model::Result<RecordPage> {
        records::read(&self.data(), account_id, collection, ids).await
    }

    async fn share_notifications(
        &self,
        account_id: u32,
        after: Option<u64>,
        limit: usize,
    ) -> model::Result<Vec<ShareNotificationRecord>> {
        changes::share_notifications(&self.data(), account_id, after, limit).await
    }

    async fn read_blob(&self, hash: &BlobHash) -> model::Result<Option<Bytes>> {
        self.read_blob_checked(hash).await
    }

    async fn pointers(&self, account_id: u32) -> model::Result<AccountPointers> {
        principal::pointers(&self.data(), account_id).await
    }

    async fn counters(&self, account_id: u32) -> model::Result<Counters> {
        principal::counters(&self.data(), account_id).await
    }

    async fn global_page(
        &self,
        category: GlobalCategory,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> model::Result<GlobalPage> {
        global::page(
            &self.data(),
            &self.blob(),
            &self.telemetry,
            &self.telemetry_config,
            category,
            cursor,
            limit,
        )
        .await
    }
}

#[cfg(test)]
mod global_tests;
#[cfg(test)]
mod regressions;
#[cfg(test)]
mod tests;
