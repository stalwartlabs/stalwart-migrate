/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::DATABASE_SCHEMA_VERSION;
use registry::schema::structs::DataStore;
use std::fmt;
use store::{SUBSPACE_PROPERTY, SUBSPACE_QUOTA, Store, write::AnyKey};

#[cfg(feature = "rocks")]
use store::backend::rocksdb::{RocksDbOpenMode, RocksDbStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceScope {
    Full,
    BlobsOnly,
}

#[derive(Debug)]
pub struct OpenError(pub String);

pub const SCHEMA_VERSION: u32 = DATABASE_SCHEMA_VERSION;
const SCHEMA_KEY: u8 = 0;
const V1_SYSTEM_SUBSPACE: u8 = SUBSPACE_QUOTA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreSchema {
    V016(u32),
    V1(u32),
    Missing,
}

impl StoreSchema {
    pub(crate) async fn read(store: &Store) -> Result<Self, OpenError> {
        let read = |subspace| async move {
            store
                .get_value::<u32>(AnyKey {
                    subspace,
                    key: vec![SCHEMA_KEY],
                })
                .await
                .map_err(|err| OpenError(format!("cannot read the schema version: {err}")))
        };
        if let Some(version) = read(V1_SYSTEM_SUBSPACE).await? {
            return Ok(StoreSchema::V1(version));
        }
        Ok(match read(SUBSPACE_PROPERTY).await? {
            Some(version) => StoreSchema::V016(version),
            None => StoreSchema::Missing,
        })
    }

    pub(crate) async fn probe(config: DataStore) -> Result<Self, OpenError> {
        let store = open_data_store(config, SourceScope::Full).await?;
        Self::read(&store).await
    }
}

pub async fn open_data_store(config: DataStore, scope: SourceScope) -> Result<Store, OpenError> {
    match (config, scope) {
        #[cfg(feature = "rocks")]
        (DataStore::RocksDb(config), SourceScope::Full) => {
            RocksDbStore::open_with_mode(config, RocksDbOpenMode::ReadOnly).await
        }
        #[cfg(feature = "rocks")]
        (DataStore::RocksDb(config), SourceScope::BlobsOnly) => {
            RocksDbStore::open_with_mode(config, RocksDbOpenMode::BlobsReadOnly).await
        }
        #[cfg(not(feature = "rocks"))]
        (DataStore::RocksDb(_), _) => {
            Err("Binary was not compiled with RocksDB support".to_string())
        }
        #[cfg(feature = "sqlite")]
        (DataStore::Sqlite(config), _) => {
            store::backend::sqlite::SqliteStore::open_read_only(config).map(|(store, _)| store)
        }
        (config, _) => Store::build(config).await,
    }
    .map_err(OpenError)
}

#[cfg(feature = "foundation")]
pub fn use_external_foundationdb_network() {
    store::backend::foundationdb::FdbStore::use_external_network();
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to open the v0.16 store: {}", self.0)
    }
}

impl std::error::Error for OpenError {}
