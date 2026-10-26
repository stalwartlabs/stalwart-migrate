/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use model::BlobHash;
use registry::{
    schema::{
        prelude::{Object, ObjectInner, ObjectType},
        structs,
    },
    types::EnumImpl,
};
use store::{
    BlobStore, Store, ValueKey,
    backend::fs::FsStore,
    write::{RegistryClass, ValueClass},
};
use types::id::Id;

use super::{SourceConfig, error::trc_error};
use crate::open::OpenError;

pub(super) async fn blob_store_config(data: &Store) -> trc::Result<Option<structs::BlobStore>> {
    let object = data
        .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::BlobStore.to_id(),
            item_id: Id::singleton().id(),
        })))
        .await?;
    Ok(match object.map(|object| object.inner) {
        Some(ObjectInner::BlobStore(config)) => Some(config),
        _ => None,
    })
}

pub(super) fn rewrite_blob_store(
    config: structs::BlobStore,
    source: &SourceConfig,
) -> structs::BlobStore {
    match config {
        structs::BlobStore::FileSystem(mut store) => {
            store.path = source.rewrite(&store.path);
            structs::BlobStore::FileSystem(store)
        }
        structs::BlobStore::Sharded(mut store) => {
            for shard in store.stores.values_mut() {
                if let structs::BlobStoreBase::FileSystem(shard) = shard {
                    shard.path = source.rewrite(&shard.path);
                }
            }
            structs::BlobStore::Sharded(store)
        }
        other => other,
    }
}

pub(super) fn file_system_paths(config: Option<&structs::BlobStore>) -> impl Iterator<Item = &str> {
    let (single, shards) = match config {
        Some(structs::BlobStore::FileSystem(store)) => (Some(store.path.as_str()), None),
        Some(structs::BlobStore::Sharded(store)) => (None, Some(store.stores.iter())),
        _ => (None, None),
    };
    single.into_iter().chain(
        shards
            .into_iter()
            .flatten()
            .filter_map(|shard| match shard {
                structs::BlobStoreBase::FileSystem(store) => Some(store.path.as_str()),
                _ => None,
            }),
    )
}

#[allow(unreachable_patterns)]
pub(super) async fn open_blob_store(
    config: Option<structs::BlobStore>,
    data: &Store,
) -> Result<BlobStore, OpenError> {
    let result = match config.unwrap_or(structs::BlobStore::Default) {
        structs::BlobStore::Default => return Ok(BlobStore::Store(data.clone())),
        structs::BlobStore::FileSystem(store) => {
            if !std::path::Path::new(&store.path).is_dir() {
                return Err(OpenError(format!(
                    "the v0.16 file system blob store {} does not exist",
                    store.path
                )));
            }
            FsStore::open(store).await
        }
        #[cfg(feature = "s3")]
        structs::BlobStore::S3(store) => store::backend::s3::S3Store::open(store).await,
        #[cfg(feature = "azure")]
        structs::BlobStore::Azure(store) => store::backend::azure::AzureStore::open(store).await,
        #[cfg(feature = "foundation")]
        structs::BlobStore::FoundationDb(store) => {
            store::backend::foundationdb::FdbStore::open(store)
                .await
                .map(BlobStore::Store)
        }
        #[cfg(feature = "postgres")]
        structs::BlobStore::PostgreSql(store) => {
            store::backend::postgres::PostgresStore::open(store)
                .await
                .map(BlobStore::Store)
        }
        #[cfg(feature = "mysql")]
        structs::BlobStore::MySql(store) => store::backend::mysql::MysqlStore::open(store)
            .await
            .map(BlobStore::Store),
        #[cfg(feature = "enterprise")]
        structs::BlobStore::Sharded(store) => {
            if let Some(missing) = store.stores.iter().find_map(|shard| match shard {
                structs::BlobStoreBase::FileSystem(shard)
                    if !std::path::Path::new(&shard.path).is_dir() =>
                {
                    Some(shard.path.as_str())
                }
                _ => None,
            }) {
                return Err(OpenError(format!(
                    "the v0.16 file system blob store shard {missing} does not exist"
                )));
            }
            store::backend::composite::sharded_blob::ShardedBlob::open(store).await
        }
        _ => {
            Err("this binary was not compiled with the configured v0.16 blob store backend".into())
        }
    };
    result.map_err(OpenError)
}

pub(super) async fn read(blob: &BlobStore, hash: &BlobHash) -> model::Result<Option<Bytes>> {
    blob.get_blob(hash.as_bytes(), 0..usize::MAX)
        .await
        .map(|data| data.map(Bytes::from))
        .map_err(trc_error)
}
