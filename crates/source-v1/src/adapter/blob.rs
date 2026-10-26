/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use futures::{StreamExt, TryStreamExt, stream};
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

use super::error::{OpenError, trc_error};

const BLOB_CONCURRENCY: usize = 16;

pub(super) async fn blob_store_config(data: &Store) -> trc::Result<Option<structs::BlobStore>> {
    let object = data
        .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::BlobStore.to_id(),
            item_id: Id::singleton().id(),
        })))
        .await?;
    Ok(match object.map(|object| object.inner) {
        Some(ObjectInner::BlobStore(config)) => Some(*config),
        _ => None,
    })
}

pub(super) fn rewrite_blob_store(
    config: structs::BlobStore,
    rewrite: Option<&(dyn Fn(&str) -> String + Send + Sync)>,
) -> structs::BlobStore {
    match (config, rewrite) {
        (structs::BlobStore::FileSystem(mut store), Some(rewrite)) => {
            store.path = rewrite(&store.path);
            structs::BlobStore::FileSystem(store)
        }
        (other, _) => other,
    }
}

pub(super) fn file_system_paths(config: &structs::BlobStore) -> Vec<String> {
    match config {
        structs::BlobStore::FileSystem(store) => vec![store.path.clone()],
        #[cfg(feature = "enterprise")]
        structs::BlobStore::Sharded(store) => store
            .stores
            .iter()
            .filter_map(|shard| match shard {
                structs::BlobStoreBase::FileSystem(store) => Some(store.path.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
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
                    "the v1 file system blob store {} does not exist",
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
            store::backend::composite::sharded_blob::ShardedBlob::open(store).await
        }
        _ => Err("this binary was not compiled with the configured v1 blob store backend".into()),
    };
    result.map_err(OpenError)
}

pub(super) async fn read(blob: &BlobStore, hash: &BlobHash) -> model::Result<Option<Bytes>> {
    blob.get_blob(hash.as_bytes(), 0..usize::MAX)
        .await
        .map(|data| data.map(Bytes::from))
        .map_err(trc_error)
}

pub(super) async fn exist(blob: &BlobStore, hashes: &[BlobHash]) -> model::Result<Vec<bool>> {
    stream::iter(hashes.iter().copied())
        .map(|hash| async move { blob.has_blob(hash.as_bytes()).await })
        .buffered(BLOB_CONCURRENCY)
        .map_err(trc_error)
        .try_collect()
        .await
}
