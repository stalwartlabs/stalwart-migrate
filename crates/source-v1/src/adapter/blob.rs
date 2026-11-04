/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

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
    BlobStore, Deserialize, IterateParams, Store, U16_LEN, ValueKey,
    backend::fs::FsStore,
    write::{
        RegistryClass, ValueClass,
        blob_codec::{BlobKey, BlobKeyring},
        key::DeserializeBigEndian,
    },
};
use types::id::Id;

use super::{
    PathRewrite,
    error::{OpenError, trc_error},
};

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

pub(super) async fn keyring(
    data: &Store,
    rewrite: Option<&PathRewrite>,
) -> model::Result<BlobKeyring> {
    let key = |item_id| {
        ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::SymmetricKey.to_id(),
            item_id,
        }))
    };
    let mut stored = Vec::new();
    data.iterate(
        IterateParams::new(key(0), key(u64::MAX)).ascending(),
        |key, value| {
            let item_id = key.deserialize_be_u64(U16_LEN)?;
            let object = <Object as Deserialize>::deserialize_with_key(key, value)?;
            if let ObjectInner::SymmetricKey(symmetric) = object.inner {
                stored.push((item_id, symmetric));
            }
            Ok(true)
        },
    )
    .await
    .map_err(trc_error)?;
    let mut keys = Vec::with_capacity(stored.len());
    for (item_id, mut symmetric) in stored {
        let unusable = |reason: &str| {
            model::Error::fatal(format!(
                "v1 blob encryption key SymmetricKey/{item_id} ({}) cannot be loaded: {reason}",
                symmetric.description
            ))
        };
        if let (structs::SecretKey::File(file), Some(rewrite)) = (&mut symmetric.key, rewrite) {
            file.file_path = rewrite(&file.file_path);
        }
        let id = u32::try_from(item_id).map_err(|_| unusable("its id exceeds 32 bits"))?;
        let secret = symmetric.key.secret().await.map_err(|err| unusable(&err))?;
        let key = BlobKey::from_base64(id, symmetric.cipher, &secret)
            .map_err(|err| unusable(err.message()))?;
        if !symmetric.fingerprint.is_empty() && symmetric.fingerprint != key.fingerprint() {
            return Err(unusable("the secret does not match its stored fingerprint"));
        }
        keys.push(Arc::new(key));
    }
    Ok(BlobKeyring::new(keys))
}

pub(super) async fn read(
    blob: &BlobStore,
    keys: &BlobKeyring,
    hash: &BlobHash,
) -> model::Result<Option<Bytes>> {
    blob.get_blob(hash.as_bytes(), 0..usize::MAX, keys)
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
