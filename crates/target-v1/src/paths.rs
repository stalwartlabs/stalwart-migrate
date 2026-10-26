/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

#[cfg(feature = "enterprise")]
use registry::schema::structs::{BlobStoreBase, MetricsStore, TracingStore};
use registry::schema::{
    prelude::{Object, ObjectInner},
    structs::{BlobStore, Coordinator, DataStore, FoundationDbStore, InMemoryStore, SearchStore},
};
use store::registry::bootstrap::{ObjectRewrite, RewriteAction};

pub type PathRewrite = Arc<dyn Fn(&str) -> String + Send + Sync>;

fn rewrite_path(rewrite: &PathRewrite, path: &mut String) {
    *path = rewrite(path);
}

fn rewrite_cluster_file(rewrite: &PathRewrite, store: &mut FoundationDbStore) {
    if let Some(path) = &mut store.cluster_file {
        rewrite_path(rewrite, path);
    }
}

pub(crate) fn rewrite_data_store(rewrite: &PathRewrite, mut store: DataStore) -> DataStore {
    match &mut store {
        DataStore::RocksDb(store) => rewrite_path(rewrite, &mut store.path),
        DataStore::Sqlite(store) => rewrite_path(rewrite, &mut store.path),
        DataStore::FoundationDb(store) => rewrite_cluster_file(rewrite, store),
        DataStore::PostgreSql(_) | DataStore::MySql(_) => {}
    }
    store
}

#[cfg(feature = "enterprise")]
pub(crate) fn primary_only(mut store: DataStore) -> DataStore {
    match &mut store {
        DataStore::PostgreSql(store) => store.read_replicas = Default::default(),
        DataStore::MySql(store) => store.read_replicas = Default::default(),
        DataStore::RocksDb(_) | DataStore::Sqlite(_) | DataStore::FoundationDb(_) => {}
    }
    store
}

#[cfg(not(feature = "enterprise"))]
pub(crate) fn primary_only(store: DataStore) -> DataStore {
    store
}

#[cfg(feature = "enterprise")]
fn primary_blob_store(store: &mut BlobStore) {
    match store {
        BlobStore::PostgreSql(store) => store.read_replicas = Default::default(),
        BlobStore::MySql(store) => store.read_replicas = Default::default(),
        BlobStore::Sharded(sharded) => {
            for member in sharded.stores.values_mut() {
                match member {
                    BlobStoreBase::PostgreSql(store) => store.read_replicas = Default::default(),
                    BlobStoreBase::MySql(store) => store.read_replicas = Default::default(),
                    BlobStoreBase::S3(_)
                    | BlobStoreBase::Azure(_)
                    | BlobStoreBase::FileSystem(_)
                    | BlobStoreBase::FoundationDb(_) => {}
                }
            }
        }
        BlobStore::Default
        | BlobStore::S3(_)
        | BlobStore::Azure(_)
        | BlobStore::FileSystem(_)
        | BlobStore::FoundationDb(_) => {}
    }
}

#[cfg(not(feature = "enterprise"))]
fn primary_blob_store(_: &mut BlobStore) {}

fn rewrite_blob_store(rewrite: &PathRewrite, store: &mut BlobStore) {
    match store {
        BlobStore::FileSystem(store) => rewrite_path(rewrite, &mut store.path),
        BlobStore::FoundationDb(store) => rewrite_cluster_file(rewrite, store),
        #[cfg(feature = "enterprise")]
        BlobStore::Sharded(sharded) => {
            for member in sharded.stores.values_mut() {
                match member {
                    BlobStoreBase::FileSystem(store) => rewrite_path(rewrite, &mut store.path),
                    BlobStoreBase::FoundationDb(store) => rewrite_cluster_file(rewrite, store),
                    BlobStoreBase::S3(_)
                    | BlobStoreBase::Azure(_)
                    | BlobStoreBase::PostgreSql(_)
                    | BlobStoreBase::MySql(_) => {}
                }
            }
        }
        BlobStore::Default
        | BlobStore::S3(_)
        | BlobStore::Azure(_)
        | BlobStore::PostgreSql(_)
        | BlobStore::MySql(_) => {}
    }
}

pub(crate) fn boot_rewrite(paths: Option<PathRewrite>) -> ObjectRewrite {
    Arc::new(move |object: &mut Object| {
        match &mut object.inner {
            ObjectInner::BlobStore(store) => {
                if let Some(paths) = &paths {
                    rewrite_blob_store(paths, store);
                }
                primary_blob_store(store);
            }
            ObjectInner::SearchStore(store) => **store = SearchStore::Default,
            ObjectInner::InMemoryStore(store) => **store = InMemoryStore::Default,
            ObjectInner::Coordinator(coordinator) => **coordinator = Coordinator::Disabled,
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(store) => **store = TracingStore::Disabled,
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(store) => **store = MetricsStore::Disabled,
            ObjectInner::StoreLookup(_)
            | ObjectInner::HttpLookup(_)
            | ObjectInner::Directory(_) => {
                return RewriteAction::Skip;
            }
            _ => {}
        }
        RewriteAction::Keep
    })
}
