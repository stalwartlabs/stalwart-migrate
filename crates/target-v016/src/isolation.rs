/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use registry::schema::{
    prelude::{Object, ObjectInner},
    structs::{
        BlobStore, BlobStoreBase, Coordinator, InMemoryStore, MetricsStore, SearchStore,
        TracingStore,
    },
};
use store::registry::bootstrap::{ObjectRewrite, RewriteAction};

use model::SharedDeletes;

pub(crate) fn boot_rewrite(shared_deletes: SharedDeletes) -> ObjectRewrite {
    Arc::new(move |object: &mut Object| {
        match &mut object.inner {
            ObjectInner::SearchStore(store) => match store {
                _ if shared_deletes == SharedDeletes::Forbid => *store = SearchStore::Default,
                SearchStore::PostgreSql(store) => store.read_replicas = Default::default(),
                SearchStore::MySql(store) => store.read_replicas = Default::default(),
                SearchStore::Default
                | SearchStore::ElasticSearch(_)
                | SearchStore::Meilisearch(_)
                | SearchStore::FoundationDb(_) => {}
            },
            ObjectInner::BlobStore(store) => primary_blob_store(store),
            ObjectInner::InMemoryStore(store) => *store = InMemoryStore::Default,
            ObjectInner::Coordinator(coordinator) => *coordinator = Coordinator::Disabled,
            ObjectInner::TracingStore(store) => *store = TracingStore::Disabled,
            ObjectInner::MetricsStore(store) => *store = MetricsStore::Disabled,
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
