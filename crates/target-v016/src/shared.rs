/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    RegistryId, RegistryRecord, SharedDeletion, SharedOverwrite, SharedPlan, SharedService,
};
use registry::{
    schema::{
        prelude::{ObjectInner, ObjectType},
        structs::{BlobStore, SearchStore},
    },
    types::{EnumImpl, id::ObjectId},
};
use types::id::Id;

use crate::{
    error::{fatal, trc_error},
    target::V016Target,
};

fn search_backend(inner: Option<ObjectInner>) -> Option<&'static str> {
    match inner? {
        ObjectInner::SearchStore(store) => match store {
            SearchStore::Default => None,
            SearchStore::ElasticSearch(_) => Some("ElasticSearch"),
            SearchStore::Meilisearch(_) => Some("Meilisearch"),
            SearchStore::FoundationDb(_) => Some("FoundationDB"),
            SearchStore::PostgreSql(_) => Some("PostgreSQL"),
            SearchStore::MySql(_) => Some("MySQL"),
        },
        _ => None,
    }
}

fn blob_backend(inner: Option<ObjectInner>) -> Option<&'static str> {
    match inner? {
        ObjectInner::BlobStore(store) => match store {
            BlobStore::Default => None,
            BlobStore::Sharded(_) => Some("sharded"),
            BlobStore::S3(_) => Some("S3"),
            BlobStore::Azure(_) => Some("Azure"),
            BlobStore::FileSystem(_) => Some("file system"),
            BlobStore::FoundationDb(_) => Some("FoundationDB"),
            BlobStore::PostgreSql(_) => Some("PostgreSQL"),
            BlobStore::MySql(_) => Some("MySQL"),
        },
        _ => None,
    }
}

fn deletions(backend: Option<&str>, account_id: u32) -> Vec<SharedDeletion> {
    backend
        .map(|backend| SharedDeletion {
            service: SharedService::SearchIndex,
            account_id,
            what: format!(
                "email, calendar and contact documents in the external {backend} search store"
            )
            .into_boxed_str(),
        })
        .into_iter()
        .collect()
}

fn overwrites(backend: Option<&str>) -> Vec<SharedOverwrite> {
    backend
        .map(|backend| SharedOverwrite {
            service: SharedService::BlobStore,
            what: format!(
                "the spam classifier and trainer models under their fixed keys in the external {backend} blob store"
            )
            .into_boxed_str(),
        })
        .into_iter()
        .collect()
}

fn setting(settings: &[RegistryRecord], object: ObjectType) -> model::Result<Option<ObjectInner>> {
    settings
        .iter()
        .find(|record| {
            record.key.id == RegistryId::Singleton && record.key.object.as_ref() == object.as_str()
        })
        .map(|record| {
            ObjectInner::deserialize(object, &record.json).map_err(|err| {
                fatal(format!(
                    "cannot read the {} setting of the rollback target: {err}",
                    object.as_str()
                ))
            })
        })
        .transpose()
}

impl V016Target {
    async fn singleton(&self, object: ObjectType) -> model::Result<Option<ObjectInner>> {
        Ok(self
            .registry
            .get(ObjectId::new(object, Id::singleton()))
            .await
            .map_err(trc_error)?
            .map(|object| object.inner))
    }

    pub(crate) async fn planned_shared_deletions(
        &self,
        account_id: u32,
    ) -> model::Result<Vec<SharedDeletion>> {
        let backend = search_backend(self.singleton(ObjectType::SearchStore).await?);
        Ok(deletions(backend, account_id))
    }

    pub(crate) async fn external_blob_store(&self) -> model::Result<Option<&'static str>> {
        Ok(blob_backend(self.singleton(ObjectType::BlobStore).await?))
    }
}

pub(crate) fn planned_shared_changes(settings: &[RegistryRecord]) -> model::Result<SharedPlan> {
    Ok(SharedPlan {
        deletions: deletions(
            search_backend(setting(settings, ObjectType::SearchStore)?),
            0,
        ),
        overwrites: overwrites(blob_backend(setting(settings, ObjectType::BlobStore)?)),
    })
}
