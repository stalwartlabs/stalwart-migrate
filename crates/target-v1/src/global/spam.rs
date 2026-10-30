/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    Issue, IssueKind, RegistryKey, Severity, SpamModelChange, SpamModelKind, SpamModelRecord,
    Subject, WriteOutcome,
};
use registry::schema::{
    prelude::{ObjectInner, ObjectType},
    structs::BlobStore,
};
use source_v1::spam_archive::{self, SpamBlob};

use super::skipped;
use crate::{error::trc_error, target::V1Target};

const SPAM_MODEL_ID: u64 = 0;
const FINAL_STEP_ONLY: &str =
    "the spam model is written only by the final step, after verification passes";

fn blob_backend(inner: Option<ObjectInner>) -> Option<&'static str> {
    match inner? {
        ObjectInner::BlobStore(store) => match *store {
            BlobStore::Default => None,
            #[cfg(feature = "enterprise")]
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

#[derive(Clone, Copy)]
enum SharedChange {
    Overwritten,
    Deleted,
}

fn spam_blob(kind: SpamModelKind) -> SpamBlob {
    match kind {
        SpamModelKind::Classifier => SpamBlob::Classifier,
        SpamModelKind::Trainer => SpamBlob::Trainer,
    }
}

fn shared_change(blob: SpamBlob, backend: &str, change: SharedChange) -> Issue {
    let key = blob.as_str();
    Issue::new(
        Severity::Info,
        IssueKind::Changed,
        Subject::Registry(RegistryKey::new(key, SPAM_MODEL_ID)),
        match change {
            SharedChange::Overwritten => format!(
                "the {key} key in the external {backend} blob store was overwritten in the v1 format; v0.16 sharing this store cannot load it, and a rollback writes v0.16's model back only with --allow-shared-deletes"
            ),
            SharedChange::Deleted => format!(
                "the {key} key in the external {backend} blob store was deleted; v0.16 and v1 sharing this store retrain it"
            ),
        },
    )
}

impl V1Target {
    pub(crate) async fn external_blob_store(&self) -> model::Result<Option<&'static str>> {
        Ok(blob_backend(self.singleton(ObjectType::BlobStore).await?))
    }

    pub(super) fn defer_spam_model(records: &[SpamModelRecord]) -> Vec<Issue> {
        records
            .iter()
            .map(|record| skipped(record.as_str(), SPAM_MODEL_ID, FINAL_STEP_ONLY))
            .collect()
    }

    pub(crate) async fn apply_spam_model(
        &self,
        changes: &[SpamModelChange],
    ) -> model::Result<WriteOutcome> {
        if changes.is_empty() {
            return Ok(WriteOutcome::ok());
        }
        let backend = self.external_blob_store().await?;
        let server = self.server()?;
        let blob_store = server.blob_store();
        let mut issues = Vec::new();
        for change in changes {
            let blob = spam_blob(change.kind());
            let encoded = match change {
                SpamModelChange::Write(record) => match spam_archive::encode(record) {
                    Ok(data) => Some(data),
                    Err(err) => {
                        issues.push(skipped(
                            blob.as_str(),
                            SPAM_MODEL_ID,
                            format!("cannot encode the v1 spam model, v1 retrains it: {err}"),
                        ));
                        None
                    }
                },
                SpamModelChange::Delete(_) => None,
            };
            match (encoded, backend) {
                (Some(data), _) => {
                    blob_store
                        .delete_blob(blob.key())
                        .await
                        .map_err(trc_error)?;
                    blob_store
                        .put_blob(blob.key(), &data, server.core.email.compression)
                        .await
                        .map_err(trc_error)?;
                    if let Some(backend) = backend {
                        issues.push(shared_change(blob, backend, SharedChange::Overwritten));
                    }
                }
                (None, None) => {
                    blob_store
                        .delete_blob(blob.key())
                        .await
                        .map_err(trc_error)?;
                }
                (None, Some(backend)) => {
                    if blob_store.has_blob(blob.key()).await.map_err(trc_error)? {
                        blob_store
                            .delete_blob(blob.key())
                            .await
                            .map_err(trc_error)?;
                        issues.push(shared_change(blob, backend, SharedChange::Deleted));
                    }
                }
            }
        }
        Ok(WriteOutcome { issues })
    }
}
