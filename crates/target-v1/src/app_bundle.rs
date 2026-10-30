/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{Issue, IssueKind, RegistryKey, Severity, Subject};
use registry::schema::prelude::ObjectType;
use store::registry::RegistryQuery;
use types::{blob_hash::BlobHash, id::Id};

use crate::{error::trc_error, target::V1Target};

const APP_BLOB_PREFIX: &str = "STALWART_APP_";

impl V1Target {
    pub(crate) async fn discard_app_bundles(&self) -> model::Result<Vec<Issue>> {
        let Some(backend) = self.external_blob_store().await? else {
            return Ok(Vec::new());
        };
        let server = self.server()?;
        let blob_store = server.blob_store();
        let mut issues = Vec::new();
        for id in server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Application))
            .await
            .map_err(trc_error)?
        {
            let key = BlobHash::generate(format!("{APP_BLOB_PREFIX}{id}").as_bytes());
            if blob_store
                .delete_blob(key.as_slice())
                .await
                .map_err(trc_error)?
            {
                issues.push(Issue::new(
                    Severity::Info,
                    IssueKind::Changed,
                    Subject::Registry(RegistryKey::new("Application", id.id())),
                    format!(
                        "the cached bundle of this Application was deleted from the external {backend} blob store; v1 downloads its own on the next start"
                    ),
                ));
            }
        }
        Ok(issues)
    }
}
