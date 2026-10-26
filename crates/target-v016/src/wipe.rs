/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use registry::{schema::prelude::ObjectType, types::id::ObjectId};
use services::task_manager::destroy_account::destroy_account_blobs;
use store::{
    SUBSPACE_COUNTER, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_PROPERTY, U32_LEN, ValueKey,
    search::SearchQuery,
    write::{AnyKey, BatchBuilder, SearchIndex, ValueClass, key::KeySerializer},
};
use types::id::Id;

use crate::{error::trc_error, target::V016Target};

const SEARCH_INDEXES: [SearchIndex; 3] = [
    SearchIndex::Email,
    SearchIndex::Contacts,
    SearchIndex::Calendar,
];
const ACCOUNT_SUBSPACES: [u8; 3] = [SUBSPACE_LOGS, SUBSPACE_INDEXES, SUBSPACE_PROPERTY];
const TENANT_QUOTA_MARKER: u8 = u8::MAX - 1;
const LAST_MARKER: u8 = u8::MAX;

fn account_key(subspace: u8, account_id: u32, suffix: Option<u8>) -> AnyKey<Vec<u8>> {
    let key = KeySerializer::new(U32_LEN + 1).write(account_id);
    AnyKey {
        subspace,
        key: match suffix {
            Some(byte) => key.write(byte),
            None => key,
        }
        .finalize(),
    }
}

impl V016Target {
    pub(crate) async fn wipe(&self, account_id: u32) -> model::Result<()> {
        let server = self.server()?;
        self.release_tenant_quota(account_id).await?;
        failpoint!("wipe.step", "quota");
        let search = server.search_store();
        for index in SEARCH_INDEXES {
            search
                .unindex(SearchQuery::new(index).with_account_id(account_id))
                .await
                .map_err(trc_error)?;
            failpoint!("wipe.step", "search");
        }
        destroy_account_blobs(server, account_id)
            .await
            .map_err(trc_error)?;
        failpoint!("wipe.step", "blobs");
        self.store
            .acl_revoke_all(account_id)
            .await
            .map_err(trc_error)?;
        failpoint!("wipe.step", "acl");
        for subspace in ACCOUNT_SUBSPACES {
            self.store
                .delete_range(
                    account_key(subspace, account_id, None),
                    account_key(subspace, account_id, Some(LAST_MARKER)),
                )
                .await
                .map_err(trc_error)?;
            failpoint!("wipe.step", "rows");
        }
        self.store
            .delete_range(
                account_key(SUBSPACE_COUNTER, account_id, None),
                account_key(SUBSPACE_COUNTER, account_id, Some(TENANT_QUOTA_MARKER)),
            )
            .await
            .map_err(trc_error)?;
        failpoint!("wipe.step", "counters");
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id).clear(ValueClass::Quota);
        self.commit(batch).await
    }

    async fn release_tenant_quota(&self, account_id: u32) -> model::Result<()> {
        let Some(tenant_id) = self
            .registry
            .get(ObjectId::new(
                ObjectType::Account,
                Id::new(u64::from(account_id)),
            ))
            .await
            .map_err(trc_error)?
            .and_then(|object| object.inner.member_tenant_id())
        else {
            return Ok(());
        };
        let used = self
            .store
            .get_counter(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Quota,
            })
            .await
            .map_err(trc_error)?;
        if used == 0 {
            return Ok(());
        }
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .add(ValueClass::Quota, -used)
            .add(ValueClass::TenantQuota(tenant_id.document_id()), -used);
        self.commit(batch).await
    }
}

#[cfg(all(test, feature = "enterprise", feature = "rocks"))]
mod tests {
    use model::{Edition, RegistryKey, RegistryRecord, SharedDeletes, Target};
    use serde_json::json;
    use store::{
        ValueKey,
        write::{BatchBuilder, ValueClass},
    };
    use types::id::Id;

    use crate::target::{TargetConfig, V016Target};

    const ACCOUNT_ID: u32 = 5;
    const TENANT_ID: u32 = 1;
    const USED: i64 = 4096;

    async fn counter(target: &V016Target, account_id: u32, class: ValueClass) -> i64 {
        target
            .store
            .get_counter(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class,
            })
            .await
            .expect("counter")
    }

    // A tenant quota release that is retried after a failed wipe releases the account usage once.
    #[tokio::test(flavor = "multi_thread")]
    async fn tenant_quota_release_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("target.json");
        std::fs::write(
            &config,
            json!({"@type": "RocksDb", "path": dir.path().join("data").to_string_lossy()})
                .to_string(),
        )
        .expect("config");
        let target = V016Target::open(TargetConfig {
            data_store: config,
            shared_deletes: SharedDeletes::Forbid,
        })
        .await
        .expect("open");
        target
            .prepare_store(Edition::Enterprise)
            .await
            .expect("prepare");
        let tenant = Id::new(u64::from(TENANT_ID)).to_string();
        let outcome = target
            .write_registry(&[
                RegistryRecord {
                    key: RegistryKey::new("Tenant", u64::from(TENANT_ID)),
                    json: json!({"name": "acme"}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Domain", 3),
                    json: json!({"name": "example.org", "memberTenantId": tenant}),
                },
                RegistryRecord {
                    key: RegistryKey::new("Account", u64::from(ACCOUNT_ID)),
                    json: json!({
                        "@type": "User",
                        "name": "bob",
                        "domainId": Id::new(3).to_string(),
                        "memberTenantId": tenant,
                    }),
                },
            ])
            .await
            .expect("registry");
        assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(ACCOUNT_ID)
            .add(ValueClass::Quota, USED)
            .add(ValueClass::TenantQuota(TENANT_ID), USED);
        target.commit(batch).await.expect("quota");

        target
            .release_tenant_quota(ACCOUNT_ID)
            .await
            .expect("release");
        target
            .release_tenant_quota(ACCOUNT_ID)
            .await
            .expect("retried release");
        assert_eq!(
            counter(&target, TENANT_ID, ValueClass::TenantQuota(TENANT_ID)).await,
            0
        );
        assert_eq!(counter(&target, ACCOUNT_ID, ValueClass::Quota).await, 0);
    }
}
