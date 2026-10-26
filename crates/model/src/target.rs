/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, path::PathBuf};

use bytes::Bytes;
use roaring::RoaringBitmap;

use crate::{
    batch::RecordBatch,
    blob::BlobCache,
    category::CategorySet,
    changes::{AccountPointers, ChangeLogRecord, Counters, ShareNotificationRecord},
    claim::ClaimId,
    error::Result,
    global::{GlobalBatch, GlobalKey},
    ids::{BlobHash, Collection, LogCollection},
    issue::WriteOutcome,
    registry::{RegistryCounter, RegistryKey, RegistryRecord},
    shared::{SharedDeletion, SharedPlan},
    spam::SpamModelChange,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Edition {
    Enterprise,
    Community,
}

impl Edition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Edition::Enterprise => "enterprise",
            Edition::Community => "community",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), Edition,
            "enterprise" => Edition::Enterprise,
            "community" => Edition::Community,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProbe {
    Empty,
    Initialized { schema_version: u64 },
    Foreign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteMode {
    Create,
    Replace,
    Update,
}

pub trait Target: Send + Sync + 'static {
    fn max_batch_bytes(&self) -> Option<u64> {
        None
    }

    fn created_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn probe(&self) -> impl Future<Output = Result<TargetProbe>> + Send;

    fn holds_claim(&self) -> impl Future<Output = Result<bool>> + Send {
        async { Ok(false) }
    }

    fn claim_generation(&self) -> impl Future<Output = Result<Option<ClaimId>>> + Send {
        async { Ok(None) }
    }

    fn swap_claim_generation(
        &self,
        expected: Option<ClaimId>,
        next: ClaimId,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn shared_deletions(
        &self,
        _account_id: u32,
    ) -> impl Future<Output = Result<Vec<SharedDeletion>>> + Send {
        async { Ok(Vec::new()) }
    }

    fn planned_shared_changes(
        &self,
        _settings: &[RegistryRecord],
    ) -> impl Future<Output = Result<SharedPlan>> + Send {
        async { Ok(SharedPlan::default()) }
    }

    fn prepare_store(&self, edition: Edition) -> impl Future<Output = Result<()>> + Send;

    fn read_registry(
        &self,
        keys: &[RegistryKey],
    ) -> impl Future<Output = Result<Vec<Option<RegistryRecord>>>> + Send;

    fn write_registry(
        &self,
        records: &[RegistryRecord],
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn delete_registry(&self, keys: &[RegistryKey]) -> impl Future<Output = Result<()>> + Send;

    fn raise_registry_counters(
        &self,
        counters: &[RegistryCounter],
    ) -> impl Future<Output = Result<()>> + Send {
        let _ = counters;
        std::future::ready(Ok(()))
    }

    fn start_server(&self) -> impl Future<Output = Result<()>> + Send;

    fn write_pointers(
        &self,
        account_id: u32,
        pointers: &AccountPointers,
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn upsert(
        &self,
        account_id: u32,
        batch: &RecordBatch,
        mode: WriteMode,
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn upsert_with_blobs(
        &self,
        account_id: u32,
        batch: &RecordBatch,
        mode: WriteMode,
        blobs: &BlobCache,
    ) -> impl Future<Output = Result<WriteOutcome>> + Send {
        let _ = blobs;
        self.upsert(account_id, batch, mode)
    }

    fn delete(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> impl Future<Output = Result<()>> + Send;

    fn exists(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> impl Future<Output = Result<RoaringBitmap>> + Send;

    fn wipe_account(&self, account_id: u32) -> impl Future<Output = Result<()>> + Send;

    fn write_changelog(
        &self,
        account_id: u32,
        rows: &[ChangeLogRecord],
    ) -> impl Future<Output = Result<()>> + Send;

    fn write_share_notifications(
        &self,
        account_id: u32,
        records: &[ShareNotificationRecord],
    ) -> impl Future<Output = Result<()>> + Send;

    fn retain_share_notifications(
        &self,
        _account_id: u32,
        _keep: &[u64],
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }

    fn raise_counters(
        &self,
        account_id: u32,
        counters: &Counters,
    ) -> impl Future<Output = Result<()>> + Send;

    fn blobs_exist(&self, hashes: &[BlobHash]) -> impl Future<Output = Result<Vec<bool>>> + Send;

    fn put_blob(&self, hash: &BlobHash, data: Bytes) -> impl Future<Output = Result<()>> + Send;

    fn registry_blob(&self, _record: &RegistryRecord) -> Option<BlobHash> {
        None
    }

    fn write_global(
        &self,
        batch: &GlobalBatch,
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn delete_global(
        &self,
        keys: &[GlobalKey],
    ) -> impl Future<Output = Result<WriteOutcome>> + Send {
        let _ = keys;
        std::future::ready(Ok(WriteOutcome::ok()))
    }

    fn apply_final_spam_model(
        &self,
        changes: &[SpamModelChange],
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn finalize_account(
        &self,
        account_id: u32,
        counters: &Counters,
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn finalize_store(
        &self,
        categories: CategorySet,
    ) -> impl Future<Output = Result<WriteOutcome>> + Send;

    fn reopen_account(
        &self,
        account_id: u32,
        copied: &[(LogCollection, u64)],
    ) -> impl Future<Output = Result<()>> + Send {
        let _ = (account_id, copied);
        std::future::ready(Ok(()))
    }
}
