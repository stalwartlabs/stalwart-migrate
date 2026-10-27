/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use bytes::Bytes;

use crate::{
    batch::RecordPage,
    changes::{
        AccountPointers, AccountRef, ChangeBounds, ChangeLogRecord, Changes, Counters, LogRange,
        QuotaUsage, ShareNotificationRecord,
    },
    error::Result,
    global::{GlobalCategory, GlobalPage},
    ids::{BlobHash, Collection, LogCollection},
    queue::InternalReportRecord,
    registry::{RegistryCounter, RegistryEntries, RegistryKey, RegistryRecord},
};

const LAST_CHANGE_PAGE: usize = 1024;

pub trait Source: Send + Sync + 'static {
    fn catch_up(&self) -> impl Future<Output = Result<()>> + Send;

    fn check_unchanged(&self) -> Result<()> {
        Ok(())
    }

    fn registry_types(&self) -> impl Future<Output = Result<Vec<Box<str>>>> + Send;

    fn registry_page(
        &self,
        object: &str,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<RegistryEntries>> + Send;

    fn registry_id_counters(&self) -> impl Future<Output = Result<Vec<RegistryCounter>>> + Send;

    fn canonical_registry(&self, record: RegistryRecord) -> Result<RegistryRecord> {
        Ok(record)
    }

    fn registry_blob(&self, _record: &RegistryRecord) -> Option<BlobHash> {
        None
    }

    fn unlisted_registry(
        &self,
        _records: &[RegistryRecord],
    ) -> impl Future<Output = Result<Vec<RegistryKey>>> + Send {
        async { Ok(Vec::new()) }
    }

    fn accounts(&self) -> impl Future<Output = Result<Vec<AccountRef>>> + Send;

    fn stored_accounts(&self) -> impl Future<Output = Result<Vec<AccountRef>>> + Send {
        self.accounts()
    }

    fn change_bounds(
        &self,
        account: AccountRef,
    ) -> impl Future<Output = Result<ChangeBounds>> + Send {
        async move { Ok(ChangeBounds::uniform(account.change_counter)) }
    }

    fn changes(
        &self,
        account_id: u32,
        collection: Collection,
        since: u64,
    ) -> impl Future<Output = Result<Changes>> + Send;

    fn changelog(
        &self,
        account_id: u32,
        collection: LogCollection,
        range: LogRange,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<ChangeLogRecord>>> + Send;

    fn last_change_id(
        &self,
        account_id: u32,
        collection: LogCollection,
        up_to: u64,
    ) -> impl Future<Output = Result<Option<u64>>> + Send {
        async move {
            let mut range = LogRange { after: 0, up_to };
            let mut last = None;
            loop {
                let rows = self
                    .changelog(account_id, collection, range, LAST_CHANGE_PAGE)
                    .await?;
                match rows.last() {
                    Some(row) if row.change_id > range.after => {
                        range.after = row.change_id;
                        last = Some(row.change_id);
                    }
                    _ => return Ok(last),
                }
            }
        }
    }

    fn scan(
        &self,
        account_id: u32,
        collection: Collection,
        after: Option<u32>,
        limit: usize,
    ) -> impl Future<Output = Result<RecordPage>> + Send;

    fn read(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> impl Future<Output = Result<RecordPage>> + Send;

    fn share_notifications(
        &self,
        account_id: u32,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<ShareNotificationRecord>>> + Send;

    fn read_blob(&self, hash: &BlobHash) -> impl Future<Output = Result<Option<Bytes>>> + Send;

    fn blobs_exist(&self, hashes: &[BlobHash]) -> impl Future<Output = Result<Vec<bool>>> + Send {
        async move {
            let mut exist = Vec::with_capacity(hashes.len());
            for hash in hashes {
                exist.push(self.read_blob(hash).await?.is_some());
            }
            Ok(exist)
        }
    }

    fn pointers(&self, account_id: u32) -> impl Future<Output = Result<AccountPointers>> + Send;

    fn counters(&self, account_id: u32) -> impl Future<Output = Result<Counters>> + Send;

    fn quota_usage(
        &self,
        _account_id: u32,
    ) -> impl Future<Output = Result<Option<QuotaUsage>>> + Send {
        async { Ok(None) }
    }

    fn stored_report(
        &self,
        record: InternalReportRecord,
    ) -> impl Future<Output = Result<InternalReportRecord>> + Send {
        async { Ok(record) }
    }

    fn global_page(
        &self,
        category: GlobalCategory,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> impl Future<Output = Result<GlobalPage>> + Send;
}
