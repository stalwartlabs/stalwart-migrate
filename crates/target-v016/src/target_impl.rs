/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::path::PathBuf;

use bytes::Bytes;
use common::{auth::AccountTenantIds, storage::index::ObjectIndexBuilder};
use email::message::metadata::{MessageData, MessageMetadata};
use futures::{StreamExt, TryStreamExt, stream};
use model::{
    AccountPointers, BlobHash, CategorySet, ChangeLogRecord, ClaimId, Collection, Counters,
    Edition, GlobalBatch, Issue, IssueKind, LogCollection, RecordBatch, RegistryCounter,
    RegistryKey, RegistryRecord, Severity, ShareNotificationRecord, SharedDeletion, SharedPlan,
    SpamModelChange, Subject, Target, TargetProbe, WriteMode, WriteOutcome,
};
use roaring::RoaringBitmap;
use store::{
    IterateParams, U32_LEN, ValueKey,
    write::{AlignedBytes, Archive, BatchBuilder, BlobOp, key::DeserializeBigEndian},
};
use types::{
    blob_hash::BlobHash as V016BlobHash, collection::Collection as V016Collection,
    field::EmailField,
};

use crate::{
    counters::v016_collection,
    error::trc_error,
    shared::planned_shared_changes,
    target::V016Target,
    writer::{BLOB_CONCURRENCY, ImportBatch},
};

impl Target for V016Target {
    fn created_paths(&self) -> Vec<PathBuf> {
        self.paths()
    }

    async fn probe(&self) -> model::Result<TargetProbe> {
        self.probe_store().await
    }

    async fn prepare_store(&self, edition: Edition) -> model::Result<()> {
        self.prepare(edition).await?;
        self.write_claim().await
    }

    async fn holds_claim(&self) -> model::Result<bool> {
        self.holds_own_claim().await
    }

    async fn claim_generation(&self) -> model::Result<Option<ClaimId>> {
        self.stored_generation().await
    }

    async fn swap_claim_generation(
        &self,
        expected: Option<ClaimId>,
        next: ClaimId,
    ) -> model::Result<bool> {
        V016Target::swap_claim_generation(self, expected, next).await
    }

    async fn read_registry(
        &self,
        keys: &[RegistryKey],
    ) -> model::Result<Vec<Option<RegistryRecord>>> {
        self.registry_read(keys).await
    }

    async fn write_registry(&self, records: &[RegistryRecord]) -> model::Result<WriteOutcome> {
        self.registry_write(records).await
    }

    fn registry_blob(&self, record: &RegistryRecord) -> Option<BlobHash> {
        self.registry_blob_hash(record)
    }

    async fn raise_registry_counters(&self, counters: &[RegistryCounter]) -> model::Result<()> {
        self.registry_counters(counters).await
    }

    async fn delete_registry(&self, keys: &[RegistryKey]) -> model::Result<()> {
        self.registry_delete(keys).await
    }

    async fn start_server(&self) -> model::Result<()> {
        self.boot_server().await
    }

    async fn write_pointers(
        &self,
        account_id: u32,
        pointers: &AccountPointers,
    ) -> model::Result<WriteOutcome> {
        self.store_pointers(account_id, pointers).await
    }

    async fn upsert(
        &self,
        account_id: u32,
        batch: &RecordBatch,
        mode: WriteMode,
    ) -> model::Result<WriteOutcome> {
        let server = self.server()?;
        let context = self.account_context(server, account_id).await?;
        let mut outcome = WriteOutcome::ok();
        match batch {
            RecordBatch::Mailbox(records) => {
                self.write_mailboxes(context, account_id, records, mode, &mut outcome)
                    .await?
            }
            RecordBatch::Calendar(records) => {
                self.write_calendars(context, account_id, records, mode, &mut outcome)
                    .await?
            }
            RecordBatch::AddressBook(records) => {
                self.write_address_books(context, account_id, records, mode)
                    .await?
            }
            RecordBatch::FileNode(records) => {
                self.write_file_nodes(context, account_id, records, mode)
                    .await?
            }
            RecordBatch::Identity(records) => {
                self.write_identities(context, account_id, records, mode)
                    .await?
            }
            RecordBatch::SieveScript(records) => {
                self.write_sieve_scripts(server, context, account_id, records, mode, &mut outcome)
                    .await?
            }
            RecordBatch::Email(records) => {
                self.write_emails(server, context, account_id, records, mode, &mut outcome)
                    .await?
            }
            RecordBatch::EmailSubmission(records) => {
                self.write_submissions(context, account_id, records, mode)
                    .await?
            }
            RecordBatch::CalendarEvent(records) => {
                self.write_calendar_events(server, context, account_id, records, mode, &mut outcome)
                    .await?
            }
            RecordBatch::CalendarEventNotification(records) => {
                self.write_event_notifications(context, account_id, records, mode, &mut outcome)
                    .await?
            }
            RecordBatch::ContactCard(records) => {
                self.write_contacts(context, account_id, records, mode, &mut outcome)
                    .await?
            }
        }
        Ok(outcome)
    }

    async fn delete(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> model::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let server = self.server()?;
        let context = self.account_context(server, account_id).await?;
        let collection = v016_collection(collection);
        if collection == V016Collection::Email {
            self.delete_emails(context, account_id, ids).await
        } else {
            self.delete_documents(context, account_id, collection, ids)
                .await
        }
    }

    async fn exists(
        &self,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> model::Result<RoaringBitmap> {
        let wanted = ids.iter().copied().collect::<RoaringBitmap>();
        let mut found = RoaringBitmap::new();
        let (Some(first), Some(last)) = (wanted.min(), wanted.max()) else {
            return Ok(found);
        };
        let collection = v016_collection(collection);
        self.store
            .iterate(
                IterateParams::new(
                    ValueKey::archive(account_id, collection, first),
                    ValueKey::archive(account_id, collection, last),
                )
                .no_values()
                .ascending(),
                |key, _| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if wanted.contains(document_id) {
                        found.insert(document_id);
                    }
                    Ok(true)
                },
            )
            .await
            .map_err(trc_error)?;
        Ok(found)
    }

    async fn wipe_account(&self, account_id: u32) -> model::Result<()> {
        self.wipe(account_id).await
    }

    async fn write_changelog(
        &self,
        account_id: u32,
        rows: &[ChangeLogRecord],
    ) -> model::Result<()> {
        self.write_log_rows(account_id, rows).await
    }

    async fn write_share_notifications(
        &self,
        account_id: u32,
        records: &[ShareNotificationRecord],
    ) -> model::Result<()> {
        self.write_shares(account_id, records).await
    }

    async fn retain_share_notifications(&self, account_id: u32, keep: &[u64]) -> model::Result<()> {
        self.retain_shares(account_id, keep).await
    }

    async fn raise_counters(&self, account_id: u32, counters: &Counters) -> model::Result<()> {
        self.raise_account_counters(account_id, counters).await
    }

    async fn blobs_exist(&self, hashes: &[BlobHash]) -> model::Result<Vec<bool>> {
        let store = &self.store;
        stream::iter(hashes.iter().copied())
            .map(|hash| async move { store.blob_exists(&V016BlobHash(hash.0)).await })
            .buffered(BLOB_CONCURRENCY)
            .map_err(trc_error)
            .try_collect()
            .await
    }

    async fn stored_blobs_exist(&self, hashes: &[BlobHash]) -> model::Result<Vec<bool>> {
        let server = self.server()?;
        let blob_store = server.blob_store();
        stream::iter(hashes.iter().copied())
            .map(|hash| async move {
                blob_store
                    .get_blob(hash.as_bytes(), 0..1)
                    .await
                    .map(|blob| blob.is_some())
            })
            .buffered(BLOB_CONCURRENCY)
            .map_err(trc_error)
            .try_collect()
            .await
    }

    async fn put_blob(&self, hash: &BlobHash, data: Bytes) -> model::Result<()> {
        let server = self.server()?;
        server
            .blob_store()
            .put_blob(hash.as_bytes(), &data, server.core.email.compression)
            .await
            .map_err(trc_error)?;
        failpoint!("blob.put");
        let mut batch = BatchBuilder::new();
        batch.set(
            BlobOp::Commit {
                hash: V016BlobHash(hash.0),
            },
            Vec::new(),
        );
        self.commit(batch).await
    }

    async fn shared_deletions(&self, account_id: u32) -> model::Result<Vec<SharedDeletion>> {
        self.planned_shared_deletions(account_id).await
    }

    async fn planned_shared_changes(
        &self,
        settings: &[RegistryRecord],
    ) -> model::Result<SharedPlan> {
        planned_shared_changes(settings)
    }

    async fn write_global(&self, batch: &GlobalBatch) -> model::Result<WriteOutcome> {
        if batch.is_empty() {
            return Ok(WriteOutcome::ok());
        }
        if let GlobalBatch::SpamModel(records) = batch {
            return Ok(WriteOutcome {
                issues: Self::defer_spam_model(records),
            });
        }
        Ok(WriteOutcome {
            issues: vec![Issue::new(
                Severity::Warning,
                IssueKind::Skipped,
                Subject::None,
                "only the spam model is written back to v0.16 by rollback",
            )],
        })
    }

    async fn apply_final_spam_model(
        &self,
        changes: &[SpamModelChange],
    ) -> model::Result<WriteOutcome> {
        self.apply_spam_model(changes).await
    }

    async fn finalize_account(
        &self,
        account_id: u32,
        counters: &Counters,
    ) -> model::Result<WriteOutcome> {
        self.finalize_one(account_id, counters).await
    }

    async fn reopen_account(
        &self,
        account_id: u32,
        copied: &[(LogCollection, u64)],
    ) -> model::Result<()> {
        self.reopen_one(account_id, copied).await
    }

    async fn finalize_store(&self, categories: CategorySet) -> model::Result<WriteOutcome> {
        let _ = categories;
        Ok(WriteOutcome::ok())
    }
}

impl V016Target {
    async fn delete_emails(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        ids: &[u32],
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for &document_id in ids {
            if self
                .remove_email(&mut batch.batch, context, account_id, document_id)
                .await?
            {
                batch.record_done();
            }
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn remove_email(
        &self,
        batch: &mut BatchBuilder,
        context: AccountTenantIds,
        account_id: u32,
        document_id: u32,
    ) -> model::Result<bool> {
        let Some(current) = self
            .current_archive(account_id, V016Collection::Email, document_id)
            .await?
        else {
            return Ok(false);
        };
        let data = current.to_unarchived::<MessageData>().map_err(trc_error)?;
        batch
            .with_collection(V016Collection::Email)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_current(data)
                    .with_changed_by(context),
            )
            .map_err(trc_error)?;
        if let Some(metadata) = self
            .store
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                V016Collection::Email,
                document_id,
                EmailField::Metadata,
            ))
            .await
            .map_err(trc_error)?
        {
            metadata
                .unarchive::<MessageMetadata>()
                .map_err(trc_error)?
                .unindex(batch);
        }
        Ok(true)
    }
}
