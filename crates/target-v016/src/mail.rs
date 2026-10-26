/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccountTenantIds, storage::index::ObjectIndexBuilder};
use email::{
    identity::{EmailAddress, Identity},
    mailbox::{Mailbox, UidMailbox},
    message::{
        import::{EmailImport, ImportMessage, parse_extra_headers},
        metadata::{MESSAGE_RECEIVED_MASK, MessageData},
    },
    sieve::{SieveScript, VacationResponse},
    submission::{Address, Delivered, DeliveryStatus, EmailSubmission, Envelope, UndoStatus},
};
use futures::{StreamExt, stream};
use mail_parser::MessageParser;
use model::{
    AclRecord, EmailAddressRecord, EmailRecord, Explanation, IdentityRecord, Issue, IssueKind,
    MailboxRecord, Severity, SieveRecord, SmtpAddressRecord, Subject, SubmissionRecord, WriteMode,
    WriteOutcome,
};
use store::{
    Serialize,
    write::{Archiver, BatchBuilder},
};
use types::{
    acl::{Acl, AclGrant},
    blob_hash::BlobHash,
    collection::Collection,
    field::IdentityField,
    keyword::Keyword,
    special_use::SpecialUse,
};
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

use crate::{
    error::trc_error,
    objects::{delete_object, write_object},
    target::V016Target,
    writer::{BLOB_CONCURRENCY, ImportBatch},
};

const ACL_MASK: u64 = (1 << (Acl::ModifyRSVP as u64 + 1)) - 1;
const SIEVE_HOLD_SECONDS: u64 = 60;

pub(crate) fn acl_grants(acls: &[AclRecord]) -> Vec<AclGrant> {
    acls.iter()
        .map(|acl| AclGrant {
            account_id: acl.account_id,
            grants: Bitmap::from(acl.grants & ACL_MASK),
        })
        .collect()
}

pub(crate) fn issue(
    severity: Severity,
    kind: IssueKind,
    collection: model::Collection,
    document_id: u32,
    message: impl Into<Box<str>>,
) -> Issue {
    Issue::new(
        severity,
        kind,
        Subject::Document {
            collection,
            document_id,
        },
        message,
    )
}

pub(crate) const fn stored_parent(parent_id: Option<u32>) -> u32 {
    match parent_id {
        Some(id) => id + 1,
        None => 0,
    }
}

fn email_addresses(addresses: &Option<Vec<EmailAddressRecord>>) -> Option<Vec<EmailAddress>> {
    addresses.as_ref().map(|list| {
        list.iter()
            .map(|address| EmailAddress {
                name: address.name.clone(),
                email: address.email.clone(),
            })
            .collect()
    })
}

fn smtp_address(address: &SmtpAddressRecord) -> Address {
    Address {
        email: address.email.clone(),
        parameters: address.parameters.as_ref().map(|parameters| {
            let mut map = VecMap::with_capacity(parameters.len());
            for (name, value) in parameters {
                map.append(name.clone(), value.clone());
            }
            map
        }),
    }
}

fn email_blob_hash(record: &EmailRecord) -> model::BlobHash {
    record.blob_hash
}

fn email_mailboxes(record: &EmailRecord) -> Vec<UidMailbox> {
    record
        .mailboxes
        .iter()
        .map(|mailbox| UidMailbox::new(mailbox.mailbox_id, mailbox.uid))
        .collect()
}

fn email_keywords(record: &EmailRecord) -> Vec<Keyword> {
    let mut keywords: Vec<Keyword> = Vec::with_capacity(record.keywords.len());
    for keyword in record
        .keywords
        .iter()
        .map(|keyword| Keyword::parse(keyword))
    {
        if !keywords.contains(&keyword) {
            keywords.push(keyword);
        }
    }
    keywords
}

impl V016Target {
    pub(crate) async fn write_mailboxes(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[MailboxRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let role = match record.role.as_deref() {
                Some(role) => SpecialUse::parse(role).unwrap_or_else(|| {
                    outcome.issues.push(
                        issue(
                            Severity::Warning,
                            IssueKind::Dropped,
                            model::Collection::Mailbox,
                            record.document_id,
                            format!("mailbox role {role} has no v0.16 equivalent"),
                        )
                        .explaining(Explanation::MailboxRole),
                    );
                    SpecialUse::None
                }),
                None => SpecialUse::None,
            };
            let mailbox = Mailbox {
                name: record.name.clone(),
                role,
                parent_id: stored_parent(record.parent_id),
                sort_order: record.sort_order,
                uid_validity: record.uid_validity,
                subscribers: record.subscribers.clone(),
                acls: acl_grants(&record.acls),
            };
            let current = self
                .existing(account_id, Collection::Mailbox, record.document_id, mode)
                .await?;
            write_object(
                &mut batch.batch,
                Collection::Mailbox,
                record.document_id,
                current.as_ref(),
                mailbox,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_identities(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[IdentityRecord],
        mode: WriteMode,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let identity = Identity {
                name: record.name.clone(),
                email: record.email.clone(),
                reply_to: email_addresses(&record.reply_to),
                bcc: email_addresses(&record.bcc),
                text_signature: record.text_signature.clone(),
                html_signature: record.html_signature.clone(),
            };
            let current = self
                .existing(account_id, Collection::Identity, record.document_id, mode)
                .await?;
            write_object(
                &mut batch.batch,
                Collection::Identity,
                record.document_id,
                current.as_ref(),
                identity,
                context,
            )
            .map_err(trc_error)?;
            batch.batch.tag(IdentityField::DocumentId);
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_submissions(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[SubmissionRecord],
        mode: WriteMode,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let mut delivery_status = VecMap::with_capacity(record.delivery_status.len());
            for (recipient, status) in &record.delivery_status {
                delivery_status.append(
                    recipient.clone(),
                    DeliveryStatus {
                        smtp_reply: status.smtp_reply.clone(),
                        delivered: match status.delivered {
                            model::Delivered::Queued => Delivered::Queued,
                            model::Delivered::Yes => Delivered::Yes,
                            model::Delivered::No => Delivered::No,
                            model::Delivered::Unknown => Delivered::Unknown,
                        },
                        displayed: status.displayed,
                    },
                );
            }
            let submission = EmailSubmission {
                email_id: record.email_id,
                thread_id: record.thread_id,
                identity_id: record.identity_id,
                send_at: record.send_at,
                queue_id: record.queue_id,
                undo_status: match record.undo_status {
                    model::UndoStatus::Pending => UndoStatus::Pending,
                    model::UndoStatus::Final => UndoStatus::Final,
                    model::UndoStatus::Canceled => UndoStatus::Canceled,
                },
                envelope: Envelope {
                    mail_from: smtp_address(&record.envelope.mail_from),
                    rcpt_to: record.envelope.rcpt_to.iter().map(smtp_address).collect(),
                },
                delivery_status,
            };
            let current = self
                .existing(
                    account_id,
                    Collection::EmailSubmission,
                    record.document_id,
                    mode,
                )
                .await?;
            write_object(
                &mut batch.batch,
                Collection::EmailSubmission,
                record.document_id,
                current.as_ref(),
                submission,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_sieve_scripts(
        &self,
        server: &Server,
        context: AccountTenantIds,
        account_id: u32,
        records: &[SieveRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        for record in records {
            let Some(mut blob) = server
                .blob_store()
                .get_blob(record.blob_hash.as_bytes(), 0..usize::MAX)
                .await
                .map_err(trc_error)?
            else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::SieveScript,
                    record.document_id,
                    format!("sieve script blob {} is missing", record.blob_hash),
                ));
                continue;
            };
            blob.truncate(usize::try_from(record.size).unwrap_or(usize::MAX));
            let size = u32::try_from(blob.len()).unwrap_or(u32::MAX);
            match server.core.sieve.untrusted_compiler.compile(&blob) {
                Ok(compiled) => {
                    let compiled = Archiver::new(compiled)
                        .untrusted()
                        .serialize()
                        .map_err(trc_error)?;
                    blob.extend_from_slice(&compiled);
                }
                Err(err) => outcome.issues.push(issue(
                    Severity::Warning,
                    IssueKind::Changed,
                    model::Collection::SieveScript,
                    record.document_id,
                    format!("sieve script does not compile in v0.16 and fails when run: {err}"),
                )),
            }
            let (blob_hash, hold) = server
                .put_temporary_blob(account_id, &blob, SIEVE_HOLD_SECONDS)
                .await
                .map_err(trc_error)?;
            let script = SieveScript {
                name: record.name.clone(),
                blob_hash,
                size,
                vacation_response: record.vacation.as_ref().map(|vacation| VacationResponse {
                    from_date: vacation.from_date,
                    to_date: vacation.to_date,
                    subject: vacation.subject.clone(),
                    text_body: vacation.text_body.clone(),
                    html_body: vacation.html_body.clone(),
                }),
            };
            let current = self
                .existing(
                    account_id,
                    Collection::SieveScript,
                    record.document_id,
                    mode,
                )
                .await?;
            let mut batch = ImportBatch::new(account_id);
            write_object(
                &mut batch.batch,
                Collection::SieveScript,
                record.document_id,
                current.as_ref(),
                script,
                context,
            )
            .map_err(trc_error)?;
            batch.batch.clear(hold);
            batch.record_done();
            batch.commit(&self.store).await?;
        }
        Ok(())
    }

    pub(crate) async fn write_emails(
        &self,
        server: &Server,
        context: AccountTenantIds,
        account_id: u32,
        records: &[EmailRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let blob_store = server.blob_store();
        let mut batch = ImportBatch::new(account_id);
        let fetches = stream::iter(records.iter().map(email_blob_hash))
            .map(|hash| async move { blob_store.get_blob(hash.as_bytes(), 0..usize::MAX).await })
            .buffered(BLOB_CONCURRENCY);
        let mut prefetched = match mode {
            WriteMode::Create => Some(fetches.left_stream()),
            WriteMode::Replace => {
                Some(stream::iter(fetches.collect::<Vec<_>>().await).right_stream())
            }
            WriteMode::Update => None,
        };
        for record in records {
            let prefetched = match prefetched.as_mut() {
                Some(blobs) => blobs.next().await,
                None => None,
            };
            if mode == WriteMode::Update
                && self
                    .update_email(&mut batch.batch, context, account_id, record)
                    .await?
            {
                batch.record_done();
                continue;
            }
            let raw = match prefetched {
                Some(raw) => raw,
                None => {
                    blob_store
                        .get_blob(record.blob_hash.as_bytes(), 0..usize::MAX)
                        .await
                }
            };
            let Some(raw) = raw.map_err(trc_error)? else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::Email,
                    record.document_id,
                    format!("message blob {} is missing", record.blob_hash),
                ));
                continue;
            };
            let Some(message) = MessageParser::new().parse(raw.as_slice()) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::Email,
                    record.document_id,
                    "the message cannot be parsed by v0.16",
                ));
                continue;
            };
            let extra_headers: &[u8] = if parse_extra_headers(&record.extra_headers).is_some() {
                &record.extra_headers
            } else {
                outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Dropped,
                        model::Collection::Email,
                        record.document_id,
                        "server-added headers could not be parsed and were dropped",
                    )
                    .explaining(Explanation::ExtraHeaders),
                );
                &[]
            };
            let received_at = if record.received_at & MESSAGE_RECEIVED_MASK == record.received_at {
                record.received_at
            } else {
                outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Clamped,
                        model::Collection::Email,
                        record.document_id,
                        format!(
                            "received time {} is beyond the v0.16 maximum and was clamped to {MESSAGE_RECEIVED_MASK}",
                            record.received_at
                        ),
                    )
                    .explaining(Explanation::ReceivedAt),
                );
                MESSAGE_RECEIVED_MASK
            };
            if mode != WriteMode::Create {
                self.remove_email(&mut batch.batch, context, account_id, record.document_id)
                    .await?;
            }
            batch
                .batch
                .import_message(ImportMessage {
                    account_id,
                    tenant_id: context.tenant_id,
                    document_id: record.document_id,
                    thread_id: record.thread_id,
                    change_id: record.change_id,
                    mailboxes: email_mailboxes(record),
                    keywords: email_keywords(record),
                    received_at,
                    message,
                    extra_headers,
                    blob_hash: BlobHash(record.blob_hash.0),
                    commit_blob: true,
                })
                .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    async fn update_email(
        &self,
        batch: &mut BatchBuilder,
        context: AccountTenantIds,
        account_id: u32,
        record: &EmailRecord,
    ) -> model::Result<bool> {
        let Some(current) = self
            .current_archive(account_id, Collection::Email, record.document_id)
            .await?
        else {
            return Ok(false);
        };
        let current = current.to_unarchived::<MessageData>().map_err(trc_error)?;
        let data = MessageData {
            mailboxes: email_mailboxes(record).into_boxed_slice(),
            keywords: email_keywords(record).into_boxed_slice(),
            thread_id: current.inner.thread_id.to_native(),
            size: current.inner.size.to_native(),
        };
        batch
            .with_collection(Collection::Email)
            .with_document(record.document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(current)
                    .with_changes(data)
                    .with_changed_by(context)
                    .with_change_id(Some(record.change_id)),
            )
            .map_err(trc_error)?;
        Ok(true)
    }

    pub(crate) async fn delete_documents(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for &document_id in ids {
            let Some(current) = self
                .current_archive(account_id, collection, document_id)
                .await?
            else {
                continue;
            };
            let result = match collection {
                Collection::Mailbox => delete_object::<Mailbox>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    context,
                ),
                Collection::Identity => delete_object::<Identity>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    context,
                )
                .map(|_| {
                    batch.batch.untag(IdentityField::DocumentId);
                }),
                Collection::SieveScript => delete_object::<SieveScript>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    context,
                ),
                Collection::EmailSubmission => delete_object::<EmailSubmission>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    context,
                ),
                _ => self.delete_groupware(
                    &mut batch.batch,
                    context,
                    collection,
                    document_id,
                    &current,
                ),
            };
            result.map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }
}
