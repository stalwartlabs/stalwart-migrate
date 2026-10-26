/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::{MAX_RECEIVED_AT, MessageUid, Server, storage::index::ObjectIndexBuilder};
use email::{
    identity::{EmailAddress, Identity},
    mailbox::Mailbox,
    message::{
        import::{EmailImport, ImportMessage},
        messagedata::{MessageData, PendingMessageData},
        metadata::ExtraHeaders,
    },
    sieve::{SieveScript, VacationResponse},
    submission::{Address, Delivered, DeliveryStatus, EmailSubmission, Envelope, UndoStatus},
};
use futures::{StreamExt, stream};
use mail_parser::MessageParser;
use model::{
    AclRecord, BlobCache, EmailAddressRecord, EmailRecord, Explanation, IdentityRecord, Issue,
    IssueKind, MailboxRecord, Severity, SieveRecord, SmtpAddressRecord, Subject, SubmissionRecord,
    WriteMode, WriteOutcome,
};
use store::{
    BlobStore, ValueKey,
    write::{Archive, ArchiveBytes, SlotRange},
};
use types::{
    acl::{Acl, AclGrant},
    blob_hash::BlobHash,
    collection::Collection,
    keyword::{HASATTACHMENT, HASNOATTACHMENT, Keyword},
    special_use::SpecialUse,
};
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

use crate::{
    error::trc_error,
    objects::{delete_object, write_object},
    target::V1Target,
    target_impl::EmailRemoval,
    writer::{AccountContext, BLOB_CONCURRENCY},
};

const ACL_MASK: u64 = (1 << (Acl::ModifyRSVP as u64 + 1)) - 1;
const ATTACHMENT_BITS: u32 = (1 << HASATTACHMENT) | (1 << HASNOATTACHMENT);

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

const fn stored_parent(parent_id: Option<u32>) -> u32 {
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

impl V1Target {
    pub(crate) async fn write_mailboxes(
        &self,
        context: &AccountContext,
        account_id: u32,
        records: &[MailboxRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for record in records {
            let mut mailbox = Mailbox {
                name: record.name.clone(),
                parent_id: stored_parent(record.parent_id),
                sort_order: record.sort_order,
                uid_validity: record.uid_validity,
                subscribers: record.subscribers.clone(),
                acls: acl_grants(&record.acls),
                flags: 0,
            };
            if let Some(role) = record.role.as_deref() {
                match SpecialUse::parse(role) {
                    Some(role) => mailbox.set_role(role),
                    None => outcome.issues.push(
                        issue(
                            Severity::Warning,
                            IssueKind::Dropped,
                            model::Collection::Mailbox,
                            record.document_id,
                            format!("mailbox role {role} has no v1 equivalent"),
                        )
                        .explaining(Explanation::MailboxRole),
                    ),
                }
            }
            let current = self
                .existing(account_id, Collection::Mailbox, record.document_id, mode)
                .await?;
            write_object(
                &mut batch.batch,
                Collection::Mailbox,
                record.document_id,
                current.as_ref(),
                mailbox,
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn existing(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        mode: WriteMode,
    ) -> model::Result<Option<Archive<ArchiveBytes>>> {
        if mode == WriteMode::Create {
            Ok(None)
        } else {
            self.current_archive(account_id, collection, document_id)
                .await
        }
    }

    pub(crate) async fn write_identities(
        &self,
        context: &AccountContext,
        account_id: u32,
        records: &[IdentityRecord],
        mode: WriteMode,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
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
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_submissions(
        &self,
        context: &AccountContext,
        account_id: u32,
        records: &[SubmissionRecord],
        mode: WriteMode,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
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
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_sieve_scripts(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        records: &[SieveRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        for record in records {
            let Some(blob) = server
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
            let raw = blob
                .get(..usize::try_from(record.size).unwrap_or(usize::MAX))
                .unwrap_or(&blob);
            let mut script = SieveScript::new(record.name.clone(), BlobHash::default())
                .with_size(raw.len() as u32);
            match server.core.sieve.untrusted_compiler.compile(raw) {
                Ok(compiled) => script.set_script(&compiled),
                Err(err) => outcome.issues.push(issue(
                    Severity::Warning,
                    IssueKind::Changed,
                    model::Collection::SieveScript,
                    record.document_id,
                    format!(
                        "sieve script does not compile in v1 and stays inactive until fixed: {err}"
                    ),
                )),
            }
            if let Some(vacation) = &record.vacation {
                script = script.with_vacation_response(VacationResponse {
                    from_date: vacation.from_date,
                    to_date: vacation.to_date,
                    subject: vacation.subject.clone(),
                    text_body: vacation.text_body.clone(),
                    html_body: vacation.html_body.clone(),
                });
            }
            let (blob_hash, hold) = server
                .hold_blob(account_id, BlobHash::generate(raw), raw, 60)
                .await
                .map_err(trc_error)?;
            script = script.with_blob_hash(blob_hash);
            let current = self
                .existing(
                    account_id,
                    Collection::SieveScript,
                    record.document_id,
                    mode,
                )
                .await?;
            let mut batch = self.import_batch(account_id);
            write_object(
                &mut batch.batch,
                Collection::SieveScript,
                record.document_id,
                current.as_ref(),
                script,
                context.changed_by,
            )
            .map_err(trc_error)?;
            hold.release(&mut batch.batch);
            batch.record_done(raw.len() as u64);
            batch.commit(&self.store).await?;
        }
        Ok(())
    }

    pub(crate) async fn write_emails(
        &self,
        context: &AccountContext,
        account_id: u32,
        records: &[EmailRecord],
        mode: WriteMode,
        blobs: &BlobCache,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let server = self.server()?;
        let limits = &server.core.email.limits;
        let blob_store = server.blob_store();
        let mut batch = self.import_batch(account_id);
        let fetches = stream::iter(records.iter().map(email_blob_hash))
            .map(|hash| email_body(blob_store, blobs, hash))
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
            let mailboxes = self.email_mailboxes(record, limits.mailboxes_per_email, outcome);
            let keywords = email_keywords(record, limits, outcome);
            if mode == WriteMode::Update
                && let Some(current) = self
                    .store
                    .get_value::<MessageData>(ValueKey::archive(
                        account_id,
                        Collection::Email,
                        record.document_id,
                    ))
                    .await
                    .map_err(trc_error)?
            {
                let mut data = current.clone();
                data.set_mailboxes(mailboxes.iter().copied().collect());
                data.set_keywords(keywords);
                data.keywords |= current.keywords & ATTACHMENT_BITS;
                batch
                    .batch
                    .with_collection(Collection::Email)
                    .with_document(record.document_id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_current(current)
                            .with_changes(PendingMessageData {
                                data,
                                uid_slots: SlotRange::default(),
                                thread_slot: None,
                                change_id: Some(record.change_id),
                            })
                            .with_changed_by(context.changed_by),
                    )
                    .map_err(trc_error)?;
                batch.record_done(256);
                continue;
            }

            let raw = match prefetched {
                Some(raw) => raw,
                None => email_body(blob_store, blobs, record.blob_hash).await,
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
            let Some(message) = MessageParser::new().parse(&raw) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::Email,
                    record.document_id,
                    "the message cannot be parsed by v1",
                ));
                continue;
            };
            let extra_headers = match ExtraHeaders::from_raw(&record.extra_headers) {
                Some(headers) => headers,
                None => {
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
                    ExtraHeaders::default()
                }
            };
            if record.received_at > MAX_RECEIVED_AT {
                outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Clamped,
                        model::Collection::Email,
                        record.document_id,
                        format!(
                            "received time {} is beyond the v1 maximum and was clamped to {MAX_RECEIVED_AT}",
                            record.received_at
                        ),
                    )
                    .explaining(Explanation::ReceivedAt),
                );
            }
            if mode != WriteMode::Create {
                self.remove_email(
                    &mut batch.batch,
                    context,
                    account_id,
                    record.document_id,
                    EmailRemoval::Replace,
                )
                .await?;
            }
            batch
                .batch
                .import_message(ImportMessage {
                    account_id,
                    #[cfg(feature = "enterprise")]
                    tenant_id: context.tenant_id,
                    document_id: record.document_id,
                    thread_id: record.thread_id,
                    change_id: record.change_id,
                    mailboxes: &mailboxes,
                    keywords,
                    received_at: record.received_at,
                    message: &message,
                    extra_headers: &extra_headers,
                    blob_hash: BlobHash(record.blob_hash.0),
                    commit_blob: true,
                })
                .map_err(trc_error)?;
            batch.record_done(raw.len() as u64);
        }
        batch.commit(&self.store).await
    }

    fn email_mailboxes(
        &self,
        record: &EmailRecord,
        limit: usize,
        outcome: &mut WriteOutcome,
    ) -> Vec<MessageUid> {
        if record.mailboxes.len() > limit {
            outcome.issues.push(issue(
                Severity::Warning,
                IssueKind::Truncated,
                model::Collection::Email,
                record.document_id,
                format!(
                    "the message is in {} mailboxes, v1 keeps the first {limit} (raise Email.maxMailboxesPerEmail to keep all)",
                    record.mailboxes.len()
                ),
            )
            .explaining(Explanation::Mailboxes(
                u32::try_from(limit).unwrap_or(u32::MAX),
            )));
        }
        record
            .mailboxes
            .iter()
            .take(limit)
            .map(|uid| MessageUid::new(uid.mailbox_id, uid.uid))
            .collect()
    }

    pub(crate) async fn delete_documents(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        collection: Collection,
        ids: &[u32],
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for &document_id in ids {
            let Some(current) = self
                .current_archive(account_id, collection, document_id)
                .await?
            else {
                continue;
            };
            let changed_by = context.changed_by;
            let result = match collection {
                Collection::Mailbox => delete_object::<Mailbox>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    changed_by,
                ),
                Collection::Identity => delete_object::<Identity>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    changed_by,
                ),
                Collection::SieveScript => delete_object::<SieveScript>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    changed_by,
                ),
                Collection::EmailSubmission => delete_object::<EmailSubmission>(
                    &mut batch.batch,
                    collection,
                    document_id,
                    &current,
                    changed_by,
                ),
                _ => {
                    self.delete_groupware(
                        server,
                        context,
                        &mut batch.batch,
                        account_id,
                        collection,
                        document_id,
                        current,
                    )
                    .await?;
                    Ok(())
                }
            };
            result.map_err(trc_error)?;
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }
}

fn email_blob_hash(record: &EmailRecord) -> model::BlobHash {
    record.blob_hash
}

async fn email_body<'x>(
    blob_store: &BlobStore,
    blobs: &'x BlobCache,
    hash: model::BlobHash,
) -> trc::Result<Option<Cow<'x, [u8]>>> {
    match blobs.get(&hash) {
        Some(data) => Ok(Some(Cow::Borrowed(data))),
        None => blob_store
            .get_blob(hash.as_bytes(), 0..usize::MAX)
            .await
            .map(|data| data.map(Cow::Owned)),
    }
}

fn email_keywords(
    record: &EmailRecord,
    limits: &common::config::mailstore::limits::EmailLimits,
    outcome: &mut WriteOutcome,
) -> Vec<Keyword> {
    let mut keywords = Vec::with_capacity(record.keywords.len());
    for name in &record.keywords {
        let keyword = Keyword::parse(name);
        if limits.is_keyword_allowed(&keyword) {
            keywords.push(keyword);
        } else {
            outcome.issues.push(issue(
                Severity::Warning,
                IssueKind::Dropped,
                model::Collection::Email,
                record.document_id,
                format!(
                    "keyword {name} is longer than {} characters and was dropped (raise Email.maxFlagLength to keep it)",
                    limits.keyword_length
                ),
            )
            .explaining(Explanation::Keyword(Box::from(&**name))));
        }
    }
    let mut keywords = Keyword::unique(keywords);
    if keywords.len() > limits.keywords_per_email {
        outcome.issues.push(issue(
            Severity::Warning,
            IssueKind::Truncated,
            model::Collection::Email,
            record.document_id,
            format!(
                "the message has {} keywords, v1 keeps {} (raise Email.maxFlagsPerEmail to keep all)",
                keywords.len(),
                limits.keywords_per_email
            ),
        )
        .explaining(Explanation::Keywords(
            u32::try_from(limits.keywords_per_email).unwrap_or(u32::MAX),
        )));
        keywords.truncate(limits.keywords_per_email);
    }
    keywords
}
