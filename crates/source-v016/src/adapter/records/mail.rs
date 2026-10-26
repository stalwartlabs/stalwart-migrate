/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::{
    identity::{EmailAddress, Identity},
    mailbox::Mailbox,
    message::metadata::{MESSAGE_RECEIVED_MASK, MessageData, MessageMetadata},
    sieve::SieveScript,
    submission::{Address, Delivered as V016Delivered, EmailSubmission, UndoStatus as V016Undo},
};
use model::{
    BlobHash, Delivered, DeliveryStatusRecord, EmailAddressRecord, EmailRecord, EnvelopeRecord,
    IdentityRecord, MailboxRecord, MailboxUid, SieveRecord, SmtpAddressRecord, SubmissionRecord,
    UndoStatus, VacationRecord,
};
use store::write::{AlignedBytes, Archive, ArchiveVersion};

use super::common::{acls, blob_hash, stored_parent};
use crate::adapter::error::trc_error;

pub(super) fn mailbox(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<MailboxRecord> {
    let mailbox = archive.deserialize::<Mailbox>().map_err(trc_error)?;
    Ok(MailboxRecord {
        document_id,
        name: mailbox.name,
        parent_id: stored_parent(mailbox.parent_id),
        role: mailbox.role.as_str().map(Box::from),
        sort_order: mailbox.sort_order,
        uid_validity: mailbox.uid_validity,
        subscribers: mailbox.subscribers,
        acls: acls(mailbox.acls),
    })
}

pub(super) fn email(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
    metadata: &Archive<AlignedBytes>,
) -> model::Result<EmailRecord> {
    let data = archive.deserialize::<MessageData>().map_err(trc_error)?;
    let metadata = metadata.unarchive::<MessageMetadata>().map_err(trc_error)?;
    let change_id = match archive.version {
        ArchiveVersion::Versioned { change_id, .. } => change_id,
        ArchiveVersion::Hashed { .. } | ArchiveVersion::Unversioned => 0,
    };
    let body_offset = metadata.blob_body_offset.to_native();
    let raw_headers: &[u8] = &metadata.raw_headers;
    let extra_len = raw_headers
        .len()
        .saturating_sub(usize::try_from(body_offset).unwrap_or(usize::MAX));
    let extra_headers = raw_headers
        .get(..extra_len)
        .map(Box::<[u8]>::from)
        .unwrap_or_default();
    Ok(EmailRecord {
        document_id,
        thread_id: data.thread_id,
        change_id,
        received_at: metadata.rcvd_attach.to_native() & MESSAGE_RECEIVED_MASK,
        keywords: data
            .keywords
            .iter()
            .map(|keyword| keyword.to_string().into_boxed_str())
            .collect(),
        mailboxes: data
            .mailboxes
            .iter()
            .map(|mailbox| MailboxUid {
                mailbox_id: mailbox.mailbox_id,
                uid: mailbox.uid,
            })
            .collect(),
        blob_hash: BlobHash(metadata.blob_hash.0),
        body_offset,
        extra_headers,
        size: data.size,
    })
}

pub(super) fn sieve(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<SieveRecord> {
    let script = archive.deserialize::<SieveScript>().map_err(trc_error)?;
    Ok(SieveRecord {
        document_id,
        name: script.name,
        blob_hash: blob_hash(&script.blob_hash),
        size: script.size,
        vacation: script.vacation_response.map(|vacation| VacationRecord {
            from_date: vacation.from_date,
            to_date: vacation.to_date,
            subject: vacation.subject,
            text_body: vacation.text_body,
            html_body: vacation.html_body,
        }),
    })
}

fn addresses(addresses: Option<Vec<EmailAddress>>) -> Option<Vec<EmailAddressRecord>> {
    addresses.map(|list| {
        list.into_iter()
            .map(|address| EmailAddressRecord {
                name: address.name,
                email: address.email,
            })
            .collect()
    })
}

pub(super) fn identity(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<IdentityRecord> {
    let identity = archive.deserialize::<Identity>().map_err(trc_error)?;
    Ok(IdentityRecord {
        document_id,
        name: identity.name,
        email: identity.email,
        reply_to: addresses(identity.reply_to),
        bcc: addresses(identity.bcc),
        text_signature: identity.text_signature,
        html_signature: identity.html_signature,
    })
}

fn smtp_address(address: Address) -> SmtpAddressRecord {
    SmtpAddressRecord {
        email: address.email,
        parameters: address
            .parameters
            .map(|parameters| parameters.into_iter().collect()),
    }
}

pub(super) fn submission(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<SubmissionRecord> {
    let submission = archive
        .deserialize::<EmailSubmission>()
        .map_err(trc_error)?;
    Ok(SubmissionRecord {
        document_id,
        email_id: submission.email_id,
        thread_id: submission.thread_id,
        identity_id: submission.identity_id,
        send_at: submission.send_at,
        queue_id: submission.queue_id,
        undo_status: match submission.undo_status {
            V016Undo::Pending => UndoStatus::Pending,
            V016Undo::Final => UndoStatus::Final,
            V016Undo::Canceled => UndoStatus::Canceled,
        },
        envelope: EnvelopeRecord {
            mail_from: smtp_address(submission.envelope.mail_from),
            rcpt_to: submission
                .envelope
                .rcpt_to
                .into_iter()
                .map(smtp_address)
                .collect(),
        },
        delivery_status: submission
            .delivery_status
            .into_iter()
            .map(|(recipient, status)| {
                (
                    recipient,
                    DeliveryStatusRecord {
                        smtp_reply: status.smtp_reply,
                        delivered: match status.delivered {
                            V016Delivered::Queued => Delivered::Queued,
                            V016Delivered::Yes => Delivered::Yes,
                            V016Delivered::No => Delivered::No,
                            V016Delivered::Unknown => Delivered::Unknown,
                        },
                        displayed: status.displayed,
                    },
                )
            })
            .collect(),
    })
}
