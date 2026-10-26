/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::{
    identity::{EmailAddress, Identity},
    mailbox::Mailbox,
    message::{
        messagedata::{MessageData, SERVER_SET_KEYWORDS},
        metadata::MetadataRow,
    },
    sieve::SieveScript,
    submission::{Address, Delivered as V1Delivered, EmailSubmission, UndoStatus as V1Undo},
};
use model::{
    Delivered, DeliveryStatusRecord, EmailAddressRecord, EmailRecord, EnvelopeRecord,
    IdentityRecord, MailboxRecord, MailboxUid, SieveRecord, SmtpAddressRecord, SubmissionRecord,
    UndoStatus, VacationRecord,
};
use store::Deserialize;

use super::common::{acls, archive, blob_hash, stored_parent};
use crate::adapter::error::{corrupt, trc_error};

pub(super) fn mailbox(document_id: u32, bytes: &[u8]) -> model::Result<MailboxRecord> {
    let mailbox = archive(bytes)?
        .deserialize::<Mailbox>()
        .map_err(trc_error)?;
    Ok(MailboxRecord {
        document_id,
        role: mailbox.role().as_str().map(Box::from),
        name: mailbox.name,
        parent_id: stored_parent(mailbox.parent_id),
        sort_order: mailbox.sort_order,
        uid_validity: mailbox.uid_validity,
        subscribers: mailbox.subscribers,
        acls: acls(mailbox.acls),
    })
}

pub(super) fn email(document_id: u32, data: &[u8], metadata: &[u8]) -> model::Result<EmailRecord> {
    let mut data = MessageData::deserialize(data).map_err(trc_error)?;
    let row = MetadataRow::deserialize(metadata).map_err(trc_error)?;
    let raw_headers = row.raw_headers().map_err(trc_error)?;
    let metadata = row.unarchive().map_err(trc_error)?;
    let extra_headers = raw_headers
        .get(..metadata.extra_headers_len())
        .ok_or_else(|| corrupt(format!("email {document_id} has truncated headers")))?;
    let body_offset = u32::try_from(metadata.blob_body_offset())
        .map_err(|_| corrupt(format!("email {document_id} has an invalid body offset")))?;
    data.keywords &= !SERVER_SET_KEYWORDS;
    Ok(EmailRecord {
        document_id,
        thread_id: data.thread_id,
        change_id: data.change_id,
        received_at: data.received_at,
        keywords: data
            .keywords()
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
        blob_hash: blob_hash(&metadata.blob_hash()),
        body_offset,
        extra_headers: extra_headers.into(),
        size: data.size,
    })
}

pub(super) fn sieve(document_id: u32, bytes: &[u8]) -> model::Result<SieveRecord> {
    let script = archive(bytes)?
        .deserialize::<SieveScript>()
        .map_err(trc_error)?;
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

pub(super) fn identity(document_id: u32, bytes: &[u8]) -> model::Result<IdentityRecord> {
    let identity = archive(bytes)?
        .deserialize::<Identity>()
        .map_err(trc_error)?;
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

pub(super) fn submission(document_id: u32, bytes: &[u8]) -> model::Result<SubmissionRecord> {
    let submission = archive(bytes)?
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
            V1Undo::Pending => UndoStatus::Pending,
            V1Undo::Final => UndoStatus::Final,
            V1Undo::Canceled => UndoStatus::Canceled,
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
                            V1Delivered::Queued => Delivered::Queued,
                            V1Delivered::Yes => Delivered::Yes,
                            V1Delivered::No => Delivered::No,
                            V1Delivered::Unknown => Delivered::Unknown,
                        },
                        displayed: status.displayed,
                    },
                )
            })
            .collect(),
    })
}
