/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ids::{BlobHash, MailboxUid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AclRecord {
    pub account_id: u32,
    pub grants: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MailboxRecord {
    pub document_id: u32,
    pub name: String,
    pub parent_id: Option<u32>,
    pub role: Option<Box<str>>,
    pub sort_order: Option<u32>,
    pub uid_validity: u32,
    pub subscribers: Vec<u32>,
    pub acls: Vec<AclRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmailRecord {
    pub document_id: u32,
    pub thread_id: u32,
    pub change_id: u64,
    pub received_at: u64,
    pub keywords: Vec<Box<str>>,
    pub mailboxes: Vec<MailboxUid>,
    pub blob_hash: BlobHash,
    pub body_offset: u32,
    pub extra_headers: Box<[u8]>,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VacationRecord {
    pub from_date: Option<u64>,
    pub to_date: Option<u64>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SieveRecord {
    pub document_id: u32,
    pub name: String,
    pub blob_hash: BlobHash,
    pub size: u32,
    pub vacation: Option<VacationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmailAddressRecord {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityRecord {
    pub document_id: u32,
    pub name: String,
    pub email: String,
    pub reply_to: Option<Vec<EmailAddressRecord>>,
    pub bcc: Option<Vec<EmailAddressRecord>>,
    pub text_signature: String,
    pub html_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UndoStatus {
    #[default]
    Pending,
    Final,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Delivered {
    Queued,
    Yes,
    No,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmtpAddressRecord {
    pub email: String,
    pub parameters: Option<Vec<(String, Option<String>)>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvelopeRecord {
    pub mail_from: SmtpAddressRecord,
    pub rcpt_to: Vec<SmtpAddressRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeliveryStatusRecord {
    pub smtp_reply: String,
    pub delivered: Delivered,
    pub displayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubmissionRecord {
    pub document_id: u32,
    pub email_id: u32,
    pub thread_id: u32,
    pub identity_id: u32,
    pub send_at: u64,
    pub queue_id: Option<u64>,
    pub undo_status: UndoStatus,
    pub envelope: EnvelopeRecord,
    pub delivery_status: Vec<(String, DeliveryStatusRecord)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushKeysRecord {
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmailPushRecord {
    pub account_id: u32,
    pub properties: Vec<Box<str>>,
    pub filter: serde_json::Value,
    pub urgency: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PushRecord {
    pub id: u32,
    pub url: String,
    pub device_client_id: String,
    pub expires: u64,
    pub verification_code: String,
    pub verified: bool,
    pub types: Vec<Box<str>>,
    pub keys: Option<PushKeysRecord>,
    pub email_push: Vec<EmailPushRecord>,
}
