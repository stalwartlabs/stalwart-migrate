/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use crate::ids::BlobHash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessageRecord {
    pub queue_id: u64,
    pub created: u64,
    pub blob_hash: BlobHash,
    pub size: u64,
    pub return_path: Box<str>,
    pub recipients: Vec<QueueRecipient>,
    pub received_from_ip: IpAddr,
    pub received_via_port: u16,
    pub flags: u64,
    pub env_id: Option<Box<str>>,
    pub priority: i16,
    pub metadata: Vec<QueueMetadata>,
}

impl QueuedMessageRecord {
    pub const OBJECT: &str = "queuedMessage";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueueQuotaKey(pub u128);

impl QueueQuotaKey {
    pub fn from_hash(hash: &[u8]) -> Option<Self> {
        hash.first_chunk::<16>()
            .map(|prefix| QueueQuotaKey(u128::from_be_bytes(*prefix)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueMetadata {
    QuotaSize { key: QueueQuotaKey, id: u64 },
    QuotaCount { key: QueueQuotaKey, id: u64 },
    Headers { value: Box<[u8]>, id: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueueName(pub [u8; 8]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRecipient {
    pub address: Box<str>,
    pub retry: QueueSchedule,
    pub notify: QueueSchedule,
    pub expires: QueueExpiry,
    pub queue: QueueName,
    pub status: DeliveryStatus,
    pub flags: u64,
    pub orcpt: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSchedule {
    pub due: u64,
    pub attempt: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueExpiry {
    Ttl(u64),
    Attempts(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryStatus {
    Scheduled,
    Completed(Box<HostResponse>),
    TemporaryFailure(Box<DeliveryFailure>),
    PermanentFailure(Box<DeliveryFailure>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResponse {
    pub hostname: Box<str>,
    pub response: SmtpResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpResponse {
    pub code: u16,
    pub esc: [u8; 3],
    pub message: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryFailure {
    pub entity: Box<str>,
    pub error: DeliveryError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    Dns(Box<str>),
    UnexpectedResponse {
        command: Box<str>,
        response: SmtpResponse,
    },
    Connection(Box<str>),
    Tls(Box<str>),
    Dane(Box<str>),
    MtaSts(Box<str>),
    RateLimited,
    ConcurrencyLimited,
    Io(Box<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReportKind {
    Dmarc,
    Tls,
}

impl ReportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ReportKind::Dmarc => "dmarcReport",
            ReportKind::Tls => "tlsReport",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InternalReportRecord {
    pub kind: ReportKind,
    pub id: u64,
    pub json: serde_json::Value,
}

const _: () = assert!(size_of::<DeliveryStatus>() <= 16);
