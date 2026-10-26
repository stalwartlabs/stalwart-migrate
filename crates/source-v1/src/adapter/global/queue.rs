/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::queue::QueueExpiry as V1QueueExpiry;
use model::{
    BlobHash, DeliveryError, DeliveryFailure, DeliveryStatus, GlobalBatch, GlobalPage,
    HostResponse, Issue, IssueKind, QueueExpiry, QueueMetadata, QueueName, QueueQuotaKey,
    QueueRecipient, QueueSchedule, QueuedMessageRecord, RegistryKey, Severity, SmtpResponse,
    Subject,
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse as V1HostResponse, Message, Metadata, Recipient, Schedule,
    Status,
};
use store::{
    Deserialize, IterateParams, Store, U64_LEN, ValueKey,
    write::{Archive, ArchiveBytes, QueueClass, ValueClass, key::DeserializeBigEndian},
};

use super::id_cursor;
use crate::adapter::error::trc_error;

fn key(queue_id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Queue(QueueClass::Message(queue_id)))
}

pub(super) async fn page(
    store: &Store,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    let Some(first) = id_cursor(cursor)? else {
        return Ok(GlobalPage::last(GlobalBatch::Queue(Vec::new())));
    };
    let limit = limit.max(1);
    let mut values = Vec::with_capacity(limit.min(1024));
    store
        .iterate(
            IterateParams::new(key(first), key(u64::MAX))
                .ascending()
                .limit(limit),
            |key, value| {
                if key.len() == U64_LEN {
                    values.push((key.deserialize_be_u64(0)?, value.to_vec()));
                }
                Ok(values.len() < limit)
            },
        )
        .await
        .map_err(trc_error)?;

    let next = (values.len() == limit)
        .then(|| values.last().map(|(id, _)| id.to_be_bytes().to_vec()))
        .flatten();
    let mut records = Vec::with_capacity(values.len());
    let mut issues = Vec::new();
    for (queue_id, value) in values {
        match <Archive<ArchiveBytes> as Deserialize>::deserialize(&value)
            .and_then(|archive| archive.deserialize::<Message>())
        {
            Ok(message) => records.push(record(queue_id, message)),
            Err(err) => issues.push(Issue::new(
                Severity::Error,
                IssueKind::Skipped,
                Subject::Registry(RegistryKey::new(QueuedMessageRecord::OBJECT, queue_id)),
                format!("undecodable v1 queued message: {err}"),
            )),
        }
    }
    Ok(GlobalPage {
        batch: GlobalBatch::Queue(records),
        issues,
        next,
        resume: None,
    })
}

fn record(queue_id: u64, message: Message) -> QueuedMessageRecord {
    QueuedMessageRecord {
        queue_id,
        created: message.created,
        blob_hash: BlobHash(message.blob_hash.0),
        size: message.size,
        return_path: message.return_path,
        recipients: message.recipients.into_iter().map(recipient).collect(),
        received_from_ip: message.received_from_ip,
        received_via_port: message.received_via_port,
        flags: message.flags,
        env_id: message.env_id,
        priority: message.priority,
        metadata: message
            .metadata
            .into_vec()
            .into_iter()
            .filter_map(|metadata| match metadata {
                Metadata::QueueSize { key, id } => Some(QueueMetadata::QuotaSize {
                    key: QueueQuotaKey(key),
                    id,
                }),
                Metadata::QueueCount { key, id } => Some(QueueMetadata::QuotaCount {
                    key: QueueQuotaKey(key),
                    id,
                }),
                Metadata::Headers { value, id } => Some(QueueMetadata::Headers { value, id }),
                Metadata::Submission { .. } => None,
            })
            .collect(),
    }
}

fn schedule(schedule: Schedule<u32>) -> QueueSchedule {
    QueueSchedule {
        due: schedule.due,
        attempt: schedule.inner,
    }
}

fn recipient(recipient: Recipient) -> QueueRecipient {
    QueueRecipient {
        address: recipient.address,
        retry: schedule(recipient.retry),
        notify: schedule(recipient.notify),
        expires: match recipient.expires {
            V1QueueExpiry::Ttl(ttl) => QueueExpiry::Ttl(ttl),
            V1QueueExpiry::Attempts(attempts) => QueueExpiry::Attempts(attempts),
        },
        queue: QueueName(recipient.queue.into_inner()),
        status: status(recipient.status),
        flags: recipient.flags,
        orcpt: recipient.orcpt,
    }
}

fn response(response: smtp_proto::Response<Box<str>>) -> SmtpResponse {
    SmtpResponse {
        code: response.code,
        esc: response.esc,
        message: response.message,
    }
}

fn failure(details: ErrorDetails) -> Box<DeliveryFailure> {
    Box::new(DeliveryFailure {
        entity: details.entity,
        error: match details.details {
            Error::DnsError(err) => DeliveryError::Dns(err),
            Error::UnexpectedResponse(err) => DeliveryError::UnexpectedResponse {
                command: err.command,
                response: response(err.response),
            },
            Error::ConnectionError(err) => DeliveryError::Connection(err),
            Error::TlsError(err) => DeliveryError::Tls(err),
            Error::DaneError(err) => DeliveryError::Dane(err),
            Error::MtaStsError(err) => DeliveryError::MtaSts(err),
            Error::RateLimited => DeliveryError::RateLimited,
            Error::ConcurrencyLimited => DeliveryError::ConcurrencyLimited,
            Error::Io(err) => DeliveryError::Io(err),
        },
    })
}

fn status(status: Status<V1HostResponse<Box<str>>, ErrorDetails>) -> DeliveryStatus {
    match status {
        Status::Scheduled => DeliveryStatus::Scheduled,
        Status::Completed(host) => DeliveryStatus::Completed(Box::new(HostResponse {
            hostname: host.hostname,
            response: response(host.response),
        })),
        Status::TemporaryFailure(details) => DeliveryStatus::TemporaryFailure(failure(*details)),
        Status::PermanentFailure(details) => DeliveryStatus::PermanentFailure(failure(*details)),
    }
}
