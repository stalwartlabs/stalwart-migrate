/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    BlobHash, DeliveryError, DeliveryFailure, DeliveryStatus, GlobalBatch, GlobalPage,
    HostResponse, Issue, IssueKind, QueueExpiry, QueueMetadata, QueueName, QueueQuotaKey,
    QueueRecipient, QueueSchedule, QueuedMessageRecord, RegistryKey, Severity, SmtpResponse,
    Subject,
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse as V016HostResponse, Message, Metadata, Recipient, Schedule,
    Status,
};
use store::{
    Deserialize, IterateParams, Store, U64_LEN, ValueKey,
    write::{AlignedBytes, Archive, QueueClass, ValueClass, key::DeserializeBigEndian},
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
                .with_limit(limit),
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
        match <Archive<AlignedBytes> as Deserialize>::deserialize(&value)
            .and_then(|archive| archive.deserialize::<Message>())
            .map_err(|err| err.to_string())
            .and_then(|message| record(queue_id, message))
        {
            Ok(record) => records.push(record),
            Err(err) => issues.push(Issue::new(
                Severity::Error,
                IssueKind::Skipped,
                Subject::Registry(RegistryKey::new(QueuedMessageRecord::OBJECT, queue_id)),
                format!("undecodable v0.16 queued message: {err}"),
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

fn record(queue_id: u64, message: Message) -> Result<QueuedMessageRecord, String> {
    let metadata = message
        .metadata
        .into_vec()
        .into_iter()
        .map(|metadata| match metadata {
            Metadata::QueueSize { key, id } => QueueQuotaKey::from_hash(&key)
                .map(|key| QueueMetadata::QuotaSize { key, id })
                .ok_or("short quota key"),
            Metadata::QueueCount { key, id } => QueueQuotaKey::from_hash(&key)
                .map(|key| QueueMetadata::QuotaCount { key, id })
                .ok_or("short quota key"),
            Metadata::Headers { value, id } => Ok(QueueMetadata::Headers { value, id }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(QueuedMessageRecord {
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
        metadata,
    })
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
            common::config::smtp::queue::QueueExpiry::Ttl(ttl) => QueueExpiry::Ttl(ttl),
            common::config::smtp::queue::QueueExpiry::Attempts(attempts) => {
                QueueExpiry::Attempts(attempts)
            }
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

fn status(status: Status<V016HostResponse<Box<str>>, ErrorDetails>) -> DeliveryStatus {
    match status {
        Status::Scheduled => DeliveryStatus::Scheduled,
        Status::Completed(host) => DeliveryStatus::Completed(Box::new(HostResponse {
            hostname: host.hostname,
            response: response(host.response),
        })),
        Status::TemporaryFailure(details) => DeliveryStatus::TemporaryFailure(failure(details)),
        Status::PermanentFailure(details) => DeliveryStatus::PermanentFailure(failure(details)),
    }
}
