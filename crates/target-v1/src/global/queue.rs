/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::queue::{QueueExpiry as V1QueueExpiry, QueueName as V1QueueName};
use model::{
    DeliveryError, DeliveryFailure, DeliveryStatus, Issue, QueueExpiry, QueueMetadata,
    QueueRecipient, QueueSchedule, QueuedMessageRecord, SmtpResponse,
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse, Message, Metadata, Recipient, Schedule, Status,
    UnexpectedResponse,
};
use smtp_proto::Response;
use store::{
    Serialize,
    write::{
        Archive, ArchiveBytes, Archiver, BatchBuilder, BlobLink, BlobOp, QueueClass, QueueEvent,
        ValueClass, blob::BlobLinkValue,
    },
};
use types::blob_hash::BlobHash;

use super::skipped;
use crate::{
    error::trc_error,
    prefetch::{Prefetched, keep_last},
    target::V1Target,
};

impl V1Target {
    pub(super) async fn write_queue(
        &self,
        records: &[QueuedMessageRecord],
    ) -> model::Result<Vec<Issue>> {
        #[cfg(feature = "enterprise")]
        let server = self.server()?;
        let mut issues = Vec::new();
        let mut batch = self.global_batch();
        let records = keep_last(records.iter(), |record| record.queue_id);
        let current = self
            .prefetch(records.iter().map(|record| message_key(record.queue_id)))
            .await?;
        for record in records {
            let queue_id = record.queue_id;
            #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
            let mut message = message(record);
            #[cfg(feature = "enterprise")]
            message.assign_tenants(server, 0).await;
            let archiver = Archiver::new(message);
            let archive = match archiver.serialize() {
                Ok(archive) => archive,
                Err(err) => {
                    issues.push(skipped(
                        QueuedMessageRecord::OBJECT,
                        queue_id,
                        format!("cannot serialize the v1 queued message: {err}"),
                    ));
                    continue;
                }
            };
            let message = archiver.into_inner();
            if let Some(current) = queued_message(&current, queue_id)? {
                release(&mut batch.batch, queue_id, &current);
            }
            reserve(&mut batch.batch, queue_id, &message);
            let weight = archive.len() as u64;
            batch.batch.set(message_key(queue_id), archive);
            batch.record_done(weight);
        }
        batch.commit(&self.store).await?;
        Ok(issues)
    }
}

pub(super) fn delete_queued(
    batch: &mut BatchBuilder,
    current: &Prefetched,
    queue_id: u64,
) -> model::Result<bool> {
    let Some(message) = queued_message(current, queue_id)? else {
        return Ok(false);
    };
    release(batch, queue_id, &message);
    batch.clear(message_key(queue_id));
    Ok(true)
}

fn queued_message(current: &Prefetched, queue_id: u64) -> model::Result<Option<Message>> {
    current
        .get::<Archive<ArchiveBytes>>(message_key(queue_id))?
        .map(|archive| archive.deserialize::<Message>().map_err(trc_error))
        .transpose()
}

pub(super) fn message_key(queue_id: u64) -> ValueClass {
    ValueClass::Queue(QueueClass::Message(queue_id))
}

fn events(queue_id: u64, message: &Message) -> impl Iterator<Item = ValueClass> + '_ {
    let events = message
        .next_events()
        .into_iter()
        .map(move |(queue_name, due)| {
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due,
                queue_id,
                queue_name: queue_name.into_inner(),
            }))
        });
    #[cfg(feature = "enterprise")]
    let events = events.chain(message.tenant_ids.iter().map(move |&tenant_id| {
        ValueClass::Queue(QueueClass::TenantMessage {
            tenant_id,
            queue_id,
        })
    }));
    events
}

fn size_delta(size: u64) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}

fn reserve(batch: &mut BatchBuilder, queue_id: u64, message: &Message) {
    for event in events(queue_id, message) {
        batch.set(event, Vec::new());
    }
    for metadata in &message.metadata {
        match metadata {
            Metadata::QueueCount { key, .. } => {
                batch.add(ValueClass::Queue(QueueClass::QuotaCount((*key).into())), 1);
            }
            Metadata::QueueSize { key, .. } => {
                batch.add(
                    ValueClass::Queue(QueueClass::QuotaSize((*key).into())),
                    size_delta(message.size),
                );
            }
            Metadata::Headers { .. } | Metadata::Submission { .. } => {}
        }
    }
    batch
        .set(
            BlobOp::Link {
                hash: message.blob_hash.clone(),
                to: BlobLink::Id { id: queue_id },
            },
            BlobLinkValue::new(message.size),
        )
        .set(
            BlobOp::Commit {
                hash: message.blob_hash.clone(),
            },
            Vec::new(),
        );
}

fn release(batch: &mut BatchBuilder, queue_id: u64, message: &Message) {
    for event in events(queue_id, message) {
        batch.clear(event);
    }
    for metadata in &message.metadata {
        match metadata {
            Metadata::QueueCount { key, .. } => {
                batch.add(ValueClass::Queue(QueueClass::QuotaCount((*key).into())), -1);
            }
            Metadata::QueueSize { key, .. } => {
                batch.add(
                    ValueClass::Queue(QueueClass::QuotaSize((*key).into())),
                    -size_delta(message.size),
                );
            }
            Metadata::Headers { .. } | Metadata::Submission { .. } => {}
        }
    }
    batch.clear(BlobOp::Link {
        hash: message.blob_hash.clone(),
        to: BlobLink::Id { id: queue_id },
    });
}

fn message(record: &QueuedMessageRecord) -> Message {
    Message {
        created: record.created,
        blob_hash: BlobHash(record.blob_hash.0),
        return_path: record.return_path.clone(),
        recipients: record.recipients.iter().map(recipient).collect(),
        received_from_ip: record.received_from_ip,
        received_via_port: record.received_via_port,
        flags: record.flags,
        env_id: record.env_id.clone(),
        priority: record.priority,
        size: record.size,
        metadata: record
            .metadata
            .iter()
            .map(|metadata| match metadata {
                QueueMetadata::QuotaSize { key, id } => Metadata::QueueSize {
                    key: key.0,
                    id: *id,
                },
                QueueMetadata::QuotaCount { key, id } => Metadata::QueueCount {
                    key: key.0,
                    id: *id,
                },
                QueueMetadata::Headers { value, id } => Metadata::Headers {
                    value: value.clone(),
                    id: *id,
                },
            })
            .collect(),
        #[cfg(feature = "enterprise")]
        tenant_ids: Box::default(),
    }
}

fn schedule(schedule: QueueSchedule) -> Schedule<u32> {
    Schedule {
        due: schedule.due,
        inner: schedule.attempt,
    }
}

fn recipient(recipient: &QueueRecipient) -> Recipient {
    Recipient {
        address: recipient.address.clone(),
        retry: schedule(recipient.retry),
        notify: schedule(recipient.notify),
        expires: match recipient.expires {
            QueueExpiry::Ttl(ttl) => V1QueueExpiry::Ttl(ttl),
            QueueExpiry::Attempts(attempts) => V1QueueExpiry::Attempts(attempts),
        },
        queue: V1QueueName::from(recipient.queue.0),
        status: status(&recipient.status),
        flags: recipient.flags,
        orcpt: recipient.orcpt.clone(),
    }
}

fn response(response: &SmtpResponse) -> Response<Box<str>> {
    Response {
        code: response.code,
        esc: response.esc,
        message: response.message.clone(),
    }
}

fn failure(failure: &DeliveryFailure) -> Box<ErrorDetails> {
    Box::new(ErrorDetails {
        entity: failure.entity.clone(),
        details: match &failure.error {
            DeliveryError::Dns(err) => Error::DnsError(err.clone()),
            DeliveryError::UnexpectedResponse {
                command,
                response: reply,
            } => Error::UnexpectedResponse(Box::new(UnexpectedResponse {
                command: command.clone(),
                response: response(reply),
            })),
            DeliveryError::Connection(err) => Error::ConnectionError(err.clone()),
            DeliveryError::Tls(err) => Error::TlsError(err.clone()),
            DeliveryError::Dane(err) => Error::DaneError(err.clone()),
            DeliveryError::MtaSts(err) => Error::MtaStsError(err.clone()),
            DeliveryError::RateLimited => Error::RateLimited,
            DeliveryError::ConcurrencyLimited => Error::ConcurrencyLimited,
            DeliveryError::Io(err) => Error::Io(err.clone()),
        },
    })
}

fn status(status: &DeliveryStatus) -> Status<HostResponse<Box<str>>, ErrorDetails> {
    match status {
        DeliveryStatus::Scheduled => Status::Scheduled,
        DeliveryStatus::Completed(host) => Status::Completed(Box::new(HostResponse {
            hostname: host.hostname.clone(),
            response: response(&host.response),
        })),
        DeliveryStatus::TemporaryFailure(details) => Status::TemporaryFailure(failure(details)),
        DeliveryStatus::PermanentFailure(details) => Status::PermanentFailure(failure(details)),
    }
}
