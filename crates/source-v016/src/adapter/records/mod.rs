/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod common;
mod groupware;
mod mail;

use model::{Collection, Issue, IssueKind, RecordBatch, RecordPage, Severity, Subject};
use store::{
    Store,
    write::{AlignedBytes, Archive},
};
use types::field::{EmailField, Field};

use super::{
    error::corrupt,
    error::trc_error,
    keys::{
        ArchiveResult, archive_key, fetch_many, get_property, scan_archives, scan_property_archives,
    },
};

pub(super) async fn scan(
    store: &Store,
    account_id: u32,
    collection: Collection,
    after: Option<u32>,
    limit: usize,
) -> model::Result<RecordPage> {
    let archives = scan_archives(store, account_id, collection.as_u8(), after, limit).await?;
    let metadata = match (collection, archives.first(), archives.last()) {
        (Collection::Email, Some((first, _)), Some((last, _))) => Some(
            scan_property_archives(
                store,
                account_id,
                Collection::Email.as_u8(),
                EmailField::Metadata.into(),
                *first,
                *last,
            )
            .await?,
        ),
        _ => None,
    };
    decode(store, account_id, collection, archives, metadata).await
}

pub(super) async fn read(
    store: &Store,
    account_id: u32,
    collection: Collection,
    ids: &[u32],
) -> model::Result<RecordPage> {
    let archives = fetch_many(
        store,
        account_id,
        collection.as_u8(),
        Field::ARCHIVE.into(),
        ids,
    )
    .await?;
    let metadata = if collection == Collection::Email && !archives.is_empty() {
        let found: Vec<u32> = archives
            .iter()
            .map(|(document_id, _)| *document_id)
            .collect();
        Some(
            fetch_many(
                store,
                account_id,
                collection.as_u8(),
                EmailField::Metadata.into(),
                &found,
            )
            .await?,
        )
    } else {
        None
    };
    decode(store, account_id, collection, archives, metadata).await
}

macro_rules! decode_each {
    ($list:ident, $archives:ident, $issues:ident, $collection:ident, $convert:path) => {{
        $list.reserve($archives.len());
        for (document_id, archive) in &$archives {
            if let Some(record) = skip_invalid(
                archive
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|archive| $convert(*document_id, archive)),
                $collection,
                *document_id,
                &mut $issues,
            )? {
                $list.push(record);
            }
        }
    }};
}

fn skip_invalid<T>(
    result: model::Result<T>,
    collection: Collection,
    document_id: u32,
    issues: &mut Vec<Issue>,
) -> model::Result<Option<T>> {
    match result {
        Ok(record) => Ok(Some(record)),
        Err(err) if err.is_transient() || err.is_fatal() => Err(err),
        Err(err) => {
            issues.push(Issue::new(
                Severity::Error,
                IssueKind::Skipped,
                Subject::Document {
                    collection,
                    document_id,
                },
                format!("cannot read the v0.16 object: {}", err.message()),
            ));
            Ok(None)
        }
    }
}

async fn decode(
    store: &Store,
    account_id: u32,
    collection: Collection,
    archives: Vec<(u32, ArchiveResult)>,
    metadata: Option<Vec<(u32, ArchiveResult)>>,
) -> model::Result<RecordPage> {
    let mut batch = RecordBatch::new(collection)
        .ok_or_else(|| corrupt(format!("collection {collection} has no records")))?;
    let mut issues = Vec::new();
    let last_scanned = archives.last().map(|(document_id, _)| *document_id);
    match &mut batch {
        RecordBatch::Mailbox(list) => {
            decode_each!(list, archives, issues, collection, mail::mailbox)
        }
        RecordBatch::Identity(list) => {
            decode_each!(list, archives, issues, collection, mail::identity)
        }
        RecordBatch::SieveScript(list) => {
            decode_each!(list, archives, issues, collection, mail::sieve)
        }
        RecordBatch::EmailSubmission(list) => {
            decode_each!(list, archives, issues, collection, mail::submission)
        }
        RecordBatch::Calendar(list) => {
            decode_each!(list, archives, issues, collection, groupware::calendar)
        }
        RecordBatch::CalendarEvent(list) => {
            decode_each!(
                list,
                archives,
                issues,
                collection,
                groupware::calendar_event
            )
        }
        RecordBatch::CalendarEventNotification(list) => {
            decode_each!(
                list,
                archives,
                issues,
                collection,
                groupware::event_notification
            )
        }
        RecordBatch::AddressBook(list) => {
            decode_each!(list, archives, issues, collection, groupware::address_book)
        }
        RecordBatch::ContactCard(list) => {
            decode_each!(list, archives, issues, collection, groupware::contact)
        }
        RecordBatch::FileNode(list) => {
            decode_each!(list, archives, issues, collection, groupware::file_node)
        }
        RecordBatch::Email(list) => {
            list.reserve(archives.len());
            let mut prefetched = metadata.unwrap_or_default().into_iter().peekable();
            for (document_id, archive) in &archives {
                while prefetched
                    .peek()
                    .is_some_and(|(metadata_id, _)| metadata_id < document_id)
                {
                    prefetched.next();
                }
                let metadata =
                    match prefetched.next_if(|(metadata_id, _)| metadata_id == document_id) {
                        Some((_, metadata)) => Some(metadata),
                        None => get_property::<Archive<AlignedBytes>>(
                            store,
                            account_id,
                            Collection::Email.as_u8(),
                            *document_id,
                            EmailField::Metadata.into(),
                        )
                        .await
                        .transpose(),
                    };
                if metadata.is_none() && !archive_exists(store, account_id, *document_id).await? {
                    continue;
                }
                let record = match (archive, metadata) {
                    (Ok(archive), Some(Ok(metadata))) => {
                        mail::email(*document_id, archive, &metadata)
                    }
                    (Err(err), _) => Err(err.clone()),
                    (_, Some(Err(err))) => Err(err),
                    (Ok(_), None) => Err(corrupt(format!("email {document_id} has no metadata"))),
                };
                if let Some(record) = skip_invalid(record, collection, *document_id, &mut issues)? {
                    list.push(record);
                }
            }
        }
    }
    Ok(RecordPage {
        batch,
        issues,
        last_scanned,
    })
}

async fn archive_exists(store: &Store, account_id: u32, document_id: u32) -> model::Result<bool> {
    store
        .key_exists(archive_key(
            account_id,
            Collection::Email.as_u8(),
            document_id,
        ))
        .await
        .map_err(trc_error)
}
