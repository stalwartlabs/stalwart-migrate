/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod common;
mod groupware;
mod mail;

use model::{Collection, Issue, IssueKind, RecordBatch, RecordPage, Severity, Subject};
use rustc_hash::FxHashMap;
use store::{Store, ValueKey, write::ValueClass};
use types::{
    collection::Collection as V1Collection,
    field::{CalendarEventField, CalendarNotificationField, ContactField, EmailField, Field},
    metadata::MetadataKinds,
};

use super::{
    dead::{self, DisplayName},
    error::{corrupt, trc_error},
    keys::{self, RawRows},
};

fn archive_class() -> ValueClass {
    ValueClass::Property(Field::ARCHIVE.into())
}

fn side_class(collection: Collection) -> Option<ValueClass> {
    match collection {
        Collection::Email => Some(ValueClass::Immutable(EmailField::Metadata.into())),
        Collection::CalendarEvent => Some(ValueClass::Property(
            CalendarEventField::Content.field().into(),
        )),
        Collection::CalendarEventNotification => Some(ValueClass::Property(
            CalendarNotificationField::Content.field().into(),
        )),
        Collection::ContactCard => Some(ValueClass::Property(ContactField::Content.field().into())),
        _ => None,
    }
}

pub(super) async fn scan(
    store: &Store,
    account_id: u32,
    collection: Collection,
    after: Option<u32>,
    limit: usize,
) -> model::Result<RecordPage> {
    let id = collection.as_u8();
    let archives = keys::scan(store, account_id, id, &archive_class(), after, limit).await?;
    let side = match (side_class(collection), archives.first(), archives.last()) {
        (Some(class), Some((first, _)), Some((last, _))) => {
            keys::range(store, account_id, id, &class, *first, *last).await?
        }
        _ => Vec::new(),
    };
    decode(store, account_id, collection, archives, side).await
}

pub(super) async fn read(
    store: &Store,
    account_id: u32,
    collection: Collection,
    ids: &[u32],
) -> model::Result<RecordPage> {
    let id = collection.as_u8();
    let archives = keys::fetch_many(store, account_id, id, &archive_class(), ids).await?;
    let side = match side_class(collection) {
        Some(class) if !archives.is_empty() => {
            let found: Vec<u32> = archives
                .iter()
                .map(|(document_id, _)| *document_id)
                .collect();
            keys::fetch_many(store, account_id, id, &class, &found).await?
        }
        _ => Vec::new(),
    };
    decode(store, account_id, collection, archives, side).await
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
                format!("cannot read the v1 object: {}", err.message()),
            ));
            Ok(None)
        }
    }
}

struct Decoder<'x> {
    store: &'x Store,
    account_id: u32,
    collection: Collection,
    issues: Vec<Issue>,
    side: FxHashMap<u32, Vec<u8>>,
}

impl Decoder<'_> {
    async fn side_of(&mut self, document_id: u32) -> model::Result<Option<Vec<u8>>> {
        if let Some(bytes) = self.side.remove(&document_id) {
            return Ok(Some(bytes));
        }
        let exists = self
            .store
            .key_exists(ValueKey::archive(
                self.account_id,
                self.collection.as_u8(),
                document_id,
            ))
            .await
            .map_err(trc_error)?;
        if exists {
            Err(corrupt(format!(
                "{} {document_id} has no content",
                self.collection
            )))
        } else {
            Ok(None)
        }
    }

    fn keep<T>(&mut self, document_id: u32, result: model::Result<T>) -> model::Result<Option<T>> {
        skip_invalid(result, self.collection, document_id, &mut self.issues)
    }

    async fn dav(
        &mut self,
        document_id: u32,
        kinds: MetadataKinds,
        display_name: DisplayName,
    ) -> model::Result<Option<dead::DavMetadata>> {
        let result = dead::read(
            self.store,
            self.account_id,
            V1Collection::from(self.collection.as_u8()),
            document_id,
            kinds,
            display_name,
        )
        .await;
        self.keep(document_id, result)
    }
}

macro_rules! plain {
    ($decoder:ident, $list:ident, $archives:ident, $convert:path) => {{
        $list.reserve($archives.len());
        for (document_id, bytes) in &$archives {
            if let Some(record) = $decoder.keep(*document_id, $convert(*document_id, bytes))? {
                $list.push(record);
            }
        }
    }};
}

macro_rules! with_side {
    ($decoder:ident, $archives:ident, $convert:path, |$document_id:ident, $decoded:ident| $body:block) => {{
        for (document_id, bytes) in &$archives {
            let $document_id = *document_id;
            let side = match $decoder.side_of($document_id).await {
                Ok(Some(side)) => side,
                Ok(None) => continue,
                Err(err) if err.is_transient() || err.is_fatal() => return Err(err),
                Err(err) => {
                    $decoder.keep::<()>($document_id, Err(err))?;
                    continue;
                }
            };
            if let Some($decoded) = $decoder.keep($document_id, $convert($document_id, bytes, &side))? $body
        }
    }};
}

macro_rules! with_dav {
    ($decoder:ident, $list:ident, $archives:ident, $convert:path, $mode:expr, |$record:ident, $dav:ident| $apply:block) => {{
        $list.reserve($archives.len());
        for (document_id, bytes) in &$archives {
            let Some((mut $record, kinds)) =
                $decoder.keep(*document_id, $convert(*document_id, bytes))?
            else {
                continue;
            };
            if !kinds.is_empty() {
                let Some($dav) = $decoder.dav(*document_id, kinds, $mode).await? else {
                    continue;
                };
                $apply
            }
            $list.push($record);
        }
    }};
}

async fn decode(
    store: &Store,
    account_id: u32,
    collection: Collection,
    archives: RawRows,
    side: RawRows,
) -> model::Result<RecordPage> {
    let mut batch = RecordBatch::new(collection)
        .ok_or_else(|| corrupt(format!("collection {collection} has no records")))?;
    let last_scanned = archives.last().map(|(document_id, _)| *document_id);
    let mut decoder = Decoder {
        store,
        account_id,
        collection,
        issues: Vec::new(),
        side: side.into_iter().collect(),
    };
    match &mut batch {
        RecordBatch::Mailbox(list) => plain!(decoder, list, archives, mail::mailbox),
        RecordBatch::Identity(list) => plain!(decoder, list, archives, mail::identity),
        RecordBatch::SieveScript(list) => plain!(decoder, list, archives, mail::sieve),
        RecordBatch::EmailSubmission(list) => plain!(decoder, list, archives, mail::submission),
        RecordBatch::Email(list) => {
            list.reserve(archives.len());
            with_side!(decoder, archives, mail::email, |document_id, record| {
                list.push(record);
            });
        }
        RecordBatch::Calendar(list) => with_dav!(
            decoder,
            list,
            archives,
            groupware::calendar,
            DisplayName::DeadProperty,
            |record, dav| {
                record.dead_properties = dav.dead;
            }
        ),
        RecordBatch::AddressBook(list) => with_dav!(
            decoder,
            list,
            archives,
            groupware::address_book,
            DisplayName::DeadProperty,
            |record, dav| {
                record.dead_properties = dav.dead;
            }
        ),
        RecordBatch::FileNode(list) => with_dav!(
            decoder,
            list,
            archives,
            groupware::file_node,
            DisplayName::Separate,
            |record, dav| {
                record.dead_properties = dav.dead;
                record.display_name = dav.display_name;
            }
        ),
        RecordBatch::CalendarEvent(list) => {
            list.reserve(archives.len());
            with_side!(
                decoder,
                archives,
                groupware::calendar_event,
                |document_id, decoded| {
                    let (mut record, kinds) = decoded;
                    if !kinds.is_empty() {
                        match decoder
                            .dav(document_id, kinds, DisplayName::DeadProperty)
                            .await?
                        {
                            Some(dav) => record.dead_properties = dav.dead,
                            None => continue,
                        }
                    }
                    list.push(record);
                }
            );
        }
        RecordBatch::CalendarEventNotification(list) => {
            list.reserve(archives.len());
            with_side!(
                decoder,
                archives,
                groupware::event_notification,
                |document_id, decoded| {
                    list.push(decoded.0);
                }
            );
        }
        RecordBatch::ContactCard(list) => {
            list.reserve(archives.len());
            with_side!(
                decoder,
                archives,
                groupware::contact,
                |document_id, decoded| {
                    let (mut record, kinds) = decoded;
                    if !kinds.is_empty() {
                        match decoder
                            .dav(document_id, kinds, DisplayName::DeadProperty)
                            .await?
                        {
                            Some(dav) => record.dead_properties = dav.dead,
                            None => continue,
                        }
                    }
                    list.push(record);
                }
            );
        }
    }
    Ok(RecordPage {
        batch,
        issues: decoder.issues,
        last_scanned,
    })
}
