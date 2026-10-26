/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    mailbox::UidMailbox,
    message::{
        index::{IndexMessage, extractors::VisitText},
        ingest::ThreadInfo,
        metadata::MessageData,
    },
};
use mail_parser::{Header, HeaderName, HeaderValue, Message, parsers::fields::thread::thread_name};
use registry::schema::{
    enums::IndexDocumentType,
    structs::{Task, TaskIndexDocument, TaskStatus},
};
use store::write::{BatchBuilder, BlobOp, IndexPropertyClass, ValueClass};
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection, field::EmailField, keyword::Keyword};
use utils::cheeky_hash::CheekyHash;

pub struct ImportMessage<'x> {
    pub account_id: u32,
    pub tenant_id: Option<u32>,
    pub document_id: u32,
    pub thread_id: u32,
    pub change_id: u64,
    pub mailboxes: Vec<UidMailbox>,
    pub keywords: Vec<Keyword>,
    pub received_at: u64,
    pub message: Message<'x>,
    pub extra_headers: &'x [u8],
    pub blob_hash: BlobHash,
    pub commit_blob: bool,
}

pub trait EmailImport {
    fn import_message(&mut self, message: ImportMessage<'_>) -> trc::Result<&mut Self>;
}

impl EmailImport for BatchBuilder {
    fn import_message(&mut self, params: ImportMessage<'_>) -> trc::Result<&mut Self> {
        let extra_headers_parsed = parse_extra_headers(params.extra_headers).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Invalid extra headers")
        })?;
        let (thread_hash, message_ids) = thread_fields(&params.message);
        let data = MessageData {
            mailboxes: params.mailboxes.into_boxed_slice(),
            keywords: params.keywords.into_boxed_slice(),
            thread_id: params.thread_id,
            size: (params.message.raw_message.len() + params.extra_headers.len()) as u32,
        };
        self.with_account_id(params.account_id)
            .with_collection(Collection::Email)
            .with_document(params.document_id)
            .index_message(
                params.tenant_id,
                params.message,
                params.extra_headers.to_vec(),
                extra_headers_parsed,
                params.blob_hash.clone(),
                data,
                params.received_at,
                Some(params.change_id),
            )
            .caused_by(trc::location!())?
            .set(
                ValueClass::IndexProperty(IndexPropertyClass::Hash {
                    property: EmailField::Threading.into(),
                    hash: thread_hash,
                }),
                ThreadInfo::serialize(params.thread_id, &message_ids),
            )
            .schedule_task(Task::IndexDocument(TaskIndexDocument {
                account_id: params.account_id.into(),
                document_id: params.document_id.into(),
                document_type: IndexDocumentType::Email,
                status: TaskStatus::now(),
            }));
        if params.commit_blob {
            self.set(
                BlobOp::Commit {
                    hash: params.blob_hash,
                },
                Vec::new(),
            );
        }
        Ok(self)
    }
}

pub fn thread_fields(message: &Message<'_>) -> (CheekyHash, Vec<CheekyHash>) {
    let mut message_ids = Vec::new();
    let mut subject = "";
    for header in message.root_part().headers().iter().rev() {
        match &header.name {
            HeaderName::MessageId
            | HeaderName::InReplyTo
            | HeaderName::References
            | HeaderName::ResentMessageId => header.value.visit_text(|id| {
                if !id.is_empty() {
                    message_ids.push(CheekyHash::new(id.as_bytes()));
                }
            }),
            HeaderName::Subject if subject.is_empty() => {
                subject = thread_name(match &header.value {
                    HeaderValue::Text(text) => text.as_ref(),
                    HeaderValue::TextList(list) => list.first().map_or("", |text| text.as_ref()),
                    _ => "",
                });
            }
            _ => (),
        }
    }
    message_ids.sort_unstable();
    message_ids.dedup();
    let thread_hash = CheekyHash::new(if !subject.is_empty() { subject } else { "!" });
    (thread_hash, message_ids)
}

pub fn parse_extra_headers(bytes: &[u8]) -> Option<Vec<Header<'static>>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut headers = Vec::new();
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if line.starts_with([' ', '\t']) {
            return None;
        }
        let (name, rest) = line.split_once(':')?;
        let value = rest.trim();
        let name = name.trim();
        if name.is_empty() || !line.ends_with('\n') {
            return None;
        }
        headers.push(Header {
            name: HeaderName::parse(name.to_string())?,
            value: HeaderValue::Text(value.to_string().into()),
            offset_field: offset as u32,
            offset_start: (offset + name.len() + 1) as u32,
            offset_end: (offset + line.len()) as u32,
        });
        offset += line.len();
    }
    Some(headers)
}
