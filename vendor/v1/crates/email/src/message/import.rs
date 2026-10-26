/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::IndexMessage,
    ingest::{ThreadInfo, thread_hash},
    messagedata::{MessageData, PendingMessageData},
    metadata::ExtraHeaders,
    thread::ThreadFields,
};
use common::{MAX_RECEIVED_AT, MessageUid};
use mail_parser::Message;
use store::write::{
    BatchBuilder, BlobOp, IndexPropertyClass, PendingId, QueueDocumentId, SearchIndex, SlotRange,
    ValueClass,
};
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection, field::EmailField, keyword::Keyword};

pub struct ImportMessage<'x> {
    pub account_id: u32,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub tenant_id: Option<u32>,
    // SPDX-SnippetEnd
    pub document_id: u32,
    pub thread_id: u32,
    pub change_id: u64,
    pub mailboxes: &'x [MessageUid],
    pub keywords: Vec<Keyword>,
    pub received_at: u64,
    pub message: &'x Message<'x>,
    pub extra_headers: &'x ExtraHeaders,
    pub blob_hash: BlobHash,
    pub commit_blob: bool,
}

pub trait EmailImport {
    fn import_message(&mut self, message: ImportMessage<'_>) -> trc::Result<&mut Self>;
}

impl EmailImport for BatchBuilder {
    fn import_message(&mut self, params: ImportMessage<'_>) -> trc::Result<&mut Self> {
        let mut keywords = 0;
        let mut keywords_extra = Vec::new();
        for keyword in params.keywords {
            match keyword.into_id() {
                Ok(id) => keywords |= 1 << id,
                Err(name) => keywords_extra.push(name),
            }
        }

        let fields = ThreadFields::scan(params.message);
        let thread_hash = thread_hash(fields.subject);
        let received_at = params.received_at.min(MAX_RECEIVED_AT);
        let data = PendingMessageData {
            data: MessageData {
                mailboxes: params.mailboxes.iter().copied().collect(),
                keywords,
                keywords_extra,
                thread_id: params.thread_id,
                size: (params.message.raw().len() + params.extra_headers.len()) as u32,
                received_at,
                sent_at: MessageData::sent_at_offset(fields.sent_at, received_at),
                change_id: 0,
            },
            uid_slots: SlotRange::default(),
            thread_slot: None,
            change_id: Some(params.change_id),
        };

        self.with_account_id(params.account_id)
            .with_collection(Collection::Email)
            .with_document(params.document_id);
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        self.index_message(
            params.tenant_id,
            params.message,
            params.extra_headers,
            params.blob_hash.clone(),
            data,
        )
        .caused_by(trc::location!())?;
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        self.index_message(
            params.message,
            params.extra_headers,
            params.blob_hash.clone(),
            data,
        )
        .caused_by(trc::location!())?;
        self.set(
            ValueClass::IndexProperty(IndexPropertyClass::Hash {
                property: EmailField::Threading.into(),
                hash: thread_hash,
            }),
            ThreadInfo {
                thread_id: PendingId::Assigned(params.thread_id),
                ref_ids: &fields.message_ids,
            },
        )
        .queue_document_index(
            SearchIndex::Email,
            params.account_id,
            QueueDocumentId::Current,
        );

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
