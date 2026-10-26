/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::prelude::{ObjectInner, ObjectType},
    types::{datetime::UTCDateTime, id::ObjectId},
};
use store::write::{BatchBuilder, BlobLink, BlobOp, blob::BlobLinkValue};
use types::blob_hash::BlobHash;

const NO_ACCOUNT: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TemporaryLink {
    pub(crate) hash: BlobHash,
    account_id: u32,
    until: u64,
    size: u64,
}

impl TemporaryLink {
    pub(crate) const fn holds_blob(object_type: ObjectType) -> bool {
        match object_type {
            ObjectType::SpamTrainingSample => true,
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => true,
            _ => false,
        }
    }

    pub(crate) fn of(inner: &ObjectInner) -> Option<Self> {
        match inner {
            ObjectInner::SpamTrainingSample(sample) => Some(TemporaryLink {
                hash: sample.blob_id.hash.clone(),
                account_id: sample
                    .account_id
                    .map_or(NO_ACCOUNT, |account_id| account_id.document_id()),
                until: timestamp(sample.expires_at),
                size: 0,
            }),
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(item) => Some(TemporaryLink {
                hash: item.blob_id().hash.clone(),
                account_id: item.account_id().document_id(),
                until: timestamp(item.archived_until()),
                size: item.size().unwrap_or_default(),
            }),
            _ => None,
        }
    }

    fn op(&self) -> BlobOp {
        BlobOp::Link {
            hash: self.hash.clone(),
            to: BlobLink::Temporary { until: self.until },
        }
    }

    pub(crate) fn set(&self, batch: &mut BatchBuilder, object_id: ObjectId) {
        batch.with_account_id(self.account_id).set(
            self.op(),
            BlobLinkValue::new(self.size).with_object_id(object_id),
        );
    }

    pub(crate) fn clear(&self, batch: &mut BatchBuilder) {
        batch.with_account_id(self.account_id).clear(self.op());
    }
}

fn timestamp(at: UTCDateTime) -> u64 {
    u64::try_from(at.timestamp()).unwrap_or_default()
}
