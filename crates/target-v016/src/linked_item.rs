/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::prelude::{ObjectInner, ObjectType, Property},
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
};
use store::{
    SerializeInfallible,
    write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass},
};
use types::blob_hash::BlobHash;

const NO_ACCOUNT: u32 = u32::MAX;

pub(crate) struct LinkedItem<'x> {
    object_type: ObjectType,
    account_id: u32,
    hash: &'x BlobHash,
    until: u64,
    pickled: Vec<u8>,
}

impl<'x> LinkedItem<'x> {
    pub(crate) fn of(inner: &'x ObjectInner) -> Option<Self> {
        match inner {
            ObjectInner::ArchivedItem(item) => Some(LinkedItem {
                object_type: ObjectType::ArchivedItem,
                account_id: item.account_id().document_id(),
                hash: &item.blob_id().hash,
                until: timestamp(item.archived_until()),
                pickled: item.to_pickled_vec(),
            }),
            ObjectInner::SpamTrainingSample(sample) => Some(LinkedItem {
                object_type: ObjectType::SpamTrainingSample,
                account_id: sample
                    .account_id
                    .map_or(NO_ACCOUNT, |account_id| account_id.document_id()),
                hash: &sample.blob_id.hash,
                until: timestamp(sample.expires_at),
                pickled: sample.to_pickled_vec(),
            }),
            _ => None,
        }
    }

    pub(crate) const fn holds_blob(object_type: ObjectType) -> bool {
        matches!(
            object_type,
            ObjectType::ArchivedItem | ObjectType::SpamTrainingSample
        )
    }

    pub(crate) fn hash(&self) -> &BlobHash {
        self.hash
    }

    fn link(&self) -> BlobOp {
        BlobOp::Link {
            hash: self.hash.clone(),
            to: BlobLink::Temporary { until: self.until },
        }
    }

    fn item_class(&self, item_id: u64) -> ValueClass {
        ValueClass::Registry(RegistryClass::Item {
            object_id: self.object_type.to_id(),
            item_id,
        })
    }

    fn index_class(&self, item_id: u64) -> ValueClass {
        ValueClass::Registry(RegistryClass::Index {
            index_id: Property::AccountId.to_id(),
            object_id: self.object_type.to_id(),
            item_id,
            key: u64::from(self.account_id).serialize(),
        })
    }

    pub(crate) fn write(self, batch: &mut BatchBuilder, item_id: u64, existing: Option<&Self>) {
        if let Some(old) = existing {
            batch.clear(old.index_class(item_id));
            if (old.account_id, old.hash, old.until) != (self.account_id, self.hash, self.until) {
                batch.with_account_id(old.account_id).clear(old.link());
            }
        }
        let index = self.index_class(item_id);
        let item = self.item_class(item_id);
        batch
            .with_account_id(self.account_id)
            .set(
                self.link(),
                ObjectId::new(self.object_type, item_id.into()).serialize(),
            )
            .set(index, Vec::new())
            .set(item, self.pickled);
    }

    pub(crate) fn delete(&self, batch: &mut BatchBuilder, item_id: u64) {
        batch
            .with_account_id(self.account_id)
            .clear(self.link())
            .clear(self.index_class(item_id))
            .clear(self.item_class(item_id));
    }
}

fn timestamp(at: UTCDateTime) -> u64 {
    u64::try_from(at.timestamp()).unwrap_or_default()
}
