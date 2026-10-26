/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{Collection as ModelCollection, Counters};
use store::{
    ValueKey,
    write::{BatchBuilder, ValueClass},
};
use types::collection::{ChangeGroup, Collection, SyncCollection};

use crate::{error::trc_error, target::V1Target};

const SYNC_COLLECTIONS: u8 = SyncCollection::MAX_CHANGE_GROUP;

pub(crate) fn v1_collection(collection: ModelCollection) -> Collection {
    Collection::from(collection.as_u8())
}

fn change_groups() -> impl Iterator<Item = ChangeGroup> {
    let mut seen = 0u32;
    (0..SYNC_COLLECTIONS).filter_map(move |value| {
        let group = SyncCollection::from(value).change_group();
        let bit = 1u32 << group.to_u8();
        (seen & bit == 0).then(|| {
            seen |= bit;
            group
        })
    })
}

impl V1Target {
    pub(crate) async fn raise(
        &self,
        batch: &mut BatchBuilder,
        key: ValueKey<ValueClass>,
        wanted: i64,
    ) -> model::Result<()> {
        let current = self
            .store
            .get_counter(key.clone())
            .await
            .map_err(trc_error)?;
        if wanted > current {
            batch
                .with_account_id(key.account_id)
                .with_collection(Collection::from(key.collection))
                .with_document(key.document_id)
                .add(key.class, wanted - current);
        }
        Ok(())
    }

    pub(crate) async fn raise_account_counters(
        &self,
        account_id: u32,
        counters: &Counters,
    ) -> model::Result<()> {
        let mut batch = BatchBuilder::new();
        let change_id = i64::try_from(counters.change_id).unwrap_or(i64::MAX);
        for group in change_groups() {
            self.raise(
                &mut batch,
                ValueKey {
                    account_id,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::ChangeId(group),
                },
                change_id,
            )
            .await?;
        }
        for collection in ModelCollection::ALL {
            if let Some(last_id) = counters.document_id(collection) {
                self.raise(
                    &mut batch,
                    ValueKey {
                        account_id,
                        collection: u8::from(v1_collection(collection)),
                        document_id: 0,
                        class: ValueClass::DocumentId,
                    },
                    i64::from(last_id),
                )
                .await?;
            }
        }
        for uid in &counters.mailbox_uids {
            self.raise(
                &mut batch,
                ValueKey {
                    account_id,
                    collection: u8::from(Collection::Mailbox),
                    document_id: uid.mailbox_id,
                    class: ValueClass::MailboxUid,
                },
                i64::from(uid.uid),
            )
            .await?;
        }
        if !batch.is_empty() {
            self.store
                .write_batch(&mut batch)
                .await
                .map_err(trc_error)?;
        }
        Ok(())
    }
}
