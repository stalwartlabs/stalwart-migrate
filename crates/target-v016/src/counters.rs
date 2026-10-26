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
use types::{collection::Collection, field::MailboxField};

use crate::{error::trc_error, target::V016Target};

pub(crate) fn v016_collection(collection: ModelCollection) -> Collection {
    Collection::from(collection.as_u8())
}

pub(crate) fn change_id_key(account_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: 0,
        document_id: 0,
        class: ValueClass::ChangeId,
    }
}

impl V016Target {
    async fn raise(
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
        self.raise(
            &mut batch,
            change_id_key(account_id),
            i64::try_from(counters.change_id).unwrap_or(i64::MAX),
        )
        .await?;
        for collection in ModelCollection::ALL {
            if let Some(last_id) = counters.document_id(collection) {
                self.raise(
                    &mut batch,
                    ValueKey {
                        account_id,
                        collection: u8::from(v016_collection(collection)),
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
                ValueKey::property(
                    account_id,
                    Collection::Mailbox,
                    uid.mailbox_id,
                    MailboxField::UidCounter,
                ),
                i64::from(uid.uid),
            )
            .await?;
        }
        self.commit(batch).await
    }
}
