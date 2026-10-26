/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::DATABASE_SCHEMA_VERSION;
use model::{Edition, TargetProbe};
use store::{
    IterateParams, SUBSPACE_ACL, SUBSPACE_BLOB_LINK, SUBSPACE_BLOBS, SUBSPACE_COUNTER,
    SUBSPACE_DELETED_ITEMS, SUBSPACE_DIRECTORY, SUBSPACE_IN_MEMORY_COUNTER,
    SUBSPACE_IN_MEMORY_VALUE, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_PROPERTY,
    SUBSPACE_QUEUE_EVENT, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_QUOTA, SUBSPACE_REGISTRY,
    SUBSPACE_REGISTRY_IDX, SUBSPACE_REGISTRY_PK, SUBSPACE_REPORT_IN, SUBSPACE_REPORT_OUT,
    SUBSPACE_SEARCH_INDEX, SUBSPACE_SPAM_SAMPLES, SUBSPACE_TASK_QUEUE, SUBSPACE_TELEMETRY_METRIC,
    SUBSPACE_TELEMETRY_SPAN, SerializeInfallible, Store,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};

use crate::{
    error::{fatal, trc_error},
    target::V016Target,
};

const MAX_KEY_PROBE: usize = 512;
pub(crate) const SCHEMA_KEY: u8 = 0;
const ROLLBACK_MARKER: [u8; 2] = [SCHEMA_KEY, u8::MAX];
const ROLLBACK_MARKER_VALUE: &[u8] = b"stalwart-migrate rollback";

pub(crate) const SUBSPACES: [u8; 23] = [
    SUBSPACE_ACL,
    SUBSPACE_TASK_QUEUE,
    SUBSPACE_INDEXES,
    SUBSPACE_BLOB_LINK,
    SUBSPACE_BLOBS,
    SUBSPACE_LOGS,
    SUBSPACE_COUNTER,
    SUBSPACE_IN_MEMORY_VALUE,
    SUBSPACE_IN_MEMORY_COUNTER,
    SUBSPACE_PROPERTY,
    SUBSPACE_REGISTRY,
    SUBSPACE_REGISTRY_IDX,
    SUBSPACE_REGISTRY_PK,
    SUBSPACE_DIRECTORY,
    SUBSPACE_QUEUE_MESSAGE,
    SUBSPACE_QUEUE_EVENT,
    SUBSPACE_QUOTA,
    SUBSPACE_REPORT_OUT,
    SUBSPACE_REPORT_IN,
    SUBSPACE_TELEMETRY_SPAN,
    SUBSPACE_TELEMETRY_METRIC,
    SUBSPACE_DELETED_ITEMS,
    SUBSPACE_SPAM_SAMPLES,
];

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;

fn schema_key() -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: SUBSPACE_PROPERTY,
        key: vec![SCHEMA_KEY],
    }
}

fn marker_key() -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: SUBSPACE_PROPERTY,
        key: ROLLBACK_MARKER.to_vec(),
    }
}

pub(crate) async fn probe(
    store: &Store,
    present: impl Fn(u8) -> bool,
) -> model::Result<TargetProbe> {
    if present(SUBSPACE_PROPERTY)
        && let Some(schema_version) = store
            .get_value::<u32>(schema_key())
            .await
            .map_err(trc_error)?
    {
        return Ok(if has_marker(store).await? {
            TargetProbe::Initialized {
                schema_version: u64::from(schema_version),
            }
        } else {
            TargetProbe::Foreign
        });
    }
    for subspace in SUBSPACES.into_iter().filter(|subspace| present(*subspace)) {
        if has_rows(store, subspace).await? {
            return Ok(TargetProbe::Foreign);
        }
    }
    Ok(TargetProbe::Empty)
}

pub(crate) fn is_store_table(name: &str) -> bool {
    match name.as_bytes() {
        [byte] => *byte == SUBSPACE_SEARCH_INDEX || SUBSPACES.contains(byte),
        name => hashify::set!(name, "s_email", "s_cal", "s_card", "s_file", "s_trace"),
    }
}

async fn has_marker(store: &Store) -> model::Result<bool> {
    store.key_exists(marker_key()).await.map_err(trc_error)
}

async fn has_rows(store: &Store, subspace: u8) -> model::Result<bool> {
    let mut found = false;
    store
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: Vec::new(),
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; MAX_KEY_PROBE],
                },
            )
            .no_values()
            .only_first(),
            |_, _| {
                found = true;
                Ok(false)
            },
        )
        .await
        .map_err(trc_error)?;
    Ok(found)
}

impl V016Target {
    pub(crate) async fn probe_store(&self) -> model::Result<TargetProbe> {
        probe(&self.store, |_| true).await
    }

    pub(crate) async fn prepare(&self, edition: Edition) -> model::Result<()> {
        if edition != EDITION {
            return Err(fatal(format!(
                "this build writes {} v0.16 stores, the run asks for {}",
                EDITION.as_str(),
                edition.as_str()
            )));
        }
        match self
            .store
            .get_value::<u32>(schema_key())
            .await
            .map_err(trc_error)?
        {
            Some(DATABASE_SCHEMA_VERSION) if has_marker(&self.store).await? => Ok(()),
            Some(DATABASE_SCHEMA_VERSION) => Err(fatal(
                "the target is an existing v0.16 store that rollback did not create; rollback writes only into a new empty store",
            )),
            Some(other) => Err(fatal(format!(
                "the target holds schema version {other}, this build writes {DATABASE_SCHEMA_VERSION}"
            ))),
            None => {
                let mut batch = BatchBuilder::new();
                batch.set(
                    ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_PROPERTY,
                        key: vec![SCHEMA_KEY],
                    }),
                    DATABASE_SCHEMA_VERSION.serialize(),
                );
                batch.set(
                    ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_PROPERTY,
                        key: ROLLBACK_MARKER.to_vec(),
                    }),
                    ROLLBACK_MARKER_VALUE.to_vec(),
                );
                self.add_claim(&mut batch);
                self.store
                    .write(batch.build_all())
                    .await
                    .map(|_| ())
                    .map_err(trc_error)
            }
        }
    }
}
