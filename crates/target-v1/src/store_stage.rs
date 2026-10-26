/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::DATABASE_SCHEMA_VERSION;
use model::{Edition, TargetProbe};
use store::{
    IterateParams, SerializeInfallible, Store, Subspace,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, key::SystemKind},
};

use crate::{
    error::{fatal, trc_error},
    target::V1Target,
};

const MAX_KEY_PROBE: usize = 512;

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;

fn schema_key() -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: Subspace::System,
        key: vec![SystemKind::SchemaVersion as u8],
    }
}

pub(crate) async fn probe(
    store: &Store,
    present: impl Fn(Subspace) -> bool,
) -> model::Result<TargetProbe> {
    if present(Subspace::System)
        && let Some(schema_version) = store
            .get_value::<u32>(schema_key())
            .await
            .map_err(trc_error)?
    {
        return Ok(TargetProbe::Initialized {
            schema_version: u64::from(schema_version),
        });
    }
    for subspace in Subspace::ALL
        .iter()
        .copied()
        .filter(|subspace| !subspace.is_internal_fts() && present(*subspace))
    {
        if has_rows(store, subspace).await? {
            return Ok(TargetProbe::Foreign);
        }
    }
    Ok(TargetProbe::Empty)
}

async fn has_rows(store: &Store, subspace: Subspace) -> model::Result<bool> {
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

impl V1Target {
    pub(crate) async fn probe_opened_store(&self) -> model::Result<TargetProbe> {
        probe(&self.store, |_| true).await
    }

    pub(crate) async fn prepare(&self, edition: Edition) -> model::Result<()> {
        if edition != EDITION {
            return Err(fatal(format!(
                "this build writes {} v1 stores, the run asks for {}",
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
            Some(DATABASE_SCHEMA_VERSION) => Ok(()),
            Some(other) => Err(fatal(format!(
                "the target holds schema version {other:#x}, this build writes {DATABASE_SCHEMA_VERSION:#x}"
            ))),
            None => {
                let mut batch = BatchBuilder::new();
                batch.set(
                    ValueClass::Any(AnyClass {
                        subspace: Subspace::System,
                        key: vec![SystemKind::SchemaVersion as u8],
                    }),
                    DATABASE_SCHEMA_VERSION.serialize(),
                );
                self.add_claim(&mut batch);
                self.store
                    .write_batch(&mut batch)
                    .await
                    .map(|_| ())
                    .map_err(trc_error)
            }
        }
    }
}
