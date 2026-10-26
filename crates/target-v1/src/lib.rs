/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod changelog;
mod claim;
mod counters;
mod dead;
mod error;
mod failpoint;
#[cfg(feature = "foundation")]
mod fdb_probe;
mod finalize;
mod fixture;
mod global;
mod groupware;
mod mail;
mod objects;
mod owned;
mod paths;
mod pointers;
mod precheck;
mod prefetch;
mod registry_blob;
mod registry_io;
mod self_check;
mod store_stage;
mod target;
mod target_impl;
mod wipe;
mod writer;

pub use paths::PathRewrite;
pub use self_check::{ARCHIVED_ALIGNMENT, SelfCheckError, SelfCheckStage, self_check};
pub use target::{TargetConfig, V1Target};

#[cfg(feature = "foundation")]
pub fn boot_foundationdb_network() -> Result<(), String> {
    store::backend::foundationdb::FdbStore::boot_network()
}
