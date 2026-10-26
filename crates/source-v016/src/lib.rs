/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod adapter;
mod fixture;
mod open;
mod self_check;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use adapter::{DEFAULT_REFRESH, PathRewrite, SourceConfig, V016Source, trc_error};
pub use open::{OpenError, SCHEMA_VERSION, SourceScope, StoreSchema, open_data_store};
pub use self_check::{ARCHIVED_ALIGNMENT, SelfCheckError, SelfCheckStage, self_check};

#[cfg(feature = "foundation")]
pub use open::use_external_foundationdb_network;
