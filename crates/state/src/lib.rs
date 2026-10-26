/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod error;
mod sqlite;
mod store;
mod types;

pub use error::{Error, Result};
pub use sqlite::SqliteState;
pub use store::StateStore;
pub use types::{
    AccountPhase, AccountState, AccountUpdate, ContentHash, CursorMode, CursorRow, FailedDocument,
    MetaKey, PhaseCount, RegistryState, RegistryStatus, RegistryUpdate, ReportCount, ReportFilter,
    ReportRow, ReportScope, ReportsAdded, RunId, RunMode, RunRecord, RunStart, RunStatus,
};
