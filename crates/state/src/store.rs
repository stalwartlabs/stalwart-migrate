/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, ops::Range};

use model::{BlobHash, GlobalCategory, GlobalKey, IssueKind, RegistryKey, TelemetryKind};

use crate::{
    error::Result,
    types::{
        AccountState, AccountUpdate, CursorMode, CursorRow, FailedDocument, MetaKey, PhaseCount,
        RegistryState, RegistryUpdate, ReportCount, ReportFilter, ReportRow, ReportsAdded, RunId,
        RunMode, RunRecord, RunStart, RunStatus,
    },
};

pub trait StateStore: Send + Sync + 'static {
    fn meta(&self, key: MetaKey) -> impl Future<Output = Result<Option<String>>> + Send;

    fn set_meta(&self, key: MetaKey, value: String) -> impl Future<Output = Result<()>> + Send;

    fn remove_meta(&self, key: MetaKey) -> impl Future<Output = Result<()>> + Send;

    fn begin_run(&self, mode: RunMode) -> impl Future<Output = Result<RunStart>> + Send;

    fn finish_run(
        &self,
        run_id: RunId,
        status: RunStatus,
        stats: String,
    ) -> impl Future<Output = Result<()>> + Send;

    fn runs(&self, limit: u32) -> impl Future<Output = Result<Vec<RunRecord>>> + Send;

    fn last_run_except(
        &self,
        mode: RunMode,
        before: RunId,
    ) -> impl Future<Output = Result<Option<RunRecord>>> + Send;

    fn account(&self, account_id: u32)
    -> impl Future<Output = Result<Option<AccountState>>> + Send;

    fn accounts(&self) -> impl Future<Output = Result<Vec<AccountState>>> + Send;

    fn phase_counts(&self) -> impl Future<Output = Result<Vec<PhaseCount>>> + Send;

    fn failed_accounts(&self, limit: u32)
    -> impl Future<Output = Result<Vec<AccountState>>> + Send;

    fn update_account(&self, update: AccountUpdate) -> impl Future<Output = Result<()>> + Send;

    fn cursors(&self, account_id: u32) -> impl Future<Output = Result<Vec<CursorRow>>> + Send;

    fn set_cursor(
        &self,
        account_id: u32,
        collection: u8,
        mode: CursorMode,
        last_id: u64,
    ) -> impl Future<Output = Result<()>> + Send;

    fn registry_states(
        &self,
        object: Box<str>,
    ) -> impl Future<Output = Result<Vec<RegistryState>>> + Send;

    fn registry_objects(&self) -> impl Future<Output = Result<Vec<Box<str>>>> + Send;

    fn registry_sample(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<RegistryState>>> + Send;

    fn put_registry(
        &self,
        run_id: RunId,
        updates: Vec<RegistryUpdate>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn remove_registry(&self, keys: Vec<RegistryKey>) -> impl Future<Output = Result<()>> + Send;

    fn registry_source_json(
        &self,
        key: RegistryKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    fn set_registry_fallbacks(
        &self,
        fell_back: Vec<RegistryKey>,
        cleared: Vec<RegistryKey>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn registry_fallbacks(&self) -> impl Future<Output = Result<Vec<RegistryKey>>> + Send;

    fn set_registry_pending(
        &self,
        added: Vec<RegistryKey>,
        cleared: Vec<RegistryKey>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn registry_pending(&self) -> impl Future<Output = Result<Vec<RegistryKey>>> + Send;

    fn blobs_known(&self, hashes: Vec<BlobHash>) -> impl Future<Output = Result<Vec<bool>>> + Send;

    fn add_blobs(
        &self,
        run_id: RunId,
        blobs: Vec<(BlobHash, u64)>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn global_cursor(&self, name: Box<str>)
    -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    fn set_global_cursor(
        &self,
        name: Box<str>,
        value: Vec<u8>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn track_globals(
        &self,
        generation: RunId,
        keys: Vec<GlobalKey>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn stale_globals(
        &self,
        category: GlobalCategory,
        generation: RunId,
        after: Option<GlobalKey>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<GlobalKey>>> + Send;

    fn forget_globals(&self, keys: Vec<GlobalKey>) -> impl Future<Output = Result<()>> + Send;

    fn telemetry_seen(
        &self,
        keys: Vec<(TelemetryKind, u64)>,
    ) -> impl Future<Output = Result<Vec<bool>>> + Send;

    fn see_telemetry(
        &self,
        keys: Vec<(TelemetryKind, u64)>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn prune_telemetry(
        &self,
        kind: TelemetryKind,
        window: u64,
    ) -> impl Future<Output = Result<()>> + Send;

    fn add_reports(
        &self,
        rows: Vec<ReportRow>,
    ) -> impl Future<Output = Result<ReportsAdded>> + Send;

    fn reports(&self, filter: ReportFilter) -> impl Future<Output = Result<Vec<ReportRow>>> + Send;

    fn report_counts(
        &self,
        run_id: Option<RunId>,
    ) -> impl Future<Output = Result<Vec<ReportCount>>> + Send;

    fn failed_documents(
        &self,
        after_run: RunId,
        from: Option<FailedDocument>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<FailedDocument>>> + Send;

    fn account_errors(
        &self,
        after_run: RunId,
        kind: IssueKind,
    ) -> impl Future<Output = Result<u64>> + Send;

    fn global_errors(
        &self,
        runs: Range<RunId>,
        object: Box<str>,
    ) -> impl Future<Output = Result<u64>> + Send;
}
