/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod compare;
mod explain;
mod global;
mod log;
mod registry;

use std::{
    cmp,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use model::{
    AccountRef, BlobHash, Category, CategorySet, Collection, GlobalCategory, GlobalKey, Issue,
    IssueKind, Pointer, QuotaUsage, RecordBatch, RegistryKey, Severity, ShareNotificationRecord,
    SieveRecord, Source, Subject,
};
use roaring::RoaringBitmap;
use rustc_hash::{FxHashMap, FxHashSet};
use source_v1::is_singleton_task_id;
use state::{
    AccountPhase, AccountState, MetaKey, ReportFilter, ReportRow, ReportScope, RunId, RunMode,
    RunStatus, StateStore,
};

use super::{
    RegistryConverter, Tuning,
    context::issue_row,
    error::RunError,
    executor::for_each_bounded,
    job::{CONTAINER_COLLECTIONS, ITEM_COLLECTIONS, advance},
    retry::{RetryPolicy, retry},
};
use crate::shutdown::Shutdown;
use compare::{Outcome, compare_batches};
use explain::{Explanations, Scope, missing_registry};
pub use global::GlobalCheck;
use global::GlobalVerify;

const MAX_ROWS_PER_COLLECTION: u64 = 100;
const MAX_SHARE_ROWS: u64 = 100;
const SAMPLE_MULTIPLIER: u32 = 2_654_435_761;
const PERCENT: u32 = 100;

pub const MIN_SAMPLE_ACCOUNTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyScope {
    Sample { percent: u8 },
    Full,
}

impl VerifyScope {
    const fn rank(account_id: u32) -> u32 {
        (account_id.wrapping_mul(SAMPLE_MULTIPLIER) >> 8) % PERCENT
    }

    fn includes(self, account_id: u32) -> bool {
        match self {
            VerifyScope::Full => true,
            VerifyScope::Sample { percent } => Self::rank(account_id) < u32::from(percent),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOptions {
    pub scope: VerifyScope,
    pub min_sample: usize,
    pub categories: CategorySet,
    pub globals: GlobalCheck,
    pub tuning: Tuning,
    pub retry: RetryPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySummary {
    pub run_id: RunId,
    pub status: RunStatus,
    pub accounts_checked: u64,
    pub mismatches: u64,
    pub unexplained: u64,
}

struct Verifier<S, R, St, C> {
    source: Arc<S>,
    target: Arc<R>,
    state: Arc<St>,
    converter: Arc<C>,
    options: VerifyOptions,
    shutdown: Shutdown,
    run_id: RunId,
    accepted: Option<RunId>,
    shares_retained: bool,
    accounts_checked: AtomicU64,
    mismatches: AtomicU64,
    unexplained: AtomicU64,
}

pub async fn verify<S: Source, R: Source, St: StateStore, C: RegistryConverter>(
    source: Arc<S>,
    target: Arc<R>,
    state: Arc<St>,
    converter: Arc<C>,
    options: VerifyOptions,
    shutdown: Shutdown,
) -> Result<VerifySummary, RunError> {
    let accepted = state
        .meta(MetaKey::AcceptedErrors)
        .await?
        .and_then(|value| value.parse().ok());
    let shares_retained =
        options.globals == GlobalCheck::Final || state.meta(MetaKey::FinalDone).await?.is_some();
    retry(options.retry, || target.catch_up()).await?;
    let start = state.begin_run(RunMode::Verify).await?;
    let verifier = Arc::new(Verifier {
        accepted,
        shares_retained,
        source,
        target,
        state,
        converter,
        options,
        shutdown,
        run_id: start.run_id,
        accounts_checked: AtomicU64::new(0),
        mismatches: AtomicU64::new(0),
        unexplained: AtomicU64::new(0),
    });
    let result = verifier.clone().run().await;
    let accounts_checked = verifier.accounts_checked.load(Ordering::Relaxed);
    let mismatches = verifier.mismatches.load(Ordering::Relaxed);
    let unexplained = verifier.unexplained.load(Ordering::Relaxed);
    let status = match &result {
        Ok(()) if unexplained == 0 => RunStatus::Ok,
        Ok(()) => RunStatus::Failed,
        Err(RunError::Interrupted) => RunStatus::Interrupted,
        Err(_) => RunStatus::Failed,
    };
    let stats = serde_json::json!({
        "accounts_checked": accounts_checked,
        "mismatches": mismatches,
        "unexplained": unexplained,
    });
    verifier
        .state
        .finish_run(start.run_id, status, stats.to_string())
        .await?;
    tracing::info!(
        run_id = start.run_id,
        %status,
        accounts_checked,
        mismatches,
        unexplained,
        "verify finished"
    );
    match result {
        Ok(()) | Err(RunError::Interrupted) => Ok(VerifySummary {
            run_id: start.run_id,
            status,
            accounts_checked,
            mismatches,
            unexplained,
        }),
        Err(err) => Err(err),
    }
}

struct Findings {
    issues: Vec<Issue>,
    mismatches: u64,
    unexplained: u64,
}

impl Findings {
    fn new() -> Self {
        Findings {
            issues: Vec::new(),
            mismatches: 0,
            unexplained: 0,
        }
    }

    fn add(&mut self, issue: Issue, explained: bool) {
        self.mismatches += 1;
        if !explained {
            self.unexplained += 1;
        }
        self.issues.push(issue);
    }
}

fn mismatch(subject: Subject, message: impl Into<Box<str>>) -> Issue {
    Issue::new(Severity::Verify, IssueKind::Mismatch, subject, message)
}

fn pointer_differs<T: PartialEq>(source: &Pointer<T>, target: &Pointer<T>) -> bool {
    matches!(source, Pointer::Set(_)) && source != target
}

fn document(collection: Collection, document_id: u32) -> Subject {
    Subject::Document {
        collection,
        document_id,
    }
}

struct CollectionFindings<'x> {
    findings: &'x mut Findings,
    collection: Collection,
    reported: u64,
    hidden: u64,
}

impl CollectionFindings<'_> {
    fn missing(&mut self, document_id: u32, explained: bool) {
        self.add(
            document_id,
            "present in the source but missing in the target".into(),
            explained,
        );
    }

    fn differs(
        &mut self,
        document_id: u32,
        fields: &[&'static str],
        detail: &str,
        explained: bool,
    ) {
        self.add(
            document_id,
            format!("differs in the target: {}{detail}", fields.join(", ")).into_boxed_str(),
            explained,
        );
    }

    fn extra(&mut self, document_id: u32) {
        self.add(
            document_id,
            "present in the target but not in the source".into(),
            false,
        );
    }

    fn add(&mut self, document_id: u32, message: Box<str>, explained: bool) {
        if self.reported < MAX_ROWS_PER_COLLECTION {
            self.reported += 1;
            self.findings.add(
                mismatch(document(self.collection, document_id), message),
                explained,
            );
        } else {
            self.hidden += 1;
            self.findings.mismatches += 1;
            if !explained {
                self.findings.unexplained += 1;
            }
        }
    }

    fn finish(self) {
        if self.hidden > 0 {
            self.findings.issues.push(mismatch(
                Subject::None,
                format!(
                    "{} more {} mismatches are not listed",
                    self.hidden, self.collection
                ),
            ));
        }
    }
}

impl<S: Source, R: Source, St: StateStore, C: RegistryConverter> Verifier<S, R, St, C> {
    async fn run(self: Arc<Self>) -> Result<(), RunError> {
        self.verify_registry().await?;
        let policy = self.options.retry;
        let accounts = retry(policy, || self.source.accounts()).await?;
        let since = self.last_run_start().await?;
        let mut states: FxHashMap<u32, AccountState> = self
            .state
            .accounts()
            .await?
            .into_iter()
            .map(|account| (account.account_id, account))
            .collect();
        let source_ids: FxHashSet<u32> =
            accounts.iter().map(|account| account.account_id).collect();
        self.verify_extra_accounts(&source_ids).await?;
        let mut work: Vec<(AccountRef, Option<AccountState>)> = Vec::new();
        let mut rest: Vec<AccountRef> = Vec::new();
        for account in accounts {
            let touched = since.is_some_and(|since| {
                states
                    .get(&account.account_id)
                    .is_some_and(|state| state.updated_at >= since)
            });
            if touched || self.options.scope.includes(account.account_id) {
                work.push((account, states.remove(&account.account_id)));
            } else {
                rest.push(account);
            }
        }
        let missing = self
            .options
            .min_sample
            .saturating_sub(work.len())
            .min(rest.len());
        if missing > 0 {
            let rank =
                |account: &AccountRef| (VerifyScope::rank(account.account_id), account.account_id);
            if missing < rest.len() {
                rest.select_nth_unstable_by_key(missing, rank);
                rest.truncate(missing);
            }
            work.extend(
                rest.into_iter()
                    .map(|account| (account, states.remove(&account.account_id))),
            );
        }
        let verifier = self.clone();
        for_each_bounded(
            work,
            self.options.tuning.concurrency,
            &self.shutdown,
            move |(account, state)| {
                let verifier = verifier.clone();
                async move { verifier.verify_account(account, state).await }
            },
        )
        .await
    }

    async fn last_run_start(&self) -> Result<Option<i64>, RunError> {
        Ok(self
            .state
            .last_run_except(RunMode::Verify, self.run_id)
            .await?
            .map(|run| run.started_at))
    }

    fn record(&self, findings: &Findings) {
        self.mismatches
            .fetch_add(findings.mismatches, Ordering::Relaxed);
        self.unexplained
            .fetch_add(findings.unexplained, Ordering::Relaxed);
    }

    async fn write(&self, account_id: Option<u32>, issues: Vec<Issue>) -> Result<(), RunError> {
        if issues.is_empty() {
            return Ok(());
        }
        let rows: Vec<ReportRow> = issues
            .into_iter()
            .map(|issue| issue_row(self.run_id, account_id, issue))
            .collect();
        self.state.add_reports(rows).await?;
        Ok(())
    }

    async fn verify_registry(&self) -> Result<(), RunError> {
        let rows = self
            .state
            .reports(ReportFilter {
                scope: ReportScope::Global,
                ..ReportFilter::default()
            })
            .await?;
        let explained = missing_registry(
            &rows,
            Scope {
                since: None,
                accepted: self.accepted,
            },
        );
        let tracked = self.state.registry_objects().await?;
        let fell_back: FxHashSet<RegistryKey> =
            self.state.registry_fallbacks().await?.into_iter().collect();
        let check = registry::check(
            &*self.source,
            &*self.target,
            &*self.converter,
            self.options.categories,
            registry::RegistryHistory {
                skipped: &explained,
                tracked: &tracked,
                fell_back: &fell_back,
            },
            self.options.retry,
            self.options.tuning.batch_ops,
        )
        .await?;
        let mut findings = Findings {
            mismatches: check.issues.len() as u64,
            unexplained: check.unexplained,
            issues: check.issues,
        };
        let migrated_singletons = self.migrated_singletons().await?;
        GlobalVerify {
            source: &*self.source,
            target: &*self.target,
            converter: &*self.converter,
            check: self.options.globals,
            explained: &explained,
            migrated_singletons: &migrated_singletons,
            policy: self.options.retry,
            limit: self.options.tuning.batch_ops,
        }
        .run(self.options.categories, &mut findings)
        .await?;
        self.record(&findings);
        self.write(None, findings.issues).await
    }

    async fn migrated_singletons(&self) -> Result<FxHashSet<u64>, RunError> {
        let mut singletons = FxHashSet::default();
        if self.options.globals != GlobalCheck::Final
            || !self.options.categories.contains(Category::Tasks)
        {
            return Ok(singletons);
        }
        let limit = u32::try_from(self.options.tuning.batch_ops.max(1)).unwrap_or(u32::MAX);
        let mut after = None;
        loop {
            let keys = self
                .state
                .stale_globals(GlobalCategory::Tasks, RunId::MAX, after, limit)
                .await?;
            let Some(last) = keys.last().copied() else {
                return Ok(singletons);
            };
            singletons.extend(keys.into_iter().filter_map(|key| match key {
                GlobalKey::Task(id) if is_singleton_task_id(id) => Some(id),
                _ => None,
            }));
            after = Some(last);
        }
    }

    async fn verify_extra_accounts(&self, source_ids: &FxHashSet<u32>) -> Result<(), RunError> {
        let target = retry(self.options.retry, || self.target.stored_accounts()).await?;
        let mut findings = Findings::new();
        for account in target {
            if !source_ids.contains(&account.account_id) {
                findings.add(
                    mismatch(
                        Subject::None,
                        format!(
                            "account {} exists in the target but not in the source",
                            account.account_id
                        ),
                    ),
                    false,
                );
            }
        }
        self.record(&findings);
        self.write(None, findings.issues).await
    }

    async fn verify_account(
        &self,
        account: AccountRef,
        state: Option<AccountState>,
    ) -> Result<(), RunError> {
        let account_id = account.account_id;
        let mut findings = Findings::new();
        match self.check_account(account, state, &mut findings).await {
            Ok(()) => {}
            Err(RunError::Data(err)) if !err.is_fatal() => findings.add(
                mismatch(
                    Subject::None,
                    format!("the account could not be verified: {}", err.message()),
                ),
                false,
            ),
            Err(err) => return Err(err),
        }
        self.accounts_checked.fetch_add(1, Ordering::Relaxed);
        self.record(&findings);
        self.write(Some(account_id), findings.issues).await
    }

    async fn check_account(
        &self,
        account: AccountRef,
        state: Option<AccountState>,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let account_id = account.account_id;
        let done = state
            .as_ref()
            .is_some_and(|state| state.phase == AccountPhase::Done);
        let since = state.as_ref().and_then(|state| state.full_run);
        let checkpoint = state.and_then(|state| state.checkpoint);
        if checkpoint != Some(account.change_counter) {
            findings.add(
                mismatch(
                    Subject::None,
                    format!(
                        "account is not up to date: checkpoint {checkpoint:?}, source change counter {}",
                        account.change_counter
                    ),
                ),
                false,
            );
        }
        let explanations = Explanations::from_rows(
            &self
                .state
                .reports(ReportFilter {
                    account_id: Some(account_id),
                    ..ReportFilter::default()
                })
                .await?,
            Scope {
                since,
                accepted: self.accepted,
            },
        );
        for collection in CONTAINER_COLLECTIONS.into_iter().chain(ITEM_COLLECTIONS) {
            if !self.options.categories.contains_collection(collection)
                || !RecordBatch::has_records(collection)
            {
                continue;
            }
            self.verify_collection(account_id, collection, &explanations, findings)
                .await?;
        }
        self.verify_pointers(account_id, findings).await?;
        self.verify_shares(account_id, findings).await?;
        if let Some(checkpoint) = checkpoint {
            let bounds = retry(self.options.retry, || self.source.change_bounds(account)).await?;
            self.verify_changelog(account_id, checkpoint, &bounds, &explanations, findings)
                .await?;
            self.verify_counters(account_id, checkpoint, findings)
                .await?;
        }
        if self.options.globals == GlobalCheck::Final && done {
            self.verify_quota(account_id, findings).await?;
        }
        Ok(())
    }

    async fn verify_quota(&self, account_id: u32, findings: &mut Findings) -> Result<(), RunError> {
        let Some(QuotaUsage {
            stored,
            computed,
            objects,
        }) = retry(self.options.retry, || self.target.quota_usage(account_id)).await?
        else {
            return Ok(());
        };
        if stored != computed {
            findings.add(
                mismatch(
                    Subject::None,
                    format!(
                        "quota usage is {stored} bytes in the target, but its objects add up to {computed} bytes: the finalize quota recalculation did not run or the target changed afterwards"
                    ),
                ),
                false,
            );
        }
        for object in objects
            .iter()
            .filter(|object| object.stored != object.computed)
        {
            findings.add(
                mismatch(
                    Subject::None,
                    format!(
                        "the target counts {} {}, but holds {}: the finalize quota recalculation did not run or the target changed afterwards",
                        object.stored, object.name, object.computed
                    ),
                ),
                false,
            );
        }
        Ok(())
    }

    async fn verify_collection(
        &self,
        account_id: u32,
        collection: Collection,
        explanations: &Explanations,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let limit = self.options.tuning.batch_ops;
        let policy = self.options.retry;
        let mut found = CollectionFindings {
            findings,
            collection,
            reported: 0,
            hidden: 0,
        };
        let mut seen = RoaringBitmap::new();
        let mut ids = Vec::new();
        let mut refs = Vec::new();
        let mut hashes = Vec::new();
        let mut after = None;
        loop {
            self.check_shutdown()?;
            let page = retry(policy, || {
                self.source.scan(account_id, collection, after, limit)
            })
            .await?;
            let Some(last) = advance(&page, collection, after)? else {
                break;
            };
            after = Some(last);
            ids.clear();
            page.batch.collect_ids(&mut ids);
            seen.extend(ids.iter().copied());
            let target = retry(policy, || self.target.read(account_id, collection, &ids)).await?;
            compare_batches(
                &page.batch,
                &target.batch,
                explanations,
                |document_id, outcome, explained| match outcome {
                    Outcome::Missing => found.missing(document_id, explained),
                    Outcome::Differs { fields, detail } => {
                        found.differs(document_id, &fields, &detail, explained)
                    }
                },
            );
            if matches!(collection, Collection::Email | Collection::FileNode) {
                self.verify_blobs(&target.batch, &mut refs, &mut hashes, &mut found)
                    .await?;
            }
            if let (RecordBatch::SieveScript(source), RecordBatch::SieveScript(target)) =
                (&page.batch, &target.batch)
            {
                self.verify_scripts(source, target, &mut found).await?;
            }
        }

        let mut after = None;
        loop {
            self.check_shutdown()?;
            let page = retry(policy, || {
                self.target.scan(account_id, collection, after, limit)
            })
            .await?;
            let Some(last) = advance(&page, collection, after)? else {
                break;
            };
            after = Some(last);
            ids.clear();
            page.batch.collect_ids(&mut ids);
            for &document_id in &ids {
                if !seen.contains(document_id) {
                    found.extra(document_id);
                }
            }
        }
        found.finish();
        Ok(())
    }

    async fn verify_scripts(
        &self,
        source: &[SieveRecord],
        target: &[SieveRecord],
        found: &mut CollectionFindings<'_>,
    ) -> Result<(), RunError> {
        let policy = self.options.retry;
        for script in source {
            let Some(copy) = target
                .iter()
                .find(|copy| copy.document_id == script.document_id)
            else {
                continue;
            };
            let original = retry(policy, || self.source.read_blob(&script.blob_hash)).await?;
            let copied = retry(policy, || self.target.read_blob(&copy.blob_hash)).await?;
            let original = original.as_ref().map(|blob| script_text(blob, script));
            let copied = copied.as_ref().map(|blob| script_text(blob, copy));
            if original.is_none() || original != copied {
                found.differs(script.document_id, &["script"], "", false);
            }
        }
        Ok(())
    }

    async fn verify_pointers(
        &self,
        account_id: u32,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let policy = self.options.retry;
        let mut source = retry(policy, || self.source.pointers(account_id)).await?;
        let mut target = retry(policy, || self.target.pointers(account_id)).await?;
        source.retain_categories(self.options.categories);
        target.retain_categories(self.options.categories);
        let mut differs = Vec::new();
        if pointer_differs(&source.active_script, &target.active_script) {
            differs.push("activeScript");
        }
        if pointer_differs(&source.default_calendar, &target.default_calendar) {
            differs.push("defaultCalendar");
        }
        if pointer_differs(&source.default_address_book, &target.default_address_book) {
            differs.push("defaultAddressBook");
        }
        if pointer_differs(
            &source.identity_addresses_hash,
            &target.identity_addresses_hash,
        ) {
            differs.push("identityAddresses");
        }
        if pointer_differs(
            &source.participant_identities,
            &target.participant_identities,
        ) {
            differs.push("participantIdentities");
        }
        if pointer_differs(&source.push_subscriptions, &target.push_subscriptions) {
            differs.push("pushSubscriptions");
        }
        if !differs.is_empty() {
            findings.add(
                mismatch(
                    Subject::None,
                    format!(
                        "account pointers differ in the target: {}",
                        differs.join(", ")
                    ),
                ),
                false,
            );
        }
        Ok(())
    }

    async fn verify_shares(
        &self,
        account_id: u32,
        findings: &mut Findings,
    ) -> Result<(), RunError> {
        let policy = self.options.retry;
        let limit = self.options.tuning.batch_ops.max(1);
        let mut after = None;
        let mut listed = 0u64;
        let mut hidden = 0u64;
        let mut report = |findings: &mut Findings, id: u64, what: &str| {
            if listed < MAX_SHARE_ROWS {
                listed += 1;
                findings.add(
                    mismatch(Subject::None, format!("share notification {id} {what}")),
                    false,
                );
            } else {
                hidden += 1;
                findings.mismatches += 1;
                findings.unexplained += 1;
            }
        };
        loop {
            self.check_shutdown()?;
            let source = retry(policy, || {
                self.source.share_notifications(account_id, after, limit)
            })
            .await?;
            let target = retry(policy, || {
                self.target.share_notifications(account_id, after, limit)
            })
            .await?;
            let full_last = |page: &[ShareNotificationRecord]| {
                page.last()
                    .filter(|_| page.len() >= limit)
                    .map(|last| last.id)
            };
            let bound = match (full_last(&source), full_last(&target)) {
                (Some(source), Some(target)) => Some(source.min(target)),
                (bound @ Some(_), None) | (None, bound @ Some(_)) => bound,
                (None, None) => None,
            };
            let within =
                |record: &&ShareNotificationRecord| bound.is_none_or(|bound| record.id <= bound);
            let mut source = source.iter().filter(within).peekable();
            let mut target = target.iter().filter(within).peekable();
            loop {
                let order = match (source.peek(), target.peek()) {
                    (None, None) => break,
                    (Some(_), None) => cmp::Ordering::Less,
                    (None, Some(_)) => cmp::Ordering::Greater,
                    (Some(left), Some(right)) => left.id.cmp(&right.id),
                };
                match order {
                    cmp::Ordering::Less => {
                        if let Some(left) = source.next() {
                            report(findings, left.id, "is missing in the target");
                        }
                    }
                    cmp::Ordering::Greater => {
                        if let Some(right) = target.next()
                            && self.shares_retained
                        {
                            report(
                                findings,
                                right.id,
                                "is present in the target but not in the source",
                            );
                        }
                    }
                    cmp::Ordering::Equal => {
                        if let (Some(left), Some(right)) = (source.next(), target.next())
                            && left.payload != right.payload
                        {
                            report(findings, left.id, "differs in the target");
                        }
                    }
                }
            }
            match bound {
                Some(bound) => after = Some(bound),
                None => break,
            }
        }
        if hidden > 0 {
            findings.issues.push(mismatch(
                Subject::None,
                format!("{hidden} more share notifications differ in the target"),
            ));
        }
        Ok(())
    }

    async fn verify_blobs(
        &self,
        batch: &RecordBatch,
        refs: &mut Vec<(BlobHash, u32)>,
        hashes: &mut Vec<BlobHash>,
        found: &mut CollectionFindings<'_>,
    ) -> Result<(), RunError> {
        refs.clear();
        batch.collect_blob_refs(refs);
        if refs.is_empty() {
            return Ok(());
        }
        hashes.clear();
        hashes.extend(refs.iter().map(|(hash, _)| *hash));
        let hashes = &*hashes;
        let exist = retry(self.options.retry, || self.target.blobs_exist(hashes)).await?;
        for ((_, document_id), exists) in refs.iter().zip(exist) {
            if !exists {
                found.differs(*document_id, &["blob"], "", false);
            }
        }
        Ok(())
    }

    fn check_shutdown(&self) -> Result<(), RunError> {
        if self.shutdown.is_requested() {
            Err(RunError::Interrupted)
        } else {
            Ok(())
        }
    }
}

fn script_text<'x>(blob: &'x [u8], script: &SieveRecord) -> &'x [u8] {
    let size = usize::try_from(script.size).unwrap_or(usize::MAX);
    blob.get(..size).unwrap_or(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_selects_roughly_the_requested_share() {
        let scope = VerifyScope::Sample { percent: 10 };
        let selected = (0..100_000u32).filter(|id| scope.includes(*id)).count();
        assert!((8_000..12_000).contains(&selected), "selected {selected}");
        assert!((0..1000u32).all(|id| VerifyScope::Full.includes(id)));
        assert!(!(0..1000u32).any(|id| VerifyScope::Sample { percent: 0 }.includes(id)));
    }
}
