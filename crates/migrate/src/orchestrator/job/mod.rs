/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::sync::Arc;

mod collection;
mod files;
mod log;
mod parallel;
mod pointers;
mod reader;

pub(crate) use reader::advance;
mod write;

use model::{
    AccountRef, Category, CategorySet, ChangeBounds, Collection, Issue, IssueKind, LogCollection,
    RecordBatch, Severity, Source, Subject, Target,
};
use state::{AccountPhase, AccountUpdate, CursorMode, CursorRow, StateStore};

use super::{RegistryConverter, context::Context, error::RunError, stats::incr};
use collection::Existing;
use pointers::PointerPart;

pub(crate) const CONTAINER_COLLECTIONS: [Collection; 3] = [
    Collection::Mailbox,
    Collection::Calendar,
    Collection::AddressBook,
];

pub(crate) const ITEM_COLLECTIONS: [Collection; 8] = [
    Collection::FileNode,
    Collection::Identity,
    Collection::SieveScript,
    Collection::Email,
    Collection::EmailSubmission,
    Collection::CalendarEvent,
    Collection::CalendarEventNotification,
    Collection::ContactCard,
];

pub(crate) const ACCOUNT_CATEGORIES: [Category; 8] = [
    Category::Principals,
    Category::Mail,
    Category::Calendars,
    Category::Contacts,
    Category::Files,
    Category::Sieve,
    Category::Identities,
    Category::PushSubscriptions,
];

pub(crate) fn account_categories(categories: CategorySet) -> CategorySet {
    categories.intersection(ACCOUNT_CATEGORIES.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Previous {
    pub(crate) checkpoint: u64,
    pub(crate) synced: CategorySet,
}

pub(crate) struct AccountJob<'x, S, T, St, C> {
    context: &'x Arc<Context<S, T, St, C>>,
    account_id: u32,
    counter: u64,
    bounds: ChangeBounds,
    previous: Option<Previous>,
    cursors: Vec<CursorRow>,
    ids: Vec<u32>,
}

impl<'x, S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'x, S, T, St, C> {
    pub(crate) fn new(
        context: &'x Arc<Context<S, T, St, C>>,
        account: AccountRef,
        bounds: ChangeBounds,
        previous: Option<Previous>,
    ) -> Self {
        AccountJob {
            context,
            account_id: account.account_id,
            counter: account.change_counter,
            bounds,
            previous,
            cursors: Vec::new(),
            ids: Vec::new(),
        }
    }

    fn cursor(&self, collection: u8, mode: CursorMode) -> Option<u64> {
        self.cursors
            .iter()
            .find(|cursor| cursor.collection == collection && cursor.mode == mode)
            .map(|cursor| cursor.last_id)
    }

    async fn set_cursor(
        &mut self,
        collection: u8,
        mode: CursorMode,
        last_id: u64,
    ) -> Result<(), RunError> {
        if mode == CursorMode::Checkpoint {
            self.context.source.check_unchanged()?;
        }
        if mode == CursorMode::Pending
            && self
                .cursor(collection, mode)
                .is_some_and(|pending| pending >= last_id)
        {
            return Ok(());
        }
        self.context
            .state
            .set_cursor(self.account_id, collection, mode, last_id)
            .await?;
        failpoint!("cursor", mode.as_str());
        if mode == CursorMode::Checkpoint {
            tracing::debug!(
                account_id = self.account_id,
                collection = Collection::from_u8(collection).map_or("unknown", Collection::as_str),
                code = collection,
                checkpoint = last_id,
                "collection checkpoint"
            );
        }
        match self
            .cursors
            .iter_mut()
            .find(|cursor| cursor.collection == collection && cursor.mode == mode)
        {
            Some(cursor) => cursor.last_id = last_id,
            None => self.cursors.push(CursorRow {
                collection,
                mode,
                last_id,
            }),
        }
        Ok(())
    }

    fn includes(&self, collection: Collection) -> bool {
        RecordBatch::has_records(collection)
            && self
                .context
                .options
                .categories
                .contains_collection(collection)
    }

    pub(crate) async fn full_copy(&mut self, resume: Option<u64>) -> Result<(), RunError> {
        let context = self.context;
        let full_target = match resume {
            Some(full_target) if self.counter < full_target => {
                let counter = self.counter;
                self.restart(format!(
                    "the source change counter {counter} is below the target {full_target} of the interrupted full copy; copying the account again"
                ))
                .await?;
                return Box::pin(self.full_copy(None)).await;
            }
            Some(full_target) => {
                self.cursors = context.state.cursors(self.account_id).await?;
                if let Some(message) = self.regressed_cursor() {
                    self.restart(message).await?;
                    return Box::pin(self.full_copy(None)).await;
                }
                full_target
            }
            None => {
                context
                    .state
                    .update_account(AccountUpdate::StartFull {
                        account_id: self.account_id,
                        full_target: self.counter,
                        run_id: context.run_id,
                    })
                    .await?;
                failpoint!("account.start_full");
                self.cursors.clear();
                self.previous = None;
                self.counter
            }
        };
        tracing::debug!(account_id = self.account_id, full_target, "full copy");

        for collection in CONTAINER_COLLECTIONS {
            self.copy_full_collection(collection, full_target, Existing::UpToPending)
                .await?;
        }
        self.write_pointers(PointerPart::Containers).await?;
        context
            .state
            .update_account(AccountUpdate::SetPhase {
                account_id: self.account_id,
                phase: AccountPhase::Full,
            })
            .await?;
        failpoint!("account.phase", "full");
        for collection in ITEM_COLLECTIONS {
            self.copy_full_collection(collection, full_target, Existing::UpToPending)
                .await?;
            if collection == Collection::SieveScript {
                self.write_pointers(PointerPart::ActiveScript).await?;
            }
        }
        let lagging = CONTAINER_COLLECTIONS
            .into_iter()
            .chain(ITEM_COLLECTIONS)
            .any(|collection| {
                self.includes(collection)
                    && self
                        .cursor(collection.as_u8(), CursorMode::Checkpoint)
                        .is_some_and(|checkpoint| checkpoint < self.bounds.collection(collection))
            });
        if lagging {
            if Box::pin(self.catch_up()).await? {
                incr(&context.stats.accounts_full);
            }
            return Ok(());
        }
        self.finish().await?;
        incr(&context.stats.accounts_full);
        Ok(())
    }

    pub(crate) async fn delta(&mut self) -> Result<(), RunError> {
        if self.catch_up().await? {
            incr(&self.context.stats.accounts_delta);
        }
        Ok(())
    }

    async fn restart(&mut self, message: String) -> Result<(), RunError> {
        self.context
            .report(
                Some(self.account_id),
                vec![Issue::new(
                    Severity::Warning,
                    IssueKind::Changed,
                    Subject::None,
                    message,
                )],
            )
            .await?;
        self.wipe().await
    }

    fn regressed_cursor(&self) -> Option<String> {
        self.cursors.iter().find_map(|cursor| {
            let bound = match cursor.mode {
                CursorMode::Checkpoint | CursorMode::Started => {
                    self.bounds.collection(Collection::from_u8(cursor.collection)?)
                }
                CursorMode::Log => self.bounds.log(LogCollection::from_u8(cursor.collection)?),
                _ => return None,
            };
            (cursor.last_id > bound).then(|| {
                format!(
                    "a saved {} cursor ({}) is above the source change counter {bound}; copying the account again",
                    cursor.mode, cursor.last_id
                )
            })
        })
    }

    async fn catch_up(&mut self) -> Result<bool, RunError> {
        let context = self.context;
        self.cursors = context.state.cursors(self.account_id).await?;
        if let Some(message) = self.regressed_cursor() {
            self.restart(message).await?;
            return self.full_copy(None).await.map(|()| false);
        }
        context
            .state
            .update_account(AccountUpdate::SetPhase {
                account_id: self.account_id,
                phase: AccountPhase::Delta,
            })
            .await?;
        failpoint!("account.phase", "delta");
        if self
            .cursors
            .iter()
            .any(|cursor| cursor.mode == CursorMode::Finalized)
        {
            let copied: Vec<(LogCollection, u64)> = self
                .cursors
                .iter()
                .filter(|cursor| cursor.mode == CursorMode::Log)
                .filter_map(|cursor| {
                    Some((LogCollection::from_u8(cursor.collection)?, cursor.last_id))
                })
                .collect();
            context
                .retry(|| context.target.reopen_account(self.account_id, &copied))
                .await?;
            failpoint!("account.reopen");
        }
        tracing::debug!(
            account_id = self.account_id,
            counter = self.counter,
            "delta"
        );

        for collection in CONTAINER_COLLECTIONS.into_iter().chain(ITEM_COLLECTIONS) {
            if self.includes(collection) {
                let code = collection.as_u8();
                let bound = self.bounds.collection(collection);
                let applied = match self.cursor(code, CursorMode::Checkpoint) {
                    Some(applied) => applied,
                    None => {
                        let started = match self.cursor(code, CursorMode::Started) {
                            Some(started) => started,
                            None => {
                                self.set_cursor(code, CursorMode::Started, bound).await?;
                                bound
                            }
                        };
                        self.copy_full_collection(collection, started, Existing::Always)
                            .await?;
                        started
                    }
                };
                if applied < bound {
                    if !self.apply_delta(collection, applied).await? {
                        tracing::info!(
                            account_id = self.account_id,
                            %collection,
                            applied,
                            "changelog truncated past the checkpoint; copying the account again"
                        );
                        self.wipe().await?;
                        return self.full_copy(None).await.map(|()| false);
                    }
                    self.set_cursor(code, CursorMode::Checkpoint, bound).await?;
                }
            }
            match collection {
                Collection::AddressBook => self.write_pointers(PointerPart::Containers).await?,
                Collection::SieveScript => self.write_pointers(PointerPart::ActiveScript).await?,
                _ => {}
            }
        }
        self.finish().await?;
        Ok(true)
    }

    pub(crate) async fn refresh_unlogged(&mut self) -> Result<(), RunError> {
        self.cursors = self.context.state.cursors(self.account_id).await?;
        self.write_pointers(PointerPart::All).await?;
        self.copy_share_notifications().await?;
        self.raise_counters().await?;
        incr(&self.context.stats.accounts_unchanged);
        Ok(())
    }

    pub(crate) async fn wipe(&mut self) -> Result<(), RunError> {
        let context = self.context;
        let account_id = self.account_id;
        context.wipe_target_account(account_id).await?;
        failpoint!("account.wipe");
        context
            .state
            .update_account(AccountUpdate::Wiped {
                account_id,
                run_id: context.run_id,
            })
            .await?;
        failpoint!("account.wiped");
        self.cursors.clear();
        self.previous = None;
        incr(&context.stats.accounts_wiped);
        Ok(())
    }

    async fn copy_full_collection(
        &mut self,
        collection: Collection,
        full_target: u64,
        existing: Existing,
    ) -> Result<(), RunError> {
        let code = collection.as_u8();
        if !self.includes(collection) || self.cursor(code, CursorMode::Checkpoint).is_some() {
            return Ok(());
        }
        let checkpoint = match self.cursor(code, CursorMode::Started) {
            Some(started) => started,
            None => {
                let started = full_target.min(self.bounds.collection(collection));
                if started != full_target {
                    self.set_cursor(code, CursorMode::Started, started).await?;
                }
                started
            }
        };
        if collection == Collection::FileNode {
            self.copy_file_tree(existing).await?;
        } else {
            self.scan_collection(collection, collection::ScanFilter::All, existing)
                .await?;
        }
        self.set_cursor(code, CursorMode::Checkpoint, checkpoint)
            .await
    }

    async fn finish(&mut self) -> Result<(), RunError> {
        let context = self.context;
        let checkpoint = self.counter;
        self.copy_log().await?;
        self.copy_share_notifications().await?;
        self.raise_counters().await?;
        let included = account_categories(context.options.categories);
        context.source.check_unchanged()?;
        let synced = match self.previous {
            Some(previous) if previous.checkpoint == checkpoint => included.union(previous.synced),
            _ => included,
        };
        context
            .state
            .update_account(AccountUpdate::Complete {
                account_id: self.account_id,
                checkpoint,
                synced,
            })
            .await?;
        failpoint!("account.complete");
        tracing::info!(account_id = self.account_id, checkpoint, "account done");
        Ok(())
    }
}
