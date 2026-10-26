/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use model::{AccountPointers, Pointer, Source, Target};
use state::StateStore;

use super::AccountJob;
use crate::orchestrator::{RegistryConverter, error::RunError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PointerPart {
    Containers,
    ActiveScript,
    All,
}

impl PointerPart {
    fn select(self, pointers: &mut AccountPointers) {
        match self {
            PointerPart::Containers => pointers.active_script = Pointer::Keep,
            PointerPart::ActiveScript => {
                *pointers = AccountPointers {
                    active_script: pointers.active_script.take(),
                    ..AccountPointers::default()
                };
            }
            PointerPart::All => {}
        }
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> AccountJob<'_, S, T, St, C> {
    pub(super) async fn write_pointers(&mut self, part: PointerPart) -> Result<(), RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let categories = context.options.categories;
        let mut pointers = context
            .retry(|| context.source.pointers(account_id))
            .await?;
        pointers.retain_categories(categories);
        part.select(&mut pointers);
        if pointers.is_empty() {
            return Ok(());
        }
        let outcome = context
            .retry(|| context.target.write_pointers(account_id, &pointers))
            .await?;
        failpoint!("pointers");
        context.report(Some(account_id), outcome.issues).await
    }

    pub(super) async fn raise_counters(&mut self) -> Result<(), RunError> {
        let context = self.context;
        let account_id = self.account_id;
        let counters = context
            .retry(|| context.source.counters(account_id))
            .await?;
        context
            .retry(|| context.target.raise_counters(account_id, &counters))
            .await?;
        failpoint!("counters");
        Ok(())
    }
}
