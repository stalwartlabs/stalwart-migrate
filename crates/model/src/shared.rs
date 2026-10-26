/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SharedDeletes {
    #[default]
    Forbid,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedService {
    SearchIndex,
    BlobStore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedDeletion {
    pub service: SharedService,
    pub account_id: u32,
    pub what: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedOverwrite {
    pub service: SharedService,
    pub what: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SharedPlan {
    pub deletions: Vec<SharedDeletion>,
    pub overwrites: Vec<SharedOverwrite>,
}

impl SharedPlan {
    pub fn is_empty(&self) -> bool {
        self.deletions.is_empty() && self.overwrites.is_empty()
    }
}

impl fmt::Display for SharedService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SharedService::SearchIndex => "search index",
            SharedService::BlobStore => "blob store",
        })
    }
}

impl fmt::Display for SharedDeletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of account {}: {}",
            self.service, self.account_id, self.what
        )
    }
}
