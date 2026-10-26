/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod changelog;
mod claim;
mod counters;
mod error;
mod external_report;
mod failpoint;
#[cfg(feature = "foundation")]
mod fdb_probe;
mod finalize;
mod groupware;
mod isolation;
mod linked_item;
mod mail;
mod objects;
mod owned;
mod pointers;
mod precheck;
mod registry_io;
mod shared;
mod spam;
mod store_stage;
mod target;
mod target_impl;
mod wipe;
mod writer;

pub use model::{SharedDeletes, SharedDeletion, SharedService};
pub use target::{TargetConfig, V016Target};

use std::{fmt, mem::align_of};
use types::acl::ArchivedAclGrant;

pub const ARCHIVED_ALIGNMENT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfCheckError {
    pub expected: usize,
    pub found: usize,
}

pub fn self_check() -> Result<(), SelfCheckError> {
    let found = align_of::<ArchivedAclGrant>();
    if found == ARCHIVED_ALIGNMENT {
        Ok(())
    } else {
        Err(SelfCheckError {
            expected: ARCHIVED_ALIGNMENT,
            found,
        })
    }
}

impl fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "v0.16 archived types have alignment {}, expected {}: the rkyv split is broken",
            self.found, self.expected
        )
    }
}

impl std::error::Error for SelfCheckError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that the v0.16 archived types use the v0.16 rkyv layout.
    #[test]
    fn self_check_passes() {
        self_check().expect("v0.16 self-check");
    }
}
