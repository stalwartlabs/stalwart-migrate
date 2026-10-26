/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod adapter;
mod compare;
pub mod spam_archive;
#[cfg(feature = "testkit")]
pub mod testkit;

use std::{fmt, mem::align_of};
use types::acl::ArchivedAclGrant;

pub use adapter::{
    OpenError, PathRewrite, SourceConfig, V1Source, is_derived_task_id, is_singleton_task,
    is_singleton_task_id, registry_object_is_stored, singleton_task_id, trc_error,
};
pub use compare::{same_icalendar, same_vcard};

pub const ARCHIVED_ALIGNMENT: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfCheckError {
    pub expected: usize,
    pub found: usize,
}

pub const fn is_v1_schema(version: u32) -> bool {
    version & !common::DATABASE_SCHEMA_OSS_FLAG == common::DATABASE_SCHEMA_VERSION_BASE
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
            "v1 archived types have alignment {}, expected {}: the rkyv split is broken",
            self.found, self.expected
        )
    }
}

impl std::error::Error for SelfCheckError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that the v1 archived types use the v1 rkyv layout.
    // Only the v1 schema base version, with or without the OSS flag, is a v1 schema this build reads.
    #[test]
    fn only_known_v1_schema_versions_are_accepted() {
        let base = common::DATABASE_SCHEMA_VERSION_BASE;
        assert!(is_v1_schema(base));
        assert!(is_v1_schema(base | common::DATABASE_SCHEMA_OSS_FLAG));
        assert!(!is_v1_schema(base + 1));
        assert!(!is_v1_schema(0));
    }

    #[test]
    fn self_check_passes() {
        self_check().expect("v1 self-check");
    }
}
