/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::DavName;
use model::{AclRecord, BlobHash, DavNameRecord};
use store::{
    Deserialize,
    write::{Archive, ArchiveBytes},
};
use types::{acl::AclGrant, blob_hash::BlobHash as V1BlobHash};

use crate::adapter::error::trc_error;

pub(super) fn archive(bytes: &[u8]) -> model::Result<Archive<ArchiveBytes>> {
    <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes).map_err(trc_error)
}

pub(super) fn blob_hash(hash: &V1BlobHash) -> BlobHash {
    BlobHash(hash.0)
}

pub(super) fn acls(grants: Vec<AclGrant>) -> Vec<AclRecord> {
    grants
        .into_iter()
        .map(|grant| AclRecord {
            account_id: grant.account_id,
            grants: grant.grants.bitmap,
        })
        .collect()
}

pub(super) fn dav_names(names: Vec<DavName>) -> Vec<DavNameRecord> {
    names
        .into_iter()
        .map(|name| DavNameRecord {
            name: name.name,
            parent_id: name.parent_id,
        })
        .collect()
}

pub(super) const fn stored_parent(parent_id: u32) -> Option<u32> {
    match parent_id {
        0 => None,
        id => Some(id - 1),
    }
}

#[cold]
pub(super) fn unsupported(what: impl std::fmt::Display) -> model::Error {
    model::Error::account(format!("no v0.16 equivalent: {what}"))
}
