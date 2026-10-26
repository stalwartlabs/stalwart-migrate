/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::DavName;
use model::{AclRecord, BlobHash, DavNameRecord, DeadPropertyRecord, DeadPropertyTag};
use types::{
    acl::AclGrant,
    blob_hash::BlobHash as V016BlobHash,
    dead_property::{DeadProperty, DeadPropertyTag as V016Tag},
};

pub(super) fn blob_hash(hash: &V016BlobHash) -> BlobHash {
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

pub(super) fn dead_properties(property: DeadProperty) -> DeadPropertyRecord {
    DeadPropertyRecord(
        property
            .0
            .into_iter()
            .map(|tag| match tag {
                V016Tag::ElementStart(element) => DeadPropertyTag::ElementStart {
                    name: element.name.into_boxed_str(),
                    attrs: element.attrs.map(String::into_boxed_str),
                },
                V016Tag::ElementEnd => DeadPropertyTag::ElementEnd,
                V016Tag::Text(text) => DeadPropertyTag::Text(text.into_boxed_str()),
            })
            .collect(),
    )
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
