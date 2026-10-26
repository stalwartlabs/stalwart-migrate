/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::mailbox::Mailbox;
use types::{
    acl::{Acl, AclGrant},
    keyword::Keyword,
};
use utils::map::bitmap::Bitmap;

pub const KEYWORD_COUNT: usize = 1000;

pub fn mailbox() -> Mailbox {
    Mailbox {
        name: "Fixtures/\u{dc}n\u{ef}code \u{1f4ec}".to_string(),
        parent_id: 7,
        sort_order: Some(3),
        uid_validity: 0xDEAD_BEEF,
        subscribers: vec![1, 2, 0x0102_0304],
        acls: vec![
            AclGrant {
                account_id: 7,
                grants: Bitmap::from(vec![Acl::Read, Acl::AddItems]),
            },
            AclGrant {
                account_id: 9,
                grants: Bitmap::from(vec![Acl::Read, Acl::Share, Acl::ModifyRSVP]),
            },
        ],
        flags: 0x0015,
    }
}

pub fn keywords() -> Vec<Keyword> {
    (0..KEYWORD_COUNT)
        .map(|i| match i % 5 {
            0 => Keyword::Seen,
            1 => Keyword::Flagged,
            2 => Keyword::Other(format!("$custom-keyword-{i}").into()),
            3 => Keyword::Junk,
            _ => Keyword::Other("$label/project-alpha".into()),
        })
        .collect()
}
