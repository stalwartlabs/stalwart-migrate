/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{icalendar::ICalendar, vcard::VCard};

pub fn same_icalendar(left: &str, right: &str) -> bool {
    match (ICalendar::parse(left), ICalendar::parse(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub fn same_vcard(left: &str, right: &str) -> bool {
    match (VCard::parse(left), VCard::parse(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}
