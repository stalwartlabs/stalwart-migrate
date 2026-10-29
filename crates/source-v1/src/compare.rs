/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    icalendar::ICalendar,
    vcard::{VCard, VCardVersion},
};

const VCARD_CAPACITY: usize = 256;

pub fn same_icalendar(left: &str, right: &str) -> bool {
    match (ICalendar::parse(left), ICalendar::parse(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub fn same_vcard(left: &str, right: &str) -> bool {
    match (VCard::parse(left), VCard::parse(right)) {
        (Ok(left), Ok(right)) => left == right || same_after_write(&left, &right),
        _ => left == right,
    }
}

fn same_after_write(left: &VCard, right: &VCard) -> bool {
    let mut text = String::with_capacity(VCARD_CAPACITY);
    left.write_to(&mut text, left.version().unwrap_or(VCardVersion::V4_0))
        .is_ok()
        && VCard::parse(&text).is_ok_and(|written| written == *right)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_CARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Erika Mustermann\r\nN:Mustermann;Erika;;;;\r\nADR;TYPE=WORK:;;Hauptstr. 1;Berlin;;10115;Deutschland;\r\nEND:VCARD\r\n";

    fn written(text: &str) -> String {
        let Ok(card) = VCard::parse(text) else {
            panic!("test card does not parse");
        };
        let mut out = String::new();
        let version = card.version().unwrap_or(VCardVersion::V4_0);
        if card.write_to(&mut out, version).is_err() {
            panic!("test card does not write");
        }
        out
    }

    // A v3 card with extra N and ADR components matches its v1 serialisation, which drops them.
    #[test]
    fn legacy_card_matches_its_v1_serialisation() {
        let target = written(LEGACY_CARD);
        assert!(VCard::parse(LEGACY_CARD).ok() != VCard::parse(&target).ok());
        assert!(same_vcard(LEGACY_CARD, &target));
    }

    // A real difference is still reported after the v1 serialisation.
    #[test]
    fn legacy_card_with_other_content_differs() {
        let target = written(&LEGACY_CARD.replace("FN:Erika", "FN:Max"));
        assert!(!same_vcard(LEGACY_CARD, &target));
    }
}
