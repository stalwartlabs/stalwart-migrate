/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::import::parse_extra_headers;

// Folded continuation lines are rejected instead of being split into bogus headers.
#[test]
fn folded_extra_headers_are_rejected() {
    assert!(parse_extra_headers(b"X-Spam-Status: No,\r\n score=0.1: high\r\n").is_none());
    assert!(parse_extra_headers(b"X-A: b\r\n\tc: d\r\n").is_none());
    let headers = parse_extra_headers(b"Delivered-To: bob@example.org\r\nX-Spam-Status: No\r\n")
        .expect("parsed");
    assert_eq!(headers.len(), 2);
}
