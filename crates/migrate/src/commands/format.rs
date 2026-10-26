/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write;

const SECONDS_PER_DAY: i64 = 86_400;

pub(super) fn utc_timestamp(out: &mut String, unix: i64) {
    let days = unix.div_euclid(SECONDS_PER_DAY);
    let seconds = unix.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    );
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

pub(super) fn csv_field(out: &mut String, value: &str) {
    if value.contains([',', '"', '\n', '\r']) {
        out.push('"');
        for part in value.split_inclusive('"') {
            out.push_str(part);
            if part.ends_with('"') {
                out.push('"');
            }
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamps() {
        let mut out = String::new();
        utc_timestamp(&mut out, 0);
        assert_eq!(out, "1970-01-01T00:00:00Z");
        out.clear();
        utc_timestamp(&mut out, 1_792_540_800 + 3661);
        assert_eq!(out, "2026-10-21T01:01:01Z");
        out.clear();
        utc_timestamp(&mut out, 951_782_400);
        assert_eq!(out, "2000-02-29T00:00:00Z");
    }

    #[test]
    fn quotes_csv_fields() {
        let mut out = String::new();
        csv_field(&mut out, "plain");
        out.push(',');
        csv_field(&mut out, "a,b");
        out.push(',');
        csv_field(&mut out, "say \"hi\"\nnow");
        assert_eq!(out, "plain,\"a,b\",\"say \"\"hi\"\"\nnow\"");
    }
}
