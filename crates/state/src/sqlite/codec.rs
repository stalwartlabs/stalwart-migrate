/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{SystemTime, UNIX_EPOCH};

use model::{GlobalCategory, GlobalKey, ReportKind, Severity};
use rusqlite::{
    Row,
    types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
};

use crate::types::{AccountPhase, CursorMode, MetaKey, RegistryStatus, RunMode, RunStatus};

macro_rules! sql_text {
    ($($name:ident),*) => {
        $(
            impl ToSql for $name {
                fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                    Ok(ToSqlOutput::Borrowed(ValueRef::Text(self.as_str().as_bytes())))
                }
            }

            impl FromSql for $name {
                fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                    let text = value.as_str()?;
                    $name::parse(text).ok_or_else(|| invalid_text(stringify!($name), text))
                }
            }
        )*
    };
}

sql_text!(
    AccountPhase,
    CursorMode,
    MetaKey,
    RegistryStatus,
    RunMode,
    RunStatus
);

#[cold]
fn invalid_text(kind: &str, text: &str) -> FromSqlError {
    FromSqlError::Other(format!("invalid {kind} value {text:?}").into())
}

pub(super) const fn encode_u64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

pub(super) const fn decode_u64(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GlobalKeyColumns {
    pub(super) kind: i64,
    pub(super) id: i64,
}

impl GlobalKeyColumns {
    const QUEUE: i64 = 0;
    const DMARC: i64 = 1;
    const TLS: i64 = 2;
    const TASK: i64 = 3;

    pub(super) const fn kinds(category: GlobalCategory) -> Option<(i64, i64)> {
        match category {
            GlobalCategory::Queue => Some((Self::QUEUE, Self::QUEUE)),
            GlobalCategory::Reports => Some((Self::DMARC, Self::TLS)),
            GlobalCategory::Tasks => Some((Self::TASK, Self::TASK)),
            GlobalCategory::SpamModel | GlobalCategory::Telemetry => None,
        }
    }

    pub(super) const fn encode(key: GlobalKey) -> Self {
        let (kind, id) = match key {
            GlobalKey::Queue(id) => (Self::QUEUE, id),
            GlobalKey::Report(ReportKind::Dmarc, id) => (Self::DMARC, id),
            GlobalKey::Report(ReportKind::Tls, id) => (Self::TLS, id),
            GlobalKey::Task(id) => (Self::TASK, id),
        };
        GlobalKeyColumns {
            kind,
            id: encode_u64(id),
        }
    }

    pub(super) fn read(row: &Row<'_>) -> rusqlite::Result<GlobalKey> {
        let id = get_u64(row, 1)?;
        match row.get::<_, i64>(0)? {
            Self::QUEUE => Ok(GlobalKey::Queue(id)),
            Self::DMARC => Ok(GlobalKey::Report(ReportKind::Dmarc, id)),
            Self::TLS => Ok(GlobalKey::Report(ReportKind::Tls, id)),
            Self::TASK => Ok(GlobalKey::Task(id)),
            kind => Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                format!("invalid global record kind {kind}").into(),
            )),
        }
    }
}

pub(super) fn get_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    row.get::<_, i64>(index).map(decode_u64)
}

pub(super) fn get_opt_u64(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)
        .map(|value| value.map(decode_u64))
}

pub(super) fn get_u32(row: &Row<'_>, index: usize) -> rusqlite::Result<u32> {
    row.get::<_, u32>(index)
}

pub(super) fn get_severity(row: &Row<'_>, index: usize) -> rusqlite::Result<Severity> {
    let text = row.get_ref(index)?.as_str()?;
    Severity::parse(text).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            format!("invalid severity {text:?}").into(),
        )
    })
}

pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
