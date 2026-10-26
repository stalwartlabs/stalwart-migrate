/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Io(Box<str>),
    Sqlite(Box<str>),
    Corrupt(Box<str>),
    Missing(Box<str>),
    Locked(Box<str>),
    Closed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(message) => write!(f, "state database I/O error: {message}"),
            Error::Sqlite(message) => write!(f, "state database error: {message}"),
            Error::Corrupt(message) => write!(f, "state database contains invalid data: {message}"),
            Error::Missing(message) => write!(f, "state database not found: {message}"),
            Error::Locked(message) => write!(
                f,
                "another stalwart-migrate process is using the state directory {message}"
            ),
            Error::Closed => f.write_str("state database writer has stopped"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        Error::Sqlite(err.to_string().into_boxed_str())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string().into_boxed_str())
    }
}
