/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Transient(Box<str>),
    TooLarge(Box<str>),
    Account(Box<str>),
    Fatal(Box<str>),
}

impl Error {
    pub fn transient(message: impl Into<Box<str>>) -> Self {
        Error::Transient(message.into())
    }

    pub fn too_large(message: impl Into<Box<str>>) -> Self {
        Error::TooLarge(message.into())
    }

    pub fn account(message: impl Into<Box<str>>) -> Self {
        Error::Account(message.into())
    }

    pub fn fatal(message: impl Into<Box<str>>) -> Self {
        Error::Fatal(message.into())
    }

    pub const fn is_transient(&self) -> bool {
        matches!(self, Error::Transient(_))
    }

    pub const fn is_too_large(&self) -> bool {
        matches!(self, Error::TooLarge(_))
    }

    pub const fn is_fatal(&self) -> bool {
        matches!(self, Error::Fatal(_))
    }

    pub fn message(&self) -> &str {
        match self {
            Error::Transient(message)
            | Error::TooLarge(message)
            | Error::Account(message)
            | Error::Fatal(message) => message,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Error::Transient(_) => "transient error",
            Error::TooLarge(_) => "batch too large",
            Error::Account(_) => "account error",
            Error::Fatal(_) => "fatal error",
        };
        write!(f, "{kind}: {}", self.message())
    }
}

impl std::error::Error for Error {}
