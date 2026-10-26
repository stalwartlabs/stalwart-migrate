/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    Data(model::Error),
    State(state::Error),
    Preflight(Box<str>),
    Panic(Box<str>),
    Interrupted,
}

impl RunError {
    pub fn preflight(message: impl Into<Box<str>>) -> Self {
        RunError::Preflight(message.into())
    }

    pub const fn is_account_scoped(&self) -> bool {
        matches!(self, RunError::Data(err) if !err.is_fatal())
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Data(err) => err.fmt(f),
            RunError::State(err) => err.fmt(f),
            RunError::Preflight(message) => write!(f, "preflight check failed: {message}"),
            RunError::Panic(message) => write!(f, "worker task failed: {message}"),
            RunError::Interrupted => f.write_str("interrupted by shutdown request"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<model::Error> for RunError {
    fn from(err: model::Error) -> Self {
        RunError::Data(err)
    }
}

impl From<state::Error> for RunError {
    fn from(err: state::Error) -> Self {
        RunError::State(err)
    }
}
