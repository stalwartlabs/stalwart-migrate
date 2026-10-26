/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod adapters;
mod final_report;
mod format;
mod report;
pub mod run;
mod status;

use std::{fmt, process::ExitCode};

use crate::{cli::Command, orchestrator::RunError, shutdown::Shutdown};

pub const EXIT_FAILURE: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_INTERRUPTED: u8 = 130;

#[derive(Debug)]
pub enum CommandError {
    State(state::Error),
    Run(RunError),
    Io(std::io::Error),
    Usage(Box<str>),
    Adapter(Box<str>),
    Unavailable(Box<str>),
}

impl CommandError {
    pub const fn exit_code(&self) -> u8 {
        match self {
            CommandError::Usage(_) => EXIT_USAGE,
            CommandError::Run(RunError::Interrupted) => EXIT_INTERRUPTED,
            _ => EXIT_FAILURE,
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::State(err) => err.fmt(f),
            CommandError::Run(err) => err.fmt(f),
            CommandError::Io(err) => err.fmt(f),
            CommandError::Usage(message)
            | CommandError::Adapter(message)
            | CommandError::Unavailable(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<state::Error> for CommandError {
    fn from(err: state::Error) -> Self {
        CommandError::State(err)
    }
}

impl From<RunError> for CommandError {
    fn from(err: RunError) -> Self {
        CommandError::Run(err)
    }
}

impl From<std::io::Error> for CommandError {
    fn from(err: std::io::Error) -> Self {
        CommandError::Io(err)
    }
}

pub async fn dispatch(command: Command, shutdown: Shutdown) -> Result<ExitCode, CommandError> {
    match command {
        Command::Status(args) => status::status(&args).await,
        Command::Report(args) => report::report(&args).await,
        Command::Prepare(args) => run::prepare(&args, shutdown).await,
        Command::Run(args) => run::run(&args, shutdown).await,
        Command::Verify(args) => run::verify(&args, shutdown).await,
        Command::Rollback(args) => run::rollback(&args, shutdown).await,
    }
}
