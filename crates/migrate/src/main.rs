/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{io, process::ExitCode};

#[cfg(target_env = "musl")]
use tikv_jemallocator::Jemalloc;

use clap::Parser;
use migrate::{
    cli::Cli,
    commands::{self, EXIT_FAILURE},
    logging::{self, Console},
    shutdown::Shutdown,
};

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(target_os = "macos")]
const OPEN_FILES_CEILING: libc::rlim_t = 10_240;
#[cfg(not(target_os = "macos"))]
const OPEN_FILES_CEILING: libc::rlim_t = 1 << 20;

fn raised_open_files(limit: libc::rlimit) -> Option<libc::rlimit> {
    let wanted = limit.rlim_max.min(OPEN_FILES_CEILING);
    (limit.rlim_cur < wanted).then_some(libc::rlimit {
        rlim_cur: wanted,
        rlim_max: limit.rlim_max,
    })
}

fn raise_open_file_limit() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    match raised_open_files(limit) {
        Some(raised) if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 => {
            Err(io::Error::last_os_error())
        }
        _ => Ok(()),
    }
}

fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("cannot start the async runtime: {err}");
            return ExitCode::from(EXIT_FAILURE);
        }
    };
    if let Err(err) = runtime.block_on(commands::run::check_state_location(&cli.command)) {
        eprintln!("{err}");
        return ExitCode::from(err.exit_code());
    }
    let prints_data = cli.command.prints_data();
    let (console, state_dir) = if prints_data {
        (Console::Stderr, None)
    } else {
        (Console::Stdout, Some(cli.command.state_dir().to_path_buf()))
    };
    if let Err(err) = logging::init(
        cli.log_format,
        cli.log_level,
        console,
        state_dir.as_deref(),
        cli.command.name(),
    ) {
        eprintln!("cannot initialize logging: {err}");
        return ExitCode::from(EXIT_FAILURE);
    }
    if let Err(err) = raise_open_file_limit() {
        tracing::warn!(error = %err, "cannot raise the open file limit");
    }

    runtime.block_on(async move {
        let shutdown = Shutdown::default();
        if let Err(err) = shutdown.listen_for_signals() {
            tracing::error!(error = %err, "cannot install signal handlers");
            return ExitCode::from(EXIT_FAILURE);
        }
        match commands::dispatch(cli.command, shutdown).await {
            Ok(code) => code,
            Err(err) => {
                tracing::error!(error = %err, "command failed");
                ExitCode::from(err.exit_code())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(rlim_cur: libc::rlim_t, rlim_max: libc::rlim_t) -> libc::rlimit {
        libc::rlimit { rlim_cur, rlim_max }
    }

    // The soft limit rises to the hard limit, stays below the ceiling, and is never lowered.
    #[test]
    fn open_file_limit_only_rises() {
        let raised = raised_open_files(limit(256, 4096)).expect("raised");
        assert_eq!((raised.rlim_cur, raised.rlim_max), (4096, 4096));
        let raised = raised_open_files(limit(1024, libc::RLIM_INFINITY)).expect("raised");
        assert_eq!(raised.rlim_cur, OPEN_FILES_CEILING);
        assert_eq!(raised.rlim_max, libc::RLIM_INFINITY);
        assert!(raised_open_files(limit(4096, 4096)).is_none());
        assert!(raised_open_files(limit(libc::RLIM_INFINITY, libc::RLIM_INFINITY)).is_none());
    }
}
