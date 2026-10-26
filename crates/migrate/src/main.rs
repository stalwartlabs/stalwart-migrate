/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::process::ExitCode;

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
