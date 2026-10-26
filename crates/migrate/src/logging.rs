/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fs::{DirBuilder, File},
    io::IsTerminal,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::ValueEnum;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Auto,
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const fn filter(self) -> LevelFilter {
        match self {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
        }
    }
}

pub const LOG_DIR: &str = "logs";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIR_MODE: u32 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Console {
    Stdout,
    Stderr,
}

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

pub fn init(
    format: LogFormat,
    level: LogLevel,
    console: Console,
    state_dir: Option<&Path>,
    command: &str,
) -> std::io::Result<Option<PathBuf>> {
    let filter = level.filter();
    let terminal = match console {
        Console::Stdout => std::io::stdout().is_terminal(),
        Console::Stderr => std::io::stderr().is_terminal(),
    };
    let json = match format {
        LogFormat::Auto => !terminal,
        LogFormat::Text => false,
        LogFormat::Json => true,
    };
    let console_layer: BoxedLayer = match (json, console) {
        (true, Console::Stdout) => fmt::layer()
            .json()
            .with_writer(std::io::stdout)
            .with_filter(filter)
            .boxed(),
        (true, Console::Stderr) => fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_filter(filter)
            .boxed(),
        (false, Console::Stdout) => fmt::layer()
            .with_ansi(terminal)
            .with_writer(std::io::stdout)
            .with_filter(filter)
            .boxed(),
        (false, Console::Stderr) => fmt::layer()
            .with_ansi(terminal)
            .with_writer(std::io::stderr)
            .with_filter(filter)
            .boxed(),
    };

    let mut layers = vec![console_layer];
    let file_path = match state_dir {
        Some(dir) => {
            let (file, path) = open_log_file(dir, command)?;
            layers.push(
                fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_writer(Mutex::new(file))
                    .with_filter(filter)
                    .boxed(),
            );
            Some(path)
        }
        None => None,
    };

    tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .map_err(std::io::Error::other)?;
    Ok(file_path)
}

fn open_log_file(state_dir: &Path, command: &str) -> std::io::Result<(File, PathBuf)> {
    let dir = state_dir.join(LOG_DIR);
    if !dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(&dir)?;
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let path = dir.join(format!("{command}-{stamp}-{}.log", std::process::id()));
    let file = File::options()
        .create(true)
        .append(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&path)?;
    Ok((file, path))
}
