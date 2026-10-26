/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{num::NonZeroU32, path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum};
use model::{Category, CategorySet};

use crate::{
    logging::{LogFormat, LogLevel},
    orchestrator::{FINAL_OBSERVATION, PROGRESS_INTERVAL, RetryPolicy, Tuning, WRITE_TIMEOUT},
    paths::{Owner, PathMap, PathMapping},
};

const DEFAULT_BATCH_OPS: usize = 1000;
const DEFAULT_BATCH_BYTES: u64 = 5 * 1024 * 1024;
const DEFAULT_FDB_TXN_BYTES: u64 = 2 * 1024 * 1024;
const MIN_BLOB_CONCURRENCY: usize = 16;
const DEFAULT_ACCOUNT_SPLIT: usize = 8;
const DEFAULT_READ_AHEAD: usize = 2;
const DEFAULT_RETRY_ATTEMPTS: u32 = 10;
const DEFAULT_RETRY_BUDGET_SECS: u64 = 300;
const CONCURRENCY_PER_CPU: usize = 4;

#[derive(Debug, Parser)]
#[command(
    name = "stalwart-migrate",
    version,
    about = "Migrate a Stalwart v0.16 deployment to v1.0"
)]
pub struct Cli {
    #[arg(help = "Log format: auto (text on a terminal, JSON lines otherwise), text or json", long, value_enum, default_value_t = LogFormat::Auto, global = true)]
    pub log_format: LogFormat,

    #[arg(help = "Minimum level of the log messages", long, value_enum, default_value_t = LogLevel::Info, global = true)]
    pub log_level: LogLevel,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Review the v0.16 settings interactively and record the answers")]
    Prepare(PrepareArgs),
    #[command(about = "Copy v0.16 into v1; incremental, resumable, and final with --final")]
    Run(RunArgs),
    #[command(about = "Compare the v0.16 and v1 stores")]
    Verify(VerifyArgs),
    #[command(about = "Show the progress of the migration")]
    Status(StatusArgs),
    #[command(about = "List dropped, changed and failed items and verification results")]
    Report(ReportArgs),
    #[command(about = "Copy a v1 store into a new, empty v0.16 store")]
    Rollback(RollbackArgs),
}

impl Command {
    pub const fn name(&self) -> &'static str {
        match self {
            Command::Prepare(_) => "prepare",
            Command::Run(_) => "run",
            Command::Verify(_) => "verify",
            Command::Status(_) => "status",
            Command::Report(_) => "report",
            Command::Rollback(_) => "rollback",
        }
    }

    pub fn state_dir(&self) -> &std::path::Path {
        match self {
            Command::Prepare(args) => &args.state.state,
            Command::Run(args) => &args.state.state,
            Command::Verify(args) => &args.state.state,
            Command::Status(args) => &args.state.state,
            Command::Report(args) => &args.state.state,
            Command::Rollback(args) => &args.state.state,
        }
    }

    pub const fn prints_data(&self) -> bool {
        matches!(self, Command::Status(_) | Command::Report(_))
    }
}

#[derive(Debug, Args)]
pub struct StateArgs {
    #[arg(
        help = "State directory of this migration (or rollback); created by the first command and reused by every later one",
        long,
        env = "STALWART_MIGRATE_STATE",
        value_name = "DIR"
    )]
    pub state: PathBuf,
}

#[derive(Debug, Args)]
pub struct SourceArgs {
    #[arg(
        help = "Configuration file (config.json) that defines the source data store",
        long,
        value_name = "CONFIG"
    )]
    pub source: PathBuf,

    #[arg(
        help = "Rewrites a path prefix in the source configuration and registry, for paths that differ on this host; may be repeated",
        long = "path-map",
        value_name = "FROM=TO"
    )]
    pub path_map: Vec<PathMapping>,
}

impl SourceArgs {
    pub fn path_map(&self) -> PathMap {
        PathMap::new(self.path_map.clone())
    }
}

#[derive(Debug, Args)]
pub struct TuningArgs {
    #[arg(
        help = "Number of write slots: the maximum number of accounts copied at once and of batches in flight (default 4 per CPU)",
        long
    )]
    pub concurrency: Option<usize>,

    #[arg(help = "Maximum operations per target transaction", long, default_value_t = DEFAULT_BATCH_OPS)]
    pub batch_ops: usize,

    #[arg(help = "Maximum bytes per target transaction", long, default_value_t = DEFAULT_BATCH_BYTES)]
    pub batch_bytes: u64,

    #[arg(
        help = "Number of blobs copied in parallel when blobs are copied (default: the number of write slots, at least 16)",
        long
    )]
    pub blob_concurrency: Option<usize>,

    #[arg(
        help = "Maximum write slots one account may use at once for its emails; idle slots go to the largest accounts (1 copies every account with one writer)",
        long,
        default_value_t = DEFAULT_ACCOUNT_SPLIT
    )]
    pub account_split: usize,

    #[arg(help = "Maximum bytes per FoundationDB transaction", long, default_value_t = DEFAULT_FDB_TXN_BYTES)]
    pub fdb_txn_bytes: u64,

    #[arg(
        help = "Global rate limit on source reads, to protect a live v0.16 server",
        long
    )]
    pub max_ops_per_sec: Option<NonZeroU32>,

    #[arg(help = "Number of batches read ahead of the writes for each account", long, default_value_t = DEFAULT_READ_AHEAD)]
    pub read_ahead: usize,

    #[arg(help = "Maximum attempts for each batch on transient errors", long, default_value_t = DEFAULT_RETRY_ATTEMPTS)]
    pub retry_attempts: u32,

    #[arg(help = "Maximum time spent retrying one batch", long, default_value_t = DEFAULT_RETRY_BUDGET_SECS, value_name = "SECONDS")]
    pub retry_budget: u64,

    #[arg(help = "Minimum time one batch write may take before it fails as stuck; larger batches get at least 1 second per MB", long, hide = true, default_value_t = WRITE_TIMEOUT.as_secs(), value_name = "SECONDS")]
    pub write_timeout: u64,
}

impl TuningArgs {
    pub fn tuning(&self) -> Tuning {
        let cpus = std::thread::available_parallelism().map_or(1, |cpus| cpus.get());
        let concurrency = self
            .concurrency
            .unwrap_or(CONCURRENCY_PER_CPU * cpus)
            .max(1);
        Tuning {
            concurrency,
            batch_ops: self.batch_ops.max(1),
            batch_bytes: self.batch_bytes.max(1),
            blob_concurrency: self
                .blob_concurrency
                .unwrap_or(concurrency.max(MIN_BLOB_CONCURRENCY))
                .max(1),
            account_split: self.account_split.max(1),
            read_ahead: self.read_ahead.max(1),
            max_ops_per_sec: self.max_ops_per_sec,
        }
    }

    pub fn write_timeout(&self) -> Duration {
        Duration::from_secs(self.write_timeout.max(1))
    }

    pub fn retry(&self) -> RetryPolicy {
        RetryPolicy {
            max_attempts: self.retry_attempts.max(1),
            budget: Duration::from_secs(self.retry_budget),
            ..RetryPolicy::default()
        }
    }
}

const CATEGORY_HELP: &str = "data categories, comma separated: settings, principals, mail, calendars, contacts, files, sieve, identities, push_subscriptions, spam_samples, reports (received DMARC, TLS and ARF reports), archive, spam_model, queue (queued messages and the outbound DMARC and TLS report aggregation, final run only), tasks (final run only), telemetry";

#[derive(Debug, Args)]
pub struct CategoryArgs {
    #[arg(long, value_delimiter = ',', value_name = "CATEGORY", help = CATEGORY_HELP)]
    pub include: Vec<String>,

    #[arg(long, value_delimiter = ',', value_name = "CATEGORY", help = CATEGORY_HELP)]
    pub exclude: Vec<String>,
}

impl CategoryArgs {
    pub fn resolve(&self, base: CategorySet) -> Result<CategorySet, String> {
        let mut set = base;
        for name in &self.include {
            set.insert(parse_category(name)?);
        }
        for name in &self.exclude {
            set.remove(parse_category(name)?);
        }
        Ok(set)
    }
}

fn parse_category(name: &str) -> Result<Category, String> {
    Category::parse(name.trim()).ok_or_else(|| {
        let known = CategorySet::all().to_string();
        format!("unknown category {name:?} (known: {known})")
    })
}

#[derive(Debug, Args)]
pub struct PrepareArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    #[command(flatten)]
    pub state: StateArgs,

    #[arg(
        help = "Validate the existing answers.toml without asking; exits with status 1 while questions remain",
        long
    )]
    pub non_interactive: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    #[arg(
        help = "Configuration file (config.json) that defines the new, empty v1 data store",
        long,
        value_name = "CONFIG"
    )]
    pub target: PathBuf,

    #[arg(
        help = "Rewrites a path prefix in the target configuration and registry, for paths that differ on this host; may be repeated",
        long = "target-path-map",
        value_name = "FROM=TO"
    )]
    pub target_path_map: Vec<PathMapping>,

    #[command(flatten)]
    pub state: StateArgs,

    #[command(flatten)]
    pub tuning: TuningArgs,

    #[command(flatten)]
    pub categories: CategoryArgs,

    #[arg(
        help = "Owner of the files and directories created for the target",
        long,
        value_name = "UID:GID"
    )]
    pub owner: Option<Owner>,

    #[arg(
        help = "Final run: v0.16 must be stopped; copies the last changes and the final-run categories, finalizes and verifies the target",
        long = "final"
    )]
    pub final_run: bool,

    #[arg(
        help = "Confirm in advance that every v0.16 node is stopped (needed without a terminal)",
        long
    )]
    pub yes: bool,

    #[arg(
        help = "Finalize even with reported errors, accepting them as losses",
        long
    )]
    pub allow_errors: bool,

    #[arg(
        help = "Run again after the migration was marked done; only while v1 has not served users",
        long
    )]
    pub force_after_final: bool,

    #[arg(
        help = "Verify every account after the final run instead of a sample",
        long
    )]
    pub verify_full: bool,

    #[arg(help = "Apply removals held by the mass-removal guard", long)]
    pub allow_mass_removal: bool,

    #[arg(long, hide = true, default_value_t = FINAL_OBSERVATION.as_secs(), value_name = "SECONDS")]
    pub final_observation: u64,

    #[arg(help = "Seconds between progress lines; 0 disables them", long, default_value_t = PROGRESS_INTERVAL.as_secs(), value_name = "SECONDS")]
    pub progress_interval: u64,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    #[arg(
        help = "Configuration file (config.json) of the v1 data store",
        long,
        value_name = "CONFIG"
    )]
    pub target: PathBuf,

    #[arg(
        help = "Rewrites a path prefix in the target configuration and registry, for paths that differ on this host; may be repeated",
        long = "target-path-map",
        value_name = "FROM=TO"
    )]
    pub target_path_map: Vec<PathMapping>,

    #[command(flatten)]
    pub state: StateArgs,

    #[arg(
        help = "Percentage of accounts to check, plus every account changed since the last run (at least 16 accounts)",
        long,
        default_value_t = 1,
        value_name = "PERCENT",
        conflicts_with = "full"
    )]
    pub sample: u8,

    #[arg(help = "Check every account and every change log row", long)]
    pub full: bool,

    #[command(flatten)]
    pub tuning: TuningArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StatusFormat {
    Text,
    Json,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[command(flatten)]
    pub state: StateArgs,

    #[arg(help = "Output format", long, value_enum, default_value_t = StatusFormat::Text)]
    pub format: StatusFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Csv,
    Json,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    #[command(flatten)]
    pub state: StateArgs,

    #[arg(help = "Only rows of this run", long)]
    pub run: Option<i64>,

    #[arg(
        help = "Only rows of this severity: info, warning, error or verify",
        long
    )]
    pub severity: Option<String>,

    #[arg(
        help = "Only rows of this kind: dropped, changed, truncated, clamped, skipped, failed or mismatch",
        long
    )]
    pub category: Option<String>,

    #[arg(help = "Only rows of this account id", long)]
    pub account: Option<u32>,

    #[arg(help = "Maximum number of rows", long)]
    pub limit: Option<u64>,

    #[arg(help = "Output format", long, value_enum, default_value_t = ReportFormat::Text)]
    pub format: ReportFormat,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    #[command(flatten)]
    pub source: SourceArgs,

    #[arg(
        help = "Configuration file (config.json) of the new, empty v0.16 data store",
        long,
        value_name = "CONFIG"
    )]
    pub target: PathBuf,

    #[command(flatten)]
    pub state: StateArgs,

    #[arg(
        help = "State directory of the forward migration, used to restore the original v0.16 settings",
        long,
        value_name = "DIR"
    )]
    pub forward_state: Option<PathBuf>,

    #[command(flatten)]
    pub tuning: TuningArgs,

    #[arg(
        help = "Owner of the files and directories created for the target",
        long,
        value_name = "UID:GID"
    )]
    pub owner: Option<Owner>,

    #[arg(
        help = "Allow changes to services shared with v1, including writing the v0.16 spam models back into a shared blob store",
        long
    )]
    pub allow_shared_deletes: bool,

    #[arg(
        help = "Leave v1's spam models in a shared blob store; v0.16 cannot load them until both keys are deleted",
        long,
        conflicts_with = "allow_shared_deletes"
    )]
    pub keep_v1_spam_model: bool,

    #[arg(
        help = "Confirm in advance that every v1 node is stopped (needed without a terminal)",
        long
    )]
    pub yes: bool,

    #[arg(
        help = "Complete the rollback even with reported errors, accepting them as losses",
        long
    )]
    pub allow_errors: bool,

    #[arg(help = "Apply removals held by the mass-removal guard", long)]
    pub allow_mass_removal: bool,

    #[arg(help = "Verify every account at the end instead of a sample", long)]
    pub verify_full: bool,

    #[arg(long, hide = true, default_value_t = FINAL_OBSERVATION.as_secs(), value_name = "SECONDS")]
    pub final_observation: u64,

    #[arg(help = "Seconds between progress lines; 0 disables them", long, default_value_t = PROGRESS_INTERVAL.as_secs(), value_name = "SECONDS")]
    pub progress_interval: u64,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    // Every subcommand and every visible flag has help text.
    #[test]
    fn every_command_and_flag_has_help() {
        let cli = Cli::command();
        let mut missing = Vec::new();
        for command in std::iter::once(&cli).chain(cli.get_subcommands()) {
            if command.get_name() != "stalwart-migrate" && command.get_about().is_none() {
                missing.push(command.get_name().to_string());
            }
            for arg in command.get_arguments() {
                if !arg.is_hide_set() && arg.get_help().is_none() {
                    missing.push(format!("{} --{}", command.get_name(), arg.get_id()));
                }
            }
        }
        assert!(missing.is_empty(), "{missing:?}");
    }

    // The blob concurrency follows the write slots above 16, and --account-split 1 is kept as given.
    #[test]
    fn blob_concurrency_follows_the_write_slots() {
        let tuning = |extra: &[&str]| {
            let mut args = vec![
                "stalwart-migrate",
                "run",
                "--source",
                "/etc/stalwart/config.json",
                "--target",
                "/etc/stalwart-v1/config.json",
                "--state",
                "/var/lib/stalwart-migrate",
            ];
            args.extend_from_slice(extra);
            let Command::Run(args) = Cli::try_parse_from(args).expect("valid arguments").command
            else {
                panic!("expected run");
            };
            args.tuning.tuning()
        };
        let wide = tuning(&["--concurrency", "64", "--account-split", "1"]);
        assert_eq!(
            (wide.concurrency, wide.blob_concurrency, wide.account_split),
            (64, 64, 1)
        );
        let narrow = tuning(&["--concurrency", "2", "--blob-concurrency", "3"]);
        assert_eq!(
            (
                narrow.concurrency,
                narrow.blob_concurrency,
                narrow.account_split
            ),
            (2, 3, 8)
        );
    }

    // The hidden --write-timeout raises the stuck-write limit and never goes below one second.
    #[test]
    fn write_timeout_flag_sets_the_minimum_limit() {
        let timeout = |value: &str| {
            let args = [
                "stalwart-migrate",
                "run",
                "--source",
                "/etc/stalwart/config.json",
                "--target",
                "/etc/stalwart-v1/config.json",
                "--state",
                "/var/lib/stalwart-migrate",
                "--write-timeout",
                value,
            ];
            let Command::Run(args) = Cli::try_parse_from(args).expect("valid arguments").command
            else {
                panic!("expected run");
            };
            args.tuning.write_timeout()
        };
        assert_eq!(timeout("3600"), Duration::from_secs(3600));
        assert_eq!(timeout("0"), Duration::from_secs(1));
    }

    #[test]
    fn parses_run_with_tuning_and_categories() {
        let cli = Cli::try_parse_from([
            "stalwart-migrate",
            "run",
            "--source",
            "/etc/stalwart/config.json",
            "--target",
            "/etc/stalwart-v1/config.json",
            "--state",
            "/var/lib/stalwart-migrate",
            "--path-map",
            "/var/lib/stalwart=/srv/stalwart",
            "--owner",
            "2000:2000",
            "--include",
            "queue,tasks",
            "--exclude",
            "files",
            "--concurrency",
            "8",
            "--final",
        ])
        .expect("valid arguments");
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert!(args.final_run);
        assert_eq!(
            args.owner,
            Some(Owner {
                uid: 2000,
                gid: 2000
            })
        );
        assert_eq!(args.tuning.tuning().concurrency, 8);
        assert_eq!(args.tuning.tuning().account_split, 8);
        assert_eq!(args.tuning.tuning().blob_concurrency, 16);
        assert_eq!(args.tuning.write_timeout(), WRITE_TIMEOUT);
        let categories = args
            .categories
            .resolve(CategorySet::defaults())
            .expect("valid categories");
        assert!(categories.contains(Category::Queue));
        assert!(categories.contains(Category::Tasks));
        assert!(!categories.contains(Category::Files));
        assert_eq!(
            args.source.path_map().apply("/var/lib/stalwart/data"),
            "/srv/stalwart/data"
        );
    }

    #[test]
    fn rejects_unknown_category() {
        let args = CategoryArgs {
            include: vec!["bogus".into()],
            exclude: Vec::new(),
        };
        assert!(args.resolve(CategorySet::defaults()).is_err());
    }

    // The category help names every category and says that internal reports belong to the queue category.
    #[test]
    fn category_help_lists_every_category() {
        for name in CategorySet::all().to_string().split(',') {
            assert!(CATEGORY_HELP.contains(name), "{name}");
        }
        assert!(
            CATEGORY_HELP.contains(
                "queue (queued messages and the outbound DMARC and TLS report aggregation"
            )
        );
    }
}
