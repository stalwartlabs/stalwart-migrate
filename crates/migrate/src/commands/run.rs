/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use mapping::{
    Answers, Direction, Mapping, Normalize, Options, PromptId, Singletons, ToolQuestions,
};
use model::{
    Category, CategorySet, Edition, RegistryEntries, RegistryId, RegistryKey, RegistryRecord,
    SharedDeletes, SharedPlan, SharedService, Target, TargetClaim,
};
use source_v1::V1Source;
use source_v016::V016Source;
use state::{MetaKey, RegistryStatus, RunStatus, SqliteState, StateStore};

use super::{
    CommandError, EXIT_FAILURE, EXIT_INTERRUPTED,
    adapters::{self, BlobOwner},
    final_report::{CUTOVER_CHECKLIST, FINAL_REPORT_FILE, write_final_report},
};
use crate::{
    cli::{CategoryArgs, Command, PrepareArgs, RollbackArgs, RunArgs, VerifyArgs},
    converter::{ForwardState, MappingConverter, Original, mapping_edition},
    orchestrator::{
        AfterFinal, BlobMode, ErrorPolicy, GlobalCheck, MIN_SAMPLE_ACCOUNTS, Orchestrator,
        RegistryConverter, RemovalPolicy, RetryPolicy, RunDirection, RunKind, RunOptions,
        RunSummary, StoreIdentity, VerifyOptions, VerifyScope, VerifySummary, read_registry,
        registry_categories,
    },
    paths::{Owner, PathMap, apply_owner, running_as_root},
    prepare::{
        ANSWERS_FILE, Confirmation, Prepare, StdTerminal, TERMINAL_REQUIRED, has_terminal,
        load_answers, source_objects, summary, write_outputs,
    },
    shutdown::Shutdown,
};

const REGISTRY_PAGE: usize = 1000;
const FINAL_CONFIRMATION: &str = "yes";
const BLOB_STORE_OBJECT: &str = "BlobStore";
const DEFAULT_BLOB_STORE: &str = "Default";
const SHARED_SPAM_MODEL_UNDECIDED: &str = "the v0.16 target shares its blob store with v1, which holds the spam model under the same keys in the v1 format, and v0.16 fails on every start while it finds that format there; pass --allow-shared-deletes to write the v0.16 model back, or --keep-v1-spam-model to leave v1's model in place";
const KEEP_V1_SPAM_MODEL: &str = "the spam model was not rolled back (--keep-v1-spam-model): v0.16 cannot load the v1 model; delete the blobs STALWART_SPAM_CLASSIFIER_MODEL.lz4 and STALWART_SPAM_TRAIN_DATA.lz4 from the blob store before starting v0.16, which then retrains";
const NOT_ROLLED_BACK_CATEGORIES: [Category; 3] =
    [Category::Queue, Category::Tasks, Category::Telemetry];
const NOT_ROLLED_BACK: &str = "queued messages, outbound report aggregation (internal DMARC and TLS reports), tasks and telemetry are not rolled back; v1 keeps delivering what is queued there";

#[cfg(feature = "enterprise")]
pub const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
pub const EDITION: Edition = Edition::Community;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterConfig {
    pub source: PathBuf,
    pub target: PathBuf,
    pub path_map: PathMap,
    pub target_path_map: PathMap,
    pub fdb_txn_bytes: u64,
    pub owner: Option<Owner>,
}

pub struct RunPlan {
    pub options: RunOptions,
    pub mapping: Mapping,
    pub answers: Answers,
    pub adapters: AdapterConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobLocation {
    DataStore,
    External,
}

impl BlobLocation {
    fn of(source: &V016Source) -> Self {
        if source.blobs_in_data_store() {
            BlobLocation::DataStore
        } else {
            BlobLocation::External
        }
    }
}

pub fn summary_exit_code(summary: &RunSummary) -> u8 {
    match summary.status {
        RunStatus::Interrupted => EXIT_INTERRUPTED,
        _ if summary.succeeded() => 0,
        _ => EXIT_FAILURE,
    }
}

pub fn mapping_options(edition: Edition, blobs: BlobLocation) -> Options {
    Options {
        edition: mapping_edition(edition),
        external_blob_store: blobs == BlobLocation::External,
        tool_questions: ToolQuestions::Ask,
        normalize: Normalize::From016x,
        singletons: Singletons::Synthesize,
    }
}

fn usage(message: impl Into<Box<str>>) -> CommandError {
    CommandError::Usage(message.into())
}

pub fn answer_categories(answers: &Answers) -> Result<CategorySet, CommandError> {
    let Some(answer) = answers.get(PromptId::Categories, None) else {
        return Ok(CategorySet::defaults());
    };
    let mut set = CategorySet::empty();
    for name in answer.strings("include") {
        set.insert(
            Category::parse(name)
                .ok_or_else(|| usage(format!("unknown category {name:?} in {ANSWERS_FILE}")))?,
        );
    }
    Ok(set)
}

pub fn answer_blob_mode(answers: &Answers) -> Option<BlobMode> {
    answers
        .get(PromptId::BlobStore, None)
        .map(|answer| match answer.str("mode") {
            Some("copy") => BlobMode::Copy,
            _ => BlobMode::Shared,
        })
}

fn blob_mode(answered: Option<BlobMode>, blobs: BlobLocation) -> BlobMode {
    match (blobs, answered) {
        (BlobLocation::External, answered) => answered.unwrap_or(BlobMode::Shared),
        (BlobLocation::DataStore, Some(BlobMode::Shared)) => {
            tracing::warn!(
                "the v0.16 blobs are stored in the data store and cannot be shared with v1; they are copied"
            );
            BlobMode::Copy
        }
        (BlobLocation::DataStore, _) => BlobMode::Copy,
    }
}

fn check_edition(answers: &Answers) -> Result<(), CommandError> {
    let expected = mapping_edition(EDITION).as_str();
    match answers
        .get(PromptId::Edition, None)
        .and_then(|answer| answer.str("edition"))
    {
        Some(answered) if answered != expected => Err(usage(format!(
            "{ANSWERS_FILE} selects the {answered} edition but this binary is the {expected} edition"
        ))),
        _ => Ok(()),
    }
}

fn resolve_categories(answers: &Answers, args: &CategoryArgs) -> Result<CategorySet, CommandError> {
    args.resolve(answer_categories(answers)?)
        .map_err(|err| usage(err.into_boxed_str()))
}

fn require_answers(state_dir: &Path) -> Result<Answers, CommandError> {
    if !state_dir.join(ANSWERS_FILE).is_file() {
        return Err(usage(format!(
            "{} not found; run prepare first",
            state_dir.join(ANSWERS_FILE).display()
        )));
    }
    load_answers(state_dir).map_err(|err| usage(err.to_string().into_boxed_str()))
}

fn load_mapping() -> Result<Mapping, CommandError> {
    Mapping::embedded().map_err(|err| CommandError::Unavailable(err.to_string().into_boxed_str()))
}

pub fn plan_run(args: &RunArgs) -> Result<RunPlan, CommandError> {
    let answers = require_answers(&args.state.state)?;
    check_edition(&answers)?;
    let kind = if args.final_run {
        RunKind::Final
    } else {
        RunKind::Incremental
    };
    let mut options = RunOptions::new(kind, EDITION);
    options.categories = resolve_categories(&answers, &args.categories)?;
    options.tuning = args.tuning.tuning();
    options.retry = args.tuning.retry();
    options.write_timeout = args.tuning.write_timeout();
    if args.allow_errors {
        options.errors = ErrorPolicy::Allow;
    }
    if args.force_after_final {
        options.after_final = AfterFinal::Force;
    }
    if args.allow_mass_removal {
        options.removals = RemovalPolicy::Allow;
    }
    if args.verify_full {
        options.final_verify = VerifyScope::Full;
    }
    options.final_observation = Duration::from_secs(args.final_observation);
    options.progress_interval =
        (args.progress_interval > 0).then(|| Duration::from_secs(args.progress_interval));
    Ok(RunPlan {
        options,
        mapping: load_mapping()?,
        answers,
        adapters: AdapterConfig {
            source: args.source.source.clone(),
            target: args.target.clone(),
            path_map: args.source.path_map(),
            target_path_map: PathMap::new(args.target_path_map.clone()),
            fdb_txn_bytes: args.tuning.fdb_txn_bytes,
            owner: args.owner,
        },
    })
}

pub(super) async fn prepare(
    args: &PrepareArgs,
    shutdown: Shutdown,
) -> Result<ExitCode, CommandError> {
    if !args.non_interactive && !has_terminal() {
        return Err(usage(TERMINAL_REQUIRED));
    }
    let exit_on_signal = shutdown.exit_on_signal();
    let mapping = load_mapping()?;
    let mut answers =
        load_answers(&args.state.state).map_err(|err| usage(err.to_string().into_boxed_str()))?;
    check_edition(&answers)?;
    answers.remove(PromptId::Edition, None);
    let source = adapters::open_source(&args.source.source, &args.source.path_map()).await?;
    let (objects, unreadable) = source_objects(&source, RetryPolicy::default(), REGISTRY_PAGE)
        .await
        .map_err(|err| CommandError::Adapter(err.to_string().into_boxed_str()))?;
    tracing::info!(
        source = %args.source.source.display(),
        state = %args.state.state.display(),
        objects = objects.len(),
        unreadable = unreadable.len(),
        "prepare"
    );
    let blobs = BlobLocation::of(&source);
    if blobs == BlobLocation::DataStore {
        answers.remove(PromptId::BlobStore, None);
    }
    let prepare = Prepare {
        mapping: &mapping,
        options: mapping_options(EDITION, blobs),
        objects,
        unreadable,
    };
    let prepared = if args.non_interactive {
        let prepared = prepare.validate(&answers);
        drop(exit_on_signal);
        print!("{}", summary(&prepared));
        write_outputs(&args.state.state, &mapping, &answers, &prepared)?;
        prepared
    } else {
        let mut terminal = StdTerminal::default();
        let (prepared, confirmation) = prepare.interactive(&mut answers, &mut terminal)?;
        drop(exit_on_signal);
        if confirmation == Confirmation::Discard {
            println!("Nothing was written.");
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
        write_outputs(&args.state.state, &mapping, &answers, &prepared)?;
        prepared
    };
    Ok(if prepared.is_complete() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILURE)
    })
}

pub(super) async fn run(args: &RunArgs, shutdown: Shutdown) -> Result<ExitCode, CommandError> {
    let mut plan = plan_run(args)?;
    let is_final = plan.options.kind == RunKind::Final;
    if is_final {
        let _exit_on_signal = shutdown.exit_on_signal();
        confirm_stopped(args.yes, Confirm::FinalRun)?;
    }
    warn_missing_owner(plan.adapters.owner.is_some());
    plan.options.identity = adapters::store_identity(&plan.adapters)?;
    let state = SqliteState::open_exclusive(&args.state.state)?;
    let opened = adapters::open(
        &plan.adapters,
        adapters::TargetUse::Migrate {
            state: &state,
            definition: plan.options.identity.target_def_hash.as_deref(),
        },
    )
    .await?;
    let blobs = BlobLocation::of(&opened.source);
    plan.options.blob_mode = blob_mode(answer_blob_mode(&plan.answers), blobs);
    let converter =
        MappingConverter::new(plan.mapping, plan.answers, mapping_options(EDITION, blobs));
    tracing::info!(
        state = %state.path().display(),
        source = %plan.adapters.source.display(),
        target = %plan.adapters.target.display(),
        categories = %plan.options.categories,
        blob_mode = ?plan.options.blob_mode,
        edition = plan.options.edition.as_str(),
        concurrency = plan.options.tuning.concurrency,
        "run"
    );
    let target = opened.target.clone();
    let result = Orchestrator::new(
        opened.source,
        opened.target,
        opened.reader,
        Arc::new(state),
        Arc::new(converter),
        plan.options,
        shutdown,
    )
    .run()
    .await;
    let owned = apply_owner(
        target.created_paths().iter().map(PathBuf::as_path),
        plan.adapters.owner,
    );
    let summary = result?;
    owned?;
    let mut header = Vec::new();
    write_run(&mut header, &summary, RunCommand::Migration)?;
    std::io::stdout().lock().write_all(&header)?;
    if is_final && summary.succeeded() {
        match write_final_report(&args.state.state, &summary, &header, target.as_ref()).await {
            Ok(true) => println!(
                "\n{CUTOVER_CHECKLIST}\nThe final report is in {}.",
                args.state.state.join(FINAL_REPORT_FILE).display()
            ),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "the final run completed, but {FINAL_REPORT_FILE} could not be written; list the outstanding rows with stalwart-migrate report"
                );
                println!("\n{CUTOVER_CHECKLIST}");
            }
        }
    }
    Ok(ExitCode::from(summary_exit_code(&summary)))
}

pub(super) async fn verify(
    args: &VerifyArgs,
    shutdown: Shutdown,
) -> Result<ExitCode, CommandError> {
    let answers = require_answers(&args.state.state)?;
    check_edition(&answers)?;
    let config = AdapterConfig {
        source: args.source.source.clone(),
        target: args.target.clone(),
        path_map: args.source.path_map(),
        target_path_map: PathMap::new(args.target_path_map.clone()),
        fdb_txn_bytes: args.tuning.fdb_txn_bytes,
        owner: None,
    };
    let state = SqliteState::open_exclusive(&args.state.state)?;
    let categories = match state.meta(MetaKey::Categories).await? {
        Some(recorded) => CategorySet::parse_list(&recorded).map_err(|err| {
            usage(format!(
                "the categories recorded in the state database are invalid: {err}"
            ))
        })?,
        None => answer_categories(&answers)?,
    };
    let opened = adapters::open(&config, adapters::TargetUse::Verify).await?;
    let converter = MappingConverter::new(
        load_mapping()?,
        answers,
        mapping_options(EDITION, BlobLocation::of(&opened.source)),
    );
    let scope = if args.full {
        VerifyScope::Full
    } else {
        VerifyScope::Sample {
            percent: args.sample.min(100),
        }
    };
    tracing::info!(
        state = %state.path().display(),
        ?scope,
        "verify"
    );
    let summary = crate::orchestrator::verify(
        opened.source,
        opened.reader,
        Arc::new(state),
        Arc::new(converter),
        VerifyOptions {
            scope,
            min_sample: MIN_SAMPLE_ACCOUNTS,
            categories,
            globals: GlobalCheck::Shared,
            tuning: args.tuning.tuning(),
            retry: args.tuning.retry(),
        },
        shutdown,
    )
    .await?;
    println!(
        "verify: {} accounts checked, {} mismatches, {} not explained by earlier reports ({})",
        summary.accounts_checked, summary.mismatches, summary.unexplained, summary.status
    );
    Ok(ExitCode::from(verify_exit_code(&summary)))
}

const V1_OBJECT_PREFIX: &str = "x:";

fn forward_source_key(mapping: &Mapping, key: RegistryKey) -> RegistryKey {
    let object = mapping.target_object(Direction::Reverse, &key.object);
    RegistryKey {
        object: object
            .strip_prefix(V1_OBJECT_PREFIX)
            .map_or_else(|| object.clone(), Box::from),
        id: key.id,
    }
}

async fn forward_state(dir: &Path, mapping: &Mapping) -> Result<ForwardState, CommandError> {
    let forward = SqliteState::open_read_only(dir)?;
    let mut state = ForwardState::default();
    for object in forward.registry_objects().await? {
        for entry in forward.registry_states(object).await? {
            let stored_hash = match (entry.status, entry.stored_hash) {
                (RegistryStatus::Ok, Some(stored_hash)) => Some(stored_hash),
                (RegistryStatus::Ok, None) => continue,
                (RegistryStatus::Error, Some(_)) => {
                    state.written.push(forward_source_key(mapping, entry.key));
                    continue;
                }
                (RegistryStatus::Dropped, _) | (RegistryStatus::Error, None) => None,
            };
            let Some(json) = forward
                .registry_source_json(entry.key.clone())
                .await?
                .filter(|json| !json.is_empty())
            else {
                continue;
            };
            let Ok(json) = serde_json::from_slice(&json) else {
                tracing::warn!(key = %entry.key, "unreadable original settings in the forward state; reverse-mapping it");
                continue;
            };
            match stored_hash {
                Some(stored_hash) => {
                    state
                        .originals
                        .insert(entry.key, Original { stored_hash, json });
                }
                None if source_v1::registry_object_is_stored(&entry.key.object) => {
                    state.unconverted.push(RegistryRecord {
                        key: forward_source_key(mapping, entry.key),
                        json,
                    })
                }
                None => {}
            }
        }
    }
    Ok(state)
}

pub async fn check_state_location(command: &Command) -> Result<(), CommandError> {
    if !matches!(command, Command::Status(_) | Command::Report(_)) {
        adapters::boot()?;
    }
    if let Command::Rollback(args) = command
        && let Some(dir) = &args.forward_state
    {
        adapters::refuse_forward_state_overlap(&args.state.state, dir)?;
        if let Some(forward_source) = SqliteState::open_read_only(dir)?
            .meta(MetaKey::SourceStore)
            .await?
        {
            adapters::refuse_forward_source_overlap(
                &forward_source,
                &args.state.state,
                (&args.source.source, &args.source.path_map()),
                &args.target,
            )?;
        }
    }
    match command {
        Command::Prepare(args) => {
            let path_map = args.source.path_map();
            adapters::refuse_state_overlap(
                &args.state.state,
                (&args.source.source, &path_map),
                None,
            )?;
            adapters::refuse_state_in_blob_stores(
                &args.state.state,
                BlobOwner::V016,
                &args.source.source,
                &path_map,
                None,
            )
            .await
        }
        Command::Run(args) => {
            let (path_map, target_map) = (
                args.source.path_map(),
                PathMap::new(args.target_path_map.clone()),
            );
            adapters::refuse_state_overlap(
                &args.state.state,
                (&args.source.source, &path_map),
                Some((&args.target, &target_map)),
            )?;
            adapters::refuse_state_in_blob_stores(
                &args.state.state,
                BlobOwner::V016,
                &args.source.source,
                &path_map,
                Some(&target_map),
            )
            .await
        }
        Command::Verify(args) => {
            let (path_map, target_map) = (
                args.source.path_map(),
                PathMap::new(args.target_path_map.clone()),
            );
            adapters::refuse_state_overlap(
                &args.state.state,
                (&args.source.source, &path_map),
                Some((&args.target, &target_map)),
            )?;
            adapters::refuse_state_in_blob_stores(
                &args.state.state,
                BlobOwner::V016,
                &args.source.source,
                &path_map,
                Some(&target_map),
            )
            .await
        }
        Command::Rollback(args) => {
            let path_map = args.source.path_map();
            adapters::refuse_state_overlap(
                &args.state.state,
                (&args.source.source, &path_map),
                Some((&args.target, &PathMap::default())),
            )?;
            adapters::refuse_state_in_blob_stores(
                &args.state.state,
                BlobOwner::V1,
                &args.source.source,
                &path_map,
                Some(&PathMap::default()),
            )
            .await
        }
        Command::Status(_) | Command::Report(_) => Ok(()),
    }
}

pub(super) async fn rollback(
    args: &RollbackArgs,
    shutdown: Shutdown,
) -> Result<ExitCode, CommandError> {
    {
        let _exit_on_signal = shutdown.exit_on_signal();
        confirm_stopped(args.yes, Confirm::Rollback)?;
    }
    warn_missing_owner(args.owner.is_some());
    let mapping = load_mapping()?;
    let (answers, forward) = match &args.forward_state {
        Some(dir) => (
            load_answers(dir).map_err(|err| usage(err.to_string().into_boxed_str()))?,
            Some(forward_state(dir, &mapping).await?),
        ),
        None => {
            println!(
                "no --forward-state: settings the migration dropped or could not write to v1 cannot be restored"
            );
            (Answers::default(), None)
        }
    };
    let shared_deletes = if args.allow_shared_deletes {
        SharedDeletes::Allow
    } else {
        SharedDeletes::Forbid
    };
    let config = AdapterConfig {
        source: args.source.source.clone(),
        target: args.target.clone(),
        path_map: args.source.path_map(),
        target_path_map: PathMap::default(),
        fdb_txn_bytes: args.tuning.fdb_txn_bytes,
        owner: args.owner,
    };
    let identity = adapters::store_identity(&config)?;
    if let Some(dir) = &args.forward_state
        && let Some(forward) = SqliteState::open_read_only(dir)?
            .meta(MetaKey::SourceDefHash)
            .await?
    {
        if identity.target_def_hash.as_deref() == Some(forward.as_str()) {
            return Err(usage(
                "the rollback target is the v0.16 store the migration read from; rollback writes into a new, empty store only",
            ));
        }
        if identity.source_def_hash.as_deref() == Some(forward.as_str()) {
            return Err(usage(
                "the rollback source is the v0.16 store the migration read from; rollback reads the migrated v1 store",
            ));
        }
    }
    let state = SqliteState::open_exclusive(&args.state.state)?;
    let source =
        adapters::open_rollback_source(&config.source, &config.path_map, &config.target).await?;
    let converter = MappingConverter::reverse(
        mapping,
        answers,
        mapping_options(EDITION, BlobLocation::DataStore),
        forward,
    );
    let options = rollback_options(args, identity.clone(), shared_deletes);
    let settings = rollback_settings(&source, &converter, &options).await?;
    let spam_model = SpamModelRollback::of(args);
    spam_model.refuse_unless_decided(&settings)?;
    let claim =
        claim_rollback_target(&state, &config.target, identity.target_def_hash.as_deref()).await?;
    let opened = adapters::open_rollback(source, &config.target, shared_deletes, claim).await?;
    let plan = opened
        .target
        .planned_shared_changes(&settings)
        .await
        .map_err(|err| CommandError::Adapter(err.to_string().into_boxed_str()))?;
    print_shared_plan(&plan, shared_deletes, spam_model);
    println!("Note: {NOT_ROLLED_BACK}.");
    tracing::info!(
        state = %state.path().display(),
        source = %config.source.display(),
        target = %config.target.display(),
        forward_state = ?args.forward_state,
        ?shared_deletes,
        "rollback"
    );
    let target = opened.target.clone();
    let result = Orchestrator::new(
        opened.source,
        opened.target,
        opened.reader,
        Arc::new(state),
        Arc::new(converter),
        options,
        shutdown,
    )
    .run()
    .await;
    let owned = apply_owner(
        target.created_paths().iter().map(PathBuf::as_path),
        config.owner,
    );
    let summary = result?;
    owned?;
    print_run(&summary, RunCommand::Rollback);
    Ok(ExitCode::from(summary_exit_code(&summary)))
}

fn rollback_options(
    args: &RollbackArgs,
    identity: StoreIdentity,
    shared_deletes: SharedDeletes,
) -> RunOptions {
    let mut options = RunOptions::new(RunKind::Final, EDITION);
    for category in NOT_ROLLED_BACK_CATEGORIES {
        options.categories.remove(category);
    }
    options.blob_mode = BlobMode::Copy;
    options.tuning = args.tuning.tuning();
    options.retry = args.tuning.retry();
    options.write_timeout = args.tuning.write_timeout();
    options.identity = identity;
    options.shared_deletes = shared_deletes;
    options.direction = RunDirection::Rollback;
    options.final_observation = Duration::from_secs(args.final_observation);
    options.progress_interval =
        (args.progress_interval > 0).then(|| Duration::from_secs(args.progress_interval));
    if args.allow_errors {
        options.errors = ErrorPolicy::Allow;
    }
    if args.allow_mass_removal {
        options.removals = RemovalPolicy::Allow;
    }
    if args.verify_full {
        options.final_verify = VerifyScope::Full;
    }
    options.notices.push(NOT_ROLLED_BACK.into());
    if SpamModelRollback::of(args) == SpamModelRollback::KeepV1 {
        options.categories.remove(Category::SpamModel);
        options.notices.push(KEEP_V1_SPAM_MODEL.into());
    }
    options
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpamModelRollback {
    Undecided,
    WriteBack,
    KeepV1,
}

impl SpamModelRollback {
    fn of(args: &RollbackArgs) -> Self {
        match (args.allow_shared_deletes, args.keep_v1_spam_model) {
            (_, true) => SpamModelRollback::KeepV1,
            (true, false) => SpamModelRollback::WriteBack,
            (false, false) => SpamModelRollback::Undecided,
        }
    }

    fn refuse_unless_decided(self, settings: &[RegistryRecord]) -> Result<(), CommandError> {
        let shared_spam_model = settings.iter().any(|record| {
            record
                .key
                .object
                .strip_prefix("x:")
                .unwrap_or(&record.key.object)
                == BLOB_STORE_OBJECT
                && record.key.id == RegistryId::Singleton
                && record
                    .json
                    .get("@type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|backend| backend != DEFAULT_BLOB_STORE)
        });
        if shared_spam_model && self == SpamModelRollback::Undecided {
            return Err(usage(SHARED_SPAM_MODEL_UNDECIDED));
        }
        Ok(())
    }
}

async fn claim_rollback_target(
    state: &SqliteState,
    target: &Path,
    definition: Option<&str>,
) -> Result<TargetClaim, CommandError> {
    match state.meta(MetaKey::TargetDefHash).await? {
        Some(recorded) if Some(recorded.as_str()) == definition => {
            return adapters::recorded_claim(state).await;
        }
        Some(_) => {
            return Err(usage(
                "the rollback --target definition differs from the one this --state already rolled back into; repeat the rollback with that target or use a new --state",
            ));
        }
        None => {}
    }
    adapters::refuse_existing_store(target)?;
    let claim = adapters::new_claim(state).await?;
    if let Some(definition) = definition {
        state
            .set_meta(MetaKey::TargetDefHash, definition.into())
            .await?;
    }
    Ok(claim)
}

async fn rollback_settings(
    source: &V1Source,
    converter: &MappingConverter,
    options: &RunOptions,
) -> Result<Vec<RegistryRecord>, CommandError> {
    let adapter = |err: model::Error| CommandError::Adapter(err.to_string().into_boxed_str());
    let RegistryEntries {
        records,
        unreadable,
    } = read_registry(source, options.retry, options.tuning.batch_ops)
        .await
        .map_err(adapter)?;
    for key in &unreadable {
        tracing::warn!(%key, "unreadable settings object in the v1 store; not rolled back");
    }
    let converted = converter
        .convert(records, registry_categories(options.categories))
        .map_err(|err| CommandError::Adapter(err.to_string().into_boxed_str()))?;
    let mut settings = converted.deferred;
    settings.extend(
        converted
            .records
            .into_iter()
            .map(|converted| converted.record),
    );
    Ok(settings)
}

fn print_shared_plan(
    plan: &SharedPlan,
    shared_deletes: SharedDeletes,
    spam_model: SpamModelRollback,
) {
    if plan.is_empty() {
        println!("rollback deletes nothing outside the new v0.16 store");
    }
    for deletion in &plan.deletions {
        match shared_deletes {
            SharedDeletes::Allow => println!(
                "an account that must be recopied also deletes its {}: {}",
                deletion.service, deletion.what
            ),
            SharedDeletes::Forbid => println!(
                "an account that must be recopied leaves its {} in place ({}); pass --allow-shared-deletes to delete it",
                deletion.service, deletion.what
            ),
        }
    }
    for overwrite in &plan.overwrites {
        if spam_model == SpamModelRollback::KeepV1 && overwrite.service == SharedService::BlobStore
        {
            println!(
                "rollback leaves {} as v1 wrote them (--keep-v1-spam-model); {KEEP_V1_SPAM_MODEL}",
                overwrite.what
            );
            continue;
        }
        match shared_deletes {
            SharedDeletes::Allow => println!("rollback overwrites {}", overwrite.what),
            SharedDeletes::Forbid => println!(
                "rollback leaves {} in place; pass --allow-shared-deletes to overwrite it",
                overwrite.what
            ),
        }
    }
}

pub fn verify_exit_code(summary: &VerifySummary) -> u8 {
    match summary.status {
        RunStatus::Ok => 0,
        RunStatus::Interrupted => EXIT_INTERRUPTED,
        _ => EXIT_FAILURE,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunCommand {
    Migration,
    Rollback,
}

impl RunCommand {
    const fn verify_interrupted(self) -> &'static str {
        match self {
            RunCommand::Migration => {
                "finalize completed but verification was interrupted: the final run is not marked done. Run --final again."
            }
            RunCommand::Rollback => {
                "the rollback completed but verification was interrupted: it is not marked done. Run stalwart-migrate rollback again with the same --state."
            }
        }
    }

    const fn verify_failed(self) -> &'static str {
        match self {
            RunCommand::Migration => {
                "finalize completed but verification failed: the final run is not marked done. Fix the reported mismatches (stalwart-migrate report --severity verify) and run --final again."
            }
            RunCommand::Rollback => {
                "the rollback completed but verification failed: it is not marked done. Fix the reported mismatches (stalwart-migrate report --state <rollback state> --severity verify) and run stalwart-migrate rollback again with the same --state."
            }
        }
    }
}

fn write_run(
    out: &mut impl Write,
    summary: &RunSummary,
    command: RunCommand,
) -> std::io::Result<()> {
    writeln!(
        out,
        "run {}: {} ({})",
        summary.run_id,
        summary.status,
        summary.stats.to_json()
    )?;
    if let Some(error) = &summary.error {
        writeln!(out, "error: {error}")?;
    }
    if let Some(verify) = &summary.verify {
        writeln!(
            out,
            "verify: {} accounts checked, {} mismatches, {} not explained by earlier reports ({})",
            verify.accounts_checked, verify.mismatches, verify.unexplained, verify.status
        )?;
        match verify.status {
            RunStatus::Ok => {}
            RunStatus::Interrupted => writeln!(out, "{}", command.verify_interrupted())?,
            _ => writeln!(out, "{}", command.verify_failed())?,
        }
    }
    Ok(())
}

fn print_run(summary: &RunSummary, command: RunCommand) {
    let _ = write_run(&mut std::io::stdout().lock(), summary, command);
}

fn warn_missing_owner(has_owner: bool) {
    if !has_owner && running_as_root() {
        tracing::warn!(
            "running as root without --owner: files created for the target will be owned by root and a v1 container running as uid 2000 may not be able to open them"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirm {
    FinalRun,
    Rollback,
}

impl Confirm {
    const fn prompt(self) -> &'static str {
        match self {
            Confirm::FinalRun => "The final run requires every v0.16 node to be stopped.",
            Confirm::Rollback => "The rollback requires every v1 node to be stopped.",
        }
    }

    const fn without_terminal(self) -> &'static str {
        match self {
            Confirm::FinalRun => {
                "run --final needs an interactive confirmation; pass --yes when no terminal is attached"
            }
            Confirm::Rollback => {
                "rollback needs an interactive confirmation; pass --yes when no terminal is attached"
            }
        }
    }

    const fn declined(self) -> &'static str {
        match self {
            Confirm::FinalRun => "final run not confirmed",
            Confirm::Rollback => "rollback not confirmed",
        }
    }
}

fn confirm_stopped(assume_yes: bool, confirm: Confirm) -> Result<(), CommandError> {
    if assume_yes {
        return Ok(());
    }
    if !has_terminal() {
        return Err(usage(confirm.without_terminal()));
    }
    let mut stdout = std::io::stdout().lock();
    write!(
        stdout,
        "{} Type '{FINAL_CONFIRMATION}' to continue: ",
        confirm.prompt()
    )?;
    stdout.flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if answer.trim() == FINAL_CONFIRMATION {
        Ok(())
    } else {
        Err(usage(confirm.declined()))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    // Rollback accepts --allow-mass-removal and --verify-full like a final run, and defaults to the guarded sample.
    #[test]
    fn rollback_options_follow_the_flags() {
        let parse = |extra: &[&str]| {
            let mut argv = vec![
                "stalwart-migrate",
                "rollback",
                "--source",
                "v1.json",
                "--target",
                "v016.json",
                "--state",
                "state",
            ];
            argv.extend_from_slice(extra);
            let Command::Rollback(args) = Cli::try_parse_from(argv).expect("parse").command else {
                panic!("rollback");
            };
            rollback_options(&args, StoreIdentity::default(), SharedDeletes::Forbid)
        };
        let defaults = parse(&[]);
        assert_eq!(defaults.removals, RemovalPolicy::Guarded);
        assert_eq!(defaults.final_verify, VerifyScope::Sample { percent: 1 });
        let flagged = parse(&["--allow-mass-removal", "--verify-full"]);
        assert_eq!(flagged.removals, RemovalPolicy::Allow);
        assert_eq!(flagged.final_verify, VerifyScope::Full);
        assert!(defaults.categories.contains(Category::SpamModel));
        for category in NOT_ROLLED_BACK_CATEGORIES {
            assert!(!defaults.categories.contains(category));
        }
        let kept = parse(&["--keep-v1-spam-model"]);
        assert!(!kept.categories.contains(Category::SpamModel));
        assert_eq!(defaults.direction, RunDirection::Rollback);
        assert_eq!(
            defaults.progress_interval,
            Some(crate::orchestrator::PROGRESS_INTERVAL)
        );
        assert_eq!(parse(&["--progress-interval", "0"]).progress_interval, None);
    }

    // A shared blob store overwrite needs --allow-shared-deletes or --keep-v1-spam-model.
    #[test]
    fn shared_spam_model_needs_a_decision() {
        let blob_store = |backend: &str| {
            vec![RegistryRecord {
                key: RegistryKey::singleton("BlobStore"),
                json: serde_json::json!({"@type": backend}),
            }]
        };
        let shared = blob_store("FileSystem");
        assert!(
            SpamModelRollback::Undecided
                .refuse_unless_decided(&shared)
                .is_err()
        );
        for decided in [SpamModelRollback::WriteBack, SpamModelRollback::KeepV1] {
            assert!(decided.refuse_unless_decided(&shared).is_ok());
        }
        assert!(
            SpamModelRollback::Undecided
                .refuse_unless_decided(&blob_store("Default"))
                .is_ok()
        );
    }

    // Forward rows that failed after an earlier successful write are not restorable; rows that never reached v1 are.
    #[tokio::test]
    async fn forward_state_separates_objects_written_before() {
        let dir = tempfile::tempdir().expect("tempdir");
        let row = |id: u64, status, stored: Option<&[u8]>| state::RegistryUpdate {
            key: RegistryKey::new("x:Domain", id),
            source_hash: state::ContentHash::of(b"source"),
            target_hash: None,
            stored_hash: stored.map(state::ContentHash::of),
            source_json: br#"{"name":"a.org"}"#.to_vec(),
            status,
        };
        {
            let forward = SqliteState::open(dir.path()).expect("state");
            forward
                .put_registry(
                    1,
                    vec![
                        row(1, RegistryStatus::Ok, Some(b"stored")),
                        row(2, RegistryStatus::Error, None),
                    ],
                )
                .await
                .expect("rows");
            forward
                .put_registry(2, vec![row(1, RegistryStatus::Error, None)])
                .await
                .expect("rows");
        }
        let mapping = Mapping::embedded().expect("mapping");
        let loaded = forward_state(dir.path(), &mapping)
            .await
            .expect("forward state");
        assert_eq!(loaded.written, [RegistryKey::new("Domain", 1)]);
        assert_eq!(
            forward_source_key(&mapping, RegistryKey::new("x:SpamAi", 3)),
            RegistryKey::new("SpamLlm", 3)
        );
        assert_eq!(
            loaded
                .unconverted
                .iter()
                .map(|record| record.key.clone())
                .collect::<Vec<_>>(),
            [RegistryKey::new("Domain", 2)]
        );
    }
    use crate::{
        cli::{Cli, Command},
        orchestrator::StatsSnapshot,
    };

    fn run_args(state: &Path, extra: &[&str]) -> RunArgs {
        let state = state.to_str().expect("utf8 path");
        let mut argv = vec![
            "stalwart-migrate",
            "run",
            "--source",
            "/etc/stalwart/config.json",
            "--target",
            "/etc/stalwart-v1/config.json",
            "--state",
            state,
        ];
        argv.extend_from_slice(extra);
        match Cli::try_parse_from(argv).expect("valid").command {
            Command::Run(args) => args,
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn run_requires_answers() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            plan_run(&run_args(dir.path(), &[])),
            Err(CommandError::Usage(_))
        ));
    }

    #[test]
    fn run_plan_follows_answers_and_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(ANSWERS_FILE),
            "version = 1\n[global.categories]\ninclude = [\"mail\", \"files\"]\n[global.blob_store]\nmode = \"copy\"\n",
        )
        .expect("write answers");
        let plan = plan_run(&run_args(
            dir.path(),
            &[
                "--exclude",
                "files",
                "--include",
                "queue",
                "--final",
                "--verify-full",
                "--allow-mass-removal",
                "--fdb-txn-bytes",
                "1000",
            ],
        ))
        .expect("plan");
        let categories = plan.options.categories;
        assert!(categories.contains(Category::Mail));
        assert!(categories.contains(Category::Queue));
        assert!(!categories.contains(Category::Files));
        assert!(!categories.contains(Category::Calendars));
        assert_eq!(answer_blob_mode(&plan.answers), Some(BlobMode::Copy));
        assert_eq!(plan.options.kind, RunKind::Final);
        assert_eq!(plan.options.final_verify, VerifyScope::Full);
        assert_eq!(plan.options.removals, RemovalPolicy::Allow);
        assert_eq!(plan.adapters.fdb_txn_bytes, 1000);
    }

    #[test]
    fn run_refuses_other_edition() {
        let dir = tempfile::tempdir().expect("tempdir");
        let other = match EDITION {
            Edition::Enterprise => "oss",
            Edition::Community => "enterprise",
        };
        std::fs::write(
            dir.path().join(ANSWERS_FILE),
            format!("version = 1\n[global.edition]\nedition = \"{other}\"\n"),
        )
        .expect("write answers");
        assert!(matches!(
            plan_run(&run_args(dir.path(), &[])),
            Err(CommandError::Usage(_))
        ));
    }

    #[test]
    fn exit_codes_follow_run_status() {
        let summary = |status| RunSummary {
            run_id: 1,
            status,
            interrupted_runs: Vec::new(),
            stats: StatsSnapshot::default(),
            error: None,
            verify: None,
        };
        assert_eq!(summary_exit_code(&summary(RunStatus::Ok)), 0);
        assert_eq!(
            summary_exit_code(&summary(RunStatus::Interrupted)),
            EXIT_INTERRUPTED
        );
        assert_eq!(summary_exit_code(&summary(RunStatus::Failed)), EXIT_FAILURE);
    }

    // A failed verify tells the operator to repeat the command that ran, rollback or run --final.
    #[test]
    fn failed_verify_names_the_command_to_repeat() {
        let summary = RunSummary {
            run_id: 3,
            status: RunStatus::Failed,
            interrupted_runs: Vec::new(),
            stats: StatsSnapshot::default(),
            error: None,
            verify: Some(VerifySummary {
                run_id: 4,
                status: RunStatus::Failed,
                accounts_checked: 1,
                mismatches: 1,
                unexplained: 1,
            }),
        };
        let text = |command| {
            let mut out = Vec::new();
            write_run(&mut out, &summary, command).expect("write");
            String::from_utf8(out).expect("utf8")
        };
        let rollback = text(RunCommand::Rollback);
        assert!(
            rollback.contains("stalwart-migrate rollback again"),
            "{rollback}"
        );
        assert!(!rollback.contains("--final"), "{rollback}");
        assert!(text(RunCommand::Migration).contains("run --final again"));
    }

    // A final run whose verify was interrupted exits as interrupted and asks for the command again, not for mismatches to be fixed.
    #[test]
    fn interrupted_final_verify_is_an_interrupted_run() {
        let summary = RunSummary {
            run_id: 3,
            status: RunStatus::Interrupted,
            interrupted_runs: Vec::new(),
            stats: StatsSnapshot::default(),
            error: None,
            verify: Some(VerifySummary {
                run_id: 3,
                status: RunStatus::Interrupted,
                accounts_checked: 0,
                mismatches: 0,
                unexplained: 0,
            }),
        };
        assert_eq!(summary_exit_code(&summary), EXIT_INTERRUPTED);
        let mut out = Vec::new();
        write_run(&mut out, &summary, RunCommand::Migration).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("verification was interrupted"), "{text}");
        assert!(!text.contains("mismatches (stalwart-migrate"), "{text}");
    }
}
