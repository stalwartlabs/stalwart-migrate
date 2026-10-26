/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Write as _,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use model::{ClaimId, SharedDeletes, TargetClaim, TargetProbe};
use source_v1::V1Source;
use source_v016::{SourceConfig, StoreSchema, V016Source};
use state::{ContentHash, MetaKey, SqliteState, StateStore};
use target_v1::{TargetConfig, V1Target};
use target_v016::V016Target;

use super::{CommandError, run::AdapterConfig};
use crate::{orchestrator::StoreIdentity, paths::PathMap};

pub(super) struct Adapters {
    pub(super) source: Arc<V016Source>,
    pub(super) target: Arc<V1Target>,
    pub(super) reader: Arc<V1Source>,
}

fn failed(what: &str, err: impl std::fmt::Display) -> CommandError {
    CommandError::Adapter(format!("{what}: {err}").into_boxed_str())
}

pub(super) fn self_check() -> Result<(), CommandError> {
    source_v016::self_check().map_err(|err| failed("v0.16 self-check failed", err))?;
    target_v1::self_check().map_err(|err| failed("v1 self-check failed", err))?;
    source_v1::self_check().map_err(|err| failed("v1 reader self-check failed", err))
}

#[cfg(feature = "foundation")]
fn boot_foundationdb() -> Result<(), CommandError> {
    target_v1::boot_foundationdb_network()
        .map_err(|err| failed("cannot start the FoundationDB network", err))?;
    source_v016::use_external_foundationdb_network();
    Ok(())
}

#[cfg(not(feature = "foundation"))]
fn boot_foundationdb() -> Result<(), CommandError> {
    Ok(())
}

pub(super) fn boot() -> Result<(), CommandError> {
    self_check()?;
    boot_foundationdb()
}

fn rewrite(path_map: &PathMap) -> Option<impl Fn(&str) -> String + Send + Sync + 'static> {
    (!path_map.is_empty()).then(|| {
        let path_map = path_map.clone();
        move |path: &str| path_map.apply(path).into_owned()
    })
}

pub(super) async fn open_source(
    path: &Path,
    path_map: &PathMap,
) -> Result<V016Source, CommandError> {
    let mut config = SourceConfig::from_file(path)
        .map_err(|err| failed("cannot read the v0.16 configuration", err))?;
    config.path_rewrite =
        rewrite(path_map).map(|rewrite| Box::new(rewrite) as source_v016::PathRewrite);
    V016Source::open(config)
        .await
        .map_err(|err| failed("cannot open the v0.16 store", err))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Source,
    Target,
}

impl Side {
    const fn store(self) -> &'static str {
        match self {
            Side::Source => "source",
            Side::Target => "target",
        }
    }
}

const SQLITE_URI_SCHEME: &str = "file:";
const ROCKSDB_CURRENT: &str = "CURRENT";
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

enum LocalStore {
    Directory(PathBuf),
    Sqlite(PathBuf),
}

impl LocalStore {
    const DIRECTORY: &str = "directory ";
    const SQLITE: &str = "sqlite ";

    fn encode(&self) -> String {
        let (kind, path) = match self {
            LocalStore::Directory(path) => (Self::DIRECTORY, path),
            LocalStore::Sqlite(path) => (Self::SQLITE, path),
        };
        format!("{kind}{}", path.display())
    }

    fn decode(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix(Self::DIRECTORY) {
            Some(LocalStore::Directory(PathBuf::from(path)))
        } else {
            value
                .strip_prefix(Self::SQLITE)
                .map(|path| LocalStore::Sqlite(PathBuf::from(path)))
        }
    }

    fn path(&self) -> &Path {
        match self {
            LocalStore::Directory(path) | LocalStore::Sqlite(path) => path,
        }
    }

    fn holds_data(&self) -> bool {
        match self {
            LocalStore::Directory(path) => path.join(ROCKSDB_CURRENT).is_file(),
            LocalStore::Sqlite(path) => path.is_file(),
        }
    }

    fn files(&self) -> impl Iterator<Item = PathBuf> + '_ {
        let (path, sidecars): (&Path, &[&str]) = match self {
            LocalStore::Directory(path) => (path, &[]),
            LocalStore::Sqlite(path) => (path, &SQLITE_SIDECARS),
        };
        std::iter::once(path.to_path_buf()).chain(sidecars.iter().map(move |suffix| {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            PathBuf::from(file)
        }))
    }
}

fn is_sqlite_uri(path: &str) -> bool {
    path.get(..SQLITE_URI_SCHEME.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(SQLITE_URI_SCHEME))
}

fn local_store_path(
    config: &Path,
    path_map: &PathMap,
    side: Side,
) -> Result<Option<LocalStore>, CommandError> {
    let contents = std::fs::read(config)
        .map_err(|err| failed(&format!("cannot read {}", config.display()), err))?;
    let value: serde_json::Value = serde_json::from_slice(&contents)
        .map_err(|err| failed(&format!("cannot parse {}", config.display()), err))?;
    let Some(kind) = value.get("@type").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    let Some(&sqlite) = hashify::map!(kind.as_bytes(), bool, "Sqlite" => true, "RocksDb" => false)
    else {
        return Ok(None);
    };
    let Some(path) = value.get("path").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    let path = path_map.apply(path);
    if !sqlite {
        return Ok(Some(LocalStore::Directory(resolved(Path::new(
            path.as_ref(),
        )))));
    }
    if is_sqlite_uri(&path) {
        return Err(CommandError::Usage(
            format!(
                "the {} store path {path} is a SQLite URI; use a plain file system path",
                side.store()
            )
            .into_boxed_str(),
        ));
    }
    Ok(Some(LocalStore::Sqlite(resolved(Path::new(path.as_ref())))))
}

const MAX_SYMLINKS: u32 = 40;

fn resolved(path: &Path) -> PathBuf {
    resolved_within(path, MAX_SYMLINKS)
}

fn resolved_within(path: &Path, links: u32) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut resolved = PathBuf::with_capacity(absolute.as_os_str().len());
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            component => {
                resolved.push(component);
                if let Ok(canonical) = resolved.canonicalize() {
                    resolved = canonical;
                } else if let Some(link) = links
                    .checked_sub(1)
                    .and_then(|_| std::fs::read_link(&resolved).ok())
                {
                    resolved.pop();
                    resolved = resolved_within(&resolved.join(link), links - 1);
                }
            }
        }
    }
    resolved
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

fn shares_files(source: &Path, target: &Path) -> bool {
    let within = |inner: &Path, outer: &Path| {
        file_identity(outer).is_some_and(|outer| {
            inner
                .ancestors()
                .filter_map(file_identity)
                .any(|identity| identity == outer)
        })
    };
    within(target, source) || within(source, target)
}

fn starts_with_ignoring_case(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix.components().all(|prefix| {
        path.next().is_some_and(|component| {
            component
                .as_os_str()
                .eq_ignore_ascii_case(prefix.as_os_str())
        })
    })
}

fn overlaps(source: &Path, target: &Path) -> bool {
    starts_with_ignoring_case(source, target)
        || starts_with_ignoring_case(target, source)
        || shares_files(source, target)
}

fn refuse_overlap(
    source: &LocalStore,
    target: &LocalStore,
    what: &str,
) -> Result<(), CommandError> {
    let overlapping = source
        .files()
        .any(|source| target.files().any(|target| overlaps(&source, &target)));
    if overlapping {
        Err(CommandError::Usage(
            format!(
                "the target store {} overlaps the source {what} {}; the target must be a separate, new location",
                target.path().display(),
                source.path().display()
            )
            .into_boxed_str(),
        ))
    } else {
        Ok(())
    }
}

fn state_overlap(state: &Path, store: &LocalStore, what: &str) -> Result<(), CommandError> {
    if store.files().any(|file| overlaps(&file, state)) {
        Err(CommandError::Usage(
            format!(
                "the --state directory {} overlaps the {what} {}; keep the state outside every store",
                state.display(),
                store.path().display()
            )
            .into_boxed_str(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn refuse_state_overlap(
    state: &Path,
    source: (&Path, &PathMap),
    target: Option<(&Path, &PathMap)>,
) -> Result<(), CommandError> {
    let state = resolved(state);
    let stores =
        std::iter::once((source, Side::Source)).chain(target.map(|target| (target, Side::Target)));
    for ((config, path_map), side) in stores {
        if let Some(store) = local_store_path(config, path_map, side)? {
            state_overlap(&state, &store, &format!("{} store", side.store()))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlobOwner {
    V016,
    V1,
}

impl BlobOwner {
    const fn names(self) -> [&'static str; 2] {
        match self {
            BlobOwner::V016 => ["v0.16 file system blob store", "v1 file system blob store"],
            BlobOwner::V1 => ["v1 file system blob store", "v0.16 file system blob store"],
        }
    }
}

pub(super) async fn refuse_state_in_blob_stores(
    state: &Path,
    owner: BlobOwner,
    config: &Path,
    path_map: &PathMap,
    other_map: Option<&PathMap>,
) -> Result<(), CommandError> {
    let paths = match owner {
        BlobOwner::V016 => match SourceConfig::from_file(config) {
            Ok(mut source) => {
                source.path_rewrite =
                    rewrite(path_map).map(|rewrite| Box::new(rewrite) as source_v016::PathRewrite);
                V016Source::configured_file_system_blob_paths(&source)
                    .await
                    .ok()
            }
            Err(_) => None,
        },
        BlobOwner::V1 => match source_v1::SourceConfig::from_file(config) {
            Ok(mut source) => {
                source.path_rewrite =
                    rewrite(path_map).map(|rewrite| Box::new(rewrite) as source_v1::PathRewrite);
                V1Source::configured_file_system_blob_paths(&source)
                    .await
                    .ok()
            }
            Err(_) => None,
        },
    };
    let Some(paths) = paths else {
        return Ok(());
    };
    let state = resolved(state);
    let [own, other] = owner.names();
    for path in &paths {
        let mapped = std::iter::once((path_map.apply(path), own))
            .chain(other_map.map(|map| (map.apply(path), other)));
        for (mapped, what) in mapped {
            state_overlap(
                &state,
                &LocalStore::Directory(resolved(Path::new(mapped.as_ref()))),
                what,
            )?;
        }
    }
    Ok(())
}

pub(super) fn refuse_forward_state_overlap(
    state: &Path,
    forward: &Path,
) -> Result<(), CommandError> {
    if overlaps(&resolved(state), &resolved(forward)) {
        Err(CommandError::Usage(
            format!(
                "the rollback --state {} overlaps the --forward-state {} of the migration; use a new directory",
                state.display(),
                forward.display()
            )
            .into_boxed_str(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn refuse_forward_source_overlap(
    forward_source: &str,
    state: &Path,
    source: (&Path, &PathMap),
    target: &Path,
) -> Result<(), CommandError> {
    let Some(forward) = LocalStore::decode(forward_source) else {
        return Ok(());
    };
    let what = "v0.16 store the migration read from";
    state_overlap(&resolved(state), &forward, what)?;
    if let Some(store) = local_store_path(target, &PathMap::default(), Side::Target)? {
        refuse_overlap(&forward, &store, what)?;
    }
    if let Some(store) = local_store_path(source.0, source.1, Side::Source)?
        && store
            .files()
            .any(|file| forward.files().any(|forward| overlaps(&file, &forward)))
    {
        return Err(CommandError::Usage(
            format!(
                "the rollback source {} overlaps the {what} {}; rollback reads the migrated v1 store",
                store.path().display(),
                forward.path().display()
            )
            .into_boxed_str(),
        ));
    }
    Ok(())
}

pub(super) enum TargetUse<'x> {
    Verify,
    Migrate {
        state: &'x SqliteState,
        definition: Option<&'x str>,
    },
}

pub(super) async fn recorded_claim(state: &SqliteState) -> Result<TargetClaim, CommandError> {
    match state
        .meta(MetaKey::TargetClaim)
        .await?
        .as_deref()
        .and_then(ClaimId::parse_hex)
    {
        Some(id) => Ok(TargetClaim::Claimed(id)),
        None => new_claim(state).await,
    }
}

pub(super) async fn new_claim(state: &SqliteState) -> Result<TargetClaim, CommandError> {
    let id = ClaimId::random();
    state.set_meta(MetaKey::TargetClaim, id.to_string()).await?;
    Ok(TargetClaim::New(id))
}

async fn claim_target(
    config: &AdapterConfig,
    state: &SqliteState,
    definition: Option<&str>,
) -> Result<TargetClaim, CommandError> {
    match state.meta(MetaKey::TargetDefHash).await? {
        Some(recorded) if Some(recorded.as_str()) == definition || definition.is_none() => {
            return recorded_claim(state).await;
        }
        Some(_) => {
            return Err(CommandError::Usage(
                "the target store definition differs from the one recorded in the state database"
                    .into(),
            ));
        }
        None => {}
    }
    let rewrite =
        rewrite(&config.target_path_map).map(|rewrite| Arc::new(rewrite) as target_v1::PathRewrite);
    let probe = V1Target::probe_store(
        &TargetConfig {
            data_store: config.target.clone(),
            fdb_txn_bytes: config.fdb_txn_bytes,
        },
        rewrite.as_ref(),
    )
    .await
    .map_err(|err| failed("cannot check the v1 target", err))?;
    if let TargetProbe::Initialized { .. } = probe {
        return Err(CommandError::Usage(
            "the v1 --target already holds a v1 store that this --state did not create; the migration writes only into a new, empty v1 store".into(),
        ));
    }
    let claim = new_claim(state).await?;
    if let Some(definition) = definition {
        state
            .set_meta(MetaKey::TargetDefHash, definition.into())
            .await?;
    }
    Ok(claim)
}

pub(super) async fn open(
    config: &AdapterConfig,
    usage: TargetUse<'_>,
) -> Result<Adapters, CommandError> {
    let target_path = local_store_path(&config.target, &config.target_path_map, Side::Target)?;
    if let (Some(target), Some(source)) = (
        &target_path,
        local_store_path(&config.source, &config.path_map, Side::Source)?,
    ) {
        refuse_overlap(&source, target, "data store")?;
    }
    if same_database(
        &store_definition(&config.source)?,
        &store_definition(&config.target)?,
    ) {
        return Err(CommandError::Usage(
            "the v1 target store is the database of the v0.16 source; the target must be a separate, new store".into(),
        ));
    }
    let source = open_source(&config.source, &config.path_map).await?;
    if let Some(target) = &target_path {
        for blobs in source.file_system_blob_paths() {
            refuse_overlap(
                &LocalStore::Directory(resolved(Path::new(blobs))),
                target,
                "blob store",
            )?;
        }
    }
    refuse_v016_target(
        &config.target,
        &config.target_path_map,
        target_path.as_ref(),
    )
    .await?;
    let target_config = TargetConfig {
        data_store: config.target.clone(),
        fdb_txn_bytes: config.fdb_txn_bytes,
    };
    let target_rewrite =
        rewrite(&config.target_path_map).map(|rewrite| Arc::new(rewrite) as target_v1::PathRewrite);
    let target = match usage {
        TargetUse::Migrate { state, definition } => {
            let claim = claim_target(config, state, definition).await?;
            V1Target::open_claimed(target_config, target_rewrite, claim).await
        }
        _ => V1Target::open_with_rewrite(target_config, target_rewrite).await,
    }
    .map_err(|err| failed("cannot open the v1 target", err))?;
    let reader = V1Source::from_store_with_rewrite(
        target.store().clone(),
        rewrite(&config.target_path_map).map(|rewrite| Box::new(rewrite) as source_v1::PathRewrite),
    );
    Ok(Adapters {
        source: Arc::new(source),
        target: Arc::new(target),
        reader: Arc::new(reader),
    })
}

pub(super) struct RollbackAdapters {
    pub(super) source: Arc<V1Source>,
    pub(super) target: Arc<V016Target>,
    pub(super) reader: Arc<V016Source>,
}

const CLUSTER_FILE: &str = "clusterFile";

fn store_definition(path: &Path) -> Result<serde_json::Value, CommandError> {
    let contents = std::fs::read(path)
        .map_err(|err| failed(&format!("cannot read {}", path.display()), err))?;
    serde_json::from_slice(&contents)
        .map_err(|err| failed(&format!("cannot parse {}", path.display()), err))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Database {
    Sql { default_port: u64 },
    Foundation,
}

const DEFAULT_SQL_DATABASE: &str = "stalwart";
const FDB_CLUSTER_FILE_VAR: &str = "FDB_CLUSTER_FILE";
#[cfg(target_os = "macos")]
const DEFAULT_CLUSTER_FILE: &str = "/usr/local/etc/foundationdb/fdb.cluster";
#[cfg(not(target_os = "macos"))]
const DEFAULT_CLUSTER_FILE: &str = "/etc/foundationdb/fdb.cluster";
const LOCAL_CLUSTER_FILE: &str = "fdb.cluster";

fn database_kind(value: &serde_json::Value) -> Option<(Database, &str)> {
    let kind = value.get("@type")?.as_str()?;
    hashify::map!(kind.as_bytes(), Database,
        "PostgreSql" => Database::Sql { default_port: 5432 },
        "MySql" => Database::Sql { default_port: 3306 },
        "FoundationDb" => Database::Foundation,
    )
    .map(|database| (*database, kind))
}

fn local_host(host: &str) -> bool {
    hashify::set_ignore_case!(
        host.as_bytes(),
        "",
        "localhost",
        "127.0.0.1",
        "::1",
        "[::1]",
        "0:0:0:0:0:0:0:1"
    )
}

fn sql_identity(value: &serde_json::Value, default_port: u64) -> (String, u64, String) {
    let text = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    let host = text("host").unwrap_or_default();
    let host = if local_host(host) {
        "localhost".to_string()
    } else {
        host.to_ascii_lowercase()
    };
    let port = value
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(default_port);
    let database = text("database")
        .unwrap_or(DEFAULT_SQL_DATABASE)
        .to_ascii_lowercase();
    (host, port, database)
}

struct ClientEnvironment {
    cluster_file: Option<std::ffi::OsString>,
    current_dir: PathBuf,
}

impl ClientEnvironment {
    fn current() -> Self {
        ClientEnvironment {
            cluster_file: std::env::var_os(FDB_CLUSTER_FILE_VAR),
            current_dir: std::env::current_dir().unwrap_or_default(),
        }
    }

    fn cluster_file(&self, value: &serde_json::Value) -> PathBuf {
        match value.get(CLUSTER_FILE).and_then(serde_json::Value::as_str) {
            Some(path) if !path.is_empty() => self.current_dir.join(path),
            _ => self
                .cluster_file
                .as_ref()
                .map(|path| self.current_dir.join(path))
                .or_else(|| {
                    let local = self.current_dir.join(LOCAL_CLUSTER_FILE);
                    local.is_file().then_some(local)
                })
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CLUSTER_FILE)),
        }
    }
}

fn same_cluster(left: &Path, right: &Path) -> bool {
    if resolved(left) == resolved(right) {
        return true;
    }
    match (std::fs::read(left), std::fs::read(right)) {
        (Ok(left), Ok(right)) => left.trim_ascii() == right.trim_ascii(),
        _ => false,
    }
}

fn same_database(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    same_database_in(&ClientEnvironment::current(), left, right)
}

fn same_database_in(
    environment: &ClientEnvironment,
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> bool {
    let (Some((database, left_kind)), Some((_, right_kind))) =
        (database_kind(left), database_kind(right))
    else {
        return false;
    };
    left_kind == right_kind
        && match database {
            Database::Sql { default_port } => {
                sql_identity(left, default_port) == sql_identity(right, default_port)
            }
            Database::Foundation => same_cluster(
                &environment.cluster_file(left),
                &environment.cluster_file(right),
            ),
        }
}

pub(super) fn refuse_existing_store(target: &Path) -> Result<(), CommandError> {
    let Some(store) = local_store_path(target, &PathMap::default(), Side::Target)? else {
        return Ok(());
    };
    let path = store.path();
    let used = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => std::fs::read_dir(path)
            .map_err(|err| failed(&format!("cannot read {}", path.display()), err))?
            .next()
            .is_some(),
        Ok(_) => true,
        Err(_) => false,
    };
    if used {
        Err(CommandError::Usage(
            format!(
                "the v0.16 rollback target {} already exists; rollback writes into a new, empty location only",
                path.display()
            )
            .into_boxed_str(),
        ))
    } else {
        Ok(())
    }
}

async fn probe_schema(config: &Path, path_map: &PathMap) -> Result<StoreSchema, String> {
    let mut probe = SourceConfig::from_file(config).map_err(|err| err.to_string())?;
    probe.path_rewrite =
        rewrite(path_map).map(|rewrite| Box::new(rewrite) as source_v016::PathRewrite);
    V016Source::probe_schema(&probe)
        .await
        .map_err(|err| err.to_string())
}

async fn refuse_unless_v1(config: &Path, path_map: &PathMap) -> Result<(), CommandError> {
    let refusal = match probe_schema(config, path_map).await {
        Ok(StoreSchema::V1(version)) if source_v1::is_v1_schema(version) => return Ok(()),
        Ok(StoreSchema::V016(_)) => {
            "the rollback --source is a v0.16 store; rollback reads the migrated v1 store".into()
        }
        Ok(StoreSchema::V1(version)) => format!(
            "the rollback --source holds schema version {version}, which this build does not read"
        ),
        Ok(StoreSchema::Missing) => {
            "the rollback --source holds no schema version; it is not a v1 store".into()
        }
        Err(err) => format!(
            "cannot read the rollback --source without writing to it to check that it is a v1 store: {err}"
        ),
    };
    Err(CommandError::Usage(refusal.into_boxed_str()))
}

async fn refuse_v016_target(
    config: &Path,
    path_map: &PathMap,
    local: Option<&LocalStore>,
) -> Result<(), CommandError> {
    if local.is_some_and(|store| !store.holds_data()) {
        return Ok(());
    }
    match probe_schema(config, path_map).await {
        Ok(StoreSchema::V016(_)) => Err(CommandError::Usage(
            "the v1 --target is a v0.16 store; the target must be a separate, new store".into(),
        )),
        _ => Ok(()),
    }
}

pub(super) async fn open_rollback_source(
    source: &Path,
    path_map: &PathMap,
    target: &Path,
) -> Result<V1Source, CommandError> {
    let target_path = local_store_path(target, &PathMap::default(), Side::Target)?;
    if let (Some(target_path), Some(source_path)) = (
        &target_path,
        local_store_path(source, path_map, Side::Source)?,
    ) {
        refuse_overlap(&source_path, target_path, "data store")?;
    }
    if same_database(&store_definition(source)?, &store_definition(target)?) {
        return Err(CommandError::Usage(
            "the v0.16 rollback target is the database of the v1 source; the target must be a new, separate store".into(),
        ));
    }
    refuse_unless_v1(source, path_map).await?;
    let mut config = source_v1::SourceConfig::from_file(source)
        .map_err(|err| failed("cannot read the v1 configuration", err))?;
    config.path_rewrite =
        rewrite(path_map).map(|rewrite| Box::new(rewrite) as source_v1::PathRewrite);
    V1Source::open(config)
        .await
        .map_err(|err| failed("cannot open the v1 store", err))
}

pub(super) async fn open_rollback(
    source: V1Source,
    target: &Path,
    shared_deletes: SharedDeletes,
    claim: TargetClaim,
) -> Result<RollbackAdapters, CommandError> {
    let target = V016Target::open_claimed(
        target_v016::TargetConfig {
            data_store: target.to_path_buf(),
            shared_deletes,
        },
        claim,
    )
    .await
    .map_err(|err| failed("cannot open the v0.16 rollback target", err))?;
    let reader = V016Source::from_store(target.store().clone())
        .await
        .map_err(|err| failed("cannot read the v0.16 rollback target", err))?;
    Ok(RollbackAdapters {
        source: Arc::new(source),
        target: Arc::new(target),
        reader: Arc::new(reader),
    })
}

fn definition_hash(path: &Path) -> Result<String, CommandError> {
    let contents = std::fs::read(path)
        .map_err(|err| failed(&format!("cannot read {}", path.display()), err))?;
    let value: serde_json::Value = serde_json::from_slice(&contents)
        .map_err(|err| failed(&format!("cannot parse {}", path.display()), err))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|err| failed(&format!("cannot serialize {}", path.display()), err))?;
    let mut hex = String::with_capacity(32);
    for byte in ContentHash::of(&canonical).as_bytes() {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

pub(super) fn store_identity(config: &AdapterConfig) -> Result<StoreIdentity, CommandError> {
    Ok(StoreIdentity {
        source_def_hash: Some(definition_hash(&config.source)?),
        target_def_hash: Some(definition_hash(&config.target)?),
        source_store: local_store_path(&config.source, &config.path_map, Side::Source)?
            .map(|store| store.encode()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path, name: &str, kind: &str, path: &str) -> PathBuf {
        let config = dir.join(name);
        std::fs::write(
            &config,
            serde_json::json!({"@type": kind, "path": path}).to_string(),
        )
        .expect("config");
        config
    }

    // SQLite URIs are refused on both sides, whatever their case; RocksDB paths are literal.
    #[test]
    fn sqlite_uris_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let map = PathMap::default();
        for uri in [
            "file:/data/x.sqlite",
            "FILE:x.sqlite",
            "file:/d/x.sqlite%00/../y",
        ] {
            let config = store(dir.path(), "uri.json", "Sqlite", uri);
            for side in [Side::Source, Side::Target] {
                assert!(matches!(
                    local_store_path(&config, &map, side),
                    Err(CommandError::Usage(_))
                ));
            }
        }
        let config = store(dir.path(), "rocks.json", "RocksDb", "file:data");
        assert!(matches!(
            local_store_path(&config, &map, Side::Source),
            Ok(Some(LocalStore::Directory(path))) if path.ends_with("file:data")
        ));
    }

    // A SQLite target on a sidecar of the source, or whose sidecar is the source, is refused.
    #[test]
    fn sqlite_sidecars_overlap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("src.sqlite");
        std::fs::write(&source, b"data").expect("source");
        let sqlite = |path: &Path| LocalStore::Sqlite(resolved(path));
        for suffix in SQLITE_SIDECARS {
            let sidecar = dir.path().join(format!("src.sqlite{suffix}"));
            assert!(refuse_overlap(&sqlite(&source), &sqlite(&sidecar), "data store").is_err());
            assert!(refuse_overlap(&sqlite(&sidecar), &sqlite(&source), "data store").is_err());
        }
        let upper = dir.path().join("SRC.SQLITE-wal");
        assert!(refuse_overlap(&sqlite(&source), &sqlite(&upper), "data store").is_err());
        #[cfg(unix)]
        {
            let dangling = dir.path().join("dangling.sqlite");
            std::os::unix::fs::symlink(dir.path().join("src.sqlite-wal"), &dangling)
                .expect("symlink");
            assert!(refuse_overlap(&sqlite(&source), &sqlite(&dangling), "data store").is_err());
        }
        let other = dir.path().join("src.sqlite-other");
        assert!(refuse_overlap(&sqlite(&source), &sqlite(&other), "data store").is_ok());
        let rocks = LocalStore::Directory(resolved(&dir.path().join("src.sqlite-wal")));
        assert!(refuse_overlap(&sqlite(&source), &rocks, "data store").is_err());
    }

    // A state directory whose name differs from a store only by case overlaps it, even before either exists.
    #[test]
    fn case_variants_overlap_before_they_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalStore::Directory(resolved(&dir.path().join("dst")));
        let state = resolved(&dir.path().join("DST").join("state"));
        assert!(state_overlap(&state, &store, "target store").is_err());
        let sibling = resolved(&dir.path().join("dst-state"));
        assert!(state_overlap(&sibling, &store, "target store").is_ok());
    }

    // The rollback state may not resolve to, contain or lie inside the forward state, however it is spelled.
    #[test]
    fn forward_state_aliases_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let forward = dir.path().join("state");
        std::fs::create_dir(&forward).expect("forward");
        for alias in [
            dir.path().join("src").join("..").join("state"),
            dir.path().join("STATE"),
            forward.join("rollback"),
        ] {
            assert!(
                refuse_forward_state_overlap(&alias, &forward).is_err(),
                "{}",
                alias.display()
            );
        }
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&forward, &link).expect("symlink");
            assert!(refuse_forward_state_overlap(&link, &forward).is_err());
        }
        assert!(refuse_forward_state_overlap(&dir.path().join("rollback"), &forward).is_ok());
    }

    // Two configurations naming the same SQL database or FoundationDB cluster are one store.
    #[test]
    fn same_database_is_detected() {
        let pg = |host: &str, database: &str| serde_json::json!({"@type": "PostgreSql", "host": host, "port": 5432, "database": database});
        assert!(same_database(
            &pg("DB.local", "mail"),
            &pg("db.local", "mail")
        ));
        assert!(!same_database(
            &pg("db.local", "mail"),
            &pg("db.local", "rollback")
        ));
        let fdb = |file: &str| serde_json::json!({"@type": "FoundationDb", "clusterFile": file});
        assert!(same_database(
            &fdb("/etc/fdb.cluster"),
            &fdb("/etc/fdb.cluster")
        ));
        assert!(!same_database(
            &fdb("/etc/a.cluster"),
            &fdb("/etc/b.cluster")
        ));
        assert!(!same_database(
            &pg("db", "mail"),
            &serde_json::json!({"@type": "MySql", "host": "db", "port": 5432, "database": "mail"})
        ));
    }

    // Default ports, the default database, local host aliases and cluster files with the same contents name one store.
    #[test]
    fn database_identity_is_normalized() {
        let pg = serde_json::json!({"@type": "PostgreSql", "host": "localhost"});
        for same in [
            serde_json::json!({"@type": "PostgreSql", "host": "127.0.0.1", "port": 5432}),
            serde_json::json!({"@type": "PostgreSql", "host": "::1", "database": "Stalwart"}),
            serde_json::json!({"@type": "PostgreSql"}),
        ] {
            assert!(same_database(&pg, &same), "{same}");
        }
        for other in [
            serde_json::json!({"@type": "PostgreSql", "host": "localhost", "port": 5433}),
            serde_json::json!({"@type": "PostgreSql", "host": "db.local"}),
            serde_json::json!({"@type": "PostgreSql", "host": "localhost", "database": "other"}),
        ] {
            assert!(!same_database(&pg, &other), "{other}");
        }
        assert!(same_database(
            &serde_json::json!({"@type": "MySql", "host": "localhost"}),
            &serde_json::json!({"@type": "MySql", "host": "127.0.0.1", "port": 3306})
        ));

        let dir = tempfile::tempdir().expect("tempdir");
        let cluster = |name: &str, contents: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, contents).expect("cluster file");
            serde_json::json!({"@type": "FoundationDb", "clusterFile": path})
        };
        let main = cluster("a.cluster", "docker:abc@10.0.0.1:4500\n");
        assert!(same_database(
            &main,
            &cluster("b.cluster", "docker:abc@10.0.0.1:4500")
        ));
        assert!(!same_database(
            &main,
            &cluster("c.cluster", "docker:xyz@10.0.0.2:4500")
        ));
        let default = serde_json::json!({"@type": "FoundationDb"});
        let work = tempfile::tempdir().expect("work dir");
        std::fs::write(work.path().join("fdb.cluster"), "docker:abc@10.0.0.1:4500").expect("local");
        let elsewhere = cluster("d.cluster", "docker:other@10.0.0.9:4500");
        let decoy = tempfile::tempdir().expect("decoy dir");
        std::fs::write(
            decoy.path().join("fdb.cluster"),
            "docker:other@10.0.0.9:4500",
        )
        .expect("decoy");
        let from_env = ClientEnvironment {
            cluster_file: Some(dir.path().join("a.cluster").into_os_string()),
            current_dir: decoy.path().to_path_buf(),
        };
        assert!(same_database_in(&from_env, &default, &main));
        assert!(!same_database_in(&from_env, &default, &elsewhere));
        let local = ClientEnvironment {
            cluster_file: None,
            current_dir: work.path().to_path_buf(),
        };
        assert!(same_database_in(&local, &default, &main));
        assert!(same_database_in(
            &local,
            &default,
            &serde_json::json!({"@type": "FoundationDb", "clusterFile": "fdb.cluster"})
        ));
        assert!(!same_database_in(&local, &default, &elsewhere));
        let empty = tempfile::tempdir().expect("empty dir");
        let fallback = ClientEnvironment {
            cluster_file: None,
            current_dir: empty.path().to_path_buf(),
        };
        assert!(same_database_in(
            &fallback,
            &default,
            &serde_json::json!({"@type": "FoundationDb", "clusterFile": DEFAULT_CLUSTER_FILE})
        ));
        assert!(!same_database_in(&fallback, &default, &main));
    }

    // Hard links and directory aliases share files even when the paths differ.
    #[cfg(unix)]
    #[test]
    fn hard_links_and_aliases_share_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source.sqlite");
        std::fs::write(&source, b"data").expect("source");
        let link = dir.path().join("link.sqlite");
        std::fs::hard_link(&source, &link).expect("hard link");
        assert!(shares_files(&source, &link));
        assert!(
            refuse_overlap(
                &LocalStore::Sqlite(source.clone()),
                &LocalStore::Sqlite(link.clone()),
                "data store"
            )
            .is_err()
        );
        let other = dir.path().join("other.sqlite");
        assert!(!shares_files(&source, &other));

        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("inner")).expect("tree");
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&tree, &alias).expect("symlink");
        assert!(shares_files(&tree, &alias.join("inner").join("new")));
        assert!(shares_files(&alias.join("inner"), &tree));
    }
}
