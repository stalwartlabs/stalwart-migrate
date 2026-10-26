/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::Path;

use model::TargetProbe;
use registry::schema::structs::DataStore;
use store::{Rows, Store, Subspace, Value};

use crate::{
    error::{fatal, trc_error},
    store_stage::probe,
};

const LOST_FOUND: &[u8] = b"lost+found";
const FOREIGN: &str = "the v1 target is an existing store that this tool did not create; the migration writes only into a new empty v1 store and never opens another one for writing";
const CANNOT_CHECK: &str =
    "cannot check that the v1 target is a new empty store, refusing to open it";
const SQLITE_OBJECTS: &str =
    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'";
const POSTGRES_OBJECTS: &str = "SELECT CASE WHEN n.nspname = current_schema() THEN c.relname::text ELSE n.nspname || '.' || c.relname END, c.relkind::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 'c') AND n.nspname = ANY(current_schemas(false)) AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_%' AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')";
const TABLE_KIND: &str = "r";
const MYSQL_OBJECTS: &str =
    "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()";
const MYSQL_COLUMNS: &str = "SELECT table_name, GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',') FROM information_schema.columns WHERE table_schema = DATABASE() GROUP BY table_name";

enum Layout {
    Fixed,
    Tables(Vec<Subspace>),
    Foreign(Box<str>),
}

enum Verdict {
    Probed(TargetProbe),
    ForeignObject(Box<str>),
}

pub(crate) fn has_entries(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.as_encoded_bytes();
            name != LOST_FOUND && !name.starts_with(b".")
        })
    })
}

async fn open_read_only(definition: &DataStore) -> model::Result<Option<Store>> {
    let exists = match definition {
        DataStore::RocksDb(config) => has_entries(Path::new(&config.path)),
        DataStore::Sqlite(config) => Path::new(&config.path).exists(),
        _ => true,
    };
    if !exists {
        return Ok(None);
    }
    Store::build_read_only(definition.clone())
        .await
        .map(Some)
        .map_err(|err| fatal(format!("{CANNOT_CHECK}: {err}")))
}

fn table_subspace(name: &str) -> Option<Subspace> {
    let [byte] = name.as_bytes() else {
        return None;
    };
    Subspace::ALL
        .iter()
        .copied()
        .find(|subspace| subspace.byte() == *byte)
}

fn is_search_table(name: &str) -> bool {
    hashify::set!(
        name.as_bytes(),
        "s_email",
        "s_cal",
        "s_card",
        "s_file",
        "s_trace"
    )
}

#[cfg(feature = "sqlite")]
pub(crate) fn is_store_table(name: &str) -> bool {
    table_subspace(name).is_some() || is_search_table(name)
}

fn is_store_columns(columns: &str) -> bool {
    hashify::set!(columns.as_bytes(), "k", "k,v")
}

fn table_name<'x>(value: &'x Value<'_>) -> Option<&'x str> {
    match value {
        Value::Text(text) => Some(text.as_ref()),
        Value::Blob(bytes) => std::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

async fn layout(store: &Store, definition: &DataStore) -> model::Result<Layout> {
    let query = match definition {
        DataStore::Sqlite(_) => SQLITE_OBJECTS,
        DataStore::PostgreSql(_) => POSTGRES_OBJECTS,
        DataStore::MySql(_) => MYSQL_OBJECTS,
        #[cfg(feature = "foundation")]
        DataStore::FoundationDb(config) => {
            return Ok(
                match crate::fdb_probe::foreign_prefix(config, |byte| {
                    Subspace::ALL.iter().any(|subspace| subspace.byte() == byte)
                })
                .await?
                {
                    Some(prefix) => Layout::Foreign(prefix),
                    None => Layout::Fixed,
                },
            );
        }
        #[cfg(not(feature = "foundation"))]
        DataStore::FoundationDb(_) => return Ok(Layout::Fixed),
        DataStore::RocksDb(_) => return Ok(Layout::Fixed),
    };
    let tables = store
        .sql_query::<Rows>(query, Vec::new())
        .await
        .map_err(trc_error)?;
    let mut present = Vec::new();
    for row in tables.rows {
        let Some(name) = row.values.first().and_then(table_name) else {
            continue;
        };
        if let Some(kind) = row.values.get(1).and_then(table_name)
            && kind != TABLE_KIND
        {
            return Ok(Layout::Foreign(
                format!("the table {name} (relation kind {kind})").into(),
            ));
        }
        if let Some(subspace) = table_subspace(name) {
            present.push(subspace);
        } else if !is_search_table(name) {
            return Ok(Layout::Foreign(format!("the table {name}").into()));
        }
    }
    if matches!(definition, DataStore::MySql(_)) && !present.is_empty() {
        let columns = store
            .sql_query::<Rows>(MYSQL_COLUMNS, Vec::new())
            .await
            .map_err(trc_error)?;
        for row in columns.rows {
            let [name, columns, ..] = row.values.as_slice() else {
                continue;
            };
            let (Some(name), Some(columns)) = (table_name(name), table_name(columns)) else {
                continue;
            };
            if table_subspace(name).is_some() && !is_store_columns(columns) {
                return Ok(Layout::Foreign(
                    format!("the table {name} with the columns {columns}").into(),
                ));
            }
        }
    }
    Ok(Layout::Tables(present))
}

async fn verdict(store: &Store, definition: &DataStore) -> model::Result<Verdict> {
    Ok(match layout(store, definition).await? {
        Layout::Fixed => Verdict::Probed(probe(store, |_| true).await?),
        Layout::Tables(present) => {
            Verdict::Probed(probe(store, |subspace| present.contains(&subspace)).await?)
        }
        Layout::Foreign(table) => Verdict::ForeignObject(format!("it holds {table}").into()),
    })
}

#[cfg(feature = "rocks")]
fn has_v1_column_families(path: &str) -> model::Result<bool> {
    store::backend::rocksdb::RocksDbStore::has_v1_column_families(Path::new(path))
        .map_err(|err| fatal(format!("{CANNOT_CHECK}: {err}")))
}

#[cfg(not(feature = "rocks"))]
fn has_v1_column_families(_: &str) -> model::Result<bool> {
    Ok(true)
}

async fn checked_verdict(definition: &DataStore) -> model::Result<Option<Verdict>> {
    if let DataStore::RocksDb(config) = definition
        && has_entries(Path::new(&config.path))
        && !has_v1_column_families(&config.path)?
    {
        return Ok(Some(Verdict::ForeignObject(
            "it lacks the v1 column families".into(),
        )));
    }
    let Some(store) = open_read_only(definition).await? else {
        return Ok(None);
    };
    let verdict = verdict(&store, definition).await;
    drop(store);
    verdict
        .map(Some)
        .map_err(|err| fatal(format!("{CANNOT_CHECK}: {err}")))
}

pub(crate) async fn probe_definition(definition: &DataStore) -> model::Result<TargetProbe> {
    Ok(match checked_verdict(definition).await? {
        None => TargetProbe::Empty,
        Some(Verdict::Probed(probed)) => probed,
        Some(Verdict::ForeignObject(_)) => TargetProbe::Foreign,
    })
}

pub(crate) async fn refuse_foreign_store(definition: &DataStore) -> model::Result<()> {
    match checked_verdict(definition).await? {
        None | Some(Verdict::Probed(TargetProbe::Empty | TargetProbe::Initialized { .. })) => {
            Ok(())
        }
        Some(Verdict::Probed(TargetProbe::Foreign)) => Err(fatal(FOREIGN)),
        Some(Verdict::ForeignObject(detail)) => Err(fatal(format!("{FOREIGN} ({detail})"))),
    }
}
