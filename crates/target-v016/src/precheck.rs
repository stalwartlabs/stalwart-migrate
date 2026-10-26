/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::Path;

use model::TargetProbe;
use registry::schema::structs::DataStore;
use store::{Rows, Store, Value};

use crate::{
    error::{fatal, trc_error},
    store_stage::{SUBSPACES, is_store_table, probe},
};

const CANNOT_CHECK: &str =
    "cannot check that the rollback target is a new empty v0.16 store, refusing to open it";
const SQLITE_OBJECTS: &str =
    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'";
const POSTGRES_OBJECTS: &str = "SELECT CASE WHEN n.nspname = current_schema() THEN c.relname::text ELSE n.nspname || '.' || c.relname END, c.relkind::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 'c') AND n.nspname = ANY(current_schemas(false)) AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_%' AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')";
const TABLE_KIND: &str = "r";
const MYSQL_OBJECTS: &str =
    "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()";
const MYSQL_COLUMNS: &str = "SELECT table_name, GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',') FROM information_schema.columns WHERE table_schema = DATABASE() GROUP BY table_name";
const LOST_FOUND: &[u8] = b"lost+found";
const FOREIGN: &str = "the rollback target is an existing store that rollback did not create; rollback writes only into a new empty v0.16 store and never opens another one for writing";

pub(crate) fn has_entries(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.as_encoded_bytes();
            name != LOST_FOUND && !name.starts_with(b".")
        })
    })
}

enum Layout {
    Fixed,
    Tables(Vec<u8>),
    Foreign(Box<str>),
}

async fn open_read_only(definition: &DataStore) -> model::Result<Option<Store>> {
    let opened = match definition {
        DataStore::RocksDb(config) => {
            if !has_entries(Path::new(&config.path)) {
                return Ok(None);
            }
            open_rocksdb(config.clone()).await
        }
        DataStore::Sqlite(config) => {
            if !Path::new(&config.path).exists() {
                return Ok(None);
            }
            open_sqlite(config.clone())
        }
        DataStore::PostgreSql(_) | DataStore::MySql(_) | DataStore::FoundationDb(_) => {
            Store::build(definition.clone()).await
        }
    };
    opened.map(Some).map_err(|err| {
        fatal(format!(
            "cannot open the existing v0.16 target read-only to check it: {err}"
        ))
    })
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
                    byte == store::SUBSPACE_SEARCH_INDEX || SUBSPACES.contains(&byte)
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
    for row in &tables.rows {
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
        match name.as_bytes() {
            [byte] if is_store_table(name) => present.push(*byte),
            _ if is_store_table(name) => {}
            _ => return Ok(Layout::Foreign(format!("the table {name}").into())),
        }
    }
    if matches!(definition, DataStore::MySql(_)) && !present.is_empty() {
        let columns = store
            .sql_query::<Rows>(MYSQL_COLUMNS, Vec::new())
            .await
            .map_err(trc_error)?;
        for row in &columns.rows {
            let [name, columns, ..] = row.values.as_slice() else {
                continue;
            };
            let (Some(name), Some(columns)) = (table_name(name), table_name(columns)) else {
                continue;
            };
            if matches!(name.as_bytes(), [byte] if SUBSPACES.contains(byte))
                && !is_store_columns(columns)
            {
                return Ok(Layout::Foreign(
                    format!("the table {name} with the columns {columns}").into(),
                ));
            }
        }
    }
    Ok(Layout::Tables(present))
}

async fn foreign_reason(store: &Store, definition: &DataStore) -> model::Result<Option<Box<str>>> {
    let probed = match layout(store, definition).await? {
        Layout::Fixed => probe(store, |_| true).await?,
        Layout::Tables(present) => probe(store, |subspace| present.contains(&subspace)).await?,
        Layout::Foreign(table) => {
            return Ok(Some(format!("{FOREIGN} (it holds {table})").into()));
        }
    };
    Ok(matches!(probed, TargetProbe::Foreign).then(|| FOREIGN.into()))
}

#[cfg(feature = "rocks")]
async fn open_rocksdb(config: registry::schema::structs::RocksDbStore) -> Result<Store, String> {
    use store::backend::rocksdb::{RocksDbOpenMode, RocksDbStore};
    RocksDbStore::open_with_mode(config, RocksDbOpenMode::ReadOnly).await
}

#[cfg(not(feature = "rocks"))]
async fn open_rocksdb(_: registry::schema::structs::RocksDbStore) -> Result<Store, String> {
    Err("Binary was not compiled with RocksDB support".to_string())
}

#[cfg(feature = "sqlite")]
fn open_sqlite(config: registry::schema::structs::SqliteStore) -> Result<Store, String> {
    use store::backend::sqlite::{SqliteStore, main::SqliteReadOnlyMode};

    let path = config.path.clone();
    match SqliteStore::open_read_only(config)? {
        (store, SqliteReadOnlyMode::Immutable) => Ok(store),
        (_, SqliteReadOnlyMode::Live) => Err(format!(
            "SQLite database {path} has a -wal file that was not checkpointed; stop every server using it so it closes cleanly"
        )),
    }
}

#[cfg(not(feature = "sqlite"))]
fn open_sqlite(_: registry::schema::structs::SqliteStore) -> Result<Store, String> {
    Err("Binary was not compiled with SQLite support".to_string())
}

pub(crate) async fn refuse_foreign_store(definition: &DataStore) -> model::Result<()> {
    let Some(store) = open_read_only(definition).await? else {
        return Ok(());
    };
    let verdict = foreign_reason(&store, definition).await;
    drop(store);
    match verdict {
        Ok(None) => Ok(()),
        Ok(Some(reason)) => Err(fatal(reason)),
        Err(err) => Err(fatal(format!("{CANNOT_CHECK}: {err}"))),
    }
}
