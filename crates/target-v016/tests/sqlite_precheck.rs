/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "sqlite")]

use serde_json::json;
use target_v016::{SharedDeletes, TargetConfig, V016Target};

// Tables whose names only look like SQLite internals, and views, make an SQLite rollback target foreign; it is left byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn sqlite_lookalike_table_and_view_are_foreign() {
    for sql in [
        "CREATE TABLE SQLiteStudioData (id INTEGER);",
        "CREATE TABLE sqliteXdata (id INTEGER);",
        "CREATE VIEW recent AS SELECT 1 AS one;",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("store.sqlite");
        rusqlite::Connection::open(&file)
            .expect("sqlite")
            .execute_batch(sql)
            .expect("foreign objects");
        let before = std::fs::read(&file).expect("read");
        let config = dir.path().join("target.json");
        std::fs::write(
            &config,
            json!({"@type": "Sqlite", "path": file.to_string_lossy()}).to_string(),
        )
        .expect("write config");
        assert!(
            V016Target::open(TargetConfig {
                data_store: config,
                shared_deletes: SharedDeletes::Forbid,
            })
            .await
            .is_err(),
            "an SQLite store holding {sql} was opened"
        );
        assert_eq!(std::fs::read(&file).expect("read"), before, "{sql}");
        let mut names = std::fs::read_dir(dir.path())
            .expect("dir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, ["store.sqlite", "target.json"], "{sql}");
    }
}
