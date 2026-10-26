/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![cfg(feature = "rocks")]

use std::{path::Path, sync::Arc};

use bytes::Bytes;
use model::{BlobHash, Edition, RegistryKey, RegistryRecord, Target};
use serde_json::json;
use store::blake3;
use target_v1::{PathRewrite, TargetConfig, V1Target};

#[cfg(feature = "enterprise")]
const EDITION: Edition = Edition::Enterprise;
#[cfg(not(feature = "enterprise"))]
const EDITION: Edition = Edition::Community;
const CONTAINER: &str = "/opt/stalwart-container";
const BLOB: &[u8] = b"blob stored through a rewritten file system path";

// Container paths in the data store file and in a FileSystem blob store resolve on the host through the rewrite.
#[tokio::test(flavor = "multi_thread")]
async fn container_paths_are_rewritten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host = dir.path().to_string_lossy().into_owned();
    let config = dir.path().join("target.json");
    std::fs::write(
        &config,
        json!({"@type": "RocksDb", "path": format!("{CONTAINER}/data")}).to_string(),
    )
    .expect("write config");
    let rewrite: PathRewrite = Arc::new(move |path: &str| match path.strip_prefix(CONTAINER) {
        Some(rest) => format!("{host}{rest}"),
        None => path.to_string(),
    });
    let target = V1Target::open_with_rewrite(
        TargetConfig {
            data_store: config,
            fdb_txn_bytes: 9_000_000,
        },
        Some(rewrite),
    )
    .await
    .expect("open target");
    assert_eq!(target.created_paths(), [dir.path().join("data")]);
    assert!(dir.path().join("data").exists());
    target.prepare_store(EDITION).await.expect("prepare");
    let outcome = target
        .write_registry(&[RegistryRecord {
            key: RegistryKey::singleton("BlobStore"),
            json: json!({"@type": "FileSystem", "path": format!("{CONTAINER}/blobs"), "depth": 2}),
        }])
        .await
        .expect("registry");
    assert!(outcome.issues.is_empty(), "{:?}", outcome.issues);
    target.start_server().await.expect("server");
    target
        .put_blob(
            &BlobHash(*blake3::hash(BLOB).as_bytes()),
            Bytes::from_static(BLOB),
        )
        .await
        .expect("blob");
    assert!(has_files(&dir.path().join("blobs")));
    assert!(!Path::new(CONTAINER).exists());
}

fn has_files(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.path().is_file() || has_files(&entry.path()))
    })
}
