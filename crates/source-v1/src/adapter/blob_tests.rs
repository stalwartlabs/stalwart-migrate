/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{path::Path, sync::Arc};

use model::{BlobHash, Source};
use registry::{
    schema::{
        enums::{CompressionAlgo, SymmetricCipher},
        prelude::{ObjectInner, ObjectType},
        structs::{self, DataStore, RocksDbStore, SecretKey, SymmetricKey},
    },
    types::EnumImpl,
};
use store::{
    BlobStore, Store, blake3,
    write::{
        BatchBuilder, RegistryClass, ValueClass,
        blob_codec::{BlobEncryption, BlobKey, BlobOpts},
    },
};

use super::V1Source;

const KEY_ID: u64 = 3;
const SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const BODY: &[u8] = b"Subject: encrypted at rest\r\n\r\nzstd and AES-256-GCM\r\n";

async fn open(path: &Path) -> Store {
    Store::build(DataStore::RocksDb(RocksDbStore {
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    }))
    .await
    .expect("open v1 store")
}

async fn put_key(store: &Store, key: SecretKey) {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::SymmetricKey.to_id(),
            item_id: KEY_ID,
        }),
        ObjectInner::SymmetricKey(Box::new(SymmetricKey {
            description: "blobs".into(),
            cipher: SymmetricCipher::Aes256Gcm,
            key,
            fingerprint: String::new(),
        }))
        .to_pickled_vec(),
    );
    store.write_batch(&mut batch).await.expect("key");
}

async fn put_encrypted(store: &Store) -> BlobHash {
    let hash = BlobHash(*blake3::hash(BODY).as_bytes());
    let key = BlobKey::from_base64(KEY_ID as u32, SymmetricCipher::Aes256Gcm, SECRET).expect("key");
    BlobStore::Store(store.clone())
        .put_blob(
            hash.as_bytes(),
            BODY,
            &BlobOpts::new(CompressionAlgo::Zstd, BlobEncryption::Key(Arc::new(key))),
        )
        .await
        .expect("blob");
    hash
}

// A blob v1.0.3 compressed and encrypted with a SymmetricKey is read back as plaintext.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_blobs_are_decrypted_with_the_v1_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path()).await;
    put_key(
        &store,
        SecretKey::Value(structs::SecretKeyValue {
            secret: SECRET.into(),
        }),
    )
    .await;
    let hash = put_encrypted(&store).await;
    let source = V1Source::from_store(store);
    let blob = source
        .read_blob(&hash)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(&blob[..], BODY);
    assert_eq!(source.blobs_exist(&[hash]).await.expect("exists"), [true]);
}

// A key file is read through the path map, so a key the v1 host keeps elsewhere still decrypts.
#[tokio::test(flavor = "multi_thread")]
async fn key_files_follow_the_path_map() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("data")).await;
    std::fs::write(dir.path().join("blob.key"), SECRET).expect("key file");
    put_key(
        &store,
        SecretKey::File(structs::SecretKeyFile {
            file_path: "/etc/stalwart/blob.key".into(),
        }),
    )
    .await;
    let hash = put_encrypted(&store).await;
    let local = dir.path().to_string_lossy().into_owned();
    let source = V1Source::from_store_with_rewrite(
        store,
        Some(Box::new(move |path: &str| {
            path.replace("/etc/stalwart", &local)
        })),
    );
    let blob = source
        .read_blob(&hash)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(&blob[..], BODY);
}

// A key whose secret cannot be read stops the read with an error naming the key.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_keys_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path()).await;
    put_key(
        &store,
        SecretKey::EnvironmentVariable(structs::SecretKeyEnvironmentVariable {
            variable_name: "STALWART_MIGRATE_TEST_UNSET_BLOB_KEY".into(),
        }),
    )
    .await;
    let hash = put_encrypted(&store).await;
    let err = V1Source::from_store(store)
        .read_blob(&hash)
        .await
        .expect_err("unreadable key");
    assert!(err.to_string().contains("SymmetricKey/3"), "{err}");
}
