/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    BlobHash, CategorySet, Issue, IssueKind, RegistryKey, RegistryRecord, Severity, Source, Subject,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;

use super::super::{
    RegistryConverter,
    error::RunError,
    registry::{ConvertedRecord, read_registry, registry_categories},
    retry::{RetryPolicy, retry},
};

pub(super) struct RegistryCheck {
    pub(super) issues: Vec<Issue>,
    pub(super) unexplained: u64,
}

fn mismatch(key: &RegistryKey, message: &str) -> Issue {
    Issue::new(
        Severity::Verify,
        IssueKind::Mismatch,
        Subject::Registry(key.clone()),
        message,
    )
}

pub(super) struct RegistryHistory<'x> {
    pub(super) skipped: &'x FxHashSet<RegistryKey>,
    pub(super) tracked: &'x [Box<str>],
    pub(super) fell_back: &'x FxHashSet<RegistryKey>,
}

pub(super) async fn check<S: Source, R: Source, C: RegistryConverter>(
    source: &S,
    target: &R,
    converter: &C,
    categories: CategorySet,
    history: RegistryHistory<'_>,
    policy: RetryPolicy,
    limit: usize,
) -> Result<RegistryCheck, RunError> {
    let categories = registry_categories(categories);
    let objects = read_registry(source, policy, limit).await?;
    let stock = converter.missing_spam_tags(&objects);
    let converted = converter
        .convert(objects, categories)
        .map_err(|err| RunError::preflight(err.to_string()))?;
    let mut expected: FxHashMap<RegistryKey, Value> = converted
        .records
        .into_iter()
        .map(|ConvertedRecord { record, .. }| (record.key, record.json))
        .collect();
    for RegistryRecord { key, json } in converted.deferred {
        expected.insert(key, json);
    }
    let fallbacks: FxHashMap<RegistryKey, Value> = converted
        .fallbacks
        .into_iter()
        .filter(|record| history.fell_back.contains(&record.key))
        .filter_map(|record| target.canonical_registry(record).ok())
        .map(|RegistryRecord { key, json }| (key, json))
        .collect();
    let mut invalid = Vec::new();
    let mut canonical: FxHashMap<RegistryKey, Value> =
        FxHashMap::with_capacity_and_hasher(expected.len(), Default::default());
    for (key, json) in expected {
        match target.canonical_registry(RegistryRecord {
            key: key.clone(),
            json,
        }) {
            Ok(record) => {
                canonical.insert(key, record.json);
            }
            Err(err) => invalid.push((key, err)),
        }
    }
    invalid.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let RegistryHistory {
        skipped, tracked, ..
    } = history;
    let tracked: Vec<Box<str>> = tracked
        .iter()
        .map(|object| converter.target_object(object))
        .collect();
    let objects: FxHashSet<&str> = canonical
        .keys()
        .chain(invalid.iter().map(|(key, _)| key))
        .map(|key| &*key.object)
        .chain(tracked.iter().map(|object| &**object))
        .collect();
    let mut blobs: Vec<(BlobHash, RegistryKey)> = Vec::new();
    let stored: Vec<RegistryRecord> = read_registry(target, policy, limit)
        .await?
        .into_iter()
        .filter(|record| categories.contains(converter.category(&record.key.object)))
        .collect();
    let mut unlisted = Vec::new();
    for chunk in stored.chunks(limit.max(1)) {
        unlisted.extend(retry(policy, || target.unlisted_registry(chunk)).await?);
    }
    let mut actual: FxHashMap<RegistryKey, Value> = stored
        .into_iter()
        .map(|record| {
            if let Some(hash) = target.registry_blob(&record) {
                blobs.push((hash, record.key.clone()));
            }
            (record.key, record.json)
        })
        .collect();

    let mut result = RegistryCheck {
        issues: Vec::new(),
        unexplained: 0,
    };
    let mut report = |key: &RegistryKey, message: &str, explained: bool| {
        result.issues.push(mismatch(key, message));
        if !explained {
            result.unexplained += 1;
        }
    };
    for key in &unlisted {
        report(
            key,
            "the target stores the object but v1 cannot list or find it: its index entries are missing",
            false,
        );
    }
    for (key, err) in &invalid {
        actual.remove(key);
        report(
            key,
            &format!(
                "the converted source object is not a valid v1 object: {}",
                err.message()
            ),
            false,
        );
    }
    let mut expected: Vec<(&RegistryKey, &Value)> = canonical.iter().collect();
    expected.sort_unstable_by(|left, right| left.0.cmp(right.0));
    for (key, json) in expected {
        match actual.remove(key) {
            Some(actual) if actual == *json || fallbacks.get(key) == Some(&actual) => {}
            Some(_) => report(
                key,
                "the target object differs from the converted source object",
                false,
            ),
            None => report(
                key,
                "the converted source object is missing in the target",
                skipped.contains(key),
            ),
        }
    }
    for key in &converted.dropped {
        let key = RegistryKey {
            object: converter.target_object(&key.object),
            id: key.id,
        };
        if !canonical.contains_key(&key) && actual.remove(&key).is_some() {
            report(
                &key,
                "the object was dropped by the conversion but exists in the target",
                false,
            );
        }
    }
    for record in stock {
        if let Ok(record) = target.canonical_registry(record)
            && actual.get(&record.key) == Some(&record.json)
        {
            actual.remove(&record.key);
        }
    }
    let mut extra: Vec<RegistryKey> = actual
        .into_keys()
        .filter(|key| objects.contains(&*key.object))
        .collect();
    extra.sort_unstable();
    for key in &extra {
        report(
            key,
            "the target holds an object that is not in the source",
            false,
        );
    }
    blobs.sort_unstable_by(|left, right| left.1.cmp(&right.1));
    let mut hashes = Vec::with_capacity(limit.min(blobs.len()));
    for chunk in blobs.chunks(limit.max(1)) {
        hashes.clear();
        hashes.extend(chunk.iter().map(|(hash, _)| *hash));
        let exist = retry(policy, || target.blobs_exist(&hashes)).await?;
        for ((hash, key), exists) in chunk.iter().zip(exist) {
            if !exists {
                report(
                    key,
                    &format!("blob {hash} referenced by the object is missing in the target"),
                    false,
                );
            }
        }
    }
    Ok(result)
}
