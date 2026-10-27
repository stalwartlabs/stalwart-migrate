/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write as _;

use model::{RegistryCounter, RegistryEntries, RegistryKey, RegistryRecord};
use registry::{
    schema::{
        prelude::{OBJ_SEQ_ID, Object, ObjectInner, ObjectType},
        structs::{TlsInternalReport, TlsReportPolicy},
    },
    types::EnumImpl,
};
use roaring::RoaringBitmap;
use serde_json::Value;
use store::{
    Deserialize, IterateParams, Store, U16_LEN, U64_LEN, ValueKey,
    write::{RegistryClass, ValueClass, key::DeserializeBigEndian},
};
use types::id::Id;
use utils::map::vec_map::KeyValue;

use super::error::{corrupt, trc_error};

const ITEM_KEY_LEN: usize = U16_LEN + U64_LEN;
const TYPE_PROBE_LIMIT: usize = 64;
const MAX_OBJECT_ID: u16 = 1024;
const OBJECT_PREFIX: &str = "x:";

fn item_key(object_type: ObjectType, item_id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::Registry(RegistryClass::Item {
        object_id: object_type.to_id(),
        item_id,
    }))
}

fn item_range(object_type: ObjectType, first: u64) -> IterateParams<ValueKey<ValueClass>> {
    IterateParams::new(
        item_key(object_type, first),
        item_key(object_type, u64::MAX),
    )
    .ascending()
}

fn object_type(name: &str) -> model::Result<ObjectType> {
    ObjectType::parse(name.strip_prefix(OBJECT_PREFIX).unwrap_or(name))
        .ok_or_else(|| model::Error::fatal(format!("unknown v0.16 registry object {name}")))
}

pub(super) async fn types(store: &Store) -> model::Result<Vec<Box<str>>> {
    let mut names = Vec::new();
    for id in 0..MAX_OBJECT_ID {
        let Some(object_type) = ObjectType::from_id(id) else {
            continue;
        };
        let mut found = false;
        store
            .iterate(
                item_range(object_type, 0)
                    .no_values()
                    .with_limit(TYPE_PROBE_LIMIT),
                |key, _| {
                    found = key.len() == ITEM_KEY_LEN;
                    Ok(!found)
                },
            )
            .await
            .map_err(trc_error)?;
        if found {
            names.push(Box::from(object_type.as_str()));
        }
    }
    Ok(names)
}

pub(super) fn canonical(record: RegistryRecord) -> model::Result<RegistryRecord> {
    let object_type = object_type(&record.key.object)?;
    let inner = ObjectInner::deserialize(object_type, &record.json)
        .map_err(|err| corrupt(format!("{}: not a valid v0.16 object: {err}", record.key)))?;
    let json = serde_json::to_value(Object::new(inner).into_value_with_secrets())
        .map_err(|err| corrupt(format!("{}: {err}", record.key)))?;
    let mut lost = Vec::new();
    lost_fields(&record.json, &json, &mut String::new(), &mut lost);
    if !lost.is_empty() {
        return Err(corrupt(format!(
            "{}: v0.16 does not know the fields {}",
            record.key,
            lost.join(", ")
        )));
    }
    Ok(RegistryRecord {
        key: record.key,
        json,
    })
}

fn lost_fields(input: &Value, output: &Value, path: &mut String, lost: &mut Vec<String>) {
    let mut visit = |name: &str, value: &Value, kept: Option<&Value>| {
        if value.is_null() {
            return;
        }
        let length = path.len();
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(name);
        match kept {
            Some(kept) => lost_fields(value, kept, path, lost),
            None => lost.push(path.clone()),
        }
        path.truncate(length);
    };
    match (input, output) {
        (Value::Object(input), Value::Object(output)) => {
            for (name, value) in input {
                visit(name, value, output.get(name));
            }
        }
        (Value::Array(input), Value::Object(output)) => {
            let mut name = String::new();
            for (index, value) in input.iter().enumerate() {
                name.clear();
                let _ = write!(name, "{index}");
                visit(&name, value, output.get(&name));
            }
        }
        (Value::Array(input), Value::Array(output)) => {
            let mut name = String::new();
            for (index, value) in input.iter().enumerate() {
                name.clear();
                let _ = write!(name, "{index}");
                visit(&name, value, output.get(index));
            }
        }
        _ => {}
    }
}

fn order_tls_policies(report: &mut TlsInternalReport) {
    let identifiers = report.policy_identifiers.inner_mut();
    let policies = &mut report.report.policies.0.inner;
    if identifiers.len() != policies.len() || identifiers.is_sorted() {
        return;
    }
    let mut pairs: Vec<(u64, TlsReportPolicy)> = identifiers
        .drain(..)
        .zip(policies.drain(..).map(|entry| entry.value))
        .collect();
    pairs.sort_unstable_by_key(|(identifier, _)| *identifier);
    for (key, (identifier, value)) in (0u32..).zip(pairs) {
        identifiers.push(identifier);
        policies.push(KeyValue { key, value });
    }
}

pub(super) async fn page(
    store: &Store,
    name: &str,
    after: Option<u64>,
    limit: usize,
) -> model::Result<RegistryEntries> {
    let object_type = object_type(name)?;
    let mut next = match after {
        Some(u64::MAX) => return Ok(RegistryEntries::default()),
        Some(after) => after + 1,
        None => 0,
    };
    let limit = limit.max(1);
    let mut objects = Vec::with_capacity(limit.min(1024));
    let mut unreadable = Vec::new();
    loop {
        let wanted = limit - objects.len();
        let mut scanned = 0;
        let mut last = None;
        store
            .iterate(
                item_range(object_type, next).with_limit(wanted),
                |key, value| {
                    scanned += 1;
                    if key.len() != ITEM_KEY_LEN {
                        return Ok(true);
                    }
                    let item_id = key.deserialize_be_u64(U16_LEN)?;
                    last = Some(item_id);
                    match <Object as Deserialize>::deserialize_with_key(key, value) {
                        Ok(object) => objects.push((item_id, object)),
                        Err(_) => unreadable.push(registry_key(name, item_id)),
                    }
                    Ok(objects.len() < limit)
                },
            )
            .await
            .map_err(trc_error)?;
        match last {
            Some(last) if scanned >= wanted && objects.len() < limit && last < u64::MAX => {
                next = last + 1;
            }
            _ => break,
        }
    }

    let mut records = Vec::with_capacity(objects.len());
    for (item_id, mut object) in objects {
        if let ObjectInner::TlsInternalReport(report) = &mut object.inner {
            order_tls_policies(report);
        }
        let json = serde_json::to_value(object.into_value_with_secrets())
            .map_err(|err| corrupt(format!("{name}/{item_id}: {err}")))?;
        records.push(RegistryRecord {
            key: registry_key(name, item_id),
            json,
        });
    }
    Ok(RegistryEntries {
        records,
        unreadable,
    })
}

fn registry_key(name: &str, item_id: u64) -> RegistryKey {
    if Id::new(item_id).is_singleton() {
        RegistryKey::singleton(name)
    } else {
        RegistryKey::new(name, item_id)
    }
}

pub(super) async fn account_ids(store: &Store) -> model::Result<RoaringBitmap> {
    let mut ids = RoaringBitmap::new();
    store
        .iterate(item_range(ObjectType::Account, 0).no_values(), |key, _| {
            if key.len() == ITEM_KEY_LEN
                && let Ok(account_id) = u32::try_from(key.deserialize_be_u64(U16_LEN)?)
            {
                ids.insert(account_id);
            }
            Ok(true)
        })
        .await
        .map_err(trc_error)?;
    Ok(ids)
}

pub(super) async fn id_counters(store: &Store) -> model::Result<Vec<RegistryCounter>> {
    let mut counters = Vec::new();
    for id in 0..MAX_OBJECT_ID {
        let Some(object_type) = ObjectType::from_id(id) else {
            continue;
        };
        if object_type.flags() & OBJ_SEQ_ID == 0 {
            continue;
        }
        let value = store
            .get_counter(ValueKey::from(ValueClass::Registry(
                RegistryClass::IdCounter {
                    object_id: object_type.to_id(),
                },
            )))
            .await
            .map_err(trc_error)?;
        if let Ok(value) = u64::try_from(value)
            && value > 0
        {
            counters.push(RegistryCounter {
                object: Box::from(object_type.as_str()),
                value,
            });
        }
    }
    Ok(counters)
}
