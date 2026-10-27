/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{BlobHash, RegistryCounter, RegistryEntries, RegistryId, RegistryKey, RegistryRecord};
use registry::{
    schema::prelude::{OBJ_NOT_STORED, OBJ_SEQ_ID, Object, ObjectInner, ObjectType},
    types::{EnumImpl, datetime::UTCDateTime},
};
use roaring::RoaringBitmap;
use serde_json::Value;
use smtp::reporting::index::ExternalReportIndex;
use store::{
    Deserialize, IterateParams, Store, U16_LEN, U64_LEN, ValueKey,
    write::{
        BatchBuilder, Operation, RegistryClass, TaskId, ValueClass, ValueOp,
        key::DeserializeBigEndian,
    },
};
use trc::Key;
use types::id::Id;

use super::error::{corrupt, trc_error};

const ITEM_KEY_LEN: usize = U16_LEN + U64_LEN;
const TYPE_PROBE_LIMIT: usize = 64;
const MAX_OBJECT_ID: u16 = 1024;
const OBJECT_PREFIX: &str = "x:";
const EXPIRES_AT: &str = "expiresAt";
const NOT_VALID_AFTER: &str = "notValidAfter";
const FILE_BACKED: [&str; 2] = ["certificate", "privateKey"];
const TYPE_TAG: &str = "@type";
const FILE_TYPE: &str = "File";

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

fn prefixed(object_type: ObjectType) -> Box<str> {
    let name = object_type.as_str();
    let mut prefixed = String::with_capacity(OBJECT_PREFIX.len() + name.len());
    prefixed.push_str(OBJECT_PREFIX);
    prefixed.push_str(name);
    prefixed.into_boxed_str()
}

fn object_type(name: &str) -> model::Result<ObjectType> {
    ObjectType::parse(name.strip_prefix(OBJECT_PREFIX).unwrap_or(name))
        .ok_or_else(|| model::Error::fatal(format!("unknown v1 registry object {name}")))
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
                    .limit(TYPE_PROBE_LIMIT),
                |key, _| {
                    found = key.len() == ITEM_KEY_LEN;
                    Ok(!found)
                },
            )
            .await
            .map_err(trc_error)?;
        if found {
            names.push(prefixed(object_type));
        }
    }
    Ok(names)
}

pub(super) async fn page(
    store: &Store,
    name: &str,
    after: Option<u64>,
    limit: usize,
) -> model::Result<RegistryEntries> {
    let object_type = object_type(name)?;
    let name = prefixed(object_type);
    let first = match after {
        Some(u64::MAX) => return Ok(RegistryEntries::default()),
        Some(after) => after + 1,
        None => 0,
    };
    let limit = limit.max(1);
    let mut raw = Vec::with_capacity(limit.min(1024));
    store
        .iterate(item_range(object_type, first).limit(limit), |key, value| {
            if key.len() == ITEM_KEY_LEN {
                raw.push((key.to_vec(), value.to_vec()));
            }
            Ok(raw.len() < limit)
        })
        .await
        .map_err(trc_error)?;

    let mut records = Vec::with_capacity(raw.len());
    for (key, value) in raw {
        let item_id = key
            .as_slice()
            .deserialize_be_u64(U16_LEN)
            .map_err(trc_error)?;
        let object =
            <Object as Deserialize>::deserialize_with_key(&key, &value).map_err(|mut err| {
                err.take_value(Key::Value);
                corrupt(format!("{name}/{item_id}: {err}"))
            })?;
        let json = serde_json::to_value(&object.inner)
            .map_err(|err| corrupt(format!("{name}/{item_id}: {err}")))?;
        let key = if Id::new(item_id).is_singleton() {
            RegistryKey::singleton(name.clone())
        } else {
            RegistryKey::new(name.clone(), item_id)
        };
        records.push(RegistryRecord { key, json });
    }
    Ok(RegistryEntries {
        records,
        unreadable: Vec::new(),
    })
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

pub fn is_stored(name: &str) -> bool {
    ObjectType::parse(name.strip_prefix(OBJECT_PREFIX).unwrap_or(name)).is_none_or(|object_type| {
        object_type.flags() & OBJ_NOT_STORED == 0 || object_type == ObjectType::DataStore
    })
}

fn expiring_type(name: &str) -> Option<ObjectType> {
    ObjectType::parse(name.strip_prefix(OBJECT_PREFIX).unwrap_or(name)).filter(|object_type| {
        matches!(
            object_type,
            ObjectType::BlockedIp | ObjectType::AllowedIp | ObjectType::Certificate
        )
    })
}

pub fn expires_on_start(name: &str) -> bool {
    expiring_type(name).is_some()
}

pub fn is_certificate(name: &str) -> bool {
    expiring_type(name) == Some(ObjectType::Certificate)
}

pub fn refreshed_on_start(name: &str, json: &Value) -> bool {
    is_certificate(name)
        && FILE_BACKED.iter().any(|field| {
            json.get(field)
                .and_then(|text| text.get(TYPE_TAG))
                .and_then(Value::as_str)
                == Some(FILE_TYPE)
        })
}

pub fn expired_at(record: &RegistryRecord) -> Option<&str> {
    let field = match expiring_type(&record.key.object)? {
        ObjectType::Certificate if refreshed_on_start(&record.key.object, &record.json) => {
            return None;
        }
        ObjectType::Certificate => NOT_VALID_AFTER,
        _ => EXPIRES_AT,
    };
    let at = record.json.get(field)?.as_str()?;
    at.parse::<UTCDateTime>()
        .is_ok_and(|parsed| parsed.timestamp() <= UTCDateTime::now().timestamp())
        .then_some(at)
}

pub(super) fn canonical(record: RegistryRecord) -> model::Result<RegistryRecord> {
    let object_type = object_type(&record.key.object)?;
    let inner = ObjectInner::deserialize(object_type, &record.json)
        .map_err(|err| corrupt(format!("{}: not a valid v1 object: {err}", record.key)))?;
    let json =
        serde_json::to_value(&inner).map_err(|err| corrupt(format!("{}: {err}", record.key)))?;
    let id = match &inner {
        ObjectInner::Task(task) => TaskId::singleton_of(task).map_or(record.key.id, RegistryId::Id),
        _ => record.key.id,
    };
    Ok(RegistryRecord {
        key: RegistryKey {
            object: prefixed(object_type),
            id,
        },
        json,
    })
}

fn stock_lookup_keys(object: &ObjectInner, item_id: u64, batch: &mut BatchBuilder) -> bool {
    match object {
        ObjectInner::DmarcExternalReport(report) => report.write_ops(batch, item_id, true),
        ObjectInner::TlsExternalReport(report) => report.write_ops(batch, item_id, true),
        ObjectInner::ArfExternalReport(report) => report.write_ops(batch, item_id, true),
        _ => return false,
    }
    true
}

pub(super) async fn unlisted(
    store: &Store,
    records: &[RegistryRecord],
) -> model::Result<Vec<RegistryKey>> {
    let mut unlisted = Vec::new();
    for record in records {
        let RegistryId::Id(item_id) = record.key.id else {
            continue;
        };
        let Ok(object_type) = object_type(&record.key.object) else {
            continue;
        };
        let Ok(object) = ObjectInner::deserialize(object_type, &record.json) else {
            continue;
        };
        let mut batch = BatchBuilder::new();
        if !stock_lookup_keys(&object, item_id, &mut batch) {
            continue;
        }
        for operation in batch.ops() {
            let Operation::Value {
                class:
                    class @ ValueClass::Registry(
                        RegistryClass::Index { .. } | RegistryClass::PrimaryKey { .. },
                    ),
                op: ValueOp::Set(_),
            } = operation
            else {
                continue;
            };
            if !store
                .key_exists(ValueKey::from(class.clone()))
                .await
                .map_err(trc_error)?
            {
                unlisted.push(record.key.clone());
                break;
            }
        }
    }
    Ok(unlisted)
}

pub(super) fn blob(record: &RegistryRecord) -> Option<BlobHash> {
    let object_type = object_type(&record.key.object).ok()?;
    if !holds_blob(object_type) {
        return None;
    }
    match ObjectInner::deserialize(object_type, &record.json).ok()? {
        ObjectInner::SpamTrainingSample(sample) => Some(BlobHash(sample.blob_id.hash.0)),
        #[cfg(feature = "enterprise")]
        ObjectInner::ArchivedItem(item) => Some(BlobHash(item.blob_id().hash.0)),
        _ => None,
    }
}

const fn holds_blob(object_type: ObjectType) -> bool {
    match object_type {
        ObjectType::SpamTrainingSample => true,
        #[cfg(feature = "enterprise")]
        ObjectType::ArchivedItem => true,
        _ => false,
    }
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
                object: prefixed(object_type),
                value,
            });
        }
    }
    Ok(counters)
}
