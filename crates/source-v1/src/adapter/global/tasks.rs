/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{
    GlobalBatch, GlobalPage, Issue, IssueKind, RegistryKey, Severity, Subject, TaskRecord,
};
use registry::schema::{prelude::Deserialize as SerdeDeserialize, structs::Task};
use store::{
    Deserialize, IterateParams, Store, U64_LEN, ValueKey,
    write::{TaskId, TaskQueueClass, ValueClass, key::DeserializeBigEndian},
};

use super::id_cursor;
use crate::adapter::error::trc_error;

const TASK_KEY_LEN: usize = U64_LEN + 1;
const DERIVED_ID_KIND: u64 = 0b11 << 62;
const SINGLETON_ID_MARKER: u64 = 0b01 << 62;

fn key(id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
        id: TaskId::Assigned(id),
    }))
}

pub(super) async fn page(
    store: &Store,
    cursor: Option<&[u8]>,
    limit: usize,
) -> model::Result<GlobalPage> {
    let Some(first) = id_cursor(cursor)? else {
        return Ok(GlobalPage::last(GlobalBatch::Tasks(Vec::new())));
    };
    let limit = limit.max(1);
    let mut values = Vec::with_capacity(limit.min(1024));
    store
        .iterate(
            IterateParams::new(key(first), key(u64::MAX))
                .ascending()
                .limit(limit),
            |key, value| {
                if key.len() == TASK_KEY_LEN {
                    values.push((key.deserialize_be_u64(1)?, value.to_vec()));
                }
                Ok(values.len() < limit)
            },
        )
        .await
        .map_err(trc_error)?;

    let next = (values.len() == limit)
        .then(|| values.last().map(|(id, _)| id.to_be_bytes().to_vec()))
        .flatten();
    let mut records = Vec::with_capacity(values.len());
    let mut issues = Vec::new();
    for (id, value) in values {
        match <Task as Deserialize>::deserialize(&value)
            .map_err(|err| err.to_string())
            .and_then(|task| serde_json::to_value(&task).map_err(|err| err.to_string()))
        {
            Ok(json) => records.push(TaskRecord { id, json }),
            Err(err) => issues.push(Issue::new(
                Severity::Error,
                IssueKind::Skipped,
                Subject::Registry(RegistryKey::new(TaskRecord::OBJECT, id)),
                format!("undecodable v1 task: {err}"),
            )),
        }
    }
    Ok(GlobalPage {
        batch: GlobalBatch::Tasks(records),
        issues,
        next,
        resume: None,
    })
}

pub fn singleton_task_id(json: &serde_json::Value) -> Option<u64> {
    <Task as SerdeDeserialize>::deserialize(json)
        .ok()
        .and_then(|task| TaskId::singleton_of(&task))
}

pub fn is_singleton_task(json: &serde_json::Value) -> bool {
    singleton_task_id(json).is_some()
}

pub fn is_derived_task_id(id: u64) -> bool {
    id & DERIVED_ID_KIND != 0
}

pub fn is_singleton_task_id(id: u64) -> bool {
    id & DERIVED_ID_KIND == SINGLETON_ID_MARKER
}
