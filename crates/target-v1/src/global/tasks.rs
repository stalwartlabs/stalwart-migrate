/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{Issue, TaskRecord};
use registry::schema::structs::Task;
use serde::Deserialize;
use store::write::{BatchBuilder, TaskId, TaskQueueClass, ValueClass};

use super::skipped;
use crate::{
    prefetch::{Prefetched, keep_last},
    target::V1Target,
};

struct ParsedTask {
    id: u64,
    record_id: u64,
    singleton: bool,
    task: Task,
}

impl V1Target {
    pub(super) async fn write_tasks(&self, records: &[TaskRecord]) -> model::Result<Vec<Issue>> {
        let mut issues = Vec::new();
        let mut parsed = Vec::with_capacity(records.len());
        for record in records {
            match Task::deserialize(&record.json) {
                Ok(task) => {
                    let singleton = TaskId::singleton_of(&task);
                    parsed.push(ParsedTask {
                        id: singleton.unwrap_or(record.id),
                        record_id: record.id,
                        singleton: singleton.is_some(),
                        task,
                    });
                }
                Err(err) => issues.push(skipped(
                    TaskRecord::OBJECT,
                    record.id,
                    format!("invalid v1 task: {err}"),
                )),
            }
        }
        let parsed = keep_last(parsed.into_iter(), |task| task.id);
        let current = self
            .prefetch(parsed.iter().map(|task| task_key(task.id)))
            .await?;
        let mut batch = self.global_batch();
        for task in parsed {
            let id = TaskId::Assigned(task.id);
            if let Some(scheduled) = current.get::<Task>(task_key(task.id))? {
                batch.batch.clear(due_key(id, &scheduled));
            }
            if task.singleton {
                batch.batch.schedule_task(task.task);
            } else {
                batch.batch.schedule_task_with_id(task.record_id, task.task);
            }
            batch.record_done(0);
        }
        batch.commit(&self.store).await?;
        Ok(issues)
    }
}

pub(super) fn task_key(id: u64) -> ValueClass {
    ValueClass::TaskQueue(TaskQueueClass::Task {
        id: TaskId::Assigned(id),
    })
}

pub(super) fn delete_task(
    batch: &mut BatchBuilder,
    current: &Prefetched,
    task_id: u64,
) -> model::Result<bool> {
    match current.get::<Task>(task_key(task_id))? {
        Some(task) => {
            batch
                .clear(due_key(TaskId::Assigned(task_id), &task))
                .clear(task_key(task_id));
            Ok(true)
        }
        None => Ok(false),
    }
}

fn due_key(id: TaskId, task: &Task) -> ValueClass {
    ValueClass::TaskQueue(TaskQueueClass::Due {
        id,
        typ: task.object_type(),
        due: task.due_timestamp(),
    })
}
