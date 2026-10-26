/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod queue;
mod reports;
mod spam;
mod tasks;
#[cfg(feature = "enterprise")]
mod telemetry;

use model::{
    Explanation, GlobalBatch, GlobalKey, Issue, IssueKind, RegistryKey, Severity, Subject,
    WriteOutcome,
};

use registry::{
    schema::prelude::{ObjectInner, ObjectType},
    types::id::ObjectId,
};
use types::id::Id;

use crate::{error::trc_error, target::V1Target};

fn skipped(object: &str, id: u64, message: impl Into<Box<str>>) -> Issue {
    Issue::new(
        Severity::Warning,
        IssueKind::Skipped,
        Subject::Registry(RegistryKey::new(object, id)),
        message,
    )
    .explaining(Explanation::Missing)
}

impl V1Target {
    async fn singleton(&self, object: ObjectType) -> model::Result<Option<ObjectInner>> {
        self.registry
            .get(ObjectId::new(object, Id::singleton()))
            .await
            .map(|object| object.map(|object| object.inner))
            .map_err(trc_error)
    }

    pub(crate) async fn global_write(&self, batch: &GlobalBatch) -> model::Result<WriteOutcome> {
        let issues = match batch {
            GlobalBatch::Queue(records) => self.write_queue(records).await?,
            GlobalBatch::Reports(records) => self.write_reports(records).await?,
            GlobalBatch::Tasks(records) => self.write_tasks(records).await?,
            GlobalBatch::SpamModel(records) => Self::defer_spam_model(records),
            #[cfg(feature = "enterprise")]
            GlobalBatch::Telemetry(records) => self.write_telemetry(records).await?,
            #[cfg(not(feature = "enterprise"))]
            GlobalBatch::Telemetry(records) => records
                .iter()
                .map(|record| {
                    skipped(
                        record.kind.as_str(),
                        record.id,
                        "telemetry is not stored by the community edition of v1",
                    )
                })
                .collect(),
        };
        Ok(WriteOutcome { issues })
    }

    pub(crate) async fn global_delete(&self, keys: &[GlobalKey]) -> model::Result<WriteOutcome> {
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        keys.dedup();
        let queued = self
            .prefetch(keys.iter().filter_map(|key| match *key {
                GlobalKey::Queue(queue_id) => Some(queue::message_key(queue_id)),
                _ => None,
            }))
            .await?;
        let reports = self
            .prefetch(keys.iter().filter_map(|key| match *key {
                GlobalKey::Report(kind, id) => Some(reports::item_key(kind, id)),
                _ => None,
            }))
            .await?;
        let tasks = self
            .prefetch(keys.iter().filter_map(|key| match *key {
                GlobalKey::Task(id) => Some(tasks::task_key(id)),
                _ => None,
            }))
            .await?;
        let mut batch = self.global_batch();
        for key in keys {
            let deleted = match key {
                GlobalKey::Queue(queue_id) => {
                    queue::delete_queued(&mut batch.batch, &queued, queue_id)?
                }
                GlobalKey::Report(kind, id) => {
                    reports::delete_report(&mut batch.batch, &reports, kind, id)?
                }
                GlobalKey::Task(id) => tasks::delete_task(&mut batch.batch, &tasks, id)?,
            };
            if deleted {
                batch.record_done(0);
            }
        }
        batch.commit(&self.store).await?;
        Ok(WriteOutcome::ok())
    }
}
