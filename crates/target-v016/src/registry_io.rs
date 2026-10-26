/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use model::{
    BlobHash, Issue, IssueKind, RegistryCounter, RegistryId, RegistryKey, RegistryRecord,
    Rejection, Severity, Subject, WriteOutcome,
};
use registry::{
    schema::prelude::{OBJ_SEQ_ID, OBJ_SINGLETON, Object, ObjectInner, ObjectType},
    types::{EnumImpl, id::ObjectId},
};
use store::{
    ValueKey,
    ahash::AHashMap,
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::{BatchBuilder, RegistryClass, ValueClass},
};
use types::id::Id;

use crate::{
    error::{account, trc_error},
    external_report::{ExternalReport, ReportIdKey, ReportIdOwner},
    linked_item::LinkedItem,
    target::V016Target,
};

const OBJECT_PREFIX: &str = "x:";

fn object_type(name: &str) -> Option<ObjectType> {
    ObjectType::parse(name.strip_prefix(OBJECT_PREFIX).unwrap_or(name))
}

fn object_id(object_type: ObjectType, id: RegistryId) -> ObjectId {
    ObjectId::new(
        object_type,
        match id {
            RegistryId::Singleton => Id::singleton(),
            RegistryId::Id(id) => Id::new(id),
        },
    )
}

fn failed(key: &RegistryKey, message: impl Into<Box<str>>) -> Issue {
    Issue::new(
        Severity::Error,
        IssueKind::Failed,
        Subject::Registry(key.clone()),
        message,
    )
}

impl V016Target {
    pub(crate) async fn registry_read(
        &self,
        keys: &[RegistryKey],
    ) -> model::Result<Vec<Option<RegistryRecord>>> {
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(object_type) = object_type(&key.object) else {
                records.push(None);
                continue;
            };
            let record = self
                .registry
                .get(object_id(object_type, key.id))
                .await
                .map_err(trc_error)?
                .map(|object| {
                    serde_json::to_value(object.into_value_with_secrets())
                        .map(|json| RegistryRecord {
                            key: key.clone(),
                            json,
                        })
                        .map_err(|err| account(format!("cannot serialize {key}: {err}")))
                })
                .transpose()?;
            records.push(record);
        }
        Ok(records)
    }

    pub(crate) async fn registry_write(
        &self,
        records: &[RegistryRecord],
    ) -> model::Result<WriteOutcome> {
        let mut outcome = WriteOutcome::ok();
        let mut sequences: Vec<(ObjectType, u64)> = Vec::new();
        let mut linked = BatchBuilder::new();
        let mut batched: AHashMap<(u16, u64), Object> = AHashMap::new();
        let mut report_owners: AHashMap<ReportIdKey, Option<u64>> = AHashMap::new();
        for record in records {
            let Some(object_type) = object_type(&record.key.object) else {
                outcome.issues.push(failed(
                    &record.key,
                    format!("unknown v0.16 registry object {}", record.key.object),
                ));
                continue;
            };
            let object = match ObjectInner::deserialize(object_type, &record.json) {
                Ok(inner) => Object::new(inner),
                Err(err) => {
                    outcome.issues.push(
                        failed(&record.key, format!("invalid v0.16 object: {err}"))
                            .rejected(Rejection::Invalid),
                    );
                    continue;
                }
            };
            let flags = object.flags();
            let target = object_id(object_type, record.key.id);
            let key = (object_type.to_id(), target.id().id());
            let existing = match batched.remove(&key) {
                Some(previous) => Some(previous),
                None => self.registry.get(target).await.map_err(trc_error)?,
            };
            if let RegistryId::Id(item_id) = record.key.id
                && let Some(report) = ExternalReport::of(&object.inner)
            {
                let report_id = report.report_id();
                if let Some(report_id) = &report_id {
                    let owner = match report_owners.get(report_id) {
                        Some(owner) => *owner,
                        None => self.report_id_owner(report_id).await?,
                    };
                    if let Some(owner) = owner.filter(|owner| *owner != item_id) {
                        outcome.issues.push(
                            failed(
                                &record.key,
                                format!(
                                    "{} {owner} holds the same report id; retried after the deletes of this run",
                                    record.key.object
                                ),
                            )
                            .rejected(Rejection::Conflict),
                        );
                        if let Some(existing) = existing {
                            batched.insert(key, existing);
                        }
                        continue;
                    }
                    if owner.is_some() && existing.is_none() {
                        linked.clear(report_id.class());
                    }
                }
                if let Some(old) = existing
                    .as_ref()
                    .and_then(|old| ExternalReport::of(&old.inner))
                {
                    if let Some(old_id) = old.report_id() {
                        report_owners.insert(old_id, None);
                    }
                    old.write_ops(&mut linked, item_id, false);
                }
                report.write_ops(&mut linked, item_id, true);
                if let Some(report_id) = report_id {
                    report_owners.insert(report_id, Some(item_id));
                }
                if flags & OBJ_SEQ_ID != 0 {
                    raise_max(&mut sequences, object_type, item_id);
                }
                linked.commit_point();
                batched.insert(key, object);
                continue;
            }
            if let RegistryId::Id(item_id) = record.key.id
                && let Some(item) = LinkedItem::of(&object.inner)
            {
                let old = existing.as_ref().and_then(|old| LinkedItem::of(&old.inner));
                item.write(&mut linked, item_id, old.as_ref());
                linked.commit_point();
                if flags & OBJ_SEQ_ID != 0 {
                    raise_max(&mut sequences, object_type, item_id);
                }
                batched.insert(key, object);
                continue;
            }
            let write = match (&existing, record.key.id) {
                (Some(old), _) => RegistryWrite::update(target.id(), &object, old),
                (None, RegistryId::Singleton) if flags & OBJ_SINGLETON != 0 => {
                    RegistryWrite::insert(&object)
                }
                (None, _) => RegistryWrite::insert_with_id(target.id(), &object),
            };
            match self.registry.write(write).await.map_err(trc_error)? {
                RegistryWriteResult::Success(_) => {
                    failpoint!("registry.object");
                    if flags & OBJ_SEQ_ID != 0
                        && let RegistryId::Id(id) = record.key.id
                    {
                        raise_max(&mut sequences, object_type, id);
                    }
                }
                result => outcome.issues.push(tag_rejection(
                    failed(&record.key, format!("rejected by v0.16: {result}")),
                    &result,
                )),
            }
        }
        for (object_type, id) in sequences {
            self.raise_id_counter(&mut linked, object_type, id).await?;
        }
        self.commit_counters(linked).await?;
        Ok(outcome)
    }

    pub(crate) async fn registry_delete(&self, keys: &[RegistryKey]) -> model::Result<()> {
        for key in keys {
            let Some(object_type) = object_type(&key.object) else {
                continue;
            };
            if let (true, RegistryId::Id(item_id)) = (is_external_report(object_type), key.id) {
                if let Some(object) = self
                    .registry
                    .get(object_id(object_type, key.id))
                    .await
                    .map_err(trc_error)?
                    && let Some(report) = ExternalReport::of(&object.inner)
                {
                    let mut batch = BatchBuilder::new();
                    report.write_ops(&mut batch, item_id, false);
                    self.commit_counters(batch).await?;
                }
                continue;
            }
            if let (true, RegistryId::Id(item_id)) = (LinkedItem::holds_blob(object_type), key.id) {
                if let Some(object) = self
                    .registry
                    .get(object_id(object_type, key.id))
                    .await
                    .map_err(trc_error)?
                    && let Some(item) = LinkedItem::of(&object.inner)
                {
                    let mut batch = BatchBuilder::new();
                    item.delete(&mut batch, item_id);
                    self.commit_counters(batch).await?;
                }
                continue;
            }
            match self
                .registry
                .write(RegistryWrite::delete(object_id(object_type, key.id)))
                .await
                .map_err(trc_error)?
            {
                RegistryWriteResult::Success(_) => failpoint!("registry.object_deleted"),
                RegistryWriteResult::NotFound { .. }
                | RegistryWriteResult::CannotDeleteSingleton => {}
                result => return Err(account(format!("cannot delete {key}: {result}"))),
            }
        }
        Ok(())
    }

    pub(crate) fn registry_blob_hash(&self, record: &RegistryRecord) -> Option<BlobHash> {
        let object_type =
            object_type(&record.key.object).filter(|ty| LinkedItem::holds_blob(*ty))?;
        let inner = ObjectInner::deserialize(object_type, &record.json).ok()?;
        LinkedItem::of(&inner).map(|item| BlobHash(item.hash().0))
    }

    pub(crate) async fn registry_counters(
        &self,
        counters: &[RegistryCounter],
    ) -> model::Result<()> {
        let mut sequences: Vec<(ObjectType, u64)> = Vec::new();
        for counter in counters {
            if let Some(object_type) =
                object_type(&counter.object).filter(|ty| ty.flags() & OBJ_SEQ_ID != 0)
            {
                raise_max(&mut sequences, object_type, counter.value);
            }
        }
        let mut batch = BatchBuilder::new();
        for (object_type, value) in sequences {
            self.raise_id_counter(&mut batch, object_type, value)
                .await?;
        }
        self.commit_counters(batch).await
    }

    async fn report_id_owner(&self, report_id: &ReportIdKey) -> model::Result<Option<u64>> {
        self.store
            .get_value::<ReportIdOwner>(ValueKey::from(report_id.class()))
            .await
            .map(|owner| owner.map(|owner| owner.0))
            .map_err(trc_error)
    }

    async fn raise_id_counter(
        &self,
        batch: &mut BatchBuilder,
        object_type: ObjectType,
        id: u64,
    ) -> model::Result<()> {
        let class = ValueClass::Registry(RegistryClass::IdCounter {
            object_id: object_type.to_id(),
        });
        let current = self
            .store
            .get_counter(ValueKey::from(class.clone()))
            .await
            .map_err(trc_error)?;
        let wanted = i64::try_from(id).unwrap_or(i64::MAX);
        if wanted > current {
            batch.add(class, wanted - current);
        }
        Ok(())
    }

    async fn commit_counters(&self, mut batch: BatchBuilder) -> model::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut points = batch.commit_points();
        for point in points.iter() {
            self.store
                .write(batch.build_one(point))
                .await
                .map_err(trc_error)?;
        }
        Ok(())
    }
}

fn is_external_report(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::ArfExternalReport
    )
}

fn tag_rejection(issue: Issue, result: &RegistryWriteResult) -> Issue {
    match result {
        RegistryWriteResult::PrimaryKeyConflict { .. } => issue.rejected(Rejection::Conflict),
        RegistryWriteResult::ValidationError { .. }
        | RegistryWriteResult::InvalidForeignKey { .. } => issue.rejected(Rejection::Invalid),
        _ => issue,
    }
}

fn raise_max(sequences: &mut Vec<(ObjectType, u64)>, object_type: ObjectType, value: u64) {
    match sequences.iter_mut().find(|(ty, _)| *ty == object_type) {
        Some((_, max)) => *max = (*max).max(value),
        None => sequences.push((object_type, value)),
    }
}
