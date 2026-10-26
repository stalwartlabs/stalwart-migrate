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
#[cfg(feature = "enterprise")]
use registry::schema::structs::ArchivedItem;
use registry::{
    schema::prelude::{OBJ_SEQ_ID, OBJ_SINGLETON, Object, ObjectInner, ObjectType, Property},
    types::{EnumImpl, id::ObjectId},
};
use registry::{schema::structs::SpamTrainingSample, types::ObjectImpl};
use smtp::reporting::index::ExternalReportIndex;
use store::SerializeInfallible;
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::{BatchBuilder, RegistryClass, ValueClass},
};
use types::id::Id;

use crate::{
    error::{account, trc_error},
    registry_blob::TemporaryLink,
    target::V1Target,
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

fn item_key(object_id: ObjectId) -> ValueClass {
    ValueClass::Registry(RegistryClass::Item {
        object_id: object_id.object().to_id(),
        item_id: object_id.id().id(),
    })
}

fn failed(key: &RegistryKey, message: impl Into<Box<str>>) -> Issue {
    Issue::new(
        Severity::Error,
        IssueKind::Failed,
        Subject::Registry(key.clone()),
        message,
    )
}

impl V1Target {
    pub(crate) async fn registry_read(
        &self,
        keys: &[RegistryKey],
    ) -> model::Result<Vec<Option<RegistryRecord>>> {
        let current = self
            .prefetch(keys.iter().filter_map(|key| {
                object_type(&key.object)
                    .filter(|object_type| *object_type != ObjectType::DataStore)
                    .map(|object_type| item_key(object_id(object_type, key.id)))
            }))
            .await?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let object = match object_type(&key.object) {
                None => None,
                Some(ObjectType::DataStore) => self
                    .registry
                    .get(object_id(ObjectType::DataStore, key.id))
                    .await
                    .map_err(trc_error)?,
                Some(object_type) => {
                    current.get::<Object>(item_key(object_id(object_type, key.id)))?
                }
            };
            let record = object
                .map(|object| {
                    serde_json::to_value(&object.inner)
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
        let mut batch = BatchBuilder::new();
        let mut parsed = Vec::with_capacity(records.len());
        for record in records {
            let Some(object_type) = object_type(&record.key.object) else {
                outcome.issues.push(failed(
                    &record.key,
                    format!("unknown v1 registry object {}", record.key.object),
                ));
                continue;
            };
            match ObjectInner::deserialize(object_type, &record.json) {
                Ok(inner) => parsed.push((record, object_type, Object::new(inner))),
                Err(err) => outcome.issues.push(
                    failed(&record.key, format!("invalid v1 object: {err}"))
                        .rejected(Rejection::Invalid),
                ),
            }
        }
        let mut written = AHashSet::new();
        let mut batched = AHashMap::new();
        let mut report_owners: AHashMap<ReportIdKey, Option<u64>> = AHashMap::new();
        let current = self
            .prefetch(
                parsed
                    .iter()
                    .filter(|(_, object_type, _)| *object_type != ObjectType::DataStore)
                    .map(|(record, object_type, _)| {
                        item_key(object_id(*object_type, record.key.id))
                    })
                    .chain(parsed.iter().filter_map(|(_, _, object)| {
                        ReportIdKey::of(&object.inner).map(|report_id| report_id.class())
                    })),
            )
            .await?;
        for (record, object_type, object) in parsed {
            let flags = object.flags();
            let target = object_id(object_type, record.key.id);
            let key = (object_type.to_id(), record.key.id);
            let existing = if let Some(previous) = batched.remove(&key) {
                Some(previous)
            } else if object_type == ObjectType::DataStore {
                self.registry.get(target).await.map_err(trc_error)?
            } else if written.contains(&key) {
                self.store
                    .get_value::<Object>(ValueKey::from(item_key(target)))
                    .await
                    .map_err(trc_error)?
            } else {
                current.get::<Object>(item_key(target))?
            };
            if let RegistryId::Id(item_id) = record.key.id
                && is_external_report(object_type)
            {
                let report_id = ReportIdKey::of(&object.inner);
                if let Some(report_id) = &report_id {
                    let owner = match report_owners.get(report_id) {
                        Some(owner) => *owner,
                        None => current.raw(report_id.class()).and_then(ReportIdKey::owner),
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
                }
                if let Some(old) = &existing {
                    if let Some(old_id) = ReportIdKey::of(&old.inner) {
                        report_owners.insert(old_id, None);
                    }
                    external_report_ops(&old.inner, &mut batch, item_id, false);
                }
                external_report_ops(&object.inner, &mut batch, item_id, true);
                if let Some(report_id) = report_id {
                    report_owners.insert(report_id, Some(item_id));
                }
                if flags & OBJ_SEQ_ID != 0 {
                    raise_max(&mut sequences, object_type, item_id);
                }
                batch.commit_point();
                batched.insert(key, object);
                continue;
            }
            #[cfg(feature = "enterprise")]
            if let RegistryId::Id(item_id) = record.key.id
                && let ObjectInner::ArchivedItem(item) = &object.inner
            {
                if let Some(ObjectInner::ArchivedItem(old)) =
                    existing.as_ref().map(|old| &old.inner)
                {
                    batch.clear(archived_item_index(old, item_id));
                }
                batch
                    .set(archived_item_index(item, item_id), Vec::new())
                    .set(item_key(target), item.to_pickled_vec());
                update_link(&mut batch, existing.as_ref(), &object, target);
                batch.commit_point();
                batched.insert(key, object);
                continue;
            }
            if let RegistryId::Id(item_id) = record.key.id
                && let ObjectInner::SpamTrainingSample(sample) = &object.inner
            {
                if let Some(ObjectInner::SpamTrainingSample(old)) =
                    existing.as_ref().map(|old| &old.inner)
                {
                    batch.clear(spam_sample_index(old, item_id));
                }
                batch
                    .set(spam_sample_index(sample, item_id), Vec::new())
                    .set(item_key(target), sample.to_pickled_vec());
                update_link(&mut batch, existing.as_ref(), &object, target);
                batch.commit_point();
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
                    written.insert(key);
                    if TemporaryLink::holds_blob(object_type) {
                        update_link(&mut batch, existing.as_ref(), &object, target);
                    }
                    if flags & OBJ_SEQ_ID != 0
                        && let RegistryId::Id(id) = record.key.id
                    {
                        raise_max(&mut sequences, object_type, id);
                    }
                }
                result => outcome.issues.push(tag_rejection(
                    failed(&record.key, format!("rejected by v1: {result}")),
                    &result,
                )),
            }
        }
        for (object_type, id) in sequences {
            self.raise_id_counter(&mut batch, object_type, id).await?;
        }
        self.commit_counters(batch).await?;
        Ok(outcome)
    }

    pub(crate) async fn registry_delete(&self, keys: &[RegistryKey]) -> model::Result<()> {
        let mut batch = BatchBuilder::new();
        let current = self
            .prefetch(keys.iter().filter_map(|key| {
                object_type(&key.object)
                    .filter(|ty| is_external_report(*ty) || TemporaryLink::holds_blob(*ty))
                    .map(|ty| item_key(object_id(ty, key.id)))
            }))
            .await?;
        for key in keys {
            let Some(object_type) = object_type(&key.object) else {
                continue;
            };
            let target = object_id(object_type, key.id);
            if let RegistryId::Id(item_id) = key.id
                && is_external_report(object_type)
            {
                if let Some(current) = current.get::<Object>(item_key(target))? {
                    external_report_ops(&current.inner, &mut batch, item_id, false);
                    batch.commit_point();
                }
                continue;
            }
            let current_object = if TemporaryLink::holds_blob(object_type) {
                current.get::<Object>(item_key(target))?
            } else {
                None
            };
            let link = current_object
                .as_ref()
                .and_then(|object| TemporaryLink::of(&object.inner));
            #[cfg(feature = "enterprise")]
            if let RegistryId::Id(item_id) = key.id
                && let Some(ObjectInner::ArchivedItem(item)) =
                    current_object.as_ref().map(|object| &object.inner)
            {
                batch
                    .clear(archived_item_index(item, item_id))
                    .clear(item_key(target));
                if let Some(link) = link {
                    link.clear(&mut batch);
                }
                batch.commit_point();
                continue;
            }
            if let RegistryId::Id(item_id) = key.id
                && let Some(ObjectInner::SpamTrainingSample(sample)) =
                    current_object.as_ref().map(|object| &object.inner)
            {
                batch
                    .clear(spam_sample_index(sample, item_id))
                    .clear(item_key(target));
                if let Some(link) = link {
                    link.clear(&mut batch);
                }
                batch.commit_point();
                continue;
            }
            match self
                .registry
                .write(RegistryWrite::delete(target))
                .await
                .map_err(trc_error)?
            {
                RegistryWriteResult::Success(_) => {
                    failpoint!("registry.object_deleted");
                    if let Some(link) = link {
                        link.clear(&mut batch);
                    }
                }
                RegistryWriteResult::NotFound { .. }
                | RegistryWriteResult::CannotDeleteSingleton => {}
                result => return Err(account(format!("cannot delete {key}: {result}"))),
            }
        }
        self.commit_counters(batch).await
    }

    pub(crate) fn registry_blob_hash(&self, record: &RegistryRecord) -> Option<BlobHash> {
        let object_type =
            object_type(&record.key.object).filter(|ty| TemporaryLink::holds_blob(*ty))?;
        let inner = ObjectInner::deserialize(object_type, &record.json).ok()?;
        TemporaryLink::of(&inner).map(|link| BlobHash(link.hash.0))
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
        self.store
            .write_batch(&mut batch)
            .await
            .map(|_| ())
            .map_err(trc_error)
    }
}

fn update_link(
    batch: &mut BatchBuilder,
    existing: Option<&Object>,
    object: &Object,
    target: ObjectId,
) {
    let current = existing.and_then(|old| TemporaryLink::of(&old.inner));
    let link = TemporaryLink::of(&object.inner);
    if let Some(current) = current.as_ref().filter(|old| Some(*old) != link.as_ref()) {
        current.clear(batch);
    }
    if let Some(link) = link {
        link.set(batch, target);
    }
}

#[cfg(feature = "enterprise")]
fn archived_item_index(item: &ArchivedItem, item_id: u64) -> ValueClass {
    ValueClass::Registry(RegistryClass::Index {
        index_id: Property::AccountId.to_id(),
        object_id: ObjectType::ArchivedItem.to_id(),
        item_id,
        key: u64::from(item.account_id().document_id()).serialize(),
    })
}

fn spam_sample_index(sample: &SpamTrainingSample, item_id: u64) -> ValueClass {
    ValueClass::Registry(RegistryClass::Index {
        index_id: Property::AccountId.to_id(),
        object_id: ObjectType::SpamTrainingSample.to_id(),
        item_id,
        key: sample
            .account_id
            .map_or(u64::from(u32::MAX), |id| u64::from(id.document_id()))
            .serialize(),
    })
}

fn is_external_report(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::ArfExternalReport
    )
}

fn external_report_ops(inner: &ObjectInner, batch: &mut BatchBuilder, item_id: u64, is_set: bool) {
    match inner {
        ObjectInner::DmarcExternalReport(report) => report.write_ops(batch, item_id, is_set),
        ObjectInner::TlsExternalReport(report) => report.write_ops(batch, item_id, is_set),
        ObjectInner::ArfExternalReport(report) => report.write_ops(batch, item_id, is_set),
        _ => {}
    }
}

#[derive(PartialEq, Eq, Hash)]
struct ReportIdKey {
    object_id: u16,
    key: [u8; 16],
}

impl ReportIdKey {
    fn of(inner: &ObjectInner) -> Option<Self> {
        let (object_type, key) = match inner {
            ObjectInner::DmarcExternalReport(report) => {
                (ObjectType::DmarcExternalReport, report.unique_key()?)
            }
            ObjectInner::TlsExternalReport(report) => {
                (ObjectType::TlsExternalReport, report.unique_key()?)
            }
            ObjectInner::ArfExternalReport(report) => {
                (ObjectType::ArfExternalReport, report.unique_key()?)
            }
            _ => return None,
        };
        Some(ReportIdKey {
            object_id: object_type.to_id(),
            key,
        })
    }

    fn class(&self) -> ValueClass {
        ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: Some(self.object_id),
            index_id: Property::ReportId.to_id(),
            key: self.key.to_vec(),
        })
    }

    fn owner(value: &[u8]) -> Option<u64> {
        let (_, item_id) = value.split_first_chunk::<2>()?;
        item_id.first_chunk::<8>().copied().map(u64::from_be_bytes)
    }
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
