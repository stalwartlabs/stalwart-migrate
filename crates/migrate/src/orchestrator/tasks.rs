/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use std::collections::BTreeMap;

use mapping::ids::JmapId;
use model::{
    Category, CategorySet, GlobalBatch, GlobalCategory, GlobalKey, Issue, IssueKind, RegistryKey,
    RegistryRecord, Severity, Source, Subject, Target, TaskRecord,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;
use state::StateStore;

use super::{
    RegistryConverter,
    context::Context,
    error::RunError,
    registry::{ConvertedRecord, RecordSide, read_registry, registry_categories},
    retry::RetryPolicy,
    stats::add,
};

pub(super) const TASK_CONVERSION_CHUNK: usize = 10_000;
const TASK_ACCOUNT: &str = "accountId";
const TASK_STATUS: &str = "status";
const STATUS_TYPE: &str = "@type";
const STATUS_RETRY: &str = "Retry";
const STATUS_CREATED: &str = "createdAt";
const STATUS_FIRST_FAILED: &str = "firstFailedAt";

fn date_first_failure(task: &mut Value) {
    let Some(status) = task.get_mut(TASK_STATUS).and_then(Value::as_object_mut) else {
        return;
    };
    if status.get(STATUS_TYPE).and_then(Value::as_str) != Some(STATUS_RETRY)
        || status.contains_key(STATUS_FIRST_FAILED)
    {
        return;
    }
    if let Some(created) = status.get(STATUS_CREATED).cloned() {
        status.insert(STATUS_FIRST_FAILED.into(), created);
    }
}

struct TaskGraph {
    records: Vec<RegistryRecord>,
    references: Vec<Box<[usize]>>,
    index: FxHashMap<RegistryKey, usize>,
}

impl TaskGraph {
    fn new<C: RegistryConverter>(records: Vec<RegistryRecord>, converter: &C) -> Self {
        let index: FxHashMap<RegistryKey, usize> = records
            .iter()
            .enumerate()
            .map(|(position, record)| (record.key.clone(), position))
            .collect();
        let references = records
            .iter()
            .map(|record| {
                converter
                    .references(RecordSide::Source, record)
                    .iter()
                    .filter_map(|key| index.get(key).copied())
                    .collect()
            })
            .collect();
        TaskGraph {
            records,
            references,
            index,
        }
    }

    fn closure<C: RegistryConverter>(
        &self,
        converter: &C,
        tasks: &[RegistryRecord],
    ) -> Vec<RegistryRecord> {
        let mut included: FxHashSet<usize> = FxHashSet::default();
        let mut stack: Vec<usize> = tasks
            .iter()
            .flat_map(|task| converter.references(RecordSide::Source, task))
            .filter_map(|key| self.index.get(&key).copied())
            .collect();
        while let Some(position) = stack.pop() {
            if included.insert(position)
                && let Some(references) = self.references.get(position)
            {
                stack.extend(references.iter().copied());
            }
        }
        let mut positions: Vec<usize> = included.into_iter().collect();
        positions.sort_unstable();
        positions
            .into_iter()
            .filter_map(|position| self.records.get(position).cloned())
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotCopied {
    Indexing,
    Alarm,
    Report,
    ThreadMerge,
}

impl NotCopied {
    const ALL: [NotCopied; 4] = [
        NotCopied::Indexing,
        NotCopied::Alarm,
        NotCopied::Report,
        NotCopied::ThreadMerge,
    ];

    fn of(task_type: &str) -> Option<NotCopied> {
        hashify::map!(task_type.as_bytes(), NotCopied,
            "IndexDocument" => NotCopied::Indexing,
            "UnindexDocument" => NotCopied::Indexing,
            "IndexTrace" => NotCopied::Indexing,
            "CalendarAlarmEmail" => NotCopied::Alarm,
            "CalendarAlarmNotification" => NotCopied::Alarm,
            "DmarcReport" => NotCopied::Report,
            "TlsReport" => NotCopied::Report,
            "MergeThreads" => NotCopied::ThreadMerge,
        )
        .copied()
    }

    const fn index(self) -> usize {
        self as usize
    }

    const fn reason(self, reports_copied: bool) -> &'static str {
        match self {
            NotCopied::Indexing => {
                "search indexing tasks were not copied; v1 indexes from its own queue"
            }
            NotCopied::Alarm => {
                "calendar alarm tasks were not copied; the target schedules alarms when it imports events"
            }
            NotCopied::Report if reports_copied => {
                "internal report tasks were not copied; the internal reports copy schedules their delivery"
            }
            NotCopied::Report => {
                "internal report tasks were not copied; the queue category, which holds the internal reports, is excluded"
            }
            NotCopied::ThreadMerge => {
                "thread merge tasks were not copied: v1 cannot use the v0.16 thread and message hashes they carry, so the conversations v0.16 was about to merge stay split in v1"
            }
        }
    }
}

pub(super) fn is_copied(record: &TaskRecord) -> bool {
    record.task_type().and_then(NotCopied::of).is_none()
}

pub(super) struct ConvertedTasks {
    pub(super) issues: Vec<Issue>,
    pub(super) tasks: BTreeMap<u64, Value>,
}

pub(super) struct TaskConversion<'x, S, C> {
    source: &'x S,
    converter: &'x C,
    categories: CategorySet,
    policy: RetryPolicy,
    limit: usize,
    graph: Option<TaskGraph>,
}

impl<'x, S: Source, C: RegistryConverter> TaskConversion<'x, S, C> {
    pub(super) fn new(
        source: &'x S,
        converter: &'x C,
        categories: CategorySet,
        policy: RetryPolicy,
        limit: usize,
    ) -> Self {
        let mut categories = registry_categories(categories);
        categories.insert(Category::Tasks);
        TaskConversion {
            source,
            converter,
            categories,
            policy,
            limit,
            graph: None,
        }
    }

    pub(super) async fn convert(
        &mut self,
        tasks: Vec<RegistryRecord>,
    ) -> Result<ConvertedTasks, RunError> {
        let graph = match &mut self.graph {
            Some(graph) => graph,
            empty => {
                let objects = read_registry(self.source, self.policy, self.limit).await?;
                empty.insert(TaskGraph::new(objects, self.converter))
            }
        };
        let mut objects = graph.closure(self.converter, &tasks);
        objects.extend(tasks);
        let converted = self
            .converter
            .convert(objects, self.categories)
            .map_err(|err| RunError::preflight(err.to_string()))?;
        let target_object = self.converter.target_object(TaskRecord::OBJECT);
        let is_task =
            |key: &RegistryKey| &*key.object == TaskRecord::OBJECT || key.object == target_object;
        let mut issues: Vec<Issue> = converted
            .issues
            .into_iter()
            .filter(|issue| matches!(&issue.subject, Subject::Registry(key) if is_task(key)))
            .collect();
        let explained: FxHashSet<RegistryKey> = issues
            .iter()
            .filter_map(|issue| match &issue.subject {
                Subject::Registry(key) => Some(key.clone()),
                _ => None,
            })
            .collect();
        issues.extend(
            converted
                .dropped
                .into_iter()
                .filter(|key| is_task(key) && !explained.contains(key))
                .map(|key| {
                    Issue::new(
                        Severity::Warning,
                        IssueKind::Dropped,
                        Subject::Registry(key),
                        "the settings conversion dropped this task; it was not copied",
                    )
                }),
        );
        let tasks = converted
            .records
            .into_iter()
            .map(|ConvertedRecord { record, .. }| record)
            .chain(converted.deferred)
            .filter(|record| record.key.object == target_object)
            .filter_map(|mut record| {
                date_first_failure(&mut record.json);
                Some((record.key.id.id()?, record.json))
            })
            .collect();
        Ok(ConvertedTasks { issues, tasks })
    }
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn tasks_pass(&self) -> Result<(), RunError> {
        let limit = self.options.tuning.batch_ops;
        let mut not_copied = [0u64; NotCopied::ALL.len()];
        let mut thread_merges: BTreeMap<Option<u32>, u64> = BTreeMap::new();
        let mut pending: Vec<RegistryRecord> = Vec::new();
        let mut conversion = TaskConversion::new(
            &*self.source,
            &*self.converter,
            self.options.categories,
            self.policy(),
            limit,
        );
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            self.check_shutdown()?;
            self.rate.acquire(limit).await;
            let page = self
                .retry(|| {
                    self.source
                        .global_page(GlobalCategory::Tasks, cursor.as_deref(), limit)
                })
                .await?;
            self.report(None, page.issues).await?;
            let GlobalBatch::Tasks(records) = page.batch else {
                return Err(
                    model::Error::fatal("the source returned a non-task page for tasks").into(),
                );
            };
            for record in records {
                match record.task_type().and_then(NotCopied::of) {
                    Some(NotCopied::ThreadMerge) => {
                        let account_id = record
                            .json
                            .get(TASK_ACCOUNT)
                            .and_then(Value::as_str)
                            .and_then(JmapId::parse)
                            .and_then(|id| u32::try_from(id.0).ok());
                        *thread_merges.entry(account_id).or_insert(0) += 1;
                    }
                    Some(reason) => not_copied[reason.index()] += 1,
                    None => pending.push(record.into_registry()),
                }
            }
            if pending.len() >= TASK_CONVERSION_CHUNK {
                self.convert_tasks(&mut conversion, std::mem::take(&mut pending))
                    .await?;
            }
            match page.next {
                None => break,
                Some(next) if cursor.as_ref() == Some(&next) => {
                    return Err(model::Error::fatal("source tasks pages did not advance").into());
                }
                next => cursor = next,
            }
        }
        if !pending.is_empty() {
            self.convert_tasks(&mut conversion, pending).await?;
        }
        let reports_copied = self
            .options
            .categories
            .contains(GlobalCategory::Reports.category());
        let summary = NotCopied::ALL
            .into_iter()
            .zip(not_copied)
            .filter(|(_, count)| *count > 0)
            .map(|(reason, count)| {
                Issue::new(
                    Severity::Info,
                    IssueKind::Dropped,
                    Subject::None,
                    format!("{count} {}", reason.reason(reports_copied)),
                )
            })
            .collect();
        self.report(None, summary).await?;
        let reason = NotCopied::ThreadMerge.reason(reports_copied);
        for (account_id, count) in thread_merges {
            self.report(
                account_id,
                vec![Issue::new(
                    Severity::Warning,
                    IssueKind::Dropped,
                    Subject::None,
                    format!("{count} {reason}"),
                )],
            )
            .await?;
        }
        Ok(())
    }

    async fn convert_tasks(
        &self,
        conversion: &mut TaskConversion<'_, S, C>,
        tasks: Vec<RegistryRecord>,
    ) -> Result<(), RunError> {
        let limit = self.options.tuning.batch_ops;
        let ConvertedTasks { issues, tasks } = conversion.convert(tasks).await?;
        self.report(None, issues).await?;
        let mut batch = Vec::with_capacity(limit.max(1).min(tasks.len()));
        let mut tasks = tasks.into_iter().peekable();
        while tasks.peek().is_some() {
            self.check_shutdown()?;
            batch.clear();
            batch.extend(
                tasks
                    .by_ref()
                    .take(limit.max(1))
                    .map(|(id, json)| TaskRecord { id, json }),
            );
            let keys = batch
                .iter()
                .map(|task| GlobalKey::Task(self.converter.stored_task_id(task)))
                .collect();
            let records = GlobalBatch::Tasks(std::mem::take(&mut batch));
            self.state.track_globals(self.run_id, keys).await?;
            failpoint!("global.track", "tasks");
            let outcome = self.retry(|| self.target.write_global(&records)).await?;
            failpoint!("global.write", "tasks");
            add(&self.stats.global_records, records.len() as u64);
            self.report(None, outcome.issues).await?;
            if let GlobalBatch::Tasks(records) = records {
                batch = records;
            }
        }
        Ok(())
    }
}
