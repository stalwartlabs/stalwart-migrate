/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use crate::{
    category::Category,
    error::{Error, Result},
    issue::Issue,
    queue::{InternalReportRecord, QueuedMessageRecord, ReportKind},
    registry::{RegistryKey, RegistryRecord},
    spam::SpamModelRecord,
};

const REPORT_OBJECTS: [&str; 2] = [ReportKind::Dmarc.as_str(), ReportKind::Tls.as_str()];
const TELEMETRY_OBJECTS: [&str; 2] = [TelemetryKind::Span.as_str(), TelemetryKind::Metric.as_str()];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GlobalCategory {
    Queue,
    Reports,
    Tasks,
    SpamModel,
    Telemetry,
}

impl GlobalCategory {
    pub const ALL: [GlobalCategory; 5] = [
        GlobalCategory::Telemetry,
        GlobalCategory::SpamModel,
        GlobalCategory::Reports,
        GlobalCategory::Queue,
        GlobalCategory::Tasks,
    ];

    pub const fn category(self) -> Category {
        match self {
            GlobalCategory::Queue | GlobalCategory::Reports => Category::Queue,
            GlobalCategory::Tasks => Category::Tasks,
            GlobalCategory::SpamModel => Category::SpamModel,
            GlobalCategory::Telemetry => Category::Telemetry,
        }
    }

    pub const fn objects(self) -> &'static [&'static str] {
        match self {
            GlobalCategory::Queue => &[QueuedMessageRecord::OBJECT],
            GlobalCategory::Reports => &REPORT_OBJECTS,
            GlobalCategory::Tasks => &[TaskRecord::OBJECT],
            GlobalCategory::SpamModel => &["spamClassifier", "spamTrainer"],
            GlobalCategory::Telemetry => &TELEMETRY_OBJECTS,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            GlobalCategory::Reports => "reports",
            other => other.category().as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskRecord {
    pub id: u64,
    pub json: serde_json::Value,
}

impl TaskRecord {
    pub const OBJECT: &str = "Task";
    pub const TYPE: &str = "@type";

    pub fn task_type(&self) -> Option<&str> {
        self.json
            .get(Self::TYPE)
            .and_then(serde_json::Value::as_str)
    }

    pub fn into_registry(self) -> RegistryRecord {
        RegistryRecord {
            key: RegistryKey::new(Self::OBJECT, self.id),
            json: self.json,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TelemetryKind {
    Span,
    Metric,
}

pub const TEXT_TIMESTAMPS: Range<i64> = 0..32_535_216_000;

const SNOWFLAKE_TIME_SHIFT: u32 = 21;
const SPAN_LOOKBACK_MILLIS: u64 = 6 * 3_600_000;
const METRIC_LOOKBACK_MILLIS: u64 = 10 * 60_000;

impl TelemetryKind {
    pub const ALL: [TelemetryKind; 2] = [TelemetryKind::Span, TelemetryKind::Metric];

    pub const fn as_str(self) -> &'static str {
        match self {
            TelemetryKind::Span => "span",
            TelemetryKind::Metric => "metric",
        }
    }

    pub fn parse(object: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == object)
    }

    pub const fn lookback(self) -> u64 {
        let millis = match self {
            TelemetryKind::Span => SPAN_LOOKBACK_MILLIS,
            TelemetryKind::Metric => METRIC_LOOKBACK_MILLIS,
        };
        millis << SNOWFLAKE_TIME_SHIFT
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TelemetryRecord {
    pub kind: TelemetryKind,
    pub id: u64,
    pub json: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GlobalBatch {
    Queue(Vec<QueuedMessageRecord>),
    Reports(Vec<InternalReportRecord>),
    Tasks(Vec<TaskRecord>),
    SpamModel(Vec<SpamModelRecord>),
    Telemetry(Vec<TelemetryRecord>),
}

impl GlobalBatch {
    pub fn len(&self) -> usize {
        match self {
            GlobalBatch::Queue(records) => records.len(),
            GlobalBatch::Reports(records) => records.len(),
            GlobalBatch::Tasks(records) => records.len(),
            GlobalBatch::SpamModel(records) => records.len(),
            GlobalBatch::Telemetry(records) => records.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn global_keys(&self) -> Vec<GlobalKey> {
        match self {
            GlobalBatch::Queue(records) => records
                .iter()
                .map(|record| GlobalKey::Queue(record.queue_id))
                .collect(),
            GlobalBatch::Reports(records) => records
                .iter()
                .map(|record| GlobalKey::Report(record.kind, record.id))
                .collect(),
            GlobalBatch::Tasks(records) => records
                .iter()
                .map(|record| GlobalKey::Task(record.id))
                .collect(),
            GlobalBatch::SpamModel(_) | GlobalBatch::Telemetry(_) => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GlobalKey {
    Queue(u64),
    Report(ReportKind, u64),
    Task(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct GlobalPage {
    pub batch: GlobalBatch,
    pub issues: Vec<Issue>,
    pub next: Option<Vec<u8>>,
    pub resume: Option<Vec<u8>>,
}

impl GlobalPage {
    pub fn last(batch: GlobalBatch) -> Self {
        GlobalPage {
            batch,
            issues: Vec::new(),
            next: None,
            resume: None,
        }
    }
}

const ID_LEN: usize = size_of::<u64>();
const LEGACY_CURSOR_LEN: usize = 1 + ID_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggedCursor<const N: usize> {
    tag: usize,
    last: [Option<u64>; N],
}

impl<const N: usize> Default for TaggedCursor<N> {
    fn default() -> Self {
        TaggedCursor {
            tag: 0,
            last: [None; N],
        }
    }
}

impl<const N: usize> TaggedCursor<N> {
    const LEN: usize = {
        assert!(N <= u8::BITS as usize);
        2 + N * ID_LEN
    };

    pub fn decode(cursor: Option<&[u8]>) -> Result<Self> {
        let Some(cursor) = cursor else {
            return Ok(Self::default());
        };
        let invalid = || Error::fatal("invalid global cursor");
        let mut decoded = Self::default();
        if cursor.len() == LEGACY_CURSOR_LEN {
            let (&tag, last) = cursor.split_first().ok_or_else(invalid)?;
            let last = <[u8; ID_LEN]>::try_from(last).map_err(|_| invalid())?;
            decoded.tag = usize::from(tag);
            *decoded.last.get_mut(decoded.tag).ok_or_else(invalid)? =
                Some(u64::from_be_bytes(last));
            return Ok(decoded);
        }
        if cursor.len() != Self::LEN {
            return Err(invalid());
        }
        let [tag, mask, ids @ ..] = cursor else {
            return Err(invalid());
        };
        decoded.tag = usize::from(*tag);
        if decoded.tag >= N || usize::from(*mask) >> N != 0 {
            return Err(invalid());
        }
        for (index, (last, id)) in decoded
            .last
            .iter_mut()
            .zip(ids.as_chunks::<ID_LEN>().0)
            .enumerate()
        {
            if mask & (1 << index) != 0 {
                *last = Some(u64::from_be_bytes(*id));
            }
        }
        Ok(decoded)
    }

    pub fn position(&mut self) -> Option<(usize, u64)> {
        while let Some(last) = self.last.get(self.tag) {
            match last.map_or(Some(0), |last| last.checked_add(1)) {
                Some(first) => return Some((self.tag, first)),
                None => self.tag += 1,
            }
        }
        None
    }

    pub fn record(&mut self, last: u64) {
        if let Some(slot) = self.last.get_mut(self.tag) {
            *slot = Some(last);
        }
    }

    pub fn rewind(&mut self, tag: usize, by: u64) {
        if let Some(slot) = self.last.get_mut(tag) {
            *slot = slot.and_then(|last| last.checked_sub(by));
        }
    }

    pub fn next_tag(&mut self) {
        self.tag += 1;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut cursor = Vec::with_capacity(Self::LEN);
        cursor.push(u8::try_from(self.tag.min(N.saturating_sub(1))).unwrap_or(u8::MAX));
        cursor.push(
            self.last
                .iter()
                .enumerate()
                .filter(|(_, last)| last.is_some())
                .fold(0u8, |mask, (index, _)| mask | (1 << index)),
        );
        for last in &self.last {
            cursor.extend_from_slice(&last.unwrap_or_default().to_be_bytes());
        }
        cursor
    }

    pub fn restart(mut self) -> Vec<u8> {
        self.tag = 0;
        self.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(cursor: &mut TaggedCursor<2>, rows: &[&[u64]], limit: usize) -> Vec<(usize, u64)> {
        let mut read = Vec::new();
        while let Some((tag, first)) = cursor.position() {
            let page: Vec<u64> = rows[tag]
                .iter()
                .copied()
                .filter(|id| *id >= first)
                .take(limit)
                .collect();
            if let Some(last) = page.last() {
                cursor.record(*last);
            }
            read.extend(page.iter().map(|id| (tag, *id)));
            if page.len() == limit {
                *cursor = TaggedCursor::decode(Some(&cursor.encode())).expect("decode");
                continue;
            }
            cursor.next_tag();
        }
        read
    }

    // A new pass revisits every tag from its own last id, so rows added to an earlier tag are found.
    #[test]
    fn tagged_cursor_resumes_every_tag() {
        let mut cursor = TaggedCursor::<2>::default();
        assert_eq!(drain(&mut cursor, &[&[10], &[20]], 1), [(0, 10), (1, 20)]);
        let mut resumed = TaggedCursor::decode(Some(&cursor.restart())).expect("decode");
        assert_eq!(drain(&mut resumed, &[&[10, 30], &[20]], 1), [(0, 30)]);
        let mut at_end = TaggedCursor::<2>::default();
        assert_eq!(drain(&mut at_end, &[&[u64::MAX], &[]], 1), [(0, u64::MAX)]);
        let mut legacy = Vec::from([1u8]);
        legacy.extend_from_slice(&20u64.to_be_bytes());
        let mut legacy = TaggedCursor::<2>::decode(Some(&legacy)).expect("legacy");
        assert_eq!(legacy.position(), Some((1, 21)));
        assert!(TaggedCursor::<2>::decode(Some(&[2, 0])).is_err());
        assert!(TaggedCursor::<2>::decode(Some(&[0; 18][..17])).is_err());
    }

    // A rewound tag resumes that far below its last id, or from the start; other tags keep their position.
    #[test]
    fn rewound_tag_resumes_below_its_last_id() {
        let mut cursor = TaggedCursor::<2>::default();
        assert_eq!(
            drain(&mut cursor, &[&[10, 50], &[20]], 5),
            [(0, 10), (0, 50), (1, 20)]
        );
        cursor.rewind(0, 15);
        let mut resumed = TaggedCursor::decode(Some(&cursor.restart())).expect("decode");
        assert_eq!(
            drain(&mut resumed, &[&[10, 40, 50, 60], &[20, 30]], 5),
            [(0, 40), (0, 50), (0, 60), (1, 30)]
        );
        resumed.rewind(0, 100);
        let mut from_start = TaggedCursor::decode(Some(&resumed.restart())).expect("decode");
        assert_eq!(
            drain(&mut from_start, &[&[0, 60], &[30]], 5),
            [(0, 0), (0, 60)]
        );
    }
}
