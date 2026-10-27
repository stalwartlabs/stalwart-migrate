/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod batch;
mod blob;
mod category;
mod changes;
mod claim;
mod error;
mod global;
mod groupware;
mod ids;
mod issue;
mod mail;
mod queue;
mod registry;
mod shared;
mod source;
mod spam;
mod target;

pub use batch::{Record, RecordBatch, RecordPage};
pub use blob::BlobCache;
pub use category::{Category, CategorySet};
pub use changes::{
    AccountPointers, AccountRef, ChangeBounds, ChangeLogRecord, ChangeSet, Changes, Counters,
    LogChanges, LogEntry, LogRange, ObjectCountUsage, ParticipantIdentitiesRecord,
    ParticipantIdentityRecord, Pointer, QuotaUsage, ShareNotificationRecord, VanishedRecord,
};
pub use claim::{ClaimId, TargetClaim};
pub use error::{Error, Result};
pub use global::{
    GlobalBatch, GlobalCategory, GlobalKey, GlobalPage, TEXT_TIMESTAMPS, TaggedCursor, TaskRecord,
    TelemetryKind, TelemetryRecord,
};
pub use groupware::{
    AddressBookPreferencesRecord, AddressBookRecord, CalendarEventRecord,
    CalendarPreferencesRecord, CalendarRecord, ChangedByRecord, ContactRecord, DavNameRecord,
    DeadPropertyRecord, DeadPropertyTag, DefaultAlertRecord, EventNotificationRecord,
    EventPreferencesRecord, FileNodeRecord, FileRecord, TimeZoneRecord,
};
pub use ids::{BlobHash, Collection, LogCollection, MailboxUid};
pub use issue::{Explanation, Issue, IssueKind, Rejection, Severity, Subject, WriteOutcome};
pub use mail::{
    AclRecord, Delivered, DeliveryStatusRecord, EmailAddressRecord, EmailPushRecord, EmailRecord,
    EnvelopeRecord, IdentityRecord, MailboxRecord, PushKeysRecord, PushRecord, SieveRecord,
    SmtpAddressRecord, SubmissionRecord, UndoStatus, VacationRecord,
};
pub use queue::{
    DeliveryError, DeliveryFailure, DeliveryStatus, HostResponse, InternalReportRecord,
    QueueExpiry, QueueMetadata, QueueName, QueueQuotaKey, QueueRecipient, QueueSchedule,
    QueuedMessageRecord, ReportKind, SmtpResponse,
};
pub use registry::{RegistryCounter, RegistryEntries, RegistryId, RegistryKey, RegistryRecord};
pub use shared::{SharedDeletes, SharedDeletion, SharedOverwrite, SharedPlan, SharedService};
pub use source::Source;
pub use spam::{
    Ftrl, FtrlWeight, SampleReservoir, SpamClassifierModel, SpamModelChange, SpamModelKind,
    SpamModelRecord, SpamOptimizer, SpamTrainerModel, TrainingSample,
};
pub use target::{Edition, Target, TargetProbe, WriteMode};
