/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarDuration, ICalendarMethod, ICalendarProperty, ICalendarValue},
    vcard::{VCard, VCardVersion},
};
use common::{
    DavName, Server,
    auth::ChangedBy,
    storage::index::{
        ArchivedSplitObject, GroupwareWrite, ObjectIndexBuilder, PresenceFlags, SplitCurrent,
        SplitObject,
    },
};
use groupware::{
    DestroyArchive,
    calendar::{
        Calendar, CalendarEvent, CalendarEventContent, CalendarEventData,
        CalendarEventNotification, CalendarEventNotificationContent, CalendarPreferences,
        ChangedBy as NotificationChangedBy, DefaultAlert, EVENT_HAS_ALARMS,
        EVENT_NOTIFICATION_IS_CHANGE, EventPreferences, Timezone,
        alarm::AlarmTarget,
        alerts::DefaultAlertsResolver,
        schedule::{AlarmTasks, EventAlarmScheduler, EventAlarmUsers},
    },
    contact::{AddressBook, AddressBookPreferences, ContactCard, ContactCardContent},
    file::{FileNode, FileNodeContent, FileProperties},
    scheduling::inbound::itip_import_message,
};
use jmap_proto::object::{JmapRight, addressbook::AddressBookRight};
use model::{
    AddressBookRecord, CalendarEventRecord, CalendarPreferencesRecord, CalendarRecord,
    ChangedByRecord, ContactRecord, DavNameRecord, EventNotificationRecord, Explanation,
    FileNodeRecord, IssueKind, Severity, TimeZoneRecord, WriteMode, WriteOutcome,
};
use store::{
    ValueKey,
    rkyv::{
        Archive as RkyvArchive, Deserialize as RkyvDeserialize,
        api::high::{HighDeserializer, HighValidator},
        bytecheck::CheckBytes,
        rancor,
    },
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    blob_hash::BlobHash,
    collection::Collection,
    field::Field,
};

use crate::{
    error::trc_error,
    mail::{acl_grants, issue},
    objects::write_object,
    target::V1Target,
    writer::AccountContext,
};

const V016_ADDRESS_BOOK_MAY_WRITE: [Acl; 3] = [Acl::Modify, Acl::AddItems, Acl::ModifyItems];

fn report_address_book_may_write(document_id: u32, acls: &[AclGrant], outcome: &mut WriteOutcome) {
    for grant in acls {
        if V016_ADDRESS_BOOK_MAY_WRITE
            .iter()
            .all(|acl| grant.grants.contains(*acl))
            && !AddressBookRight::MayWrite.is_granted(&grant.grants)
        {
            outcome.issues.push(issue(
                Severity::Warning,
                IssueKind::Changed,
                model::Collection::AddressBook,
                document_id,
                format!(
                    "the share with account {} keeps its rights, but v1 no longer reports mayWrite for it: v1 also requires the remove items right, which v0.16 granted only with mayDelete",
                    grant.account_id
                ),
            ));
        }
    }
}

fn dav_names(names: &[DavNameRecord]) -> Vec<DavName> {
    names
        .iter()
        .map(|name| DavName {
            name: name.name.clone(),
            parent_id: name.parent_id,
        })
        .collect()
}

fn time_zone(
    record: &TimeZoneRecord,
    account_id: u32,
    document_id: u32,
    outcome: &mut WriteOutcome,
) -> Timezone {
    match record {
        TimeZoneRecord::Default => Timezone::Default,
        TimeZoneRecord::Iana(name) => match Tz::from_str(name) {
            Ok(tz) => Timezone::IANA(tz.as_id()),
            Err(()) => {
                outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Changed,
                        model::Collection::Calendar,
                        document_id,
                        format!("time zone {name} is unknown to v1, the default time zone applies"),
                    )
                    .explaining(Explanation::TimeZone(account_id)),
                );
                Timezone::Default
            }
        },
        TimeZoneRecord::Custom(text) => match ICalendar::parse(text) {
            Ok(calendar) => Timezone::Custom(calendar),
            Err(_) => {
                outcome.issues.push(
                    issue(
                        Severity::Warning,
                        IssueKind::Changed,
                        model::Collection::Calendar,
                        document_id,
                        "custom time zone does not parse in v1, the default time zone applies",
                    )
                    .explaining(Explanation::TimeZone(account_id)),
                );
                Timezone::Default
            }
        },
    }
}

fn calendar_preferences(
    record: &CalendarPreferencesRecord,
    document_id: u32,
    outcome: &mut WriteOutcome,
) -> CalendarPreferences {
    CalendarPreferences {
        account_id: record.account_id,
        name: record.name.clone(),
        description: record.description.clone(),
        sort_order: record.sort_order,
        color: record.color.clone(),
        flags: record.flags,
        time_zone: time_zone(&record.time_zone, record.account_id, document_id, outcome),
        default_alerts: record
            .default_alerts
            .iter()
            .filter_map(|alert| match parse_duration(&alert.offset) {
                Some(offset) => Some(DefaultAlert {
                    id: alert.id.clone(),
                    offset,
                    flags: alert.flags,
                }),
                None => {
                    outcome.issues.push(
                        issue(
                            Severity::Warning,
                            IssueKind::Dropped,
                            model::Collection::Calendar,
                            document_id,
                            format!("default alert offset {} does not parse", alert.offset),
                        )
                        .explaining(Explanation::DefaultAlert(
                            record.account_id,
                            alert.id.as_str().into(),
                        )),
                    );
                    None
                }
            })
            .collect(),
    }
}

fn updates_an_event(message: &ICalendar) -> bool {
    message.components.first().is_some_and(|calendar| {
        calendar.entries.iter().any(|entry| {
            entry.name == ICalendarProperty::Method
                && matches!(
                    entry.values.first(),
                    Some(ICalendarValue::Method(
                        ICalendarMethod::Reply | ICalendarMethod::Cancel
                    ))
                )
        })
    })
}

impl V1Target {
    pub(crate) async fn write_calendars(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        records: &[CalendarRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for record in records {
            let mut calendar = Calendar {
                name: record.name.clone(),
                preferences: record
                    .preferences
                    .iter()
                    .map(|preferences| {
                        calendar_preferences(preferences, record.document_id, outcome)
                    })
                    .collect(),
                acls: acl_grants(&record.acls),
                supported_components: record.supported_components,
                presence: 0,
                created: record.created,
                modified: record.modified,
            };
            let current = self
                .existing(account_id, Collection::Calendar, record.document_id, mode)
                .await?;
            if let Some(dead) = self
                .dead_write(
                    server,
                    account_id,
                    Collection::Calendar,
                    model::Collection::Calendar,
                    record.document_id,
                    &record.dead_properties,
                    None,
                    current.is_some(),
                    outcome,
                )
                .await?
            {
                calendar.set_metadata_kinds(dead.kinds);
                dead.build(record.document_id, &mut batch.batch)?;
            }
            write_object(
                &mut batch.batch,
                Collection::Calendar,
                record.document_id,
                current.as_ref(),
                calendar,
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_address_books(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        records: &[AddressBookRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for record in records {
            let mut book = AddressBook {
                name: record.name.clone(),
                preferences: record
                    .preferences
                    .iter()
                    .map(|preferences| AddressBookPreferences {
                        account_id: preferences.account_id,
                        name: preferences.name.clone(),
                        description: preferences.description.clone(),
                        sort_order: preferences.sort_order,
                    })
                    .collect(),
                subscribers: record.subscribers.clone(),
                presence: 0,
                acls: acl_grants(&record.acls),
                created: record.created,
                modified: record.modified,
            };
            let current = self
                .existing(
                    account_id,
                    Collection::AddressBook,
                    record.document_id,
                    mode,
                )
                .await?;
            if let Some(dead) = self
                .dead_write(
                    server,
                    account_id,
                    Collection::AddressBook,
                    model::Collection::AddressBook,
                    record.document_id,
                    &record.dead_properties,
                    None,
                    current.is_some(),
                    outcome,
                )
                .await?
            {
                book.set_metadata_kinds(dead.kinds);
                dead.build(record.document_id, &mut batch.batch)?;
            }
            report_address_book_may_write(record.document_id, &book.acls, outcome);
            write_object(
                &mut batch.batch,
                Collection::AddressBook,
                record.document_id,
                current.as_ref(),
                book,
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_file_nodes(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        records: &[FileNodeRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for record in records {
            let mut node = FileNode {
                parent_id: record.parent_id.map_or(0, |parent_id| parent_id + 1),
                name: record.name.clone(),
                content: match &record.file {
                    Some(file) => FileNodeContent::File(FileProperties {
                        blob_hash: BlobHash(file.blob_hash.0),
                        size: file.size,
                        media_type: file.media_type.as_deref().map(str::to_string),
                        executable: file.executable,
                    }),
                    None => FileNodeContent::Directory,
                },
                flags: 0,
                etag: 0,
                created: record.created,
                modified: record.modified,
                accessed: record.modified,
                changed: record.modified,
                unsubscribed: Vec::new(),
                acls: acl_grants(&record.acls),
            };
            let current = self
                .existing(account_id, Collection::FileNode, record.document_id, mode)
                .await?;
            if let Some(dead) = self
                .dead_write(
                    server,
                    account_id,
                    Collection::FileNode,
                    model::Collection::FileNode,
                    record.document_id,
                    &record.dead_properties,
                    record.display_name.as_deref(),
                    current.is_some(),
                    outcome,
                )
                .await?
            {
                node.set_presence(dead.file_presence);
                dead.build(record.document_id, &mut batch.batch)?;
            }
            write_object(
                &mut batch.batch,
                Collection::FileNode,
                record.document_id,
                current.as_ref(),
                node,
                context.changed_by,
            )
            .map_err(trc_error)?;
            if let Some(file) = &record.file {
                batch.batch.set(
                    store::write::BlobOp::Commit {
                        hash: BlobHash(file.blob_hash.0),
                    },
                    Vec::new(),
                );
            }
            batch.record_done(256);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_calendar_events(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        records: &[CalendarEventRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let max_instances = server.core.groupware.max_ical_instances;
        let mut batch = self.import_batch(account_id);
        let mut resolver = DefaultAlertsResolver::default();
        let start_time = now() as i64;
        for record in records {
            let Ok(ical) = ICalendar::parse(&record.icalendar) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::CalendarEvent,
                    record.document_id,
                    "the iCalendar object does not parse in v1",
                ));
                continue;
            };
            let mut preferences = Vec::new();
            for record_preferences in &record.preferences {
                if !record_preferences.properties.is_empty()
                    || !record_preferences.alerts.is_empty()
                {
                    outcome.issues.push(issue(
                        Severity::Warning,
                        IssueKind::Dropped,
                        model::Collection::CalendarEvent,
                        record.document_id,
                        format!(
                            "per-user properties and alerts of account {} are not copied",
                            record_preferences.account_id
                        ),
                    ));
                }
                let mut user = EventPreferences {
                    account_id: record_preferences.account_id,
                    updated: record.modified,
                    instances: Vec::new(),
                };
                if record_preferences.flags & model::EventPreferencesRecord::USE_DEFAULT_ALERTS != 0
                    && user.set_use_default_alerts(true).is_ok()
                {
                    preferences.push(user);
                }
            }
            let mut event = CalendarEvent {
                names: dav_names(&record.names),
                display_name: record.display_name.clone(),
                created: record.created,
                modified: record.modified,
                flags: record.flags,
                schedule_tag: record.schedule_tag,
                ..Default::default()
            };
            let content = CalendarEventContent {
                data: CalendarEventData::new(ical, Tz::Floating, max_instances),
                preferences,
            };
            let current = self
                .split_current(
                    account_id,
                    Collection::CalendarEvent,
                    CalendarEvent::CONTENT_FIELD,
                    record.document_id,
                    mode,
                )
                .await?;
            if let Some(current) = &current {
                clear_event_alarms(
                    server,
                    account_id,
                    record.document_id,
                    current,
                    &mut batch.batch,
                )
                .await?;
            }
            if let Some(dead) = self
                .dead_write(
                    server,
                    account_id,
                    Collection::CalendarEvent,
                    model::Collection::CalendarEvent,
                    record.document_id,
                    &record.dead_properties,
                    None,
                    current.is_some(),
                    outcome,
                )
                .await?
            {
                event.set_metadata_kinds(dead.kinds);
                dead.build(record.document_id, &mut batch.batch)?;
            }
            let calendar_ids = record
                .names
                .iter()
                .map(|name| name.parent_id)
                .collect::<Vec<_>>();
            let users = EventAlarmUsers::new(account_id, &content)
                .map_err(trc_error)?
                .with_event_flags(event.flags);
            let alarms = server
                .next_event_alarms(
                    account_id,
                    &users,
                    &content.data,
                    &calendar_ids,
                    start_time,
                    &mut resolver,
                )
                .await
                .map_err(trc_error)?;
            write_split(
                &mut batch.batch,
                Collection::CalendarEvent,
                record.document_id,
                current.as_ref(),
                GroupwareWrite::full(event, content, ()).map_err(trc_error)?,
                context.changed_by,
            )
            .map_err(trc_error)?;
            for alarm in alarms {
                alarm.write_task(&mut batch.batch).map_err(trc_error)?;
            }
            batch.record_done(2 * record.icalendar.len() as u64);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_event_notifications(
        &self,
        context: &AccountContext,
        account_id: u32,
        records: &[EventNotificationRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for record in records {
            let Ok(message) = ICalendar::parse(&record.icalendar) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::CalendarEventNotification,
                    record.document_id,
                    "the scheduling message does not parse in v1",
                ));
                continue;
            };
            let notification = CalendarEventNotification {
                event_id: record.event_id,
                changed_by: match &record.changed_by {
                    ChangedByRecord::PrincipalId(id) => NotificationChangedBy::PrincipalId(*id),
                    ChangedByRecord::CalendarAddress(address) => {
                        NotificationChangedBy::CalendarAddress(address.to_string())
                    }
                },
                created: record.created,
                modified: record.modified,
                flags: record.flags,
                ..Default::default()
            };
            let event = match record.event_id {
                Some(event_id)
                    if record.flags & EVENT_NOTIFICATION_IS_CHANGE != 0
                        || updates_an_event(&message) =>
                {
                    self.event_icalendar(account_id, event_id).await?
                }
                _ => None,
            };
            let current = event.or_else(|| {
                let mut current = message.clone();
                itip_import_message(&mut current).is_ok().then_some(current)
            });
            let content = CalendarEventNotificationContent::Itip {
                message,
                previous: None,
                current,
            };
            let current = self
                .split_current(
                    account_id,
                    Collection::CalendarEventNotification,
                    CalendarEventNotification::CONTENT_FIELD,
                    record.document_id,
                    mode,
                )
                .await?;
            write_split(
                &mut batch.batch,
                Collection::CalendarEventNotification,
                record.document_id,
                current.as_ref(),
                GroupwareWrite::full(notification, content, ()).map_err(trc_error)?,
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(2 * record.icalendar.len() as u64);
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_contacts(
        &self,
        server: &Server,
        context: &AccountContext,
        account_id: u32,
        records: &[ContactRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = self.import_batch(account_id);
        for record in records {
            let Ok(card) = VCard::parse(&record.vcard) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::ContactCard,
                    record.document_id,
                    "the vCard does not parse in v1",
                ));
                continue;
            };
            let version = card.version().unwrap_or(VCardVersion::V4_0);
            let mut contact = ContactCard {
                names: dav_names(&record.names),
                display_name: record.display_name.clone(),
                created: record.created,
                modified: record.modified,
                ..Default::default()
            };
            let current = self
                .split_current(
                    account_id,
                    Collection::ContactCard,
                    ContactCard::CONTENT_FIELD,
                    record.document_id,
                    mode,
                )
                .await?;
            if let Some(dead) = self
                .dead_write(
                    server,
                    account_id,
                    Collection::ContactCard,
                    model::Collection::ContactCard,
                    record.document_id,
                    &record.dead_properties,
                    None,
                    current.is_some(),
                    outcome,
                )
                .await?
            {
                contact.set_metadata_kinds(dead.kinds);
                dead.build(record.document_id, &mut batch.batch)?;
            }
            write_split(
                &mut batch.batch,
                Collection::ContactCard,
                record.document_id,
                current.as_ref(),
                GroupwareWrite::full(contact, ContactCardContent { card }, version)
                    .map_err(trc_error)?,
                context.changed_by,
            )
            .map_err(trc_error)?;
            batch.record_done(2 * record.vcard.len() as u64);
        }
        batch.commit(&self.store).await
    }

    async fn event_icalendar(
        &self,
        account_id: u32,
        event_id: u32,
    ) -> model::Result<Option<ICalendar>> {
        self.store
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                Collection::CalendarEvent,
                event_id,
                CalendarEvent::CONTENT_FIELD,
            ))
            .await
            .map_err(trc_error)?
            .map(|content| {
                content
                    .deserialize::<CalendarEventContent>()
                    .map(|content| content.data.event)
                    .map_err(trc_error)
            })
            .transpose()
    }

    async fn split_current(
        &self,
        account_id: u32,
        collection: Collection,
        content_field: Field,
        document_id: u32,
        mode: WriteMode,
    ) -> model::Result<Option<SplitArchives>> {
        let Some(meta) = self
            .existing(account_id, collection, document_id, mode)
            .await?
        else {
            return Ok(None);
        };
        let content = self
            .store
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                collection,
                document_id,
                content_field,
            ))
            .await
            .map_err(trc_error)?;
        Ok(Some(SplitArchives { meta, content }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn delete_groupware(
        &self,
        server: &Server,
        context: &AccountContext,
        batch: &mut BatchBuilder,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        current: Archive<ArchiveBytes>,
    ) -> model::Result<()> {
        let changed_by = context.changed_by;
        let result = match collection {
            Collection::Calendar => {
                let archive = current
                    .to_unarchived::<Calendar>()
                    .caused_by(trc::location!());
                match archive {
                    Ok(archive) => {
                        DestroyArchive(archive)
                            .delete(server, changed_by, account_id, document_id, None, batch)
                            .await
                    }
                    Err(err) => Err(err),
                }
            }
            Collection::AddressBook => match current.to_unarchived::<AddressBook>() {
                Ok(archive) => {
                    DestroyArchive(archive)
                        .delete(server, changed_by, account_id, document_id, None, batch)
                        .await
                }
                Err(err) => Err(err),
            },
            Collection::FileNode => match current.to_unarchived::<FileNode>() {
                Ok(archive) => {
                    DestroyArchive(archive)
                        .delete(
                            server,
                            changed_by,
                            account_id,
                            document_id,
                            batch,
                            String::new(),
                        )
                        .await
                }
                Err(err) => Err(err),
            },
            Collection::CalendarEvent => match current.to_unarchived::<CalendarEvent>() {
                Ok(archive) => {
                    let account_info = server.account_info(account_id).await.map_err(trc_error)?;
                    DestroyArchive(archive)
                        .delete_all(
                            server,
                            &account_info,
                            account_id,
                            document_id,
                            None,
                            false,
                            batch,
                        )
                        .await
                }
                Err(err) => Err(err),
            },
            Collection::CalendarEventNotification => {
                match current.to_unarchived::<CalendarEventNotification>() {
                    Ok(archive) => {
                        DestroyArchive(archive).delete(changed_by, account_id, document_id, batch)
                    }
                    Err(err) => Err(err),
                }
            }
            Collection::ContactCard => match current.to_unarchived::<ContactCard>() {
                Ok(archive) => {
                    DestroyArchive(archive)
                        .delete_all(server, changed_by, account_id, document_id, batch)
                        .await
                }
                Err(err) => Err(err),
            },
            _ => Ok(()),
        };
        result.map_err(trc_error)
    }
}

struct SplitArchives {
    meta: Archive<ArchiveBytes>,
    content: Option<Archive<ArchiveBytes>>,
}

async fn clear_event_alarms(
    server: &Server,
    account_id: u32,
    document_id: u32,
    current: &SplitArchives,
    batch: &mut BatchBuilder,
) -> model::Result<()> {
    let event = current
        .meta
        .unarchive::<CalendarEvent>()
        .map_err(trc_error)?;
    if event.flags.to_native() & EVENT_HAS_ALARMS == 0 {
        return Ok(());
    }
    let targets = match &current.content {
        Some(content) => {
            let content = content
                .unarchive::<CalendarEventContent>()
                .map_err(trc_error)?;
            EventAlarmUsers::targets(account_id, content).collect()
        }
        None => vec![AlarmTarget::Owner],
    };
    server
        .clear_event_alarms(
            account_id,
            document_id,
            targets,
            &mut AlarmTasks::None,
            batch,
        )
        .await
        .map_err(trc_error)
}

fn write_split<M>(
    batch: &mut BatchBuilder,
    collection: Collection,
    document_id: u32,
    current: Option<&SplitArchives>,
    changes: GroupwareWrite<M>,
    changed_by: ChangedBy,
) -> trc::Result<()>
where
    M: SplitObject + 'static,
    M::Archived: ArchivedSplitObject
        + for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + RkyvDeserialize<M, HighDeserializer<rancor::Error>>,
    M::Content: RkyvArchive<Archived = <M::Archived as ArchivedSplitObject>::ArchivedContent>,
    <M::Archived as ArchivedSplitObject>::ArchivedContent: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + RkyvDeserialize<M::Content, HighDeserializer<rancor::Error>>,
{
    batch.with_collection(collection).with_document(document_id);
    let Some(current) = current else {
        batch.custom(
            ObjectIndexBuilder::<(), _>::new()
                .with_changes(changes)
                .with_changed_by(changed_by),
        )?;
        return Ok(());
    };
    let meta = current
        .meta
        .to_unarchived::<M>()
        .caused_by(trc::location!())?;
    let current = match &current.content {
        Some(content) => SplitCurrent::Full {
            meta,
            content: content
                .unarchive::<M::Content>()
                .caused_by(trc::location!())?,
        },
        None => SplitCurrent::MetaOnly(meta),
    };
    batch.custom(
        ObjectIndexBuilder::new()
            .with_current(current)
            .with_changes(changes)
            .with_changed_by(changed_by),
    )?;
    Ok(())
}

fn parse_duration(value: &str) -> Option<ICalendarDuration> {
    let (neg, rest) = match value.as_bytes().split_first()? {
        (b'-', rest) => (true, rest),
        (b'+', rest) => (false, rest),
        _ => (false, value.as_bytes()),
    };
    let rest = rest.strip_prefix(b"P")?;
    let mut duration = ICalendarDuration {
        neg,
        ..Default::default()
    };
    let mut number: Option<u32> = None;
    let mut in_time = false;
    for &byte in rest {
        match byte {
            b'0'..=b'9' => {
                number = Some(
                    number
                        .unwrap_or(0)
                        .checked_mul(10)?
                        .checked_add(u32::from(byte - b'0'))?,
                )
            }
            b'T' if !in_time && number.is_none() => in_time = true,
            b'W' if !in_time => duration.weeks = number.take()?,
            b'D' if !in_time => duration.days = number.take()?,
            b'H' if in_time => duration.hours = number.take()?,
            b'M' if in_time => duration.minutes = number.take()?,
            b'S' if in_time => duration.seconds = number.take()?,
            _ => return None,
        }
    }
    number.is_none().then_some(duration)
}
