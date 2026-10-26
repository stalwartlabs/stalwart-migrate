/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarComponent, ICalendarDuration, ICalendarEntry},
    vcard::VCard,
};
use common::{DavName, Server, auth::AccountTenantIds};
use groupware::{
    calendar::{
        Calendar, CalendarEvent, CalendarEventData, CalendarEventNotification, CalendarPreferences,
        ChangedBy, DefaultAlert, EventPreferences, Timezone,
    },
    contact::{AddressBook, AddressBookPreferences, ContactCard},
    file::{FileNode, FileProperties},
};
use model::{
    AddressBookRecord, CalendarEventRecord, CalendarPreferencesRecord, CalendarRecord,
    ChangedByRecord, ContactRecord, DavNameRecord, DeadPropertyRecord, DeadPropertyTag,
    EventNotificationRecord, EventPreferencesRecord, Explanation, FileNodeRecord, IssueKind,
    Severity, TimeZoneRecord, WriteMode, WriteOutcome,
};
use store::write::{BatchBuilder, now};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    dead_property::{DeadElementTag, DeadProperty, DeadPropertyTag as V016Tag},
};

use crate::{
    error::trc_error,
    mail::{acl_grants, issue, stored_parent},
    objects::{StoredArchive, delete_object, write_object},
    target::V016Target,
    writer::ImportBatch,
};

const ENTRIES_PREFIX: &str = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n";
const ENTRIES_SUFFIX: &str = "END:VEVENT\r\nEND:VCALENDAR\r\n";
const COMPONENTS_PREFIX: &str = "BEGIN:VCALENDAR\r\n";
const COMPONENTS_SUFFIX: &str = "END:VCALENDAR\r\n";

fn dav_names(names: &[DavNameRecord]) -> Vec<DavName> {
    names
        .iter()
        .map(|name| DavName {
            name: name.name.clone(),
            parent_id: name.parent_id,
        })
        .collect()
}

fn dead_property(record: &DeadPropertyRecord) -> DeadProperty {
    DeadProperty(
        record
            .0
            .iter()
            .map(|tag| match tag {
                DeadPropertyTag::ElementStart { name, attrs } => {
                    V016Tag::ElementStart(DeadElementTag {
                        name: name.to_string(),
                        attrs: attrs.as_deref().map(str::to_string),
                    })
                }
                DeadPropertyTag::ElementEnd => V016Tag::ElementEnd,
                DeadPropertyTag::Text(text) => V016Tag::Text(text.to_string()),
            })
            .collect(),
    )
}

fn time_zone(
    record: &TimeZoneRecord,
    account_id: u32,
    document_id: u32,
    outcome: &mut WriteOutcome,
) -> Timezone {
    let unknown = |outcome: &mut WriteOutcome, message: String| {
        outcome.issues.push(
            issue(
                Severity::Warning,
                IssueKind::Changed,
                model::Collection::Calendar,
                document_id,
                message,
            )
            .explaining(Explanation::TimeZone(account_id)),
        );
        Timezone::Default
    };
    match record {
        TimeZoneRecord::Default => Timezone::Default,
        TimeZoneRecord::Iana(name) => match Tz::from_str(name) {
            Ok(tz) => Timezone::IANA(tz.as_id()),
            Err(_) => unknown(
                outcome,
                format!("time zone {name} is unknown to v0.16, the default time zone applies"),
            ),
        },
        TimeZoneRecord::Custom(text) => match ICalendar::parse(text) {
            Ok(calendar) => Timezone::Custom(calendar),
            Err(_) => unknown(
                outcome,
                "custom time zone does not parse in v0.16, the default time zone applies".into(),
            ),
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

fn wrapped(prefix: &str, body: &str, suffix: &str) -> Option<ICalendar> {
    let mut text = String::with_capacity(prefix.len() + body.len() + suffix.len());
    text.push_str(prefix);
    text.push_str(body);
    text.push_str(suffix);
    ICalendar::parse(text).ok()
}

fn preference_entries(text: &str) -> Option<Vec<ICalendarEntry>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let mut calendar = wrapped(ENTRIES_PREFIX, text, ENTRIES_SUFFIX)?;
    let event = calendar.components.get_mut(1)?;
    Some(std::mem::take(&mut event.entries))
}

fn preference_components(text: &str) -> Option<Vec<ICalendarComponent>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let calendar = wrapped(COMPONENTS_PREFIX, text, COMPONENTS_SUFFIX)?;
    let mut components = calendar.components;
    if components.is_empty() {
        return None;
    }
    components.remove(0);
    for component in &mut components {
        component.component_ids.clear();
    }
    Some(components)
}

fn event_preferences(
    record: &EventPreferencesRecord,
    document_id: u32,
    outcome: &mut WriteOutcome,
) -> EventPreferences {
    let (properties, alerts) = match (
        preference_entries(&record.properties),
        preference_components(&record.alerts),
    ) {
        (Some(properties), Some(alerts)) => (properties, alerts),
        _ => {
            outcome.issues.push(issue(
                Severity::Warning,
                IssueKind::Dropped,
                model::Collection::CalendarEvent,
                document_id,
                format!(
                    "per-user properties and alerts of account {} do not parse in v0.16",
                    record.account_id
                ),
            ));
            (Vec::new(), Vec::new())
        }
    };
    EventPreferences {
        account_id: record.account_id,
        flags: record.flags,
        properties,
        alerts,
    }
}

impl V016Target {
    pub(crate) async fn write_calendars(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[CalendarRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let calendar = Calendar {
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
                dead_properties: dead_property(&record.dead_properties),
                created: record.created,
                modified: record.modified,
            };
            let current = self
                .existing(account_id, Collection::Calendar, record.document_id, mode)
                .await?;
            write_object(
                &mut batch.batch,
                Collection::Calendar,
                record.document_id,
                current.as_ref(),
                calendar,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_address_books(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[AddressBookRecord],
        mode: WriteMode,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let book = AddressBook {
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
                dead_properties: dead_property(&record.dead_properties),
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
            write_object(
                &mut batch.batch,
                Collection::AddressBook,
                record.document_id,
                current.as_ref(),
                book,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_file_nodes(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[FileNodeRecord],
        mode: WriteMode,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let node = FileNode {
                parent_id: stored_parent(record.parent_id),
                name: record.name.clone(),
                display_name: record.display_name.clone(),
                file: record.file.as_ref().map(|file| FileProperties {
                    blob_hash: BlobHash(file.blob_hash.0),
                    size: file.size,
                    media_type: file.media_type.as_deref().map(str::to_string),
                    executable: file.executable,
                }),
                created: record.created,
                modified: record.modified,
                dead_properties: dead_property(&record.dead_properties),
                acls: acl_grants(&record.acls),
            };
            let current = self
                .existing(account_id, Collection::FileNode, record.document_id, mode)
                .await?;
            write_object(
                &mut batch.batch,
                Collection::FileNode,
                record.document_id,
                current.as_ref(),
                node,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_calendar_events(
        &self,
        server: &Server,
        context: AccountTenantIds,
        account_id: u32,
        records: &[CalendarEventRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let max_instances = server.core.groupware.max_ical_instances;
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let Ok(ical) = ICalendar::parse(&record.icalendar) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::CalendarEvent,
                    record.document_id,
                    "the event does not parse in v0.16",
                ));
                continue;
            };
            let mut next_alarm = None;
            let event = CalendarEvent {
                names: dav_names(&record.names),
                display_name: record.display_name.clone(),
                data: CalendarEventData::new(ical, Tz::Floating, max_instances, &mut next_alarm),
                preferences: record
                    .preferences
                    .iter()
                    .map(|preferences| event_preferences(preferences, record.document_id, outcome))
                    .collect(),
                flags: record.flags,
                dead_properties: dead_property(&record.dead_properties),
                size: record.size,
                created: record.created,
                modified: record.modified,
                schedule_tag: record.schedule_tag,
            };
            let current = self
                .existing(
                    account_id,
                    Collection::CalendarEvent,
                    record.document_id,
                    mode,
                )
                .await?;
            write_object(
                &mut batch.batch,
                Collection::CalendarEvent,
                record.document_id,
                current.as_ref(),
                event,
                context,
            )
            .map_err(trc_error)?;
            if let Some(current) = &current {
                clear_event_alarm(&mut batch.batch, current).map_err(trc_error)?;
            }
            if let Some(next_alarm) = next_alarm {
                next_alarm.write_task(&mut batch.batch);
            }
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_event_notifications(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[EventNotificationRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let Ok(event) = ICalendar::parse(&record.icalendar) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::CalendarEventNotification,
                    record.document_id,
                    "the scheduling message does not parse in v0.16",
                ));
                continue;
            };
            let notification = CalendarEventNotification {
                event,
                event_id: record.event_id,
                changed_by: match &record.changed_by {
                    ChangedByRecord::PrincipalId(id) => ChangedBy::PrincipalId(*id),
                    ChangedByRecord::CalendarAddress(address) => {
                        ChangedBy::CalendarAddress(address.to_string())
                    }
                },
                flags: record.flags,
                size: record.size,
                created: record.created,
                modified: record.modified,
            };
            let current = self
                .existing(
                    account_id,
                    Collection::CalendarEventNotification,
                    record.document_id,
                    mode,
                )
                .await?;
            write_object(
                &mut batch.batch,
                Collection::CalendarEventNotification,
                record.document_id,
                current.as_ref(),
                notification,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) async fn write_contacts(
        &self,
        context: AccountTenantIds,
        account_id: u32,
        records: &[ContactRecord],
        mode: WriteMode,
        outcome: &mut WriteOutcome,
    ) -> model::Result<()> {
        let mut batch = ImportBatch::new(account_id);
        for record in records {
            let Ok(card) = VCard::parse(&record.vcard) else {
                outcome.issues.push(issue(
                    Severity::Error,
                    IssueKind::Failed,
                    model::Collection::ContactCard,
                    record.document_id,
                    "the contact does not parse in v0.16",
                ));
                continue;
            };
            let contact = ContactCard {
                names: dav_names(&record.names),
                display_name: record.display_name.clone(),
                card,
                dead_properties: dead_property(&record.dead_properties),
                created: record.created,
                modified: record.modified,
                size: record.size,
            };
            let current = self
                .existing(
                    account_id,
                    Collection::ContactCard,
                    record.document_id,
                    mode,
                )
                .await?;
            write_object(
                &mut batch.batch,
                Collection::ContactCard,
                record.document_id,
                current.as_ref(),
                contact,
                context,
            )
            .map_err(trc_error)?;
            batch.record_done();
        }
        batch.commit(&self.store).await
    }

    pub(crate) fn delete_groupware(
        &self,
        batch: &mut BatchBuilder,
        context: AccountTenantIds,
        collection: Collection,
        document_id: u32,
        current: &StoredArchive,
    ) -> trc::Result<()> {
        match collection {
            Collection::Calendar => {
                delete_object::<Calendar>(batch, collection, document_id, current, context)
            }
            Collection::CalendarEvent => {
                delete_object::<CalendarEvent>(batch, collection, document_id, current, context)?;
                clear_event_alarm(batch, current)
            }
            Collection::CalendarEventNotification => delete_object::<CalendarEventNotification>(
                batch,
                collection,
                document_id,
                current,
                context,
            ),
            Collection::AddressBook => {
                delete_object::<AddressBook>(batch, collection, document_id, current, context)
            }
            Collection::ContactCard => {
                delete_object::<ContactCard>(batch, collection, document_id, current, context)
            }
            Collection::FileNode => {
                delete_object::<FileNode>(batch, collection, document_id, current, context)
            }
            _ => Err(trc::StoreEvent::NotSupported
                .into_err()
                .details("collection has no v0.16 documents to delete")),
        }
    }
}

fn clear_event_alarm(batch: &mut BatchBuilder, current: &StoredArchive) -> trc::Result<()> {
    let event = current
        .unarchive::<CalendarEvent>()
        .caused_by(trc::location!())?;
    if let Some(alarm) = event.data.next_alarm(now() as i64, Tz::Floating) {
        alarm.delete_task(batch);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Preference strings written by source-v016 parse back into entries and alarm components.
    #[test]
    fn preferences_round_trip() {
        let entries = preference_entries("COLOR:red\r\nX-FOO:bar\r\n").expect("entries");
        assert_eq!(entries.len(), 2);
        let alerts = preference_components(
            "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n",
        )
        .expect("alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].entries.len(), 2);
        assert_eq!(preference_entries(""), Some(Vec::new()));
        let duration = parse_duration("-PT15M").expect("duration");
        assert!(duration.neg);
        assert_eq!(duration.minutes, 15);
        assert!(parse_duration("P1X").is_none());
    }
}
