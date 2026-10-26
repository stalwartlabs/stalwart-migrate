/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write as _;

use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendarComponent, ICalendarEntry},
    vcard::VCardVersion,
};
use groupware::{
    calendar::{
        Calendar, CalendarEvent, CalendarEventNotification, CalendarPreferences, ChangedBy,
        DefaultAlert, EventPreferences, Timezone,
    },
    contact::{AddressBook, ContactCard},
    file::FileNode,
};
use model::{
    AddressBookPreferencesRecord, AddressBookRecord, CalendarEventRecord,
    CalendarPreferencesRecord, CalendarRecord, ChangedByRecord, ContactRecord, DefaultAlertRecord,
    EventNotificationRecord, EventPreferencesRecord, FileNodeRecord, FileRecord, TimeZoneRecord,
};
use store::write::{AlignedBytes, Archive};

use super::common::{acls, blob_hash, dav_names, dead_properties, stored_parent};
use crate::adapter::error::{corrupt, trc_error};

fn time_zone(time_zone: Timezone) -> model::Result<TimeZoneRecord> {
    Ok(match time_zone {
        Timezone::Default => TimeZoneRecord::Default,
        Timezone::IANA(id) => {
            let name = Tz::from_id(id)
                .and_then(|tz| tz.name())
                .ok_or_else(|| corrupt(format!("unknown time zone id {id}")))?;
            TimeZoneRecord::Iana(name.into_owned().into_boxed_str())
        }
        Timezone::Custom(calendar) => TimeZoneRecord::Custom(calendar.to_string()),
    })
}

fn default_alert(alert: DefaultAlert) -> DefaultAlertRecord {
    DefaultAlertRecord {
        id: alert.id,
        offset: alert.offset.to_string().into_boxed_str(),
        flags: alert.flags,
    }
}

fn calendar_preferences(
    preferences: CalendarPreferences,
) -> model::Result<CalendarPreferencesRecord> {
    Ok(CalendarPreferencesRecord {
        account_id: preferences.account_id,
        name: preferences.name,
        description: preferences.description,
        sort_order: preferences.sort_order,
        color: preferences.color,
        flags: preferences.flags,
        time_zone: time_zone(preferences.time_zone)?,
        default_alerts: preferences
            .default_alerts
            .into_iter()
            .map(default_alert)
            .collect(),
    })
}

pub(super) fn calendar(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<CalendarRecord> {
    let calendar = archive.deserialize::<Calendar>().map_err(trc_error)?;
    Ok(CalendarRecord {
        document_id,
        name: calendar.name,
        preferences: calendar
            .preferences
            .into_iter()
            .map(calendar_preferences)
            .collect::<model::Result<_>>()?,
        acls: acls(calendar.acls),
        supported_components: calendar.supported_components,
        dead_properties: dead_properties(calendar.dead_properties),
        created: calendar.created,
        modified: calendar.modified,
    })
}

fn write_entries(out: &mut String, entries: &[ICalendarEntry]) {
    for entry in entries {
        let _ = entry.write_to(out);
    }
}

fn write_components(out: &mut String, components: &[ICalendarComponent]) {
    for component in components {
        let name = component.component_type.as_str();
        let _ = write!(out, "BEGIN:{name}\r\n");
        write_entries(out, &component.entries);
        let _ = write!(out, "END:{name}\r\n");
    }
}

fn event_preferences(preferences: EventPreferences) -> EventPreferencesRecord {
    let mut properties = String::new();
    write_entries(&mut properties, &preferences.properties);
    let mut alerts = String::new();
    write_components(&mut alerts, &preferences.alerts);
    EventPreferencesRecord {
        account_id: preferences.account_id,
        flags: preferences.flags,
        properties,
        alerts,
    }
}

pub(super) fn calendar_event(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<CalendarEventRecord> {
    let event = archive.deserialize::<CalendarEvent>().map_err(trc_error)?;
    Ok(CalendarEventRecord {
        document_id,
        names: dav_names(event.names),
        display_name: event.display_name,
        icalendar: event.data.event.to_string(),
        preferences: event
            .preferences
            .into_iter()
            .map(event_preferences)
            .collect(),
        flags: event.flags,
        dead_properties: dead_properties(event.dead_properties),
        size: event.size,
        created: event.created,
        modified: event.modified,
        schedule_tag: event.schedule_tag,
    })
}

pub(super) fn event_notification(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<EventNotificationRecord> {
    let notification = archive
        .deserialize::<CalendarEventNotification>()
        .map_err(trc_error)?;
    Ok(EventNotificationRecord {
        document_id,
        icalendar: notification.event.to_string(),
        event_id: notification.event_id,
        changed_by: match notification.changed_by {
            ChangedBy::PrincipalId(id) => ChangedByRecord::PrincipalId(id),
            ChangedBy::CalendarAddress(address) => {
                ChangedByRecord::CalendarAddress(address.into_boxed_str())
            }
        },
        flags: notification.flags,
        size: notification.size,
        created: notification.created,
        modified: notification.modified,
    })
}

pub(super) fn address_book(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<AddressBookRecord> {
    let book = archive.deserialize::<AddressBook>().map_err(trc_error)?;
    Ok(AddressBookRecord {
        document_id,
        name: book.name,
        preferences: book
            .preferences
            .into_iter()
            .map(|preferences| AddressBookPreferencesRecord {
                account_id: preferences.account_id,
                name: preferences.name,
                description: preferences.description,
                sort_order: preferences.sort_order,
            })
            .collect(),
        subscribers: book.subscribers,
        dead_properties: dead_properties(book.dead_properties),
        acls: acls(book.acls),
        created: book.created,
        modified: book.modified,
    })
}

pub(super) fn contact(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<ContactRecord> {
    let card = archive.deserialize::<ContactCard>().map_err(trc_error)?;
    let mut vcard = String::with_capacity(256);
    let version = card.card.version().unwrap_or(VCardVersion::V4_0);
    card.card
        .write_to(&mut vcard, version)
        .map_err(|_| corrupt("vCard could not be written"))?;
    Ok(ContactRecord {
        document_id,
        names: dav_names(card.names),
        display_name: card.display_name,
        vcard,
        dead_properties: dead_properties(card.dead_properties),
        created: card.created,
        modified: card.modified,
        size: card.size,
    })
}

pub(super) fn file_node(
    document_id: u32,
    archive: &Archive<AlignedBytes>,
) -> model::Result<FileNodeRecord> {
    let node = archive.deserialize::<FileNode>().map_err(trc_error)?;
    Ok(FileNodeRecord {
        document_id,
        parent_id: stored_parent(node.parent_id),
        name: node.name,
        display_name: node.display_name,
        file: node.file.map(|file| FileRecord {
            blob_hash: blob_hash(&file.blob_hash),
            size: file.size,
            media_type: file.media_type.map(String::into_boxed_str),
            executable: file.executable,
        }),
        created: node.created,
        modified: node.modified,
        dead_properties: dead_properties(node.dead_properties),
        acls: acls(node.acls),
    })
}
