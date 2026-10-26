/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{common::timezone::Tz, vcard::VCardVersion};
use groupware::{
    calendar::{
        Calendar, CalendarEvent, CalendarEventContent, CalendarEventNotification,
        CalendarEventNotificationContent, CalendarPreferences, ChangedBy, DefaultAlert, Timezone,
    },
    contact::{AddressBook, ContactCard, ContactCardContent},
    file::{FileNode, FileNodeContent},
};
use model::{
    AddressBookPreferencesRecord, AddressBookRecord, CalendarEventRecord,
    CalendarPreferencesRecord, CalendarRecord, ChangedByRecord, ContactRecord, DefaultAlertRecord,
    EventNotificationRecord, EventPreferencesRecord, FileNodeRecord, FileRecord, TimeZoneRecord,
};
use types::metadata::MetadataKinds;

use super::common::{acls, archive, blob_hash, dav_names, stored_parent, unsupported};
use crate::adapter::error::{corrupt, trc_error};

const EVENT_FLAGS: u16 = CalendarEventRecord::INVITE_SELF
    | CalendarEventRecord::INVITE_OTHERS
    | CalendarEventRecord::HIDE_ATTENDEES
    | CalendarEventRecord::DRAFT;
const NOTIFICATION_FLAGS: u16 =
    EventNotificationRecord::IS_DRAFT | EventNotificationRecord::IS_CHANGE;

pub(super) type Decoded<R> = (R, MetadataKinds);

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

pub(super) fn calendar(document_id: u32, bytes: &[u8]) -> model::Result<Decoded<CalendarRecord>> {
    let calendar = archive(bytes)?
        .deserialize::<Calendar>()
        .map_err(trc_error)?;
    let kinds = calendar.metadata_kinds();
    Ok((
        CalendarRecord {
            document_id,
            name: calendar.name,
            preferences: calendar
                .preferences
                .into_iter()
                .map(calendar_preferences)
                .collect::<model::Result<_>>()?,
            acls: acls(calendar.acls),
            supported_components: calendar.supported_components,
            dead_properties: Default::default(),
            created: calendar.created,
            modified: calendar.modified,
        },
        kinds,
    ))
}

pub(super) fn calendar_event(
    document_id: u32,
    meta: &[u8],
    content: &[u8],
) -> model::Result<Decoded<CalendarEventRecord>> {
    let event = archive(meta)?
        .deserialize::<CalendarEvent>()
        .map_err(trc_error)?;
    let content = archive(content)?
        .deserialize::<CalendarEventContent>()
        .map_err(trc_error)?;
    let kinds = event.metadata_kinds();
    Ok((
        CalendarEventRecord {
            document_id,
            names: dav_names(event.names),
            display_name: event.display_name,
            icalendar: content.data.event.to_string(),
            preferences: content
                .preferences
                .iter()
                .filter(|preferences| preferences.use_default_alerts())
                .map(|preferences| EventPreferencesRecord {
                    account_id: preferences.account_id,
                    flags: EventPreferencesRecord::USE_DEFAULT_ALERTS,
                    properties: String::new(),
                    alerts: String::new(),
                })
                .collect(),
            flags: event.flags & EVENT_FLAGS,
            dead_properties: Default::default(),
            size: event.size,
            created: event.created,
            modified: event.modified,
            schedule_tag: event.schedule_tag,
        },
        kinds,
    ))
}

pub(super) fn event_notification(
    document_id: u32,
    meta: &[u8],
    content: &[u8],
) -> model::Result<Decoded<EventNotificationRecord>> {
    let notification = archive(meta)?
        .deserialize::<CalendarEventNotification>()
        .map_err(trc_error)?;
    let content = archive(content)?
        .deserialize::<CalendarEventNotificationContent>()
        .map_err(trc_error)?;
    let icalendar = match content {
        CalendarEventNotificationContent::Itip { message, .. } => message.to_string(),
        CalendarEventNotificationContent::Direct { .. } => {
            return Err(unsupported("direct calendar notification"));
        }
    };
    Ok((
        EventNotificationRecord {
            document_id,
            icalendar,
            event_id: notification.event_id,
            changed_by: match notification.changed_by {
                ChangedBy::PrincipalId(id) => ChangedByRecord::PrincipalId(id),
                ChangedBy::CalendarAddress(address) => {
                    ChangedByRecord::CalendarAddress(address.into_boxed_str())
                }
            },
            flags: notification.flags & NOTIFICATION_FLAGS,
            size: notification.size,
            created: notification.created,
            modified: notification.modified,
        },
        MetadataKinds::NONE,
    ))
}

pub(super) fn address_book(
    document_id: u32,
    bytes: &[u8],
) -> model::Result<Decoded<AddressBookRecord>> {
    let book = archive(bytes)?
        .deserialize::<AddressBook>()
        .map_err(trc_error)?;
    let kinds = book.metadata_kinds();
    Ok((
        AddressBookRecord {
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
            dead_properties: Default::default(),
            acls: acls(book.acls),
            created: book.created,
            modified: book.modified,
        },
        kinds,
    ))
}

pub(super) fn contact(
    document_id: u32,
    meta: &[u8],
    content: &[u8],
) -> model::Result<Decoded<ContactRecord>> {
    let card = archive(meta)?
        .deserialize::<ContactCard>()
        .map_err(trc_error)?;
    let content = archive(content)?
        .deserialize::<ContactCardContent>()
        .map_err(trc_error)?;
    let kinds = card.metadata_kinds();
    let mut vcard = String::with_capacity(256);
    let version = content.card.version().unwrap_or(VCardVersion::V4_0);
    content
        .card
        .write_to(&mut vcard, version)
        .map_err(|_| corrupt("vCard could not be written"))?;
    Ok((
        ContactRecord {
            document_id,
            names: dav_names(card.names),
            display_name: card.display_name,
            vcard,
            dead_properties: Default::default(),
            created: card.created,
            modified: card.modified,
            size: card.size,
        },
        kinds,
    ))
}

pub(super) fn file_node(document_id: u32, bytes: &[u8]) -> model::Result<Decoded<FileNodeRecord>> {
    let node = archive(bytes)?
        .deserialize::<FileNode>()
        .map_err(trc_error)?;
    let kinds = node.metadata_kinds();
    let file = match node.content {
        FileNodeContent::Directory => None,
        FileNodeContent::File(file) => Some(FileRecord {
            blob_hash: blob_hash(&file.blob_hash),
            size: file.size,
            media_type: file.media_type.map(String::into_boxed_str),
            executable: file.executable,
        }),
        FileNodeContent::Symlink(_) => return Err(unsupported("file system symlink")),
    };
    Ok((
        FileNodeRecord {
            document_id,
            parent_id: stored_parent(node.parent_id),
            name: node.name,
            display_name: None,
            file,
            created: node.created,
            modified: node.modified,
            dead_properties: Default::default(),
            acls: acls(node.acls),
        },
        kinds,
    ))
}
