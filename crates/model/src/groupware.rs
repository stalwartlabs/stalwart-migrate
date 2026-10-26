/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ids::BlobHash, mail::AclRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadPropertyTag {
    ElementStart {
        name: Box<str>,
        attrs: Option<Box<str>>,
    },
    ElementEnd,
    Text(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeadPropertyRecord(pub Vec<DeadPropertyTag>);

impl DeadPropertyRecord {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DavNameRecord {
    pub name: String,
    pub parent_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TimeZoneRecord {
    #[default]
    Default,
    Iana(Box<str>),
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefaultAlertRecord {
    pub id: String,
    pub offset: Box<str>,
    pub flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarPreferencesRecord {
    pub account_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
    pub color: Option<String>,
    pub flags: u16,
    pub time_zone: TimeZoneRecord,
    pub default_alerts: Vec<DefaultAlertRecord>,
}

impl CalendarPreferencesRecord {
    pub const SUBSCRIBED: u16 = 1;
    pub const INVISIBLE: u16 = 1 << 1;
    pub const AVAILABILITY_NONE: u16 = 1 << 2;
    pub const AVAILABILITY_ATTENDING: u16 = 1 << 3;
    pub const AVAILABILITY_ALL: u16 = 1 << 4;
}

impl DefaultAlertRecord {
    pub const WITH_TIME: u16 = 1;
    pub const EMAIL: u16 = 1 << 1;
    pub const RELATIVE_TO_END: u16 = 1 << 2;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarRecord {
    pub document_id: u32,
    pub name: String,
    pub preferences: Vec<CalendarPreferencesRecord>,
    pub acls: Vec<AclRecord>,
    pub supported_components: u64,
    pub dead_properties: DeadPropertyRecord,
    pub created: i64,
    pub modified: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventPreferencesRecord {
    pub account_id: u32,
    pub flags: u16,
    pub properties: String,
    pub alerts: String,
}

impl EventPreferencesRecord {
    pub const USE_DEFAULT_ALERTS: u16 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarEventRecord {
    pub document_id: u32,
    pub names: Vec<DavNameRecord>,
    pub display_name: Option<String>,
    pub icalendar: String,
    pub preferences: Vec<EventPreferencesRecord>,
    pub flags: u16,
    pub dead_properties: DeadPropertyRecord,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
    pub schedule_tag: Option<u32>,
}

impl CalendarEventRecord {
    pub const INVITE_SELF: u16 = 1;
    pub const INVITE_OTHERS: u16 = 1 << 1;
    pub const HIDE_ATTENDEES: u16 = 1 << 2;
    pub const DRAFT: u16 = 1 << 3;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedByRecord {
    PrincipalId(u32),
    CalendarAddress(Box<str>),
}

impl Default for ChangedByRecord {
    fn default() -> Self {
        ChangedByRecord::PrincipalId(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventNotificationRecord {
    pub document_id: u32,
    pub icalendar: String,
    pub event_id: Option<u32>,
    pub changed_by: ChangedByRecord,
    pub flags: u16,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
}

impl EventNotificationRecord {
    pub const IS_DRAFT: u16 = 1;
    pub const IS_CHANGE: u16 = 1 << 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressBookPreferencesRecord {
    pub account_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressBookRecord {
    pub document_id: u32,
    pub name: String,
    pub preferences: Vec<AddressBookPreferencesRecord>,
    pub subscribers: Vec<u32>,
    pub dead_properties: DeadPropertyRecord,
    pub acls: Vec<AclRecord>,
    pub created: i64,
    pub modified: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContactRecord {
    pub document_id: u32,
    pub names: Vec<DavNameRecord>,
    pub display_name: Option<String>,
    pub vcard: String,
    pub dead_properties: DeadPropertyRecord,
    pub created: i64,
    pub modified: i64,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileRecord {
    pub blob_hash: BlobHash,
    pub size: u32,
    pub media_type: Option<Box<str>>,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileNodeRecord {
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub name: String,
    pub display_name: Option<String>,
    pub file: Option<FileRecord>,
    pub created: i64,
    pub modified: i64,
    pub dead_properties: DeadPropertyRecord,
    pub acls: Vec<AclRecord>,
}
