/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Collection {
    Email = 0,
    Mailbox = 1,
    Thread = 2,
    Identity = 3,
    EmailSubmission = 4,
    SieveScript = 5,
    PushSubscription = 6,
    Principal = 7,
    Calendar = 8,
    CalendarEvent = 9,
    AddressBook = 10,
    ContactCard = 11,
    FileNode = 12,
    CalendarEventNotification = 13,
}

impl Collection {
    pub const COUNT: usize = 14;

    pub const ALL: [Collection; Collection::COUNT] = [
        Collection::Email,
        Collection::Mailbox,
        Collection::Thread,
        Collection::Identity,
        Collection::EmailSubmission,
        Collection::SieveScript,
        Collection::PushSubscription,
        Collection::Principal,
        Collection::Calendar,
        Collection::CalendarEvent,
        Collection::AddressBook,
        Collection::ContactCard,
        Collection::FileNode,
        Collection::CalendarEventNotification,
    ];

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        Self::ALL.get(usize::from(value)).copied()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Collection::Email => "email",
            Collection::Mailbox => "mailbox",
            Collection::Thread => "thread",
            Collection::Identity => "identity",
            Collection::EmailSubmission => "emailSubmission",
            Collection::SieveScript => "sieveScript",
            Collection::PushSubscription => "pushSubscription",
            Collection::Principal => "principal",
            Collection::Calendar => "calendar",
            Collection::CalendarEvent => "calendarEvent",
            Collection::AddressBook => "addressBook",
            Collection::ContactCard => "contactCard",
            Collection::FileNode => "fileNode",
            Collection::CalendarEventNotification => "calendarEventNotification",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::map!(value.as_bytes(), Collection,
            "email" => Collection::Email,
            "mailbox" => Collection::Mailbox,
            "thread" => Collection::Thread,
            "identity" => Collection::Identity,
            "emailSubmission" => Collection::EmailSubmission,
            "sieveScript" => Collection::SieveScript,
            "pushSubscription" => Collection::PushSubscription,
            "principal" => Collection::Principal,
            "calendar" => Collection::Calendar,
            "calendarEvent" => Collection::CalendarEvent,
            "addressBook" => Collection::AddressBook,
            "contactCard" => Collection::ContactCard,
            "fileNode" => Collection::FileNode,
            "calendarEventNotification" => Collection::CalendarEventNotification,
        )
        .copied()
    }
}

impl fmt::Display for Collection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogCollection {
    Email = 0,
    Thread = 1,
    Calendar = 2,
    AddressBook = 3,
    FileNode = 4,
    Identity = 5,
    EmailSubmission = 6,
    SieveScript = 7,
    CalendarEventNotification = 8,
    ShareNotification = 9,
    VanishedEmail = 251,
    VanishedCalendar = 252,
    VanishedAddressBook = 253,
    VanishedFileNode = 254,
}

impl LogCollection {
    pub const ALL: [LogCollection; 14] = [
        LogCollection::Email,
        LogCollection::Thread,
        LogCollection::Calendar,
        LogCollection::AddressBook,
        LogCollection::FileNode,
        LogCollection::Identity,
        LogCollection::EmailSubmission,
        LogCollection::SieveScript,
        LogCollection::CalendarEventNotification,
        LogCollection::ShareNotification,
        LogCollection::VanishedEmail,
        LogCollection::VanishedCalendar,
        LogCollection::VanishedAddressBook,
        LogCollection::VanishedFileNode,
    ];

    pub const CHANGES: [LogCollection; 13] = [
        LogCollection::Email,
        LogCollection::Thread,
        LogCollection::Calendar,
        LogCollection::AddressBook,
        LogCollection::FileNode,
        LogCollection::Identity,
        LogCollection::EmailSubmission,
        LogCollection::SieveScript,
        LogCollection::CalendarEventNotification,
        LogCollection::VanishedEmail,
        LogCollection::VanishedCalendar,
        LogCollection::VanishedAddressBook,
        LogCollection::VanishedFileNode,
    ];

    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0..=9 => Self::ALL.get(usize::from(value)).copied(),
            251 => Some(LogCollection::VanishedEmail),
            252 => Some(LogCollection::VanishedCalendar),
            253 => Some(LogCollection::VanishedAddressBook),
            254 => Some(LogCollection::VanishedFileNode),
            _ => None,
        }
    }

    pub const fn is_vanished(self) -> bool {
        matches!(
            self,
            LogCollection::VanishedEmail
                | LogCollection::VanishedCalendar
                | LogCollection::VanishedAddressBook
                | LogCollection::VanishedFileNode
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BlobHash(pub [u8; 32]);

impl BlobHash {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MailboxUid {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_names_round_trip() {
        for collection in Collection::ALL {
            assert_eq!(Collection::parse(collection.as_str()), Some(collection));
        }
        assert_eq!(Collection::parse("unknown"), None);
    }
}
