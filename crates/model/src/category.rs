/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use crate::ids::{Collection, LogCollection};

macro_rules! categories {
    ($($variant:ident => $name:literal, $final_only:expr;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Category {
            $($variant,)*
        }

        impl Category {
            pub const ALL: &'static [Category] = &[$(Category::$variant,)*];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Category::$variant => $name,)*
                }
            }

            pub const fn is_final_only(self) -> bool {
                match self {
                    $(Category::$variant => $final_only,)*
                }
            }

            pub fn parse(value: &str) -> Option<Self> {
                hashify::map_ignore_case!(value.as_bytes(), Category,
                    $($name => Category::$variant,)*
                )
                .copied()
            }
        }
    };
}

categories! {
    Settings => "settings", false;
    Principals => "principals", false;
    Mail => "mail", false;
    Calendars => "calendars", false;
    Contacts => "contacts", false;
    Files => "files", false;
    Sieve => "sieve", false;
    Identities => "identities", false;
    PushSubscriptions => "push_subscriptions", false;
    SpamSamples => "spam_samples", false;
    Reports => "reports", false;
    Archive => "archive", false;
    SpamModel => "spam_model", true;
    Queue => "queue", true;
    Tasks => "tasks", true;
    Telemetry => "telemetry", false;
}

impl Category {
    pub const fn of_collection(collection: Collection) -> Category {
        match collection {
            Collection::Email
            | Collection::Mailbox
            | Collection::Thread
            | Collection::EmailSubmission => Category::Mail,
            Collection::Identity => Category::Identities,
            Collection::SieveScript => Category::Sieve,
            Collection::PushSubscription => Category::PushSubscriptions,
            Collection::Principal => Category::Principals,
            Collection::Calendar
            | Collection::CalendarEvent
            | Collection::CalendarEventNotification => Category::Calendars,
            Collection::AddressBook | Collection::ContactCard => Category::Contacts,
            Collection::FileNode => Category::Files,
        }
    }

    pub const fn of_log_collection(collection: LogCollection) -> Category {
        match collection {
            LogCollection::Email
            | LogCollection::Thread
            | LogCollection::EmailSubmission
            | LogCollection::VanishedEmail => Category::Mail,
            LogCollection::Calendar
            | LogCollection::CalendarEventNotification
            | LogCollection::VanishedCalendar => Category::Calendars,
            LogCollection::AddressBook | LogCollection::VanishedAddressBook => Category::Contacts,
            LogCollection::FileNode | LogCollection::VanishedFileNode => Category::Files,
            LogCollection::Identity => Category::Identities,
            LogCollection::SieveScript => Category::Sieve,
            LogCollection::ShareNotification => Category::Principals,
        }
    }

    const fn bit(self) -> u32 {
        1 << (self as u8)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CategorySet(u32);

impl CategorySet {
    pub const fn empty() -> Self {
        CategorySet(0)
    }

    pub fn all() -> Self {
        Category::ALL.iter().copied().collect()
    }

    pub fn defaults() -> Self {
        Self::all()
    }

    pub const fn contains(self, category: Category) -> bool {
        self.0 & category.bit() != 0
    }

    pub const fn contains_collection(self, collection: Collection) -> bool {
        self.contains(Category::of_collection(collection))
    }

    pub const fn contains_log_collection(self, collection: LogCollection) -> bool {
        self.contains(Category::of_log_collection(collection))
    }

    pub fn insert(&mut self, category: Category) {
        self.0 |= category.bit();
    }

    pub fn remove(&mut self, category: Category) {
        self.0 &= !category.bit();
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub fn from_bits(bits: u32) -> Self {
        CategorySet(bits & CategorySet::all().0)
    }

    pub const fn contains_all(self, other: CategorySet) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: CategorySet) -> CategorySet {
        CategorySet(self.0 | other.0)
    }

    pub const fn intersection(self, other: CategorySet) -> CategorySet {
        CategorySet(self.0 & other.0)
    }

    pub fn iter(self) -> impl Iterator<Item = Category> {
        Category::ALL
            .iter()
            .copied()
            .filter(move |category| self.contains(*category))
    }

    pub fn parse_list(value: &str) -> Result<Self, Box<str>> {
        let mut set = CategorySet::empty();
        for name in value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            let category =
                Category::parse(name).ok_or_else(|| format!("unknown category {name:?}"))?;
            set.insert(category);
        }
        Ok(set)
    }
}

impl FromIterator<Category> for CategorySet {
    fn from_iter<I: IntoIterator<Item = Category>>(iter: I) -> Self {
        let mut set = CategorySet::empty();
        for category in iter {
            set.insert(category);
        }
        set
    }
}

impl fmt::Display for CategorySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for category in self.iter() {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            f.write_str(category.as_str())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_round_trip() {
        let set = CategorySet::parse_list("mail, Queue,files").expect("valid list");
        assert!(set.contains(Category::Mail));
        assert!(set.contains(Category::Queue));
        assert!(set.contains(Category::Files));
        assert!(!set.contains(Category::Tasks));
        assert_eq!(set.to_string(), "mail,files,queue");
        assert_eq!(CategorySet::parse_list(&set.to_string()), Ok(set));
        assert!(CategorySet::parse_list("mail,bogus").is_err());
    }

    #[test]
    fn defaults_include_every_category() {
        let defaults = CategorySet::defaults();
        assert_eq!(defaults, CategorySet::all());
        assert!(defaults.contains(Category::Queue));
        assert!(defaults.contains(Category::Tasks));
        assert!(defaults.contains(Category::Telemetry));
        assert!(defaults.contains(Category::SpamModel));
        assert!(defaults.contains_collection(Collection::CalendarEvent));
    }
}
