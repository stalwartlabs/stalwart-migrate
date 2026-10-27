/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RegistryId {
    Singleton,
    Id(u64),
}

impl RegistryId {
    pub const fn id(self) -> Option<u64> {
        match self {
            RegistryId::Singleton => None,
            RegistryId::Id(id) => Some(id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegistryKey {
    pub object: Box<str>,
    pub id: RegistryId,
}

impl RegistryKey {
    pub fn new(object: impl Into<Box<str>>, id: u64) -> Self {
        RegistryKey {
            object: object.into(),
            id: RegistryId::Id(id),
        }
    }

    pub fn singleton(object: impl Into<Box<str>>) -> Self {
        RegistryKey {
            object: object.into(),
            id: RegistryId::Singleton,
        }
    }
}

impl fmt::Display for RegistryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id {
            RegistryId::Singleton => f.write_str(&self.object),
            RegistryId::Id(id) => write!(f, "{}/{id}", self.object),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegistryRecord {
    pub key: RegistryKey,
    pub json: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RegistryEntries {
    pub records: Vec<RegistryRecord>,
    pub unreadable: Vec<RegistryKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryCounter {
    pub object: Box<str>,
    pub value: u64,
}
