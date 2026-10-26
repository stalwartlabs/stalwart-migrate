/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use trc::{EventType, RegistryEvent, StoreEvent};

pub fn trc_error(err: trc::Error) -> model::Error {
    let message = format!("{err}");
    match err.event_type() {
        EventType::Store(
            StoreEvent::DataCorruption
            | StoreEvent::DeserializeError
            | StoreEvent::DecompressError
            | StoreEvent::NotFound,
        )
        | EventType::Registry(RegistryEvent::DeserializationError) => {
            model::Error::account(message)
        }
        EventType::Store(StoreEvent::NotConfigured | StoreEvent::NotSupported) => {
            model::Error::fatal(message)
        }
        _ => model::Error::transient(message),
    }
}

#[cold]
pub(super) fn corrupt(what: impl fmt::Display) -> model::Error {
    model::Error::account(format!("invalid v1 data: {what}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenError(pub String);

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenError {}
