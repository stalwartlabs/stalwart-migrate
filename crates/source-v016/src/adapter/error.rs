/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::{EventType, Key, RegistryEvent, StoreEvent};

pub fn trc_error(mut err: trc::Error) -> model::Error {
    err.take_value(Key::Value);
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
pub fn corrupt(what: impl std::fmt::Display) -> model::Error {
    model::Error::account(format!("invalid v0.16 data: {what}"))
}
