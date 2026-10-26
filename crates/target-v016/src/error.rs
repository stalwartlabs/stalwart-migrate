/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use trc::{EventType, RegistryEvent, StoreEvent};

const FDB_TRANSACTION_TOO_LARGE: u64 = 2101;
const FDB_VALUE_TOO_LARGE: u64 = 2103;

pub(crate) fn trc_error(err: trc::Error) -> model::Error {
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
        EventType::Store(StoreEvent::FoundationdbError)
            if err.value_as_uint(trc::Key::Code).is_some_and(|code| {
                code == FDB_TRANSACTION_TOO_LARGE || code == FDB_VALUE_TOO_LARGE
            }) =>
        {
            model::Error::too_large(message)
        }
        _ => model::Error::transient(message),
    }
}

#[cold]
pub(crate) fn fatal(what: impl Display) -> model::Error {
    model::Error::fatal(what.to_string())
}

#[cold]
pub(crate) fn account(what: impl Display) -> model::Error {
    model::Error::account(what.to_string())
}
