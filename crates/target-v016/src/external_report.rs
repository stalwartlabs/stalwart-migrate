/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::{
        prelude::{ObjectInner, Property},
        structs::{ArfExternalReport, DmarcExternalReport, TlsExternalReport},
    },
    types::{EnumImpl, ObjectImpl},
};
use smtp::reporting::index::ExternalReportIndex;
use store::{
    Deserialize,
    write::{BatchBuilder, RegistryClass, ValueClass},
};

pub(crate) enum ExternalReport<'x> {
    Dmarc(&'x DmarcExternalReport),
    Tls(&'x TlsExternalReport),
    Arf(&'x ArfExternalReport),
}

#[derive(PartialEq, Eq, Hash)]
pub(crate) struct ReportIdKey {
    object_id: u16,
    key: [u8; 16],
}

pub(crate) struct ReportIdOwner(pub(crate) u64);

impl Deserialize for ReportIdOwner {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes
            .split_first_chunk::<2>()
            .and_then(|(_, item_id)| item_id.first_chunk::<8>())
            .map(|item_id| ReportIdOwner(u64::from_be_bytes(*item_id)))
            .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())
    }
}

impl<'x> ExternalReport<'x> {
    pub(crate) fn of(inner: &'x ObjectInner) -> Option<Self> {
        match inner {
            ObjectInner::DmarcExternalReport(report) => Some(ExternalReport::Dmarc(report)),
            ObjectInner::TlsExternalReport(report) => Some(ExternalReport::Tls(report)),
            ObjectInner::ArfExternalReport(report) => Some(ExternalReport::Arf(report)),
            _ => None,
        }
    }

    pub(crate) fn write_ops(&self, batch: &mut BatchBuilder, item_id: u64, is_set: bool) {
        match self {
            ExternalReport::Dmarc(report) => report.write_ops(batch, item_id, is_set),
            ExternalReport::Tls(report) => report.write_ops(batch, item_id, is_set),
            ExternalReport::Arf(report) => report.write_ops(batch, item_id, is_set),
        }
    }

    pub(crate) fn report_id(&self) -> Option<ReportIdKey> {
        let (object_id, key) = match self {
            ExternalReport::Dmarc(report) => (DmarcExternalReport::OBJECT, report.unique_key()?),
            ExternalReport::Tls(report) => (TlsExternalReport::OBJECT, report.unique_key()?),
            ExternalReport::Arf(report) => (ArfExternalReport::OBJECT, report.unique_key()?),
        };
        Some(ReportIdKey {
            object_id: object_id.to_id(),
            key,
        })
    }
}

impl ReportIdKey {
    pub(crate) fn class(&self) -> ValueClass {
        ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: Some(self.object_id),
            index_id: Property::ReportId.to_id(),
            key: self.key.to_vec(),
        })
    }
}
