/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::push::{EmailPush, Keys, PushSubscription, PushSubscriptions, Urgency};
use groupware::calendar::{ParticipantIdentities, ParticipantIdentity};
use jmap_proto::object::{email::EmailProperty, push_subscription::EmailPushProperty};
use jmap_tools::Property;
use model::{
    AccountPointers, EmailPushRecord, Issue, IssueKind, ParticipantIdentitiesRecord, Pointer,
    PushRecord, Severity, Subject, WriteOutcome,
};
use store::{
    Serialize, SerializeInfallible,
    write::{Archiver, BatchBuilder, PendingId},
};
use types::{collection::Collection, field::PrincipalField, type_state::DataType};
use utils::map::bitmap::Bitmap;

use crate::{error::trc_error, target::V1Target};

const PRINCIPAL_DOCUMENT: u32 = 0;
const GLOBAL_ACCOUNT: u32 = u32::MAX;

fn principal_issue(message: impl Into<Box<str>>) -> Issue {
    Issue::new(
        Severity::Warning,
        IssueKind::Dropped,
        Subject::None,
        message,
    )
}

fn urgency(value: &str) -> Option<Urgency> {
    hashify::map!(value.as_bytes(), Urgency,
        "very-low" => Urgency::VeryLow,
        "low" => Urgency::Low,
        "normal" => Urgency::Normal,
        "high" => Urgency::High,
    )
    .copied()
}

fn email_push(record: &EmailPushRecord) -> Option<EmailPush> {
    if !record.filter.is_null() {
        return None;
    }
    let properties = record
        .properties
        .iter()
        .map(|name| {
            <EmailProperty as Property>::try_parse(None, name)
                .and_then(|property| EmailPushProperty::try_from(&property).ok())
        })
        .collect::<Option<Vec<_>>>()?;
    Some(EmailPush {
        account_id: record.account_id,
        properties,
        filter: Vec::new(),
        urgency: urgency(&record.urgency)?,
    })
}

fn push_subscription(record: &PushRecord, outcome: &mut WriteOutcome) -> PushSubscription {
    let mut types = Bitmap::new();
    for name in &record.types {
        match DataType::parse(name) {
            Some(data_type) => types.insert(data_type),
            None => outcome.issues.push(principal_issue(format!(
                "push subscription {} type {name} has no v1 equivalent",
                record.id
            ))),
        }
    }
    let email_push = record
        .email_push
        .iter()
        .filter_map(|push| {
            let converted = email_push(push);
            if converted.is_none() {
                outcome.issues.push(principal_issue(format!(
                    "push subscription {} email push settings for account {} were dropped",
                    record.id, push.account_id
                )));
            }
            converted
        })
        .collect();
    PushSubscription {
        id: record.id,
        url: record.url.clone(),
        device_client_id: record.device_client_id.clone(),
        expires: record.expires,
        verification_code: record.verification_code.clone(),
        verified: record.verified,
        types,
        keys: record.keys.as_ref().map(|keys| Keys {
            p256dh: keys.p256dh.clone(),
            auth: keys.auth.clone(),
        }),
        email_push,
    }
}

fn participant_identities(record: &ParticipantIdentitiesRecord) -> ParticipantIdentities {
    ParticipantIdentities {
        identities: record
            .identities
            .iter()
            .map(|identity| ParticipantIdentity {
                id: identity.id,
                name: identity.name.clone(),
                calendar_address: identity.calendar_address.clone(),
            })
            .collect(),
        default_name: record.default_name.clone(),
        default: record.default,
        ..Default::default()
    }
}

fn set_or_clear_id(batch: &mut BatchBuilder, field: PrincipalField, value: &Pointer<u32>) {
    match value {
        Pointer::Keep => {}
        Pointer::Set(Some(id)) => {
            batch.set(field, PendingId::Assigned(*id));
        }
        Pointer::Set(None) => {
            batch.clear(field);
        }
    }
}

impl V1Target {
    pub(crate) async fn store_pointers(
        &self,
        account_id: u32,
        pointers: &AccountPointers,
    ) -> model::Result<WriteOutcome> {
        let mut outcome = WriteOutcome::ok();
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Principal)
            .with_document(PRINCIPAL_DOCUMENT);
        match &pointers.active_script {
            Pointer::Keep => {}
            Pointer::Set(Some(id)) => {
                batch.set(PrincipalField::ActiveScriptId, id.serialize());
            }
            Pointer::Set(None) => {
                batch.clear(PrincipalField::ActiveScriptId);
            }
        }
        set_or_clear_id(
            &mut batch,
            PrincipalField::DefaultCalendarId,
            &pointers.default_calendar,
        );
        set_or_clear_id(
            &mut batch,
            PrincipalField::DefaultAddressBookId,
            &pointers.default_address_book,
        );
        match &pointers.identity_addresses_hash {
            Pointer::Keep => {}
            Pointer::Set(Some(hash)) => {
                batch.set(PrincipalField::IdentityAddresses, hash.serialize());
            }
            Pointer::Set(None) => {
                batch.clear(PrincipalField::IdentityAddresses);
            }
        }
        match &pointers.participant_identities {
            Pointer::Keep => {}
            Pointer::Set(Some(identities)) => {
                batch.set(
                    PrincipalField::ParticipantIdentities,
                    Archiver::new(participant_identities(identities))
                        .serialize()
                        .map_err(trc_error)?,
                );
            }
            Pointer::Set(None) => {
                batch.clear(PrincipalField::ParticipantIdentities);
            }
        }
        if let Pointer::Set(subscriptions) = &pointers.push_subscriptions {
            let subscriptions = PushSubscriptions {
                subscriptions: subscriptions
                    .iter()
                    .flatten()
                    .map(|record| push_subscription(record, &mut outcome))
                    .collect(),
            };
            if subscriptions.subscriptions.is_empty() {
                batch.clear(PrincipalField::PushSubscriptions);
                batch
                    .with_account_id(GLOBAL_ACCOUNT)
                    .with_collection(Collection::Principal)
                    .with_document(account_id)
                    .untag(PrincipalField::PushSubscriptions);
            } else {
                batch.set(
                    PrincipalField::PushSubscriptions,
                    Archiver::new(subscriptions)
                        .serialize()
                        .map_err(trc_error)?,
                );
                batch
                    .with_account_id(GLOBAL_ACCOUNT)
                    .with_collection(Collection::Principal)
                    .with_document(account_id)
                    .tag(PrincipalField::PushSubscriptions);
            }
        }
        self.store
            .write_batch(&mut batch)
            .await
            .map_err(trc_error)?;
        Ok(outcome)
    }
}
