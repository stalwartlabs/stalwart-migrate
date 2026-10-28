mod ai;
mod auth;
mod misc;

pub(crate) use misc::report_strings;
mod stores;

use serde_json::{Map, Value};

use crate::{
    engine::{Direction, Flow, Walker},
    schema::TypeDef,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformKind {
    Value,
    Group,
    Property,
}

macro_rules! transforms {
    ($($variant:ident => $name:literal, $kind:ident, always: $always:literal, reverse: $reverse:literal, triggers: [$($trigger:literal),*];)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Transform {
            $($variant,)*
        }

        impl Transform {
            pub const ALL: &'static [Transform] = &[$(Transform::$variant,)*];

            pub fn parse(name: &str) -> Option<Self> {
                hashify::map!(name.as_bytes(), Transform,
                    $($name => Transform::$variant,)*
                )
                .copied()
            }

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Transform::$variant => $name,)*
                }
            }

            pub const fn kind(self) -> TransformKind {
                match self {
                    $(Transform::$variant => TransformKind::$kind,)*
                }
            }

            pub const fn always(self) -> bool {
                match self {
                    $(Transform::$variant => $always,)*
                }
            }

            pub const fn has_reverse(self) -> bool {
                match self {
                    $(Transform::$variant => $reverse,)*
                }
            }

            pub const fn reverse_triggers(self) -> &'static [&'static str] {
                match self {
                    $(Transform::$variant => &[$($trigger),*],)*
                }
            }
        }
    };
}

transforms! {
    AiModelUnion => "ai_model_union", Value, always: false, reverse: true, triggers: [];
    SpamLlmToAi => "spam_llm_to_ai", Value, always: false, reverse: true, triggers: [];
    DnsSig0 => "dns_sig0", Value, always: false, reverse: false, triggers: [];
    InMemoryCluster => "in_memory_cluster", Value, always: false, reverse: false, triggers: [];
    AzureAuth => "azure_auth", Group, always: true, reverse: true, triggers: ["auth"];
    S3SessionToken => "s3_session_token", Group, always: false, reverse: false, triggers: [];
    OidcDirectory => "oidc_directory", Group, always: true, reverse: true, triggers: ["acceptedAudiences"];
    OidcTokenLifetimes => "oidc_token_lifetimes", Group, always: false, reverse: false, triggers: [];
    OauthRegistration => "oauth_registration", Group, always: true, reverse: false, triggers: [];
    ClientIpSource => "client_ip_source", Group, always: false, reverse: true, triggers: ["clientIpSource", "forwardedHops"];
    Permissions => "permissions", Group, always: false, reverse: false, triggers: [];
    DmarcEnvelopeFrom => "dmarc_envelope_from", Group, always: true, reverse: false, triggers: ["envelopeFrom"];
    AcmeDescription => "acme_description", Group, always: true, reverse: true, triggers: ["description"];
    SearchFieldsFilter => "search_fields_filter", Property, always: false, reverse: true, triggers: ["indexEmailFields", "indexCalendarFields", "indexContactFields"];
    ExpressionRemovedVars => "expression_removed_vars", Property, always: false, reverse: false, triggers: [];
    WebuiBundle => "webui_bundle", Property, always: false, reverse: false, triggers: [];
    SpamTag => "spam_tag", Value, always: false, reverse: false, triggers: [];
}

impl Transform {
    pub(crate) fn apply_value(self, w: &mut Walker, value: Value) -> Option<Value> {
        match (self, w.direction()) {
            (Transform::AiModelUnion, Direction::Forward) => ai::ai_model_forward(w, value),
            (Transform::AiModelUnion, Direction::Reverse) => ai::ai_model_reverse(w, value),
            (Transform::SpamLlmToAi, Direction::Forward) => ai::spam_llm_forward(w, value),
            (Transform::SpamLlmToAi, Direction::Reverse) => ai::spam_ai_reverse(w, value),
            (Transform::DnsSig0, Direction::Forward) => stores::dns_sig0(w, value),
            (Transform::InMemoryCluster, Direction::Forward) => stores::in_memory_cluster(w, value),
            (Transform::SpamTag, Direction::Forward) => misc::spam_tag(w, value),
            _ => Some(value),
        }
    }

    pub(crate) fn apply_group(
        self,
        w: &mut Walker,
        src: &mut Map<String, Value>,
        out: &mut Map<String, Value>,
    ) -> Flow {
        match (self, w.direction()) {
            (Transform::AzureAuth, Direction::Forward) => stores::azure_auth_forward(w, src, out),
            (Transform::AzureAuth, Direction::Reverse) => stores::azure_auth_reverse(w, src, out),
            (Transform::S3SessionToken, Direction::Forward) => {
                stores::s3_session_token(w, src, out)
            }
            (Transform::OidcDirectory, Direction::Forward) => {
                auth::oidc_directory_forward(w, src, out)
            }
            (Transform::OidcDirectory, Direction::Reverse) => {
                auth::oidc_directory_reverse(w, src, out)
            }
            (Transform::OauthRegistration, Direction::Forward) => {
                auth::oauth_registration(w, src, out)
            }
            (Transform::OidcTokenLifetimes, Direction::Forward) => {
                auth::oidc_token_lifetimes(w, src, out)
            }
            (Transform::ClientIpSource, Direction::Forward) => {
                misc::client_ip_source_forward(w, src, out)
            }
            (Transform::ClientIpSource, Direction::Reverse) => {
                misc::client_ip_source_reverse(w, src, out)
            }
            (Transform::Permissions, Direction::Forward) => auth::permissions(w, src, out),
            (Transform::DmarcEnvelopeFrom, Direction::Forward) => {
                misc::dmarc_envelope_from(w, src, out)
            }
            (Transform::AcmeDescription, Direction::Forward) => misc::acme_description(w, src, out),
            (Transform::AcmeDescription, Direction::Reverse) => misc::acme_description_reverse(src),
            _ => Flow::Keep,
        }
    }

    pub(crate) fn apply_property(
        self,
        w: &mut Walker,
        name: &str,
        ty: &TypeDef,
        value: Value,
        out: &mut Map<String, Value>,
    ) -> Flow {
        match (self, w.direction()) {
            (Transform::SearchFieldsFilter, Direction::Forward) => {
                misc::search_fields_filter(w, name, ty, value, out)
            }
            (Transform::SearchFieldsFilter, Direction::Reverse) => {
                misc::search_fields_restore(w, name, ty, value, out)
            }
            (Transform::ExpressionRemovedVars, Direction::Forward) => {
                misc::expression_removed_vars(w, name, ty, value, out)
            }
            (Transform::WebuiBundle, Direction::Forward) => {
                misc::webui_bundle(w, name, ty, value, out)
            }
            _ => {
                let mut value = value;
                let flow = w.walk_value(ty, &mut value);
                out.insert(name.to_string(), value);
                flow
            }
        }
    }
}

pub(crate) fn is_set_secret(value: Option<&Value>) -> bool {
    value
        .and_then(|v| v.get(crate::engine::TYPE_KEY))
        .and_then(Value::as_str)
        .is_some_and(|t| t != "None")
}

pub(crate) fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

pub(crate) fn string(value: &str) -> Value {
    Value::String(value.to_string())
}

pub fn report_required_strings(fields: &str) -> &'static [&'static str] {
    misc::report_required(fields).unwrap_or(&[])
}
