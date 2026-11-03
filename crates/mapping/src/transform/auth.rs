use serde_json::{Map, Value};

use super::{object, string};
use crate::{
    engine::{Flow, TYPE_KEY, Walker},
    prompts::PromptId,
    report::{Change, DropReason},
    transform::Transform,
};

const LIFETIMES: &[(&str, &str, u64)] = &[
    ("authCodeExpiry", "auth_code_expiry", 600_000),
    ("accessTokenExpiry", "access_token_expiry", 600_000),
    ("refreshTokenExpiry", "refresh_token_expiry", 86_400_000),
];

fn string_set<'x>(values: impl IntoIterator<Item = &'x str>) -> Value {
    Value::Object(
        values
            .into_iter()
            .map(|v| (v.to_string(), Value::Bool(true)))
            .collect(),
    )
}

pub(super) fn oidc_directory_forward(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let audience = src.remove("requireAudience");
    let scopes = src.remove("requireScopes");
    let claim_name = src.remove("claimName");
    let audience_text = audience
        .as_ref()
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty());

    let mut defaults = w.prompt_defaults(PromptId::OidcDirectory);
    defaults.set(
        "accepted_audiences",
        Value::Array(audience_text.map(string).into_iter().collect()),
    );
    defaults.set(
        "skip_audience_validation",
        Value::Bool(audience_text.is_none()),
    );
    defaults.set(
        "claim_name",
        string(
            claim_name
                .as_ref()
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
    );
    let mut context = Vec::with_capacity(4);
    for (label, value) in [
        ("issuerUrl", src.get("issuerUrl")),
        ("requireAudience", audience.as_ref()),
        ("requireScopes", scopes.as_ref()),
        ("claimName", claim_name.as_ref()),
    ] {
        if let Some(value) = value {
            context.push((label.into(), value.clone()));
        }
    }
    let answer = w.ask(PromptId::OidcDirectory, defaults, context);

    if let Some(scopes) = scopes.filter(|s| s.as_object().is_some_and(|m| !m.is_empty())) {
        w.dropped("requireScopes", DropReason::NoEquivalent, Some(&scopes));
    }
    out.insert(
        "acceptedAudiences".into(),
        string_set(answer.strings("accepted_audiences")),
    );
    let flags = [
        ("skipAudienceValidation", "skip_audience_validation"),
        ("allowIdTokenClaims", "allow_id_token_claims"),
        ("lenientIssuerMatch", "lenient_issuer_match"),
        ("allowInvalidCerts", "allow_invalid_certs"),
    ];
    for (property, field) in flags {
        out.insert(
            property.into(),
            Value::Bool(answer.bool(field).unwrap_or(false)),
        );
    }
    let opaque = answer.str("opaque_token_validation").unwrap_or("none");
    out.insert("opaqueTokenValidation".into(), string(opaque));
    if opaque == "introspection" {
        out.insert(
            "introspectionClientId".into(),
            answer
                .str("introspection_client_id")
                .map(string)
                .unwrap_or(Value::Null),
        );
        let secret = match answer.str("introspection_client_secret") {
            Some(secret) => object([(TYPE_KEY, string("Value")), ("secret", string(secret))]),
            None => object([(TYPE_KEY, string("None"))]),
        };
        out.insert("introspectionClientSecret".into(), secret);
        out.insert(
            "introspectionAuthMethod".into(),
            string(
                answer
                    .str("introspection_auth_method")
                    .unwrap_or("clientSecretBasic"),
            ),
        );
    }
    out.insert(
        "unscopedTokens".into(),
        string(answer.str("unscoped_tokens").unwrap_or("reject")),
    );
    let claim = answer.str("claim_name").filter(|c| !c.is_empty());
    out.insert("claimName".into(), claim.map(string).unwrap_or(Value::Null));
    w.transformed(
        Transform::OidcDirectory,
        "",
        format!("OIDC validation settings applied (opaque tokens {opaque})"),
    );
    Flow::Keep
}

pub(super) fn oidc_directory_reverse(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let Some(audiences) = src.remove("acceptedAudiences") else {
        return Flow::Keep;
    };
    let mut keys = audiences.as_object().into_iter().flat_map(|m| m.keys());
    let first = keys.next().cloned();
    if keys.next().is_some() {
        w.dropped(
            "acceptedAudiences",
            DropReason::NoEquivalent,
            Some(&audiences),
        );
    }
    out.insert(
        "requireAudience".into(),
        first.map(Value::String).unwrap_or(Value::Null),
    );
    Flow::Keep
}

pub(super) fn oidc_token_lifetimes(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let mut values: [Option<Value>; 3] = Default::default();
    let mut below = Vec::new();
    for ((property, _, min), slot) in LIFETIMES.iter().zip(values.iter_mut()) {
        *slot = src.remove(*property);
        if let Some(current) = slot.as_ref().and_then(Value::as_u64)
            && current < *min
        {
            below.push(((*property).into(), Value::from(current)));
        }
    }
    let answer = if below.is_empty() {
        None
    } else {
        let defaults = w.prompt_defaults(PromptId::OidcTokenLifetimes);
        Some(w.ask(PromptId::OidcTokenLifetimes, defaults, below))
    };
    for ((property, field, min), value) in LIFETIMES.iter().zip(values) {
        let Some(mut value) = value else {
            continue;
        };
        if let Some(answer) = &answer
            && value.as_u64().is_some_and(|v| v < *min)
        {
            let replacement = match answer.str("action") {
                Some("set") => answer.u64(field).unwrap_or(*min).max(*min),
                _ => *min,
            };
            w.path.push(property);
            w.report.push(
                w.key,
                w.path.as_str(),
                Change::Clamped {
                    from: value,
                    to: Value::from(replacement),
                },
            );
            w.path.pop();
            value = Value::from(replacement);
        }
        out.insert((*property).into(), value);
    }
    Flow::Keep
}

pub(super) fn oauth_registration(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    _out: &mut Map<String, Value>,
) -> Flow {
    let mut context = Vec::with_capacity(2);
    for name in ["anonymousClientRegistration", "requireClientRegistration"] {
        if let Some(value) = src.remove(name) {
            w.dropped(name, DropReason::NoEquivalent, Some(&value));
            context.push((name.into(), value));
        }
    }
    let defaults = w.prompt_defaults(PromptId::OauthRegistration);
    let answer = w.ask(PromptId::OauthRegistration, defaults, context);
    if answer.str("action") == Some("abort") {
        w.abort = true;
    }
    Flow::Keep
}
