use serde_json::{Map, Value};

use super::{is_set_secret, object, string};
use crate::{
    engine::{Flow, IN_MEMORY_STORE, TYPE_KEY, Walker},
    prompts::PromptId,
    report::DropReason,
    transform::Transform,
};

fn optional_string(value: Option<&str>) -> Value {
    value
        .filter(|v| !v.is_empty())
        .map(string)
        .unwrap_or(Value::Null)
}

fn secret_value(secret: &str) -> Value {
    object([(TYPE_KEY, string("Value")), ("secret", string(secret))])
}

pub(super) fn azure_auth_forward(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let access = src.remove("accessKey");
    let sas = src.remove("sasToken");
    let auth = if is_set_secret(access.as_ref()) {
        if is_set_secret(sas.as_ref()) {
            w.dropped("sasToken", DropReason::NoEquivalent, sas.as_ref());
        }
        w.transformed(
            Transform::AzureAuth,
            "auth",
            "access key mapped to SharedKey",
        );
        object([
            (TYPE_KEY, string("SharedKey")),
            ("accountKey", access.unwrap_or_default()),
        ])
    } else if is_set_secret(sas.as_ref()) {
        w.transformed(Transform::AzureAuth, "auth", "SAS token mapped to SasToken");
        object([
            (TYPE_KEY, string("SasToken")),
            ("sasToken", sas.unwrap_or_default()),
        ])
    } else {
        let defaults = w.prompt_defaults(PromptId::AzureAuth);
        let context = ["storageAccount", "container"]
            .iter()
            .filter_map(|k| src.get(*k).map(|v| ((*k).into(), v.clone())))
            .collect();
        let answer = w.ask(PromptId::AzureAuth, defaults, context);
        let mode = answer.str("mode").unwrap_or("ManagedIdentity");
        let client_id = optional_string(answer.str("client_id"));
        let tenant_id = optional_string(answer.str("tenant_id"));
        let auth = match mode {
            "WorkloadIdentity" => object([
                (TYPE_KEY, string(mode)),
                ("tenantId", tenant_id),
                ("clientId", client_id),
                ("tokenFile", optional_string(answer.str("token_file"))),
            ]),
            "ClientSecret" => object([
                (TYPE_KEY, string(mode)),
                ("tenantId", tenant_id),
                ("clientId", client_id),
                (
                    "clientSecret",
                    secret_value(answer.str("client_secret").unwrap_or_default()),
                ),
            ]),
            _ => object([
                (TYPE_KEY, string("ManagedIdentity")),
                ("clientId", client_id),
            ]),
        };
        w.transformed(
            Transform::AzureAuth,
            "auth",
            format!("authentication set to {mode} as answered"),
        );
        auth
    };
    out.insert("auth".into(), auth);
    Flow::Keep
}

pub(super) fn azure_auth_reverse(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let Some(Value::Object(mut auth)) = src.remove("auth") else {
        return Flow::Keep;
    };
    match auth.get(TYPE_KEY).and_then(Value::as_str) {
        Some("SharedKey") => {
            out.insert(
                "accessKey".into(),
                auth.remove("accountKey").unwrap_or_default(),
            );
        }
        Some("SasToken") => {
            out.insert(
                "sasToken".into(),
                auth.remove("sasToken").unwrap_or_default(),
            );
        }
        _ => w.dropped("auth", DropReason::NoEquivalent, Some(&Value::Object(auth))),
    }
    Flow::Keep
}

pub(super) fn s3_session_token(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let session = src.remove("sessionToken");
    let security = src.remove("securityToken");
    let token = if is_set_secret(session.as_ref()) {
        if is_set_secret(security.as_ref()) && security != session {
            w.dropped("securityToken", DropReason::NoEquivalent, security.as_ref());
        }
        session
    } else if is_set_secret(security.as_ref()) {
        w.transformed(
            Transform::S3SessionToken,
            "sessionToken",
            "security token moved to the session token",
        );
        security
    } else {
        session.or(security)
    };
    if let Some(token) = token {
        out.insert("sessionToken".into(), token);
    }
    Flow::Keep
}

pub(super) fn dns_sig0(w: &mut Walker, value: Value) -> Option<Value> {
    let defaults = w.prompt_defaults(PromptId::DnsSig0);
    let context = ["description", "host", "signerName"]
        .iter()
        .filter_map(|k| value.get(*k).map(|v| ((*k).into(), v.clone())))
        .collect();
    let answer = w.ask(PromptId::DnsSig0, defaults, context);
    match (answer.str("action"), answer.get("replacement")) {
        (Some("replace"), Some(replacement)) if replacement.is_object() => {
            w.transformed(Transform::DnsSig0, "", "replaced as answered");
            Some(replacement.clone())
        }
        _ => {
            w.dropped("", DropReason::NoEquivalent, None);
            None
        }
    }
}

pub(super) fn in_memory_cluster(w: &mut Walker, value: Value) -> Option<Value> {
    let Some(coordinator) = w.coordinator.filter(|_| &*w.key.object == IN_MEMORY_STORE) else {
        return Some(value);
    };
    let defaults = w.prompt_defaults(PromptId::InMemoryCluster);
    let context = vec![("coordinator".into(), Value::from(coordinator))];
    let answer = w.ask(PromptId::InMemoryCluster, defaults, context);
    match (answer.str("action"), answer.get("store")) {
        (Some("replace"), Some(store)) if store.is_object() => {
            w.transformed(
                Transform::InMemoryCluster,
                "",
                "replaced by the shared store as answered",
            );
            Some(store.clone())
        }
        _ => Some(value),
    }
}
