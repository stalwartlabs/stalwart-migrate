use serde_json::{Map, Value};

use super::{object, string};
use crate::{
    answers::Answer,
    engine::{TYPE_KEY, Walker},
    prompts::PromptId,
    report::DropReason,
    transform::Transform,
};

const OPENAI_TAIL: &str = "/chat/completions";
const OPENAI_VERSION: &str = "/v1";
const OPENAI_DEFAULT_URL: &str = "https://api.openai.com/v1/chat/completions";
const AUTHORIZATION: &str = "Authorization";
const AZURE_KEY_HEADER: &str = "api-key";
const PROFILE: &str = "profile";
const COMMON_FIELDS: &[&str] = &[
    "name",
    "model",
    "timeout",
    "allowInvalidCerts",
    "httpHeaders",
];
const SPAM_LLM_FIELDS: &[&str] = &[
    "prompt",
    "categories",
    "confidence",
    "separator",
    "responsePosCategory",
    "responsePosConfidence",
    "responsePosExplanation",
    "temperature",
];

fn default_profile(url: &str) -> &'static str {
    let host = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or_default();
    if host == "api.openai.com" {
        "OpenAi"
    } else if host.ends_with(".openai.azure.com") {
        "Azure"
    } else {
        "Generic"
    }
}

pub(super) fn ai_model_forward(w: &mut Walker, value: Value) -> Option<Value> {
    let Value::Object(mut src) = value else {
        w.dropped("", DropReason::Invalid, Some(&value));
        return None;
    };
    let url = src
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut defaults = w.prompt_defaults(PromptId::AiModelProvider);
    defaults.set("profile", string(default_profile(&url)));
    defaults.set("url", string(&url));
    let context = ["name", "model", "url", "modelType"]
        .iter()
        .filter_map(|k| src.get(*k).map(|v| ((*k).into(), v.clone())))
        .collect();
    let answer = w.ask(PromptId::AiModelProvider, defaults, context);
    let provider = answer.str("provider").unwrap_or("OpenAi").to_string();
    if provider == "drop" {
        w.dropped("", DropReason::Operator, None);
        return None;
    }

    let mut out = Map::new();
    out.insert(TYPE_KEY.into(), string(&provider));
    for field in COMMON_FIELDS {
        if let Some(v) = src.remove(*field) {
            out.insert((*field).into(), v);
        }
    }
    let url_answered = w
        .session
        .answers
        .get(PromptId::AiModelProvider, Some(w.key))
        .is_some_and(|a| a.get("url").is_some());
    let url = answer
        .str("url")
        .filter(|u| !u.is_empty() && (url_answered || provider == "OpenAi"))
        .map(string)
        .unwrap_or(Value::Null);
    out.insert("url".into(), url);
    if provider == "OpenAi" {
        out.insert(
            "profile".into(),
            string(answer.str("profile").unwrap_or("Generic")),
        );
    }
    if let Some(temperature) = src.remove("temperature") {
        out.insert("temperature".into(), temperature);
    }
    if src.remove("modelType").as_ref().and_then(Value::as_str) == Some("Text") {
        w.transformed(
            Transform::AiModelUnion,
            "modelType",
            "text completion models are not supported by v1; migrated as a chat model",
        );
    }
    let api_key = match src.remove("httpAuth") {
        Some(Value::Object(auth)) => {
            let keep_basic = answer.str("basic_auth") == Some("header");
            http_auth_to_api_key(w, auth, &mut out, keep_basic)
        }
        _ => None,
    };
    out.insert(
        "apiKey".into(),
        api_key.unwrap_or_else(|| object([(TYPE_KEY, string("None"))])),
    );
    w.transformed(
        Transform::AiModelUnion,
        "",
        format!("converted to provider {provider}"),
    );
    Some(Value::Object(out))
}

fn http_auth_to_api_key(
    w: &mut Walker,
    mut auth: Map<String, Value>,
    out: &mut Map<String, Value>,
    keep_basic: bool,
) -> Option<Value> {
    match auth.get(TYPE_KEY).and_then(Value::as_str) {
        Some("Bearer") => auth.remove("bearerToken"),
        Some("Basic") => {
            let username = auth
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let secret = auth
                .get("secret")
                .filter(|s| s.get(TYPE_KEY).and_then(Value::as_str) == Some("Value"))
                .and_then(|s| s.get("secret"))
                .and_then(Value::as_str);
            match secret {
                Some(secret) if keep_basic => {
                    let header = format!(
                        "Basic {}",
                        base64(format!("{username}:{secret}").as_bytes())
                    );
                    if let Value::Object(headers) = out
                        .entry("httpHeaders")
                        .or_insert_with(|| Value::Object(Map::new()))
                    {
                        headers.insert(AUTHORIZATION.into(), Value::String(header));
                    }
                    w.transformed(
                        Transform::AiModelUnion,
                        "httpAuth",
                        "basic authentication converted to an Authorization header",
                    );
                }
                _ => w.dropped(
                    "httpAuth",
                    DropReason::NoEquivalent,
                    Some(&Value::Object(auth)),
                ),
            }
            None
        }
        _ => None,
    }
}

pub(super) fn ai_model_reverse(w: &mut Walker, value: Value) -> Option<Value> {
    let Value::Object(mut src) = value else {
        return None;
    };
    let provider = src
        .get(TYPE_KEY)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if provider != "OpenAi" {
        w.dropped("", DropReason::NoEquivalent, Some(&string(&provider)));
        return None;
    }
    let mut out = Map::new();
    for field in COMMON_FIELDS {
        if let Some(v) = src.remove(*field) {
            out.insert((*field).into(), v);
        }
    }
    let url = match src
        .remove("url")
        .as_ref()
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        Some(url) => match openai_endpoint(url) {
            Some(endpoint) => {
                w.transformed(
                    Transform::AiModelUnion,
                    "url",
                    format!("v0.16 expects the full endpoint; set to {endpoint}, the URL v1 calls"),
                );
                endpoint
            }
            None => url.to_string(),
        },
        None => OPENAI_DEFAULT_URL.to_string(),
    };
    out.insert("url".into(), Value::String(url));
    if let Some(temperature) = src.remove("temperature").filter(|t| !t.is_null()) {
        out.insert("temperature".into(), temperature);
    }
    out.insert("modelType".into(), string("Chat"));
    let azure = src.get(PROFILE).and_then(Value::as_str) == Some("Azure");
    let mut azure_header = false;
    let auth = match src.remove("apiKey") {
        Some(key) if super::is_set_secret(Some(&key)) => {
            match (azure, key.get("secret").and_then(Value::as_str)) {
                (true, Some("")) => object([(TYPE_KEY, string("Unauthenticated"))]),
                (true, Some(secret)) => {
                    azure_header = true;
                    azure_key_header(w, &mut out, secret);
                    object([(TYPE_KEY, string("Unauthenticated"))])
                }
                _ => object([(TYPE_KEY, string("Bearer")), ("bearerToken", key)]),
            }
        }
        _ => object([(TYPE_KEY, string("Unauthenticated"))]),
    };
    out.insert("httpAuth".into(), auth);
    let fields = format!("x:AiModel{provider}");
    for (name, value) in src {
        if name == TYPE_KEY || value.is_null() || (azure_header && name == PROFILE) {
            continue;
        }
        let ty = w.session.source.property(&fields, &name).map(|p| &p.ty);
        w.dropped_typed(&name, DropReason::NotInTarget, Some(&value), ty);
    }
    Some(Value::Object(out))
}

fn openai_endpoint(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = (rest.get(..authority_end)?, rest.get(authority_end..)?);
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let (path, query) = (tail.get(..path_end)?, tail.get(path_end..)?);
    let path = path.trim_end_matches('/');
    if path.ends_with(OPENAI_TAIL) {
        return None;
    }
    let version = if path.is_empty() { OPENAI_VERSION } else { "" };
    Some(format!(
        "{scheme}://{authority}{path}{version}{OPENAI_TAIL}{query}"
    ))
}

fn azure_key_header(w: &mut Walker, out: &mut Map<String, Value>, secret: &str) {
    let slot = out.entry("httpHeaders").or_insert(Value::Null);
    if !slot.is_object() {
        *slot = Value::Object(Map::new());
    }
    let Value::Object(headers) = slot else {
        return;
    };
    let existing: Vec<String> = headers
        .keys()
        .filter(|name| name.eq_ignore_ascii_case(AZURE_KEY_HEADER))
        .cloned()
        .collect();
    for name in existing {
        headers.remove(&name);
        w.dropped(
            &format!("httpHeaders/{name}"),
            DropReason::NoEquivalent,
            None,
        );
    }
    headers.insert(AZURE_KEY_HEADER.into(), string(secret));
    w.transformed(
        Transform::AiModelUnion,
        "apiKey",
        "Azure API key moved to a plain api-key HTTP header (v0.16 has no Azure profile)",
    );
}

pub(super) fn spam_llm_forward(w: &mut Walker, value: Value) -> Option<Value> {
    let Value::Object(mut src) = value else {
        return None;
    };
    if src.get(TYPE_KEY).and_then(Value::as_str) != Some("Enable") {
        return Some(object([(TYPE_KEY, string("Disable"))]));
    }
    let context = ["modelId", "prompt", "categories"]
        .iter()
        .filter_map(|k| src.get(*k).map(|v| ((*k).into(), v.clone())))
        .collect();
    let defaults = w.prompt_defaults(PromptId::SpamAi);
    let answer: Answer = w.ask(PromptId::SpamAi, defaults, context);
    for field in SPAM_LLM_FIELDS {
        if let Some(v) = src.remove(*field) {
            w.dropped(field, DropReason::NoEquivalent, Some(&v));
        }
    }
    let action = answer.str("action").unwrap_or("defaults");
    let model = src.remove("modelId");
    if action == "disable" || model.is_none() {
        w.transformed(Transform::SpamLlmToAi, "", "AI classifier left disabled");
        return Some(object([(TYPE_KEY, string("Disable"))]));
    }
    let mut out = Map::new();
    out.insert(TYPE_KEY.into(), string("Enable"));
    let tier = object([("modelId", model.unwrap_or(Value::Null))]);
    out.insert("tiers".into(), object([("0", tier)]));
    if action == "custom"
        && let Some(instructions) = answer.str("instructions")
    {
        out.insert("instructions".into(), string(instructions));
    }
    w.transformed(
        Transform::SpamLlmToAi,
        "",
        format!("AI classifier enabled ({action})"),
    );
    Some(Value::Object(out))
}

pub(super) fn spam_ai_reverse(w: &mut Walker, value: Value) -> Option<Value> {
    if value.get(TYPE_KEY).and_then(Value::as_str) == Some("Enable") {
        w.dropped("", DropReason::NoEquivalent, None);
    }
    Some(object([(TYPE_KEY, string("Disable"))]))
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let (chunks, remainder) = input.as_chunks::<3>();
    for &[a, b, c] in chunks {
        let n = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        for shift in [18, 12, 6, 0] {
            out.push(char::from(TABLE[((n >> shift) & 63) as usize]));
        }
    }
    match *remainder {
        [a] => {
            let n = u32::from(a) << 16;
            out.push(char::from(TABLE[((n >> 18) & 63) as usize]));
            out.push(char::from(TABLE[((n >> 12) & 63) as usize]));
            out.push_str("==");
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.push(char::from(TABLE[((n >> 18) & 63) as usize]));
            out.push(char::from(TABLE[((n >> 12) & 63) as usize]));
            out.push(char::from(TABLE[((n >> 6) & 63) as usize]));
            out.push('=');
        }
        _ => (),
    }
    out
}

#[cfg(test)]
mod tests {
    // The reverse endpoint is the URL v1 calls: tail appended to the path only, /v1 added to an empty path, query kept.
    #[test]
    fn reverse_endpoint_matches_what_v1_calls() {
        for (base, expected) in [
            (
                "https://api.openai.com",
                Some("https://api.openai.com/v1/chat/completions"),
            ),
            (
                "http://vllm:8000/",
                Some("http://vllm:8000/v1/chat/completions"),
            ),
            (
                "https://llm.example.org/v1/",
                Some("https://llm.example.org/v1/chat/completions"),
            ),
            (
                "https://r.openai.azure.com/openai/deployments/d?api-version=2024-02-01",
                Some(
                    "https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-02-01",
                ),
            ),
            (
                "http://h:1?x=1#f",
                Some("http://h:1/v1/chat/completions?x=1#f"),
            ),
            (
                "https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-02-01",
                None,
            ),
            ("https://api.openai.com/v1/chat/completions/", None),
            ("not a url", None),
        ] {
            assert_eq!(super::openai_endpoint(base).as_deref(), expected, "{base}");
        }
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC 4648 section 10 test vectors.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(super::base64(input.as_bytes()), expected);
        }
    }
}
