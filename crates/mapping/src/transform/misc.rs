use serde_json::{Map, Value};

use super::string;
use crate::{
    engine::{Flow, Walker, expression_mentions},
    prompts::PromptId,
    report::{Change, DropReason, WEBUI_CUSTOM_BUNDLE},
    schema::{Type, TypeDef},
    transform::Transform,
};

const PEER: &str = "peer";
const SPAM_TAG: &str = "tag";
const ACME_DESCRIPTION: &str = "description";
const DEFAULT_FORWARDED_HOPS: u64 = 1;
const WEBUI_RELEASES: &str = "https://github.com/stalwartlabs/webui/releases/";
const WEBUI_LATEST: &str = "latest/download/";
const WEBUI_TAGGED: &str = "download/";
const WEBUI_DEFAULT_URL: &str =
    "https://github.com/stalwartlabs/webui/releases/download/v2/webui.zip";

pub(super) fn client_ip_source_forward(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let enabled = src
        .remove("useXForwarded")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enabled {
        out.insert("clientIpSource".into(), string(PEER));
        return Flow::Keep;
    }
    let defaults = w.prompt_defaults(PromptId::HttpForwarded);
    let context = vec![("useXForwarded".into(), Value::Bool(true))];
    let answer = w.ask(PromptId::HttpForwarded, defaults, context);
    let source = answer.str("source").unwrap_or(PEER);
    out.insert("clientIpSource".into(), string(source));
    if source != PEER {
        out.insert(
            "forwardedHops".into(),
            Value::from(answer.u64("hops").unwrap_or(1)),
        );
    }
    w.transformed(
        Transform::ClientIpSource,
        "clientIpSource",
        format!("useXForwarded replaced by {source} as answered"),
    );
    Flow::Keep
}

pub(super) fn client_ip_source_reverse(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let source = src.remove("clientIpSource");
    let hops = src.remove("forwardedHops");
    let enabled = source
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|s| s != PEER);
    if hops
        .as_ref()
        .and_then(Value::as_u64)
        .is_some_and(|h| h != DEFAULT_FORWARDED_HOPS)
    {
        w.dropped("forwardedHops", DropReason::NoEquivalent, hops.as_ref());
    }
    out.insert("useXForwarded".into(), Value::Bool(enabled));
    Flow::Keep
}

fn implicit_search_fields(name: &str) -> &'static [&'static str] {
    hashify::map!(name.as_bytes(), &'static [&'static str],
        "indexEmailFields" => &["receivedAt", "sentAt", "size", "hasAttachment"],
        "indexCalendarFields" => &["start", "uid"],
        "indexContactFields" => &["uid"],
    )
    .copied()
    .unwrap_or(&[])
}

pub(super) fn search_fields_restore(
    w: &mut Walker,
    name: &str,
    ty: &TypeDef,
    mut value: Value,
    out: &mut Map<String, Value>,
) -> Flow {
    let flow = w.walk_value(ty, &mut value);
    if let Value::Object(members) = &mut value {
        let added: Vec<&str> = implicit_search_fields(name)
            .iter()
            .copied()
            .filter(|field| {
                members
                    .insert((*field).to_string(), Value::Bool(true))
                    .is_none()
            })
            .collect();
        if !added.is_empty() {
            w.transformed(
                Transform::SearchFieldsFilter,
                "",
                format!(
                    "v1 always indexes {}; v0.16 sorts and filters on them only when listed, so they were added",
                    added.join(", ")
                ),
            );
        }
    }
    out.insert(name.to_string(), value);
    flow
}

pub(super) fn search_fields_filter(
    w: &mut Walker,
    name: &str,
    ty: &TypeDef,
    mut value: Value,
    out: &mut Map<String, Value>,
) -> Flow {
    let was_empty = value.as_object().is_none_or(Map::is_empty);
    if let (Type::Set { class, .. }, Value::Object(members)) = (&ty.ty, &mut value)
        && let Type::Enum(enum_name) = &class.ty
    {
        w.remap_enum_keys(enum_name, members);
    }
    if !was_empty && value.as_object().is_some_and(Map::is_empty) {
        w.transformed(
            Transform::SearchFieldsFilter,
            "",
            "every indexed field was removed in v1; the v1 default applies",
        );
        return Flow::Keep;
    }
    out.insert(name.to_string(), value);
    Flow::Keep
}

pub(super) fn expression_removed_vars(
    w: &mut Walker,
    name: &str,
    ty: &TypeDef,
    mut value: Value,
    out: &mut Map<String, Value>,
) -> Flow {
    let found = expression_mentions(&value, w.variables);
    if !found.is_empty() {
        let detail = format!(
            "uses {} which v1 does not provide in this context; the v1 default applies",
            found.join(", ")
        );
        w.transformed(Transform::ExpressionRemovedVars, "", detail);
        return Flow::Keep;
    }
    let flow = w.walk_value(ty, &mut value);
    out.insert(name.to_string(), value);
    flow
}

enum WebuiRelease<'x> {
    Latest,
    Tagged(&'x str),
}

impl<'x> WebuiRelease<'x> {
    fn parse(url: &'x str) -> Option<Self> {
        let path = url.strip_prefix(WEBUI_RELEASES)?;
        if path.starts_with(WEBUI_LATEST) {
            return Some(WebuiRelease::Latest);
        }
        let (tag, _) = path.strip_prefix(WEBUI_TAGGED)?.split_once('/')?;
        let version = tag.strip_prefix('v')?;
        Some(WebuiRelease::Tagged(
            version.split_once('.').map_or(version, |(major, _)| major),
        ))
    }
}

pub(super) fn webui_bundle(
    w: &mut Walker,
    name: &str,
    ty: &TypeDef,
    mut value: Value,
    out: &mut Map<String, Value>,
) -> Flow {
    match value.as_str().map(WebuiRelease::parse) {
        Some(Some(WebuiRelease::Tagged("1"))) => {
            out.insert(name.to_string(), string(WEBUI_DEFAULT_URL));
            w.transformed(
                Transform::WebuiBundle,
                "",
                "official WebUI v1 bundle replaced by the v1 default WebUI v2 bundle",
            );
            return Flow::Keep;
        }
        Some(Some(WebuiRelease::Latest | WebuiRelease::Tagged("2"))) | None => (),
        Some(_) => w.report.push(
            w.key,
            w.path.as_str(),
            Change::Transformed {
                transform: WEBUI_CUSTOM_BUNDLE,
                detail: "custom application bundle URL kept; if it is a WebUI build, v1 only loads WebUI major version 2 and does not serve an older one".into(),
            },
        ),
    }
    let flow = w.walk_value(ty, &mut value);
    out.insert(name.to_string(), value);
    flow
}

pub(super) fn spam_tag(w: &mut Walker, mut value: Value) -> Option<Value> {
    let session = w.session;
    let tags = &session.rules.spam_tags;
    let tag = value.get(SPAM_TAG).and_then(Value::as_str);
    if tag.is_some_and(|tag| {
        tags.removed_prefixes
            .iter()
            .any(|prefix| tag.starts_with(&**prefix))
    }) {
        w.dropped("", DropReason::NoEquivalent, Some(&value));
        return None;
    }
    if let Some((old, renamed)) = tag.and_then(|tag| tags.renamed.get_key_value(tag))
        && let Some(map) = value.as_object_mut()
    {
        map.insert(SPAM_TAG.to_string(), string(renamed));
        w.transformed(
            Transform::SpamTag,
            SPAM_TAG,
            format!("{old} renamed to {renamed}, the tag v1 emits"),
        );
    }
    if !value.is_object() {
        w.dropped("", DropReason::Invalid, Some(&value));
        return None;
    }
    let key = w.key;
    match w.walk_schema(&key.object, &mut value) {
        Flow::Keep => Some(value),
        Flow::Remove => None,
    }
}

fn spf_mail_from_domain(src: &Map<String, Value>) -> Option<String> {
    src.get("spfResults")?
        .as_object()?
        .values()
        .find_map(|result| {
            let scope = result.get("scope").and_then(Value::as_str);
            if matches!(scope, None | Some("mfrom" | "unspecified")) {
                result
                    .get("domain")
                    .and_then(Value::as_str)
                    .filter(|d| !d.is_empty())
                    .map(str::to_string)
            } else {
                None
            }
        })
}

pub(super) fn dmarc_envelope_from(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    if src
        .get("envelopeFrom")
        .and_then(Value::as_str)
        .is_some_and(|v| !v.is_empty())
    {
        return Flow::Keep;
    }
    match spf_mail_from_domain(src) {
        Some(domain) => {
            src.remove("envelopeFrom");
            out.insert("envelopeFrom".into(), string(&domain));
            w.transformed(
                Transform::DmarcEnvelopeFrom,
                "envelopeFrom",
                "the report omitted envelope_from; derived from the SPF mfrom result domain",
            );
            Flow::Keep
        }
        None => {
            src.remove("envelopeFrom");
            out.insert("envelopeFrom".into(), string(""));
            Flow::Keep
        }
    }
}

pub(super) fn acme_description(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    if src
        .get(ACME_DESCRIPTION)
        .and_then(Value::as_str)
        .is_some_and(|v| !v.is_empty())
    {
        return Flow::Keep;
    }
    let Some(directory) = src.get("directory").and_then(Value::as_str) else {
        return Flow::Keep;
    };
    let mut description = directory.to_string();
    if let Some(account) = src
        .get("accountUri")
        .and_then(Value::as_str)
        .and_then(|uri| uri.rsplit('/').find(|segment| !segment.is_empty()))
    {
        description.push_str(" (");
        description.push_str(account);
        description.push(')');
    }
    src.remove(ACME_DESCRIPTION);
    out.insert(ACME_DESCRIPTION.into(), Value::String(description));
    w.transformed(
        Transform::AcmeDescription,
        ACME_DESCRIPTION,
        "v0.16 computed the description from the directory URL and the account; v1 stores it",
    );
    Flow::Keep
}

pub(super) fn acme_description_reverse(src: &mut Map<String, Value>) -> Flow {
    src.remove(ACME_DESCRIPTION);
    Flow::Keep
}

pub(crate) fn report_required(fields: &str) -> Option<&'static [&'static str]> {
    hashify::map!(fields.as_bytes(), &'static [&'static str],
        "x:DmarcReport" => &["orgName", "email", "reportId", "policyDomain"],
        "x:DmarcExtension" => &["definition", "name"],
        "x:DmarcDkimResult" => &["domain", "selector"],
        "x:DmarcReportRecord" => &["headerFrom"],
        "x:DmarcSpfResult" => &["domain"],
        "x:DmarcPolicyOverrideReason" => &[],
        "x:TlsReport" => &["reportId"],
        "x:TlsReportPolicy" => &["policyDomain"],
        "x:TlsFailureDetails" => &[],
        "x:ArfFeedbackReport" => &[],
    )
    .copied()
}

fn report_sets(fields: &str) -> &'static [&'static str] {
    hashify::map!(fields.as_bytes(), &'static [&'static str],
        "x:DmarcReport" => &["errors"],
        "x:TlsReportPolicy" => &["mxHosts", "policyStrings"],
        "x:ArfFeedbackReport" => &["authenticationResults", "reportedDomains", "reportedUris"],
    )
    .copied()
    .unwrap_or(&[])
}

pub(crate) fn report_strings(w: &mut Walker, fields: &str, map: &mut Map<String, Value>) -> Flow {
    let Some(required) = report_required(fields) else {
        return Flow::Keep;
    };
    let mut names: Vec<&String> = map.keys().collect();
    names.sort_unstable();
    let mut nulled = Vec::new();
    let mut emptied = Vec::new();
    for name in names {
        match map.get(name) {
            Some(Value::String(text)) if text.is_empty() => {
                if required.contains(&name.as_str()) {
                    w.dropped(name, DropReason::Invalid, None);
                    return Flow::Remove;
                }
                nulled.push(name.clone());
            }
            Some(Value::Object(members))
                if report_sets(fields).contains(&name.as_str()) && members.contains_key("") =>
            {
                emptied.push(name.clone());
            }
            _ => (),
        }
    }
    for name in nulled {
        w.dropped(
            &name,
            DropReason::Invalid,
            Some(&Value::String(String::new())),
        );
        map.insert(name, Value::Null);
    }
    for name in emptied {
        w.dropped(
            &name,
            DropReason::Invalid,
            Some(&Value::String(String::new())),
        );
        if let Some(Value::Object(members)) = map.get_mut(&name) {
            members.remove("");
        }
    }
    Flow::Keep
}
