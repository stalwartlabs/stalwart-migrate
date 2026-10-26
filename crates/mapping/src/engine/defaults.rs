use std::ops::Range;

use serde_json::{Map, Value};

use super::walk::{EXPRESSION_SCHEMA, Walker};
use crate::{
    report::Change,
    rules::{FunctionRule, Policy, PropertyRule},
    schema::{Fields, Type, TypeDef},
};

const MATCH: &str = "match";
const ELSE: &str = "else";
const IF: &str = "if";
const THEN: &str = "then";
const SCHEMA_DEFAULT: &str = "default";

pub(super) fn apply(
    w: &mut Walker,
    fields_name: &str,
    fields: &Fields,
    map: &mut Map<String, Value>,
) {
    let session = w.session;
    let Some(table) = session.rules.defaults(fields_name) else {
        return;
    };
    let rules = session.rules.property_rules(fields_name);
    for (name, old_default) in &fields.defaults {
        let Some(table_policy) = table.policy(name) else {
            continue;
        };
        let Some(prop) = fields.property(name) else {
            continue;
        };
        let (target_fields, target_name) = match rules.and_then(|r| r.get(name.as_str())) {
            Some(PropertyRule::Rename { to, .. }) => (fields_name, &**to),
            Some(PropertyRule::Move { object, property }) => (&**object, &**property),
            Some(PropertyRule::Drop) => continue,
            _ => (fields_name, name.as_str()),
        };
        let new_default = session
            .target_full
            .fields(target_fields)
            .and_then(|f| f.default_value(target_name));
        if new_default.is_some_and(|new| schema_defaults_equal(&prop.ty, old_default, new)) {
            continue;
        }
        if map
            .get(name.as_str())
            .is_some_and(|current| !value_equals_default(&prop.ty, current, old_default))
        {
            continue;
        }
        let answer = w.changed_defaults();
        let policy = answer
            .policy_override(&format!("{fields_name}.{name}"))
            .or_else(|| answer.str("policy").and_then(Policy::parse))
            .unwrap_or(table_policy);
        w.path.push(name);
        match (policy, map.contains_key(name.as_str())) {
            (Policy::Inherit, true) => {
                map.remove(name.as_str());
                w.report.push(
                    w.key,
                    w.path.as_str(),
                    Change::DefaultInherited {
                        old: default_to_wire(&prop.ty, old_default),
                    },
                );
            }
            (Policy::Pin, present) => {
                let wire = default_to_wire(&prop.ty, old_default);
                if !present {
                    map.insert(name.clone(), wire.clone());
                }
                w.report.push(
                    w.key,
                    w.path.as_str(),
                    Change::DefaultPinned { value: wire },
                );
            }
            (Policy::Inherit, false) => (),
        }
        w.path.pop();
    }
}

fn is_expression(ty: &TypeDef) -> bool {
    matches!(&ty.ty, Type::Object(schema) if &**schema == EXPRESSION_SCHEMA)
}

fn schema_defaults_equal(ty: &TypeDef, a: &Value, b: &Value) -> bool {
    if is_expression(ty) {
        canonical_expression(a) == canonical_expression(b)
    } else {
        values_equal(a, b)
    }
}

fn value_equals_default(ty: &TypeDef, value: &Value, default: &Value) -> bool {
    if is_expression(ty) {
        canonical_expression(value).is_some_and(|v| Some(v) == canonical_expression(default))
    } else {
        values_equal(value, default)
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

type Canonical<'x> = (Vec<(&'x str, &'x str)>, &'x str);

fn branch(item: &Value) -> Option<(&str, &str)> {
    Some((item.get(IF)?.as_str()?, item.get(THEN)?.as_str()?))
}

fn canonical_expression(value: &Value) -> Option<Canonical<'_>> {
    let map = value.as_object()?;
    if let Some(text) = map.get(SCHEMA_DEFAULT).and_then(Value::as_str) {
        return Some((Vec::new(), text));
    }
    let otherwise = map.get(ELSE)?.as_str()?;
    let branches = match map.get(MATCH) {
        None => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(branch).collect::<Option<_>>()?,
        Some(Value::Object(items)) => {
            let mut ordered: Vec<(usize, &Value)> = items
                .iter()
                .map(|(k, v)| k.parse::<usize>().ok().map(|k| (k, v)))
                .collect::<Option<_>>()?;
            ordered.sort_unstable_by_key(|(k, _)| *k);
            ordered
                .into_iter()
                .map(|(_, v)| branch(v))
                .collect::<Option<_>>()?
        }
        Some(_) => return None,
    };
    Some((branches, otherwise))
}

pub(crate) fn default_to_wire(ty: &TypeDef, default: &Value) -> Value {
    if !is_expression(ty) {
        return default.clone();
    }
    let Some((branches, otherwise)) = canonical_expression(default) else {
        return default.clone();
    };
    let mut matches = Map::with_capacity(branches.len());
    for (index, (condition, result)) in branches.into_iter().enumerate() {
        let mut branch = Map::with_capacity(2);
        branch.insert(IF.into(), Value::String(condition.into()));
        branch.insert(THEN.into(), Value::String(result.into()));
        matches.insert(index.to_string(), Value::Object(branch));
    }
    let mut wire = Map::with_capacity(2);
    wire.insert(MATCH.into(), Value::Object(matches));
    wire.insert(ELSE.into(), Value::String(otherwise.into()));
    Value::Object(wire)
}

pub(crate) fn for_each_expression_text(value: &mut Value, mut f: impl FnMut(&mut String)) {
    let Some(map) = value.as_object_mut() else {
        return;
    };
    if let Some(Value::Object(items)) = map.get_mut(MATCH) {
        for item in items.values_mut() {
            for key in [IF, THEN] {
                if let Some(Value::String(text)) = item.get_mut(key) {
                    f(text);
                }
            }
        }
    }
    if let Some(Value::String(text)) = map.get_mut(ELSE) {
        f(text);
    }
}

pub(crate) fn expression_texts(value: &Value) -> Vec<&str> {
    let mut texts = Vec::new();
    if let Some(map) = value.as_object() {
        if let Some(Value::Object(items)) = map.get(MATCH) {
            for item in items.values() {
                for key in [IF, THEN] {
                    if let Some(text) = item.get(key).and_then(Value::as_str) {
                        texts.push(text);
                    }
                }
            }
        }
        if let Some(text) = map.get(ELSE).and_then(Value::as_str) {
            texts.push(text);
        }
    }
    texts
}

pub(crate) fn expression_mentions<'x>(value: &'x Value, names: &[Box<str>]) -> Vec<&'x str> {
    let mut found = Vec::new();
    let mut check = |text: &'x str| {
        scan_identifiers(text, |range| {
            if let Some(ident) = text.get(range)
                && names.iter().any(|n| &**n == ident)
                && !found.contains(&ident)
            {
                found.push(ident);
            }
        });
    };
    if let Some(map) = value.as_object() {
        if let Some(Value::Object(items)) = map.get(MATCH) {
            for item in items.values() {
                for key in [IF, THEN] {
                    if let Some(text) = item.get(key).and_then(Value::as_str) {
                        check(text);
                    }
                }
            }
        }
        if let Some(text) = map.get(ELSE).and_then(Value::as_str) {
            check(text);
        }
    }
    found
}

pub(crate) fn rename_identifiers<'x>(
    text: &str,
    lookup: impl Fn(&str) -> Option<&'x str>,
) -> Option<String> {
    let mut out: Option<String> = None;
    let mut copied = 0;
    scan_identifiers(text, |range| {
        let Some(replacement) = text.get(range.clone()).and_then(&lookup) else {
            return;
        };
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len() + 8));
        buf.push_str(text.get(copied..range.start).unwrap_or_default());
        buf.push_str(replacement);
        copied = range.end;
    });
    out.map(|mut buf| {
        buf.push_str(text.get(copied..).unwrap_or_default());
        buf
    })
}

pub(crate) fn rewrite_function_calls<'x>(
    text: &str,
    lookup: impl Fn(&str) -> Option<&'x FunctionRule>,
) -> Option<String> {
    let mut idents = Vec::new();
    scan_identifiers(text, |range| idents.push(range));
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for range in idents {
        let Some(rule) = text.get(range.clone()).and_then(&lookup) else {
            continue;
        };
        let rest = text.get(range.end..).unwrap_or_default();
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('(') {
            continue;
        }
        let open = range.end + (rest.len() - trimmed.len());
        edits.push((range.start, range.end, rule.to.to_string()));
        if !rule.append.is_empty()
            && let Some(close) = matching_paren(text, open)
        {
            let empty = text
                .get(open + 1..close)
                .is_some_and(|args| args.trim().is_empty());
            let mut insertion = String::new();
            for (i, arg) in rule.append.iter().enumerate() {
                if i > 0 || !empty {
                    insertion.push_str(", ");
                }
                insertion.push_str(arg);
            }
            edits.push((close, close, insertion));
        }
    }
    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(text.len() + 16);
    let mut copied = 0;
    for (start, end, replacement) in edits {
        out.push_str(text.get(copied..start).unwrap_or_default());
        out.push_str(&replacement);
        copied = end;
    }
    out.push_str(text.get(copied..).unwrap_or_default());
    Some(out)
}

fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in text.get(open..)?.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + index);
                }
            }
            _ => (),
        }
    }
    None
}

fn scan_identifiers(text: &str, mut on_ident: impl FnMut(Range<usize>)) {
    let mut chars = text.char_indices().peekable();
    let mut previous: Option<char> = None;
    while let Some((start, ch)) = chars.next() {
        match ch {
            '\'' | '"' => {
                let quote = ch;
                let mut escaped = false;
                for (_, inner) in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == quote {
                        break;
                    }
                }
                previous = Some(quote);
            }
            c if (c.is_ascii_alphabetic() || c == '_')
                && !previous.is_some_and(|p| {
                    p.is_ascii_alphanumeric() || p == '_' || p == '$' || p == '.'
                }) =>
            {
                let mut end = start + c.len_utf8();
                while let Some(&(index, next)) = chars.peek() {
                    if next.is_ascii_alphanumeric() || next == '_' {
                        end = index + next.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                on_ident(start..end);
                previous = Some('_');
            }
            c => previous = Some(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_skip_quoted_text() {
        let text = "retry_num > 3 && 'retry_num' == x.retry_num && $retry_num && retry_num2";
        let renamed = rename_identifiers(text, |i| (i == "retry_num").then_some("attempts"));
        assert_eq!(
            renamed.as_deref(),
            Some("attempts > 3 && 'retry_num' == x.retry_num && $retry_num && retry_num2")
        );
        assert_eq!(rename_identifiers("sender_domain", |_| None), None);
    }

    #[test]
    fn function_calls_are_renamed_and_extended() {
        let incr = FunctionRule {
            to: "key_incr".into(),
            append: Box::default(),
            prompt: None,
        };
        let get = FunctionRule {
            to: "key_incr".into(),
            append: Box::new(["0".into()]),
            prompt: None,
        };
        let lookup = |name: &str| match name {
            "counter_incr" => Some(&incr),
            "counter_get" => Some(&get),
            _ => None,
        };
        assert_eq!(
            rewrite_function_calls(
                "counter_get('s', concat('a', ')')) > 2 && counter_incr ('s', 'k', 1)",
                lookup
            )
            .as_deref(),
            Some("key_incr('s', concat('a', ')'), 0) > 2 && key_incr ('s', 'k', 1)")
        );
        assert_eq!(rewrite_function_calls("counter_get", lookup), None);
    }

    #[test]
    fn expression_defaults_compare_with_wire_form() {
        let ty = TypeDef {
            ty: Type::Object(EXPRESSION_SCHEMA.into()),
            nullable: false,
        };
        let schema: Value =
            serde_json::json!({"else": "false", "match": [{"if": "a", "then": "b"}]});
        let wire: Value =
            serde_json::json!({"match": {"0": {"if": "a", "then": "b"}}, "else": "false"});
        assert!(value_equals_default(&ty, &wire, &schema));
        assert_eq!(default_to_wire(&ty, &schema), wire);
        let short: Value = serde_json::json!({"default": "system('domain')"});
        let short_wire: Value = serde_json::json!({"match": {}, "else": "system('domain')"});
        assert!(value_equals_default(&ty, &short_wire, &short));
    }
}
