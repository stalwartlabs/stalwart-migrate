use std::mem;

use serde_json::{Map, Value};

use super::{Direction, Move, Session, defaults, path::Path};
use crate::{
    answers::{Answer, mask_property},
    ids::ObjectKey,
    prompts::PromptId,
    report::{COUNTER_READ, Change, DropReason, Report},
    rules::{Conversion, EnumRule, ObjectAction, PropertyRule, VariantRule},
    schema::{SchemaDef, Type, TypeDef},
    transform::{Transform, TransformKind},
};

pub(crate) const TYPE_KEY: &str = "@type";
pub(crate) const EXPRESSION_SCHEMA: &str = "x:Expression";
const EXPRESSION_VARIABLES: &str = "ExpressionVariable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Keep,
    Remove,
}

pub(crate) struct Walker<'s, 'r> {
    pub session: &'s Session<'s>,
    pub report: &'r mut Report,
    pub key: &'r ObjectKey,
    pub path: Path,
    pub moves: Vec<Move>,
    pub variables: &'s [Box<str>],
    changed_defaults: Option<Answer>,
    pub abort: bool,
    pub coordinator: Option<&'r str>,
    drop_expression: bool,
}

impl<'s, 'r> Walker<'s, 'r> {
    pub fn new(session: &'s Session<'s>, report: &'r mut Report, key: &'r ObjectKey) -> Self {
        Walker {
            session,
            report,
            key,
            path: Path::default(),
            moves: Vec::new(),
            variables: &[],
            changed_defaults: None,
            abort: false,
            coordinator: None,
            drop_expression: false,
        }
    }

    pub fn direction(&self) -> Direction {
        self.session.direction
    }

    pub fn convert(&mut self, value: Value) -> Option<(Box<str>, Value)> {
        let object = self.key.object.clone();
        let rule = self.session.rules.object(&object);
        let target = rule
            .and_then(|r| r.to.clone())
            .unwrap_or_else(|| object.clone());
        match rule.map(|r| r.action) {
            Some(ObjectAction::Drop) => {
                self.dropped("", DropReason::NoEquivalent, None);
                return None;
            }
            Some(ObjectAction::Transform(transform)) => {
                return transform.apply_value(self, value).map(|v| (target, v));
            }
            Some(ObjectAction::Keep) | None => (),
        }
        let mut value = value;
        if !value.is_object() {
            self.dropped("", DropReason::Invalid, Some(&value));
            return None;
        }
        if self.session.source.schema(&object).is_none() {
            self.report.push(self.key, "", Change::Unknown);
            return Some((target, value));
        }
        match self.walk_schema(&object, &mut value) {
            Flow::Keep => Some((target, value)),
            Flow::Remove => None,
        }
    }

    pub fn walk_schema(&mut self, name: &str, value: &mut Value) -> Flow {
        let session = self.session;
        let Some(def) = session.source.schema(name) else {
            self.report
                .push(self.key, self.path.as_str(), Change::Unknown);
            return Flow::Keep;
        };
        let Value::Object(map) = value else {
            return Flow::Keep;
        };
        match def {
            SchemaDef::Single(fields) => self.walk_fields(fields, map),
            SchemaDef::Union(_) => {
                let Some(variant_name) = map.get(TYPE_KEY).and_then(Value::as_str) else {
                    return Flow::Keep;
                };
                let variant_name: Box<str> = variant_name.into();
                match session.rules.variant(name, &variant_name) {
                    Some(VariantRule::Keep) | None => (),
                    Some(VariantRule::Rename(to)) => {
                        map.insert(TYPE_KEY.into(), Value::String(to.to_string()));
                    }
                    Some(VariantRule::Drop) => {
                        let path = self.path.child(TYPE_KEY);
                        self.report.push(
                            self.key,
                            &path,
                            Change::Dropped {
                                reason: DropReason::NoEquivalent,
                                value: Some(Value::String(variant_name.to_string())),
                            },
                        );
                        return Flow::Remove;
                    }
                    Some(VariantRule::Transform(transform)) => {
                        let input = mem::take(value);
                        return match transform.apply_value(self, input) {
                            Some(output) => {
                                *value = output;
                                Flow::Keep
                            }
                            None => Flow::Remove,
                        };
                    }
                }
                match def.variant(&variant_name) {
                    Some(variant) => match &variant.schema {
                        Some(fields) => self.walk_fields(fields, map),
                        None => Flow::Keep,
                    },
                    None => {
                        let path = self.path.child(TYPE_KEY);
                        self.report.push(self.key, &path, Change::Unknown);
                        Flow::Keep
                    }
                }
            }
        }
    }

    pub fn walk_fields(&mut self, fields_name: &str, map: &mut Map<String, Value>) -> Flow {
        let session = self.session;
        let Some(fields) = session.source.fields(fields_name) else {
            return Flow::Keep;
        };
        let rules = session.rules.property_rules(fields_name);

        defaults::apply(self, fields_name, fields, map);

        let mut out = Map::new();
        if let Some(rules) = rules {
            let mut seen: [Option<Transform>; 4] = [None; 4];
            for (name, rule) in rules {
                let PropertyRule::Transform { transform, .. } = rule else {
                    continue;
                };
                if transform.kind() != TransformKind::Group
                    || !(map.contains_key(&**name) || transform.always())
                    || seen.contains(&Some(*transform))
                {
                    continue;
                }
                if let Some(slot) = seen.iter_mut().find(|s| s.is_none()) {
                    *slot = Some(*transform);
                }
                if transform.apply_group(self, map, &mut out) == Flow::Remove {
                    return Flow::Remove;
                }
            }
        }
        if crate::transform::report_strings(self, fields_name, map) == Flow::Remove {
            return Flow::Remove;
        }

        let src = mem::take(map);
        for (name, mut value) in src {
            if name == TYPE_KEY {
                out.insert(name, value);
                continue;
            }
            let rule = rules.and_then(|r| r.get(name.as_str()));
            let Some(prop) = fields.property(&name) else {
                if rule.is_none() {
                    self.path.push(&name);
                    self.report
                        .push(self.key, self.path.as_str(), Change::Unknown);
                    self.path.pop();
                }
                out.insert(name, value);
                continue;
            };
            self.path.push(&name);
            let (flow, insert) = match rule {
                None => {
                    let flow = self.walk_value(&prop.ty, &mut value);
                    (flow, Some((name, value)))
                }
                Some(PropertyRule::Keep(conversion)) => {
                    let flow = self.convert_then_walk(*conversion, &prop.ty, &mut value);
                    (flow, Some((name, value)))
                }
                Some(PropertyRule::Rename { to, convert }) => {
                    let flow = self.convert_then_walk(*convert, &prop.ty, &mut value);
                    (flow, Some((to.to_string(), value)))
                }
                Some(PropertyRule::Drop) => {
                    let shown = self.shown_value(&prop.ty, &value);
                    self.report.push(
                        self.key,
                        self.path.as_str(),
                        Change::Dropped {
                            reason: DropReason::NoEquivalent,
                            value: shown,
                        },
                    );
                    (Flow::Keep, None)
                }
                Some(PropertyRule::Move { object, property }) => {
                    if self.walk_value(&prop.ty, &mut value) == Flow::Keep {
                        self.moves.push(Move {
                            source: self.key.clone(),
                            object: object.clone(),
                            property: property.clone(),
                            value,
                        });
                    }
                    (Flow::Keep, None)
                }
                Some(PropertyRule::Transform {
                    transform,
                    variables,
                }) if transform.kind() == TransformKind::Property => {
                    let previous = mem::replace(&mut self.variables, variables);
                    let flow = transform.apply_property(self, &name, &prop.ty, value, &mut out);
                    self.variables = previous;
                    if self.drop_expression {
                        out.remove(&name);
                    }
                    (flow, None)
                }
                Some(PropertyRule::Transform { .. }) => (Flow::Keep, Some((name, value))),
            };
            if std::mem::take(&mut self.drop_expression) {
                self.report.push(
                    self.key,
                    self.path.as_str(),
                    Change::Transformed {
                        transform: COUNTER_READ,
                        detail: "expression dropped as answered; the v1 default applies".into(),
                    },
                );
                self.path.pop();
                continue;
            }
            self.path.pop();
            match (flow, insert) {
                (Flow::Keep, Some((key, value))) => {
                    out.insert(key, value);
                }
                (Flow::Keep, None) => (),
                (Flow::Remove, insert) if prop.ty.nullable => {
                    if let Some((key, _)) = insert {
                        out.insert(key, Value::Null);
                    }
                }
                (Flow::Remove, _) => return Flow::Remove,
            }
        }
        *map = out;
        Flow::Keep
    }

    pub fn walk_value(&mut self, ty: &TypeDef, value: &mut Value) -> Flow {
        match &ty.ty {
            Type::Enum(name) => {
                let Some(current) = value.as_str() else {
                    return Flow::Keep;
                };
                match self.session.rules.enum_rule(name, current) {
                    Some(EnumRule::Rename(targets)) => {
                        if let Some(first) = targets.first() {
                            *value = Value::String(first.to_string());
                        }
                        Flow::Keep
                    }
                    Some(EnumRule::Drop) => {
                        let shown = Some(value.clone());
                        self.dropped_here(DropReason::NoEquivalent, shown);
                        Flow::Remove
                    }
                    None => Flow::Keep,
                }
            }
            Type::Object(schema) => {
                if !value.is_object() {
                    return Flow::Keep;
                }
                let flow = self.walk_schema(schema, value);
                if flow == Flow::Keep && &**schema == EXPRESSION_SCHEMA {
                    self.rename_expression_variables(value);
                }
                flow
            }
            Type::ObjectList { schema, .. } => {
                let Value::Object(items) = value else {
                    return Flow::Keep;
                };
                let mut removed = Vec::new();
                for (index, item) in items.iter_mut() {
                    if !item.is_object() {
                        continue;
                    }
                    self.path.push(index);
                    let flow = self.walk_schema(schema, item);
                    if flow == Flow::Remove {
                        removed.push(index.clone());
                    } else if &**schema == EXPRESSION_SCHEMA {
                        self.rename_expression_variables(item);
                    }
                    self.path.pop();
                }
                for index in removed {
                    items.remove(&index);
                }
                Flow::Keep
            }
            Type::Set { class, .. } => {
                if let (Type::Enum(name), Value::Object(members)) = (&class.ty, &mut *value) {
                    self.remap_enum_keys(name, members);
                }
                Flow::Keep
            }
            Type::Map {
                key,
                value: value_ty,
            } => {
                let Value::Object(entries) = value else {
                    return Flow::Keep;
                };
                if let Type::Enum(name) = &key.ty {
                    self.remap_enum_keys(name, entries);
                }
                let mut removed = Vec::new();
                for (entry_key, entry) in entries.iter_mut() {
                    self.path.push(entry_key);
                    if self.walk_value(value_ty, entry) == Flow::Remove {
                        removed.push(entry_key.clone());
                    }
                    self.path.pop();
                }
                for entry_key in removed {
                    entries.remove(&entry_key);
                }
                Flow::Keep
            }
            _ => Flow::Keep,
        }
    }

    pub fn remap_enum_keys(&mut self, name: &str, members: &mut Map<String, Value>) {
        let rules = self.session.rules;
        if !members.keys().any(|k| rules.enum_rule(name, k).is_some()) {
            return;
        }
        let src = mem::take(members);
        for (member, value) in src {
            match rules.enum_rule(name, &member) {
                Some(EnumRule::Rename(targets)) => {
                    for target in targets.iter() {
                        members
                            .entry(target.to_string())
                            .or_insert_with(|| value.clone());
                    }
                }
                Some(EnumRule::Drop) => {
                    let path = self.path.child(&member);
                    self.report.push(
                        self.key,
                        &path,
                        Change::Dropped {
                            reason: DropReason::NoEquivalent,
                            value: None,
                        },
                    );
                }
                None => {
                    members.insert(member, value);
                }
            }
        }
    }

    fn rename_expression_variables(&mut self, value: &mut Value) {
        let rules = self.session.rules;
        let renames = rules.enums.get(EXPRESSION_VARIABLES);
        if renames.is_none() && rules.functions.is_empty() {
            return;
        }
        let prompted = defaults::expression_texts(value)
            .into_iter()
            .find_map(|text| {
                rules.functions.iter().find_map(|(name, rule)| {
                    let prompt = rule.prompt?;
                    defaults::rewrite_function_calls(text, |n| (n == &**name).then_some(rule))
                        .map(|_| prompt)
                })
            });
        let mut allow_prompted = true;
        if let Some(prompt) = prompted {
            let context = defaults::expression_texts(value)
                .into_iter()
                .map(|text| (Box::<str>::from("expression"), Value::String(text.into())))
                .collect();
            let defaults = self.prompt_defaults(prompt);
            let answer = self.ask(prompt, defaults, context);
            match answer.str("action") {
                Some("rewrite") => (),
                Some("abort") => {
                    self.abort = true;
                    allow_prompted = false;
                }
                _ => {
                    self.drop_expression = true;
                    return;
                }
            }
        }
        let mut changed = Vec::new();
        defaults::for_each_expression_text(value, |text| {
            let original = text.clone();
            if let Some(renames) = renames
                && let Some(rewritten) =
                    defaults::rename_identifiers(text, |ident| match renames.get(ident) {
                        Some(EnumRule::Rename(targets)) => targets.first().map(|t| &**t),
                        _ => None,
                    })
            {
                *text = rewritten;
            }
            if let Some(rewritten) = defaults::rewrite_function_calls(text, |name| {
                rules
                    .functions
                    .get(name)
                    .filter(|rule| allow_prompted || rule.prompt.is_none())
            }) {
                *text = rewritten;
            }
            if *text != original {
                changed.push(format!("{original} -> {text}"));
            }
        });
        for detail in changed {
            let change = if prompted.is_some() {
                Change::Transformed {
                    transform: COUNTER_READ,
                    detail,
                }
            } else {
                Change::Transformed {
                    transform: "expression_variables",
                    detail,
                }
            };
            self.report.push(self.key, self.path.as_str(), change);
        }
    }

    fn convert_then_walk(
        &mut self,
        conversion: Conversion,
        ty: &TypeDef,
        value: &mut Value,
    ) -> Flow {
        match self.convert_value(conversion, ty, value) {
            Flow::Keep => self.walk_value(ty, value),
            Flow::Remove => Flow::Remove,
        }
    }

    fn convert_value(&mut self, conversion: Conversion, ty: &TypeDef, value: &mut Value) -> Flow {
        match convert_plain(conversion, value) {
            Ok(Some(converted)) => {
                *value = converted;
                Flow::Keep
            }
            Ok(None) => Flow::Keep,
            Err(InvalidValue) => {
                let shown = self.shown_value(ty, value);
                self.dropped_here(DropReason::Invalid, shown);
                Flow::Remove
            }
        }
    }

    pub fn shown_value(&self, ty: &TypeDef, value: &Value) -> Option<Value> {
        if value.is_null() {
            None
        } else if ty.is_secret() {
            Some(mask_property("", Some(ty), value))
        } else {
            Some(value.clone())
        }
    }

    pub fn dropped(&mut self, segment: &str, reason: DropReason, value: Option<&Value>) {
        self.dropped_typed(segment, reason, value, None);
    }

    pub fn dropped_typed(
        &mut self,
        segment: &str,
        reason: DropReason,
        value: Option<&Value>,
        ty: Option<&TypeDef>,
    ) {
        let path = if segment.is_empty() {
            self.path.as_str().to_string()
        } else {
            self.path.child(segment)
        };
        self.report.push(
            self.key,
            &path,
            Change::Dropped {
                reason,
                value: value.map(|v| mask_property(segment, ty, v)),
            },
        );
    }

    pub fn dropped_here(&mut self, reason: DropReason, value: Option<Value>) {
        self.report.push(
            self.key,
            self.path.as_str(),
            Change::Dropped { reason, value },
        );
    }

    pub fn transformed(&mut self, transform: Transform, segment: &str, detail: impl Into<String>) {
        let path = if segment.is_empty() {
            self.path.as_str().to_string()
        } else {
            self.path.child(segment)
        };
        self.report.push(
            self.key,
            &path,
            Change::Transformed {
                transform: transform.as_str(),
                detail: detail.into(),
            },
        );
    }

    pub fn ask(
        &mut self,
        prompt: PromptId,
        defaults: Answer,
        context: Vec<(Box<str>, Value)>,
    ) -> Answer {
        let key = self.key;
        self.session
            .answer(self.report, prompt, Some(key), defaults, context)
    }

    pub fn ask_global(&mut self, prompt: PromptId) -> Answer {
        self.session.global_answer(self.report, prompt)
    }

    pub fn changed_defaults(&mut self) -> &Answer {
        if self.changed_defaults.is_none() {
            let answer = match self.direction() {
                Direction::Forward => self.ask_global(PromptId::ChangedDefaults),
                Direction::Reverse => Answer::default(),
            };
            self.changed_defaults = Some(answer);
        }
        self.changed_defaults.get_or_insert_default()
    }

    pub fn prompt_defaults(&self, prompt: PromptId) -> Answer {
        Answer::defaults_of(self.session.mapping.catalogue().prompt(prompt))
    }
}

#[derive(Debug)]
pub(crate) struct InvalidValue;

pub(crate) fn convert_plain(
    conversion: Conversion,
    value: &Value,
) -> Result<Option<Value>, InvalidValue> {
    if conversion == Conversion::Compatible
        || (value.is_null() && conversion != Conversion::StringToPublicOptional)
    {
        return Ok(None);
    }
    let converted = match (conversion, value) {
        (Conversion::StringToUnsigned, Value::String(s)) => {
            Value::from(s.trim().parse::<u64>().map_err(|_| InvalidValue)?)
        }
        (Conversion::UnsignedToString, Value::Number(n)) => Value::String(n.to_string()),
        (Conversion::ScalarToSet, Value::String(s)) => {
            let mut set = Map::with_capacity(1);
            set.insert(s.clone(), Value::Bool(true));
            Value::Object(set)
        }
        (Conversion::SetToScalar, Value::Object(set)) => set
            .keys()
            .next()
            .map(|k| Value::String(k.clone()))
            .unwrap_or(Value::Null),
        (Conversion::StringToPublicOptional, Value::Null) => {
            let mut map = Map::with_capacity(1);
            map.insert(TYPE_KEY.into(), Value::String("None".into()));
            Value::Object(map)
        }
        (Conversion::StringToPublicOptional, Value::String(s)) => {
            let mut map = Map::with_capacity(2);
            map.insert(TYPE_KEY.into(), Value::String("Value".into()));
            map.insert("value".into(), Value::String(s.clone()));
            Value::Object(map)
        }
        _ => return Ok(None),
    };
    Ok(Some(converted))
}
