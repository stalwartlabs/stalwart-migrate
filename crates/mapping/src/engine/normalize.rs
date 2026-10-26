use serde_json::{Map, Value};

use super::{
    Session,
    walk::{TYPE_KEY, convert_plain},
};
use crate::{
    ids::ObjectKey,
    report::{Change, Report},
    rules::{EnumRule, PropertyRule, RuleSet},
    schema::{Schema, SchemaDef, Type, TypeDef},
};

const NORMALIZE: &str = "normalize_016x";

struct Normalizer<'s, 'r> {
    rules: &'s RuleSet,
    schema: &'s Schema,
    report: &'r mut Report,
    key: &'r ObjectKey,
}

pub(super) fn normalize_object(
    session: &Session,
    key: &ObjectKey,
    value: &mut Value,
    report: &mut Report,
) {
    let mut normalizer = Normalizer {
        rules: &session.mapping.normalize,
        schema: &session.mapping.v016,
        report,
        key,
    };
    normalizer.schema(&key.object, value);
}

impl Normalizer<'_, '_> {
    fn changed(&mut self, from: &str, to: &str) {
        self.report.push(
            self.key,
            "",
            Change::Transformed {
                transform: NORMALIZE,
                detail: format!("{from} -> {to}"),
            },
        );
    }

    fn schema(&mut self, name: &str, value: &mut Value) {
        let schema = self.schema;
        let (Some(def), Value::Object(map)) = (schema.schema(name), value) else {
            return;
        };
        let fields = match def {
            SchemaDef::Single(fields) => fields,
            SchemaDef::Union(_) => {
                let Some(current) = map.get(TYPE_KEY).and_then(Value::as_str) else {
                    return;
                };
                let current: Box<str> = current.into();
                let variant = match def.variant(&current) {
                    Some(variant) => variant,
                    None => {
                        let Some(rule_target) = (match self.rules.variant(name, &current) {
                            Some(crate::rules::VariantRule::Rename(to)) => Some(to.clone()),
                            _ => None,
                        }) else {
                            return;
                        };
                        let Some(variant) = def.variant(&rule_target) else {
                            return;
                        };
                        map.insert(TYPE_KEY.into(), Value::String(rule_target.to_string()));
                        self.changed(&current, &rule_target);
                        variant
                    }
                };
                let Some(fields) = &variant.schema else {
                    return;
                };
                fields
            }
        };
        self.fields(fields, map);
    }

    fn fields(&mut self, fields_name: &str, map: &mut Map<String, Value>) {
        let schema = self.schema;
        let Some(fields) = schema.fields(fields_name) else {
            return;
        };
        let rules = self.rules.property_rules(fields_name);
        for (name, value) in map.iter_mut() {
            let Some(prop) = fields.property(name) else {
                continue;
            };
            if let Some(PropertyRule::Keep(conversion)) = rules.and_then(|r| r.get(name.as_str()))
                && !value.is_object()
                && let Ok(Some(converted)) = convert_plain(*conversion, value)
            {
                self.changed(name, "object form");
                *value = converted;
            }
            self.value(&prop.ty, value);
        }
    }

    fn value(&mut self, ty: &TypeDef, value: &mut Value) {
        match &ty.ty {
            Type::Enum(name) => {
                if let Some(fixed) = value.as_str().and_then(|v| self.enum_value(name, v)) {
                    *value = Value::String(fixed);
                }
            }
            Type::Set { class, .. } => {
                if let (Type::Enum(name), Value::Object(members)) = (&class.ty, &mut *value) {
                    self.enum_keys(name, members);
                }
            }
            Type::Map {
                key,
                value: value_ty,
            } => {
                if let Value::Object(entries) = value {
                    if let Type::Enum(name) = &key.ty {
                        self.enum_keys(name, entries);
                    }
                    for entry in entries.values_mut() {
                        self.value(value_ty, entry);
                    }
                }
            }
            Type::Object(name) => self.schema(name, value),
            Type::ObjectList { schema, .. } => {
                if let Value::Object(items) = value {
                    for item in items.values_mut() {
                        self.schema(schema, item);
                    }
                }
            }
            _ => (),
        }
    }

    fn enum_keys(&mut self, name: &str, members: &mut Map<String, Value>) {
        let fixes: Vec<(String, String)> = members
            .keys()
            .filter_map(|k| self.enum_value(name, k).map(|fixed| (k.clone(), fixed)))
            .collect();
        for (from, to) in fixes {
            if let Some(v) = members.remove(&from) {
                members.insert(to, v);
            }
        }
    }

    fn enum_value(&mut self, name: &str, current: &str) -> Option<String> {
        if self.schema.enum_has(name, current) {
            return None;
        }
        let fixed = match self.rules.enum_rule(name, current) {
            Some(EnumRule::Rename(targets)) => targets.first().map(|t| t.to_string()),
            _ => self
                .rules
                .separators
                .get(name)
                .map(|sep| current.replace(&*sep.from, &sep.to))
                .filter(|candidate| self.schema.enum_has(name, candidate)),
        }?;
        self.changed(current, &fixed);
        Some(fixed)
    }
}
