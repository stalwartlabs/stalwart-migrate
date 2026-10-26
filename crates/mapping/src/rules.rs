use std::collections::BTreeMap;

use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::{
    error::{Error, Result},
    schema::{ObjectKind, Schema, SchemaDef},
    transform::Transform,
};

const SUPPORTED_VERSION: u32 = 1;
const WILDCARD: &str = "*";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conversion {
    Compatible,
    StringToUnsigned,
    UnsignedToString,
    ScalarToSet,
    SetToScalar,
    StringToPublicOptional,
}

impl Conversion {
    fn parse(name: &str) -> Option<Self> {
        hashify::map!(name.as_bytes(), Conversion,
            "compatible" => Conversion::Compatible,
            "string_to_unsigned" => Conversion::StringToUnsigned,
            "unsigned_to_string" => Conversion::UnsignedToString,
            "scalar_to_set" => Conversion::ScalarToSet,
            "set_to_scalar" => Conversion::SetToScalar,
            "string_to_public_optional" => Conversion::StringToPublicOptional,
        )
        .copied()
    }

    fn inverse(self) -> Self {
        match self {
            Conversion::Compatible | Conversion::StringToPublicOptional => Conversion::Compatible,
            Conversion::StringToUnsigned => Conversion::UnsignedToString,
            Conversion::UnsignedToString => Conversion::StringToUnsigned,
            Conversion::ScalarToSet => Conversion::SetToScalar,
            Conversion::SetToScalar => Conversion::ScalarToSet,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PropertyRule {
    Keep(Conversion),
    Rename {
        to: Box<str>,
        convert: Conversion,
    },
    Drop,
    Move {
        object: Box<str>,
        property: Box<str>,
    },
    Transform {
        transform: Transform,
        variables: Box<[Box<str>]>,
    },
}

#[derive(Debug, Clone)]
pub enum VariantRule {
    Keep,
    Rename(Box<str>),
    Drop,
    Transform(Transform),
}

#[derive(Debug, Clone, Copy)]
pub enum ObjectAction {
    Keep,
    Drop,
    Transform(Transform),
}

#[derive(Debug, Clone)]
pub struct ObjectRule {
    pub to: Option<Box<str>>,
    pub action: ObjectAction,
}

#[derive(Debug, Clone)]
pub enum EnumRule {
    Rename(Box<[Box<str>]>),
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Pin,
    Inherit,
}

impl Policy {
    pub fn parse(name: &str) -> Option<Self> {
        hashify::map!(name.as_bytes(), Policy,
            "pin" => Policy::Pin,
            "inherit" => Policy::Inherit,
        )
        .copied()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Pin => "pin",
            Policy::Inherit => "inherit",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DefaultsTable {
    pub all: Option<Policy>,
    pub properties: FxHashMap<Box<str>, Policy>,
}

impl DefaultsTable {
    pub fn policy(&self, property: &str) -> Option<Policy> {
        self.properties.get(property).copied().or(self.all)
    }
}

#[derive(Debug, Clone)]
pub struct FunctionRule {
    pub to: Box<str>,
    pub append: Box<[Box<str>]>,
    pub prompt: Option<crate::prompts::PromptId>,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub permission: Box<str>,
    pub when_any: Box<[Box<str>]>,
}

#[derive(Debug, Clone)]
pub struct Separator {
    pub from: Box<str>,
    pub to: Box<str>,
}

#[derive(Debug, Clone, Default)]
pub struct SpamTags {
    pub renamed: FxHashMap<Box<str>, Box<str>>,
    pub removed_prefixes: Box<[Box<str>]>,
    pub added: Box<[(Box<str>, f64)]>,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub objects: FxHashMap<Box<str>, ObjectRule>,
    pub variants: FxHashMap<Box<str>, FxHashMap<Box<str>, VariantRule>>,
    pub properties: FxHashMap<Box<str>, FxHashMap<Box<str>, PropertyRule>>,
    pub enums: FxHashMap<Box<str>, FxHashMap<Box<str>, EnumRule>>,
    pub separators: FxHashMap<Box<str>, Separator>,
    pub defaults: FxHashMap<Box<str>, DefaultsTable>,
    pub grants: Box<[Grant]>,
    pub functions: FxHashMap<Box<str>, FunctionRule>,
    pub spam_tags: SpamTags,
}

impl RuleSet {
    pub fn object(&self, name: &str) -> Option<&ObjectRule> {
        self.objects.get(name)
    }

    pub fn variant(&self, union: &str, name: &str) -> Option<&VariantRule> {
        self.variants.get(union).and_then(|t| t.get(name))
    }

    pub fn property_rules(&self, fields: &str) -> Option<&FxHashMap<Box<str>, PropertyRule>> {
        self.properties.get(fields)
    }

    pub fn enum_rule(&self, name: &str, value: &str) -> Option<&EnumRule> {
        self.enums.get(name).and_then(|t| t.get(value))
    }

    pub fn defaults(&self, fields: &str) -> Option<&DefaultsTable> {
        self.defaults.get(fields)
    }

    pub fn parse(file: &str, text: &str) -> Result<Self> {
        let raw: RawRules = toml::from_str(text).map_err(|source| Error::Toml {
            file: file.into(),
            source,
        })?;
        if raw.version != SUPPORTED_VERSION {
            return Err(Error::rule(
                file,
                "version",
                format!("unsupported {}", raw.version),
            ));
        }
        let mut rules = RuleSet::default();
        for (name, rule) in raw.objects {
            let parsed = rule.into_object(file, &name)?;
            rules.objects.insert(name.into(), parsed);
        }
        for (union, table) in raw.variants {
            let mut parsed = FxHashMap::default();
            for (name, rule) in table {
                let key = format!("{union}.{name}");
                parsed.insert(name.into(), rule.into_variant(file, &key)?);
            }
            rules.variants.insert(union.into(), parsed);
        }
        for (fields, table) in raw.properties {
            let mut parsed = FxHashMap::default();
            for (name, rule) in table {
                let key = format!("{fields}.{name}");
                parsed.insert(name.into(), rule.into_property(file, &key)?);
            }
            rules.properties.insert(fields.into(), parsed);
        }
        for (name, table) in raw.enums {
            let mut parsed = FxHashMap::default();
            for (value, rule) in table {
                let key = format!("{name}.{value}");
                parsed.insert(value.into(), rule.into_enum(file, &key)?);
            }
            rules.enums.insert(name.into(), parsed);
        }
        for (name, separator) in raw.enum_separators {
            rules.separators.insert(
                name.into(),
                Separator {
                    from: separator.from.into(),
                    to: separator.to.into(),
                },
            );
        }
        for (fields, table) in raw.defaults {
            let mut parsed = DefaultsTable::default();
            for (name, policy) in table {
                let policy = Policy::parse(&policy).ok_or_else(|| {
                    Error::rule(file, format!("defaults.{fields}.{name}"), "pin or inherit")
                })?;
                if name == WILDCARD {
                    parsed.all = Some(policy);
                } else {
                    parsed.properties.insert(name.into(), policy);
                }
            }
            rules.defaults.insert(fields.into(), parsed);
        }
        for (name, rule) in raw.expression_functions {
            let parsed = match rule {
                RawFunction::Rename(to) => FunctionRule {
                    to: to.into(),
                    append: Box::default(),
                    prompt: None,
                },
                RawFunction::Table {
                    to,
                    append_args,
                    prompt,
                } => FunctionRule {
                    to: to.into(),
                    append: append_args.into_iter().map(Into::into).collect(),
                    prompt: prompt
                        .map(|p| {
                            crate::prompts::PromptId::parse(&p).ok_or_else(|| {
                                Error::rule(
                                    file,
                                    format!("expression_functions.{name}"),
                                    "unknown prompt",
                                )
                            })
                        })
                        .transpose()?,
                },
            };
            rules.functions.insert(name.into(), parsed);
        }
        rules.grants = raw
            .permission_grants
            .into_iter()
            .map(|(new, old)| Grant {
                permission: new.into(),
                when_any: old.into_iter().map(Into::into).collect(),
            })
            .collect();
        rules.spam_tags = SpamTags {
            renamed: raw
                .spam_tags
                .renamed
                .into_iter()
                .map(|(old, new)| (old.into(), new.into()))
                .collect(),
            removed_prefixes: raw
                .spam_tags
                .removed_prefixes
                .into_iter()
                .map(Into::into)
                .collect(),
            added: raw
                .spam_tags
                .added
                .into_iter()
                .map(|(tag, score)| (tag.into(), score))
                .collect(),
        };
        Ok(rules)
    }

    pub fn check_against(&self, file: &str, old: &Schema, new: &Schema) -> Result<()> {
        for (name, rule) in &self.objects {
            if old.object(name).is_none() {
                return Err(Error::rule(file, &**name, "not a source object"));
            }
            if let Some(to) = &rule.to
                && new.object(to).is_none()
            {
                return Err(Error::rule(
                    file,
                    &**name,
                    format!("{to} is not a target object"),
                ));
            }
        }
        for (fields, table) in &self.properties {
            if old.fields(fields).is_none() {
                return Err(Error::rule(file, &**fields, "not a source schema"));
            }
            for (name, rule) in table {
                let target = match rule {
                    PropertyRule::Rename { to, .. } => Some((&**fields, &**to)),
                    PropertyRule::Move { object, property } => Some((&**object, &**property)),
                    _ => None,
                };
                if let Some((target_fields, target_prop)) = target
                    && new.property(target_fields, target_prop).is_none()
                {
                    return Err(Error::rule(
                        file,
                        format!("{fields}.{name}"),
                        format!("{target_fields}.{target_prop} is not a target property"),
                    ));
                }
            }
        }
        for (name, table) in &self.enums {
            for (value, rule) in table {
                if let EnumRule::Rename(targets) = rule
                    && let Some(bad) = targets.iter().find(|t| !new.enum_has(name, t))
                {
                    return Err(Error::rule(
                        file,
                        format!("{name}.{value}"),
                        format!("{bad} is not a target value"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn pin_singletons(&self, source: &Schema) -> Box<[Box<str>]> {
        let mut singletons: Vec<Box<str>> = source
            .objects()
            .filter(|(_, def)| def.kind == ObjectKind::Singleton)
            .filter_map(|(name, _)| match source.schema(name) {
                Some(SchemaDef::Single(fields)) => self
                    .defaults
                    .get(fields)
                    .filter(|t| {
                        t.all == Some(Policy::Pin)
                            || t.properties.values().any(|p| *p == Policy::Pin)
                    })
                    .map(|_| Box::from(name)),
                _ => None,
            })
            .collect();
        singletons.sort_unstable();
        singletons.into_boxed_slice()
    }

    pub fn invert(&self, old: &Schema) -> RuleSet {
        let mut inverse = RuleSet::default();
        for (name, rule) in &self.objects {
            let action = match rule.action {
                ObjectAction::Transform(t) if t.has_reverse() => ObjectAction::Transform(t),
                _ => ObjectAction::Keep,
            };
            match &rule.to {
                Some(to) => {
                    inverse.objects.insert(
                        to.clone(),
                        ObjectRule {
                            to: Some(name.clone()),
                            action,
                        },
                    );
                }
                None if matches!(action, ObjectAction::Transform(_)) => {
                    inverse
                        .objects
                        .insert(name.clone(), ObjectRule { to: None, action });
                }
                None => (),
            }
        }
        for (union, table) in &self.variants {
            for (name, rule) in table {
                let entry = match rule {
                    VariantRule::Rename(to) => {
                        Some((to.clone(), VariantRule::Rename(name.clone())))
                    }
                    VariantRule::Transform(t) if t.has_reverse() => {
                        Some((name.clone(), VariantRule::Transform(*t)))
                    }
                    _ => None,
                };
                if let Some((key, rule)) = entry {
                    inverse
                        .variants
                        .entry(union.clone())
                        .or_default()
                        .insert(key, rule);
                }
            }
        }
        for (fields, table) in &self.properties {
            for (name, rule) in table {
                let (target_fields, key, inverse_rule) = match rule {
                    PropertyRule::Keep(convert) => (
                        fields.clone(),
                        name.clone(),
                        PropertyRule::Keep(convert.inverse()),
                    ),
                    PropertyRule::Rename { to, convert } => (
                        fields.clone(),
                        to.clone(),
                        PropertyRule::Rename {
                            to: name.clone(),
                            convert: convert.inverse(),
                        },
                    ),
                    PropertyRule::Move { object, property } => (
                        object.clone(),
                        property.clone(),
                        PropertyRule::Move {
                            object: fields.clone(),
                            property: name.clone(),
                        },
                    ),
                    PropertyRule::Transform {
                        transform,
                        variables,
                    } => {
                        if transform.has_reverse() {
                            let entry = inverse.properties.entry(fields.clone()).or_default();
                            for trigger in transform.reverse_triggers() {
                                entry.insert(
                                    (*trigger).into(),
                                    PropertyRule::Transform {
                                        transform: *transform,
                                        variables: variables.clone(),
                                    },
                                );
                            }
                        }
                        continue;
                    }
                    PropertyRule::Drop => continue,
                };
                inverse
                    .properties
                    .entry(target_fields)
                    .or_default()
                    .insert(key, inverse_rule);
            }
        }
        for (name, table) in &self.enums {
            let mut sources: Vec<(&str, &str)> = table
                .iter()
                .filter_map(|(value, rule)| match rule {
                    EnumRule::Rename(targets) => Some((value, targets)),
                    EnumRule::Drop => None,
                })
                .flat_map(|(value, targets)| targets.iter().map(move |t| (&**t, &**value)))
                .filter(|(target, _)| !old.enum_has(name, target))
                .collect();
            sources.sort_unstable();
            let entry = inverse.enums.entry(name.clone()).or_default();
            for (target, source) in sources {
                entry
                    .entry(target.into())
                    .or_insert_with(|| EnumRule::Rename(Box::new([source.into()])));
            }
        }
        for (name, rule) in &self.functions {
            if rule.append.is_empty() {
                inverse.functions.insert(
                    rule.to.clone(),
                    FunctionRule {
                        to: name.clone(),
                        append: Box::default(),
                        prompt: None,
                    },
                );
            }
        }
        for (fields, table) in &self.defaults {
            let renames = self.properties.get(fields);
            let mut parsed = DefaultsTable {
                all: table.all,
                properties: FxHashMap::default(),
            };
            for (name, policy) in &table.properties {
                let key = match renames.and_then(|r| r.get(name)) {
                    Some(PropertyRule::Rename { to, .. }) => to.clone(),
                    _ => name.clone(),
                };
                parsed.properties.insert(key, *policy);
            }
            inverse.defaults.insert(fields.clone(), parsed);
        }
        inverse
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    version: u32,
    #[serde(default)]
    objects: BTreeMap<String, RawRule>,
    #[serde(default, rename = "schemas")]
    _schemas: BTreeMap<String, String>,
    #[serde(default, rename = "retired_enums")]
    _retired_enums: BTreeMap<String, String>,
    #[serde(default)]
    variants: BTreeMap<String, BTreeMap<String, RawRule>>,
    #[serde(default)]
    properties: BTreeMap<String, BTreeMap<String, RawRule>>,
    #[serde(default)]
    enums: BTreeMap<String, BTreeMap<String, RawRule>>,
    #[serde(default)]
    enum_separators: BTreeMap<String, RawSeparator>,
    #[serde(default)]
    defaults: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    permission_grants: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    expression_functions: BTreeMap<String, RawFunction>,
    #[serde(default)]
    spam_tags: RawSpamTags,
    #[serde(default, rename = "populated")]
    _populated: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawSpamTags {
    #[serde(default)]
    renamed: BTreeMap<String, String>,
    #[serde(default)]
    removed_prefixes: Vec<String>,
    #[serde(default)]
    added: BTreeMap<String, f64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawFunction {
    Rename(String),
    Table {
        to: String,
        #[serde(default)]
        append_args: Vec<String>,
        prompt: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSeparator {
    from: String,
    to: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRule {
    Rename(String),
    Table(RawRuleTable),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawTarget {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParams {
    variables: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawRuleTable {
    to: Option<RawTarget>,
    #[serde(default)]
    drop: bool,
    convert: Option<String>,
    transform: Option<String>,
    #[serde(rename = "move")]
    move_to: Option<String>,
    params: Option<RawParams>,
    payload: Option<String>,
}

impl RawRule {
    fn into_table(self) -> RawRuleTable {
        match self {
            RawRule::Rename(to) => RawRuleTable {
                to: Some(RawTarget::One(to)),
                ..Default::default()
            },
            RawRule::Table(table) => table,
        }
    }

    fn into_object(self, file: &str, key: &str) -> Result<ObjectRule> {
        let table = self.into_table();
        table.only(file, key, &["to", "drop", "transform"])?;
        let action = match (table.drop, table.transform) {
            (true, None) => ObjectAction::Drop,
            (false, Some(name)) => ObjectAction::Transform(parse_transform(file, key, &name)?),
            (false, None) => ObjectAction::Keep,
            (true, Some(_)) => return Err(Error::rule(file, key, "drop and transform")),
        };
        Ok(ObjectRule {
            to: table.to.map(|t| t.single(file, key)).transpose()?,
            action,
        })
    }

    fn into_variant(self, file: &str, key: &str) -> Result<VariantRule> {
        let table = self.into_table();
        table.only(file, key, &["to", "drop", "transform", "payload"])?;
        if table.payload.as_deref() == Some("compatible") {
            return Ok(VariantRule::Keep);
        }
        match (table.to, table.drop, table.transform) {
            (Some(to), false, None) => Ok(VariantRule::Rename(to.single(file, key)?)),
            (None, true, None) => Ok(VariantRule::Drop),
            (None, false, Some(name)) => {
                Ok(VariantRule::Transform(parse_transform(file, key, &name)?))
            }
            _ => Err(Error::rule(
                file,
                key,
                "expected exactly one of to, drop, transform",
            )),
        }
    }

    fn into_property(self, file: &str, key: &str) -> Result<PropertyRule> {
        let table = self.into_table();
        let convert = table
            .convert
            .as_deref()
            .map(|name| {
                Conversion::parse(name)
                    .ok_or_else(|| Error::rule(file, key, format!("unknown conversion {name}")))
            })
            .transpose()?;
        match (table.to, table.drop, table.move_to, table.transform) {
            (Some(to), false, None, None) if table.params.is_none() => Ok(PropertyRule::Rename {
                to: to.single(file, key)?,
                convert: convert.unwrap_or(Conversion::Compatible),
            }),
            (None, false, None, None) if table.params.is_none() => convert
                .map(PropertyRule::Keep)
                .ok_or_else(|| Error::rule(file, key, "empty rule")),
            (None, true, None, None) if convert.is_none() && table.params.is_none() => {
                Ok(PropertyRule::Drop)
            }
            (None, false, Some(target), None) if convert.is_none() && table.params.is_none() => {
                let (object, property) = target
                    .split_once('.')
                    .ok_or_else(|| Error::rule(file, key, "move target is object.property"))?;
                Ok(PropertyRule::Move {
                    object: object.into(),
                    property: property.into(),
                })
            }
            (None, false, None, Some(name)) if convert.is_none() => Ok(PropertyRule::Transform {
                transform: parse_transform(file, key, &name)?,
                variables: table
                    .params
                    .map(|p| p.variables.into_iter().map(Into::into).collect())
                    .unwrap_or_default(),
            }),
            _ => Err(Error::rule(file, key, "conflicting rule keys")),
        }
    }

    fn into_enum(self, file: &str, key: &str) -> Result<EnumRule> {
        let table = self.into_table();
        table.only(file, key, &["to", "drop"])?;
        match (table.to, table.drop) {
            (Some(RawTarget::One(to)), false) => Ok(EnumRule::Rename(Box::new([to.into()]))),
            (Some(RawTarget::Many(targets)), false) if !targets.is_empty() => Ok(EnumRule::Rename(
                targets.into_iter().map(Into::into).collect(),
            )),
            (None, true) => Ok(EnumRule::Drop),
            _ => Err(Error::rule(file, key, "expected to or drop")),
        }
    }
}

impl RawRuleTable {
    fn only(&self, file: &str, key: &str, allowed: &[&str]) -> Result<()> {
        let present = [
            ("convert", self.convert.is_some()),
            ("payload", self.payload.is_some()),
            ("move", self.move_to.is_some()),
            ("params", self.params.is_some()),
            ("transform", self.transform.is_some()),
            ("drop", self.drop),
            ("to", self.to.is_some()),
        ];
        match present
            .iter()
            .find(|(name, set)| *set && !allowed.contains(name))
        {
            Some((name, _)) => Err(Error::rule(
                file,
                key,
                format!("{name} is not allowed here"),
            )),
            None => Ok(()),
        }
    }
}

impl RawTarget {
    fn single(self, file: &str, key: &str) -> Result<Box<str>> {
        match self {
            RawTarget::One(to) => Ok(to.into()),
            RawTarget::Many(_) => Err(Error::rule(
                file,
                key,
                "a list target is only valid for enums",
            )),
        }
    }
}

fn parse_transform(file: &str, key: &str, name: &str) -> Result<Transform> {
    Transform::parse(name)
        .ok_or_else(|| Error::rule(file, key, format!("unknown transform {name}")))
}
