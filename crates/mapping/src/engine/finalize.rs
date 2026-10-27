use std::collections::hash_map::Entry;

use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{Map, Number, Value};

use super::{
    Direction, Outcome, Session,
    path::Path,
    walk::{TYPE_KEY, compact_list},
};
use crate::{
    answers::{mask_all, mask_property},
    ids::ObjectKey,
    prompts::PromptId,
    report::{Change, DropReason, Report},
    schema::{NumberFormat, SchemaDef, Type, TypeDef},
};

const STORE_OBJECTS: &[&str] = &[
    "x:BlobStore",
    "x:InMemoryStore",
    "x:SearchStore",
    "x:DataStore",
];

struct Finalizer<'s, 'r> {
    session: &'s Session<'s>,
    report: &'r mut Report,
    key: &'r ObjectKey,
    path: Path,
    enterprise_seen: bool,
    store_lost: bool,
    in_secret: bool,
}

#[derive(PartialEq, Eq)]
enum Flow {
    Keep,
    Remove,
}

pub(super) fn finalize_all(
    session: &Session,
    outcome: &mut Outcome,
    originals: &[(ObjectKey, Value)],
) {
    let mut enterprise_seen = false;
    let mut kept = Vec::with_capacity(outcome.objects.len());
    for mut object in std::mem::take(&mut outcome.objects) {
        let mut finalizer = Finalizer {
            session,
            report: &mut outcome.report,
            key: &object.source,
            path: Path::default(),
            enterprise_seen: false,
            store_lost: false,
            in_secret: false,
        };
        let flow = finalizer.object(&object.key.object, &mut object.value);
        enterprise_seen |= finalizer.enterprise_seen;
        outcome.aborted |= finalizer.store_lost;
        match flow {
            Flow::Keep => kept.push(object),
            Flow::Remove => outcome.dropped.push(object.source),
        }
    }
    outcome.objects = kept;
    drop_lost_keys(outcome, originals);
    if enterprise_seen {
        let answer = session.global_answer(&mut outcome.report, PromptId::EnterpriseOnOss);
        if answer.str("action") == Some("abort") {
            outcome.aborted = true;
        }
    }
}

/// The properties forming the unique key of a registry object in both versions, empty when it has none.
pub fn unique_key(object: &str) -> &'static [&'static str] {
    hashify::map!(object.as_bytes(), &'static [&'static str],
        "x:Account" => &["name", "domainId"],
        "x:AllowedIp" => &["address"],
        "x:BlockedIp" => &["address"],
        "x:ClusterRole" => &["name"],
        "x:DmarcExternalReport" => &[
            "report/orgName",
            "report/policyDomain",
            "report/reportId",
            "report/dateRangeEnd",
        ],
        "x:Domain" => &["name"],
        "x:EventTracingLevel" => &["event"],
        "x:HttpLookup" => &["namespace"],
        "x:MailingList" => &["name", "domainId"],
        "x:MemoryLookupKey" => &["namespace", "key"],
        "x:MemoryLookupKeyValue" => &["namespace", "key"],
        "x:MtaConnectionStrategy" => &["name"],
        "x:MtaDeliverySchedule" => &["name"],
        "x:MtaRoute" => &["name"],
        "x:MtaTlsStrategy" => &["name"],
        "x:MtaVirtualQueue" => &["name"],
        "x:NetworkListener" => &["name"],
        "x:OAuthClient" => &["clientId"],
        "x:SieveSystemScript" => &["name"],
        "x:SieveUserScript" => &["name"],
        "x:SpamDnsblServer" => &["name"],
        "x:SpamFileExtension" => &["extension"],
        "x:SpamRule" => &["name"],
        "x:SpamTag" => &["tag"],
        "x:StoreLookup" => &["namespace"],
    )
    .copied()
    .unwrap_or(&[])
}

/// The unique key of `value` rendered as text, `None` when the object has no unique key or lacks a key property.
pub fn unique_key_value(object: &str, value: &Value) -> Option<String> {
    let key = unique_key(object);
    if key.is_empty() {
        return None;
    }
    let mut text = String::new();
    for property in key {
        let part = property
            .split('/')
            .try_fold(value, |value, name| value.get(name))
            .filter(|v| !v.is_null())?;
        if !text.is_empty() {
            text.push_str(", ");
        }
        text.push_str(property);
        text.push(' ');
        text.push_str(&serde_json::to_string(part).unwrap_or_default());
    }
    Some(text)
}

fn keeps_keyless(object: &str) -> bool {
    hashify::set!(object.as_bytes(), "x:DmarcExternalReport")
}

const MERGED_OBJECT: &str = "x:EventTracingLevel";
const MERGED_PROPERTY: &str = "level";
const MERGED_DEFAULT: &str = "info";
const VERBOSITY: [&str; 6] = ["disable", "error", "warn", "info", "debug", "trace"];
pub(super) const KEY_MERGE: &str = "key_merge";

pub(super) fn merges(object: &str) -> bool {
    object == MERGED_OBJECT
}

fn level_of(value: &Value) -> &str {
    value
        .get(MERGED_PROPERTY)
        .and_then(Value::as_str)
        .unwrap_or(MERGED_DEFAULT)
}

fn verbosity(level: &str) -> usize {
    VERBOSITY.iter().position(|l| *l == level).unwrap_or(0)
}

fn describe_original(originals: &[(ObjectKey, Value)], source: &ObjectKey) -> String {
    let value = originals
        .iter()
        .find(|(key, _)| key == source)
        .map(|(_, value)| value);
    let event = value
        .and_then(|v| v.get("event"))
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .unwrap_or_else(|| "null".into());
    let level = value.map_or(MERGED_DEFAULT, level_of);
    format!("event {event} at level {level}")
}

enum Verdict {
    Keep,
    Lost,
    Conflict { key: Box<str>, kept: usize },
    Merged { key: Box<str>, into: usize },
}

fn drop_lost_keys(outcome: &mut Outcome, originals: &[(ObjectKey, Value)]) {
    let lost: FxHashSet<ObjectKey> = outcome
        .report
        .entries
        .iter()
        .filter(|entry| {
            matches!(entry.change, Change::Dropped { .. })
                && unique_key(&entry.key.object).contains(&&*entry.path)
        })
        .map(|entry| entry.key.clone())
        .collect();
    let objects = &mut outcome.objects;
    let mut order: Vec<usize> = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| !unique_key(&object.key.object).is_empty())
        .map(|(position, _)| position)
        .collect();
    if order.is_empty() {
        return;
    }
    order.sort_unstable_by(|a, b| objects[*a].source.cmp(&objects[*b].source));
    let mut verdicts: Vec<Verdict> = objects.iter().map(|_| Verdict::Keep).collect();
    let mut winners: FxHashMap<(Box<str>, String), usize> = FxHashMap::default();
    for position in order {
        let object = &objects[position];
        let text = (!lost.contains(&object.source))
            .then(|| unique_key_value(&object.key.object, &object.value))
            .flatten();
        let Some(text) = text else {
            if !keeps_keyless(&object.key.object) {
                verdicts[position] = Verdict::Lost;
            }
            continue;
        };
        match winners.entry((object.key.object.clone(), text)) {
            Entry::Vacant(slot) => {
                slot.insert(position);
            }
            Entry::Occupied(slot) => {
                let key: Box<str> = slot.key().1.as_str().into();
                let winner = *slot.get();
                verdicts[position] = if merges(&object.key.object) {
                    Verdict::Merged { key, into: winner }
                } else {
                    Verdict::Conflict { key, kept: winner }
                };
            }
        }
    }
    let mut raised: FxHashMap<usize, (String, Vec<ObjectKey>)> = FxHashMap::default();
    for (position, verdict) in verdicts.iter().enumerate() {
        if let Verdict::Merged { into, .. } = verdict {
            let level = level_of(&objects[position].value).to_string();
            let entry = raised
                .entry(*into)
                .or_insert_with(|| (level_of(&objects[*into].value).to_string(), Vec::new()));
            if verbosity(&level) > verbosity(&entry.0) {
                entry.0 = level;
            }
            entry.1.push(objects[position].source.clone());
        }
    }
    let report = &mut outcome.report;
    for (winner, (level, merged)) in &raised {
        let object = &mut objects[*winner];
        let own = describe_original(originals, &object.source);
        let names: Vec<String> = merged.iter().map(ToString::to_string).collect();
        report.push(
            &object.source,
            MERGED_PROPERTY,
            Change::Transformed {
                transform: KEY_MERGE,
                detail: format!(
                    "kept for {} with the same unique key, level {level} (most verbose); it was {own}",
                    names.join(", ")
                ),
            },
        );
        if let Value::Object(map) = &mut object.value {
            map.insert(MERGED_PROPERTY.into(), Value::String(level.clone()));
        }
    }
    let mut reasons: Vec<Option<DropReason>> = Vec::with_capacity(verdicts.len());
    for (position, verdict) in verdicts.into_iter().enumerate() {
        let reason = match verdict {
            Verdict::Keep => None,
            Verdict::Lost => Some(DropReason::KeyLost),
            Verdict::Conflict { key, kept } => Some(DropReason::KeyConflict {
                key,
                kept: objects[kept].source.clone(),
            }),
            Verdict::Merged { key, into } => Some(DropReason::Merged {
                key,
                into: objects[into].source.clone(),
                original: describe_original(originals, &objects[position].source).into(),
            }),
        };
        reasons.push(reason);
    }
    let dropped = &mut outcome.dropped;
    let mut reasons = reasons.into_iter();
    objects.retain(|object| {
        let Some(reason) = reasons.next().flatten() else {
            return true;
        };
        report.push(
            &object.source,
            "",
            Change::Dropped {
                reason,
                value: None,
            },
        );
        dropped.push(object.source.clone());
        false
    });
}

pub(super) fn check(session: &Session, schema: &str, value: &Value) -> Vec<crate::report::Entry> {
    let mut report = Report::default();
    let key = ObjectKey::singleton(schema);
    let mut finalizer = Finalizer {
        session,
        report: &mut report,
        key: &key,
        path: Path::default(),
        enterprise_seen: false,
        store_lost: false,
        in_secret: false,
    };
    let mut value = value.clone();
    if finalizer.schema(schema, &mut value) == Flow::Remove && report.entries.is_empty() {
        report.push(
            &key,
            "",
            Change::Dropped {
                reason: DropReason::Invalid,
                value: None,
            },
        );
    }
    report.entries
}

impl Finalizer<'_, '_> {
    fn reason(&mut self, in_full_target: bool) -> DropReason {
        if in_full_target && self.session.direction == Direction::Forward {
            self.enterprise_seen = true;
            DropReason::Enterprise
        } else {
            DropReason::NotInTarget
        }
    }

    fn drop(&mut self, segment: Option<&str>, reason: DropReason, value: Option<Value>) {
        let value = if self.in_secret {
            value.map(|v| mask_all(&v))
        } else {
            value
        };
        let path = match segment {
            Some(segment) => self.path.child(segment),
            None => self.path.as_str().to_string(),
        };
        self.report
            .push(self.key, &path, Change::Dropped { reason, value });
    }

    fn object(&mut self, name: &str, value: &mut Value) -> Flow {
        let target = self.session.target;
        if target.object(name).is_none() {
            let reason = self.reason(self.session.target_full.object(name).is_some());
            self.drop(None, reason, None);
            return Flow::Remove;
        }
        self.schema(name, value)
    }

    fn schema(&mut self, name: &str, value: &mut Value) -> Flow {
        let session = self.session;
        let Some(def) = session.target.schema(name) else {
            return Flow::Keep;
        };
        let Value::Object(map) = value else {
            let shown = if name.starts_with("x:Secret") {
                Value::String("****".into())
            } else {
                value.clone()
            };
            self.drop(None, DropReason::Invalid, Some(shown));
            return Flow::Remove;
        };
        let fields = match def {
            SchemaDef::Single(fields) => fields,
            SchemaDef::Union(_) => {
                let Some(variant_name) = map.get(TYPE_KEY).and_then(Value::as_str) else {
                    self.drop(Some(TYPE_KEY), DropReason::Invalid, None);
                    return Flow::Remove;
                };
                match def.variant(variant_name) {
                    Some(variant) => match &variant.schema {
                        Some(fields) => fields,
                        None => {
                            let extra: Vec<String> =
                                map.keys().filter(|k| *k != TYPE_KEY).cloned().collect();
                            for name in extra {
                                if let Some(value) = map.remove(&name) {
                                    let shown = (!value.is_null())
                                        .then(|| mask_property(&name, None, &value));
                                    self.drop(Some(&name), DropReason::NotInTarget, shown);
                                }
                            }
                            return Flow::Keep;
                        }
                    },
                    None => {
                        let in_full = session
                            .target_full
                            .schema(name)
                            .and_then(|d| d.variant(variant_name))
                            .is_some();
                        let reason = self.reason(in_full);
                        if reason == DropReason::Enterprise
                            && self.path.as_str().is_empty()
                            && STORE_OBJECTS.contains(&name)
                        {
                            self.store_lost = true;
                        }
                        let shown = Some(Value::String(variant_name.into()));
                        self.drop(Some(TYPE_KEY), reason, shown);
                        return Flow::Remove;
                    }
                }
            }
        };
        self.fields(fields, map)
    }

    fn fields(&mut self, fields_name: &str, map: &mut Map<String, Value>) -> Flow {
        let session = self.session;
        let Some(fields) = session.target.fields(fields_name) else {
            return Flow::Keep;
        };
        let mut removed = Vec::new();
        for (name, value) in map.iter_mut() {
            if name == TYPE_KEY {
                continue;
            }
            let Some(prop) = fields.property(name) else {
                let in_full = session.target_full.property(fields_name, name).is_some();
                let reason = self.reason(in_full);
                let full_type = session
                    .target_full
                    .property(fields_name, name)
                    .or_else(|| {
                        (session.direction == Direction::Reverse)
                            .then(|| session.source.property(fields_name, name))
                            .flatten()
                    })
                    .map(|p| &p.ty);
                let shown = (!value.is_null()).then(|| mask_property(name, full_type, value));
                self.drop(Some(name), reason, shown);
                removed.push(name.clone());
                continue;
            };
            self.path.push(name);
            let outer_secret = self.in_secret;
            self.in_secret |= prop.ty.is_secret();
            let flow = if value.is_null() {
                if !prop.ty.nullable {
                    self.drop(None, DropReason::Invalid, None);
                    removed.push(name.clone());
                }
                Flow::Keep
            } else {
                self.value(&prop.ty, value)
            };
            self.in_secret = outer_secret;
            self.path.pop();
            if flow == Flow::Remove {
                if prop.ty.nullable {
                    *value = Value::Null;
                } else {
                    removed.push(name.clone());
                }
            }
        }
        for name in removed {
            map.remove(&name);
        }
        Flow::Keep
    }

    fn value(&mut self, ty: &TypeDef, value: &mut Value) -> Flow {
        match &ty.ty {
            Type::Number { format, min, max } => {
                if let Some(clamped) = clamp(*format, *min, *max, value) {
                    let from = std::mem::replace(value, clamped.clone());
                    self.report.push(
                        self.key,
                        self.path.as_str(),
                        Change::Clamped { from, to: clamped },
                    );
                }
                Flow::Keep
            }
            Type::Enum(name) => match value.as_str() {
                Some(v) if self.session.target.enum_has(name, v) => Flow::Keep,
                Some(v) => {
                    let in_full = self.session.target_full.enum_has(name, v);
                    let reason = self.reason(in_full);
                    self.drop(None, reason, Some(value.clone()));
                    Flow::Remove
                }
                None => Flow::Keep,
            },
            Type::Object(schema) => self.schema(schema, value),
            Type::ObjectList { schema, .. } => {
                let Value::Object(items) = value else {
                    return Flow::Keep;
                };
                let mut removed = Vec::new();
                for (index, item) in items.iter_mut() {
                    self.path.push(index);
                    if self.schema(schema, item) == Flow::Remove {
                        removed.push(index.clone());
                    }
                    self.path.pop();
                }
                if !removed.is_empty() {
                    for index in removed {
                        items.remove(&index);
                    }
                    compact_list(items);
                }
                Flow::Keep
            }
            Type::Set { class, .. } => {
                if let (Type::Enum(name), Value::Object(members)) = (&class.ty, &mut *value) {
                    self.enum_keys(name, members);
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
                    self.enum_keys(name, entries);
                }
                let mut removed = Vec::new();
                for (entry_key, entry) in entries.iter_mut() {
                    self.path.push(entry_key);
                    if !entry.is_null() && self.value(value_ty, entry) == Flow::Remove {
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

    fn enum_keys(&mut self, name: &str, members: &mut Map<String, Value>) {
        let target = self.session.target;
        let invalid: Vec<String> = members
            .keys()
            .filter(|m| !target.enum_has(name, m))
            .cloned()
            .collect();
        for member in invalid {
            members.remove(&member);
            let in_full = self.session.target_full.enum_has(name, &member);
            let reason = self.reason(in_full);
            self.drop(Some(&member), reason, None);
        }
    }
}

fn clamp(format: NumberFormat, min: Option<f64>, max: Option<f64>, value: &Value) -> Option<Value> {
    let current = value.as_f64()?;
    let unsigned = !matches!(format, NumberFormat::Float | NumberFormat::Integer);
    let min = if unsigned {
        Some(min.unwrap_or(0.0).max(0.0))
    } else {
        min
    };
    let bound = match (min, max) {
        (Some(min), _) if current < min => min,
        (_, Some(max)) if current > max => max,
        _ => return None,
    };
    let clamped = match format {
        NumberFormat::Float => Number::from_f64(bound).map(Value::Number)?,
        NumberFormat::Integer => Value::from(bound as i64),
        NumberFormat::Unsigned | NumberFormat::Duration | NumberFormat::Size => {
            Value::from(bound.max(0.0) as u64)
        }
    };
    Some(clamped)
}
