use std::{cmp::Reverse, collections::BinaryHeap};

use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{Map, Value};

use super::{
    DeferredUpdate, Outcome, Owners, Principals, Session, TargetObject, path::Path, walk::TYPE_KEY,
};
use crate::{
    ids::{Instance, JmapId, ObjectKey},
    report::{Change, DropReason, Report},
    schema::{Fields, Schema, SchemaDef, Type, TypeDef},
};

const WRITE_RANK: &[&str] = &[
    "x:Tenant",
    "x:Domain",
    "x:Directory",
    "x:Role",
    "x:Account",
    "x:MailingList",
];

const MARKER_FALLBACK: &[&str] = &["x:DnsManagement", "x:CertificateManagement", "x:SpamAi"];

type Present = FxHashMap<Box<str>, FxHashSet<u64>>;
type Ready = Reverse<(usize, Box<str>, Instance, usize)>;

struct Fixer<'s, 'r> {
    schema: &'s Schema,
    present: &'s Present,
    owners: &'s Owners,
    orphan: Option<ObjectKey>,
    report: &'r mut Report,
    key: &'r ObjectKey,
    path: Path,
    pending: Vec<(String, ObjectKey)>,
}

#[derive(PartialEq, Eq)]
enum Fix {
    Keep,
    Remove,
}

pub(super) fn fix_dangling(session: &Session, outcome: &mut Outcome) {
    let mut present = Present::default();
    for object in &outcome.objects {
        if let Instance::Id(id) = object.key.instance {
            present
                .entry(object.key.object.clone())
                .or_default()
                .insert(id);
        }
    }
    let mut orphans: Vec<ObjectKey> = Vec::new();
    for object in &mut outcome.objects {
        let mut fixer = Fixer {
            schema: session.target,
            present: &present,
            owners: &session.owners,
            orphan: None,
            report: &mut outcome.report,
            key: &object.source,
            path: Path::default(),
            pending: Vec::new(),
        };
        if fixer.schema(&object.key.object, &mut object.value) == Fix::Remove {
            let pending = std::mem::take(&mut fixer.pending);
            if let Some(account) = fixer.orphan.take() {
                fixer.report.push(
                    fixer.key,
                    "",
                    Change::Dropped {
                        reason: DropReason::Orphaned { account },
                        value: None,
                    },
                );
                orphans.push(object.source.clone());
                continue;
            }
            for (path, target) in pending {
                fixer
                    .report
                    .push(fixer.key, &path, Change::Dangling { target });
            }
        }
    }
    if !orphans.is_empty() {
        outcome
            .objects
            .retain(|object| !orphans.contains(&object.source));
        outcome.dropped.extend(orphans);
    }
}

const OWNER_REFERENCE: &str = "accountId";

enum Owner {
    Satisfied,
    Orphan(ObjectKey),
    Missing(ObjectKey),
}

impl Fixer<'_, '_> {
    fn owner(&self, ty: &TypeDef, value: &Value) -> Owner {
        let (Type::ObjectId(target), Some(id)) = (&ty.ty, value.as_str()) else {
            return Owner::Satisfied;
        };
        let Some(missing) = self.missing(target, id) else {
            return Owner::Satisfied;
        };
        let Instance::Id(id) = missing.instance else {
            return Owner::Missing(missing);
        };
        match self.owners {
            Owners::Listed { accounts, .. } if !accounts.contains(&id) => Owner::Orphan(missing),
            Owners::Listed {
                principals: Principals::Excluded,
                ..
            } => Owner::Satisfied,
            Owners::Listed { .. } | Owners::Unknown => Owner::Missing(missing),
        }
    }

    fn absorb(&mut self) {
        for (path, target) in std::mem::take(&mut self.pending) {
            self.report
                .push(self.key, &path, Change::ReferenceCleared { target });
        }
    }

    fn missing(&self, object: &str, id: &str) -> Option<ObjectKey> {
        let object = self.schema.reference_target(object)?;
        let id = JmapId::parse(id)?.0;
        let found = self
            .present
            .get(object)
            .is_some_and(|ids| ids.contains(&id));
        (!found).then(|| ObjectKey::with_id(object, id))
    }

    fn schema(&mut self, name: &str, value: &mut Value) -> Fix {
        let schema = self.schema;
        let Some(def) = schema.schema(name) else {
            return Fix::Keep;
        };
        let Value::Object(map) = value else {
            return Fix::Keep;
        };
        let fields = match def {
            SchemaDef::Single(fields) => fields,
            SchemaDef::Union(_) => {
                let Some(variant) = map
                    .get(TYPE_KEY)
                    .and_then(Value::as_str)
                    .and_then(|v| def.variant(v))
                else {
                    return Fix::Keep;
                };
                let Some(fields) = &variant.schema else {
                    return Fix::Keep;
                };
                fields
            }
        };
        if self.fields(fields, map) == Fix::Keep {
            return Fix::Keep;
        }
        match def
            .marker_variant()
            .filter(|_| MARKER_FALLBACK.contains(&name))
        {
            Some(marker) => {
                let mut replacement = Map::with_capacity(1);
                replacement.insert(TYPE_KEY.into(), Value::String(marker.name.to_string()));
                *map = replacement;
                self.absorb();
                Fix::Keep
            }
            None => Fix::Remove,
        }
    }

    fn fields(&mut self, fields_name: &str, map: &mut Map<String, Value>) -> Fix {
        let schema = self.schema;
        let Some(fields) = schema.fields(fields_name) else {
            return Fix::Keep;
        };
        let top = self.path.as_str().is_empty();
        for (name, value) in map.iter_mut() {
            let Some(prop) = fields.property(name) else {
                continue;
            };
            if top && name == OWNER_REFERENCE {
                match self.owner(&prop.ty, value) {
                    Owner::Satisfied => continue,
                    Owner::Orphan(account) => {
                        self.orphan = Some(account);
                        return Fix::Remove;
                    }
                    Owner::Missing(account) => {
                        self.pending.push((OWNER_REFERENCE.to_string(), account));
                        return Fix::Remove;
                    }
                }
            }
            self.path.push(name);
            let fix = self.value(&prop.ty, value);
            self.path.pop();
            if fix == Fix::Remove {
                if prop.ty.nullable {
                    *value = Value::Null;
                    self.absorb();
                } else {
                    return Fix::Remove;
                }
            }
        }
        Fix::Keep
    }

    fn value(&mut self, ty: &TypeDef, value: &mut Value) -> Fix {
        match &ty.ty {
            Type::ObjectId(target) => {
                if let Some(missing) = value.as_str().and_then(|id| self.missing(target, id)) {
                    self.pending.push((self.path.as_str().to_string(), missing));
                    return Fix::Remove;
                }
                Fix::Keep
            }
            Type::Set { class, .. } => {
                if let (Type::ObjectId(target), Value::Object(members)) = (&class.ty, &mut *value) {
                    self.remove_missing_keys(target, members);
                }
                Fix::Keep
            }
            Type::Map {
                key,
                value: value_ty,
            } => {
                let Value::Object(entries) = value else {
                    return Fix::Keep;
                };
                if let Type::ObjectId(target) = &key.ty {
                    self.remove_missing_keys(target, entries);
                }
                let mut removed = Vec::new();
                for (entry_key, entry) in entries.iter_mut() {
                    self.path.push(entry_key);
                    if self.value(value_ty, entry) == Fix::Remove {
                        removed.push(entry_key.clone());
                    }
                    self.path.pop();
                }
                if !removed.is_empty() {
                    for entry_key in removed {
                        entries.remove(&entry_key);
                    }
                    self.absorb();
                }
                Fix::Keep
            }
            Type::Object(schema) => self.schema(schema, value),
            Type::ObjectList { schema, min_items } => {
                let Value::Object(items) = value else {
                    return Fix::Keep;
                };
                let mut removed = Vec::new();
                for (index, item) in items.iter_mut() {
                    self.path.push(index);
                    if self.schema(schema, item) == Fix::Remove {
                        removed.push(index.clone());
                    }
                    self.path.pop();
                }
                if removed.is_empty() {
                    return Fix::Keep;
                }
                for index in removed {
                    items.remove(&index);
                }
                if min_items.is_some_and(|min| (items.len() as u64) < min) {
                    Fix::Remove
                } else {
                    self.absorb();
                    Fix::Keep
                }
            }
            _ => Fix::Keep,
        }
    }

    fn remove_missing_keys(&mut self, target: &str, members: &mut Map<String, Value>) {
        let missing: Vec<(String, ObjectKey)> = members
            .keys()
            .filter_map(|k| self.missing(target, k).map(|m| (k.clone(), m)))
            .collect();
        for (member, target_key) in missing {
            members.remove(&member);
            let path = self.path.child(&member);
            self.report.push(
                self.key,
                &path,
                Change::ReferenceCleared { target: target_key },
            );
        }
    }
}

struct CycleBreak {
    candidate: usize,
    properties: Vec<String>,
    later: FxHashSet<(Box<str>, u64)>,
}

struct Edge<'v> {
    from: usize,
    to: usize,
    property: &'v str,
    active: bool,
}

fn cyclic_nodes(written: &[bool], outgoing: &[Vec<usize>], edges: &[Edge<'_>]) -> Vec<bool> {
    const UNVISITED: usize = usize::MAX;
    let n = written.len();
    let mut index = vec![UNVISITED; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut cyclic = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut call: Vec<(usize, usize)> = Vec::new();
    let mut counter = 0usize;
    for root in 0..n {
        if written[root] || index[root] != UNVISITED {
            continue;
        }
        index[root] = counter;
        low[root] = counter;
        counter += 1;
        stack.push(root);
        on_stack[root] = true;
        call.push((root, 0));
        while let Some(frame) = call.last_mut() {
            let v = frame.0;
            match outgoing[v].get(frame.1) {
                Some(&e) => {
                    frame.1 += 1;
                    let edge = &edges[e];
                    let w = edge.to;
                    if !edge.active || written[w] {
                        continue;
                    }
                    if index[w] == UNVISITED {
                        index[w] = counter;
                        low[w] = counter;
                        counter += 1;
                        stack.push(w);
                        on_stack[w] = true;
                        call.push((w, 0));
                    } else if on_stack[w] {
                        low[v] = low[v].min(index[w]);
                    }
                }
                None => {
                    call.pop();
                    if let Some(&(parent, _)) = call.last() {
                        low[parent] = low[parent].min(low[v]);
                    }
                    if low[v] == index[v] {
                        let start = stack.iter().rposition(|w| *w == v).unwrap_or(0);
                        let component = stack.split_off(start);
                        for w in &component {
                            on_stack[*w] = false;
                        }
                        if component.len() > 1 {
                            for w in component {
                                cyclic[w] = true;
                            }
                        }
                    }
                }
            }
        }
    }
    cyclic
}

fn top_fields<'s>(schema: &'s Schema, object: &str, value: &Value) -> Option<&'s Fields> {
    let def = schema.schema(object)?;
    let name = match def {
        SchemaDef::Single(fields) => fields,
        SchemaDef::Union(_) => value
            .get(TYPE_KEY)
            .and_then(Value::as_str)
            .and_then(|v| def.variant(v))
            .and_then(|v| v.schema.as_ref())?,
    };
    schema.fields(name)
}

fn placeholder(
    schema: &Schema,
    ty: &TypeDef,
    value: &Value,
    pending: &FxHashSet<(&str, u64)>,
) -> Option<Value> {
    if ty.nullable {
        return Some(Value::Null);
    }
    let pending_key = |target: &str, id: &str| {
        let target = schema.reference_target(target);
        let id = JmapId::parse(id);
        matches!((target, id), (Some(t), Some(id)) if pending.contains(&(t, id.0)))
    };
    match (&ty.ty, value) {
        (Type::Set { class, .. }, Value::Object(members)) => match &class.ty {
            Type::ObjectId(target) => Some(Value::Object(
                members
                    .iter()
                    .filter(|(k, _)| !pending_key(target, k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )),
            _ => None,
        },
        (Type::Map { key, .. }, Value::Object(entries)) => match &key.ty {
            Type::ObjectId(target) => Some(Value::Object(
                entries
                    .iter()
                    .filter(|(k, _)| !pending_key(target, k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            )),
            _ => None,
        },
        (Type::Object(name), _) => {
            schema
                .schema(name)
                .and_then(SchemaDef::marker_variant)
                .map(|marker| {
                    let mut map = Map::with_capacity(1);
                    map.insert(TYPE_KEY.into(), Value::String(marker.name.to_string()));
                    Value::Object(map)
                })
        }
        _ => None,
    }
}

pub(super) fn sort_for_writing(schema: &Schema, outcome: &mut Outcome) {
    let mut objects = std::mem::take(&mut outcome.objects);
    let mut deferred = Vec::new();
    let order = {
        let index: FxHashMap<(&str, u64), usize> = objects
            .iter()
            .enumerate()
            .filter_map(|(i, o)| match o.key.instance {
                Instance::Id(id) => Some(((&*o.key.object, id), i)),
                _ => None,
            })
            .collect();
        let mut edges: Vec<Edge> = Vec::new();
        let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); objects.len()];
        let mut incoming: Vec<Vec<usize>> = vec![Vec::new(); objects.len()];
        let mut blockers = vec![0usize; objects.len()];
        let mut refs = Vec::new();
        for (i, object) in objects.iter().enumerate() {
            let (Some(fields), Value::Object(map)) = (
                top_fields(schema, &object.key.object, &object.value),
                &object.value,
            ) else {
                continue;
            };
            for (property, value) in map {
                let Some(prop) = fields.property(property) else {
                    continue;
                };
                refs.clear();
                collect_value(schema, &prop.ty, value, &mut refs);
                refs.sort_unstable();
                refs.dedup();
                for (target, id) in &refs {
                    if let Some(&j) = index.get(&(*target, *id))
                        && j != i
                    {
                        let edge = edges.len();
                        edges.push(Edge {
                            from: i,
                            to: j,
                            property,
                            active: true,
                        });
                        outgoing[i].push(edge);
                        incoming[j].push(edge);
                        blockers[i] += 1;
                    }
                }
            }
        }
        let rank = |o: &TargetObject| {
            let rank = WRITE_RANK
                .iter()
                .position(|r| *r == &*o.key.object)
                .unwrap_or(WRITE_RANK.len());
            (rank, o.key.object.clone(), o.key.instance.clone())
        };
        let mut ready: BinaryHeap<Ready> = blockers
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == 0)
            .map(|(i, _)| {
                let (r, o, inst) = rank(&objects[i]);
                Reverse((r, o, inst, i))
            })
            .collect();
        let mut written = vec![false; objects.len()];
        let mut order = Vec::with_capacity(objects.len());
        let mut breaks: Vec<(usize, Vec<&str>)> = Vec::new();
        while order.len() < objects.len() {
            if let Some(Reverse((_, _, _, i))) = ready.pop() {
                written[i] = true;
                order.push(i);
                for &e in &incoming[i] {
                    if edges[e].active {
                        edges[e].active = false;
                        let from = edges[e].from;
                        blockers[from] -= 1;
                        if blockers[from] == 0 {
                            let (r, o, inst) = rank(&objects[from]);
                            ready.push(Reverse((r, o, inst, from)));
                        }
                    }
                }
                continue;
            }
            let cyclic = cyclic_nodes(&written, &outgoing, &edges);
            let Some(candidate) = (0..objects.len())
                .filter(|i| cyclic[*i])
                .min_by_key(|i| rank(&objects[*i]))
                .or_else(|| {
                    (0..objects.len())
                        .filter(|i| !written[*i] && blockers[*i] > 0)
                        .min_by_key(|i| rank(&objects[*i]))
                })
            else {
                break;
            };
            let mut properties: Vec<&str> = Vec::new();
            for &e in &outgoing[candidate] {
                if edges[e].active {
                    edges[e].active = false;
                    blockers[candidate] -= 1;
                    if !properties.contains(&edges[e].property) {
                        properties.push(edges[e].property);
                    }
                }
            }
            breaks.push((candidate, properties));
            let (r, o, inst) = rank(&objects[candidate]);
            ready.push(Reverse((r, o, inst, candidate)));
        }
        let breaks: Vec<CycleBreak> = breaks
            .into_iter()
            .map(|(candidate, properties)| {
                let position = order
                    .iter()
                    .position(|o| *o == candidate)
                    .unwrap_or(order.len());
                let later: FxHashSet<(Box<str>, u64)> = order
                    .iter()
                    .skip(position + 1)
                    .filter_map(|i| match objects[*i].key.instance {
                        Instance::Id(id) => Some((objects[*i].key.object.clone(), id)),
                        _ => None,
                    })
                    .collect();
                CycleBreak {
                    candidate,
                    properties: properties.into_iter().map(str::to_string).collect(),
                    later,
                }
            })
            .collect();
        for CycleBreak {
            candidate,
            properties,
            later,
        } in breaks
        {
            let pending: FxHashSet<(&str, u64)> = later.iter().map(|(o, id)| (&**o, *id)).collect();
            let object = &mut objects[candidate];
            let fields = top_fields(schema, &object.key.object, &object.value);
            let mut original = Map::new();
            for property in properties {
                let Value::Object(map) = &mut object.value else {
                    break;
                };
                let Some(current) = map.get(&property) else {
                    continue;
                };
                let replacement = fields
                    .and_then(|f| f.property(&property))
                    .and_then(|p| placeholder(schema, &p.ty, current, &pending));
                match replacement {
                    Some(replacement) => {
                        if let Some(value) = map.insert(property.clone(), replacement) {
                            original.insert(property.clone(), value);
                        }
                        outcome
                            .report
                            .push(&object.source, &property, Change::ReferenceDeferred);
                    }
                    None => outcome
                        .report
                        .push(&object.source, &property, Change::ReferenceCycle),
                }
            }
            if !original.is_empty() {
                deferred.push(DeferredUpdate {
                    source: object.source.clone(),
                    key: object.key.clone(),
                    properties: original,
                });
            }
        }
        order
    };
    let mut slots: Vec<Option<TargetObject>> = objects.into_iter().map(Some).collect();
    outcome.objects = order
        .into_iter()
        .filter_map(|i| slots.get_mut(i).and_then(Option::take))
        .collect();
    outcome.deferred = deferred;
}

pub(crate) fn collect_schema<'s>(
    schema: &'s Schema,
    name: &str,
    value: &Value,
    refs: &mut Vec<(&'s str, u64)>,
) {
    let (Some(def), Value::Object(map)) = (schema.schema(name), value) else {
        return;
    };
    let fields = match def {
        SchemaDef::Single(fields) => Some(fields),
        SchemaDef::Union(_) => map
            .get(TYPE_KEY)
            .and_then(Value::as_str)
            .and_then(|v| def.variant(v))
            .and_then(|v| v.schema.as_ref()),
    };
    let Some(fields) = fields.and_then(|f| schema.fields(f)) else {
        return;
    };
    for (name, value) in map {
        if let Some(prop) = fields.property(name) {
            collect_value(schema, &prop.ty, value, refs);
        }
    }
}

fn collect_value<'s>(
    schema: &'s Schema,
    ty: &'s TypeDef,
    value: &Value,
    refs: &mut Vec<(&'s str, u64)>,
) {
    let push = |refs: &mut Vec<(&'s str, u64)>, target: &'s str, id: &str| {
        if let (Some(target), Some(id)) = (schema.reference_target(target), JmapId::parse(id)) {
            refs.push((target, id.0));
        }
    };
    match (&ty.ty, value) {
        (Type::ObjectId(target), Value::String(id)) => push(refs, target, id),
        (Type::Set { class, .. }, Value::Object(members)) => {
            if let Type::ObjectId(target) = &class.ty {
                members.keys().for_each(|id| push(refs, target, id));
            }
        }
        (
            Type::Map {
                key,
                value: value_ty,
            },
            Value::Object(entries),
        ) => {
            if let Type::ObjectId(target) = &key.ty {
                entries.keys().for_each(|id| push(refs, target, id));
            }
            for entry in entries.values() {
                collect_value(schema, value_ty, entry, refs);
            }
        }
        (Type::Object(name), _) => collect_schema(schema, name, value, refs),
        (Type::ObjectList { schema: name, .. }, Value::Object(items)) => {
            for item in items.values() {
                collect_schema(schema, name, item, refs);
            }
        }
        _ => (),
    }
}
