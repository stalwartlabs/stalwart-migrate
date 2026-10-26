use serde_json::{Map, Value, json};

use crate::{
    Answers, Change, Direction, DropReason, Mapping, ObjectKey, Options, SourceObject,
    ToolQuestions,
    schema::{ObjectKind, Schema, SchemaDef, Type, TypeDef},
};

const MAX_DEPTH: usize = 6;

fn sample_value(schema: &Schema, ty: &TypeDef, depth: usize) -> Value {
    match &ty.ty {
        Type::Boolean => Value::Bool(true),
        Type::Number { min, .. } => min.map(|m| json!(m.max(1.0) as u64)).unwrap_or(json!(1)),
        Type::String { .. } => json!("sample"),
        Type::Enum(name) => schema
            .enum_def(name)
            .and_then(|d| d.values.last())
            .map(|v| Value::String(v.to_string()))
            .unwrap_or(Value::Null),
        Type::Object(name) if depth < MAX_DEPTH => sample_object(schema, name, None, depth + 1),
        Type::ObjectList { schema: name, .. } if depth < MAX_DEPTH => {
            json!({"0": sample_object(schema, name, None, depth + 1)})
        }
        Type::ObjectId(_) => json!("b"),
        Type::UtcDateTime => json!("2026-01-01T00:00:00Z"),
        _ => Value::Object(Map::new()),
    }
}

fn sample_object(schema: &Schema, name: &str, variant: Option<&str>, depth: usize) -> Value {
    let mut map = Map::new();
    let fields = match schema.schema(name) {
        Some(SchemaDef::Single(fields)) => Some(&**fields),
        Some(def @ SchemaDef::Union(variants)) => {
            let chosen = variant
                .and_then(|v| def.variant(v))
                .or_else(|| variants.iter().find(|v| v.schema.is_some()))
                .or_else(|| variants.first());
            match chosen {
                Some(v) => {
                    map.insert("@type".into(), Value::String(v.name.to_string()));
                    v.schema.as_deref()
                }
                None => None,
            }
        }
        None => None,
    };
    if let Some(fields) = fields.and_then(|f| schema.fields(f)) {
        for (prop, def) in &fields.properties {
            if def.server_set {
                continue;
            }
            let value = fields
                .default_value(prop)
                .filter(|_| !matches!(def.ty.ty, Type::Object(_)))
                .cloned()
                .unwrap_or_else(|| sample_value(schema, &def.ty, depth));
            map.insert(prop.to_string(), value);
        }
    }
    Value::Object(map)
}

#[test]
fn every_v016_object_converts_without_unmapped_names() {
    let mapping = Mapping::embedded().expect("embedded mapping");
    let answers = Answers::default();
    let options = Options {
        tool_questions: ToolQuestions::Skip,
        ..Options::default()
    };
    let session = mapping.session(Direction::Forward, &answers, options);
    let mut inputs = Vec::new();
    let mut objects: Vec<(&str, ObjectKind)> = mapping
        .v016
        .objects()
        .filter(|(name, def)| name.starts_with("x:") && def.kind != ObjectKind::View)
        .map(|(name, def)| (name, def.kind))
        .collect();
    objects.sort_unstable_by_key(|(name, _)| *name);
    let mut next_id = 1u64;
    for (name, kind) in objects {
        let variants: Vec<Option<&str>> = match mapping.v016.schema(name) {
            Some(SchemaDef::Union(variants)) => variants.iter().map(|v| Some(&*v.name)).collect(),
            _ => vec![None],
        };
        for variant in variants {
            let key = match kind {
                ObjectKind::Singleton => ObjectKey::singleton(name),
                _ => {
                    next_id += 1;
                    ObjectKey::with_id(name, next_id)
                }
            };
            if kind == ObjectKind::Singleton && inputs.iter().any(|i: &SourceObject| i.key == key) {
                continue;
            }
            inputs.push(SourceObject {
                key,
                value: sample_object(&mapping.v016, name, variant, 0),
            });
        }
    }
    let count = inputs.len();
    let outcome = session.convert_all(inputs);
    let unmapped: Vec<String> = outcome
        .report
        .entries
        .iter()
        .filter(|e| {
            matches!(
                e.change,
                Change::Unknown
                    | Change::Dropped {
                        reason: DropReason::NotInTarget,
                        ..
                    }
            )
        })
        .map(ToString::to_string)
        .collect();
    assert!(count > 200, "only {count} sample objects");
    assert!(
        unmapped.is_empty(),
        "{} unmapped:\n{}",
        unmapped.len(),
        unmapped.join("\n")
    );
}
