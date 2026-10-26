/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mapping::schema::{ObjectKind, Schema, SchemaDef, Type, TypeDef};
use rustc_hash::{FxHashMap, FxHashSet};

const OBJECT_PREFIX: &str = "x:";

fn bare(object: &str) -> &str {
    object.strip_prefix(OBJECT_PREFIX).unwrap_or(object)
}

pub(crate) struct ReferenceTargets(FxHashMap<Box<str>, Box<[Box<str>]>>);

impl ReferenceTargets {
    pub(crate) fn of(schema: &Schema) -> Self {
        let mut objects = FxHashMap::default();
        let mut targets = Vec::new();
        let mut visiting = Vec::new();
        for (name, def) in schema.objects() {
            if def.kind == ObjectKind::View {
                continue;
            }
            targets.clear();
            walk_schema(schema, name, &mut visiting, &mut targets);
            targets.sort_unstable();
            targets.dedup();
            objects.insert(
                bare(name).into(),
                targets.iter().map(|target| bare(target).into()).collect(),
            );
        }
        ReferenceTargets(objects)
    }

    pub(crate) fn targets(&self, object: &str) -> Option<&[Box<str>]> {
        self.0.get(bare(object)).map(AsRef::as_ref)
    }

    pub(crate) fn unlinked<'k>(
        &self,
        objects: impl Iterator<Item = &'k str>,
    ) -> FxHashSet<Box<str>> {
        let objects: FxHashSet<&str> = objects.collect();
        let deleted: FxHashSet<&str> = objects.iter().map(|object| bare(object)).collect();
        objects
            .into_iter()
            .filter(|object| {
                self.targets(object).is_some_and(|targets| {
                    !targets.iter().any(|target| deleted.contains(&**target))
                })
            })
            .map(Into::into)
            .collect()
    }
}

fn walk_schema<'s>(
    schema: &'s Schema,
    name: &'s str,
    visiting: &mut Vec<&'s str>,
    targets: &mut Vec<&'s str>,
) {
    if visiting.contains(&name) {
        return;
    }
    let Some(def) = schema.schema(name) else {
        return;
    };
    visiting.push(name);
    let mut walk_fields = |fields: &'s str, visiting: &mut Vec<&'s str>| {
        if let Some(fields) = schema.fields(fields) {
            for property in fields.properties.values() {
                walk_type(schema, &property.ty, visiting, targets);
            }
        }
    };
    match def {
        SchemaDef::Single(fields) => walk_fields(fields, visiting),
        SchemaDef::Union(variants) => {
            for fields in variants
                .iter()
                .filter_map(|variant| variant.schema.as_deref())
            {
                walk_fields(fields, visiting);
            }
        }
    }
    visiting.pop();
}

fn walk_type<'s>(
    schema: &'s Schema,
    ty: &'s TypeDef,
    visiting: &mut Vec<&'s str>,
    targets: &mut Vec<&'s str>,
) {
    match &ty.ty {
        Type::ObjectId(target) => {
            if let Some(target) = schema.reference_target(target) {
                targets.push(target);
            }
        }
        Type::Object(name) | Type::ObjectList { schema: name, .. } => {
            walk_schema(schema, name, visiting, targets)
        }
        Type::Set { class, .. } => walk_type(schema, class, visiting, targets),
        Type::Map { key, value } => {
            walk_type(schema, key, visiting, targets);
            walk_type(schema, value, visiting, targets);
        }
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use mapping::{Mapping, SchemaVersion};

    use super::*;

    // The objects with reference targets are exactly the objects the mapping lists reference fields for, in both schemas.
    #[test]
    fn referencing_objects_match_the_mapping_reference_fields() {
        let mapping = Mapping::embedded().expect("mapping");
        for version in [SchemaVersion::V1, SchemaVersion::V016] {
            let targets = ReferenceTargets::of(mapping.schema(version));
            let mut walked: Vec<&str> = targets
                .0
                .iter()
                .filter(|(_, targets)| !targets.is_empty())
                .map(|(object, _)| &**object)
                .collect();
            walked.sort_unstable();
            let fields = mapping.reference_fields(version);
            let mut listed: Vec<&str> = fields.iter().map(|(object, _)| bare(object)).collect();
            listed.sort_unstable();
            listed.dedup();
            assert_eq!(walked, listed, "{version:?}");
            assert!(walked.len() > 10, "{version:?}");
        }
    }
}
