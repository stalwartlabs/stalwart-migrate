use std::io::Read;

use flate2::read::GzDecoder;
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

const REGISTRY_PREFIX: &str = "x:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Object,
    Singleton,
    View,
}

#[derive(Debug)]
pub struct ObjectDef {
    pub kind: ObjectKind,
    pub enterprise: bool,
    pub base: Option<Box<str>>,
}

#[derive(Debug)]
pub struct Variant {
    pub name: Box<str>,
    pub schema: Option<Box<str>>,
}

#[derive(Debug)]
pub enum SchemaDef {
    Single(Box<str>),
    Union(Box<[Variant]>),
}

impl SchemaDef {
    pub fn variant(&self, name: &str) -> Option<&Variant> {
        match self {
            SchemaDef::Union(variants) => variants.iter().find(|v| &*v.name == name),
            SchemaDef::Single(_) => None,
        }
    }

    pub fn marker_variant(&self) -> Option<&Variant> {
        match self {
            SchemaDef::Union(variants) => variants.iter().find(|v| v.schema.is_none()),
            SchemaDef::Single(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberFormat {
    Integer,
    Unsigned,
    Float,
    Duration,
    Size,
}

#[derive(Debug)]
pub enum Type {
    Boolean,
    Number {
        format: NumberFormat,
        min: Option<f64>,
        max: Option<f64>,
    },
    String {
        secret: bool,
    },
    Enum(Box<str>),
    Object(Box<str>),
    ObjectId(Box<str>),
    ObjectList {
        schema: Box<str>,
        min_items: Option<u64>,
    },
    Set {
        class: Box<TypeDef>,
        min_items: Option<u64>,
    },
    Map {
        key: Box<TypeDef>,
        value: Box<TypeDef>,
    },
    UtcDateTime,
    BlobId,
}

#[derive(Debug)]
pub struct TypeDef {
    pub ty: Type,
    pub nullable: bool,
}

impl TypeDef {
    pub fn is_secret(&self) -> bool {
        match &self.ty {
            Type::String { secret } => *secret,
            Type::Object(schema) => schema.starts_with("x:Secret"),
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct Property {
    pub ty: TypeDef,
    pub server_set: bool,
    pub enterprise: bool,
}

#[derive(Debug, Default)]
pub struct Fields {
    pub properties: FxHashMap<Box<str>, Property>,
    pub defaults: Map<String, Value>,
}

impl Fields {
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.get(name)
    }

    pub fn default_value(&self, name: &str) -> Option<&Value> {
        self.defaults.get(name)
    }
}

#[derive(Debug, Default)]
pub struct Schema {
    objects: FxHashMap<Box<str>, ObjectDef>,
    schemas: FxHashMap<Box<str>, SchemaDef>,
    fields: FxHashMap<Box<str>, Fields>,
    enums: FxHashMap<Box<str>, EnumDef>,
}

#[derive(Debug, Default)]
pub struct EnumDef {
    pub values: Box<[Box<str>]>,
    lookup: FxHashSet<Box<str>>,
}

impl Schema {
    pub fn from_gzip(file: &str, bytes: &[u8]) -> Result<Self> {
        let mut json = String::new();
        GzDecoder::new(bytes)
            .read_to_string(&mut json)
            .map_err(|source| Error::Io {
                path: file.into(),
                source,
            })?;
        Self::from_json(file, &json)
    }

    pub fn from_json(file: &str, json: &str) -> Result<Self> {
        let root: Value = serde_json::from_str(json).map_err(|source| Error::Json {
            file: file.into(),
            source,
        })?;
        let section = |name: &str| {
            root.get(name)
                .and_then(Value::as_object)
                .ok_or_else(|| Error::schema(file, format!("missing section {name}")))
        };

        let mut schema = Schema::default();
        for (name, def) in section("objects")? {
            let kind = match def.get("type").and_then(Value::as_str) {
                Some("object") => ObjectKind::Object,
                Some("singleton") => ObjectKind::Singleton,
                Some("view") => ObjectKind::View,
                other => {
                    return Err(Error::schema(
                        file,
                        format!("object {name}: type {other:?}"),
                    ));
                }
            };
            schema.objects.insert(
                name.as_str().into(),
                ObjectDef {
                    kind,
                    enterprise: flag(def, "enterprise"),
                    base: str_field(def, "objectName").map(Into::into),
                },
            );
        }
        for (name, def) in section("schemas")? {
            let parsed = match def.get("type").and_then(Value::as_str) {
                Some("single") => SchemaDef::Single(
                    str_field(def, "schemaName")
                        .ok_or_else(|| Error::schema(file, format!("schema {name}: schemaName")))?
                        .into(),
                ),
                Some("multiple") => SchemaDef::Union(
                    def.get("variants")
                        .and_then(Value::as_array)
                        .ok_or_else(|| Error::schema(file, format!("schema {name}: variants")))?
                        .iter()
                        .map(|variant| {
                            Ok(Variant {
                                name: str_field(variant, "name")
                                    .ok_or_else(|| {
                                        Error::schema(file, format!("schema {name}: variant name"))
                                    })?
                                    .into(),
                                schema: str_field(variant, "schemaName").map(Into::into),
                            })
                        })
                        .collect::<Result<_>>()?,
                ),
                other => {
                    return Err(Error::schema(
                        file,
                        format!("schema {name}: type {other:?}"),
                    ));
                }
            };
            schema.schemas.insert(name.as_str().into(), parsed);
        }
        for (name, def) in section("fields")? {
            let mut fields = Fields::default();
            if let Some(properties) = def.get("properties").and_then(Value::as_object) {
                fields.properties.reserve(properties.len());
                for (prop, prop_def) in properties {
                    let ty = prop_def
                        .get("type")
                        .ok_or_else(|| Error::schema(file, format!("{name}.{prop}: type")))
                        .and_then(|ty| parse_type(file, ty))?;
                    fields.properties.insert(
                        prop.as_str().into(),
                        Property {
                            ty,
                            server_set: str_field(prop_def, "update") == Some("serverSet"),
                            enterprise: flag(prop_def, "enterprise"),
                        },
                    );
                }
            }
            if let Some(Value::Object(defaults)) = def.get("defaults") {
                fields.defaults = defaults.clone();
            }
            schema.fields.insert(name.as_str().into(), fields);
        }
        for (name, values) in section("enums")? {
            let values: Box<[Box<str>]> = values
                .as_array()
                .ok_or_else(|| Error::schema(file, format!("enum {name}")))?
                .iter()
                .filter_map(|v| str_field(v, "name").map(Into::into))
                .collect();
            let lookup = values.iter().cloned().collect();
            schema
                .enums
                .insert(name.as_str().into(), EnumDef { values, lookup });
        }
        Ok(schema)
    }

    pub fn object(&self, name: &str) -> Option<&ObjectDef> {
        self.objects.get(name)
    }

    pub fn schema(&self, name: &str) -> Option<&SchemaDef> {
        self.schemas.get(name)
    }

    pub fn fields(&self, name: &str) -> Option<&Fields> {
        self.fields.get(name)
    }

    pub fn has_enum(&self, name: &str) -> bool {
        self.enums.contains_key(name)
    }

    pub fn enum_has(&self, name: &str, value: &str) -> bool {
        self.enums
            .get(name)
            .is_some_and(|def| def.lookup.contains(value))
    }

    pub fn property(&self, fields: &str, name: &str) -> Option<&Property> {
        self.fields(fields).and_then(|f| f.property(name))
    }

    pub fn enum_def(&self, name: &str) -> Option<&EnumDef> {
        self.enums.get(name)
    }

    pub fn objects(&self) -> impl Iterator<Item = (&str, &ObjectDef)> {
        self.objects.iter().map(|(k, v)| (&**k, v))
    }

    pub fn reference_fields(&self) -> Vec<(Box<str>, Box<str>)> {
        let mut out = Vec::new();
        let mut path = Vec::new();
        let mut visiting = Vec::new();
        for (name, def) in &self.objects {
            if def.kind != ObjectKind::View {
                self.schema_references(name, name, &mut path, &mut visiting, &mut out);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn schema_references<'s>(
        &'s self,
        object: &str,
        schema: &'s str,
        path: &mut Vec<&'s str>,
        visiting: &mut Vec<&'s str>,
        out: &mut Vec<(Box<str>, Box<str>)>,
    ) {
        if visiting.contains(&schema) {
            return;
        }
        let Some(def) = self.schemas.get(schema) else {
            return;
        };
        visiting.push(schema);
        let names: Vec<&str> = match def {
            SchemaDef::Single(fields) => vec![fields],
            SchemaDef::Union(variants) => variants
                .iter()
                .filter_map(|v| v.schema.as_deref())
                .collect(),
        };
        for fields in names {
            let Some(fields) = self.fields.get(fields) else {
                continue;
            };
            for (property, prop) in &fields.properties {
                path.push(property);
                self.type_references(object, &prop.ty, path, visiting, out);
                path.pop();
            }
        }
        visiting.pop();
    }

    fn type_references<'s>(
        &'s self,
        object: &str,
        ty: &'s TypeDef,
        path: &mut Vec<&'s str>,
        visiting: &mut Vec<&'s str>,
        out: &mut Vec<(Box<str>, Box<str>)>,
    ) {
        const ANY: &str = "*";
        match &ty.ty {
            Type::ObjectId(target) if self.reference_target(target).is_some() => {
                out.push((object.into(), path.join("/").into()));
            }
            Type::Object(schema) => self.schema_references(object, schema, path, visiting, out),
            Type::ObjectList { schema, .. } => {
                path.push(ANY);
                self.schema_references(object, schema, path, visiting, out);
                path.pop();
            }
            Type::Set { class, .. } => {
                path.push(ANY);
                self.type_references(object, class, path, visiting, out);
                path.pop();
            }
            Type::Map { key, value } => {
                path.push(ANY);
                self.type_references(object, key, path, visiting, out);
                self.type_references(object, value, path, visiting, out);
                path.pop();
            }
            _ => (),
        }
    }

    pub fn reference_target<'x>(&'x self, name: &'x str) -> Option<&'x str> {
        if !name.starts_with(REGISTRY_PREFIX) {
            return None;
        }
        match self.objects.get(name) {
            Some(ObjectDef {
                kind: ObjectKind::View,
                base: Some(base),
                ..
            }) => Some(base),
            _ => Some(name),
        }
    }
}

fn flag(def: &Value, name: &str) -> bool {
    def.get(name).and_then(Value::as_bool).unwrap_or(false)
}

fn str_field<'x>(def: &'x Value, name: &str) -> Option<&'x str> {
    def.get(name).and_then(Value::as_str)
}

fn parse_type(file: &str, def: &Value) -> Result<TypeDef> {
    let kind = str_field(def, "type").ok_or_else(|| Error::schema(file, "type without kind"))?;
    let name = |key: &str| {
        str_field(def, key)
            .map(Box::<str>::from)
            .ok_or_else(|| Error::schema(file, format!("{kind} without {key}")))
    };
    let min_items = def.get("minItems").and_then(Value::as_u64);
    let ty = match kind {
        "boolean" => Type::Boolean,
        "number" => Type::Number {
            format: match str_field(def, "format") {
                Some("integer") => NumberFormat::Integer,
                Some("unsignedInteger") => NumberFormat::Unsigned,
                Some("float") => NumberFormat::Float,
                Some("duration") => NumberFormat::Duration,
                Some("size") => NumberFormat::Size,
                other => return Err(Error::schema(file, format!("number format {other:?}"))),
            },
            min: def.get("min").and_then(Value::as_f64),
            max: def.get("max").and_then(Value::as_f64),
        },
        "string" => Type::String {
            secret: matches!(str_field(def, "format"), Some("secret" | "secretText")),
        },
        "enum" => Type::Enum(name("enumName")?),
        "object" => Type::Object(name("objectName")?),
        "objectId" => Type::ObjectId(name("objectName")?),
        "objectList" => Type::ObjectList {
            schema: name("objectName")?,
            min_items,
        },
        "set" => Type::Set {
            class: Box::new(parse_type(
                file,
                def.get("class")
                    .ok_or_else(|| Error::schema(file, "set without class"))?,
            )?),
            min_items,
        },
        "map" => Type::Map {
            key: Box::new(parse_type(
                file,
                def.get("keyClass")
                    .ok_or_else(|| Error::schema(file, "map without keyClass"))?,
            )?),
            value: Box::new(parse_type(
                file,
                def.get("valueClass")
                    .ok_or_else(|| Error::schema(file, "map without valueClass"))?,
            )?),
        },
        "utcDateTime" => Type::UtcDateTime,
        "blobId" => Type::BlobId,
        other => return Err(Error::schema(file, format!("unknown type {other}"))),
    };
    Ok(TypeDef {
        ty,
        nullable: flag(def, "nullable"),
    })
}
