pub mod answers;
#[cfg(test)]
mod coverage_tests;
mod engine;
pub mod error;
pub mod ids;
pub mod prompts;
pub mod report;
pub mod rules;
pub mod schema;
pub mod transform;

use std::{borrow::Cow, path::Path};

use rustc_hash::FxHashSet;
use serde_json::Value;

pub use answers::{Answer, AnswerIssue, Answers};
pub use engine::{
    DeferredUpdate, DeletePlan, Direction, Edition, Normalize, Options, Outcome, Owners,
    Principals, Session, Singletons, SourceObject, TargetObject, ToolQuestions, unique_key,
    unique_key_value,
};
pub use error::{Error, Result};
pub use ids::{Instance, JmapId, ObjectKey};
pub use prompts::{Catalogue, PromptId};
pub use report::{Change, DropReason, Entry, Level, Question, Report};

use crate::{prompts::Catalogue as PromptCatalogue, rules::RuleSet, schema::Schema};

const V016_SCHEMA: &str = "schema/v0.16.27.json.gz";
const V1_SCHEMA: &str = "schema/v1.json.gz";
const V1_OSS_SCHEMA: &str = "schema/v1_oss.json.gz";
const RULES: &str = "v016_to_v1.toml";
const NORMALIZE: &str = "normalize_016x.toml";
const PROMPTS: &str = "prompts.toml";
const OBJECT_PREFIX: &str = "x:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaVersion {
    V016,
    V1,
}

pub struct Mapping {
    pub(crate) v016: Schema,
    pub(crate) v1: Schema,
    pub(crate) v1_oss: Schema,
    pub(crate) forward: RuleSet,
    pub(crate) reverse: RuleSet,
    pub(crate) normalize: RuleSet,
    pub(crate) catalogue: PromptCatalogue,
    pub(crate) pin_singletons: Box<[Box<str>]>,
}

struct Sources<'x> {
    v016: &'x [u8],
    v1: &'x [u8],
    v1_oss: &'x [u8],
    rules: &'x str,
    normalize: &'x str,
    prompts: &'x str,
}

impl Mapping {
    pub fn embedded() -> Result<Self> {
        Self::from_sources(Sources {
            v016: include_bytes!("../../../mapping/schema/v0.16.27.json.gz"),
            v1: include_bytes!("../../../mapping/schema/v1.json.gz"),
            v1_oss: include_bytes!("../../../mapping/schema/v1_oss.json.gz"),
            rules: include_str!("../../../mapping/v016_to_v1.toml"),
            normalize: include_str!("../../../mapping/normalize_016x.toml"),
            prompts: include_str!("../../../mapping/prompts.toml"),
        })
    }

    pub fn load(dir: impl AsRef<Path>) -> Result<Self> {
        Self::load_inner(dir.as_ref())
    }

    fn load_inner(dir: &Path) -> Result<Self> {
        let read = |name: &str| {
            std::fs::read(dir.join(name)).map_err(|source| Error::Io {
                path: dir.join(name).display().to_string().into(),
                source,
            })
        };
        let text = |name: &str| {
            read(name).and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| Error::schema(name, "not UTF-8"))
            })
        };
        let (v016, v1, v1_oss) = (read(V016_SCHEMA)?, read(V1_SCHEMA)?, read(V1_OSS_SCHEMA)?);
        let (rules, normalize, prompts) = (text(RULES)?, text(NORMALIZE)?, text(PROMPTS)?);
        Self::from_sources(Sources {
            v016: &v016,
            v1: &v1,
            v1_oss: &v1_oss,
            rules: &rules,
            normalize: &normalize,
            prompts: &prompts,
        })
    }

    fn from_sources(sources: Sources) -> Result<Self> {
        let v016 = Schema::from_gzip(V016_SCHEMA, sources.v016)?;
        let v1 = Schema::from_gzip(V1_SCHEMA, sources.v1)?;
        let v1_oss = Schema::from_gzip(V1_OSS_SCHEMA, sources.v1_oss)?;
        let forward = RuleSet::parse(RULES, sources.rules)?;
        forward.check_against(RULES, &v016, &v1)?;
        let normalize = RuleSet::parse(NORMALIZE, sources.normalize)?;
        let reverse = forward.invert(&v016);
        let catalogue = PromptCatalogue::parse(sources.prompts)?;
        let pin_singletons = forward.pin_singletons(&v016);
        Ok(Mapping {
            pin_singletons,
            v016,
            v1,
            v1_oss,
            forward,
            reverse,
            normalize,
            catalogue,
        })
    }

    pub fn catalogue(&self) -> &Catalogue {
        &self.catalogue
    }

    pub fn session<'a>(
        &'a self,
        direction: Direction,
        answers: &'a Answers,
        options: Options,
    ) -> Session<'a> {
        Session::new(self, direction, answers, options)
    }

    /// Returns the name an object of the direction's source takes in its target, with the `x:` prefix.
    pub fn target_object(&self, direction: Direction, object: &str) -> Box<str> {
        let rules = self.rules(direction);
        let name = if object.starts_with(OBJECT_PREFIX) {
            Cow::Borrowed(object)
        } else {
            Cow::Owned(format!("{OBJECT_PREFIX}{object}"))
        };
        match rules.object(&name).and_then(|rule| rule.to.clone()) {
            Some(renamed) => renamed,
            None => name.into(),
        }
    }

    /// Returns the schema snapshot of `version`.
    pub fn schema(&self, version: SchemaVersion) -> &Schema {
        self.schema_of(version)
    }

    /// Returns the stock v1 spam filter tags, with their scores, that a migrated
    /// registry holding `source_tags` (v0.16 tag names) lacks.
    pub fn missing_spam_tags<'s>(
        &self,
        source_tags: impl Iterator<Item = &'s str>,
    ) -> Vec<(&str, f64)> {
        let tags = &self.forward.spam_tags;
        let present: FxHashSet<&str> = source_tags
            .map(|tag| tags.renamed.get(tag).map_or(tag, |renamed| &**renamed))
            .collect();
        tags.added
            .iter()
            .filter(|(tag, _)| !present.contains(&**tag))
            .map(|(tag, score)| (&**tag, *score))
            .collect()
    }

    /// Returns the rules that convert objects of the direction's source into its target.
    pub fn rules(&self, direction: Direction) -> &RuleSet {
        match direction {
            Direction::Forward => &self.forward,
            Direction::Reverse => &self.reverse,
        }
    }

    fn schema_of(&self, version: SchemaVersion) -> &Schema {
        match version {
            SchemaVersion::V016 => &self.v016,
            SchemaVersion::V1 => &self.v1,
        }
    }

    /// Returns every registry reference in `value`, an object of type `object` (with or without `x:`), as the referenced object (with `x:`, views resolved to their base) and id, sorted and without duplicates.
    pub fn references<'s>(
        &'s self,
        version: SchemaVersion,
        object: &str,
        value: &Value,
    ) -> Vec<(&'s str, u64)> {
        let name = if object.starts_with(OBJECT_PREFIX) {
            Cow::Borrowed(object)
        } else {
            Cow::Owned(format!("{OBJECT_PREFIX}{object}"))
        };
        let mut refs = Vec::new();
        engine::collect_schema(self.schema_of(version), &name, value, &mut refs);
        refs.sort_unstable();
        refs.dedup();
        refs
    }

    /// Returns every object and property path (segments joined by `/`, `*` for list, set and map members) whose type is a registry reference.
    pub fn reference_fields(&self, version: SchemaVersion) -> Vec<(Box<str>, Box<str>)> {
        self.schema_of(version).reference_fields()
    }

    pub fn validate_value(&self, schema: &str, value: &Value) -> std::result::Result<(), String> {
        engine::check_value(self, schema, value)
    }
}
