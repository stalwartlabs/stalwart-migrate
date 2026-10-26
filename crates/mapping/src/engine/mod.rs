mod defaults;
mod finalize;
mod normalize;
mod path;
mod refs;
mod walk;

use rustc_hash::FxHashSet;
use serde_json::{Map, Value};

use crate::{
    Mapping,
    answers::{Answer, Answers},
    ids::{Instance, ObjectKey},
    prompts::PromptId,
    report::{Change, Question, Report},
    rules::RuleSet,
    schema::Schema,
};

pub(crate) use defaults::expression_mentions;
pub use finalize::{unique_key, unique_key_value};
pub(crate) use refs::collect_schema;
pub(crate) use walk::{Flow, TYPE_KEY, Walker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    Enterprise,
    Oss,
}

impl Edition {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map!(value.as_bytes(), Edition,
            "enterprise" => Edition::Enterprise,
            "oss" => Edition::Oss,
        )
        .copied()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Edition::Enterprise => "enterprise",
            Edition::Oss => "oss",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolQuestions {
    Ask,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Normalize {
    From016x,
    Off,
}

/// Whether `convert_all` adds v0.16 singletons that are absent from the input.
///
/// v0.16 uses the built-in defaults for a singleton that was never saved. With
/// `Synthesize`, every such singleton that has a `pin` default policy is
/// converted from an empty object so the pinned v0.16 defaults are written;
/// it is skipped when nothing would be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Singletons {
    Synthesize,
    AsGiven,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub edition: Edition,
    pub external_blob_store: bool,
    pub tool_questions: ToolQuestions,
    pub normalize: Normalize,
    pub singletons: Singletons,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            edition: Edition::Enterprise,
            external_blob_store: false,
            tool_questions: ToolQuestions::Ask,
            normalize: Normalize::Off,
            singletons: Singletons::Synthesize,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SourceObject {
    pub key: ObjectKey,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TargetObject {
    pub source: ObjectKey,
    pub key: ObjectKey,
    pub value: Value,
}

/// A property removed from an object to break a reference cycle.
///
/// The object is written first with a placeholder (null, the marker variant of
/// a union, or a set without the cyclic members); once every object in
/// `Outcome::objects` is written, the caller patches `properties` onto `key`.
/// Example: an account with encryption at rest and its `PublicKey`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeferredUpdate {
    pub source: ObjectKey,
    pub key: ObjectKey,
    pub properties: Map<String, Value>,
}

/// Result of `Session::delete_plan`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeletePlan {
    pub updates: Vec<DeferredUpdate>,
    pub order: Vec<ObjectKey>,
    pub report: Report,
}

/// Result of `Session::convert_all`.
///
/// Write `objects` in order, then apply every entry of `deferred` as an update.
/// `dropped` lists source objects that are not written. `report` holds the
/// change log and the questions; `is_complete` is false while a question is
/// unanswered, a `Dangling` or unsplittable cycle error remains, or `aborted`
/// is set (operator answer, or an enterprise-only store on an OSS target).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub objects: Vec<TargetObject>,
    pub deferred: Vec<DeferredUpdate>,
    pub dropped: Vec<ObjectKey>,
    pub report: Report,
    pub aborted: bool,
}

impl Outcome {
    pub fn is_complete(&self) -> bool {
        !self.aborted
            && self.report.unanswered().next().is_none()
            && self.report.errors().next().is_none()
    }
}

#[derive(Debug)]
pub(crate) struct Move {
    pub source: ObjectKey,
    pub object: Box<str>,
    pub property: Box<str>,
    pub value: Value,
}

pub struct Session<'a> {
    pub(crate) mapping: &'a Mapping,
    pub(crate) direction: Direction,
    pub(crate) answers: &'a Answers,
    pub(crate) options: Options,
    pub(crate) rules: &'a RuleSet,
    pub(crate) source: &'a Schema,
    pub(crate) target: &'a Schema,
    pub(crate) target_full: &'a Schema,
    pub(crate) edition: Edition,
    pub(crate) owners: Owners,
}

/// Whether the run migrates accounts, for objects owned through `accountId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principals {
    Migrated,
    Excluded,
}

/// The accounts the source lists, which tell an orphan apart from an account the run does not convert.
#[derive(Debug, Clone, Default)]
pub enum Owners {
    /// Nothing is known: an object whose owner is not converted is a blocking `Dangling` error.
    #[default]
    Unknown,
    /// Every account id the source lists, converted or not.
    ///
    /// An owner absent from `accounts` drops its objects as orphans. A listed owner that is not
    /// converted satisfies the reference when `principals` is `Excluded` and is a blocking
    /// `Dangling` error when it is `Migrated` (the mapping dropped the account).
    Listed {
        accounts: FxHashSet<u64>,
        principals: Principals,
    },
}

impl<'a> Session<'a> {
    /// Sets the accounts listed by the source; see `Owners`.
    pub fn with_owners(mut self, owners: Owners) -> Self {
        self.owners = owners;
        self
    }

    pub(crate) fn new(
        mapping: &'a Mapping,
        direction: Direction,
        answers: &'a Answers,
        options: Options,
    ) -> Self {
        let edition = match direction {
            Direction::Forward => answers
                .get(PromptId::Edition, None)
                .and_then(|a| a.str("edition"))
                .and_then(Edition::parse)
                .unwrap_or(options.edition),
            Direction::Reverse => options.edition,
        };
        let (rules, source, target_full) = match direction {
            Direction::Forward => (&mapping.forward, &mapping.v016, &mapping.v1),
            Direction::Reverse => (&mapping.reverse, &mapping.v1, &mapping.v016),
        };
        let target = match (direction, edition) {
            (Direction::Forward, Edition::Oss) => &mapping.v1_oss,
            _ => target_full,
        };
        Session {
            mapping,
            direction,
            answers,
            options,
            rules,
            source,
            target,
            target_full,
            edition,
            owners: Owners::default(),
        }
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn edition(&self) -> Edition {
        self.edition
    }

    /// Converts every registry object of the source in one call.
    ///
    /// Pass the complete set on every run: moves between singletons, reference
    /// clearing, cycle splitting and the write order depend on all objects.
    /// Decide what to write by comparing the converted values with what the
    /// target holds.
    pub fn convert_all(&self, mut inputs: Vec<SourceObject>) -> Outcome {
        let mut outcome = Outcome::default();
        if self.direction == Direction::Forward && self.options.tool_questions == ToolQuestions::Ask
        {
            self.ask_tool_questions(&mut outcome.report);
        }
        let coordinator = coordinator_type(&inputs);
        let in_memory = ObjectKey::singleton(IN_MEMORY_STORE);
        if coordinator.is_some()
            && self.direction == Direction::Forward
            && !inputs.iter().any(|input| input.key == in_memory)
        {
            inputs.push(SourceObject {
                key: in_memory,
                value: Value::Object(Map::from_iter([(
                    TYPE_KEY.to_string(),
                    Value::from(IN_MEMORY_DEFAULT),
                )])),
            });
        }
        let given = inputs.len();
        if self.direction == Direction::Forward && self.options.singletons == Singletons::Synthesize
        {
            for object in self.mapping.pin_singletons.iter() {
                let key = ObjectKey::singleton(object);
                if !inputs.iter().take(given).any(|i| i.key == key) {
                    inputs.push(SourceObject {
                        key,
                        value: Value::Object(Map::new()),
                    });
                }
            }
        }
        let mut moves = Vec::new();
        let mut originals = Vec::new();
        for (position, input) in inputs.into_iter().enumerate() {
            let synthesized = position >= given;
            let mut value = input.value;
            if finalize::merges(&input.key.object) {
                originals.push((input.key.clone(), value.clone()));
            }
            if self.direction == Direction::Forward && self.options.normalize == Normalize::From016x
            {
                normalize::normalize_object(self, &input.key, &mut value, &mut outcome.report);
            }
            let mut walker = Walker::new(self, &mut outcome.report, &input.key);
            walker.coordinator = coordinator.as_deref();
            let converted = walker.convert(value);
            moves.append(&mut walker.moves);
            outcome.aborted |= walker.abort;
            match converted {
                Some((_, Value::Object(map))) if synthesized && map.is_empty() => (),
                Some((object, value)) => outcome.objects.push(TargetObject {
                    key: ObjectKey {
                        object,
                        instance: input.key.instance.clone(),
                    },
                    source: input.key,
                    value,
                }),
                None => outcome.dropped.push(input.key),
            }
        }
        self.apply_moves(moves, &mut outcome);
        finalize::finalize_all(self, &mut outcome, &originals);
        refs::fix_dangling(self, &mut outcome);
        refs::sort_for_writing(self.target, &mut outcome);
        outcome
    }

    pub fn convert_one(&self, input: SourceObject) -> Outcome {
        self.convert_all(vec![input])
    }

    /// Orders objects for deletion: referencing objects first.
    ///
    /// Equivalent to `delete_plan(objects).order`; the values must be the ones
    /// last written to the target, otherwise references cannot be seen.
    pub fn delete_order(&self, objects: Vec<TargetObject>) -> Vec<TargetObject> {
        let mut outcome = Outcome {
            objects,
            ..Default::default()
        };
        refs::sort_for_writing(self.target, &mut outcome);
        outcome.objects.reverse();
        outcome.objects
    }

    /// Orders objects that are already in the target schema for writing.
    ///
    /// No conversion runs: `objects` are written as given, except that the
    /// references splitting a cycle are replaced with placeholders in the
    /// returned `objects` and their original values are returned in
    /// `deferred`, to patch once every object exists. References to objects
    /// outside `objects` count as already written. A cycle that cannot be
    /// split is reported as a `ReferenceCycle` error in `report`.
    pub fn write_plan(&self, objects: Vec<TargetObject>) -> Outcome {
        let mut outcome = Outcome {
            objects,
            ..Default::default()
        };
        refs::sort_for_writing(self.target, &mut outcome);
        outcome
    }

    /// Plans the deletion of target objects.
    ///
    /// `objects` carry the values last written to the target (`key` is the
    /// target key, `source` is reported back in `updates`). Apply `updates`
    /// first: they replace the references that form cycles with placeholders
    /// (for example an account's `encryptionAtRest` before its `PublicKey` and
    /// the account are both deleted). Then delete in `order`, which removes
    /// every referencing object before the objects it references. A cycle that
    /// cannot be split is reported as a `ReferenceCycle` error in `report`.
    pub fn delete_plan(&self, objects: Vec<TargetObject>) -> DeletePlan {
        let mut outcome = Outcome {
            objects,
            ..Default::default()
        };
        refs::sort_for_writing(self.target, &mut outcome);
        let updates = outcome
            .deferred
            .iter()
            .filter_map(|deferred| {
                let object = outcome.objects.iter().find(|o| o.key == deferred.key)?;
                let properties: Map<String, Value> = deferred
                    .properties
                    .keys()
                    .filter_map(|name| object.value.get(name).map(|v| (name.clone(), v.clone())))
                    .collect();
                Some(DeferredUpdate {
                    source: deferred.source.clone(),
                    key: deferred.key.clone(),
                    properties,
                })
            })
            .collect();
        DeletePlan {
            updates,
            order: outcome.objects.into_iter().rev().map(|o| o.key).collect(),
            report: outcome.report,
        }
    }

    fn apply_moves(&self, moves: Vec<Move>, outcome: &mut Outcome) {
        for mv in moves {
            let target = outcome
                .objects
                .iter_mut()
                .find(|o| o.key.object == mv.object && o.key.instance == Instance::Singleton);
            let to = format!("{}.{}", mv.object, mv.property);
            match target {
                Some(object) => {
                    if let Value::Object(map) = &mut object.value {
                        map.insert(mv.property.to_string(), mv.value);
                    }
                }
                None => {
                    let mut map = Map::new();
                    map.insert(mv.property.to_string(), mv.value);
                    outcome.objects.push(TargetObject {
                        source: mv.source.clone(),
                        key: ObjectKey {
                            object: mv.object.clone(),
                            instance: Instance::Singleton,
                        },
                        value: Value::Object(map),
                    });
                }
            }
            outcome
                .report
                .push(&mv.source, &mv.property, Change::Moved { to: to.into() });
        }
    }

    fn ask_tool_questions(&self, report: &mut Report) {
        let catalogue = self.mapping.catalogue();
        let blob_store = self
            .options
            .external_blob_store
            .then_some(PromptId::BlobStore);
        for prompt in blob_store.into_iter().chain([PromptId::Categories]) {
            report.add_question(Question {
                prompt,
                key: None,
                answered: self.answers.get(prompt, None).is_some(),
                defaults: Answer::defaults_of(catalogue.prompt(prompt)),
                context: Vec::new(),
            });
        }
    }

    pub(crate) fn answer(
        &self,
        report: &mut Report,
        prompt: PromptId,
        key: Option<&ObjectKey>,
        defaults: Answer,
        context: Vec<(Box<str>, Value)>,
    ) -> Answer {
        let given = self.answers.get(prompt, key);
        let answer = given
            .map(|a| a.merge_over(&defaults))
            .unwrap_or_else(|| defaults.clone());
        report.add_question(Question {
            prompt,
            key: key.cloned(),
            defaults,
            context,
            answered: given.is_some(),
        });
        answer
    }

    pub(crate) fn global_answer(&self, report: &mut Report, prompt: PromptId) -> Answer {
        let defaults = Answer::defaults_of(self.mapping.catalogue().prompt(prompt));
        self.answer(report, prompt, None, defaults, Vec::new())
    }
}

pub(crate) fn check_value(mapping: &Mapping, schema: &str, value: &Value) -> Result<(), String> {
    let answers = Answers::default();
    let session = Session::new(mapping, Direction::Forward, &answers, Options::default());
    match finalize::check(&session, schema, value).first() {
        Some(entry) => Err(entry.to_string()),
        None => Ok(()),
    }
}

const COORDINATOR: &str = "x:Coordinator";
const COORDINATOR_DISABLED: &str = "Disabled";
pub(crate) const IN_MEMORY_STORE: &str = "x:InMemoryStore";
const IN_MEMORY_DEFAULT: &str = "Default";

fn coordinator_type(inputs: &[SourceObject]) -> Option<Box<str>> {
    let coordinator = ObjectKey::singleton(COORDINATOR);
    inputs
        .iter()
        .find(|input| input.key == coordinator)
        .and_then(|input| input.value.get(TYPE_KEY))
        .and_then(Value::as_str)
        .filter(|kind| *kind != COORDINATOR_DISABLED)
        .map(Into::into)
}
