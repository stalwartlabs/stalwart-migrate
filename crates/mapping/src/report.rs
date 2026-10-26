use std::fmt;

use serde_json::Value;

use crate::{answers::Answer, ids::ObjectKey, prompts::PromptId};

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub prompt: PromptId,
    pub key: Option<ObjectKey>,
    pub defaults: Answer,
    pub context: Vec<(Box<str>, Value)>,
    pub answered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    NoEquivalent,
    Enterprise,
    NotInTarget,
    Invalid,
    /// Owned through `accountId` by an account the source does not list.
    Orphaned {
        account: ObjectKey,
    },
    Operator,
    /// The unique key was dropped by the conversion or is absent.
    KeyLost,
    /// Another object, `kept`, converts to the same unique key.
    KeyConflict {
        key: Box<str>,
        kept: ObjectKey,
    },
    /// Merged into `into`, which converts to the same unique key; `original` describes the dropped source.
    Merged {
        key: Box<str>,
        into: ObjectKey,
        original: Box<str>,
    },
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropReason::NoEquivalent => f.write_str("no equivalent in the target version"),
            DropReason::Enterprise => f.write_str("enterprise only, target is open source"),
            DropReason::NotInTarget => f.write_str("not part of the target schema"),
            DropReason::Invalid => f.write_str("invalid value"),
            DropReason::Orphaned { account } => {
                write!(f, "its owner {account} is not listed by the source")
            }
            DropReason::Operator => f.write_str("dropped as answered"),
            DropReason::KeyLost => {
                f.write_str("its unique key is absent or has no equivalent in the target version")
            }
            DropReason::KeyConflict { key, kept } => write!(
                f,
                "{kept} has the same unique key {key} in the target version and is kept"
            ),
            DropReason::Merged {
                key,
                into,
                original,
            } => write!(
                f,
                "merged into {into}, which has the same unique key {key} in the target version; it was {original}"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Dropped {
        reason: DropReason,
        value: Option<Value>,
    },
    Clamped {
        from: Value,
        to: Value,
    },
    DefaultPinned {
        value: Value,
    },
    DefaultInherited {
        old: Value,
    },
    Transformed {
        transform: &'static str,
        detail: String,
    },
    Unknown,
    ReferenceCleared {
        target: ObjectKey,
    },
    Dangling {
        target: ObjectKey,
    },
    Moved {
        to: Box<str>,
    },
    ReferenceCycle,
    ReferenceDeferred,
}

pub const COUNTER_READ: &str = "counter_read";
pub const WEBUI_CUSTOM_BUNDLE: &str = "webui_custom_bundle";
const WARNING_TRANSFORMS: &[&str] = &[COUNTER_READ, WEBUI_CUSTOM_BUNDLE];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub key: ObjectKey,
    pub path: Box<str>,
    pub change: Change,
}

impl Entry {
    pub fn level(&self) -> Level {
        match &self.change {
            Change::Dangling { .. } => Level::Error,
            Change::Dropped { .. }
            | Change::Unknown
            | Change::Clamped { .. }
            | Change::ReferenceCleared { .. } => Level::Warning,
            Change::Transformed { transform, .. } if WARNING_TRANSFORMS.contains(transform) => {
                Level::Warning
            }
            Change::ReferenceCycle => Level::Error,
            Change::ReferenceDeferred => Level::Info,
            Change::DefaultPinned { .. }
            | Change::DefaultInherited { .. }
            | Change::Transformed { .. }
            | Change::Moved { .. } => Level::Info,
        }
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.level() {
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Error => "error",
        };
        write!(f, "{level}: {}", self.key)?;
        if !self.path.is_empty() {
            write!(f, " {}", self.path)?;
        }
        let json = |v: &Value| serde_json::to_string(v).unwrap_or_default();
        match &self.change {
            Change::Dropped { reason, value } => {
                write!(f, ": dropped ({reason})")?;
                if let Some(value) = value {
                    write!(f, ", was {}", json(value))?;
                }
                Ok(())
            }
            Change::Clamped { from, to } => write!(f, ": clamped {} to {}", json(from), json(to)),
            Change::DefaultPinned { value } => {
                write!(
                    f,
                    ": v0.16 default {} kept (changed default pinned)",
                    json(value)
                )
            }
            Change::DefaultInherited { old } => {
                write!(
                    f,
                    ": v0.16 default {} replaced by the new default",
                    json(old)
                )
            }
            Change::Transformed { transform, detail } => write!(f, ": {transform}: {detail}"),
            Change::Unknown => write!(f, ": unknown in the source schema, kept as is"),
            Change::ReferenceCleared { target } => {
                write!(f, ": reference to {target} removed (target not migrated)")
            }
            Change::Dangling { target } => {
                write!(
                    f,
                    ": references {target}, which is not migrated, and cannot be cleared"
                )
            }
            Change::Moved { to } => write!(f, ": moved to {to}"),
            Change::ReferenceCycle => {
                write!(f, ": part of a reference cycle that cannot be split")
            }
            Change::ReferenceDeferred => write!(
                f,
                ": written without this reference first, then updated (Outcome::deferred)"
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub entries: Vec<Entry>,
    pub questions: Vec<Question>,
}

impl Report {
    pub fn push(&mut self, key: &ObjectKey, path: &str, change: Change) {
        self.entries.push(Entry {
            key: key.clone(),
            path: path.into(),
            change,
        });
    }

    pub fn unanswered(&self) -> impl Iterator<Item = &Question> {
        self.questions.iter().filter(|q| !q.answered)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.level() == Level::Error)
    }

    pub(crate) fn add_question(&mut self, question: Question) {
        if !self
            .questions
            .iter()
            .any(|q| q.prompt == question.prompt && q.key == question.key)
        {
            self.questions.push(question);
        }
    }

    pub fn merge(&mut self, other: Report) {
        self.entries.extend(other.entries);
        for question in other.questions {
            self.add_question(question);
        }
    }
}
