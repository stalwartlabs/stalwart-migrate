use std::{collections::BTreeMap, fmt, fmt::Write as _, path::Path};

use serde_json::{Map, Value};

use crate::{
    Mapping,
    error::{Error, Result},
    ids::ObjectKey,
    prompts::{Catalogue, Field, FieldKind, Prompt, PromptId, PromptScope, Required},
    report::Question,
    rules::Policy,
};

const ANSWERS_VERSION: i64 = 1;
const WRAP: usize = 78;
const SECRET_MASK: &str = "****";
#[cfg(unix)]
const ANSWERS_MODE: u32 = 0o600;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Answer(BTreeMap<Box<str>, Value>);

impl Answer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_fields(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
        Answer(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    pub fn defaults_of(prompt: &Prompt) -> Self {
        Answer(
            prompt
                .fields
                .iter()
                .filter_map(|f| f.default.clone().map(|d| (f.name.clone(), d)))
                .collect(),
        )
    }

    pub fn get(&self, field: &str) -> Option<&Value> {
        self.0.get(field).filter(|v| !v.is_null())
    }

    pub fn str(&self, field: &str) -> Option<&str> {
        self.get(field).and_then(Value::as_str)
    }

    pub fn bool(&self, field: &str) -> Option<bool> {
        self.get(field).and_then(Value::as_bool)
    }

    pub fn u64(&self, field: &str) -> Option<u64> {
        self.get(field).and_then(Value::as_u64)
    }

    pub fn strings(&self, field: &str) -> impl Iterator<Item = &str> {
        self.get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
    }

    pub fn set(&mut self, field: &str, value: Value) {
        self.0.insert(field.into(), value);
    }

    pub fn fields(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (&**k, v))
    }

    pub fn merge_over(&self, defaults: &Answer) -> Answer {
        let mut merged = defaults.clone();
        merged
            .0
            .extend(self.0.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
    }

    pub fn policy_override(&self, path: &str) -> Option<Policy> {
        self.get("overrides")
            .and_then(|o| o.get(path))
            .and_then(Value::as_str)
            .and_then(Policy::parse)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Answers {
    global: BTreeMap<PromptId, Answer>,
    instance: BTreeMap<(PromptId, ObjectKey), Answer>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnswerIssue {
    Missing {
        prompt: PromptId,
        key: Option<ObjectKey>,
    },
    MissingField {
        prompt: PromptId,
        key: Option<ObjectKey>,
        field: Box<str>,
    },
    InvalidField {
        prompt: PromptId,
        key: Option<ObjectKey>,
        field: Box<str>,
        detail: String,
    },
    UnknownField {
        prompt: PromptId,
        key: Option<ObjectKey>,
        field: Box<str>,
    },
    NotApplicable {
        prompt: PromptId,
        key: Option<ObjectKey>,
    },
}

impl AnswerIssue {
    pub fn is_error(&self) -> bool {
        !matches!(self, AnswerIssue::NotApplicable { .. })
    }
}

impl fmt::Display for AnswerIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope = |key: &Option<ObjectKey>| {
            key.as_ref()
                .map(|k| format!(" for {k}"))
                .unwrap_or_default()
        };
        match self {
            AnswerIssue::Missing { prompt, key } => {
                write!(f, "{prompt}{}: not answered", scope(key))
            }
            AnswerIssue::MissingField { prompt, key, field } => {
                write!(f, "{prompt}{}: {field} is required", scope(key))
            }
            AnswerIssue::InvalidField {
                prompt,
                key,
                field,
                detail,
            } => write!(f, "{prompt}{}: {field}: {detail}", scope(key)),
            AnswerIssue::UnknownField { prompt, key, field } => {
                write!(f, "{prompt}{}: unknown field {field}", scope(key))
            }
            AnswerIssue::NotApplicable { prompt, key } => {
                write!(f, "{prompt}{}: no longer applies to the source", scope(key))
            }
        }
    }
}

impl Answers {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_inner(path.as_ref())
    }

    fn load_inner(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.display().to_string().into(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let root: toml::Table = toml::from_str(text).map_err(|source| Error::Toml {
            file: "answers.toml".into(),
            source,
        })?;
        Self::from_table(root)
    }

    pub fn from_json(value: Value) -> Result<Self> {
        let mut root: toml::Table = serde_json::from_value(value)
            .map_err(|e| Error::answers(format!("invalid answers JSON: {e}")))?;
        root.entry("version")
            .or_insert(toml::Value::Integer(ANSWERS_VERSION));
        Self::from_table(root)
    }

    fn from_table(root: toml::Table) -> Result<Self> {
        let mut answers = Answers::default();
        for (name, value) in root {
            match (name.as_str(), value) {
                ("version", toml::Value::Integer(ANSWERS_VERSION)) => (),
                ("version", other) => {
                    return Err(Error::answers(format!("unsupported version {other}")));
                }
                ("global", toml::Value::Table(prompts)) => {
                    for (prompt, table) in prompts {
                        if RETIRED_PROMPTS.contains(&prompt.as_str()) {
                            continue;
                        }
                        let id = parse_prompt(&prompt)?;
                        answers.global.insert(id, parse_answer(&prompt, table)?);
                    }
                }
                ("instance", toml::Value::Table(prompts)) => {
                    for (prompt, keys) in prompts {
                        let id = parse_prompt(&prompt)?;
                        let toml::Value::Table(keys) = keys else {
                            return Err(Error::answers(format!(
                                "instance.{prompt} must be a table"
                            )));
                        };
                        for (key, table) in keys {
                            let object_key = ObjectKey::parse(&key).ok_or_else(|| {
                                Error::answers(format!("invalid object key {key}"))
                            })?;
                            answers
                                .instance
                                .insert((id, object_key), parse_answer(&key, table)?);
                        }
                    }
                }
                (other, _) => return Err(Error::answers(format!("unexpected key {other}"))),
            }
        }
        Ok(answers)
    }

    pub fn get(&self, prompt: PromptId, key: Option<&ObjectKey>) -> Option<&Answer> {
        match key {
            None => self.global.get(&prompt),
            Some(key) => self.instance.get(&(prompt, key.clone())),
        }
    }

    pub fn set(&mut self, prompt: PromptId, key: Option<ObjectKey>, answer: Answer) {
        match key {
            None => {
                self.global.insert(prompt, answer);
            }
            Some(key) => {
                self.instance.insert((prompt, key), answer);
            }
        }
    }

    pub fn remove(&mut self, prompt: PromptId, key: Option<&ObjectKey>) -> Option<Answer> {
        match key {
            None => self.global.remove(&prompt),
            Some(key) => self.instance.remove(&(prompt, key.clone())),
        }
    }

    pub fn validate(&self, mapping: &Mapping, questions: &[Question]) -> Vec<AnswerIssue> {
        let catalogue = mapping.catalogue();
        let mut issues = Vec::new();
        for question in questions {
            let key = question.key.clone();
            let Some(answer) = self.get(question.prompt, question.key.as_ref()) else {
                issues.push(AnswerIssue::Missing {
                    prompt: question.prompt,
                    key,
                });
                continue;
            };
            let prompt = catalogue.prompt(question.prompt);
            let merged = answer.merge_over(&question.defaults);
            for (name, _) in answer.fields() {
                if prompt.field(name).is_none() {
                    issues.push(AnswerIssue::UnknownField {
                        prompt: question.prompt,
                        key: key.clone(),
                        field: name.into(),
                    });
                }
            }
            for field in prompt.fields.iter() {
                if field.when.as_ref().is_some_and(|c| !c.holds(&merged)) {
                    continue;
                }
                let required = field_required(field, &merged);
                let Some(value) = merged
                    .get(&field.name)
                    .filter(|v| !(required && is_blank(v)))
                else {
                    if required {
                        issues.push(AnswerIssue::MissingField {
                            prompt: question.prompt,
                            key: key.clone(),
                            field: field.name.clone(),
                        });
                    }
                    continue;
                };
                let checked = check_value(field, value).and_then(|()| match &field.kind {
                    FieldKind::Object { schema } => mapping.validate_value(schema, value),
                    _ => Ok(()),
                });
                if let Err(detail) = checked {
                    issues.push(AnswerIssue::InvalidField {
                        prompt: question.prompt,
                        key: key.clone(),
                        field: field.name.clone(),
                        detail,
                    });
                }
            }
        }
        let applicable = |prompt: PromptId, key: Option<&ObjectKey>| {
            questions
                .iter()
                .any(|q| q.prompt == prompt && q.key.as_ref() == key)
        };
        for prompt in self.global.keys() {
            if !applicable(*prompt, None) {
                issues.push(AnswerIssue::NotApplicable {
                    prompt: *prompt,
                    key: None,
                });
            }
        }
        for (prompt, key) in self.instance.keys() {
            if !applicable(*prompt, Some(key)) {
                issues.push(AnswerIssue::NotApplicable {
                    prompt: *prompt,
                    key: Some(key.clone()),
                });
            }
        }
        issues
    }

    pub fn write(
        &self,
        path: impl AsRef<Path>,
        catalogue: &Catalogue,
        questions: &[Question],
    ) -> Result<()> {
        self.write_inner(path.as_ref(), catalogue, questions)
    }

    fn write_inner(
        &self,
        path: &Path,
        catalogue: &Catalogue,
        questions: &[Question],
    ) -> Result<()> {
        let text = self.to_toml(catalogue, questions);
        write_atomically(path, text.as_bytes())
    }

    pub fn to_toml(&self, catalogue: &Catalogue, questions: &[Question]) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("# Answers for stalwart-migrate and cli-plan/convert_plan.py.\n");
        out.push_str(
            "# Written by `prepare`; it can be edited by hand. Fields left out take the\n",
        );
        out.push_str("# recommended value shown in the comments. Secrets are stored in clear.\n\n");
        let _ = writeln!(out, "version = {ANSWERS_VERSION}");

        for (index, section) in catalogue.sections().iter().enumerate() {
            let mut header_written = false;
            for prompt in catalogue.prompts().iter().filter(|p| p.section == index) {
                for question in questions.iter().filter(|q| q.prompt == prompt.id) {
                    if !header_written {
                        let _ = write!(out, "\n# ==== {} ====\n", section.title);
                        header_written = true;
                    }
                    let given = self.get(prompt.id, question.key.as_ref());
                    write_prompt(&mut out, prompt, question.key.as_ref(), question, given);
                }
            }
        }

        let stale: Vec<(PromptId, Option<&ObjectKey>, &Answer)> = self
            .global
            .iter()
            .map(|(p, a)| (*p, None, a))
            .chain(self.instance.iter().map(|((p, k), a)| (*p, Some(k), a)))
            .filter(|(p, k, _)| {
                !questions
                    .iter()
                    .any(|q| q.prompt == *p && q.key.as_ref() == *k)
            })
            .collect();
        if !stale.is_empty() {
            out.push_str("\n# ==== Answers that no longer apply to the source ====\n");
            for (prompt, key, answer) in stale {
                out.push('\n');
                write_table(
                    &mut out,
                    prompt,
                    key,
                    catalogue.prompt(prompt),
                    answer,
                    answer,
                    "",
                );
            }
        }
        out
    }
}

fn is_blank(value: &Value) -> bool {
    match value {
        Value::String(s) => s.trim().is_empty(),
        Value::Array(items) => items.is_empty(),
        _ => false,
    }
}

fn field_required(field: &Field, answer: &Answer) -> bool {
    match &field.required {
        Required::Always => return true,
        Required::When(condition) if condition.holds(answer) => return true,
        _ => (),
    }
    field.default.is_none()
        && !matches!(
            field.kind,
            FieldKind::Secret | FieldKind::String | FieldKind::List
        )
}

fn write_prompt(
    out: &mut String,
    prompt: &Prompt,
    key: Option<&ObjectKey>,
    question: &Question,
    given: Option<&Answer>,
) {
    out.push('\n');
    let _ = writeln!(out, "# {}", prompt.title);
    write_wrapped(out, "v0.16: ", &prompt.v016);
    write_wrapped(out, "v1: ", &prompt.v1);
    if let Some(recommendation) = &prompt.recommendation {
        write_wrapped(out, "Recommendation: ", recommendation);
    }
    for (label, value) in &question.context {
        let _ = writeln!(out, "# Source {label}: {}", compact(value));
    }
    for field in prompt.fields.iter() {
        let _ = write!(out, "#   {}: {}", field.name, field.label);
        if let FieldKind::Choice(choices) | FieldKind::MultiChoice(choices) = &field.kind {
            out.push_str(" (");
            for (i, choice) in choices.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&choice.value);
            }
            out.push(')');
        }
        if let Some(default) = question.defaults.get(&field.name) {
            let _ = write!(out, "; recommended {}", compact(default));
        }
        out.push('\n');
    }
    match given {
        Some(given) => {
            let merged = given.merge_over(&question.defaults);
            write_table(out, prompt.id, key, prompt, given, &merged, "");
        }
        None => {
            out.push_str(
                "# Not answered yet: uncomment the table to accept the recommended values.\n",
            );
            write_table(
                out,
                prompt.id,
                key,
                prompt,
                &question.defaults,
                &question.defaults,
                "# ",
            );
        }
    }
}

fn write_table(
    out: &mut String,
    id: PromptId,
    key: Option<&ObjectKey>,
    prompt: &Prompt,
    answer: &Answer,
    scope: &Answer,
    prefix: &str,
) {
    match (prompt.scope, key) {
        (PromptScope::Global, _) | (_, None) => {
            let _ = writeln!(out, "{prefix}[global.{id}]");
        }
        (PromptScope::Instance, Some(key)) => {
            let _ = writeln!(
                out,
                "{prefix}[instance.{id}.{}]",
                toml_string(&key.to_string())
            );
        }
    }
    let mut write_field = |name: &str, value: &Value| {
        if let Some(rendered) = toml_inline(value) {
            let _ = writeln!(out, "{prefix}{} = {rendered}", toml_key(name));
        }
    };
    for field in prompt.fields.iter() {
        if field.when.as_ref().is_some_and(|c| !c.holds(scope)) {
            continue;
        }
        if let Some(value) = answer.get(&field.name) {
            write_field(&field.name, value);
        }
    }
    for (name, value) in answer.fields() {
        if prompt.field(name).is_none() && !value.is_null() {
            write_field(name, value);
        }
    }
}

fn write_wrapped(out: &mut String, prefix: &str, text: &str) {
    let mut line = String::with_capacity(WRAP);
    line.push_str("# ");
    line.push_str(prefix);
    for word in text.split_whitespace() {
        if line.len() + word.len() + 1 > WRAP && line.len() > 2 {
            out.push_str(line.trim_end());
            out.push('\n');
            line.clear();
            line.push_str("#   ");
        }
        line.push_str(word);
        line.push(' ');
    }
    out.push_str(line.trim_end());
    out.push('\n');
}

fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

const TEMPORARY_SUFFIX: &str = ".tmp";
const SECRET_HINTS: &[&str] = &["secret", "password", "token", "key"];

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let io_error = |at: &Path| {
        let at = at.display().to_string();
        move |source| Error::Io {
            path: at.into(),
            source,
        }
    };
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(TEMPORARY_SUFFIX);
    let temporary = std::path::PathBuf::from(temporary);
    match std::fs::remove_file(&temporary) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(io_error(&temporary)(e));
        }
        _ => (),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(ANSWERS_MODE);
    }
    let mut file = options.open(&temporary).map_err(io_error(&temporary))?;
    let written = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(ANSWERS_MODE))
                .map_err(io_error(&temporary))?;
        }
        file.write_all(bytes).map_err(io_error(&temporary))?;
        file.sync_all().map_err(io_error(&temporary))?;
        std::fs::rename(&temporary, path).map_err(io_error(path))
    })();
    drop(file);
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written?;
    #[cfg(unix)]
    if let Some(directory) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(directory)
            .and_then(|dir| dir.sync_all())
            .map_err(io_error(directory))?;
    }
    Ok(())
}

pub(crate) fn mask_property(
    name: &str,
    ty: Option<&crate::schema::TypeDef>,
    value: &Value,
) -> Value {
    let secret = match ty {
        Some(ty) => ty.is_secret(),
        None => {
            let lower = name.to_ascii_lowercase();
            SECRET_HINTS.iter().any(|hint| lower.contains(hint))
        }
    };
    match value {
        Value::Object(_) | Value::Array(_) => mask_secrets(value),
        Value::Null => Value::Null,
        _ if secret => Value::String(SECRET_MASK.into()),
        _ => value.clone(),
    }
}

pub(crate) fn mask_all(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let masked = if k == "@type" { v.clone() } else { mask_all(v) };
                    (k.clone(), masked)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(mask_all).collect()),
        Value::Null => Value::Null,
        _ => Value::String(SECRET_MASK.into()),
    }
}

pub(crate) fn mask_secrets(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let masked = if k == "secret" {
                        Value::String(SECRET_MASK.into())
                    } else {
                        mask_secrets(v)
                    };
                    (k.clone(), masked)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(mask_secrets).collect()),
        other => other.clone(),
    }
}

fn toml_key(key: &str) -> String {
    if !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        key.to_string()
    } else {
        toml_string(key)
    }
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn toml_inline(value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => return None,
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => toml_string(s),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().filter_map(toml_inline).enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&item);
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            let mut out = String::from("{");
            for (i, (k, v)) in map
                .iter()
                .filter_map(|(k, v)| toml_inline(v).map(|v| (k, v)))
                .enumerate()
            {
                out.push_str(if i > 0 { ", " } else { " " });
                let _ = write!(out, "{} = {v}", toml_key(k));
            }
            out.push_str(if map.is_empty() { "}" } else { " }" });
            out
        }
    })
}

const RETIRED_PROMPTS: &[&str] = &["target_store"];

fn parse_prompt(name: &str) -> Result<PromptId> {
    PromptId::parse(name).ok_or_else(|| Error::answers(format!("unknown prompt {name}")))
}

fn parse_answer(context: &str, value: toml::Value) -> Result<Answer> {
    let toml::Value::Table(table) = value else {
        return Err(Error::answers(format!("{context} must be a table")));
    };
    let mut answer = Answer::default();
    for (name, value) in table {
        let value = serde_json::to_value(value)
            .map_err(|e| Error::answers(format!("{context}.{name}: {e}")))?;
        answer.0.insert(name.into(), value);
    }
    Ok(answer)
}

pub(crate) fn check_value(field: &Field, value: &Value) -> std::result::Result<(), String> {
    let choice = |choices: &[crate::prompts::Choice], v: &Value| match v.as_str() {
        Some(s) if choices.iter().any(|c| &*c.value == s) => Ok(()),
        Some(s) => Err(format!("{s} is not one of the options")),
        None => Err("expected a string".to_string()),
    };
    match &field.kind {
        FieldKind::Choice(choices) => choice(choices, value),
        FieldKind::MultiChoice(choices) => value
            .as_array()
            .ok_or_else(|| "expected a list".to_string())?
            .iter()
            .try_for_each(|v| choice(choices, v)),
        FieldKind::Bool => value
            .is_boolean()
            .then_some(())
            .ok_or_else(|| "expected true or false".to_string()),
        FieldKind::Number { min, max } => {
            let n = value
                .as_f64()
                .ok_or_else(|| "expected a number".to_string())?;
            if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
                Err(format!("{n} is out of range"))
            } else {
                Ok(())
            }
        }
        FieldKind::String | FieldKind::Secret => value
            .is_string()
            .then_some(())
            .ok_or_else(|| "expected a string".to_string()),
        FieldKind::List => value
            .as_array()
            .filter(|items| items.iter().all(Value::is_string))
            .map(|_| ())
            .ok_or_else(|| "expected a list of strings".to_string()),
        FieldKind::Object { .. } => value
            .is_object()
            .then_some(())
            .ok_or_else(|| "expected an object".to_string()),
        FieldKind::PolicyMap => value
            .as_object()
            .filter(|map: &&Map<String, Value>| {
                map.values()
                    .all(|v| v.as_str().and_then(Policy::parse).is_some())
            })
            .map(|_| ())
            .ok_or_else(|| "expected a table of pin or inherit".to_string()),
    }
}
