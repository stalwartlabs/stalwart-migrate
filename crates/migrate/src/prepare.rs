/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Write as _,
    io::{self, BufRead, IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use mapping::{
    Answer, Answers, Direction, Instance, Level, Mapping, Options, Outcome, Question, SourceObject,
    prompts::{Choice, Field, FieldKind, Required},
};
use model::{CategorySet, RegistryEntries, RegistryKey, RegistryRecord, Source};
use serde_json::Value;

use crate::{
    commands::run::answer_categories,
    converter::{instance_id, listed_owners, object_key, outcome_problems},
    orchestrator::{RetryPolicy, read_registry},
    terminal::EchoGuard,
};

pub const ANSWERS_FILE: &str = "answers.toml";
pub const REPORT_FILE: &str = "prepare-report.txt";

pub const TERMINAL_REQUIRED: &str = "prepare is interactive and needs a terminal. \
Run it with a TTY attached: `docker run -it ...` or `docker compose run --rm migrate prepare` with Docker, \
`kubectl run -it ...` or `kubectl exec -it ...` with Kubernetes. \
Use `prepare --non-interactive` to only validate an existing answers.toml.";

pub fn has_terminal() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

pub trait Terminal {
    fn read_line(&mut self, buf: &mut String) -> io::Result<usize>;

    fn read_secret(&mut self, buf: &mut String) -> io::Result<usize>;

    fn output(&mut self) -> &mut dyn Write;
}

pub struct StdTerminal {
    stdout: io::Stdout,
}

impl Default for StdTerminal {
    fn default() -> Self {
        StdTerminal {
            stdout: io::stdout(),
        }
    }
}

impl Terminal for StdTerminal {
    fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
        io::stdin().lock().read_line(buf)
    }

    fn read_secret(&mut self, buf: &mut String) -> io::Result<usize> {
        let guard = EchoGuard::disable();
        let read = io::stdin().lock().read_line(buf);
        drop(guard);
        let _ = writeln!(self.stdout);
        read
    }

    fn output(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }
}

pub struct Prepare<'x> {
    pub mapping: &'x Mapping,
    pub options: Options,
    pub objects: Vec<SourceObject>,
    pub unreadable: Vec<RegistryKey>,
}

#[derive(Debug)]
pub struct Prepared {
    pub outcome: Outcome,
    pub problems: Vec<Box<str>>,
    pub unreadable: Vec<RegistryKey>,
    pub answered: usize,
}

impl Prepared {
    pub fn is_complete(&self) -> bool {
        self.problems.is_empty() && self.outcome.is_complete()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    Write,
    Discard,
}

pub async fn source_objects<S: Source>(
    source: &S,
    policy: RetryPolicy,
    limit: usize,
) -> model::Result<(Vec<SourceObject>, Vec<RegistryKey>)> {
    let RegistryEntries {
        records,
        unreadable,
    } = read_registry(source, policy, limit).await?;
    let objects = records
        .into_iter()
        .map(|RegistryRecord { key, json }| SourceObject {
            key: object_key(&key),
            value: json,
        })
        .collect();
    Ok((objects, unreadable))
}

impl Prepare<'_> {
    fn convert(&self, answers: &Answers) -> Outcome {
        let categories = answer_categories(answers).unwrap_or_else(|_| CategorySet::defaults());
        let owners = listed_owners(
            self.objects
                .iter()
                .map(|object| (&*object.key.object, instance_id(&object.key.instance))),
            categories,
        );
        self.mapping
            .session(Direction::Forward, answers, self.options.clone())
            .with_owners(owners)
            .convert_all(self.objects.clone())
    }

    pub fn validate(&self, answers: &Answers) -> Prepared {
        let outcome = self.convert(answers);
        let problems = outcome_problems(self.mapping, answers, &outcome);
        Prepared {
            outcome,
            problems,
            unreadable: self.unreadable.clone(),
            answered: 0,
        }
    }

    pub fn interactive(
        &self,
        answers: &mut Answers,
        terminal: &mut dyn Terminal,
    ) -> io::Result<(Prepared, Confirmation)> {
        let catalogue = self.mapping.catalogue();
        let mut answered = 0usize;
        let mut section: Option<usize> = None;
        writeln!(
            terminal.output(),
            "stalwart-migrate prepare: review how the v0.16 settings are converted to v1.\n\
             Press Enter to accept the value in brackets."
        )?;
        let outcome = loop {
            let outcome = self.convert(answers);
            let Some(question) = outcome.report.unanswered().next().cloned() else {
                break outcome;
            };
            let prompt = catalogue.prompt(question.prompt);
            if section != Some(prompt.section) {
                section = Some(prompt.section);
                if let Some(title) = catalogue.sections().get(prompt.section) {
                    writeln!(terminal.output(), "\n==== {} ====", title.title)?;
                }
            }
            let answer = self.ask(&question, terminal)?;
            answers.set(question.prompt, question.key.clone(), answer);
            answered += 1;
            let again = self.convert(answers);
            if again
                .report
                .unanswered()
                .any(|next| next.prompt == question.prompt && next.key == question.key)
            {
                return Err(io::Error::other(format!(
                    "question {} is still pending after being answered",
                    question.prompt
                )));
            }
        };
        let problems = outcome_problems(self.mapping, answers, &outcome);
        let prepared = Prepared {
            outcome,
            problems,
            unreadable: self.unreadable.clone(),
            answered,
        };
        let out = terminal.output();
        out.write_all(summary(&prepared).as_bytes())?;
        write!(out, "\nWrite {ANSWERS_FILE} and {REPORT_FILE}? [Y/n] ")?;
        out.flush()?;
        let mut line = String::new();
        terminal.read_line(&mut line)?;
        let confirmation = match line.trim() {
            "" => Confirmation::Write,
            text if parse_bool(text) == Some(true) => Confirmation::Write,
            _ => Confirmation::Discard,
        };
        Ok((prepared, confirmation))
    }

    fn ask(&self, question: &Question, terminal: &mut dyn Terminal) -> io::Result<Answer> {
        let prompt = self.mapping.catalogue().prompt(question.prompt);
        let out = terminal.output();
        write!(out, "\n{}", prompt.title)?;
        if let Some(key) = &question.key {
            write!(out, " ({key})")?;
        }
        writeln!(out, "\n  v0.16: {}\n  v1:    {}", prompt.v016, prompt.v1)?;
        if let Some(recommendation) = &prompt.recommendation {
            writeln!(out, "  Recommended: {recommendation}")?;
        }
        for (name, value) in &question.context {
            writeln!(out, "  {name}: {value}")?;
        }

        let mut answer = Answer::new();
        let mut line = String::new();
        for field in prompt.fields.iter() {
            if matches!(field.kind, FieldKind::PolicyMap) {
                continue;
            }
            let merged = answer.merge_over(&question.defaults);
            if field.when.as_ref().is_some_and(|when| !when.holds(&merged)) {
                continue;
            }
            let default = question
                .defaults
                .get(&field.name)
                .or(field.default.as_ref())
                .cloned();
            loop {
                write_field(terminal.output(), field, default.as_ref())?;
                line.clear();
                let read = match field.kind {
                    FieldKind::Secret => terminal.read_secret(&mut line)?,
                    _ => terminal.read_line(&mut line)?,
                };
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "input closed before all questions were answered",
                    ));
                }
                let required = match &field.required {
                    Required::Never => false,
                    Required::Always => true,
                    Required::When(condition) => {
                        condition.holds(&answer.merge_over(&question.defaults))
                    }
                };
                match parse_field(self.mapping, field, line.trim(), default.as_ref(), required) {
                    Ok(Some(value)) => {
                        answer.set(&field.name, value);
                        break;
                    }
                    Ok(None) => break,
                    Err(message) => writeln!(terminal.output(), "  {message}")?,
                }
            }
        }
        Ok(answer)
    }
}

fn write_field(out: &mut dyn Write, field: &Field, default: Option<&Value>) -> io::Result<()> {
    write!(out, "  {}", field.label)?;
    match &field.kind {
        FieldKind::Choice(choices) | FieldKind::MultiChoice(choices) => {
            writeln!(out)?;
            for (index, choice) in choices.iter().enumerate() {
                writeln!(
                    out,
                    "    {}) {} [{}]",
                    index + 1,
                    choice.label,
                    choice.value
                )?;
            }
            if matches!(field.kind, FieldKind::MultiChoice(_)) {
                write!(out, "  (comma separated)")?;
            }
        }
        FieldKind::Bool => write!(out, " (y/n)")?,
        FieldKind::Number { min, max } => {
            if min.is_some() || max.is_some() {
                write!(
                    out,
                    " ({} to {})",
                    min.map_or_else(|| "-inf".to_string(), |min| min.to_string()),
                    max.map_or_else(|| "+inf".to_string(), |max| max.to_string())
                )?;
            }
        }
        FieldKind::List => write!(out, " (comma separated)")?,
        FieldKind::Object { schema } => write!(out, " (JSON {schema})")?,
        FieldKind::String | FieldKind::Secret | FieldKind::PolicyMap => {}
    }
    match (default, &field.kind) {
        (Some(_), FieldKind::Secret) => write!(out, " [keep current]")?,
        (Some(default), _) => write!(out, " [{}]", display_value(default))?,
        (None, _) => {}
    }
    write!(out, ": ")?;
    out.flush()
}

fn display_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(display_value)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

fn parse_bool(text: &str) -> Option<bool> {
    hashify::map_ignore_case!(text.as_bytes(), bool,
        "y" => true,
        "yes" => true,
        "true" => true,
        "n" => false,
        "no" => false,
        "false" => false,
    )
    .copied()
}

fn parse_field(
    mapping: &Mapping,
    field: &Field,
    text: &str,
    default: Option<&Value>,
    required: bool,
) -> Result<Option<Value>, String> {
    if text.is_empty() {
        return match default {
            Some(default) => Ok(Some(default.clone())),
            None if required => Err("a value is required".into()),
            None => Ok(None),
        };
    }
    match &field.kind {
        FieldKind::Choice(choices) => choose(choices, text).map(|value| Some(Value::String(value))),
        FieldKind::MultiChoice(choices) => text
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| choose(choices, item).map(Value::String))
            .collect::<Result<Vec<_>, _>>()
            .map(|items| Some(Value::Array(items))),
        FieldKind::Bool => parse_bool(text)
            .map(|value| Some(Value::Bool(value)))
            .ok_or_else(|| "answer y or n".to_string()),
        FieldKind::Number { min, max } => {
            let number: f64 = text.parse().map_err(|_| "enter a number".to_string())?;
            if min.is_some_and(|min| number < min) || max.is_some_and(|max| number > max) {
                return Err("the value is out of range".into());
            }
            let value = if number.fract() == 0.0 && number.abs() < 9.0e15 {
                Value::from(number as i64)
            } else {
                Value::from(number)
            };
            Ok(Some(value))
        }
        FieldKind::String | FieldKind::Secret => Ok(Some(Value::String(text.into()))),
        FieldKind::List => Ok(Some(Value::Array(
            text.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| Value::String(item.into()))
                .collect(),
        ))),
        FieldKind::Object { schema } => {
            let value: Value =
                serde_json::from_str(text).map_err(|err| format!("invalid JSON: {err}"))?;
            mapping.validate_value(schema, &value)?;
            Ok(Some(value))
        }
        FieldKind::PolicyMap => Err(format!("set this field by editing {ANSWERS_FILE}")),
    }
}

fn choose(choices: &[Choice], text: &str) -> Result<String, String> {
    let selected = match text.parse::<usize>() {
        Ok(index) => index.checked_sub(1).and_then(|index| choices.get(index)),
        Err(_) => choices.iter().find(|choice| &*choice.value == text),
    };
    selected
        .map(|choice| choice.value.to_string())
        .ok_or_else(|| format!("choose 1-{} or one of the listed values", choices.len()))
}

const BLOB_STORE: &str = "BlobStore";
const LOCAL_BLOB_STORE: &str = "Default";

fn external_blob_store(outcome: &Outcome) -> Option<&str> {
    outcome
        .objects
        .iter()
        .find(|object| {
            object.key.instance == Instance::Singleton
                && object
                    .key
                    .object
                    .strip_prefix("x:")
                    .unwrap_or(&object.key.object)
                    == BLOB_STORE
        })?
        .value
        .get("@type")?
        .as_str()
        .filter(|backend| *backend != LOCAL_BLOB_STORE)
}

pub fn summary(prepared: &Prepared) -> String {
    let outcome = &prepared.outcome;
    let count = |level: Level| {
        outcome
            .report
            .entries
            .iter()
            .filter(|entry| entry.level() == level)
            .count()
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\nSummary: {} objects to write, {} dropped, {} warnings, {} errors, {} questions answered now.",
        outcome.objects.len(),
        outcome.dropped.len(),
        count(Level::Warning),
        count(Level::Error),
        prepared.answered
    );
    if !prepared.unreadable.is_empty() {
        let _ = writeln!(
            out,
            "Warning: {} settings objects are unreadable in the v0.16 store and also ignored by v0.16.27; they are not migrated, recreate them in v1 if needed:",
            prepared.unreadable.len()
        );
        for key in &prepared.unreadable {
            let _ = writeln!(out, "  {key}");
        }
    }
    if let Some(backend) = external_blob_store(outcome) {
        let _ = writeln!(
            out,
            "With the spam_model category, run --final overwrites the spam classifier and trainer models under their fixed keys in the external {backend} blob store, after its verification passed. v0.16 uses the same keys and cannot read the v1 format; a later rollback into this blob store refuses to start unless it is told to write the v0.16 model back (--allow-shared-deletes) or to keep the v1 model (--keep-v1-spam-model)."
        );
    }
    if prepared.problems.is_empty() {
        let _ = writeln!(out, "Every question has an answer; run can start.");
    } else {
        let _ = writeln!(out, "run will refuse to start until these are resolved:");
        for problem in &prepared.problems {
            let _ = writeln!(out, "  {problem}");
        }
    }
    out
}

pub fn report_text(prepared: &Prepared) -> String {
    let mut out = String::from("stalwart-migrate prepare report\n");
    out.push_str(&summary(prepared));
    if !prepared.outcome.dropped.is_empty() {
        out.push_str("\nDropped objects:\n");
        for key in &prepared.outcome.dropped {
            let _ = writeln!(out, "  {key}");
        }
    }
    out.push_str("\nChanges:\n");
    for entry in &prepared.outcome.report.entries {
        let _ = writeln!(out, "  {entry}");
    }
    out
}

pub fn load_answers(dir: &Path) -> Result<Answers, mapping::Error> {
    let path = dir.join(ANSWERS_FILE);
    if path.is_file() {
        Answers::load(path)
    } else {
        Ok(Answers::default())
    }
}

pub fn write_outputs(
    dir: &Path,
    mapping: &Mapping,
    answers: &Answers,
    prepared: &Prepared,
) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    answers
        .write(
            dir.join(ANSWERS_FILE),
            mapping.catalogue(),
            &prepared.outcome.report.questions,
        )
        .map_err(io::Error::other)?;
    write_atomic(&dir.join(REPORT_FILE), report_text(prepared).as_bytes())
}

const PRIVATE_FILE_MODE: u32 = 0o600;

fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)
}

#[cfg(test)]
mod tests;
