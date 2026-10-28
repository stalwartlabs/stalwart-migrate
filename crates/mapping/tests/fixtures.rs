use std::{
    fs,
    path::{Path, PathBuf},
};

use mapping::{
    Answers, Change, Direction, Edition, JmapId, Level, Mapping, Normalize, ObjectKey, Options,
    Outcome, Owners, Principals, Singletons, SourceObject, ToolQuestions,
};
use serde_json::{Value, json};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../mapping/fixtures")
}

fn read_json(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

fn change_kind(change: &Change) -> &'static str {
    match change {
        Change::Dropped { .. } => "dropped",
        Change::Clamped { .. } => "clamped",
        Change::DefaultPinned { .. } => "default_pinned",
        Change::DefaultInherited { .. } => "default_inherited",
        Change::Transformed { .. } => "transformed",
        Change::Unknown => "unknown",
        Change::ReferenceCleared { .. } => "reference_cleared",
        Change::ReferenceOutsideTenant { .. } => "reference_outside_tenant",
        Change::ReferenceCopiedIntoTenant { .. } => "reference_copied_into_tenant",
        Change::Dangling { .. } => "dangling",
        Change::Moved { .. } => "moved",
        Change::ReferenceCycle => "reference_cycle",
        Change::ReferenceDeferred => "reference_deferred",
    }
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Info => "info",
        Level::Warning => "warning",
        Level::Error => "error",
    }
}

fn owners(input: &Value) -> Owners {
    let Some(spec) = input.get("owners") else {
        return Owners::Unknown;
    };
    let accounts = spec["accounts"]
        .as_array()
        .expect("owners.accounts")
        .iter()
        .map(|id| {
            JmapId::parse(id.as_str().expect("account id"))
                .expect("jmap id")
                .0
        })
        .collect();
    let principals = match spec["principals"].as_str() {
        Some("excluded") => Principals::Excluded,
        _ => Principals::Migrated,
    };
    Owners::Listed {
        accounts,
        principals,
    }
}

fn outcome_json(outcome: &Outcome) -> Value {
    let objects: Vec<Value> = outcome
        .objects
        .iter()
        .map(
            |o| json!({"key": o.key.to_string(), "source": o.source.to_string(), "value": o.value}),
        )
        .collect();
    let mut dropped: Vec<String> = outcome.dropped.iter().map(ToString::to_string).collect();
    dropped.sort();
    let mut questions: Vec<Value> = outcome
        .report
        .questions
        .iter()
        .map(|q| {
            json!({
                "prompt": q.prompt.as_str(),
                "key": q.key.as_ref().map(ToString::to_string),
                "answered": q.answered,
            })
        })
        .collect();
    questions.sort_by_key(|q| q.to_string());
    let mut changes: Vec<Value> = outcome
        .report
        .entries
        .iter()
        .map(|e| {
            let mut change = json!({
                "key": e.key.to_string(),
                "path": &*e.path,
                "change": change_kind(&e.change),
                "level": level_name(e.level()),
            });
            if let Change::Dropped { reason, .. } = &e.change {
                change["reason"] = json!(reason.to_string());
            }
            change
        })
        .collect();
    changes.sort_by_key(|c| c.to_string());
    changes.dedup();
    let deferred: Vec<Value> = outcome
        .deferred
        .iter()
        .map(|d| json!({"key": d.key.to_string(), "properties": d.properties}))
        .collect();
    json!({
        "objects": objects,
        "deferred": deferred,
        "dropped": dropped,
        "questions": questions,
        "changes": changes,
        "aborted": outcome.aborted,
    })
}

fn options(input: &Value) -> Options {
    let mut options = Options {
        tool_questions: ToolQuestions::Skip,
        singletons: Singletons::AsGiven,
        ..Options::default()
    };
    let Some(spec) = input.get("options") else {
        return options;
    };
    if let Some(edition) = spec.get("edition").and_then(Value::as_str) {
        options.edition = Edition::parse(edition).expect("edition");
    }
    if spec.get("synthesize").and_then(Value::as_bool) == Some(true) {
        options.singletons = Singletons::Synthesize;
    }
    if spec.get("normalize").and_then(Value::as_bool) == Some(true) {
        options.normalize = Normalize::From016x;
    }
    options
}

fn run_fixture(mapping: &Mapping, dir: &Path) -> Value {
    let input = read_json(&dir.join("in.json")).expect("in.json");
    let answers = read_json(&dir.join("answers.json"))
        .map(|a| Answers::from_json(a).expect("answers.json"))
        .unwrap_or_default();
    let direction = match input.get("direction").and_then(Value::as_str) {
        Some("reverse") => Direction::Reverse,
        _ => Direction::Forward,
    };
    let session = mapping
        .session(direction, &answers, options(&input))
        .with_owners(owners(&input));
    let objects = input["objects"]
        .as_array()
        .expect("objects")
        .iter()
        .map(|o| SourceObject {
            key: ObjectKey::parse(o["key"].as_str().expect("key")).expect("valid key"),
            value: o["value"].clone(),
        })
        .collect();
    outcome_json(&session.convert_all(objects))
}

#[test]
fn golden_fixtures() {
    let mapping = Mapping::embedded().expect("embedded mapping");
    let update = std::env::var_os("UPDATE_FIXTURES").is_some();
    let mut dirs: Vec<PathBuf> = fs::read_dir(fixtures_dir())
        .expect("fixtures directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("in.json").exists())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no fixtures found");
    let mut failures = Vec::new();
    for dir in &dirs {
        let actual = run_fixture(&mapping, dir);
        let out = dir.join("out.json");
        if update {
            let text = serde_json::to_string_pretty(&actual).expect("serialize") + "\n";
            fs::write(&out, text).expect("write out.json");
            continue;
        }
        let expected = read_json(&out).unwrap_or(Value::Null);
        if expected != actual {
            failures.push(format!(
                "{}:\nexpected {}\nactual   {}",
                dir.display(),
                serde_json::to_string_pretty(&expected).unwrap_or_default(),
                serde_json::to_string_pretty(&actual).unwrap_or_default()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} fixture(s) differ:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
