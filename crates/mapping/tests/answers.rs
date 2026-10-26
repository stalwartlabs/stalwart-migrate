use mapping::{
    Answer, AnswerIssue, Answers, Direction, Mapping, ObjectKey, Options, PromptId, SourceObject,
};
use serde_json::{Value, json};

fn sources() -> Vec<SourceObject> {
    vec![
        SourceObject {
            key: ObjectKey::singleton("x:Http"),
            value: json!({"useXForwarded": true}),
        },
        SourceObject {
            key: ObjectKey::parse("x:Directory/b").expect("key"),
            value: json!({"@type": "Oidc", "issuerUrl": "https://sso", "requireAudience": "aud",
                          "requireScopes": {}, "claimName": "name"}),
        },
    ]
}

#[test]
fn unanswered_questions_block_the_run() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &answers, Options::default())
        .convert_all(sources());
    assert!(!outcome.is_complete());
    let issues = answers.validate(&mapping, &outcome.report.questions);
    let missing: Vec<String> = issues
        .iter()
        .filter(|i| matches!(i, AnswerIssue::Missing { .. }))
        .map(ToString::to_string)
        .collect();
    for expected in [
        "categories: not answered",
        "http_forwarded for x:Http: not answered",
        "oidc_directory for x:Directory/b: not answered",
        "changed_defaults: not answered",
    ] {
        assert!(
            missing.iter().any(|m| m == expected),
            "missing {expected} in {missing:?}"
        );
    }
}

// The edition is never asked and the blob store only for an external blob store.
#[test]
fn tool_questions_follow_the_source() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let asked = |options: Options| -> Vec<PromptId> {
        mapping
            .session(Direction::Forward, &answers, options)
            .convert_all(sources())
            .report
            .questions
            .iter()
            .filter(|q| q.key.is_none())
            .map(|q| q.prompt)
            .collect()
    };
    let local = asked(Options::default());
    assert!(local.contains(&PromptId::Categories));
    assert!(!local.contains(&PromptId::BlobStore));
    assert!(!local.contains(&PromptId::Edition));
    let external = asked(Options {
        external_blob_store: true,
        ..Options::default()
    });
    assert!(external.contains(&PromptId::BlobStore));
    assert!(!external.contains(&PromptId::Edition));
}

#[test]
fn answers_round_trip_and_validate() {
    let mapping = Mapping::embedded().expect("mapping");
    let empty = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &empty, Options::default())
        .convert_all(sources());
    let questions = &outcome.report.questions;

    let mut answers = Answers::default();
    for question in questions {
        answers.set(
            question.prompt,
            question.key.clone(),
            question.defaults.clone(),
        );
    }
    assert!(answers.validate(&mapping, questions).is_empty());
    let mut http = Answer::new();
    http.set("source", json!("forwarded"));
    http.set("hops", json!(2));
    answers.set(
        PromptId::HttpForwarded,
        Some(ObjectKey::singleton("x:Http")),
        http,
    );
    assert!(answers.validate(&mapping, questions).is_empty());

    let text = answers.to_toml(mapping.catalogue(), questions);
    assert!(
        text.contains("[instance.http_forwarded.\"x:Http\"]"),
        "{text}"
    );
    assert!(text.contains("# v0.16: "), "{text}");
    let parsed = Answers::parse(&text).expect("parse written answers");
    let http_key = ObjectKey::singleton("x:Http");
    for (prompt, key) in [
        (PromptId::HttpForwarded, Some(&http_key)),
        (PromptId::Categories, None),
    ] {
        assert_eq!(
            parsed.get(prompt, key),
            answers.get(prompt, key),
            "{prompt}"
        );
    }
    assert!(parsed.validate(&mapping, questions).is_empty());

    let rerun = mapping
        .session(Direction::Forward, &parsed, Options::default())
        .convert_all(sources());
    assert!(
        rerun.is_complete(),
        "{:?}",
        rerun.report.unanswered().collect::<Vec<_>>()
    );
    let http = rerun
        .objects
        .iter()
        .find(|o| o.key == ObjectKey::singleton("x:Http"))
        .expect("http");
    assert_eq!(
        http.value,
        json!({"clientIpSource": "forwarded", "forwardedHops": 2})
    );
}

#[test]
fn invalid_answers_are_reported() {
    let mapping = Mapping::embedded().expect("mapping");
    let empty = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &empty, Options::default())
        .convert_all(sources());
    let questions = &outcome.report.questions;
    let answers = Answers::parse(
        r#"
version = 1

[instance.http_forwarded."x:Http"]
source = "bogus"
hops = 99
colour = "blue"

[instance.oidc_directory."x:Directory/c"]
unscoped_tokens = "full"

[global.target_store]
store = { "@type" = "NoSuchStore" }
"#,
    )
    .expect("parse");
    let issues: Vec<String> = answers
        .validate(&mapping, questions)
        .iter()
        .map(ToString::to_string)
        .collect();
    for expected in [
        "http_forwarded for x:Http: source: bogus is not one of the options",
        "http_forwarded for x:Http: hops: 99 is out of range",
        "http_forwarded for x:Http: unknown field colour",
        "oidc_directory for x:Directory/c: no longer applies to the source",
    ] {
        assert!(
            issues.iter().any(|i| i == expected),
            "missing {expected} in {issues:?}"
        );
    }
    assert!(
        !issues.iter().any(|i| i.starts_with("target_store")),
        "{issues:?}"
    );
}

#[test]
fn catalogue_covers_every_prompt() {
    let mapping = Mapping::embedded().expect("mapping");
    let catalogue = mapping.catalogue();
    for &id in PromptId::ALL {
        let prompt = catalogue.prompt(id);
        assert_eq!(prompt.id, id);
        assert!(!prompt.fields.is_empty(), "{id} has no fields");
        assert!(catalogue.sections().get(prompt.section).is_some());
    }
    assert_eq!(catalogue.prompts().len(), PromptId::ALL.len());
}

#[test]
fn answers_from_json_match_toml() {
    let json_answers = Answers::from_json(json!({
        "global": {"edition": {"edition": "oss"}},
        "instance": {"spam_ai": {"x:SpamLlm": {"action": "disable"}}}
    }))
    .expect("json");
    let toml_answers = Answers::parse(
        "version = 1\n[global.edition]\nedition = \"oss\"\n[instance.spam_ai.\"x:SpamLlm\"]\naction = \"disable\"\n",
    )
    .expect("toml");
    assert_eq!(json_answers, toml_answers);
    assert_eq!(
        toml_answers
            .get(PromptId::Edition, None)
            .and_then(|a| a.get("edition"))
            .cloned(),
        Some(Value::String("oss".into()))
    );
}

#[test]
fn conditional_required_fields_are_enforced() {
    let mapping = Mapping::embedded().expect("mapping");
    let empty = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &empty, Options::default())
        .convert_all(vec![SourceObject {
            key: ObjectKey::singleton("x:BlobStore"),
            value: json!({"@type": "Azure", "storageAccount": "a", "container": "c",
                          "accessKey": {"@type": "None"}, "sasToken": {"@type": "None"}}),
        }]);
    let answers = Answers::parse(
        "version = 1\n[instance.azure_auth.\"x:BlobStore\"]\nmode = \"ClientSecret\"\n",
    )
    .expect("parse");
    let issues: Vec<String> = answers
        .validate(&mapping, &outcome.report.questions)
        .iter()
        .map(ToString::to_string)
        .collect();
    for field in ["tenant_id", "client_id", "client_secret"] {
        let expected = format!("azure_auth for x:BlobStore: {field} is required");
        assert!(
            issues.contains(&expected),
            "missing {expected} in {issues:?}"
        );
    }
    let blank = Answers::parse(
        "version = 1\n[instance.azure_auth.\"x:BlobStore\"]\nmode = \"ClientSecret\"\ntenant_id = \"  \"\nclient_id = \"c\"\nclient_secret = \"\"\n",
    )
    .expect("parse");
    let blank_issues: Vec<String> = blank
        .validate(&mapping, &outcome.report.questions)
        .iter()
        .map(ToString::to_string)
        .collect();
    for field in ["tenant_id", "client_secret"] {
        let expected = format!("azure_auth for x:BlobStore: {field} is required");
        assert!(
            blank_issues.contains(&expected),
            "missing {expected} in {blank_issues:?}"
        );
    }
    let managed = Answers::parse(
        "version = 1\n[instance.azure_auth.\"x:BlobStore\"]\nmode = \"ManagedIdentity\"\n",
    )
    .expect("parse");
    assert!(
        !managed
            .validate(&mapping, &outcome.report.questions)
            .iter()
            .any(|i| i.to_string().starts_with("azure_auth")),
    );
}

#[test]
fn unanswered_questions_are_written_commented_out() {
    let mapping = Mapping::embedded().expect("mapping");
    let empty = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &empty, Options::default())
        .convert_all(sources());
    let text = empty.to_toml(mapping.catalogue(), &outcome.report.questions);
    assert!(
        text.contains("# [instance.http_forwarded.\"x:Http\"]"),
        "{text}"
    );
    let parsed = Answers::parse(&text).expect("parse");
    assert_eq!(parsed, Answers::default());
    let rerun = mapping
        .session(Direction::Forward, &parsed, Options::default())
        .convert_all(sources());
    assert!(rerun.report.unanswered().count() > 0);
}

#[cfg(unix)]
#[test]
fn answers_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let mapping = Mapping::embedded().expect("mapping");
    let dir = std::env::temp_dir().join(format!("mapping-answers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("answers.toml");
    Answers::default()
        .write(&path, mapping.catalogue(), &[])
        .expect("write");
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

// A failed write never truncates the existing answers file: the new text goes to a temporary file that replaces the old one only once complete.
#[test]
fn failed_write_keeps_the_previous_answers() {
    let mapping = Mapping::embedded().expect("mapping");
    let dir = std::env::temp_dir().join(format!("mapping-answers-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("answers.toml");
    std::fs::write(&path, "version = 1\n# operator answers\n").expect("previous answers");
    std::fs::create_dir_all(dir.join("answers.toml.tmp")).expect("blocking temporary");
    assert!(
        Answers::default()
            .write(&path, mapping.catalogue(), &[])
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("previous answers"),
        "version = 1\n# operator answers\n"
    );
    std::fs::remove_dir_all(dir.join("answers.toml.tmp")).expect("unblock");
    Answers::default()
        .write(&path, mapping.catalogue(), &[])
        .expect("write");
    assert!(!dir.join("answers.toml.tmp").exists());
    assert_ne!(
        std::fs::read_to_string(&path).expect("new answers"),
        "version = 1\n# operator answers\n"
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

// A write that fails after the temporary file was created removes it again.
#[test]
fn failed_write_removes_its_temporary_file() {
    let mapping = Mapping::embedded().expect("mapping");
    let dir = std::env::temp_dir().join(format!("mapping-answers-cleanup-{}", std::process::id()));
    let path = dir.join("answers.toml");
    std::fs::create_dir_all(path.join("occupied")).expect("blocking directory");
    assert!(
        Answers::default()
            .write(&path, mapping.catalogue(), &[])
            .is_err()
    );
    assert!(!dir.join("answers.toml.tmp").exists());
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

// A stale temporary symlink is replaced, never written through.
#[cfg(unix)]
#[test]
fn stale_temporary_symlink_is_not_followed() {
    let mapping = Mapping::embedded().expect("mapping");
    let dir = std::env::temp_dir().join(format!("mapping-answers-symlink-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let victim = dir.join("victim");
    std::fs::write(&victim, "untouched").expect("victim");
    std::os::unix::fs::symlink(&victim, dir.join("answers.toml.tmp")).expect("symlink");
    let path = dir.join("answers.toml");
    Answers::default()
        .write(&path, mapping.catalogue(), &[])
        .expect("write");
    assert_eq!(
        std::fs::read_to_string(&victim).expect("victim"),
        "untouched"
    );
    assert!(
        std::fs::read_to_string(&path)
            .expect("answers")
            .contains("version")
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}
