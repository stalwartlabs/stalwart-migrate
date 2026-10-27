use mapping::{
    Answers, Change, Direction, Mapping, ObjectKey, Options, SchemaVersion, Singletons,
    SourceObject, ToolQuestions,
};
use serde_json::{Value, json};

fn options() -> Options {
    Options {
        tool_questions: ToolQuestions::Skip,
        singletons: Singletons::AsGiven,
        ..Options::default()
    }
}

fn dropped_values(outcome: &mapping::Outcome) -> Vec<(String, Option<Value>)> {
    outcome
        .report
        .entries
        .iter()
        .filter_map(|e| match &e.change {
            Change::Dropped { value, .. } => Some((e.path.to_string(), value.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn secrets_with_a_wrong_shape_are_masked_in_reports() {
    // Secret fields are masked by declared type even when the JSON shape is wrong.
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::singleton("x:BlobStore"),
                value: json!({"@type": "S3", "bucket": "b", "region": {"@type": "UsEast1"},
                              "secretKey": "plaintext-secret"}),
            },
            SourceObject {
                key: ObjectKey::singleton("x:InMemoryStore"),
                value: json!({"@type": "Default", "password": "hunter2", "url": "redis://x"}),
            },
        ]);
    let dropped = dropped_values(&outcome);
    assert!(
        dropped.contains(&("secretKey".into(), Some(json!("****")))),
        "{dropped:?}"
    );
    assert!(
        dropped.contains(&("password".into(), Some(json!("****")))),
        "{dropped:?}"
    );
    assert!(
        dropped.contains(&("url".into(), Some(json!("redis://x")))),
        "{dropped:?}"
    );
    let text: String = outcome
        .report
        .entries
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        !text.contains("plaintext-secret") && !text.contains("hunter2"),
        "{text}"
    );
}

// A v1-only property dropped on rollback is masked by its v1 type, not by its name: booleans and enums named like tokens stay readable, secrets stay hidden.
#[test]
fn reverse_drops_are_masked_by_the_source_type() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Reverse, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::singleton("x:SystemSettings"),
                value: json!({"includeSecrets": true}),
            },
            SourceObject {
                key: ObjectKey::with_id("x:HttpLookup", 1),
                value: json!({"namespace": "n", "url": "https://example.org/{key}", "enable": false,
                              "httpAuth": {"@type": "Basic", "username": "u", "secret": "hunter2"}}),
            },
        ]);
    let dropped = dropped_values(&outcome);
    assert!(
        dropped.contains(&("includeSecrets".into(), Some(json!(true)))),
        "{dropped:?}"
    );
    let auth = dropped
        .iter()
        .find(|(path, _)| path == "httpAuth")
        .and_then(|(_, value)| value.clone())
        .expect("httpAuth dropped");
    assert_eq!(auth["secret"], json!("****"), "{dropped:?}");
    assert_eq!(auth["username"], json!("u"), "{dropped:?}");
}

// Rolling an OpenAI model back to the flat v0.16 AiModel reports every v1-only setting it cannot keep, unmasked unless the v1 type is secret.
#[test]
fn reverse_ai_models_report_what_v016_cannot_hold() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Reverse, &answers, options())
        .convert_all(vec![SourceObject {
            key: ObjectKey::with_id("x:AiModel", 1),
            value: json!({"@type": "OpenAi", "name": "m", "model": "gpt", "url": "https://api.openai.com/v1",
                          "logprobs": false, "maxOutputTokens": 4096, "extraParameters": null,
                          "apiKey": {"@type": "Value", "secret": "k"}}),
        }]);
    let dropped = dropped_values(&outcome);
    assert!(
        dropped.contains(&("logprobs".into(), Some(json!(false)))),
        "{dropped:?}"
    );
    assert!(
        dropped.contains(&("maxOutputTokens".into(), Some(json!(4096)))),
        "{dropped:?}"
    );
    assert!(
        !dropped
            .iter()
            .any(|(path, _)| path == "extraParameters" || path == "apiKey"),
        "{dropped:?}"
    );

    let outcome = mapping
        .session(Direction::Reverse, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::with_id("x:AiModel", 2),
                value: json!({"@type": "OpenAi", "name": "env", "model": "gpt", "profile": "Azure",
                              "url": "https://r.openai.azure.com/openai/deployments/d",
                              "apiKey": {"@type": "EnvironmentVariable", "variableName": "AZURE_KEY"}}),
            },
            SourceObject {
                key: ObjectKey::with_id("x:AiModel", 3),
                value: json!({"@type": "OpenAi", "name": "key", "model": "gpt", "profile": "Azure",
                              "url": "https://r.openai.azure.com/openai/deployments/d",
                              "httpHeaders": {"api-key": "old"},
                              "apiKey": {"@type": "Value", "secret": "az"}}),
            },
            SourceObject {
                key: ObjectKey::with_id("x:AiModel", 4),
                value: json!({"@type": "OpenAi", "name": "query", "model": "gpt", "profile": "Azure",
                              "url": "https://r.openai.azure.com/openai/deployments/d?api-version=2024-02-01",
                              "httpHeaders": {"Api-Key": "old"},
                              "apiKey": {"@type": "Value", "secret": "az"}}),
            },
            SourceObject {
                key: ObjectKey::with_id("x:AiModel", 5),
                value: json!({"@type": "OpenAi", "name": "empty", "model": "gpt", "profile": "Azure",
                              "url": "http://vllm:8000",
                              "apiKey": {"@type": "Value", "secret": ""}}),
            },
        ]);
    let rows = |id: &str| -> Vec<(String, &'static str)> {
        outcome
            .report
            .entries
            .iter()
            .filter(|e| e.key.to_string() == format!("x:AiModel/{id}"))
            .map(|e| {
                let kind = match &e.change {
                    Change::Dropped { .. } => "dropped",
                    Change::Transformed { .. } => "transformed",
                    _ => "other",
                };
                (e.path.to_string(), kind)
            })
            .collect()
    };
    let env = rows("c");
    assert!(env.contains(&("profile".into(), "dropped")), "{env:?}");
    assert!(env.contains(&("url".into(), "transformed")), "{env:?}");
    let key = rows("d");
    assert!(!key.contains(&("profile".into(), "dropped")), "{key:?}");
    assert!(
        key.contains(&("httpHeaders/api-key".into(), "dropped")),
        "{key:?}"
    );
    assert!(key.contains(&("apiKey".into(), "transformed")), "{key:?}");
    let converted = |id: &str| {
        outcome
            .objects
            .iter()
            .find(|o| o.key.to_string() == format!("x:AiModel/{id}"))
            .map(|o| o.value.clone())
            .expect("converted model")
    };
    assert_eq!(converted("d")["httpHeaders"]["api-key"], json!("az"));
    let query = rows("e");
    assert!(
        query.contains(&("httpHeaders/Api-Key".into(), "dropped")),
        "{query:?}"
    );
    assert_eq!(converted("e")["httpHeaders"], json!({"api-key": "az"}));
    assert_eq!(
        converted("e")["url"],
        json!(
            "https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-02-01"
        )
    );
    let empty = rows("f");
    assert!(empty.contains(&("profile".into(), "dropped")), "{empty:?}");
    assert!(
        !empty.contains(&("apiKey".into(), "transformed")),
        "{empty:?}"
    );
    assert_eq!(
        converted("f")["httpAuth"],
        json!({"@type": "Unauthenticated"})
    );
    assert!(converted("f").get("httpHeaders").is_none());
    assert_eq!(
        converted("f")["url"],
        json!("http://vllm:8000/v1/chat/completions")
    );
}

#[test]
fn reverse_direction_never_prompts_for_defaults() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Reverse, &answers, options())
        .convert_all(vec![SourceObject {
            key: ObjectKey::singleton("x:Cache"),
            value: json!({"messages": 335544320}),
        }]);
    assert!(outcome.report.questions.is_empty());
    assert!(outcome.is_complete());
    assert_eq!(outcome.objects[0].value, json!({}));
}

#[test]
fn cycles_are_split_into_deferred_updates() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::parse("x:PublicKey/d").expect("key"),
                value: json!({"accountId": "c", "key": "k"}),
            },
            SourceObject {
                key: ObjectKey::parse("x:Account/c").expect("key"),
                value: json!({"@type": "User", "name": "u", "emailAddress": "u@example.com", "domainId": "a",
                              "encryptionAtRest": {"@type": "Aes128", "publicKey": "d"}}),
            },
            SourceObject {
                key: ObjectKey::parse("x:Domain/a").expect("key"),
                value: json!({"name": "example.com"}),
            },
        ]);
    let order: Vec<String> = outcome.objects.iter().map(|o| o.key.to_string()).collect();
    assert_eq!(order, ["x:Domain/a", "x:Account/c", "x:PublicKey/d"]);
    assert_eq!(
        outcome.objects[1].value["encryptionAtRest"],
        json!({"@type": "Disabled"})
    );
    let [deferred] = outcome.deferred.as_slice() else {
        panic!("expected one deferred update: {:?}", outcome.deferred);
    };
    assert_eq!(deferred.key.to_string(), "x:Account/c");
    assert_eq!(
        deferred.properties.get("encryptionAtRest"),
        Some(&json!({"@type": "Aes128", "publicKey": "d"}))
    );
    assert!(outcome.is_complete());
}

#[test]
fn cycle_break_never_picks_an_object_that_only_depends_on_the_cycle() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::parse("x:Account/b").expect("key"),
                value: json!({"@type": "User", "name": "member", "emailAddress": "m@example.com", "domainId": "a",
                              "memberGroupIds": {"c": true}}),
            },
            SourceObject {
                key: ObjectKey::parse("x:PublicKey/d").expect("key"),
                value: json!({"accountId": "c", "key": "k"}),
            },
            SourceObject {
                key: ObjectKey::parse("x:Account/c").expect("key"),
                value: json!({"@type": "User", "name": "u", "emailAddress": "u@example.com", "domainId": "a",
                              "encryptionAtRest": {"@type": "Aes128", "publicKey": "d"}}),
            },
            SourceObject {
                key: ObjectKey::parse("x:Domain/a").expect("key"),
                value: json!({"name": "example.com"}),
            },
        ]);
    let keys: Vec<String> = outcome.deferred.iter().map(|d| d.key.to_string()).collect();
    assert_eq!(keys, ["x:Account/c"]);
    let member = outcome
        .objects
        .iter()
        .find(|o| o.key.to_string() == "x:Account/b")
        .expect("member written");
    assert_eq!(member.value["memberGroupIds"], json!({"c": true}));
    let order: Vec<String> = outcome.objects.iter().map(|o| o.key.to_string()).collect();
    let position = |key: &str| order.iter().position(|k| k == key).expect("written");
    assert!(
        position("x:Account/c") < position("x:Account/b"),
        "{order:?}"
    );
    assert!(outcome.is_complete());
}

#[test]
fn values_under_secret_properties_are_masked_whatever_their_key() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(vec![SourceObject {
            key: ObjectKey::parse("x:Directory/b").expect("key"),
            value: json!({"@type": "Ldap", "url": "ldap://x", "baseDn": "dc=x",
                          "bindSecret": {"@type": "Value", "value": "hunter2"}}),
        }]);
    let text: String = outcome
        .report
        .entries
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(!text.contains("hunter2"), "{text}");
    assert!(text.contains("bindSecret/value"), "{text}");
}

#[test]
fn delete_plan_breaks_cycles_before_deleting() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let session = mapping.session(Direction::Forward, &answers, options());
    let target = |key: &str, value: Value| mapping::TargetObject {
        source: ObjectKey::parse(key).expect("key"),
        key: ObjectKey::parse(key).expect("key"),
        value,
    };
    let plan = session.delete_plan(vec![
        target("x:Domain/b", json!({"name": "example.com"})),
        target(
            "x:Account/c",
            json!({"@type": "User", "name": "u", "domainId": "b",
                   "encryptionAtRest": {"@type": "Aes128", "publicKey": "d"}}),
        ),
        target("x:PublicKey/d", json!({"accountId": "c", "key": "k"})),
    ]);
    let order: Vec<String> = plan.order.iter().map(ToString::to_string).collect();
    assert_eq!(order, ["x:PublicKey/d", "x:Account/c", "x:Domain/b"]);
    let [update] = plan.updates.as_slice() else {
        panic!("expected one pre-delete update: {:?}", plan.updates);
    };
    assert_eq!(update.key.to_string(), "x:Account/c");
    assert_eq!(
        update.properties.get("encryptionAtRest"),
        Some(&json!({"@type": "Disabled"}))
    );
}

#[test]
fn counter_reads_are_an_operator_decision() {
    let mapping = Mapping::embedded().expect("mapping");
    let source = || {
        vec![SourceObject {
            key: ObjectKey::parse("x:SpamRule/b").expect("key"),
            value: json!({"@type": "Any", "name": "r", "enable": true, "priority": 1,
                          "condition": {"match": {}, "else": "counter_get('s', 'k') > 1"}}),
        }]
    };
    let empty = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &empty, options())
        .convert_all(source());
    assert!(outcome.objects[0].value.get("condition").is_none());
    assert_eq!(outcome.report.unanswered().count(), 1);
    let answers = Answers::parse(
        "version = 1\n[instance.counter_read.\"x:SpamRule/b\"]\naction = \"rewrite\"\n",
    )
    .expect("parse");
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(source());
    assert_eq!(
        outcome.objects[0].value["condition"]["else"],
        json!("key_incr('s', 'k', 0) > 1")
    );
    assert!(
        outcome
            .report
            .entries
            .iter()
            .any(|e| e.level() == mapping::Level::Warning)
    );
}

// Renamed objects map in both directions, with or without the x: prefix; others keep their name.
#[test]
fn target_object_follows_renames_in_both_directions() {
    let mapping = Mapping::embedded().expect("mapping");
    for (direction, input, expected) in [
        (Direction::Forward, "SpamLlm", "x:SpamAi"),
        (Direction::Forward, "x:SpamLlm", "x:SpamAi"),
        (Direction::Reverse, "x:SpamAi", "x:SpamLlm"),
        (Direction::Reverse, "SpamAi", "x:SpamLlm"),
        (Direction::Forward, "Domain", "x:Domain"),
        (Direction::Reverse, "x:Domain", "x:Domain"),
    ] {
        assert_eq!(
            &*mapping.target_object(direction, input),
            expected,
            "{direction:?} {input}"
        );
    }
}

#[test]
fn references_follow_nested_objects_and_resolve_ids() {
    // An account's domain and its encryption key are both found, in either schema version.
    let mapping = Mapping::embedded().expect("mapping");
    let account = json!({
        "@type": "User",
        "name": "alice",
        "domainId": "b",
        "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true}
    });
    for version in [SchemaVersion::V016, SchemaVersion::V1] {
        for object in ["Account", "x:Account"] {
            assert_eq!(
                mapping.references(version, object, &account),
                vec![("x:Domain", 1), ("x:PublicKey", 3)],
                "{version:?} {object}"
            );
        }
    }
}

#[test]
fn reference_fields_list_nested_paths() {
    // The schema walk reaches references inside union variants and top-level ids.
    let mapping = Mapping::embedded().expect("mapping");
    for version in [SchemaVersion::V016, SchemaVersion::V1] {
        let fields = mapping.reference_fields(version);
        for (object, path) in [
            ("x:Account", "encryptionAtRest/publicKey"),
            ("x:Account", "domainId"),
            ("x:PublicKey", "accountId"),
        ] {
            assert!(
                fields.iter().any(|(o, p)| &**o == object && &**p == path),
                "{version:?}: {object} {path} missing"
            );
        }
    }
}

#[test]
fn write_plan_splits_a_cycle_of_target_objects_without_converting() {
    // v0.16 Account and PublicKey referring to each other: one placeholder write plus one deferred patch, nothing converted.
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let target = |key: &str, value: Value| mapping::TargetObject {
        source: ObjectKey::parse(key).expect("key"),
        key: ObjectKey::parse(key).expect("key"),
        value,
    };
    let account = json!({"@type": "User", "name": "erin", "domainId": "z",
                         "encryptionAtRest": {"@type": "Aes256", "publicKey": "d", "encryptOnAppend": true, "allowSpamTraining": false}});
    let key = json!({"accountId": "c", "description": "erin", "key": "k"});
    let outcome = mapping
        .session(Direction::Reverse, &answers, options())
        .write_plan(vec![
            target("x:PublicKey/d", key.clone()),
            target("x:Account/c", account.clone()),
        ]);
    let order: Vec<String> = outcome.objects.iter().map(|o| o.key.to_string()).collect();
    assert_eq!(order, ["x:Account/c", "x:PublicKey/d"]);
    assert_eq!(
        outcome.objects[0].value["encryptionAtRest"],
        json!({"@type": "Disabled"})
    );
    assert_eq!(outcome.objects[0].value["domainId"], json!("z"));
    assert_eq!(outcome.objects[1].value, key);
    assert_eq!(outcome.deferred.len(), 1);
    assert_eq!(outcome.deferred[0].key.to_string(), "x:Account/c");
    assert_eq!(
        outcome.deferred[0].properties.get("encryptionAtRest"),
        account.get("encryptionAtRest")
    );
    assert!(outcome.report.errors().next().is_none());
}

// Colliding EventTracingLevel objects merge into the lowest id at the most verbose level, and every merged source is reported with its event and level.
#[test]
fn event_tracing_levels_merge_at_the_most_verbose_level() {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::parse("x:EventTracingLevel/c").expect("key"),
                value: json!({"event": "arc.invalid-cv", "level": "trace"}),
            },
            SourceObject {
                key: ObjectKey::parse("x:EventTracingLevel/b").expect("key"),
                value: json!({"event": "arc.chain-too-long", "level": "error"}),
            },
        ]);
    let [kept] = outcome.objects.as_slice() else {
        panic!("expected one object: {:?}", outcome.objects);
    };
    assert_eq!(kept.source.to_string(), "x:EventTracingLevel/b");
    assert_eq!(kept.value["level"], json!("trace"));
    let text: Vec<String> = outcome
        .report
        .entries
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        text.iter().any(|t| t.contains("x:EventTracingLevel/c")
            && t.contains("merged into x:EventTracingLevel/b")
            && t.contains("\"arc.invalid-cv\" at level trace")),
        "{text:?}"
    );
    assert!(
        text.iter().any(|t| t.contains("key_merge")
            && t.contains("level trace")
            && t.contains("\"arc.chain-too-long\" at level error")),
        "{text:?}"
    );
}

#[test]
fn references_outside_the_tenant_fall_back_like_missing_ones() {
    // A tenant domain using an ACME provider of no tenant or another tenant falls back to manual certificates; one of its own tenant is kept.
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::default();
    let provider = |id: u64, tenant: Option<&str>| {
        let mut value = json!({
            "directory": "https://acme.example.org/directory",
            "challengeType": "TlsAlpn01",
            "contact": {"postmaster@example.org": true},
            "accountUri": "https://acme.example.org/acct/42",
            "accountKey": "key",
        });
        if let Some(tenant) = tenant {
            value["memberTenantId"] = tenant.into();
        }
        SourceObject {
            key: ObjectKey::with_id("x:AcmeProvider", id),
            value,
        }
    };
    let domain = |id: u64, provider: &str| SourceObject {
        key: ObjectKey::with_id("x:Domain", id),
        value: json!({
            "name": format!("d{id}.example.org"),
            "memberTenantId": "b",
            "certificateManagement": {"@type": "Automatic", "acmeProviderId": provider},
        }),
    };
    let outcome = mapping
        .session(Direction::Forward, &answers, options())
        .convert_all(vec![
            SourceObject {
                key: ObjectKey::with_id("x:Tenant", 1),
                value: json!({"name": "first"}),
            },
            SourceObject {
                key: ObjectKey::with_id("x:Tenant", 2),
                value: json!({"name": "second"}),
            },
            provider(10, None),
            provider(11, Some("b")),
            provider(12, Some("c")),
            domain(20, "k"),
            domain(21, "l"),
            domain(22, "m"),
        ]);
    assert!(outcome.is_complete(), "{:?}", outcome.report.entries);
    let management = |id: u64| {
        outcome
            .objects
            .iter()
            .find(|o| o.key == ObjectKey::with_id("x:Domain", id))
            .map(|o| o.value["certificateManagement"].clone())
    };
    assert_eq!(management(20), Some(json!({"@type": "Manual"})));
    assert_eq!(
        management(21),
        Some(json!({"@type": "Automatic", "acmeProviderId": "l"}))
    );
    assert_eq!(management(22), Some(json!({"@type": "Manual"})));
    let outside: Vec<&ObjectKey> = outcome
        .report
        .entries
        .iter()
        .filter_map(|e| match &e.change {
            Change::ReferenceOutsideTenant { target } => Some(target),
            _ => None,
        })
        .collect();
    assert_eq!(
        outside,
        [
            &ObjectKey::with_id("x:AcmeProvider", 10),
            &ObjectKey::with_id("x:AcmeProvider", 12)
        ],
        "{:?}",
        outcome.report.entries
    );
}
