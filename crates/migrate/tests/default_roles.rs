/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::BTreeSet;

use mapping::{
    Answers, Direction, Edition, Mapping, ObjectKey, Options, Outcome, SourceObject, ToolQuestions,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

const ADDED_IN_V016: &[&str] = &["jmapFileNodeCopy", "scimAccess"];
const USER: &str = "x:Role/b";
const GROUP: &str = "x:Role/c";
const TENANT: &str = "x:Role/d";
const ADMIN: &str = "x:Role/e";

fn names<T: Serialize>(permissions: &[T]) -> BTreeSet<String> {
    permissions
        .iter()
        .map(|p| match serde_json::to_value(p).expect("permission") {
            Value::String(name) => name,
            other => panic!("permission serialized as {other}"),
        })
        .collect()
}

fn set(names: &BTreeSet<String>) -> Value {
    Value::Object(
        names
            .iter()
            .map(|n| (n.clone(), Value::Bool(true)))
            .collect(),
    )
}

fn role(key: &str, description: &str, enabled: &BTreeSet<String>) -> SourceObject {
    SourceObject {
        key: ObjectKey::parse(key).expect("key"),
        value: json!({"description": description, "enabledPermissions": set(enabled),
                      "disabledPermissions": {}, "roleIds": {}}),
    }
}

struct Seeds {
    user: BTreeSet<String>,
    group: BTreeSet<String>,
    tenant: BTreeSet<String>,
    superuser: BTreeSet<String>,
}

impl Seeds {
    fn v016() -> Self {
        let defaults = common_v016::auth::permissions::DefaultPermissions::default();
        Seeds {
            user: names(&defaults.user),
            group: names(&defaults.group),
            tenant: names(&defaults.tenant),
            superuser: names(&defaults.superuser),
        }
    }

    fn v016_0() -> Self {
        let mut seeds = Seeds::v016();
        for list in [
            &mut seeds.user,
            &mut seeds.group,
            &mut seeds.tenant,
            &mut seeds.superuser,
        ] {
            list.retain(|p| !ADDED_IN_V016.contains(&p.as_str()));
        }
        seeds
    }

    fn v1() -> Self {
        let defaults = common_v1::auth::permissions::DefaultPermissions::default();
        Seeds {
            user: names(&defaults.user),
            group: names(&defaults.group),
            #[cfg(feature = "enterprise")]
            tenant: names(&defaults.tenant),
            #[cfg(not(feature = "enterprise"))]
            tenant: BTreeSet::new(),
            superuser: names(&defaults.superuser),
        }
    }
}

fn edition() -> Edition {
    if cfg!(feature = "enterprise") {
        Edition::Enterprise
    } else {
        Edition::Oss
    }
}

fn convert(seeds: &Seeds, answers: &str) -> Outcome {
    let mapping = Mapping::embedded().expect("mapping");
    let answers = Answers::parse(answers).expect("answers");
    let options = Options {
        edition: edition(),
        tool_questions: ToolQuestions::Skip,
        ..Options::default()
    };
    let mut inputs = vec![
        SourceObject {
            key: ObjectKey::singleton("x:Authentication"),
            value: json!({
                "defaultUserRoleIds": {"b": true},
                "defaultGroupRoleIds": {"c": true},
                "defaultTenantRoleIds": {"d": true, "b": true},
                "defaultAdminRoleIds": {"e": true, "b": true},
            }),
        },
        role(USER, "User", &seeds.user),
        role(GROUP, "Group", &seeds.group),
        role(ADMIN, "System Administrator", &seeds.superuser),
    ];
    if edition() == Edition::Enterprise {
        inputs.push(role(TENANT, "Tenant Administrator", &seeds.tenant));
    }
    mapping
        .session(Direction::Forward, &answers, options)
        .convert_all(inputs)
}

fn enabled(outcome: &Outcome, key: &str) -> BTreeSet<String> {
    outcome
        .objects
        .iter()
        .find(|o| o.key.to_string() == key)
        .and_then(|o| o.value.get("enabledPermissions"))
        .and_then(Value::as_object)
        .map(Map::keys)
        .into_iter()
        .flatten()
        .cloned()
        .collect()
}

fn assert_matches_v1(outcome: &Outcome) {
    let v1 = Seeds::v1();
    let mut expected = vec![(USER, &v1.user), (GROUP, &v1.group), (ADMIN, &v1.superuser)];
    if edition() == Edition::Enterprise {
        expected.push((TENANT, &v1.tenant));
    }
    for (key, permissions) in expected {
        let actual = enabled(outcome, key);
        let missing: Vec<_> = permissions.difference(&actual).collect();
        let extra: Vec<_> = actual.difference(permissions).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{key}: missing {missing:?}, extra {extra:?}"
        );
    }
}

const DECLINED: &str = "version = 1\n[global.new_permissions]\naction = \"none\"\n";
const GRANTED: &str = "version = 1\n[global.new_permissions]\naction = \"grant\"\n";

// Default roles seeded by v0.16.0 end up with the v1.0.2 defaults, whatever the new_permissions answer.
#[test]
fn roles_seeded_by_v016_0_get_the_v1_defaults() {
    for answers in [DECLINED, GRANTED] {
        assert_matches_v1(&convert(&Seeds::v016_0(), answers));
    }
}

// Default roles seeded by v0.16.27 also end up with exactly the v1.0.2 defaults.
#[test]
fn roles_seeded_by_v016_27_get_the_v1_defaults() {
    for answers in [DECLINED, GRANTED] {
        assert_matches_v1(&convert(&Seeds::v016(), answers));
    }
}

// The mail.stalw.art case: a System Administrator role seeded before scimAccess existed keeps sysActionCreate and gains scimAccess.
#[cfg(feature = "enterprise")]
#[test]
fn old_system_administrator_gains_scim_access() {
    let outcome = convert(&Seeds::v016_0(), DECLINED);
    let admin = enabled(&outcome, ADMIN);
    assert!(admin.contains("scimAccess"));
    assert!(admin.contains("sysActionCreate"));
}

// Every regular user gets the OAuth consent permissions, also when the operator declined the new permissions.
#[test]
fn users_can_manage_oauth_consents() {
    let outcome = convert(&Seeds::v016_0(), DECLINED);
    let user = enabled(&outcome, USER);
    for permission in [
        "sysOAuthGrantGet",
        "sysOAuthGrantQuery",
        "sysOAuthGrantDestroy",
    ] {
        assert!(user.contains(permission), "{permission}");
    }
}
