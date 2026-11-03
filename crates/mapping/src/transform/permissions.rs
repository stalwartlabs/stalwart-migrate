use rustc_hash::FxHashSet;
use serde_json::{Map, Value};

use crate::{
    engine::{Flow, SourceObject, Walker},
    ids::Instance,
    prompts::PromptId,
    rules::EnumRule,
    transform::Transform,
};

const PERMISSION_ENUM: &str = "Permission";
const ENABLED: &str = "enabledPermissions";
const DISABLED: &str = "disabledPermissions";
const CREDENTIAL: &str = "permissions";
const PERMISSION_PROPERTIES: [&str; 3] = [DISABLED, ENABLED, CREDENTIAL];
const SIGN_IN: &str = "authenticate";
const ROLE_OBJECT: &str = "x:Role";
const AUTHENTICATION_OBJECT: &str = "x:Authentication";
const PERCENT: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleKind {
    User,
    Group,
    Tenant,
    Superuser,
}

impl RoleKind {
    const ALL: [RoleKind; 4] = [
        RoleKind::User,
        RoleKind::Group,
        RoleKind::Tenant,
        RoleKind::Superuser,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    const fn list(self) -> &'static str {
        match self {
            RoleKind::User => "defaultUserRoleIds",
            RoleKind::Group => "defaultGroupRoleIds",
            RoleKind::Tenant => "defaultTenantRoleIds",
            RoleKind::Superuser => "defaultAdminRoleIds",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            RoleKind::User => "User",
            RoleKind::Group => "Group",
            RoleKind::Tenant => "Tenant Administrator",
            RoleKind::Superuser => "System Administrator",
        }
    }

    fn holds(self, permission: &str) -> bool {
        Self::kinds_of(permission) & self.bit() != 0
    }

    fn kinds_of(permission: &str) -> u8 {
        if let Some(kinds) = hashify::map!(permission.as_bytes(), u8,
            "authenticate" => USER | SUPERUSER | TENANT,
            "authenticateWithAlias" => USER | SUPERUSER | TENANT,
            "interactAi" => USER | SUPERUSER | TENANT,
            "impersonate" => SUPERUSER,
            "unlimitedRequests" => SUPERUSER,
            "unlimitedUploads" => SUPERUSER,
            "liveMetrics" => SUPERUSER,
            "liveTracing" => SUPERUSER,
            "fetchAnyBlob" => SUPERUSER | TENANT,
            "liveDeliveryTest" => SUPERUSER | TENANT,
        ) {
            return *kinds;
        }
        let has_prefix = |prefixes: &[&str]| prefixes.iter().any(|p| permission.starts_with(p));
        if has_prefix(MEMBER_PREFIXES) {
            USER | GROUP
        } else if has_prefix(SELF_SERVICE_PREFIXES)
            || (permission.starts_with("sysSpamTrainingSample") && !permission.contains("Create"))
        {
            USER | GROUP | SUPERUSER
        } else if has_prefix(CREDENTIAL_PREFIXES) {
            USER | SUPERUSER
        } else if has_prefix(TENANT_PREFIXES) {
            TENANT | SUPERUSER
        } else {
            SUPERUSER
        }
    }
}

const USER: u8 = RoleKind::User.bit();
const GROUP: u8 = RoleKind::Group.bit();
const TENANT: u8 = RoleKind::Tenant.bit();
const SUPERUSER: u8 = RoleKind::Superuser.bit();

const MEMBER_PREFIXES: &[&str] = &["jmap", "imap", "pop3", "calendar", "email", "dav", "sieve"];
const SELF_SERVICE_PREFIXES: &[&str] = &[
    "sysMaskedEmail",
    "sysArchivedItem",
    "sysAccountSettings",
    "sysPublicKey",
];
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sysAccountPassword",
    "sysApiKey",
    "sysAppPassword",
    "sysOAuthGrant",
];
const TENANT_PREFIXES: &[&str] = &[
    "sysDomain",
    "sysDkimSignature",
    "sysAcmeProvider",
    "sysAccount",
    "sysRole",
    "sysOAuthClient",
    "sysMailingList",
    "sysExternalReport",
    "sysDnsServer",
    "sysQueuedMessage",
];

#[derive(Debug, Default)]
pub(crate) struct DefaultRoles {
    roles: Vec<(Instance, u8)>,
}

impl DefaultRoles {
    pub(crate) fn scan(inputs: &[SourceObject]) -> Self {
        let mut roles: Vec<(Instance, u8)> = Vec::new();
        let Some(authentication) = inputs
            .iter()
            .find(|input| &*input.key.object == AUTHENTICATION_OBJECT)
        else {
            return DefaultRoles { roles };
        };
        for kind in RoleKind::ALL {
            let ids = authentication
                .value
                .get(kind.list())
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|ids| ids.keys())
                .filter_map(|id| Instance::parse_reference(id));
            for id in ids {
                match roles.iter_mut().find(|(role, _)| *role == id) {
                    Some((_, kinds)) => *kinds |= kind.bit(),
                    None => roles.push((id, kind.bit())),
                }
            }
        }
        DefaultRoles { roles }
    }

    fn kinds(&self, role: &Instance) -> u8 {
        self.roles
            .iter()
            .find(|(id, _)| id == role)
            .map_or(0, |(_, bits)| *bits)
    }
}

pub(super) fn permissions(
    w: &mut Walker,
    src: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Flow {
    let session = w.session;
    let grants = &session.rules.grants;
    let mut grant_answer = None;
    for property in PERMISSION_PROPERTIES {
        let Some(mut value) = src.remove(property) else {
            continue;
        };
        let Value::Object(members) = &mut value else {
            out.insert(property.into(), value);
            continue;
        };
        let granted: Vec<&str> = grants
            .iter()
            .filter(|g| {
                !members.contains_key(&*g.permission)
                    && g.when_any.iter().any(|o| members.contains_key(&**o))
            })
            .map(|g| &*g.permission)
            .collect();
        w.path.push(property);
        w.remap_enum_keys(PERMISSION_ENUM, members);
        if !granted.is_empty() {
            let answer = grant_answer.get_or_insert_with(|| w.ask_global(PromptId::NewPermissions));
            if answer.str("action") == Some("grant") {
                for permission in &granted {
                    members.insert((*permission).to_string(), Value::Bool(true));
                }
                w.transformed(
                    Transform::Permissions,
                    "",
                    format!("granted {}", granted.join(", ")),
                );
            }
        }
        if property == ENABLED {
            let disabled = out.get(DISABLED).and_then(Value::as_object);
            let mut added = Vec::new();
            let is_default_role = &*w.key.object == ROLE_OBJECT
                && complete_default_role(w, members, disabled, &mut added);
            if !is_default_role && members.contains_key(SIGN_IN) {
                for permission in &session.rules.sign_in_grants {
                    grant(w, members, disabled, permission, &mut added);
                }
                report(
                    w,
                    "granted to a role or list that allows sign-in",
                    &mut added,
                );
            }
        }
        w.path.pop();
        out.insert(property.into(), value);
    }
    Flow::Keep
}

fn grant<'x>(
    w: &Walker,
    members: &mut Map<String, Value>,
    disabled: Option<&Map<String, Value>>,
    permission: &'x str,
    added: &mut Vec<&'x str>,
) {
    if !members.contains_key(permission)
        && !disabled.is_some_and(|d| d.contains_key(permission))
        && w.session.target.enum_has(PERMISSION_ENUM, permission)
    {
        members.insert(permission.into(), Value::Bool(true));
        added.push(permission);
    }
}

fn report(w: &mut Walker, reason: &str, added: &mut Vec<&str>) {
    if !added.is_empty() {
        w.transformed(
            Transform::Permissions,
            "",
            format!("{reason}: {}", added.join(", ")),
        );
        added.clear();
    }
}

fn complete_default_role<'s>(
    w: &mut Walker<'s, '_>,
    members: &mut Map<String, Value>,
    disabled: Option<&Map<String, Value>>,
    added: &mut Vec<&'s str>,
) -> bool {
    let session = w.session;
    let Some(permissions) = session.target.enum_def(PERMISSION_ENUM) else {
        return false;
    };
    let kinds = w.facts.default_roles.kinds(&w.key.instance);
    if kinds == 0 {
        return false;
    }
    let renamed: FxHashSet<&str> = session
        .rules
        .enums
        .get(PERMISSION_ENUM)
        .into_iter()
        .flat_map(|table| table.values())
        .filter_map(|rule| match rule {
            EnumRule::Rename(targets) => Some(targets.iter().map(|t| &**t)),
            EnumRule::Drop => None,
        })
        .flatten()
        .collect();
    let defaults = &session.rules.default_roles;
    let is_new = |permission: &str| {
        defaults.added_in_v016.iter().any(|p| &**p == permission)
            || !(session.source.enum_has(PERMISSION_ENUM, permission)
                || renamed.contains(permission))
    };
    let mut completed = false;
    for kind in RoleKind::ALL
        .into_iter()
        .filter(|kind| kinds & kind.bit() != 0)
    {
        let mut seeded = 0;
        let mut held = 0;
        for permission in permissions.values.iter().map(|p| &**p) {
            if kind.holds(permission) && !is_new(permission) {
                seeded += 1;
                held += usize::from(members.contains_key(permission));
            }
        }
        if seeded == 0 || held * PERCENT < seeded * usize::from(defaults.min_coverage) {
            continue;
        }
        completed = true;
        for permission in permissions.values.iter().map(|p| &**p) {
            if kind.holds(permission) && is_new(permission) {
                grant(w, members, disabled, permission, added);
            }
        }
        let reason = format!("completed with the v1 {} role defaults", kind.label());
        report(w, &reason, added);
    }
    completed
}
