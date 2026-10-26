use std::{collections::BTreeMap, fmt};

use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

macro_rules! prompt_ids {
    ($($variant:ident => $name:literal,)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum PromptId {
            $($variant,)*
        }

        impl PromptId {
            pub const ALL: &'static [PromptId] = &[$(PromptId::$variant,)*];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(PromptId::$variant => $name,)*
                }
            }

            pub fn parse(name: &str) -> Option<Self> {
                hashify::map!(name.as_bytes(), PromptId,
                    $($name => PromptId::$variant,)*
                )
                .copied()
            }
        }
    };
}

prompt_ids! {
    BlobStore => "blob_store",
    Edition => "edition",
    Categories => "categories",
    OidcDirectory => "oidc_directory",
    OidcTokenLifetimes => "oidc_token_lifetimes",
    OauthRegistration => "oauth_registration",
    CounterRead => "counter_read",
    HttpForwarded => "http_forwarded",
    SpamAi => "spam_ai",
    AiModelProvider => "ai_model_provider",
    DnsSig0 => "dns_sig0",
    AzureAuth => "azure_auth",
    InMemoryCluster => "in_memory_cluster",
    EnterpriseOnOss => "enterprise_on_oss",
    NewPermissions => "new_permissions",
    ChangedDefaults => "changed_defaults",
}

impl fmt::Display for PromptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptScope {
    Global,
    Instance,
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub value: Box<str>,
    pub label: Box<str>,
}

#[derive(Debug, Clone)]
pub enum FieldKind {
    Choice(Box<[Choice]>),
    MultiChoice(Box<[Choice]>),
    Bool,
    Number { min: Option<f64>, max: Option<f64> },
    String,
    Secret,
    List,
    Object { schema: Box<str> },
    PolicyMap,
}

#[derive(Debug, Clone)]
pub enum Condition {
    Equals { field: Box<str>, value: Box<str> },
    NotEquals { field: Box<str>, value: Box<str> },
}

impl Condition {
    pub fn holds(&self, answer: &crate::answers::Answer) -> bool {
        match self {
            Condition::Equals { field, value } => answer.str(field) == Some(&**value),
            Condition::NotEquals { field, value } => answer.str(field) != Some(&**value),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: Box<str>,
    pub label: Box<str>,
    pub kind: FieldKind,
    pub default: Option<Value>,
    pub when: Option<Condition>,
    pub required: Required,
}

#[derive(Debug, Clone)]
pub enum Required {
    Never,
    Always,
    When(Condition),
}

#[derive(Debug, Clone)]
pub struct Section {
    pub id: Box<str>,
    pub title: Box<str>,
}

#[derive(Debug, Clone)]
pub struct Prompt {
    pub id: PromptId,
    pub section: usize,
    pub scope: PromptScope,
    pub trigger: Box<str>,
    pub objects: Box<[Box<str>]>,
    pub title: Box<str>,
    pub v016: Box<str>,
    pub v1: Box<str>,
    pub recommendation: Option<Box<str>>,
    pub fields: Box<[Field]>,
}

impl Prompt {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| &*f.name == name)
    }
}

#[derive(Debug, Clone)]
pub struct Catalogue {
    sections: Box<[Section]>,
    prompts: Box<[Prompt]>,
}

impl Catalogue {
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawCatalogue = toml::from_str(text).map_err(|source| Error::Toml {
            file: "prompts.toml".into(),
            source,
        })?;
        if raw.version != 1 {
            return Err(Error::catalogue(format!(
                "unsupported version {}",
                raw.version
            )));
        }
        let sections: Box<[Section]> = raw
            .sections
            .into_iter()
            .map(|s| Section {
                id: s.id.into(),
                title: s.title.into(),
            })
            .collect();
        let mut prompts = Vec::with_capacity(PromptId::ALL.len());
        for &id in PromptId::ALL {
            let raw_prompt = raw
                .prompt
                .get(id.as_str())
                .ok_or_else(|| Error::catalogue(format!("missing prompt {id}")))?;
            prompts.push(raw_prompt.parse(id, &sections)?);
        }
        if let Some(unknown) = raw.prompt.keys().find(|k| PromptId::parse(k).is_none()) {
            return Err(Error::catalogue(format!("unknown prompt {unknown}")));
        }
        Ok(Catalogue {
            sections,
            prompts: prompts.into_boxed_slice(),
        })
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    pub fn prompts(&self) -> &[Prompt] {
        &self.prompts
    }

    pub fn prompt(&self, id: PromptId) -> &Prompt {
        &self.prompts[id as usize]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalogue {
    version: u32,
    sections: Vec<RawSection>,
    prompt: BTreeMap<String, RawPrompt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSection {
    id: String,
    title: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrompt {
    section: String,
    scope: String,
    trigger: String,
    #[serde(default)]
    objects: Vec<String>,
    title: String,
    v016: String,
    v1: String,
    recommendation: Option<String>,
    fields: Vec<RawField>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawField {
    name: String,
    label: String,
    kind: String,
    default: Option<toml::Value>,
    options: Option<Vec<RawChoice>>,
    min: Option<f64>,
    max: Option<f64>,
    schema: Option<String>,
    when: Option<RawCondition>,
    required: Option<RawRequired>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRequired {
    Flag(bool),
    When(RawCondition),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChoice {
    value: String,
    label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCondition {
    field: String,
    equals: Option<String>,
    not_equals: Option<String>,
}

impl RawPrompt {
    fn parse(&self, id: PromptId, sections: &[Section]) -> Result<Prompt> {
        let section = sections
            .iter()
            .position(|s| *s.id == *self.section)
            .ok_or_else(|| Error::catalogue(format!("{id}: unknown section {}", self.section)))?;
        let scope = match self.scope.as_str() {
            "global" => PromptScope::Global,
            "instance" => PromptScope::Instance,
            other => return Err(Error::catalogue(format!("{id}: scope {other}"))),
        };
        let fields = self
            .fields
            .iter()
            .map(|f| f.parse(id))
            .collect::<Result<Box<[Field]>>>()?;
        for field in fields.iter() {
            if let Some(
                Condition::Equals { field: other, .. } | Condition::NotEquals { field: other, .. },
            ) = &field.when
                && !fields.iter().any(|f| f.name == *other)
            {
                return Err(Error::catalogue(format!(
                    "{id}.{}: unknown field {other}",
                    field.name
                )));
            }
        }
        Ok(Prompt {
            id,
            section,
            scope,
            trigger: self.trigger.as_str().into(),
            objects: self.objects.iter().map(|o| o.as_str().into()).collect(),
            title: self.title.as_str().into(),
            v016: self.v016.as_str().into(),
            v1: self.v1.as_str().into(),
            recommendation: self.recommendation.as_deref().map(Into::into),
            fields,
        })
    }
}

impl RawField {
    fn parse(&self, id: PromptId) -> Result<Field> {
        let err = |detail: &str| Error::catalogue(format!("{id}.{}: {detail}", self.name));
        let choices = || {
            self.options
                .as_ref()
                .filter(|o| !o.is_empty())
                .map(|o| {
                    o.iter()
                        .map(|c| Choice {
                            value: c.value.as_str().into(),
                            label: c.label.as_str().into(),
                        })
                        .collect::<Box<[Choice]>>()
                })
                .ok_or_else(|| err("options required"))
        };
        let kind = match self.kind.as_str() {
            "choice" => FieldKind::Choice(choices()?),
            "multi_choice" => FieldKind::MultiChoice(choices()?),
            "bool" => FieldKind::Bool,
            "number" => FieldKind::Number {
                min: self.min,
                max: self.max,
            },
            "string" => FieldKind::String,
            "secret" => FieldKind::Secret,
            "list" => FieldKind::List,
            "object" => FieldKind::Object {
                schema: self
                    .schema
                    .as_deref()
                    .ok_or_else(|| err("schema required"))?
                    .into(),
            },
            "policy_map" => FieldKind::PolicyMap,
            other => return Err(err(&format!("unknown kind {other}"))),
        };
        let condition = |c: &RawCondition| match (&c.equals, &c.not_equals) {
            (Some(v), None) => Ok(Condition::Equals {
                field: c.field.as_str().into(),
                value: v.as_str().into(),
            }),
            (None, Some(v)) => Ok(Condition::NotEquals {
                field: c.field.as_str().into(),
                value: v.as_str().into(),
            }),
            _ => Err(err("condition needs equals or not_equals")),
        };
        let required = match &self.required {
            None | Some(RawRequired::Flag(false)) => Required::Never,
            Some(RawRequired::Flag(true)) => Required::Always,
            Some(RawRequired::When(c)) => Required::When(condition(c)?),
        };
        let when = self
            .when
            .as_ref()
            .map(|c| match (&c.equals, &c.not_equals) {
                (Some(v), None) => Ok(Condition::Equals {
                    field: c.field.as_str().into(),
                    value: v.as_str().into(),
                }),
                (None, Some(v)) => Ok(Condition::NotEquals {
                    field: c.field.as_str().into(),
                    value: v.as_str().into(),
                }),
                _ => Err(err("when needs equals or not_equals")),
            })
            .transpose()?;
        let default = self
            .default
            .clone()
            .map(|v| serde_json::to_value(v).map_err(|e| err(&e.to_string())))
            .transpose()?;
        let field = Field {
            name: self.name.as_str().into(),
            label: self.label.as_str().into(),
            kind,
            default,
            when,
            required,
        };
        if let Some(default) = &field.default
            && let Err(detail) = crate::answers::check_value(&field, default)
        {
            return Err(err(&format!("default: {detail}")));
        }
        Ok(field)
    }
}
