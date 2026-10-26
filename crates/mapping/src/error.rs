use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Io {
        path: Box<str>,
        source: io::Error,
    },
    Json {
        file: Box<str>,
        source: serde_json::Error,
    },
    Toml {
        file: Box<str>,
        source: toml::de::Error,
    },
    Schema {
        file: Box<str>,
        detail: String,
    },
    Rule {
        file: Box<str>,
        key: String,
        detail: String,
    },
    Catalogue {
        detail: String,
    },
    Answers {
        detail: String,
    },
}

impl Error {
    pub(crate) fn rule(file: &str, key: impl Into<String>, detail: impl Into<String>) -> Self {
        Error::Rule {
            file: file.into(),
            key: key.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn schema(file: &str, detail: impl Into<String>) -> Self {
        Error::Schema {
            file: file.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn catalogue(detail: impl Into<String>) -> Self {
        Error::Catalogue {
            detail: detail.into(),
        }
    }

    pub(crate) fn answers(detail: impl Into<String>) -> Self {
        Error::Answers {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{path}: {source}"),
            Error::Json { file, source } => write!(f, "{file}: invalid JSON: {source}"),
            Error::Toml { file, source } => write!(f, "{file}: invalid TOML: {source}"),
            Error::Schema { file, detail } => write!(f, "{file}: invalid schema: {detail}"),
            Error::Rule { file, key, detail } => write!(f, "{file}: rule {key}: {detail}"),
            Error::Catalogue { detail } => write!(f, "prompts.toml: {detail}"),
            Error::Answers { detail } => write!(f, "answers: {detail}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Json { source, .. } => Some(source),
            Error::Toml { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
