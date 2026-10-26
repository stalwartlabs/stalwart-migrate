/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use crate::{
    ids::{BlobHash, Collection, LogCollection},
    registry::RegistryKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Verify,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Verify => "verify",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), Severity,
            "info" => Severity::Info,
            "warning" => Severity::Warning,
            "error" => Severity::Error,
            "verify" => Severity::Verify,
        )
        .copied()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IssueKind {
    Dropped,
    Truncated,
    Clamped,
    Skipped,
    Changed,
    Failed,
    Mismatch,
}

impl IssueKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            IssueKind::Dropped => "dropped",
            IssueKind::Truncated => "truncated",
            IssueKind::Clamped => "clamped",
            IssueKind::Skipped => "skipped",
            IssueKind::Changed => "changed",
            IssueKind::Failed => "failed",
            IssueKind::Mismatch => "mismatch",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::map!(value.as_bytes(), IssueKind,
            "dropped" => IssueKind::Dropped,
            "truncated" => IssueKind::Truncated,
            "clamped" => IssueKind::Clamped,
            "skipped" => IssueKind::Skipped,
            "changed" => IssueKind::Changed,
            "failed" => IssueKind::Failed,
            "mismatch" => IssueKind::Mismatch,
        )
        .copied()
    }
}

impl fmt::Display for IssueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    None,
    Document {
        collection: Collection,
        document_id: u32,
    },
    Registry(RegistryKey),
    Blob(BlobHash),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Explanation {
    Missing,
    DeadProperty(Box<str>),
    DeadAttribute(Box<str>, Box<str>),
    DeadProperties,
    DisplayName,
    TimeZone(u32),
    DefaultAlert(u32, Box<str>),
    MailboxRole,
    Keyword(Box<str>),
    Keywords(u32),
    Mailboxes(u32),
    ExtraHeaders,
    ReceivedAt,
    LogRow(LogCollection, u64),
}

impl Explanation {
    pub fn encode(&self) -> String {
        match self {
            Explanation::Missing => "missing".into(),
            Explanation::DeadProperty(label) => format!("deadProperty:{label}"),
            Explanation::DeadAttribute(label, attribute) => {
                format!("deadAttribute:{attribute}={label}")
            }
            Explanation::DeadProperties => "deadProperties".into(),
            Explanation::DisplayName => "displayName".into(),
            Explanation::TimeZone(account_id) => format!("timeZone:{account_id}"),
            Explanation::DefaultAlert(account_id, id) => format!("defaultAlert:{account_id}:{id}"),
            Explanation::MailboxRole => "mailboxRole".into(),
            Explanation::Keyword(keyword) => format!("keyword:{keyword}"),
            Explanation::Keywords(limit) => format!("keywords:{limit}"),
            Explanation::Mailboxes(limit) => format!("mailboxes:{limit}"),
            Explanation::ExtraHeaders => "extraHeaders".into(),
            Explanation::ReceivedAt => "receivedAt".into(),
            Explanation::LogRow(collection, change_id) => {
                format!("logRow:{}:{change_id}", collection.as_u8())
            }
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        let (head, tail) = value.split_once(':').unwrap_or((value, ""));
        hashify::fnc_map!(head.as_bytes(),
            "missing" => Some(Explanation::Missing),
            "deadProperty" => Some(Explanation::DeadProperty(tail.into())),
            "deadAttribute" => tail
                .split_once('=')
                .map(|(attribute, label)| Explanation::DeadAttribute(label.into(), attribute.into())),
            "deadProperties" => Some(Explanation::DeadProperties),
            "displayName" => Some(Explanation::DisplayName),
            "timeZone" => tail.parse().ok().map(Explanation::TimeZone),
            "defaultAlert" => tail.split_once(':').and_then(|(account_id, id)| {
                Some(Explanation::DefaultAlert(account_id.parse().ok()?, id.into()))
            }),
            "mailboxRole" => Some(Explanation::MailboxRole),
            "keyword" => Some(Explanation::Keyword(tail.into())),
            "keywords" => tail.parse().ok().map(Explanation::Keywords),
            "mailboxes" => tail.parse().ok().map(Explanation::Mailboxes),
            "extraHeaders" => Some(Explanation::ExtraHeaders),
            "receivedAt" => Some(Explanation::ReceivedAt),
            "logRow" => tail.split_once(':').and_then(|(collection, change_id)| {
                Some(Explanation::LogRow(
                    LogCollection::from_u8(collection.parse().ok()?)?,
                    change_id.parse().ok()?,
                ))
            }),
            _ => None
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Conflict,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub severity: Severity,
    pub kind: IssueKind,
    pub subject: Subject,
    pub message: Box<str>,
    pub explains: Option<Explanation>,
    pub rejection: Option<Rejection>,
}

impl Issue {
    pub fn new(
        severity: Severity,
        kind: IssueKind,
        subject: Subject,
        message: impl Into<Box<str>>,
    ) -> Self {
        Issue {
            severity,
            kind,
            subject,
            message: message.into(),
            explains: None,
            rejection: None,
        }
    }

    pub fn rejected(mut self, rejection: Rejection) -> Self {
        self.rejection = Some(rejection);
        self
    }

    pub fn explaining(mut self, explanation: Explanation) -> Self {
        self.explains = Some(explanation);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteOutcome {
    pub issues: Vec<Issue>,
}

impl WriteOutcome {
    pub const fn ok() -> Self {
        WriteOutcome { issues: Vec::new() }
    }

    pub fn merge(&mut self, other: WriteOutcome) {
        if self.issues.is_empty() {
            self.issues = other.issues;
        } else {
            self.issues.extend(other.issues);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_kind_names_round_trip() {
        for kind in [
            IssueKind::Dropped,
            IssueKind::Truncated,
            IssueKind::Clamped,
            IssueKind::Skipped,
            IssueKind::Changed,
            IssueKind::Failed,
            IssueKind::Mismatch,
        ] {
            assert_eq!(IssueKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(IssueKind::parse("verify"), None);
    }

    #[test]
    fn explanations_round_trip() {
        for explanation in [
            Explanation::Missing,
            Explanation::DeadProperty("{urn:x}a:b".into()),
            Explanation::DeadAttribute("{urn:x=y}a".into(), "p:b".into()),
            Explanation::DeadProperties,
            Explanation::DisplayName,
            Explanation::TimeZone(7),
            Explanation::DefaultAlert(7, "a:1".into()),
            Explanation::MailboxRole,
            Explanation::Keyword("$a:b".into()),
            Explanation::Keywords(100),
            Explanation::Mailboxes(5),
            Explanation::ExtraHeaders,
            Explanation::ReceivedAt,
            Explanation::LogRow(LogCollection::VanishedEmail, 42),
        ] {
            assert_eq!(Explanation::parse(&explanation.encode()), Some(explanation));
        }
        assert_eq!(Explanation::parse("timeZone:x"), None);
        assert_eq!(Explanation::parse("other"), None);
    }
}
