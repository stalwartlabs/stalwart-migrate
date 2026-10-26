/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::failpoint::failpoint;
use model::{
    Category, GlobalBatch, GlobalCategory, Issue, IssueKind, RegistryKey, Severity, Source,
    SpamModelChange, SpamModelKind, SpamModelRecord, Subject, Target,
};
use state::StateStore;

use super::{RegistryConverter, context::Context, error::RunError};

const SPAM_MODEL_ID: u64 = 0;

fn object_of(issue: &Issue) -> Option<&str> {
    match &issue.subject {
        Subject::Registry(key) => Some(&key.object),
        _ => None,
    }
}

fn unreadable_kinds(issues: &[Issue]) -> Vec<SpamModelKind> {
    issues
        .iter()
        .filter(|issue| issue.kind == IssueKind::Skipped)
        .filter_map(|issue| object_of(issue).and_then(SpamModelKind::from_object))
        .collect()
}

impl<S: Source, T: Target, St: StateStore, C: RegistryConverter> Context<S, T, St, C> {
    pub(super) async fn write_final_spam_model<R: Source>(
        &self,
        reader: &R,
    ) -> Result<u64, RunError> {
        if !self.options.categories.contains(Category::SpamModel) {
            return Ok(0);
        }
        self.retry(|| self.source.catch_up()).await?;
        let (records, source_issues) = self.spam_model_of(&*self.source).await?;
        let unreadable_in_source = unreadable_kinds(&source_issues);
        let changes: Vec<SpamModelChange> = SpamModelKind::ALL
            .into_iter()
            .filter(|kind| !unreadable_in_source.contains(kind))
            .map(
                |kind| match records.iter().find(|record| record.kind() == kind) {
                    Some(record) => SpamModelChange::Write(record.clone()),
                    None => SpamModelChange::Delete(kind),
                },
            )
            .collect();
        let outcome = self
            .retry(|| self.target.apply_final_spam_model(&changes))
            .await?;
        failpoint!("spam.final");
        let issues = outcome.issues;

        self.retry(|| reader.catch_up()).await?;
        let (written, reader_issues) = self.spam_model_of(reader).await?;
        let unreadable_in_target = unreadable_kinds(&reader_issues);
        let mut notes = Vec::new();
        let mut mismatches = Vec::new();
        for kind in SpamModelKind::ALL {
            let object = kind.as_str();
            let subject = || Subject::Registry(RegistryKey::new(object, SPAM_MODEL_ID));
            let actual = written.iter().find(|record| record.kind() == kind);
            if unreadable_in_source.contains(&kind) {
                let source_issue = source_issues
                    .iter()
                    .find(|issue| object_of(issue) == Some(object));
                let reason = source_issue.map_or("", |issue| issue.message.as_ref());
                notes.push(match actual {
                    Some(_) => Issue::new(
                        Severity::Info,
                        IssueKind::Changed,
                        subject(),
                        format!(
                            "the source spam model cannot be read ({reason}); the target already holds a readable model and it was kept"
                        ),
                    ),
                    None => Issue::new(
                        Severity::Warning,
                        IssueKind::Skipped,
                        subject(),
                        format!(
                            "the source spam model cannot be read ({reason}); the stored model was left untouched"
                        ),
                    ),
                });
                continue;
            }
            let skipped = issues
                .iter()
                .any(|issue| issue.kind == IssueKind::Skipped && object_of(issue) == Some(object));
            if skipped {
                continue;
            }
            let expected = records.iter().find(|record| record.kind() == kind);
            let message = if unreadable_in_target.contains(&kind) {
                "the spam model written by the final step cannot be read back from the target"
            } else {
                match (expected, actual) {
                    (Some(expected), Some(actual)) if expected.bit_eq(actual) => continue,
                    (None, None) => continue,
                    (Some(_), Some(_)) => {
                        "the spam model read back from the target differs from the source"
                    }
                    (Some(_), None) => "the spam model written by the final step is missing",
                    (None, Some(_)) => {
                        "the source has no spam model but the target still holds one"
                    }
                }
            };
            mismatches.push(Issue::new(
                Severity::Verify,
                IssueKind::Mismatch,
                subject(),
                message,
            ));
        }
        let count = mismatches.len() as u64;
        self.report(None, issues).await?;
        self.report(None, notes).await?;
        self.report(None, mismatches).await?;
        Ok(count)
    }

    async fn spam_model_of<X: Source>(
        &self,
        source: &X,
    ) -> Result<(Vec<SpamModelRecord>, Vec<Issue>), RunError> {
        let limit = self.options.tuning.batch_ops;
        let mut records = Vec::new();
        let mut issues = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            self.check_shutdown()?;
            let page = self
                .retry(|| source.global_page(GlobalCategory::SpamModel, cursor.as_deref(), limit))
                .await?;
            issues.extend(page.issues);
            if let GlobalBatch::SpamModel(batch) = page.batch {
                records.extend(batch);
            }
            match page.next {
                Some(next) if cursor.as_deref() != Some(next.as_slice()) => cursor = Some(next),
                Some(_) => {
                    return Err(
                        model::Error::fatal("source spam model pages did not advance").into(),
                    );
                }
                None => return Ok((records, issues)),
            }
        }
    }
}
