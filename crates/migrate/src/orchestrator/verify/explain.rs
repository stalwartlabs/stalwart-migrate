/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use model::{Collection, Explanation, IssueKind, LogCollection, RegistryKey, Severity};
use rustc_hash::{FxHashMap, FxHashSet};
use state::{ReportRow, RunId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Scope {
    pub(super) since: Option<RunId>,
    pub(super) accepted: Option<RunId>,
}

impl Scope {
    fn explanation(self, row: &ReportRow) -> Option<Explanation> {
        if self.since.is_some_and(|since| row.run_id < since) {
            return None;
        }
        let accepted = row.severity == Severity::Error
            && self.accepted.is_some_and(|accepted| row.run_id <= accepted);
        match (row.severity, &row.explains) {
            (Severity::Info | Severity::Verify, _) => None,
            (Severity::Error, Some(_)) | (_, Some(Explanation::LogRow(..))) if !accepted => None,
            (_, Some(explanation)) => Some(explanation.clone()),
            (Severity::Warning, None) => None,
            (Severity::Error, None) => (accepted
                && matches!(
                    IssueKind::parse(&row.category),
                    Some(IssueKind::Failed | IssueKind::Skipped)
                ))
            .then_some(Explanation::Missing),
        }
    }
}

#[derive(Default)]
pub(super) struct Explanations {
    documents: FxHashMap<(Collection, u32), Vec<Explanation>>,
    log_rows: FxHashSet<(LogCollection, u64)>,
}

impl Explanations {
    pub(super) fn from_rows(rows: &[ReportRow], scope: Scope) -> Self {
        let mut explanations = Explanations::default();
        for row in rows {
            let Some(explanation) = scope.explanation(row) else {
                continue;
            };
            if let Explanation::LogRow(collection, change_id) = explanation {
                explanations.log_rows.insert((collection, change_id));
                continue;
            }
            let (Some(collection), Some(document_id)) = (
                row.object.as_deref().and_then(Collection::parse),
                row.object_id.and_then(|id| u32::try_from(id).ok()),
            ) else {
                continue;
            };
            let list = explanations
                .documents
                .entry((collection, document_id))
                .or_default();
            if !list.contains(&explanation) {
                list.push(explanation);
            }
        }
        explanations
    }

    pub(super) fn get(&self, collection: Collection, document_id: u32) -> &[Explanation] {
        self.documents
            .get(&(collection, document_id))
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn log_row(&self, collection: LogCollection, change_id: u64) -> bool {
        self.log_rows.contains(&(collection, change_id))
    }
}

pub(super) fn missing_registry(rows: &[ReportRow], scope: Scope) -> FxHashSet<RegistryKey> {
    rows.iter()
        .filter(|row| scope.explanation(row) == Some(Explanation::Missing))
        .filter_map(|row| {
            let object = row.object.clone()?;
            Some(match row.object_id {
                Some(id) => RegistryKey::new(object, id),
                None => RegistryKey::singleton(object),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        run_id: RunId,
        severity: Severity,
        kind: IssueKind,
        explains: Option<Explanation>,
    ) -> ReportRow {
        ReportRow {
            id: None,
            run_id,
            severity,
            category: kind.as_str().into(),
            account_id: Some(7),
            object: Some("email".into()),
            object_id: Some(3),
            message: "message".into(),
            explains,
        }
    }

    // Only structured explanations of warning or error rows count, scoped to the last full copy.
    #[test]
    fn explanations_follow_severity_and_scope() {
        let rows = [
            row(
                1,
                Severity::Warning,
                IssueKind::Dropped,
                Some(Explanation::Keyword("$a".into())),
            ),
            row(
                3,
                Severity::Info,
                IssueKind::Dropped,
                Some(Explanation::Keyword("$b".into())),
            ),
            row(
                3,
                Severity::Warning,
                IssueKind::Truncated,
                Some(Explanation::Keywords(100)),
            ),
            row(3, Severity::Warning, IssueKind::Dropped, None),
            row(3, Severity::Error, IssueKind::Failed, None),
        ];
        let scope = Scope {
            since: Some(2),
            accepted: None,
        };
        let explanations = Explanations::from_rows(&rows, scope);
        assert_eq!(
            explanations.get(Collection::Email, 3),
            [Explanation::Keywords(100)]
        );
        assert!(explanations.get(Collection::Email, 4).is_empty());
    }

    // Failed and skipped error rows explain a missing object only once the errors were accepted.
    #[test]
    fn accepted_errors_explain_missing_objects() {
        let rows = [
            row(3, Severity::Error, IssueKind::Failed, None),
            row(5, Severity::Error, IssueKind::Skipped, None),
        ];
        let open = Scope {
            since: None,
            accepted: None,
        };
        assert!(
            Explanations::from_rows(&rows, open)
                .get(Collection::Email, 3)
                .is_empty()
        );
        let accepted = Scope {
            since: None,
            accepted: Some(4),
        };
        assert_eq!(
            Explanations::from_rows(&rows, accepted).get(Collection::Email, 3),
            [Explanation::Missing]
        );
        let accepted = Scope {
            since: None,
            accepted: Some(5),
        };
        assert_eq!(
            Explanations::from_rows(&rows, accepted).get(Collection::Email, 3),
            [Explanation::Missing]
        );
    }

    // A skipped changelog row explains its change id only once the errors were accepted.
    #[test]
    fn skipped_log_rows_need_acceptance() {
        let mut skipped = row(
            3,
            Severity::Error,
            IssueKind::Skipped,
            Some(Explanation::LogRow(LogCollection::Email, 9)),
        );
        skipped.object = None;
        skipped.object_id = None;
        let rows = [skipped];
        let scope = |accepted| Scope {
            since: None,
            accepted,
        };
        let open = Explanations::from_rows(&rows, scope(None));
        assert!(!open.log_row(LogCollection::Email, 9));
        let early = Explanations::from_rows(&rows, scope(Some(2)));
        assert!(!early.log_row(LogCollection::Email, 9));
        let accepted = Explanations::from_rows(&rows, scope(Some(3)));
        assert!(accepted.log_row(LogCollection::Email, 9));
        assert!(!accepted.log_row(LogCollection::Email, 8));
        assert!(!accepted.log_row(LogCollection::Thread, 9));
    }
}
