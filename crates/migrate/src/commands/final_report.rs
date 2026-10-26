/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Write,
    path::Path,
};

#[cfg(unix)]
use std::{
    fs::Permissions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

use model::{Collection, GlobalCategory, RegistryKey, Severity, Target};
use rustc_hash::{FxHashMap, FxHashSet};
use state::{MetaKey, RegistryStatus, ReportFilter, ReportRow, RunId, SqliteState, StateStore};

use super::{CommandError, report::render};
use crate::{
    cli::ReportFormat,
    orchestrator::{RunError, RunSummary},
};

pub(super) const FINAL_REPORT_FILE: &str = "final-report.txt";

pub(super) const CUTOVER_CHECKLIST: &str = "\
Cutover checklist:
  1. Start the v1 server with the --target configuration.
  2. Check the v1 logs for errors.
  3. Check that the search index rebuild progresses: every copied object is queued for indexing.
  4. Tell users that OAuth clients must sign in again.
  5. Expect CalDAV, CardDAV and WebDAV clients to fetch their data once more.
  6. Keep the v0.16 store until v1 is confirmed to work. With a shared blob store, going back to v0.16 now requires stalwart-migrate rollback into a new store.
";

const DOCUMENT_CHUNK: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RowKey {
    Object {
        account_id: Option<u32>,
        object: Box<str>,
        object_id: u64,
    },
    Message {
        account_id: Option<u32>,
        object: Option<Box<str>>,
        message: Box<str>,
    },
}

impl RowKey {
    fn of(row: &ReportRow) -> Self {
        match (&row.object, row.object_id) {
            (Some(object), Some(object_id)) => RowKey::Object {
                account_id: row.account_id,
                object: object.clone(),
                object_id,
            },
            _ => RowKey::Message {
                account_id: row.account_id,
                object: row.object.clone(),
                message: row.message.clone(),
            },
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Outstanding {
    errors: Vec<ReportRow>,
    warnings: Vec<ReportRow>,
    history_errors: usize,
    history_warnings: usize,
}

struct Selection<'a> {
    run_ids: &'a [RunId],
    registry: &'a FxHashMap<RegistryKey, RegistryStatus>,
    present: &'a FxHashSet<(u32, Collection, u32)>,
}

impl Selection<'_> {
    fn final_only(row: &ReportRow) -> bool {
        row.account_id.is_none()
            && row.object.as_deref().is_some_and(|object| {
                GlobalCategory::ALL.iter().any(|category| {
                    category.category().is_final_only() && category.objects().contains(&object)
                })
            })
    }

    fn registry_key(row: &ReportRow) -> Option<RegistryKey> {
        if row.account_id.is_some() {
            return None;
        }
        let object = row.object.as_deref()?;
        Some(match row.object_id {
            Some(id) => RegistryKey::new(object, id),
            None => RegistryKey::singleton(object),
        })
    }

    fn is_outstanding(&self, row: &ReportRow) -> bool {
        if Self::final_only(row) {
            return self.run_ids.contains(&row.run_id);
        }
        if row.severity != Severity::Error {
            return true;
        }
        if let Some(document) = document(row) {
            return !self.present.contains(&document);
        }
        match Self::registry_key(row).and_then(|key| self.registry.get(&key)) {
            Some(status) => *status == RegistryStatus::Error,
            None => true,
        }
    }

    fn select(&self, mut rows: Vec<ReportRow>) -> Outstanding {
        rows.sort_unstable_by_key(|row| row.id);
        let total_errors = rows
            .iter()
            .filter(|row| row.severity == Severity::Error)
            .count();
        let total_warnings = rows.len() - total_errors;
        let mut latest: FxHashMap<RowKey, ReportRow> =
            FxHashMap::with_capacity_and_hasher(rows.len(), Default::default());
        for row in rows {
            latest.insert(RowKey::of(&row), row);
        }
        let mut outstanding = Outstanding::default();
        for row in latest.into_values() {
            if !self.is_outstanding(&row) {
                continue;
            }
            match row.severity {
                Severity::Error => outstanding.errors.push(row),
                _ => outstanding.warnings.push(row),
            }
        }
        outstanding.errors.sort_unstable_by_key(|row| row.id);
        outstanding.warnings.sort_unstable_by_key(|row| row.id);
        outstanding.history_errors = total_errors - outstanding.errors.len();
        outstanding.history_warnings = total_warnings - outstanding.warnings.len();
        outstanding
    }
}

fn document(row: &ReportRow) -> Option<(u32, Collection, u32)> {
    Some((
        row.account_id?,
        Collection::parse(row.object.as_deref()?)?,
        u32::try_from(row.object_id?).ok()?,
    ))
}

async fn present_documents<T: Target>(
    target: &T,
    rows: &[ReportRow],
) -> Result<FxHashSet<(u32, Collection, u32)>, CommandError> {
    let mut wanted: BTreeMap<(u32, Collection), Vec<u32>> = BTreeMap::new();
    for (account_id, collection, document_id) in rows
        .iter()
        .filter(|row| row.severity == Severity::Error)
        .filter_map(document)
    {
        wanted
            .entry((account_id, collection))
            .or_default()
            .push(document_id);
    }
    let mut present = FxHashSet::default();
    for ((account_id, collection), mut ids) in wanted {
        ids.sort_unstable();
        ids.dedup();
        for chunk in ids.chunks(DOCUMENT_CHUNK) {
            let found = target
                .exists(account_id, collection, chunk)
                .await
                .map_err(RunError::from)?;
            present.extend(
                found
                    .iter()
                    .map(|document_id| (account_id, collection, document_id)),
            );
        }
    }
    Ok(present)
}

async fn registry_statuses(
    state: &SqliteState,
    rows: &[ReportRow],
) -> Result<FxHashMap<RegistryKey, RegistryStatus>, CommandError> {
    let objects: BTreeSet<&str> = rows
        .iter()
        .filter(|row| row.severity == Severity::Error && row.account_id.is_none())
        .filter_map(|row| row.object.as_deref())
        .collect();
    let mut statuses = FxHashMap::default();
    for object in objects {
        statuses.extend(
            state
                .registry_states(object.into())
                .await?
                .into_iter()
                .map(|entry| (entry.key, entry.status)),
        );
    }
    Ok(statuses)
}

pub(super) async fn write_final_report<T: Target>(
    dir: &Path,
    summary: &RunSummary,
    header: &[u8],
    target: &T,
) -> Result<bool, CommandError> {
    let state = SqliteState::open_read_only(dir)?;
    if state.meta(MetaKey::FinalDone).await?.is_none() {
        return Ok(false);
    }
    let verify_run = summary
        .verify
        .as_ref()
        .map_or(summary.run_id, |verify| verify.run_id);
    let mut rows = Vec::new();
    for severity in [Severity::Error, Severity::Warning] {
        rows.extend(
            state
                .reports(ReportFilter {
                    severity: Some(severity),
                    ..ReportFilter::default()
                })
                .await?,
        );
    }
    let mismatches = state
        .reports(ReportFilter {
            severity: Some(Severity::Verify),
            run_id: Some(verify_run),
            ..ReportFilter::default()
        })
        .await?;
    let registry = registry_statuses(&state, &rows).await?;
    let present = present_documents(target, &rows).await?;
    let mut run_ids = summary.interrupted_runs.clone();
    run_ids.push(summary.run_id);
    let outstanding = Selection {
        run_ids: &run_ids,
        registry: &registry,
        present: &present,
    }
    .select(rows);

    let mut out = Vec::with_capacity(4096);
    writeln!(
        out,
        "Final report of the v0.16 to v1 migration (run {})\n",
        summary.run_id
    )?;
    out.extend_from_slice(header);
    for (title, rows) in [
        ("Outstanding errors", &outstanding.errors),
        ("Verification mismatches of this run", &mismatches),
        (
            "Outstanding warnings (drops, truncations, clamps, skips and other changes)",
            &outstanding.warnings,
        ),
    ] {
        writeln!(out, "\n{title}: {}", rows.len())?;
        if !rows.is_empty() {
            out.extend_from_slice(render(rows, ReportFormat::Text).as_bytes());
        }
    }
    writeln!(
        out,
        "\nEarlier rows that were resolved or superseded by a later row: {} errors, {} warnings (list them with stalwart-migrate report).",
        outstanding.history_errors, outstanding.history_warnings
    )?;
    writeln!(out)?;
    out.extend_from_slice(CUTOVER_CHECKLIST.as_bytes());
    write_private(&dir.join(FINAL_REPORT_FILE), &out)?;
    Ok(true)
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        id: i64,
        run_id: RunId,
        severity: Severity,
        account_id: Option<u32>,
        object: &str,
        object_id: Option<u64>,
    ) -> ReportRow {
        ReportRow {
            id: Some(id),
            run_id,
            severity,
            category: "failed".into(),
            account_id,
            object: Some(object.into()),
            object_id,
            message: format!("row {id}").into_boxed_str(),
            explains: None,
        }
    }

    // Only the latest row per object counts, and errors count only while the object is still missing or in error.
    #[test]
    fn only_outstanding_rows_are_listed() {
        let rows = vec![
            row(1, 1, Severity::Error, Some(7), "email", Some(1)),
            row(2, 1, Severity::Error, Some(7), "email", Some(2)),
            row(3, 2, Severity::Warning, Some(7), "email", Some(2)),
            row(4, 1, Severity::Error, Some(7), "email", Some(3)),
            row(5, 1, Severity::Error, None, "x:Domain", Some(1)),
            row(6, 1, Severity::Error, None, "x:Domain", Some(2)),
            row(7, 1, Severity::Error, None, "queuedMessage", Some(9)),
            row(8, 3, Severity::Error, None, "queuedMessage", Some(10)),
            row(9, 1, Severity::Warning, Some(7), "contactCard", Some(4)),
        ];
        let registry = FxHashMap::from_iter([
            (RegistryKey::new("x:Domain", 1), RegistryStatus::Ok),
            (RegistryKey::new("x:Domain", 2), RegistryStatus::Error),
        ]);
        let present = FxHashSet::from_iter([(7, Collection::Email, 1)]);
        let outstanding = Selection {
            run_ids: &[3],
            registry: &registry,
            present: &present,
        }
        .select(rows);
        let ids = |rows: &[ReportRow]| rows.iter().filter_map(|row| row.id).collect::<Vec<_>>();
        assert_eq!(ids(&outstanding.errors), [4, 6, 8]);
        assert_eq!(ids(&outstanding.warnings), [3, 9]);
        assert_eq!(outstanding.history_errors, 4);
        assert_eq!(outstanding.history_warnings, 0);
    }

    // A report file that already exists with wider permissions is narrowed to 0600 when rewritten.
    #[cfg(unix)]
    #[test]
    fn rewritten_report_is_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FINAL_REPORT_FILE);
        std::fs::write(&path, b"old").expect("write");
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).expect("chmod");
        write_private(&path, b"new").expect("rewrite");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
    }
}
