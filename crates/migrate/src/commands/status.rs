/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Write as _, io::Write as _, process::ExitCode};

use serde_json::{Map, Value, json};
use state::{AccountState, MetaKey, PhaseCount, ReportCount, RunRecord, SqliteState, StateStore};

use super::{CommandError, format::utc_timestamp};
use crate::cli::{StatusArgs, StatusFormat};

const RECENT_RUNS: u32 = 5;
const FAILED_ACCOUNTS: u32 = 20;

pub(super) struct StatusData {
    pub(super) path: String,
    pub(super) meta: Vec<(MetaKey, String)>,
    pub(super) phases: Vec<PhaseCount>,
    pub(super) failed: Vec<AccountState>,
    pub(super) runs: Vec<RunRecord>,
    pub(super) last_run_reports: Vec<ReportCount>,
    pub(super) total_reports: Vec<ReportCount>,
}

pub(super) async fn status(args: &StatusArgs) -> Result<ExitCode, CommandError> {
    let state = SqliteState::open_read_only(&args.state.state)?;
    let mut data = collect(&state).await?;
    data.path = state.path().display().to_string();
    let rendered = match args.format {
        StatusFormat::Text => render_text(&data),
        StatusFormat::Json => render_json(&data).to_string(),
    };
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(rendered.as_bytes())?;
    stdout.write_all(b"\n")?;
    Ok(ExitCode::SUCCESS)
}

pub(super) async fn collect<St: StateStore>(state: &St) -> Result<StatusData, CommandError> {
    let mut meta = Vec::with_capacity(MetaKey::ALL.len());
    for key in MetaKey::ALL {
        if let Some(value) = state.meta(*key).await? {
            meta.push((*key, value));
        }
    }
    let runs = state.runs(RECENT_RUNS).await?;
    let last_run_reports = match runs.first() {
        Some(run) => state.report_counts(Some(run.id)).await?,
        None => Vec::new(),
    };
    Ok(StatusData {
        path: String::new(),
        meta,
        phases: state.phase_counts().await?,
        failed: state.failed_accounts(FAILED_ACCOUNTS).await?,
        runs,
        last_run_reports,
        total_reports: state.report_counts(None).await?,
    })
}

pub(super) fn render_text(data: &StatusData) -> String {
    let mut out = String::new();
    if !data.path.is_empty() {
        let _ = writeln!(out, "State database: {}", data.path);
    }
    for (key, value) in &data.meta {
        let _ = write!(out, "{:<22} ", key.as_str());
        match key {
            MetaKey::CreatedAt | MetaKey::FinalDone => match value.parse::<i64>() {
                Ok(unix) => utc_timestamp(&mut out, unix),
                Err(_) => out.push_str(value),
            },
            _ => out.push_str(value),
        }
        out.push('\n');
    }
    if !data.meta.iter().any(|(key, _)| *key == MetaKey::FinalDone) {
        let _ = writeln!(out, "{:<22} not done", MetaKey::FinalDone.as_str());
    }

    let total: u64 = data.phases.iter().map(|phase| phase.count).sum();
    let _ = writeln!(out, "\nAccounts: {total}");
    for phase in &data.phases {
        let _ = writeln!(out, "  {:<12} {:>10}", phase.phase.as_str(), phase.count);
    }
    if !data.failed.is_empty() {
        let _ = writeln!(out, "\nAccounts in error:");
        for account in &data.failed {
            let _ = writeln!(
                out,
                "  {:>10}  attempts {:<3} {}",
                account.account_id,
                account.attempts,
                account.last_error.as_deref().unwrap_or("")
            );
        }
    }

    let _ = writeln!(out, "\nRecent runs:");
    if data.runs.is_empty() {
        let _ = writeln!(out, "  none");
    }
    for run in &data.runs {
        let _ = write!(
            out,
            "  #{:<5} {:<12} {:<12} started ",
            run.id,
            run.mode.as_str(),
            run.status.as_str()
        );
        utc_timestamp(&mut out, run.started_at);
        if let Some(finished) = run.finished_at {
            let _ = write!(out, "  took {}s", finished.saturating_sub(run.started_at));
        }
        out.push('\n');
        if let Some(stats) = run.stats.as_deref().and_then(non_zero_stats) {
            let _ = writeln!(out, "         {stats}");
        }
    }

    write_report_counts(
        &mut out,
        "Reports in the latest run",
        &data.last_run_reports,
    );
    write_report_counts(&mut out, "Reports in all runs", &data.total_reports);
    out
}

fn write_report_counts(out: &mut String, title: &str, counts: &[ReportCount]) {
    let _ = writeln!(out, "\n{title}:");
    if counts.is_empty() {
        let _ = writeln!(out, "  none");
    }
    for count in counts {
        let _ = writeln!(
            out,
            "  {:<8} {:<12} {:>10}",
            count.severity.as_str(),
            count.category,
            count.count
        );
    }
}

fn non_zero_stats(stats: &str) -> Option<String> {
    let value: Value = serde_json::from_str(stats).ok()?;
    let map = value.as_object()?;
    let mut out = String::new();
    for (key, value) in map {
        if value.as_u64() == Some(0) {
            continue;
        }
        if !out.is_empty() {
            out.push_str(", ");
        }
        let _ = write!(out, "{key}={value}");
    }
    (!out.is_empty()).then_some(out)
}

pub(super) fn render_json(data: &StatusData) -> Value {
    let meta: Map<String, Value> = data
        .meta
        .iter()
        .map(|(key, value)| (key.as_str().to_string(), Value::from(value.as_str())))
        .collect();
    let phases: Map<String, Value> = data
        .phases
        .iter()
        .map(|phase| (phase.phase.as_str().to_string(), Value::from(phase.count)))
        .collect();
    let failed: Vec<Value> = data
        .failed
        .iter()
        .map(|account| {
            json!({
                "account_id": account.account_id,
                "attempts": account.attempts,
                "last_error": account.last_error.as_deref(),
                "updated_at": account.updated_at,
            })
        })
        .collect();
    let runs: Vec<Value> = data
        .runs
        .iter()
        .map(|run| {
            json!({
                "id": run.id,
                "mode": run.mode.as_str(),
                "status": run.status.as_str(),
                "started_at": run.started_at,
                "finished_at": run.finished_at,
                "stats": run.stats.as_deref().and_then(|stats| serde_json::from_str::<Value>(stats).ok()),
            })
        })
        .collect();
    json!({
        "state": data.path,
        "meta": meta,
        "accounts": {
            "total": data.phases.iter().map(|phase| phase.count).sum::<u64>(),
            "phases": phases,
            "failed": failed,
        },
        "runs": runs,
        "reports": {
            "latest_run": report_counts_json(&data.last_run_reports),
            "all_runs": report_counts_json(&data.total_reports),
        },
    })
}

fn report_counts_json(counts: &[ReportCount]) -> Vec<Value> {
    counts
        .iter()
        .map(|count| {
            json!({
                "severity": count.severity.as_str(),
                "category": &*count.category,
                "count": count.count,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use model::{CategorySet, Severity};
    use state::{AccountUpdate, ReportRow, RunMode, RunStatus};

    use super::*;

    #[tokio::test]
    async fn renders_text_and_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = SqliteState::open(dir.path()).expect("open");
        state
            .set_meta(MetaKey::Edition, "enterprise".into())
            .await
            .expect("meta");
        let run = state.begin_run(RunMode::Incremental).await.expect("run");
        state
            .finish_run(
                run.run_id,
                RunStatus::Failed,
                "{\"objects_written\":10,\"issues\":0}".into(),
            )
            .await
            .expect("finish");
        state
            .update_account(AccountUpdate::Complete {
                account_id: 1,
                checkpoint: 5,
                synced: CategorySet::defaults(),
            })
            .await
            .expect("account");
        state
            .update_account(AccountUpdate::Fail {
                account_id: 2,
                error: "target unavailable".into(),
            })
            .await
            .expect("account");
        state
            .add_reports(vec![ReportRow {
                id: None,
                run_id: run.run_id,
                severity: Severity::Warning,
                category: "truncated".into(),
                account_id: Some(1),
                object: None,
                object_id: None,
                message: "keywords truncated".into(),
                explains: None,
            }])
            .await
            .expect("reports");

        let mut data = collect(&state).await.expect("collect");
        data.path = "state.sqlite".into();
        let text = render_text(&data);
        assert!(text.contains("edition                enterprise"));
        assert!(text.contains("final_done             not done"));
        assert!(text.contains("Accounts: 2"));
        assert!(text.contains("target unavailable"));
        assert!(text.contains("objects_written=10"));
        assert!(!text.contains("issues=0"));
        assert!(text.contains("truncated"));

        let json = render_json(&data);
        assert_eq!(json["accounts"]["total"], 2);
        assert_eq!(json["accounts"]["phases"]["error"], 1);
        assert_eq!(json["accounts"]["failed"][0]["account_id"], 2);
        assert_eq!(json["runs"][0]["status"], "failed");
        assert_eq!(json["runs"][0]["stats"]["objects_written"], 10);
        assert_eq!(json["reports"]["latest_run"][0]["count"], 1);
        assert_eq!(json["meta"]["edition"], "enterprise");
    }
}
