/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Write as _, io::Write as _, process::ExitCode};

use model::Severity;
use serde_json::{Value, json};
use state::{ReportFilter, ReportRow, ReportScope, SqliteState, StateStore};

use super::{CommandError, format::csv_field};
use crate::cli::{ReportArgs, ReportFormat};

const CSV_HEADER: &str = "id,run,severity,category,account,object,object_id,message\n";

pub(super) async fn report(args: &ReportArgs) -> Result<ExitCode, CommandError> {
    let filter = ReportFilter {
        run_id: args.run,
        severity: match args.severity.as_deref() {
            Some(name) => Some(Severity::parse(name).ok_or_else(|| {
                CommandError::Usage(
                    format!("unknown severity {name:?} (info, warning, error, verify)")
                        .into_boxed_str(),
                )
            })?),
            None => None,
        },
        category: args.category.as_deref().map(Box::from),
        account_id: args.account,
        scope: ReportScope::All,
        limit: args.limit,
    };
    let state = SqliteState::open_read_only(&args.state.state)?;
    let rows = state.reports(filter).await?;
    let rendered = render(&rows, args.format);
    std::io::stdout().lock().write_all(rendered.as_bytes())?;
    Ok(ExitCode::SUCCESS)
}

pub(super) fn render(rows: &[ReportRow], format: ReportFormat) -> String {
    match format {
        ReportFormat::Text => render_text(rows),
        ReportFormat::Csv => render_csv(rows),
        ReportFormat::Json => {
            let mut out = Value::Array(rows.iter().map(row_json).collect()).to_string();
            out.push('\n');
            out
        }
    }
}

fn render_text(rows: &[ReportRow]) -> String {
    let mut out = String::with_capacity(64 * (rows.len() + 1));
    let _ = writeln!(
        out,
        "{:<6} {:<8} {:<10} {:<10} {:<20} {:<20} message",
        "run", "severity", "category", "account", "object", "id"
    );
    for row in rows {
        let _ = write!(
            out,
            "{:<6} {:<8} {:<10} ",
            row.run_id,
            row.severity.as_str(),
            row.category
        );
        match row.account_id {
            Some(account_id) => {
                let _ = write!(out, "{account_id:<10} ");
            }
            None => out.push_str("-          "),
        }
        let _ = write!(out, "{:<20} ", row.object.as_deref().unwrap_or("-"));
        match row.object_id {
            Some(object_id) => {
                let _ = write!(out, "{object_id:<20} ");
            }
            None => out.push_str("-                    "),
        }
        out.push_str(&row.message);
        out.push('\n');
    }
    let _ = writeln!(out, "{} rows", rows.len());
    out
}

fn render_csv(rows: &[ReportRow]) -> String {
    let mut out = String::with_capacity(64 * (rows.len() + 1));
    out.push_str(CSV_HEADER);
    for row in rows {
        if let Some(id) = row.id {
            let _ = write!(out, "{id}");
        }
        let _ = write!(out, ",{},{},", row.run_id, row.severity.as_str());
        csv_field(&mut out, &row.category);
        out.push(',');
        if let Some(account_id) = row.account_id {
            let _ = write!(out, "{account_id}");
        }
        out.push(',');
        if let Some(object) = row.object.as_deref() {
            csv_field(&mut out, object);
        }
        out.push(',');
        if let Some(object_id) = row.object_id {
            let _ = write!(out, "{object_id}");
        }
        out.push(',');
        csv_field(&mut out, &row.message);
        out.push('\n');
    }
    out
}

fn row_json(row: &ReportRow) -> Value {
    json!({
        "id": row.id,
        "run": row.run_id,
        "severity": row.severity.as_str(),
        "category": &*row.category,
        "account": row.account_id,
        "object": row.object.as_deref(),
        "object_id": row.object_id,
        "message": &*row.message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<ReportRow> {
        vec![
            ReportRow {
                id: Some(1),
                run_id: 3,
                severity: Severity::Warning,
                category: "truncated".into(),
                account_id: Some(42),
                object: Some("email".into()),
                object_id: Some(7),
                message: "keywords truncated to 100, \"$custom\" dropped".into(),
                explains: None,
            },
            ReportRow {
                id: Some(2),
                run_id: 3,
                severity: Severity::Error,
                category: "dropped".into(),
                account_id: None,
                object: Some("SpamLlm".into()),
                object_id: None,
                message: "no v1 equivalent".into(),
                explains: None,
            },
        ]
    }

    #[test]
    fn renders_all_formats() {
        let rows = rows();
        let text = render(&rows, ReportFormat::Text);
        assert!(text.contains("warning  truncated  42"));
        assert!(text.contains("2 rows"));

        let csv = render(&rows, ReportFormat::Csv);
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some(CSV_HEADER.trim_end()));
        assert_eq!(
            lines.next(),
            Some(
                "1,3,warning,truncated,42,email,7,\"keywords truncated to 100, \"\"$custom\"\" dropped\""
            )
        );
        assert_eq!(
            lines.next(),
            Some("2,3,error,dropped,,SpamLlm,,no v1 equivalent")
        );

        let json: Value =
            serde_json::from_str(&render(&rows, ReportFormat::Json)).expect("valid json");
        assert_eq!(json[0]["account"], 42);
        assert_eq!(json[1]["account"], Value::Null);
        assert_eq!(json[1]["object"], "SpamLlm");
    }
}
