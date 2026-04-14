// ═══════════════════════════════════════════════════════════════════════
// Export — Audit event export in multiple formats.
//
// Supports JSON Lines (one event per line), CEF (Common Event Format
// for SIEM integration), CSV, and human-readable summary.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;

use crate::event::UnifiedEvent;

// ── ExportFormat ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    JsonLines,
    Cef,
    Csv,
    Summary,
    Ndjson,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::JsonLines => "json-lines",
            Self::Cef => "cef",
            Self::Csv => "csv",
            Self::Summary => "summary",
            Self::Ndjson => "ndjson",
        };
        f.write_str(s)
    }
}

// ── AuditExporter ───────────────────────────────────────────────────

pub struct AuditExporter;

impl AuditExporter {
    pub fn new() -> Self {
        Self
    }

    pub fn export(&self, events: &[&UnifiedEvent], format: ExportFormat) -> String {
        match format {
            ExportFormat::JsonLines => self.json_lines(events),
            ExportFormat::Cef => self.cef(events),
            ExportFormat::Csv => self.csv(events),
            ExportFormat::Summary => self.summary(events),
            ExportFormat::Ndjson => self.ndjson(events),
        }
    }

    pub fn json_lines(&self, events: &[&UnifiedEvent]) -> String {
        events
            .iter()
            .map(|e| {
                let mut obj = serde_json::to_value(e).unwrap_or_default();
                if let Some(map) = obj.as_object_mut() {
                    map.insert("schema_version".into(), serde_json::json!("1.0"));
                    map.insert("export_timestamp".into(), serde_json::json!(iso8601_now()));
                }
                serde_json::to_string(&obj).unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn cef(&self, events: &[&UnifiedEvent]) -> String {
        events
            .iter()
            .map(|e| {
                let sev = cef_severity(e.severity);
                let source_esc = cef_escape(&e.source.to_string());
                let action_esc = cef_escape(&e.action);
                let detail_esc = cef_escape(&e.detail);
                let mut ext = format!(
                    "src={actor} dst={subject} msg={msg}",
                    actor = cef_escape(&e.actor),
                    subject = cef_escape(&e.subject),
                    msg = cef_escape(&e.detail),
                );
                if let Some(ref cid) = e.correlation_id {
                    ext = format!("{ext} cs1Label=correlationId cs1={}", cef_escape(cid));
                }
                format!(
                    "CEF:0|RUNE|rune-audit-ext|1.0|{action_esc}|{detail_esc}|{sev}|{ext}",
                    action_esc = action_esc,
                    detail_esc = detail_esc,
                    sev = sev,
                    ext = ext,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn ndjson(&self, events: &[&UnifiedEvent]) -> String {
        events
            .iter()
            .map(|e| {
                let ecs = serde_json::json!({
                    "@timestamp": iso8601_from_epoch(e.timestamp),
                    "event": {
                        "kind": "event",
                        "category": e.category.to_string(),
                        "outcome": e.outcome.to_string(),
                        "action": e.action,
                        "severity": cef_severity(e.severity),
                    },
                    "source": {
                        "component": e.source.to_string(),
                    },
                    "user": {
                        "name": e.actor,
                    },
                    "message": e.detail,
                    "labels": {
                        "rune_event_id": e.id.0,
                        "rune_subject": e.subject,
                    },
                    "tags": e.tags,
                });
                serde_json::to_string(&ecs).unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn csv(&self, events: &[&UnifiedEvent]) -> String {
        let mut lines = vec!["id,timestamp,source,category,severity,outcome,actor,action,subject,detail".to_string()];
        for e in events {
            lines.push(format!(
                "{},{},{},{},{},{},{},{},{},{}",
                e.id,
                e.timestamp,
                e.source,
                e.category,
                e.severity,
                e.outcome,
                csv_escape(&e.actor),
                csv_escape(&e.action),
                csv_escape(&e.subject),
                csv_escape(&e.detail),
            ));
        }
        lines.join("\n")
    }

    pub fn summary(&self, events: &[&UnifiedEvent]) -> String {
        if events.is_empty() {
            return "No events.".to_string();
        }
        let total = events.len();
        let mut by_severity = std::collections::HashMap::new();
        let mut by_source = std::collections::HashMap::new();
        for e in events {
            *by_severity.entry(e.severity).or_insert(0usize) += 1;
            *by_source.entry(e.source).or_insert(0usize) += 1;
        }
        let first_ts = events.iter().map(|e| e.timestamp).min().unwrap();
        let last_ts = events.iter().map(|e| e.timestamp).max().unwrap();

        let mut lines = vec![format!("Audit Summary: {total} events ({first_ts}..{last_ts})")];
        lines.push("By severity:".into());
        let mut sevs: Vec<_> = by_severity.into_iter().collect();
        sevs.sort_by_key(|(s, _)| *s);
        for (sev, count) in sevs {
            lines.push(format!("  {sev}: {count}"));
        }
        lines.push("By source:".into());
        let mut srcs: Vec<_> = by_source.into_iter().collect();
        srcs.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (src, count) in srcs {
            lines.push(format!("  {src}: {count}"));
        }
        lines.join("\n")
    }
}

impl Default for AuditExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ── ExportValidation ───────────────────────────────────────────────

#[derive(Debug)]
pub struct ExportValidation {
    pub format: ExportFormat,
    pub event_count: usize,
    pub output_bytes: usize,
    pub valid: bool,
    pub issues: Vec<String>,
}

impl AuditExporter {
    pub fn validate_export(&self, events: &[&UnifiedEvent], format: ExportFormat) -> ExportValidation {
        let output = self.export(events, format);
        let mut issues = Vec::new();
        if output.is_empty() && !events.is_empty() {
            issues.push("export produced empty output for non-empty event set".into());
        }
        match format {
            ExportFormat::JsonLines | ExportFormat::Ndjson => {
                for (i, line) in output.lines().enumerate() {
                    if serde_json::from_str::<serde_json::Value>(line).is_err() {
                        issues.push(format!("invalid JSON on line {}", i + 1));
                    }
                }
            }
            ExportFormat::Csv => {
                let lines: Vec<&str> = output.lines().collect();
                if !lines.is_empty() {
                    let header_cols = lines[0].split(',').count();
                    for (i, line) in lines.iter().enumerate().skip(1) {
                        let cols = line.split(',').count();
                        if cols != header_cols {
                            issues.push(format!("row {} has {cols} columns, expected {header_cols}", i + 1));
                        }
                    }
                }
            }
            ExportFormat::Cef => {
                for (i, line) in output.lines().enumerate() {
                    if !line.starts_with("CEF:0|") {
                        issues.push(format!("line {} missing CEF header", i + 1));
                    }
                }
            }
            ExportFormat::Summary => {}
        }
        ExportValidation {
            format,
            event_count: events.len(),
            output_bytes: output.len(),
            valid: issues.is_empty(),
            issues,
        }
    }
}

/// Map SecuritySeverity to CEF severity (0-10 scale).
/// Info=1, Low=3, Medium=5, High=7, Critical=9, Emergency=10.
fn cef_severity(sev: SecuritySeverity) -> u8 {
    match sev {
        SecuritySeverity::Info => 1,
        SecuritySeverity::Low => 3,
        SecuritySeverity::Medium => 5,
        SecuritySeverity::High => 7,
        SecuritySeverity::Critical => 9,
        SecuritySeverity::Emergency => 10,
    }
}

fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn iso8601_from_epoch(ts: i64) -> String {
    let secs = ts;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    let s = rem % 60;
    // Simplified: days from epoch 1970-01-01
    let (year, month, day) = epoch_days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{s:02}Z")
}

fn epoch_days_to_date(days: i64) -> (i64, i64, i64) {
    // Civil calendar from days since 1970-01-01
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn iso8601_now() -> String {
    "2026-04-13T00:00:00Z".to_string()
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;

    fn sample_events() -> Vec<UnifiedEvent> {
        vec![
            UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 100)
                .severity(SecuritySeverity::High)
                .actor("system")
                .subject("host-1")
                .detail("port scan detected")
                .build(),
            UnifiedEventBuilder::new("e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 200)
                .severity(SecuritySeverity::Info)
                .actor("alice")
                .outcome(EventOutcome::Success)
                .build(),
        ]
    }

    #[test]
    fn test_json_lines() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.json_lines(&refs);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"e1\""));
    }

    #[test]
    fn test_cef_format() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.cef(&refs);
        assert!(output.contains("CEF:0|RUNE|rune-audit-ext|1.0|"));
        assert!(output.contains("|7|")); // High = 7
    }

    #[test]
    fn test_csv_format() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.csv(&refs);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[0].starts_with("id,timestamp"));
    }

    #[test]
    fn test_summary_format() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.summary(&refs);
        assert!(output.contains("2 events"));
        assert!(output.contains("By severity:"));
        assert!(output.contains("By source:"));
    }

    #[test]
    fn test_export_dispatch() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let jl = exporter.export(&refs, ExportFormat::JsonLines);
        let cef = exporter.export(&refs, ExportFormat::Cef);
        let csv = exporter.export(&refs, ExportFormat::Csv);
        let sum = exporter.export(&refs, ExportFormat::Summary);
        assert!(jl.contains("\"e1\""));
        assert!(cef.contains("CEF:0"));
        assert!(csv.contains("id,timestamp"));
        assert!(sum.contains("2 events"));
    }

    #[test]
    fn test_cef_severity_mapping() {
        assert_eq!(cef_severity(SecuritySeverity::Info), 1);
        assert_eq!(cef_severity(SecuritySeverity::Low), 3);
        assert_eq!(cef_severity(SecuritySeverity::Medium), 5);
        assert_eq!(cef_severity(SecuritySeverity::High), 7);
        assert_eq!(cef_severity(SecuritySeverity::Critical), 9);
        assert_eq!(cef_severity(SecuritySeverity::Emergency), 10);
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::JsonLines.to_string(), "json-lines");
        assert_eq!(ExportFormat::Cef.to_string(), "cef");
        assert_eq!(ExportFormat::Csv.to_string(), "csv");
        assert_eq!(ExportFormat::Summary.to_string(), "summary");
        assert_eq!(ExportFormat::Ndjson.to_string(), "ndjson");
    }

    #[test]
    fn test_empty_summary() {
        let exporter = AuditExporter::new();
        let output = exporter.summary(&[]);
        assert_eq!(output, "No events.");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("has,comma"), "\"has,comma\"");
        assert_eq!(csv_escape("has\"quote"), "\"has\"\"quote\"");
    }

    // ── Layer 2 export tests ───────────────────────────────────────

    #[test]
    fn test_json_lines_schema_version() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.json_lines(&refs);
        for line in output.lines() {
            assert!(line.contains("schema_version"));
            assert!(line.contains("export_timestamp"));
            let val: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(val["schema_version"], "1.0");
        }
    }

    #[test]
    fn test_cef_pipe_escaping() {
        let events = vec![
            UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "test|action", 100)
                .detail("detail|with|pipes")
                .actor("system")
                .build(),
        ];
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.cef(&refs);
        assert!(output.contains(r"test\|action"));
        assert!(output.contains(r"detail\|with\|pipes"));
    }

    #[test]
    fn test_cef_correlation_id_label() {
        let events = vec![
            UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 100)
                .correlation_id("corr-42")
                .build(),
        ];
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.cef(&refs);
        assert!(output.contains("cs1Label=correlationId"));
        assert!(output.contains("cs1=corr-42"));
    }

    #[test]
    fn test_ndjson_ecs_format() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.ndjson(&refs);
        for line in output.lines() {
            let val: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(val.get("@timestamp").is_some());
            assert!(val.get("event").is_some());
            assert!(val.get("source").is_some());
            assert!(val.get("message").is_some());
        }
    }

    #[test]
    fn test_ndjson_dispatch() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let output = exporter.export(&refs, ExportFormat::Ndjson);
        assert!(output.contains("@timestamp"));
    }

    #[test]
    fn test_export_validation_json_lines() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let validation = exporter.validate_export(&refs, ExportFormat::JsonLines);
        assert!(validation.valid);
        assert_eq!(validation.event_count, 2);
        assert!(validation.output_bytes > 0);
        assert!(validation.issues.is_empty());
    }

    #[test]
    fn test_export_validation_cef() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let validation = exporter.validate_export(&refs, ExportFormat::Cef);
        assert!(validation.valid);
    }

    #[test]
    fn test_export_validation_csv() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let validation = exporter.validate_export(&refs, ExportFormat::Csv);
        assert!(validation.valid);
    }

    #[test]
    fn test_export_validation_ndjson() {
        let events = sample_events();
        let refs: Vec<&UnifiedEvent> = events.iter().collect();
        let exporter = AuditExporter::new();
        let validation = exporter.validate_export(&refs, ExportFormat::Ndjson);
        assert!(validation.valid);
    }

    #[test]
    fn test_cef_escape_fn() {
        assert_eq!(cef_escape("no special"), "no special");
        assert_eq!(cef_escape("has|pipe"), r"has\|pipe");
        assert_eq!(cef_escape(r"has\backslash"), r"has\\backslash");
    }
}
