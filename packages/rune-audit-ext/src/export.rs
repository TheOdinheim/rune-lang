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
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::JsonLines => "json-lines",
            Self::Cef => "cef",
            Self::Csv => "csv",
            Self::Summary => "summary",
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
        }
    }

    pub fn json_lines(&self, events: &[&UnifiedEvent]) -> String {
        events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn cef(&self, events: &[&UnifiedEvent]) -> String {
        events
            .iter()
            .map(|e| {
                let sev = cef_severity(e.severity);
                format!(
                    "CEF:0|RUNE|{source}|1.0|{action}|{detail}|{sev}|src={actor} dst={subject} msg={detail_esc}",
                    source = e.source,
                    action = e.action,
                    detail = e.action,
                    sev = sev,
                    actor = e.actor,
                    subject = e.subject,
                    detail_esc = e.detail.replace('|', "\\|"),
                )
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

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
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
        assert!(output.contains("CEF:0|RUNE|rune-security"));
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
}
