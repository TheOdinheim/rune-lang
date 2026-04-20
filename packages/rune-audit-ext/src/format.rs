// ═══════════════════════════════════════════════════════════════════════
// Format — Trait-based audit export with CEF, OCSF, and JSON
// exporter implementations.
//
// Layer 3 defines the export contract so customers can implement
// their own serialization formats. RUNE provides three reference
// implementations: CEF (ArcSight SIEM), OCSF (Open Cybersecurity
// Schema Framework), and structured JSON.
// ═══════════════════════════════════════════════════════════════════════

use rune_security::SecuritySeverity;

use crate::error::AuditExtError;
use crate::event::UnifiedEvent;

// ── AuditFormatExporter trait ─────────────────────────────────────

pub trait AuditFormatExporter {
    fn export_event(&self, event: &UnifiedEvent) -> Result<Vec<u8>, AuditExtError>;
    fn export_batch(&self, events: &[UnifiedEvent]) -> Result<Vec<Vec<u8>>, AuditExtError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── CEF severity mapping ──────────────────────────────────────────

fn cef_severity_num(sev: SecuritySeverity) -> u8 {
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

// ── CefExporter ───────────────────────────────────────────────────

pub struct CefExporter;

impl CefExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CefExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditFormatExporter for CefExporter {
    fn export_event(&self, event: &UnifiedEvent) -> Result<Vec<u8>, AuditExtError> {
        let sev = cef_severity_num(event.severity);
        let action_esc = cef_escape(&event.action);
        let detail_esc = cef_escape(&event.detail);
        let actor_esc = cef_escape(&event.actor);
        let subject_esc = cef_escape(&event.subject);

        let mut ext = format!(
            "rt={ts} src={actor} msg={detail} cs1={eid}",
            ts = event.timestamp,
            actor = actor_esc,
            detail = cef_escape(&event.detail),
            eid = event.id.0,
        );

        if let Some(ref hash) = event.correlation_id {
            ext = format!("{ext} cs2={}", cef_escape(hash));
        }

        let line = format!(
            "CEF:0|Odin's LLC|RUNE|1.0|{action}|{detail}|{sev}|{ext}",
            action = action_esc,
            detail = detail_esc,
            sev = sev,
            ext = ext,
        );
        Ok(line.into_bytes())
    }

    fn export_batch(&self, events: &[UnifiedEvent]) -> Result<Vec<Vec<u8>>, AuditExtError> {
        events.iter().map(|e| self.export_event(e)).collect()
    }

    fn format_name(&self) -> &str {
        "CEF"
    }

    fn content_type(&self) -> &str {
        "text/plain"
    }
}

// ── OcsfExporter ──────────────────────────────────────────────────

pub struct OcsfExporter;

impl OcsfExporter {
    pub fn new() -> Self {
        Self
    }

    fn severity_id(sev: SecuritySeverity) -> u8 {
        match sev {
            SecuritySeverity::Info => 1,
            SecuritySeverity::Low => 2,
            SecuritySeverity::Medium => 3,
            SecuritySeverity::High => 4,
            SecuritySeverity::Critical => 5,
            SecuritySeverity::Emergency => 6,
        }
    }

    fn class_uid_for(event: &UnifiedEvent) -> u32 {
        // Security Finding (2001) for threat events, Audit Activity (3001) for others
        match event.category {
            crate::event::EventCategory::ThreatDetection
            | crate::event::EventCategory::ThreatResponse => 2001,
            _ => 3001,
        }
    }
}

impl Default for OcsfExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditFormatExporter for OcsfExporter {
    fn export_event(&self, event: &UnifiedEvent) -> Result<Vec<u8>, AuditExtError> {
        let class_uid = Self::class_uid_for(event);
        let severity_id = Self::severity_id(event.severity);
        let activity_id: u32 = 1; // Create/Generate
        let type_uid = class_uid * 100 + activity_id;

        let ocsf = serde_json::json!({
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "RUNE",
                    "vendor_name": "Odin's LLC",
                    "version": "1.0"
                }
            },
            "class_uid": class_uid,
            "severity_id": severity_id,
            "activity_id": activity_id,
            "type_uid": type_uid,
            "time": event.timestamp,
            "message": event.detail,
            "observables": [{
                "name": "actor",
                "value": event.actor,
                "type_id": 1
            }],
            "status_id": 1,
            "category_uid": event.category.to_string(),
            "unmapped": {
                "event_id": event.id.0,
                "source_crate": event.source.to_string(),
                "action": event.action,
                "subject": event.subject,
                "outcome": event.outcome.to_string(),
            }
        });

        serde_json::to_vec(&ocsf).map_err(|e| AuditExtError::ExportFailed {
            format: "OCSF".to_string(),
            reason: e.to_string(),
        })
    }

    fn export_batch(&self, events: &[UnifiedEvent]) -> Result<Vec<Vec<u8>>, AuditExtError> {
        events.iter().map(|e| self.export_event(e)).collect()
    }

    fn format_name(&self) -> &str {
        "OCSF"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── JsonExporter ──────────────────────────────────────────────────

pub struct JsonExporter {
    pretty: bool,
}

impl JsonExporter {
    pub fn new() -> Self {
        Self { pretty: false }
    }

    pub fn with_pretty_print(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }
}

impl Default for JsonExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditFormatExporter for JsonExporter {
    fn export_event(&self, event: &UnifiedEvent) -> Result<Vec<u8>, AuditExtError> {
        let mut metadata = serde_json::Map::new();
        for (k, v) in &event.metadata {
            metadata.insert(k.clone(), serde_json::Value::String(v.clone()));
        }

        let obj = serde_json::json!({
            "event_id": event.id.0,
            "event_type": event.action,
            "timestamp": event.timestamp,
            "source": event.source.to_string(),
            "severity": event.severity.to_string(),
            "description": event.detail,
            "hash": event.correlation_id,
            "metadata": metadata,
        });

        let bytes = if self.pretty {
            serde_json::to_vec_pretty(&obj)
        } else {
            serde_json::to_vec(&obj)
        };

        bytes.map_err(|e| AuditExtError::ExportFailed {
            format: "JSON".to_string(),
            reason: e.to_string(),
        })
    }

    fn export_batch(&self, events: &[UnifiedEvent]) -> Result<Vec<Vec<u8>>, AuditExtError> {
        events.iter().map(|e| self.export_event(e)).collect()
    }

    fn format_name(&self) -> &str {
        "JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;

    fn sample_event() -> UnifiedEvent {
        UnifiedEventBuilder::new(
            "e1",
            SourceCrate::RuneSecurity,
            EventCategory::ThreatDetection,
            "scan",
            1000,
        )
        .severity(SecuritySeverity::High)
        .actor("system")
        .subject("host-1")
        .detail("port scan detected")
        .correlation_id("corr-42")
        .build()
    }

    // ── CEF tests ─────────────────────────────────────────────────

    #[test]
    fn test_cef_exporter_produces_valid_format() {
        let exporter = CefExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let output = String::from_utf8(bytes).unwrap();
        assert!(output.starts_with("CEF:0|"));
        assert!(output.contains("Odin's LLC"));
        assert!(output.contains("RUNE"));
        assert!(output.contains("1.0"));
    }

    #[test]
    fn test_cef_exporter_includes_required_fields() {
        let exporter = CefExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let output = String::from_utf8(bytes).unwrap();
        assert!(output.contains("rt="));
        assert!(output.contains("src="));
        assert!(output.contains("msg="));
        assert!(output.contains("cs1="));
        assert!(output.contains("cs2="));
    }

    #[test]
    fn test_cef_exporter_severity_mapping() {
        assert_eq!(cef_severity_num(SecuritySeverity::Info), 1);
        assert_eq!(cef_severity_num(SecuritySeverity::Low), 3);
        assert_eq!(cef_severity_num(SecuritySeverity::Medium), 5);
        assert_eq!(cef_severity_num(SecuritySeverity::High), 7);
        assert_eq!(cef_severity_num(SecuritySeverity::Critical), 9);
        assert_eq!(cef_severity_num(SecuritySeverity::Emergency), 10);
    }

    #[test]
    fn test_cef_exporter_format_name() {
        let exporter = CefExporter::new();
        assert_eq!(exporter.format_name(), "CEF");
    }

    #[test]
    fn test_cef_exporter_content_type() {
        let exporter = CefExporter::new();
        assert_eq!(exporter.content_type(), "text/plain");
    }

    // ── OCSF tests ────────────────────────────────────────────────

    #[test]
    fn test_ocsf_exporter_produces_valid_json() {
        let exporter = OcsfExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(val.is_object());
    }

    #[test]
    fn test_ocsf_exporter_includes_required_fields() {
        let exporter = OcsfExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(val.get("metadata").is_some());
        assert!(val.get("severity_id").is_some());
        assert!(val.get("time").is_some());
        assert!(val.get("class_uid").is_some());
        assert!(val.get("activity_id").is_some());
        assert!(val.get("type_uid").is_some());
    }

    #[test]
    fn test_ocsf_exporter_format_name() {
        let exporter = OcsfExporter::new();
        assert_eq!(exporter.format_name(), "OCSF");
    }

    #[test]
    fn test_ocsf_exporter_threat_class_uid() {
        let exporter = OcsfExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["class_uid"], 2001); // Security Finding for threat events
    }

    #[test]
    fn test_ocsf_exporter_audit_class_uid() {
        let exporter = OcsfExporter::new();
        let event = UnifiedEventBuilder::new(
            "e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 2000,
        ).build();
        let bytes = exporter.export_event(&event).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["class_uid"], 3001); // Audit Activity for non-threat events
    }

    // ── JSON tests ────────────────────────────────────────────────

    #[test]
    fn test_json_exporter_produces_valid_json() {
        let exporter = JsonExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(val.is_object());
    }

    #[test]
    fn test_json_exporter_with_pretty_print() {
        let exporter = JsonExporter::new().with_pretty_print(true);
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let output = String::from_utf8(bytes).unwrap();
        assert!(output.contains('\n')); // pretty-printed JSON contains newlines
    }

    #[test]
    fn test_json_exporter_includes_event_id_and_timestamp() {
        let exporter = JsonExporter::new();
        let bytes = exporter.export_event(&sample_event()).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["event_id"], "e1");
        assert_eq!(val["timestamp"], 1000);
    }

    #[test]
    fn test_json_exporter_format_name() {
        let exporter = JsonExporter::new();
        assert_eq!(exporter.format_name(), "JSON");
    }

    #[test]
    fn test_json_exporter_content_type() {
        let exporter = JsonExporter::new();
        assert_eq!(exporter.content_type(), "application/json");
    }

    // ── Batch tests ───────────────────────────────────────────────

    #[test]
    fn test_cef_batch_export() {
        let exporter = CefExporter::new();
        let events = vec![sample_event()];
        let batched = exporter.export_batch(&events).unwrap();
        assert_eq!(batched.len(), 1);
    }

    #[test]
    fn test_ocsf_batch_export() {
        let exporter = OcsfExporter::new();
        let events = vec![sample_event()];
        let batched = exporter.export_batch(&events).unwrap();
        assert_eq!(batched.len(), 1);
    }

    #[test]
    fn test_json_batch_export() {
        let exporter = JsonExporter::new();
        let events = vec![sample_event()];
        let batched = exporter.export_batch(&events).unwrap();
        assert_eq!(batched.len(), 1);
    }
}
