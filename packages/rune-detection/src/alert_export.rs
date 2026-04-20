// ═══════════════════════════════════════════════════════════════════════
// Alert Export — Alert/finding export format interfaces.
//
// Layer 3 defines serialization formats for detection findings so
// they can be exported to SIEM, SOAR, and threat intel platforms.
// RUNE produces the bytes — the customer ships them.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::DetectionFinding;
use crate::error::DetectionError;

// ── AlertExporter trait ─────────────────────────────────────────

pub trait AlertExporter {
    fn export_finding(&self, finding: &DetectionFinding) -> Result<Vec<u8>, DetectionError>;
    fn export_batch(&self, findings: &[&DetectionFinding]) -> Result<Vec<u8>, DetectionError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonAlertExporter ───────────────────────────────────────────

pub struct JsonAlertExporter;

impl JsonAlertExporter {
    pub fn new() -> Self { Self }
}

impl Default for JsonAlertExporter {
    fn default() -> Self { Self::new() }
}

fn finding_to_json(f: &DetectionFinding) -> serde_json::Value {
    serde_json::json!({
        "id": f.id,
        "title": f.title,
        "description": f.description,
        "severity": format!("{:?}", f.severity),
        "category": f.category,
        "source": f.source,
        "timestamp": f.timestamp,
        "evidence": f.evidence,
        "metadata": f.metadata,
    })
}

impl AlertExporter for JsonAlertExporter {
    fn export_finding(&self, finding: &DetectionFinding) -> Result<Vec<u8>, DetectionError> {
        serde_json::to_vec_pretty(&finding_to_json(finding))
            .map_err(|e| DetectionError::InvalidConfiguration(format!("JSON export: {e}")))
    }

    fn export_batch(&self, findings: &[&DetectionFinding]) -> Result<Vec<u8>, DetectionError> {
        let arr: Vec<serde_json::Value> = findings.iter().map(|f| finding_to_json(f)).collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("JSON batch: {e}")))
    }

    fn format_name(&self) -> &str { "json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── CefAlertExporter ────────────────────────────────────────────

/// ArcSight CEF header format.
pub struct CefAlertExporter;

impl CefAlertExporter {
    pub fn new() -> Self { Self }
}

impl Default for CefAlertExporter {
    fn default() -> Self { Self::new() }
}

fn severity_to_cef(severity: rune_security::SecuritySeverity) -> u32 {
    match severity {
        rune_security::SecuritySeverity::Info => 1,
        rune_security::SecuritySeverity::Low => 3,
        rune_security::SecuritySeverity::Medium => 5,
        rune_security::SecuritySeverity::High => 7,
        rune_security::SecuritySeverity::Critical => 9,
        rune_security::SecuritySeverity::Emergency => 10,
    }
}

impl AlertExporter for CefAlertExporter {
    fn export_finding(&self, finding: &DetectionFinding) -> Result<Vec<u8>, DetectionError> {
        let sev = severity_to_cef(finding.severity);
        let cef = format!(
            "CEF:0|Odin's LLC|RUNE-Detection|1.0|{}|{}|{sev}|cat={} src={} rt={}",
            finding.id, finding.title, finding.category, finding.source, finding.timestamp,
        );
        Ok(cef.into_bytes())
    }

    fn export_batch(&self, findings: &[&DetectionFinding]) -> Result<Vec<u8>, DetectionError> {
        let mut lines = Vec::new();
        for f in findings {
            lines.push(String::from_utf8(self.export_finding(f)?).unwrap());
        }
        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "cef" }
    fn content_type(&self) -> &str { "text/plain" }
}

// ── OcsfAlertExporter ───────────────────────────────────────────

/// OCSF Detection Finding (class_uid 2004).
pub struct OcsfAlertExporter;

impl OcsfAlertExporter {
    pub fn new() -> Self { Self }
}

impl Default for OcsfAlertExporter {
    fn default() -> Self { Self::new() }
}

fn severity_to_ocsf_id(severity: rune_security::SecuritySeverity) -> u32 {
    match severity {
        rune_security::SecuritySeverity::Info => 1,
        rune_security::SecuritySeverity::Low => 2,
        rune_security::SecuritySeverity::Medium => 3,
        rune_security::SecuritySeverity::High => 4,
        rune_security::SecuritySeverity::Critical => 5,
        rune_security::SecuritySeverity::Emergency => 6,
    }
}

impl AlertExporter for OcsfAlertExporter {
    fn export_finding(&self, finding: &DetectionFinding) -> Result<Vec<u8>, DetectionError> {
        let ocsf = serde_json::json!({
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": severity_to_ocsf_id(finding.severity),
            "finding": {
                "title": finding.title,
                "desc": finding.description,
                "uid": finding.id,
            },
            "time": finding.timestamp,
            "metadata": {
                "product": { "name": "RUNE-Detection", "vendor_name": "Odin's LLC" },
            },
        });
        serde_json::to_vec_pretty(&ocsf)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("OCSF export: {e}")))
    }

    fn export_batch(&self, findings: &[&DetectionFinding]) -> Result<Vec<u8>, DetectionError> {
        let arr: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "class_uid": 2004,
                    "severity_id": severity_to_ocsf_id(f.severity),
                    "finding": { "title": f.title, "uid": f.id },
                    "time": f.timestamp,
                })
            })
            .collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("OCSF batch: {e}")))
    }

    fn format_name(&self) -> &str { "ocsf-2004" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── EcsAlertExporter ────────────────────────────────────────────

/// Elastic Common Schema shape.
pub struct EcsAlertExporter;

impl EcsAlertExporter {
    pub fn new() -> Self { Self }
}

impl Default for EcsAlertExporter {
    fn default() -> Self { Self::new() }
}

impl AlertExporter for EcsAlertExporter {
    fn export_finding(&self, finding: &DetectionFinding) -> Result<Vec<u8>, DetectionError> {
        let ecs = serde_json::json!({
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "severity": severity_to_ocsf_id(finding.severity),
            },
            "threat": {
                "technique": { "name": finding.category },
            },
            "observer": {
                "product": "RUNE-Detection",
                "vendor": "Odin's LLC",
            },
            "message": finding.title,
            "@timestamp": finding.timestamp,
            "rule": { "id": finding.id, "description": finding.description },
        });
        serde_json::to_vec_pretty(&ecs)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("ECS export: {e}")))
    }

    fn export_batch(&self, findings: &[&DetectionFinding]) -> Result<Vec<u8>, DetectionError> {
        let arr: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "event": { "kind": "alert", "category": ["intrusion_detection"] },
                    "message": f.title,
                    "@timestamp": f.timestamp,
                })
            })
            .collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("ECS batch: {e}")))
    }

    fn format_name(&self) -> &str { "ecs" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── SplunkNotableExporter ───────────────────────────────────────

/// Splunk notable event JSON.
pub struct SplunkNotableExporter;

impl SplunkNotableExporter {
    pub fn new() -> Self { Self }
}

impl Default for SplunkNotableExporter {
    fn default() -> Self { Self::new() }
}

impl AlertExporter for SplunkNotableExporter {
    fn export_finding(&self, finding: &DetectionFinding) -> Result<Vec<u8>, DetectionError> {
        let urgency = match finding.severity {
            rune_security::SecuritySeverity::Critical | rune_security::SecuritySeverity::Emergency => "critical",
            rune_security::SecuritySeverity::High => "high",
            rune_security::SecuritySeverity::Medium => "medium",
            rune_security::SecuritySeverity::Low => "low",
            rune_security::SecuritySeverity::Info => "informational",
        };
        let notable = serde_json::json!({
            "search_name": format!("RUNE Detection: {}", finding.title),
            "urgency": urgency,
            "severity": format!("{:?}", finding.severity),
            "title": finding.title,
            "description": finding.description,
            "source": finding.source,
            "time": finding.timestamp,
        });
        serde_json::to_vec_pretty(&notable)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("Splunk export: {e}")))
    }

    fn export_batch(&self, findings: &[&DetectionFinding]) -> Result<Vec<u8>, DetectionError> {
        let arr: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "search_name": format!("RUNE Detection: {}", f.title),
                    "title": f.title,
                    "time": f.timestamp,
                })
            })
            .collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| DetectionError::InvalidConfiguration(format!("Splunk batch: {e}")))
    }

    fn format_name(&self) -> &str { "splunk-notable" }
    fn content_type(&self) -> &str { "application/json" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rune_security::SecuritySeverity;

    fn make_finding() -> DetectionFinding {
        DetectionFinding::new("f1", "Prompt Injection Detected", SecuritySeverity::High, 1000)
            .with_category("injection")
            .with_source("pipeline-1")
            .with_description("Suspicious prompt pattern")
            .with_evidence("ignore previous instructions")
    }

    #[test]
    fn test_json_exporter() {
        let exp = JsonAlertExporter::new();
        let f = make_finding();
        let data = exp.export_finding(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["id"], "f1");
        assert_eq!(parsed["category"], "injection");
    }

    #[test]
    fn test_json_batch() {
        let exp = JsonAlertExporter::new();
        let f = make_finding();
        let data = exp.export_batch(&[&f]).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_cef_exporter() {
        let exp = CefAlertExporter::new();
        let f = make_finding();
        let data = exp.export_finding(&f).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.starts_with("CEF:0|Odin's LLC|RUNE-Detection|1.0"));
        assert!(text.contains("cat=injection"));
    }

    #[test]
    fn test_cef_batch() {
        let exp = CefAlertExporter::new();
        let f = make_finding();
        let data = exp.export_batch(&[&f]).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("CEF:0"));
    }

    #[test]
    fn test_ocsf_exporter() {
        let exp = OcsfAlertExporter::new();
        let f = make_finding();
        let data = exp.export_finding(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["class_uid"], 2004);
        assert_eq!(parsed["severity_id"], 4); // High
    }

    #[test]
    fn test_ecs_exporter() {
        let exp = EcsAlertExporter::new();
        let f = make_finding();
        let data = exp.export_finding(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["event"]["kind"], "alert");
        assert_eq!(parsed["observer"]["product"], "RUNE-Detection");
    }

    #[test]
    fn test_splunk_exporter() {
        let exp = SplunkNotableExporter::new();
        let f = make_finding();
        let data = exp.export_finding(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["urgency"], "high");
        assert!(parsed["search_name"].as_str().unwrap().contains("RUNE Detection"));
    }

    #[test]
    fn test_format_names_and_content_types() {
        assert_eq!(JsonAlertExporter::new().format_name(), "json");
        assert_eq!(CefAlertExporter::new().format_name(), "cef");
        assert_eq!(OcsfAlertExporter::new().format_name(), "ocsf-2004");
        assert_eq!(EcsAlertExporter::new().format_name(), "ecs");
        assert_eq!(SplunkNotableExporter::new().format_name(), "splunk-notable");
        assert_eq!(CefAlertExporter::new().content_type(), "text/plain");
    }

    #[test]
    fn test_splunk_batch() {
        let exp = SplunkNotableExporter::new();
        let f = make_finding();
        let data = exp.export_batch(&[&f]).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed.len(), 1);
    }
}
