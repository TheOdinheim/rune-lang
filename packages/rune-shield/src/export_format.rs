// ═══════════════════════════════════════════════════════════════════════
// Export Format — Verdict and rule export format interfaces.
//
// Layer 3 defines serialization formats for verdicts and detection
// rules so they can be exported to SIEM, SOAR, and threat intel
// platforms. RUNE produces the bytes — the customer ships them.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::DetectionRule;
use crate::error::ShieldError;
use crate::response::ShieldVerdict;

// ── VerdictExporter trait ────────────────────────────────────────

pub trait VerdictExporter {
    fn export_verdict(&self, verdict: &ShieldVerdict) -> Result<Vec<u8>, ShieldError>;
    fn export_batch(&self, verdicts: &[&ShieldVerdict]) -> Result<Vec<u8>, ShieldError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonVerdictExporter ──────────────────────────────────────────

pub struct JsonVerdictExporter;

impl JsonVerdictExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonVerdictExporter {
    fn default() -> Self {
        Self::new()
    }
}

fn verdict_to_json(verdict: &ShieldVerdict) -> serde_json::Value {
    serde_json::json!({
        "action": verdict.action.to_string(),
        "severity": format!("{:?}", verdict.severity),
        "confidence": verdict.confidence,
        "evidence": verdict.evidence,
        "governance_decision": verdict.action.to_governance_decision().to_string(),
    })
}

impl VerdictExporter for JsonVerdictExporter {
    fn export_verdict(&self, verdict: &ShieldVerdict) -> Result<Vec<u8>, ShieldError> {
        let json = verdict_to_json(verdict);
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("JSON export: {e}")))
    }

    fn export_batch(&self, verdicts: &[&ShieldVerdict]) -> Result<Vec<u8>, ShieldError> {
        let arr: Vec<serde_json::Value> = verdicts.iter().map(|v| verdict_to_json(v)).collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("JSON batch export: {e}")))
    }

    fn format_name(&self) -> &str {
        "json"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── StixVerdictExporter ──────────────────────────────────────────

/// STIX 2.1 sighting object shape. One-way export only — this
/// layer does not parse STIX, only produces it.
pub struct StixVerdictExporter;

impl StixVerdictExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StixVerdictExporter {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_to_stix(severity: rune_security::SecuritySeverity) -> &'static str {
    match severity {
        rune_security::SecuritySeverity::Info => "informational",
        rune_security::SecuritySeverity::Low => "low",
        rune_security::SecuritySeverity::Medium => "medium",
        rune_security::SecuritySeverity::High => "high",
        rune_security::SecuritySeverity::Critical => "critical",
        rune_security::SecuritySeverity::Emergency => "critical",
    }
}

impl VerdictExporter for StixVerdictExporter {
    fn export_verdict(&self, verdict: &ShieldVerdict) -> Result<Vec<u8>, ShieldError> {
        let stix = serde_json::json!({
            "type": "sighting",
            "spec_version": "2.1",
            "sighting_of_ref": "indicator--rune-shield-detection",
            "confidence": (verdict.confidence * 100.0) as u32,
            "severity": severity_to_stix(verdict.severity),
            "description": verdict.action.to_string(),
            "custom_properties": {
                "x_rune_governance_decision": verdict.action.to_governance_decision().to_string(),
                "x_rune_evidence": verdict.evidence,
            }
        });
        serde_json::to_vec_pretty(&stix)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("STIX export: {e}")))
    }

    fn export_batch(&self, verdicts: &[&ShieldVerdict]) -> Result<Vec<u8>, ShieldError> {
        let bundle = serde_json::json!({
            "type": "bundle",
            "spec_version": "2.1",
            "objects": verdicts.iter().map(|v| serde_json::json!({
                "type": "sighting",
                "spec_version": "2.1",
                "sighting_of_ref": "indicator--rune-shield-detection",
                "confidence": (v.confidence * 100.0) as u32,
                "severity": severity_to_stix(v.severity),
                "description": v.action.to_string(),
            })).collect::<Vec<_>>()
        });
        serde_json::to_vec_pretty(&bundle)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("STIX batch export: {e}")))
    }

    fn format_name(&self) -> &str {
        "stix-2.1"
    }

    fn content_type(&self) -> &str {
        "application/stix+json"
    }
}

// ── OcsfVerdictExporter ──────────────────────────────────────────

/// OCSF Detection Finding (class_uid 2004).
pub struct OcsfVerdictExporter;

impl OcsfVerdictExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OcsfVerdictExporter {
    fn default() -> Self {
        Self::new()
    }
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

impl VerdictExporter for OcsfVerdictExporter {
    fn export_verdict(&self, verdict: &ShieldVerdict) -> Result<Vec<u8>, ShieldError> {
        let ocsf = serde_json::json!({
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": severity_to_ocsf_id(verdict.severity),
            "confidence_id": if verdict.confidence >= 0.9 { 3 } else if verdict.confidence >= 0.5 { 2 } else { 1 },
            "confidence_score": (verdict.confidence * 100.0) as u32,
            "finding": {
                "title": verdict.action.to_string(),
                "desc": verdict.evidence.join("; "),
            },
            "status": verdict.action.to_governance_decision().to_string(),
        });
        serde_json::to_vec_pretty(&ocsf)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("OCSF export: {e}")))
    }

    fn export_batch(&self, verdicts: &[&ShieldVerdict]) -> Result<Vec<u8>, ShieldError> {
        let arr: Vec<serde_json::Value> = verdicts
            .iter()
            .map(|v| {
                serde_json::json!({
                    "class_uid": 2004,
                    "class_name": "Detection Finding",
                    "severity_id": severity_to_ocsf_id(v.severity),
                    "confidence_score": (v.confidence * 100.0) as u32,
                    "finding": { "title": v.action.to_string() },
                    "status": v.action.to_governance_decision().to_string(),
                })
            })
            .collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("OCSF batch export: {e}")))
    }

    fn format_name(&self) -> &str {
        "ocsf-2004"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── MispVerdictExporter ──────────────────────────────────────────

/// MISP event JSON shape with attributes array.
pub struct MispVerdictExporter;

impl MispVerdictExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MispVerdictExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl VerdictExporter for MispVerdictExporter {
    fn export_verdict(&self, verdict: &ShieldVerdict) -> Result<Vec<u8>, ShieldError> {
        let misp = serde_json::json!({
            "Event": {
                "info": format!("RUNE Shield: {}", verdict.action),
                "threat_level_id": match verdict.severity {
                    rune_security::SecuritySeverity::Critical | rune_security::SecuritySeverity::Emergency => "1",
                    rune_security::SecuritySeverity::High => "2",
                    rune_security::SecuritySeverity::Medium => "3",
                    _ => "4",
                },
                "Attribute": verdict.evidence.iter().map(|e| {
                    serde_json::json!({
                        "type": "text",
                        "category": "Payload delivery",
                        "value": e,
                    })
                }).collect::<Vec<_>>(),
            }
        });
        serde_json::to_vec_pretty(&misp)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("MISP export: {e}")))
    }

    fn export_batch(&self, verdicts: &[&ShieldVerdict]) -> Result<Vec<u8>, ShieldError> {
        let events: Vec<serde_json::Value> = verdicts
            .iter()
            .map(|v| {
                serde_json::json!({
                    "Event": {
                        "info": format!("RUNE Shield: {}", v.action),
                        "Attribute": v.evidence.iter().map(|e| {
                            serde_json::json!({"type": "text", "value": e})
                        }).collect::<Vec<_>>(),
                    }
                })
            })
            .collect();
        serde_json::to_vec_pretty(&events)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("MISP batch export: {e}")))
    }

    fn format_name(&self) -> &str {
        "misp"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── SigmaRuleExporter ────────────────────────────────────────────

/// Sigma rule YAML-equivalent JSON for detection rules (not verdicts).
/// Supports SOC rule pack distribution.
pub struct SigmaRuleExporter;

impl SigmaRuleExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SigmaRuleExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SigmaRuleExporter {
    pub fn export_rule(&self, rule: &DetectionRule) -> Result<Vec<u8>, ShieldError> {
        let sigma = serde_json::json!({
            "title": rule.name,
            "id": rule.id,
            "status": if rule.enabled { "experimental" } else { "test" },
            "level": rule.severity.to_lowercase(),
            "detection": {
                "selection": {
                    "pattern": rule.pattern,
                },
                "condition": "selection",
            },
            "tags": [format!("attack.{}", rule.category)],
            "falsepositives": [],
        });
        serde_json::to_vec_pretty(&sigma)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("Sigma export: {e}")))
    }

    pub fn export_rules(&self, rules: &[&DetectionRule]) -> Result<Vec<u8>, ShieldError> {
        let arr: Vec<serde_json::Value> = rules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "title": r.name,
                    "id": r.id,
                    "level": r.severity.to_lowercase(),
                    "detection": { "selection": { "pattern": r.pattern } },
                })
            })
            .collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("Sigma batch export: {e}")))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::response::ShieldVerdict;
    use rune_security::SecuritySeverity;

    fn make_verdict() -> ShieldVerdict {
        ShieldVerdict::block("prompt injection detected", SecuritySeverity::High, 0.92)
            .with_evidence("pattern-match: ignore previous")
    }

    fn make_rule() -> DetectionRule {
        DetectionRule {
            id: "r1".to_string(),
            name: "Prompt Injection Pattern".to_string(),
            pattern: "ignore.*previous.*instructions".to_string(),
            severity: "High".to_string(),
            category: "injection".to_string(),
            enabled: true,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_json_exporter_produces_valid_json() {
        let exporter = JsonVerdictExporter::new();
        let verdict = make_verdict();
        let data = exporter.export_verdict(&verdict).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(parsed["action"].as_str().unwrap().contains("Block"));
        assert_eq!(parsed["governance_decision"], "Deny");
    }

    #[test]
    fn test_json_exporter_batch() {
        let exporter = JsonVerdictExporter::new();
        let v1 = make_verdict();
        let v2 = ShieldVerdict::allow();
        let data = exporter.export_batch(&[&v1, &v2]).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_stix_exporter_produces_sighting() {
        let exporter = StixVerdictExporter::new();
        let verdict = make_verdict();
        let data = exporter.export_verdict(&verdict).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["type"], "sighting");
        assert_eq!(parsed["spec_version"], "2.1");
        assert_eq!(parsed["confidence"], 92);
    }

    #[test]
    fn test_stix_exporter_batch_bundle() {
        let exporter = StixVerdictExporter::new();
        let v = make_verdict();
        let data = exporter.export_batch(&[&v]).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["type"], "bundle");
    }

    #[test]
    fn test_ocsf_exporter_class_uid_2004() {
        let exporter = OcsfVerdictExporter::new();
        let verdict = make_verdict();
        let data = exporter.export_verdict(&verdict).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["class_uid"], 2004);
        assert_eq!(parsed["class_name"], "Detection Finding");
        assert_eq!(parsed["severity_id"], 4); // High
    }

    #[test]
    fn test_ocsf_confidence_mapping() {
        let exporter = OcsfVerdictExporter::new();
        let v = ShieldVerdict::block("test", SecuritySeverity::Low, 0.3);
        let data = exporter.export_verdict(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["confidence_id"], 1); // low confidence
    }

    #[test]
    fn test_misp_exporter_produces_event() {
        let exporter = MispVerdictExporter::new();
        let verdict = make_verdict();
        let data = exporter.export_verdict(&verdict).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert!(parsed["Event"]["info"].as_str().unwrap().contains("RUNE Shield"));
        assert_eq!(parsed["Event"]["threat_level_id"], "2"); // High
    }

    #[test]
    fn test_sigma_rule_exporter() {
        let exporter = SigmaRuleExporter::new();
        let rule = make_rule();
        let data = exporter.export_rule(&rule).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["title"], "Prompt Injection Pattern");
        assert_eq!(parsed["level"], "high");
        assert!(parsed["detection"]["selection"]["pattern"].as_str().is_some());
    }

    #[test]
    fn test_sigma_batch_export() {
        let exporter = SigmaRuleExporter::new();
        let rule = make_rule();
        let data = exporter.export_rules(&[&rule]).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_format_names_and_content_types() {
        assert_eq!(JsonVerdictExporter::new().format_name(), "json");
        assert_eq!(StixVerdictExporter::new().format_name(), "stix-2.1");
        assert_eq!(OcsfVerdictExporter::new().format_name(), "ocsf-2004");
        assert_eq!(MispVerdictExporter::new().format_name(), "misp");
        assert_eq!(StixVerdictExporter::new().content_type(), "application/stix+json");
    }
}
