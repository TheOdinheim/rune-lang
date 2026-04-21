// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — SafetyExporter trait for safety cases, envelopes, violation
// reports, and shutdown records in standards-aligned formats.
// ═══════════════════════════════════════════════════════════════════════

use serde_json::json;

use crate::backend::{
    StoredBoundaryViolationRecord, StoredSafetyCaseRecord, StoredSafetyEnvelope,
    StoredShutdownRecord,
};
use crate::error::SafetyError;

// ── SafetyExporter trait ────────────────────────────────────────────

pub trait SafetyExporter {
    fn export_safety_case(
        &self,
        case: &StoredSafetyCaseRecord,
    ) -> Result<Vec<u8>, SafetyError>;

    fn export_envelope(
        &self,
        envelope: &StoredSafetyEnvelope,
    ) -> Result<Vec<u8>, SafetyError>;

    fn export_violation_report(
        &self,
        violations: &[StoredBoundaryViolationRecord],
        shutdowns: &[StoredShutdownRecord],
    ) -> Result<Vec<u8>, SafetyError>;

    fn export_batch(
        &self,
        cases: &[StoredSafetyCaseRecord],
    ) -> Result<Vec<Vec<u8>>, SafetyError> {
        cases.iter().map(|c| self.export_safety_case(c)).collect()
    }

    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonSafetyExporter ──────────────────────────────────────────────

pub struct JsonSafetyExporter;

impl JsonSafetyExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonSafetyExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyExporter for JsonSafetyExporter {
    fn export_safety_case(
        &self,
        case: &StoredSafetyCaseRecord,
    ) -> Result<Vec<u8>, SafetyError> {
        let doc = json!({
            "safety_case": {
                "case_id": case.case_id,
                "system_id": case.system_id,
                "name": case.name,
                "description": case.description,
                "methodology": format!("{}", case.methodology),
                "top_level_claim": case.top_level_claim,
                "evidence_refs": case.evidence_refs,
                "status": format!("{}", case.status),
                "reviewed_by": case.reviewed_by,
                "reviewed_at": case.reviewed_at,
                "created_at": case.created_at,
                "metadata": case.metadata,
            }
        });
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SafetyError::SerializationFailed(e.to_string()))
    }

    fn export_envelope(
        &self,
        envelope: &StoredSafetyEnvelope,
    ) -> Result<Vec<u8>, SafetyError> {
        let doc = json!({
            "safety_envelope": {
                "envelope_id": envelope.envelope_id,
                "system_id": envelope.system_id,
                "name": envelope.name,
                "description": envelope.description,
                "constraint_refs": envelope.constraint_refs,
                "status": format!("{}", envelope.status),
                "safe_state_description": envelope.safe_state_description,
                "degraded_operation_available": envelope.degraded_operation_available,
                "created_at": envelope.created_at,
                "last_evaluated_at": envelope.last_evaluated_at,
                "metadata": envelope.metadata,
            }
        });
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SafetyError::SerializationFailed(e.to_string()))
    }

    fn export_violation_report(
        &self,
        violations: &[StoredBoundaryViolationRecord],
        shutdowns: &[StoredShutdownRecord],
    ) -> Result<Vec<u8>, SafetyError> {
        let v_json: Vec<_> = violations
            .iter()
            .map(|v| {
                json!({
                    "violation_id": v.violation_id,
                    "envelope_id": v.envelope_id,
                    "constraint_ref_violated": v.constraint_ref_violated,
                    "violation_description": v.violation_description,
                    "detected_at": v.detected_at,
                    "severity_at_detection": v.severity_at_detection,
                    "response_taken": v.response_taken,
                    "resolved_at": v.resolved_at,
                })
            })
            .collect();
        let s_json: Vec<_> = shutdowns
            .iter()
            .map(|s| {
                json!({
                    "shutdown_id": s.shutdown_id,
                    "system_id": s.system_id,
                    "trigger_reason": s.trigger_reason,
                    "shutdown_type": format!("{}", s.shutdown_type),
                    "initiated_at": s.initiated_at,
                    "completed_at": s.completed_at,
                    "reauthorization_required": s.reauthorization_required,
                })
            })
            .collect();
        let doc = json!({
            "violation_report": {
                "violations": v_json,
                "shutdowns": s_json,
            }
        });
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SafetyError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── GsnXmlExporter ──────────────────────────────────────────────────

pub struct GsnXmlExporter;

impl GsnXmlExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GsnXmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyExporter for GsnXmlExporter {
    fn export_safety_case(
        &self,
        case: &StoredSafetyCaseRecord,
    ) -> Result<Vec<u8>, SafetyError> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<gsn:SafetyCase xmlns:gsn=\"http://www.goalstructuringnotation.info/1.0\">\n");
        xml.push_str(&format!("  <gsn:goal id=\"{}\">\n", case.case_id));
        xml.push_str(&format!(
            "    <gsn:statement>{}</gsn:statement>\n",
            case.top_level_claim
        ));
        xml.push_str(&format!(
            "    <gsn:status>{}</gsn:status>\n",
            case.status
        ));
        xml.push_str("  </gsn:goal>\n");
        for ev_ref in &case.evidence_refs {
            xml.push_str(&format!("  <gsn:solution ref=\"{ev_ref}\"/>\n"));
        }
        xml.push_str("</gsn:SafetyCase>\n");
        Ok(xml.into_bytes())
    }

    fn export_envelope(
        &self,
        _envelope: &StoredSafetyEnvelope,
    ) -> Result<Vec<u8>, SafetyError> {
        Err(SafetyError::InvalidOperation(
            "GSN XML export is for safety cases only".into(),
        ))
    }

    fn export_violation_report(
        &self,
        _violations: &[StoredBoundaryViolationRecord],
        _shutdowns: &[StoredShutdownRecord],
    ) -> Result<Vec<u8>, SafetyError> {
        Err(SafetyError::InvalidOperation(
            "GSN XML export is for safety cases only".into(),
        ))
    }

    fn format_name(&self) -> &str {
        "GSN-XML"
    }

    fn content_type(&self) -> &str {
        "application/xml"
    }
}

// ── SafetyCaseReportExporter ────────────────────────────────────────

pub struct SafetyCaseReportExporter;

impl SafetyCaseReportExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SafetyCaseReportExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyExporter for SafetyCaseReportExporter {
    fn export_safety_case(
        &self,
        case: &StoredSafetyCaseRecord,
    ) -> Result<Vec<u8>, SafetyError> {
        let mut md = String::new();
        md.push_str(&format!("# Safety Case: {}\n\n", case.name));
        md.push_str(&format!("**System**: {}\n\n", case.system_id));
        md.push_str(&format!("**Methodology**: {}\n\n", case.methodology));
        md.push_str(&format!("**Status**: {}\n\n", case.status));
        md.push_str("## Top-Level Claim\n\n");
        md.push_str(&format!("{}\n\n", case.top_level_claim));
        md.push_str("## Evidence References\n\n");
        for ev_ref in &case.evidence_refs {
            md.push_str(&format!("- {ev_ref}\n"));
        }
        if let Some(ref reviewer) = case.reviewed_by {
            md.push_str(&format!("\n**Reviewed by**: {reviewer}\n"));
        }
        Ok(md.into_bytes())
    }

    fn export_envelope(
        &self,
        envelope: &StoredSafetyEnvelope,
    ) -> Result<Vec<u8>, SafetyError> {
        let mut md = String::new();
        md.push_str(&format!("# Safety Envelope: {}\n\n", envelope.name));
        md.push_str(&format!("**System**: {}\n\n", envelope.system_id));
        md.push_str(&format!("**Status**: {}\n\n", envelope.status));
        md.push_str("## Safe State\n\n");
        md.push_str(&format!("{}\n\n", envelope.safe_state_description));
        md.push_str(&format!(
            "**Degraded operation available**: {}\n\n",
            envelope.degraded_operation_available
        ));
        md.push_str("## Constraint References\n\n");
        for c_ref in &envelope.constraint_refs {
            md.push_str(&format!("- {c_ref}\n"));
        }
        Ok(md.into_bytes())
    }

    fn export_violation_report(
        &self,
        violations: &[StoredBoundaryViolationRecord],
        shutdowns: &[StoredShutdownRecord],
    ) -> Result<Vec<u8>, SafetyError> {
        let mut md = String::new();
        md.push_str("# Safety Incident Report\n\n");
        md.push_str("## Boundary Violations\n\n");
        for v in violations {
            md.push_str(&format!(
                "- **{}**: {} (constraint: {}, severity: {})\n",
                v.violation_id,
                v.violation_description,
                v.constraint_ref_violated,
                v.severity_at_detection
            ));
        }
        md.push_str("\n## Emergency Shutdowns\n\n");
        for s in shutdowns {
            md.push_str(&format!(
                "- **{}**: {} (type: {}, system: {})\n",
                s.shutdown_id, s.trigger_reason, s.shutdown_type, s.system_id
            ));
        }
        Ok(md.into_bytes())
    }

    fn format_name(&self) -> &str {
        "Markdown-Report"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── BowTieExporter ──────────────────────────────────────────────────

pub struct BowTieExporter;

impl BowTieExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BowTieExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyExporter for BowTieExporter {
    fn export_safety_case(
        &self,
        _case: &StoredSafetyCaseRecord,
    ) -> Result<Vec<u8>, SafetyError> {
        Err(SafetyError::InvalidOperation(
            "BowTie export is for envelopes/violations only".into(),
        ))
    }

    fn export_envelope(
        &self,
        envelope: &StoredSafetyEnvelope,
    ) -> Result<Vec<u8>, SafetyError> {
        let doc = json!({
            "bowtie_analysis": {
                "hazard": format!("Violation of envelope: {}", envelope.name),
                "threats": envelope.constraint_refs.iter().map(|c| {
                    json!({
                        "constraint_ref": c,
                        "description": format!("Violation of constraint {c}"),
                    })
                }).collect::<Vec<_>>(),
                "barriers": envelope.constraint_refs.iter().map(|c| {
                    json!({
                        "barrier_ref": c,
                        "type": "safety_constraint",
                    })
                }).collect::<Vec<_>>(),
                "consequences": [{
                    "if_degraded_available": envelope.degraded_operation_available,
                    "safe_state": &envelope.safe_state_description,
                }],
            }
        });
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SafetyError::SerializationFailed(e.to_string()))
    }

    fn export_violation_report(
        &self,
        violations: &[StoredBoundaryViolationRecord],
        shutdowns: &[StoredShutdownRecord],
    ) -> Result<Vec<u8>, SafetyError> {
        let doc = json!({
            "bowtie_incident_report": {
                "realized_threats": violations.iter().map(|v| {
                    json!({
                        "violation_id": v.violation_id,
                        "constraint_ref": v.constraint_ref_violated,
                        "description": v.violation_description,
                        "response": v.response_taken,
                    })
                }).collect::<Vec<_>>(),
                "consequence_actions": shutdowns.iter().map(|s| {
                    json!({
                        "shutdown_id": s.shutdown_id,
                        "type": format!("{}", s.shutdown_type),
                        "trigger": s.trigger_reason,
                    })
                }).collect::<Vec<_>>(),
            }
        });
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SafetyError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "BowTie-JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── IncidentReportExporter ──────────────────────────────────────────

pub struct IncidentReportExporter;

impl IncidentReportExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IncidentReportExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyExporter for IncidentReportExporter {
    fn export_safety_case(
        &self,
        _case: &StoredSafetyCaseRecord,
    ) -> Result<Vec<u8>, SafetyError> {
        Err(SafetyError::InvalidOperation(
            "Incident report export is for violations/shutdowns only".into(),
        ))
    }

    fn export_envelope(
        &self,
        _envelope: &StoredSafetyEnvelope,
    ) -> Result<Vec<u8>, SafetyError> {
        Err(SafetyError::InvalidOperation(
            "Incident report export is for violations/shutdowns only".into(),
        ))
    }

    fn export_violation_report(
        &self,
        violations: &[StoredBoundaryViolationRecord],
        shutdowns: &[StoredShutdownRecord],
    ) -> Result<Vec<u8>, SafetyError> {
        let doc = json!({
            "incident_report": {
                "report_type": "safety_incident",
                "incidents": violations.iter().map(|v| {
                    json!({
                        "incident_id": v.violation_id,
                        "category": "boundary_violation",
                        "system_id": v.system_id,
                        "envelope_id": v.envelope_id,
                        "description": v.violation_description,
                        "severity": v.severity_at_detection,
                        "detected_at": v.detected_at,
                        "response_action": v.response_taken,
                        "resolved_at": v.resolved_at,
                        "constraint_ref": v.constraint_ref_violated,
                    })
                }).collect::<Vec<_>>(),
                "shutdowns": shutdowns.iter().map(|s| {
                    json!({
                        "shutdown_id": s.shutdown_id,
                        "system_id": s.system_id,
                        "category": "emergency_shutdown",
                        "trigger_reason": s.trigger_reason,
                        "shutdown_type": format!("{}", s.shutdown_type),
                        "initiated_by": s.initiated_by,
                        "initiated_at": s.initiated_at,
                        "completed_at": s.completed_at,
                        "reauthorization_required": s.reauthorization_required,
                    })
                }).collect::<Vec<_>>(),
            }
        });
        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SafetyError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "Incident-Report"
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
    use std::collections::HashMap;

    use super::*;
    use crate::backend::{
        SafetyCaseMethodology, SafetyCaseRecordStatus, ShutdownType, StoredEnvelopeStatus,
    };

    fn sample_case() -> StoredSafetyCaseRecord {
        StoredSafetyCaseRecord {
            case_id: "case-1".into(),
            system_id: "sys-1".into(),
            name: "Test case".into(),
            description: "desc".into(),
            methodology: SafetyCaseMethodology::Gsn,
            top_level_claim: "System is safe".into(),
            argument_structure_bytes: vec![],
            evidence_refs: vec!["ev-1".into(), "ev-2".into()],
            status: SafetyCaseRecordStatus::Accepted,
            reviewed_by: Some("reviewer".into()),
            reviewed_at: Some(5000),
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_envelope() -> StoredSafetyEnvelope {
        StoredSafetyEnvelope {
            envelope_id: "env-1".into(),
            system_id: "sys-1".into(),
            name: "Production".into(),
            description: "desc".into(),
            constraint_refs: vec!["c-1".into(), "c-2".into()],
            status: StoredEnvelopeStatus::Active,
            safe_state_description: "fallback mode".into(),
            degraded_operation_available: true,
            created_at: 1000,
            last_evaluated_at: 2000,
            metadata: HashMap::new(),
        }
    }

    fn sample_violation() -> StoredBoundaryViolationRecord {
        StoredBoundaryViolationRecord {
            violation_id: "v-1".into(),
            envelope_id: "env-1".into(),
            system_id: "sys-1".into(),
            constraint_ref_violated: "c-1".into(),
            violation_description: "latency exceeded".into(),
            detected_at: 3000,
            severity_at_detection: "Critical".into(),
            response_taken: "degraded".into(),
            resolved_at: Some(3500),
            metadata: HashMap::new(),
        }
    }

    fn sample_shutdown() -> StoredShutdownRecord {
        StoredShutdownRecord {
            shutdown_id: "sd-1".into(),
            system_id: "sys-1".into(),
            envelope_id: Some("env-1".into()),
            trigger_reason: "repeated violations".into(),
            initiated_by: "controller".into(),
            initiated_at: 4000,
            completed_at: Some(4100),
            shutdown_type: ShutdownType::EmergencyImmediate,
            reauthorization_required: true,
            reauthorized_by: None,
            reauthorized_at: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_json_export_case() {
        let exp = JsonSafetyExporter::new();
        let bytes = exp.export_safety_case(&sample_case()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("case-1"));
        assert!(s.contains("System is safe"));
    }

    #[test]
    fn test_json_export_envelope() {
        let exp = JsonSafetyExporter::new();
        let bytes = exp.export_envelope(&sample_envelope()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("env-1"));
        assert!(s.contains("fallback mode"));
    }

    #[test]
    fn test_json_export_violation_report() {
        let exp = JsonSafetyExporter::new();
        let bytes = exp
            .export_violation_report(&[sample_violation()], &[sample_shutdown()])
            .unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("v-1"));
        assert!(s.contains("sd-1"));
    }

    #[test]
    fn test_gsn_xml_export() {
        let exp = GsnXmlExporter::new();
        let bytes = exp.export_safety_case(&sample_case()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("<gsn:SafetyCase"));
        assert!(s.contains("System is safe"));
        assert!(s.contains("ev-1"));
        // GSN doesn't support envelope/violation export
        assert!(exp.export_envelope(&sample_envelope()).is_err());
    }

    #[test]
    fn test_markdown_report_case() {
        let exp = SafetyCaseReportExporter::new();
        let bytes = exp.export_safety_case(&sample_case()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("# Safety Case:"));
        assert!(s.contains("reviewer"));
    }

    #[test]
    fn test_markdown_report_envelope() {
        let exp = SafetyCaseReportExporter::new();
        let bytes = exp.export_envelope(&sample_envelope()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("# Safety Envelope:"));
    }

    #[test]
    fn test_bowtie_export_envelope() {
        let exp = BowTieExporter::new();
        let bytes = exp.export_envelope(&sample_envelope()).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("bowtie_analysis"));
        assert!(s.contains("barriers"));
    }

    #[test]
    fn test_incident_report_export() {
        let exp = IncidentReportExporter::new();
        let bytes = exp
            .export_violation_report(&[sample_violation()], &[sample_shutdown()])
            .unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("incident_report"));
        assert!(s.contains("boundary_violation"));
        assert!(s.contains("emergency_shutdown"));
    }

    #[test]
    fn test_format_metadata() {
        assert_eq!(JsonSafetyExporter::new().format_name(), "JSON");
        assert_eq!(GsnXmlExporter::new().content_type(), "application/xml");
        assert_eq!(SafetyCaseReportExporter::new().content_type(), "text/markdown");
        assert_eq!(BowTieExporter::new().format_name(), "BowTie-JSON");
        assert_eq!(IncidentReportExporter::new().format_name(), "Incident-Report");
    }
}
