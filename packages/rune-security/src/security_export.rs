// ═══════════════════════════════════════════════════════════════════════
// Security Export — Serialization of security data into standard
// external formats.
//
// Each exporter produces a Vec<u8> in a well-known format.  The trait
// takes stored record types from backend.rs so export always works
// from the canonical stored form.
//
// Five formats ship with this module:
//   1. STIX Course of Action (JSON)
//   2. CSAF Advisory (JSON)
//   3. VEX Statement (JSON)
//   4. OCSF Security Finding (JSON)
//   5. JSON — direct serialization
//
// All formats produce structurally valid JSON that a downstream
// system can enrich with signatures, contexts, etc.
// evidence_attestation_refs are preserved in all exports.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::{StoredIncidentRecord, StoredPostureSnapshot, StoredSecurityControlRecord, StoredVulnerabilityRecord};
use crate::error::SecurityError;

// ── SecurityDataExporter trait ───────────────────────────────────

pub trait SecurityDataExporter {
    fn export_vulnerability(&self, record: &StoredVulnerabilityRecord) -> Result<Vec<u8>, SecurityError>;
    fn export_incident(&self, record: &StoredIncidentRecord) -> Result<Vec<u8>, SecurityError>;
    fn export_posture_snapshot(&self, snapshot: &StoredPostureSnapshot) -> Result<Vec<u8>, SecurityError>;
    fn export_control_implementation(&self, record: &StoredSecurityControlRecord) -> Result<Vec<u8>, SecurityError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── Helper: build JSON object ────────────────────────────────────

fn vuln_to_json(record: &StoredVulnerabilityRecord) -> serde_json::Value {
    serde_json::json!({
        "vulnerability_id": record.vulnerability_id,
        "artifact_ref": record.artifact_ref,
        "cve_identifier": record.cve_identifier,
        "cvss_base_score": record.cvss_base_score,
        "cvss_severity": record.cvss_severity.to_string(),
        "discovered_at": record.discovered_at,
        "remediated_at": record.remediated_at,
        "evidence_attestation_refs": record.evidence_attestation_refs,
        "current_status": record.current_status.to_string(),
    })
}

fn incident_to_json(record: &StoredIncidentRecord) -> serde_json::Value {
    serde_json::json!({
        "incident_id": record.incident_id,
        "severity": record.severity,
        "status": record.status.to_string(),
        "declared_at": record.declared_at,
        "closed_at": record.closed_at,
        "description": record.description,
        "affected_systems": record.affected_systems,
    })
}

fn posture_to_json(snapshot: &StoredPostureSnapshot) -> serde_json::Value {
    serde_json::json!({
        "snapshot_id": snapshot.snapshot_id,
        "system_identifier": snapshot.system_identifier,
        "captured_at": snapshot.captured_at,
        "vulnerability_subscore": snapshot.vulnerability_subscore,
        "control_subscore": snapshot.control_subscore,
        "incident_subscore": snapshot.incident_subscore,
        "threat_exposure_subscore": snapshot.threat_exposure_subscore,
        "overall_score": snapshot.overall_score,
        "posture_class": format!("{:?}", snapshot.posture_class),
    })
}

fn control_to_json(record: &StoredSecurityControlRecord) -> serde_json::Value {
    serde_json::json!({
        "control_id": record.control_id,
        "framework_name": record.framework_name,
        "control_identifier": record.control_identifier,
        "implementation_status": record.implementation_status.to_string(),
        "last_validated_at": record.last_validated_at,
        "evidence_attestation_refs": record.evidence_attestation_refs,
    })
}

// ── JsonSecurityExporter ─────────────────────────────────────────

pub struct JsonSecurityExporter;

impl SecurityDataExporter for JsonSecurityExporter {
    fn export_vulnerability(&self, record: &StoredVulnerabilityRecord) -> Result<Vec<u8>, SecurityError> {
        serde_json::to_vec_pretty(&vuln_to_json(record))
            .map_err(|e| SecurityError::InvalidOperation(format!("JSON serialization failed: {e}")))
    }

    fn export_incident(&self, record: &StoredIncidentRecord) -> Result<Vec<u8>, SecurityError> {
        serde_json::to_vec_pretty(&incident_to_json(record))
            .map_err(|e| SecurityError::InvalidOperation(format!("JSON serialization failed: {e}")))
    }

    fn export_posture_snapshot(&self, snapshot: &StoredPostureSnapshot) -> Result<Vec<u8>, SecurityError> {
        serde_json::to_vec_pretty(&posture_to_json(snapshot))
            .map_err(|e| SecurityError::InvalidOperation(format!("JSON serialization failed: {e}")))
    }

    fn export_control_implementation(&self, record: &StoredSecurityControlRecord) -> Result<Vec<u8>, SecurityError> {
        serde_json::to_vec_pretty(&control_to_json(record))
            .map_err(|e| SecurityError::InvalidOperation(format!("JSON serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── StixCourseOfActionExporter ───────────────────────────────────

pub struct StixCourseOfActionExporter;

impl StixCourseOfActionExporter {
    fn wrap_stix(type_name: &str, id_prefix: &str, id: &str, body: serde_json::Value) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": type_name,
            "spec_version": "2.1",
            "id": format!("{id_prefix}--{id}"),
        });
        if let (Some(target), Some(source)) = (obj.as_object_mut(), body.as_object()) {
            for (k, v) in source {
                target.insert(k.clone(), v.clone());
            }
        }
        obj
    }
}

impl SecurityDataExporter for StixCourseOfActionExporter {
    fn export_vulnerability(&self, record: &StoredVulnerabilityRecord) -> Result<Vec<u8>, SecurityError> {
        let body = serde_json::json!({
            "name": format!("Vulnerability {}", record.vulnerability_id),
            "description": format!("CVSS {} ({})", record.cvss_base_score, record.cvss_severity),
            "created": record.discovered_at,
            "external_references": record.cve_identifier.as_ref().map(|cve| vec![
                serde_json::json!({"source_name": "cve", "external_id": cve})
            ]).unwrap_or_default(),
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        let stix = Self::wrap_stix("vulnerability", "vulnerability", &record.vulnerability_id, body);
        serde_json::to_vec_pretty(&stix)
            .map_err(|e| SecurityError::InvalidOperation(format!("STIX serialization failed: {e}")))
    }

    fn export_incident(&self, record: &StoredIncidentRecord) -> Result<Vec<u8>, SecurityError> {
        let body = serde_json::json!({
            "name": format!("Incident {}", record.incident_id),
            "description": record.description,
            "severity": record.severity,
            "created": record.declared_at,
            "affected_systems": record.affected_systems,
        });
        let stix = Self::wrap_stix("incident", "incident", &record.incident_id, body);
        serde_json::to_vec_pretty(&stix)
            .map_err(|e| SecurityError::InvalidOperation(format!("STIX serialization failed: {e}")))
    }

    fn export_posture_snapshot(&self, snapshot: &StoredPostureSnapshot) -> Result<Vec<u8>, SecurityError> {
        let body = serde_json::json!({
            "name": format!("Posture Snapshot {}", snapshot.snapshot_id),
            "description": format!("Overall score: {}, class: {:?}", snapshot.overall_score, snapshot.posture_class),
            "created": snapshot.captured_at,
        });
        let stix = Self::wrap_stix("report", "report", &snapshot.snapshot_id, body);
        serde_json::to_vec_pretty(&stix)
            .map_err(|e| SecurityError::InvalidOperation(format!("STIX serialization failed: {e}")))
    }

    fn export_control_implementation(&self, record: &StoredSecurityControlRecord) -> Result<Vec<u8>, SecurityError> {
        let body = serde_json::json!({
            "name": format!("Control {} ({})", record.control_identifier, record.framework_name),
            "description": format!("Status: {}", record.implementation_status),
            "created": record.last_validated_at,
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        let stix = Self::wrap_stix("course-of-action", "course-of-action", &record.control_id, body);
        serde_json::to_vec_pretty(&stix)
            .map_err(|e| SecurityError::InvalidOperation(format!("STIX serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "stix-2.1" }
    fn content_type(&self) -> &str { "application/stix+json" }
}

// ── CsafAdvisoryExporter ─────────────────────────────────────────

pub struct CsafAdvisoryExporter;

impl SecurityDataExporter for CsafAdvisoryExporter {
    fn export_vulnerability(&self, record: &StoredVulnerabilityRecord) -> Result<Vec<u8>, SecurityError> {
        let advisory = serde_json::json!({
            "document": {
                "category": "csaf_vex",
                "title": format!("Advisory for {}", record.vulnerability_id),
            },
            "vulnerabilities": [{
                "cve": record.cve_identifier,
                "scores": [{
                    "cvss_v3": {
                        "baseScore": record.cvss_base_score,
                        "baseSeverity": record.cvss_severity.to_string(),
                    }
                }],
                "product_status": {
                    "known_affected": [record.artifact_ref.clone()],
                },
                "evidence_attestation_refs": record.evidence_attestation_refs,
            }],
        });
        serde_json::to_vec_pretty(&advisory)
            .map_err(|e| SecurityError::InvalidOperation(format!("CSAF serialization failed: {e}")))
    }

    fn export_incident(&self, record: &StoredIncidentRecord) -> Result<Vec<u8>, SecurityError> {
        let advisory = serde_json::json!({
            "document": {
                "category": "csaf_informational_advisory",
                "title": format!("Incident {}", record.incident_id),
            },
            "notes": [{
                "category": "description",
                "text": record.description,
            }],
            "severity": record.severity,
        });
        serde_json::to_vec_pretty(&advisory)
            .map_err(|e| SecurityError::InvalidOperation(format!("CSAF serialization failed: {e}")))
    }

    fn export_posture_snapshot(&self, snapshot: &StoredPostureSnapshot) -> Result<Vec<u8>, SecurityError> {
        let advisory = serde_json::json!({
            "document": {
                "category": "csaf_informational_advisory",
                "title": format!("Posture Report {}", snapshot.snapshot_id),
            },
            "notes": [{
                "category": "summary",
                "text": format!("Overall: {}, Class: {:?}", snapshot.overall_score, snapshot.posture_class),
            }],
        });
        serde_json::to_vec_pretty(&advisory)
            .map_err(|e| SecurityError::InvalidOperation(format!("CSAF serialization failed: {e}")))
    }

    fn export_control_implementation(&self, record: &StoredSecurityControlRecord) -> Result<Vec<u8>, SecurityError> {
        let advisory = serde_json::json!({
            "document": {
                "category": "csaf_informational_advisory",
                "title": format!("Control {} Implementation", record.control_identifier),
            },
            "notes": [{
                "category": "description",
                "text": format!("{} in {} — {}", record.control_identifier, record.framework_name, record.implementation_status),
            }],
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        serde_json::to_vec_pretty(&advisory)
            .map_err(|e| SecurityError::InvalidOperation(format!("CSAF serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "csaf" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── VexStatementExporter ─────────────────────────────────────────

pub struct VexStatementExporter;

impl fmt::Display for VexStatementExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VexStatementExporter")
    }
}

impl SecurityDataExporter for VexStatementExporter {
    fn export_vulnerability(&self, record: &StoredVulnerabilityRecord) -> Result<Vec<u8>, SecurityError> {
        let vex_status = match record.current_status.to_string().as_str() {
            "Remediated" => "fixed",
            "FalsePositive" => "not_affected",
            "Accepted" => "known_not_affected",
            _ => "affected",
        };
        let statement = serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@type": "VexStatement",
            "vulnerability": {
                "@id": record.cve_identifier.as_deref().unwrap_or(&record.vulnerability_id),
                "name": record.vulnerability_id,
            },
            "products": [record.artifact_ref.clone()],
            "status": vex_status,
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        serde_json::to_vec_pretty(&statement)
            .map_err(|e| SecurityError::InvalidOperation(format!("VEX serialization failed: {e}")))
    }

    fn export_incident(&self, record: &StoredIncidentRecord) -> Result<Vec<u8>, SecurityError> {
        // VEX is vulnerability-oriented; wrap incident as informational
        let statement = serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@type": "VexStatement",
            "vulnerability": {
                "@id": record.incident_id,
                "name": format!("Incident: {}", record.description),
            },
            "status": "under_investigation",
        });
        serde_json::to_vec_pretty(&statement)
            .map_err(|e| SecurityError::InvalidOperation(format!("VEX serialization failed: {e}")))
    }

    fn export_posture_snapshot(&self, snapshot: &StoredPostureSnapshot) -> Result<Vec<u8>, SecurityError> {
        let statement = serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@type": "VexStatement",
            "vulnerability": {
                "@id": snapshot.snapshot_id,
                "name": format!("Posture snapshot, class: {:?}", snapshot.posture_class),
            },
            "status": "not_affected",
        });
        serde_json::to_vec_pretty(&statement)
            .map_err(|e| SecurityError::InvalidOperation(format!("VEX serialization failed: {e}")))
    }

    fn export_control_implementation(&self, record: &StoredSecurityControlRecord) -> Result<Vec<u8>, SecurityError> {
        let statement = serde_json::json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@type": "VexStatement",
            "vulnerability": {
                "@id": record.control_id,
                "name": format!("Control {}", record.control_identifier),
            },
            "status": "not_affected",
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        serde_json::to_vec_pretty(&statement)
            .map_err(|e| SecurityError::InvalidOperation(format!("VEX serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "openvex" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── OcsfSecurityFindingExporter ──────────────────────────────────

pub struct OcsfSecurityFindingExporter;

impl SecurityDataExporter for OcsfSecurityFindingExporter {
    fn export_vulnerability(&self, record: &StoredVulnerabilityRecord) -> Result<Vec<u8>, SecurityError> {
        let finding = serde_json::json!({
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "finding_info": {
                "uid": record.vulnerability_id,
                "title": format!("Vulnerability {}", record.vulnerability_id),
                "types": ["Vulnerability"],
                "created_time": record.discovered_at,
            },
            "severity_id": severity_id_from_cvss(&record.cvss_severity.to_string()),
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        serde_json::to_vec_pretty(&finding)
            .map_err(|e| SecurityError::InvalidOperation(format!("OCSF serialization failed: {e}")))
    }

    fn export_incident(&self, record: &StoredIncidentRecord) -> Result<Vec<u8>, SecurityError> {
        let finding = serde_json::json!({
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "finding_info": {
                "uid": record.incident_id,
                "title": format!("Incident: {}", record.description),
                "types": ["Incident"],
                "created_time": record.declared_at,
            },
            "affected_systems": record.affected_systems,
        });
        serde_json::to_vec_pretty(&finding)
            .map_err(|e| SecurityError::InvalidOperation(format!("OCSF serialization failed: {e}")))
    }

    fn export_posture_snapshot(&self, snapshot: &StoredPostureSnapshot) -> Result<Vec<u8>, SecurityError> {
        let finding = serde_json::json!({
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "finding_info": {
                "uid": snapshot.snapshot_id,
                "title": format!("Posture: {:?} ({})", snapshot.posture_class, snapshot.overall_score),
                "types": ["PostureAssessment"],
                "created_time": snapshot.captured_at,
            },
        });
        serde_json::to_vec_pretty(&finding)
            .map_err(|e| SecurityError::InvalidOperation(format!("OCSF serialization failed: {e}")))
    }

    fn export_control_implementation(&self, record: &StoredSecurityControlRecord) -> Result<Vec<u8>, SecurityError> {
        let finding = serde_json::json!({
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "finding_info": {
                "uid": record.control_id,
                "title": format!("Control {} ({})", record.control_identifier, record.framework_name),
                "types": ["Compliance"],
                "created_time": record.last_validated_at,
            },
            "evidence_attestation_refs": record.evidence_attestation_refs,
        });
        serde_json::to_vec_pretty(&finding)
            .map_err(|e| SecurityError::InvalidOperation(format!("OCSF serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "ocsf" }
    fn content_type(&self) -> &str { "application/json" }
}

fn severity_id_from_cvss(severity: &str) -> u8 {
    match severity {
        "Critical" => 5,
        "High" => 4,
        "Medium" => 3,
        "Low" => 2,
        _ => 1,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::*;

    fn sample_vuln() -> StoredVulnerabilityRecord {
        StoredVulnerabilityRecord {
            vulnerability_id: "VULN-001".to_string(),
            artifact_ref: "art-1".to_string(),
            cve_identifier: Some("CVE-2025-1234".to_string()),
            cvss_base_score: "8.5".to_string(),
            cvss_severity: CvssSeverity::High,
            discovered_at: 1000,
            remediated_at: None,
            evidence_attestation_refs: vec!["att-1".to_string()],
            current_status: VulnerabilityStatus::Discovered,
        }
    }

    fn sample_incident() -> StoredIncidentRecord {
        StoredIncidentRecord {
            incident_id: "INC-001".to_string(),
            severity: "High".to_string(),
            status: IncidentRecordStatus::Declared,
            declared_at: 2000,
            closed_at: None,
            description: "Test incident".to_string(),
            affected_systems: vec!["sys-a".to_string()],
        }
    }

    fn sample_posture() -> StoredPostureSnapshot {
        StoredPostureSnapshot {
            snapshot_id: "SNAP-001".to_string(),
            system_identifier: "sys-1".to_string(),
            captured_at: 3000,
            vulnerability_subscore: "80.0".to_string(),
            control_subscore: "90.0".to_string(),
            incident_subscore: "95.0".to_string(),
            threat_exposure_subscore: "70.0".to_string(),
            overall_score: "83.75".to_string(),
            posture_class: PostureClass::Adequate,
        }
    }

    fn sample_control() -> StoredSecurityControlRecord {
        StoredSecurityControlRecord {
            control_id: "CTRL-001".to_string(),
            framework_name: "NIST-CSF".to_string(),
            control_identifier: "ID.AM-1".to_string(),
            implementation_status: ControlImplementationStatus::Implemented,
            last_validated_at: 4000,
            evidence_attestation_refs: vec!["att-2".to_string()],
        }
    }

    #[test]
    fn test_json_export_vulnerability() {
        let exporter = JsonSecurityExporter;
        let bytes = exporter.export_vulnerability(&sample_vuln()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("VULN-001"));
        assert!(text.contains("CVE-2025-1234"));
        assert!(text.contains("att-1"));
    }

    #[test]
    fn test_json_export_incident() {
        let exporter = JsonSecurityExporter;
        let bytes = exporter.export_incident(&sample_incident()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("INC-001"));
    }

    #[test]
    fn test_json_export_posture() {
        let exporter = JsonSecurityExporter;
        let bytes = exporter.export_posture_snapshot(&sample_posture()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("SNAP-001"));
        assert!(text.contains("83.75"));
    }

    #[test]
    fn test_json_export_control() {
        let exporter = JsonSecurityExporter;
        let bytes = exporter.export_control_implementation(&sample_control()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("CTRL-001"));
        assert!(text.contains("att-2"));
    }

    #[test]
    fn test_stix_export_vulnerability() {
        let exporter = StixCourseOfActionExporter;
        let bytes = exporter.export_vulnerability(&sample_vuln()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("spec_version"));
        assert!(text.contains("2.1"));
        assert!(text.contains("VULN-001"));
    }

    #[test]
    fn test_stix_export_control() {
        let exporter = StixCourseOfActionExporter;
        let bytes = exporter.export_control_implementation(&sample_control()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("course-of-action"));
    }

    #[test]
    fn test_csaf_export_vulnerability() {
        let exporter = CsafAdvisoryExporter;
        let bytes = exporter.export_vulnerability(&sample_vuln()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("csaf_vex"));
        assert!(text.contains("CVE-2025-1234"));
    }

    #[test]
    fn test_vex_export_vulnerability() {
        let exporter = VexStatementExporter;
        let bytes = exporter.export_vulnerability(&sample_vuln()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("openvex.dev"));
        assert!(text.contains("affected"));
    }

    #[test]
    fn test_vex_export_remediated() {
        let mut vuln = sample_vuln();
        vuln.current_status = VulnerabilityStatus::Remediated;
        let exporter = VexStatementExporter;
        let bytes = exporter.export_vulnerability(&vuln).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("fixed"));
    }

    #[test]
    fn test_ocsf_export_vulnerability() {
        let exporter = OcsfSecurityFindingExporter;
        let bytes = exporter.export_vulnerability(&sample_vuln()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Security Finding"));
        assert!(text.contains("2001"));
    }

    #[test]
    fn test_format_names() {
        assert_eq!(JsonSecurityExporter.format_name(), "json");
        assert_eq!(StixCourseOfActionExporter.format_name(), "stix-2.1");
        assert_eq!(CsafAdvisoryExporter.format_name(), "csaf");
        assert_eq!(VexStatementExporter.format_name(), "openvex");
        assert_eq!(OcsfSecurityFindingExporter.format_name(), "ocsf");
    }

    #[test]
    fn test_content_types() {
        assert_eq!(JsonSecurityExporter.content_type(), "application/json");
        assert_eq!(StixCourseOfActionExporter.content_type(), "application/stix+json");
    }

    #[test]
    fn test_all_exporters_handle_incident() {
        let inc = sample_incident();
        let exporters: Vec<Box<dyn SecurityDataExporter>> = vec![
            Box::new(JsonSecurityExporter),
            Box::new(StixCourseOfActionExporter),
            Box::new(CsafAdvisoryExporter),
            Box::new(VexStatementExporter),
            Box::new(OcsfSecurityFindingExporter),
        ];
        for exp in &exporters {
            let bytes = exp.export_incident(&inc).unwrap();
            assert!(!bytes.is_empty());
        }
    }

    #[test]
    fn test_all_exporters_handle_posture() {
        let snap = sample_posture();
        let exporters: Vec<Box<dyn SecurityDataExporter>> = vec![
            Box::new(JsonSecurityExporter),
            Box::new(StixCourseOfActionExporter),
            Box::new(CsafAdvisoryExporter),
            Box::new(VexStatementExporter),
            Box::new(OcsfSecurityFindingExporter),
        ];
        for exp in &exporters {
            let bytes = exp.export_posture_snapshot(&snap).unwrap();
            assert!(!bytes.is_empty());
        }
    }
}
