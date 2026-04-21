// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — FrameworkExporter trait with five format implementations:
// JSON, OSCAL Profile, STIX 2.1, CJIS compliance evidence, and XLSX
// compliance matrix.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{StoredComplianceEvidenceRecord, StoredFrameworkManifest};
use crate::error::FrameworkError;

// ── FrameworkExporter trait ──────────────────────────────────────────

pub trait FrameworkExporter {
    fn export_framework(&self, manifest: &StoredFrameworkManifest) -> Result<Vec<u8>, FrameworkError>;

    fn export_framework_with_evidence(
        &self,
        manifest: &StoredFrameworkManifest,
        evidence: &[StoredComplianceEvidenceRecord],
    ) -> Result<Vec<u8>, FrameworkError> {
        let _ = evidence;
        self.export_framework(manifest)
    }

    fn export_batch(&self, manifests: &[StoredFrameworkManifest]) -> Result<Vec<Vec<u8>>, FrameworkError> {
        manifests.iter().map(|m| self.export_framework(m)).collect()
    }

    fn format_name(&self) -> &str;

    fn content_type(&self) -> &str;
}

// ── JsonFrameworkExporter ────────────────────────────────────────────

pub struct JsonFrameworkExporter;

impl JsonFrameworkExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonFrameworkExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkExporter for JsonFrameworkExporter {
    fn export_framework(&self, manifest: &StoredFrameworkManifest) -> Result<Vec<u8>, FrameworkError> {
        serde_json::to_vec_pretty(manifest).map_err(|e| FrameworkError::AuditError {
            reason: format!("JSON serialization failed: {e}"),
        })
    }

    fn export_framework_with_evidence(
        &self,
        manifest: &StoredFrameworkManifest,
        evidence: &[StoredComplianceEvidenceRecord],
    ) -> Result<Vec<u8>, FrameworkError> {
        let mut output = String::from("{\n");
        let manifest_json = serde_json::to_string_pretty(manifest).map_err(|e| {
            FrameworkError::AuditError {
                reason: format!("JSON serialization failed: {e}"),
            }
        })?;
        output.push_str(&format!("  \"framework\": {manifest_json},\n"));
        let evidence_json = serde_json::to_string_pretty(evidence).map_err(|e| {
            FrameworkError::AuditError {
                reason: format!("JSON serialization failed: {e}"),
            }
        })?;
        output.push_str(&format!("  \"evidence\": {evidence_json}\n"));
        output.push('}');
        Ok(output.into_bytes())
    }

    fn format_name(&self) -> &str {
        "JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── OscalProfileExporter ─────────────────────────────────────────────

pub struct OscalProfileExporter;

impl OscalProfileExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OscalProfileExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkExporter for OscalProfileExporter {
    fn export_framework(&self, manifest: &StoredFrameworkManifest) -> Result<Vec<u8>, FrameworkError> {
        let mut output = String::from("{\n");
        output.push_str("  \"profile\": {\n");
        output.push_str(&format!(
            "    \"uuid\": \"{}\",\n",
            manifest.framework_id
        ));
        output.push_str("    \"metadata\": {\n");
        output.push_str(&format!("      \"title\": \"{}\",\n", manifest.name));
        output.push_str(&format!(
            "      \"version\": \"{}\",\n",
            manifest.version
        ));
        output.push_str(&format!(
            "      \"oscal-version\": \"1.1.2\",\n"
        ));
        output.push_str(&format!(
            "      \"published\": \"{}\"\n",
            manifest.published_at
        ));
        output.push_str("    },\n");

        // imports section
        output.push_str("    \"imports\": [\n");
        for (i, req_ref) in manifest.requirement_refs.iter().enumerate() {
            let comma = if i + 1 < manifest.requirement_refs.len() { "," } else { "" };
            output.push_str(&format!(
                "      {{ \"href\": \"#{req_ref}\" }}{comma}\n"
            ));
        }
        output.push_str("    ],\n");

        // merge section
        output.push_str("    \"merge\": { \"combine\": { \"method\": \"merge\" } },\n");

        // back-matter
        output.push_str("    \"back-matter\": {\n");
        output.push_str(&format!(
            "      \"authority\": \"{}\",\n",
            manifest.authority
        ));
        output.push_str(&format!(
            "      \"jurisdiction\": \"{}\"\n",
            manifest.jurisdiction
        ));
        output.push_str("    }\n");
        output.push_str("  }\n");
        output.push('}');
        Ok(output.into_bytes())
    }

    fn format_name(&self) -> &str {
        "OSCAL-Profile"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── Stix21CourseOfActionExporter ──────────────────────────────────────

pub struct Stix21CourseOfActionExporter;

impl Stix21CourseOfActionExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Stix21CourseOfActionExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkExporter for Stix21CourseOfActionExporter {
    fn export_framework(&self, manifest: &StoredFrameworkManifest) -> Result<Vec<u8>, FrameworkError> {
        let mut output = String::from("{\n");
        output.push_str("  \"type\": \"bundle\",\n");
        output.push_str("  \"id\": \"bundle--rune-framework\",\n");
        output.push_str("  \"objects\": [\n");

        for (i, req_ref) in manifest.requirement_refs.iter().enumerate() {
            let comma = if i + 1 < manifest.requirement_refs.len() { "," } else { "" };
            output.push_str("    {\n");
            output.push_str("      \"type\": \"course-of-action\",\n");
            output.push_str(&format!(
                "      \"id\": \"course-of-action--{req_ref}\",\n"
            ));
            output.push_str("      \"spec_version\": \"2.1\",\n");
            output.push_str(&format!(
                "      \"name\": \"{req_ref}\",\n"
            ));
            output.push_str(&format!(
                "      \"description\": \"Requirement from {}\",\n",
                manifest.name
            ));
            output.push_str(&format!(
                "      \"x_rune_framework_id\": \"{}\",\n",
                manifest.framework_id
            ));
            output.push_str(&format!(
                "      \"x_rune_requirement_id\": \"{req_ref}\"\n"
            ));
            output.push_str(&format!("    }}{comma}\n"));
        }

        output.push_str("  ]\n");
        output.push('}');
        Ok(output.into_bytes())
    }

    fn format_name(&self) -> &str {
        "STIX-2.1"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── CjisComplianceEvidenceExporter ───────────────────────────────────

pub struct CjisComplianceEvidenceExporter;

impl CjisComplianceEvidenceExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CjisComplianceEvidenceExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkExporter for CjisComplianceEvidenceExporter {
    fn export_framework(&self, manifest: &StoredFrameworkManifest) -> Result<Vec<u8>, FrameworkError> {
        let mut output = String::from("{\n");
        output.push_str(&format!(
            "  \"cjis_framework_id\": \"{}\",\n",
            manifest.framework_id
        ));
        output.push_str(&format!(
            "  \"cjis_version\": \"{}\",\n",
            manifest.version
        ));
        output.push_str(&format!(
            "  \"authority\": \"{}\",\n",
            manifest.authority
        ));
        output.push_str(&format!(
            "  \"policy_area_count\": {},\n",
            manifest.policy_area_count
        ));
        output.push_str("  \"sections\": [\n");
        for (i, req_ref) in manifest.requirement_refs.iter().enumerate() {
            let comma = if i + 1 < manifest.requirement_refs.len() { "," } else { "" };
            output.push_str(&format!(
                "    {{ \"section_id\": \"{req_ref}\", \"evidence_artifacts\": [] }}{comma}\n"
            ));
        }
        output.push_str("  ]\n");
        output.push('}');
        Ok(output.into_bytes())
    }

    fn export_framework_with_evidence(
        &self,
        manifest: &StoredFrameworkManifest,
        evidence: &[StoredComplianceEvidenceRecord],
    ) -> Result<Vec<u8>, FrameworkError> {
        let mut output = String::from("{\n");
        output.push_str(&format!(
            "  \"cjis_framework_id\": \"{}\",\n",
            manifest.framework_id
        ));
        output.push_str(&format!(
            "  \"cjis_version\": \"{}\",\n",
            manifest.version
        ));
        output.push_str(&format!(
            "  \"authority\": \"{}\",\n",
            manifest.authority
        ));
        output.push_str("  \"sections\": [\n");
        for (i, req_ref) in manifest.requirement_refs.iter().enumerate() {
            let comma = if i + 1 < manifest.requirement_refs.len() { "," } else { "" };
            let artifacts: Vec<&str> = evidence
                .iter()
                .filter(|e| e.requirement_id == *req_ref)
                .map(|e| e.evidence_artifact_ref.as_str())
                .collect();
            let artifacts_json = serde_json::to_string(&artifacts).unwrap_or_else(|_| "[]".to_string());
            output.push_str(&format!(
                "    {{ \"section_id\": \"{req_ref}\", \"evidence_artifacts\": {artifacts_json} }}{comma}\n"
            ));
        }
        output.push_str("  ]\n");
        output.push('}');
        Ok(output.into_bytes())
    }

    fn format_name(&self) -> &str {
        "CJIS-Evidence"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── XlsxComplianceMatrixExporter ─────────────────────────────────────

pub struct XlsxComplianceMatrixExporter;

impl XlsxComplianceMatrixExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for XlsxComplianceMatrixExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Structured row/column representation for a compliance matrix worksheet.
/// Actual XLSX byte stream generation belongs in adapter crates with workbook libraries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceMatrixRow {
    pub requirement_ref: String,
    pub framework_name: String,
    pub framework_version: String,
    pub jurisdiction: String,
    pub evidence_status: String,
    pub evidence_artifact_ref: String,
}

impl FrameworkExporter for XlsxComplianceMatrixExporter {
    fn export_framework(&self, manifest: &StoredFrameworkManifest) -> Result<Vec<u8>, FrameworkError> {
        let rows: Vec<ComplianceMatrixRow> = manifest
            .requirement_refs
            .iter()
            .map(|req_ref| ComplianceMatrixRow {
                requirement_ref: req_ref.clone(),
                framework_name: manifest.name.clone(),
                framework_version: manifest.version.clone(),
                jurisdiction: manifest.jurisdiction.to_string(),
                evidence_status: "pending".to_string(),
                evidence_artifact_ref: String::new(),
            })
            .collect();

        serde_json::to_vec_pretty(&rows).map_err(|e| FrameworkError::AuditError {
            reason: format!("XLSX matrix serialization failed: {e}"),
        })
    }

    fn export_framework_with_evidence(
        &self,
        manifest: &StoredFrameworkManifest,
        evidence: &[StoredComplianceEvidenceRecord],
    ) -> Result<Vec<u8>, FrameworkError> {
        let rows: Vec<ComplianceMatrixRow> = manifest
            .requirement_refs
            .iter()
            .map(|req_ref| {
                let ev = evidence.iter().find(|e| e.requirement_id == *req_ref);
                ComplianceMatrixRow {
                    requirement_ref: req_ref.clone(),
                    framework_name: manifest.name.clone(),
                    framework_version: manifest.version.clone(),
                    jurisdiction: manifest.jurisdiction.to_string(),
                    evidence_status: if ev.is_some() {
                        "collected".to_string()
                    } else {
                        "pending".to_string()
                    },
                    evidence_artifact_ref: ev
                        .map(|e| e.evidence_artifact_ref.clone())
                        .unwrap_or_default(),
                }
            })
            .collect();

        serde_json::to_vec_pretty(&rows).map_err(|e| FrameworkError::AuditError {
            reason: format!("XLSX matrix serialization failed: {e}"),
        })
    }

    fn format_name(&self) -> &str {
        "XLSX-Matrix"
    }

    fn content_type(&self) -> &str {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ComplianceEvidenceType, FrameworkDomain, Jurisdiction};
    use std::collections::HashMap;

    fn test_manifest() -> StoredFrameworkManifest {
        StoredFrameworkManifest {
            framework_id: "cjis-v6.0".to_string(),
            name: "CJIS Security Policy".to_string(),
            version: "6.0.0".to_string(),
            jurisdiction: Jurisdiction::UnitedStates,
            domain: FrameworkDomain::CriminalJustice,
            description: "FBI CJIS".to_string(),
            authority: "FBI CJIS Division".to_string(),
            policy_area_count: 20,
            requirement_refs: vec!["cjis-5.6".to_string(), "cjis-5.4".to_string()],
            mapping_refs: vec![],
            published_at: 1000,
            effective_date: 1000,
            sunset_date: None,
            metadata: HashMap::new(),
        }
    }

    fn test_evidence() -> Vec<StoredComplianceEvidenceRecord> {
        vec![StoredComplianceEvidenceRecord {
            record_id: "ev-1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_id: "cjis-5.6".to_string(),
            evidence_type: ComplianceEvidenceType::PolicyDocument,
            evidence_artifact_ref: "doc://policy-123".to_string(),
            recorded_by: "auditor".to_string(),
            recorded_at: 1000,
            expires_at: None,
            metadata: HashMap::new(),
        }]
    }

    #[test]
    fn test_json_exporter() {
        let exporter = JsonFrameworkExporter::new();
        let bytes = exporter.export_framework(&test_manifest()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("cjis-v6.0"));
        assert_eq!(exporter.format_name(), "JSON");
    }

    #[test]
    fn test_json_exporter_with_evidence() {
        let exporter = JsonFrameworkExporter::new();
        let bytes = exporter
            .export_framework_with_evidence(&test_manifest(), &test_evidence())
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("evidence"));
        assert!(text.contains("doc://policy-123"));
    }

    #[test]
    fn test_oscal_profile_exporter() {
        let exporter = OscalProfileExporter::new();
        let bytes = exporter.export_framework(&test_manifest()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("profile"));
        assert!(text.contains("oscal-version"));
        assert!(text.contains("1.1.2"));
        assert!(text.contains("imports"));
    }

    #[test]
    fn test_stix21_exporter() {
        let exporter = Stix21CourseOfActionExporter::new();
        let bytes = exporter.export_framework(&test_manifest()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("course-of-action"));
        assert!(text.contains("spec_version"));
        assert!(text.contains("2.1"));
        assert!(text.contains("x_rune_framework_id"));
    }

    #[test]
    fn test_cjis_evidence_exporter() {
        let exporter = CjisComplianceEvidenceExporter::new();
        let bytes = exporter.export_framework(&test_manifest()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("cjis_framework_id"));
        assert!(text.contains("sections"));
    }

    #[test]
    fn test_cjis_evidence_exporter_with_evidence() {
        let exporter = CjisComplianceEvidenceExporter::new();
        let bytes = exporter
            .export_framework_with_evidence(&test_manifest(), &test_evidence())
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("doc://policy-123"));
    }

    #[test]
    fn test_xlsx_matrix_exporter() {
        let exporter = XlsxComplianceMatrixExporter::new();
        let bytes = exporter.export_framework(&test_manifest()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("requirement_ref"));
        assert!(text.contains("pending"));
    }

    #[test]
    fn test_xlsx_matrix_with_evidence() {
        let exporter = XlsxComplianceMatrixExporter::new();
        let bytes = exporter
            .export_framework_with_evidence(&test_manifest(), &test_evidence())
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("collected"));
        assert!(text.contains("doc://policy-123"));
    }

    #[test]
    fn test_export_batch() {
        let exporter = JsonFrameworkExporter::new();
        let manifests = vec![test_manifest(), test_manifest()];
        let results = exporter.export_batch(&manifests).unwrap();
        assert_eq!(results.len(), 2);
    }
}
