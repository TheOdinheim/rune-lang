// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — FrameworkBackend trait for pluggable framework manifest,
// requirement, cross-framework mapping, and compliance evidence storage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::FrameworkError;

// ── Jurisdiction ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    UnitedStates,
    EuropeanUnion,
    UnitedKingdom,
    Canada,
    Australia,
    International,
    Other { name: String },
}

impl std::fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnitedStates => f.write_str("United States"),
            Self::EuropeanUnion => f.write_str("European Union"),
            Self::UnitedKingdom => f.write_str("United Kingdom"),
            Self::Canada => f.write_str("Canada"),
            Self::Australia => f.write_str("Australia"),
            Self::International => f.write_str("International"),
            Self::Other { name } => write!(f, "Other({name})"),
        }
    }
}

// ── FrameworkDomain ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameworkDomain {
    CriminalJustice,
    Healthcare,
    FinancialServices,
    GeneralPrivacy,
    FederalGovernment,
    ArtificialIntelligence,
    CloudServices,
    PaymentCard,
    Other { name: String },
}

impl std::fmt::Display for FrameworkDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CriminalJustice => f.write_str("Criminal Justice"),
            Self::Healthcare => f.write_str("Healthcare"),
            Self::FinancialServices => f.write_str("Financial Services"),
            Self::GeneralPrivacy => f.write_str("General Privacy"),
            Self::FederalGovernment => f.write_str("Federal Government"),
            Self::ArtificialIntelligence => f.write_str("Artificial Intelligence"),
            Self::CloudServices => f.write_str("Cloud Services"),
            Self::PaymentCard => f.write_str("Payment Card"),
            Self::Other { name } => write!(f, "Other({name})"),
        }
    }
}

// ── RequirementPriorityLevel ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequirementPriorityLevel {
    Sanctionable,
    Recommended,
    Informational,
}

impl std::fmt::Display for RequirementPriorityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sanctionable => f.write_str("Sanctionable"),
            Self::Recommended => f.write_str("Recommended"),
            Self::Informational => f.write_str("Informational"),
        }
    }
}

// ── MappingType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MappingType {
    Equivalent,
    Subset,
    Superset,
    Related,
    PartiallyOverlapping,
}

impl std::fmt::Display for MappingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Equivalent => f.write_str("Equivalent"),
            Self::Subset => f.write_str("Subset"),
            Self::Superset => f.write_str("Superset"),
            Self::Related => f.write_str("Related"),
            Self::PartiallyOverlapping => f.write_str("PartiallyOverlapping"),
        }
    }
}

// ── MappingConfidence ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MappingConfidence {
    DisputedMapping = 0,
    ProvisionalMapping = 1,
    HighConfidence = 2,
    Authoritative = 3,
}

impl std::fmt::Display for MappingConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DisputedMapping => f.write_str("Disputed"),
            Self::ProvisionalMapping => f.write_str("Provisional"),
            Self::HighConfidence => f.write_str("HighConfidence"),
            Self::Authoritative => f.write_str("Authoritative"),
        }
    }
}

// ── ComplianceEvidenceType ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceEvidenceType {
    PolicyDocument,
    ProcedureDocument,
    ConfigurationSnapshot,
    AuditLogReference,
    AssessmentReport,
    AttestationStatement,
    Other { name: String },
}

impl std::fmt::Display for ComplianceEvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyDocument => f.write_str("PolicyDocument"),
            Self::ProcedureDocument => f.write_str("ProcedureDocument"),
            Self::ConfigurationSnapshot => f.write_str("ConfigurationSnapshot"),
            Self::AuditLogReference => f.write_str("AuditLogReference"),
            Self::AssessmentReport => f.write_str("AssessmentReport"),
            Self::AttestationStatement => f.write_str("AttestationStatement"),
            Self::Other { name } => write!(f, "Other({name})"),
        }
    }
}

// ── StoredFrameworkManifest ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFrameworkManifest {
    pub framework_id: String,
    pub name: String,
    pub version: String,
    pub jurisdiction: Jurisdiction,
    pub domain: FrameworkDomain,
    pub description: String,
    pub authority: String,
    pub policy_area_count: usize,
    pub requirement_refs: Vec<String>,
    pub mapping_refs: Vec<String>,
    pub published_at: i64,
    pub effective_date: i64,
    pub sunset_date: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── StoredFrameworkRequirement ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFrameworkRequirement {
    pub requirement_id: String,
    pub framework_id: String,
    pub requirement_identifier: String,
    pub title: String,
    pub description: String,
    pub policy_area: String,
    pub priority_level: RequirementPriorityLevel,
    pub referenced_library: String,
    pub referenced_capability: String,
    pub evaluation_context_hint: HashMap<String, String>,
}

// ── StoredCrossFrameworkMapping ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCrossFrameworkMapping {
    pub mapping_id: String,
    pub source_requirement_id: String,
    pub target_requirement_id: String,
    pub mapping_type: MappingType,
    pub confidence: MappingConfidence,
    pub justification: String,
    pub mapped_by: String,
    pub mapped_at: i64,
}

// ── StoredComplianceEvidenceRecord ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredComplianceEvidenceRecord {
    pub record_id: String,
    pub framework_id: String,
    pub requirement_id: String,
    pub evidence_type: ComplianceEvidenceType,
    pub evidence_artifact_ref: String,
    pub recorded_by: String,
    pub recorded_at: i64,
    pub expires_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── FrameworkBackendInfo ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkBackendInfo {
    pub backend_type: String,
    pub framework_count: usize,
    pub requirement_count: usize,
    pub mapping_count: usize,
    pub evidence_count: usize,
}

// ── FrameworkBackend trait ────────────────────────────────────────────

pub trait FrameworkBackend {
    fn store_framework(
        &mut self,
        manifest: StoredFrameworkManifest,
    ) -> Result<(), FrameworkError>;

    fn retrieve_framework(&self, framework_id: &str) -> Option<&StoredFrameworkManifest>;

    fn delete_framework(&mut self, framework_id: &str) -> Result<(), FrameworkError>;

    fn list_frameworks_by_jurisdiction(
        &self,
        jurisdiction: &Jurisdiction,
    ) -> Vec<&StoredFrameworkManifest>;

    fn list_frameworks_by_domain(&self, domain: &FrameworkDomain) -> Vec<&StoredFrameworkManifest>;

    fn list_framework_versions(&self, name: &str) -> Vec<&StoredFrameworkManifest>;

    fn resolve_framework_version(
        &self,
        name: &str,
        version: &str,
    ) -> Option<&StoredFrameworkManifest>;

    fn framework_count(&self) -> usize;

    fn store_requirement(
        &mut self,
        requirement: StoredFrameworkRequirement,
    ) -> Result<(), FrameworkError>;

    fn retrieve_requirement(&self, requirement_id: &str) -> Option<&StoredFrameworkRequirement>;

    fn list_requirements_for_framework(
        &self,
        framework_id: &str,
    ) -> Vec<&StoredFrameworkRequirement>;

    fn store_cross_framework_mapping(
        &mut self,
        mapping: StoredCrossFrameworkMapping,
    ) -> Result<(), FrameworkError>;

    fn retrieve_cross_framework_mapping(
        &self,
        mapping_id: &str,
    ) -> Option<&StoredCrossFrameworkMapping>;

    fn list_mappings_for_requirement(
        &self,
        requirement_id: &str,
    ) -> Vec<&StoredCrossFrameworkMapping>;

    fn store_compliance_evidence_record(
        &mut self,
        record: StoredComplianceEvidenceRecord,
    ) -> Result<(), FrameworkError>;

    fn retrieve_compliance_evidence_record(
        &self,
        record_id: &str,
    ) -> Option<&StoredComplianceEvidenceRecord>;

    fn list_evidence_for_framework(
        &self,
        framework_id: &str,
    ) -> Vec<&StoredComplianceEvidenceRecord>;

    fn flush(&mut self) -> Result<(), FrameworkError>;

    fn backend_info(&self) -> FrameworkBackendInfo;
}

// ── InMemoryFrameworkBackend ─────────────────────────────────────────

pub struct InMemoryFrameworkBackend {
    frameworks: HashMap<String, StoredFrameworkManifest>,
    requirements: HashMap<String, StoredFrameworkRequirement>,
    mappings: HashMap<String, StoredCrossFrameworkMapping>,
    evidence: HashMap<String, StoredComplianceEvidenceRecord>,
}

impl InMemoryFrameworkBackend {
    pub fn new() -> Self {
        Self {
            frameworks: HashMap::new(),
            requirements: HashMap::new(),
            mappings: HashMap::new(),
            evidence: HashMap::new(),
        }
    }
}

impl Default for InMemoryFrameworkBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkBackend for InMemoryFrameworkBackend {
    fn store_framework(
        &mut self,
        manifest: StoredFrameworkManifest,
    ) -> Result<(), FrameworkError> {
        self.frameworks
            .insert(manifest.framework_id.clone(), manifest);
        Ok(())
    }

    fn retrieve_framework(&self, framework_id: &str) -> Option<&StoredFrameworkManifest> {
        self.frameworks.get(framework_id)
    }

    fn delete_framework(&mut self, framework_id: &str) -> Result<(), FrameworkError> {
        self.frameworks.remove(framework_id).ok_or_else(|| {
            FrameworkError::ComponentNotFound {
                component_id: framework_id.to_string(),
            }
        })?;
        Ok(())
    }

    fn list_frameworks_by_jurisdiction(
        &self,
        jurisdiction: &Jurisdiction,
    ) -> Vec<&StoredFrameworkManifest> {
        self.frameworks
            .values()
            .filter(|m| &m.jurisdiction == jurisdiction)
            .collect()
    }

    fn list_frameworks_by_domain(&self, domain: &FrameworkDomain) -> Vec<&StoredFrameworkManifest> {
        self.frameworks
            .values()
            .filter(|m| &m.domain == domain)
            .collect()
    }

    fn list_framework_versions(&self, name: &str) -> Vec<&StoredFrameworkManifest> {
        self.frameworks
            .values()
            .filter(|m| m.name == name)
            .collect()
    }

    fn resolve_framework_version(
        &self,
        name: &str,
        version: &str,
    ) -> Option<&StoredFrameworkManifest> {
        self.frameworks
            .values()
            .find(|m| m.name == name && m.version == version)
    }

    fn framework_count(&self) -> usize {
        self.frameworks.len()
    }

    fn store_requirement(
        &mut self,
        requirement: StoredFrameworkRequirement,
    ) -> Result<(), FrameworkError> {
        self.requirements
            .insert(requirement.requirement_id.clone(), requirement);
        Ok(())
    }

    fn retrieve_requirement(&self, requirement_id: &str) -> Option<&StoredFrameworkRequirement> {
        self.requirements.get(requirement_id)
    }

    fn list_requirements_for_framework(
        &self,
        framework_id: &str,
    ) -> Vec<&StoredFrameworkRequirement> {
        self.requirements
            .values()
            .filter(|r| r.framework_id == framework_id)
            .collect()
    }

    fn store_cross_framework_mapping(
        &mut self,
        mapping: StoredCrossFrameworkMapping,
    ) -> Result<(), FrameworkError> {
        self.mappings.insert(mapping.mapping_id.clone(), mapping);
        Ok(())
    }

    fn retrieve_cross_framework_mapping(
        &self,
        mapping_id: &str,
    ) -> Option<&StoredCrossFrameworkMapping> {
        self.mappings.get(mapping_id)
    }

    fn list_mappings_for_requirement(
        &self,
        requirement_id: &str,
    ) -> Vec<&StoredCrossFrameworkMapping> {
        self.mappings
            .values()
            .filter(|m| {
                m.source_requirement_id == requirement_id
                    || m.target_requirement_id == requirement_id
            })
            .collect()
    }

    fn store_compliance_evidence_record(
        &mut self,
        record: StoredComplianceEvidenceRecord,
    ) -> Result<(), FrameworkError> {
        self.evidence.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_compliance_evidence_record(
        &self,
        record_id: &str,
    ) -> Option<&StoredComplianceEvidenceRecord> {
        self.evidence.get(record_id)
    }

    fn list_evidence_for_framework(
        &self,
        framework_id: &str,
    ) -> Vec<&StoredComplianceEvidenceRecord> {
        self.evidence
            .values()
            .filter(|e| e.framework_id == framework_id)
            .collect()
    }

    fn flush(&mut self) -> Result<(), FrameworkError> {
        Ok(())
    }

    fn backend_info(&self) -> FrameworkBackendInfo {
        FrameworkBackendInfo {
            backend_type: "in-memory".to_string(),
            framework_count: self.frameworks.len(),
            requirement_count: self.requirements.len(),
            mapping_count: self.mappings.len(),
            evidence_count: self.evidence.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest() -> StoredFrameworkManifest {
        StoredFrameworkManifest {
            framework_id: "cjis-v6.0".to_string(),
            name: "CJIS Security Policy".to_string(),
            version: "6.0.0".to_string(),
            jurisdiction: Jurisdiction::UnitedStates,
            domain: FrameworkDomain::CriminalJustice,
            description: "FBI CJIS Security Policy v6.0".to_string(),
            authority: "FBI CJIS Division".to_string(),
            policy_area_count: 20,
            requirement_refs: vec!["cjis-5.6.2.1".to_string()],
            mapping_refs: vec![],
            published_at: 1735257600,
            effective_date: 1735257600,
            sunset_date: None,
            metadata: HashMap::new(),
        }
    }

    fn test_requirement() -> StoredFrameworkRequirement {
        StoredFrameworkRequirement {
            requirement_id: "cjis-5.6.2.1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_identifier: "CJIS-5.6.2.1".to_string(),
            title: "Multi-Factor Authentication".to_string(),
            description: "Advanced authentication for CJI access".to_string(),
            policy_area: "Identification and Authentication".to_string(),
            priority_level: RequirementPriorityLevel::Sanctionable,
            referenced_library: "rune-identity".to_string(),
            referenced_capability: "FactorType::Possession".to_string(),
            evaluation_context_hint: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_framework() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_framework(test_manifest()).unwrap();
        assert!(backend.retrieve_framework("cjis-v6.0").is_some());
        assert!(backend.retrieve_framework("nonexistent").is_none());
    }

    #[test]
    fn test_delete_framework() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_framework(test_manifest()).unwrap();
        backend.delete_framework("cjis-v6.0").unwrap();
        assert!(backend.retrieve_framework("cjis-v6.0").is_none());
        assert!(backend.delete_framework("nonexistent").is_err());
    }

    #[test]
    fn test_list_by_jurisdiction() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_framework(test_manifest()).unwrap();
        let us = backend.list_frameworks_by_jurisdiction(&Jurisdiction::UnitedStates);
        assert_eq!(us.len(), 1);
        let eu = backend.list_frameworks_by_jurisdiction(&Jurisdiction::EuropeanUnion);
        assert!(eu.is_empty());
    }

    #[test]
    fn test_list_by_domain() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_framework(test_manifest()).unwrap();
        let cj = backend.list_frameworks_by_domain(&FrameworkDomain::CriminalJustice);
        assert_eq!(cj.len(), 1);
    }

    #[test]
    fn test_resolve_framework_version() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_framework(test_manifest()).unwrap();
        let found = backend.resolve_framework_version("CJIS Security Policy", "6.0.0");
        assert!(found.is_some());
        let not_found = backend.resolve_framework_version("CJIS Security Policy", "5.0.0");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_store_and_retrieve_requirement() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_requirement(test_requirement()).unwrap();
        let req = backend.retrieve_requirement("cjis-5.6.2.1").unwrap();
        assert_eq!(req.title, "Multi-Factor Authentication");
    }

    #[test]
    fn test_list_requirements_for_framework() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_requirement(test_requirement()).unwrap();
        let reqs = backend.list_requirements_for_framework("cjis-v6.0");
        assert_eq!(reqs.len(), 1);
        let empty = backend.list_requirements_for_framework("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_store_and_retrieve_mapping() {
        let mut backend = InMemoryFrameworkBackend::new();
        let mapping = StoredCrossFrameworkMapping {
            mapping_id: "m-1".to_string(),
            source_requirement_id: "cjis-5.6.2.1".to_string(),
            target_requirement_id: "nist-ia-2".to_string(),
            mapping_type: MappingType::Equivalent,
            confidence: MappingConfidence::Authoritative,
            justification: "CJIS v6.0 aligns with NIST SP 800-53 IA-2".to_string(),
            mapped_by: "compliance-team".to_string(),
            mapped_at: 1000,
        };
        backend.store_cross_framework_mapping(mapping).unwrap();
        assert!(backend.retrieve_cross_framework_mapping("m-1").is_some());
    }

    #[test]
    fn test_list_mappings_for_requirement() {
        let mut backend = InMemoryFrameworkBackend::new();
        let mapping = StoredCrossFrameworkMapping {
            mapping_id: "m-1".to_string(),
            source_requirement_id: "cjis-5.6.2.1".to_string(),
            target_requirement_id: "nist-ia-2".to_string(),
            mapping_type: MappingType::Equivalent,
            confidence: MappingConfidence::Authoritative,
            justification: "aligned".to_string(),
            mapped_by: "team".to_string(),
            mapped_at: 1000,
        };
        backend.store_cross_framework_mapping(mapping).unwrap();
        let from_source = backend.list_mappings_for_requirement("cjis-5.6.2.1");
        assert_eq!(from_source.len(), 1);
        let from_target = backend.list_mappings_for_requirement("nist-ia-2");
        assert_eq!(from_target.len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_evidence() {
        let mut backend = InMemoryFrameworkBackend::new();
        let record = StoredComplianceEvidenceRecord {
            record_id: "ev-1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_id: "cjis-5.6.2.1".to_string(),
            evidence_type: ComplianceEvidenceType::PolicyDocument,
            evidence_artifact_ref: "doc://policy-123".to_string(),
            recorded_by: "auditor".to_string(),
            recorded_at: 1000,
            expires_at: Some(2000),
            metadata: HashMap::new(),
        };
        backend.store_compliance_evidence_record(record).unwrap();
        let ev = backend.retrieve_compliance_evidence_record("ev-1").unwrap();
        assert_eq!(ev.evidence_artifact_ref, "doc://policy-123");
    }

    #[test]
    fn test_list_evidence_for_framework() {
        let mut backend = InMemoryFrameworkBackend::new();
        let record = StoredComplianceEvidenceRecord {
            record_id: "ev-1".to_string(),
            framework_id: "cjis-v6.0".to_string(),
            requirement_id: "cjis-5.6.2.1".to_string(),
            evidence_type: ComplianceEvidenceType::AuditLogReference,
            evidence_artifact_ref: "audit://range-456".to_string(),
            recorded_by: "system".to_string(),
            recorded_at: 1000,
            expires_at: None,
            metadata: HashMap::new(),
        };
        backend.store_compliance_evidence_record(record).unwrap();
        assert_eq!(backend.list_evidence_for_framework("cjis-v6.0").len(), 1);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryFrameworkBackend::new();
        backend.store_framework(test_manifest()).unwrap();
        backend.store_requirement(test_requirement()).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.framework_count, 1);
        assert_eq!(info.requirement_count, 1);
        assert_eq!(info.backend_type, "in-memory");
    }

    #[test]
    fn test_flush_succeeds() {
        let mut backend = InMemoryFrameworkBackend::new();
        assert!(backend.flush().is_ok());
    }

    #[test]
    fn test_jurisdiction_and_domain_display() {
        assert_eq!(Jurisdiction::UnitedStates.to_string(), "United States");
        assert_eq!(FrameworkDomain::CriminalJustice.to_string(), "Criminal Justice");
        assert_eq!(
            Jurisdiction::Other { name: "Japan".into() }.to_string(),
            "Other(Japan)"
        );
    }
}
