// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — SafetyBackend trait for pluggable storage of safety
// constraints, envelopes, cases, violation records, and shutdown records.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SafetyError;

// ── ConstraintCategory ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstraintCategory {
    OperationalBoundary,
    BehavioralLimit,
    ResourceLimit,
    TemporalLimit,
    InteractionLimit,
    DataBoundary,
    Other { name: String },
}

impl fmt::Display for ConstraintCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationalBoundary => f.write_str("OperationalBoundary"),
            Self::BehavioralLimit => f.write_str("BehavioralLimit"),
            Self::ResourceLimit => f.write_str("ResourceLimit"),
            Self::TemporalLimit => f.write_str("TemporalLimit"),
            Self::InteractionLimit => f.write_str("InteractionLimit"),
            Self::DataBoundary => f.write_str("DataBoundary"),
            Self::Other { name } => write!(f, "Other({name})"),
        }
    }
}

// ── ConstraintSeverityLevel ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstraintSeverityLevel {
    Advisory,
    Mandatory,
    Critical,
    Absolute,
}

impl fmt::Display for ConstraintSeverityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advisory => f.write_str("Advisory"),
            Self::Mandatory => f.write_str("Mandatory"),
            Self::Critical => f.write_str("Critical"),
            Self::Absolute => f.write_str("Absolute"),
        }
    }
}

// ── EnvelopeStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredEnvelopeStatus {
    Active,
    Suspended,
    Retired,
}

impl fmt::Display for StoredEnvelopeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("Active"),
            Self::Suspended => f.write_str("Suspended"),
            Self::Retired => f.write_str("Retired"),
        }
    }
}

// ── SafetyCaseMethodology ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyCaseMethodology {
    Gsn,
    Cae,
    Amlas,
    NistAiRmf,
    Custom { name: String },
}

impl fmt::Display for SafetyCaseMethodology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gsn => f.write_str("GSN"),
            Self::Cae => f.write_str("CAE"),
            Self::Amlas => f.write_str("AMLAS"),
            Self::NistAiRmf => f.write_str("NIST AI RMF"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── SafetyCaseRecordStatus ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyCaseRecordStatus {
    Draft,
    UnderReview,
    Accepted,
    Challenged,
    Withdrawn,
}

impl fmt::Display for SafetyCaseRecordStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => f.write_str("Draft"),
            Self::UnderReview => f.write_str("UnderReview"),
            Self::Accepted => f.write_str("Accepted"),
            Self::Challenged => f.write_str("Challenged"),
            Self::Withdrawn => f.write_str("Withdrawn"),
        }
    }
}

// ── ShutdownType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShutdownType {
    EmergencyImmediate,
    GracefulDegradation,
    ScheduledMaintenance,
    ManualOverride,
}

impl fmt::Display for ShutdownType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmergencyImmediate => f.write_str("EmergencyImmediate"),
            Self::GracefulDegradation => f.write_str("GracefulDegradation"),
            Self::ScheduledMaintenance => f.write_str("ScheduledMaintenance"),
            Self::ManualOverride => f.write_str("ManualOverride"),
        }
    }
}

// ── Stored types ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSafetyConstraint {
    pub constraint_id: String,
    pub name: String,
    pub description: String,
    pub constraint_category: ConstraintCategory,
    pub severity: ConstraintSeverityLevel,
    pub referenced_system: String,
    pub enforcement_policy: String,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSafetyEnvelope {
    pub envelope_id: String,
    pub system_id: String,
    pub name: String,
    pub description: String,
    pub constraint_refs: Vec<String>,
    pub status: StoredEnvelopeStatus,
    pub safe_state_description: String,
    pub degraded_operation_available: bool,
    pub created_at: i64,
    pub last_evaluated_at: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSafetyCaseRecord {
    pub case_id: String,
    pub system_id: String,
    pub name: String,
    pub description: String,
    pub methodology: SafetyCaseMethodology,
    pub top_level_claim: String,
    pub argument_structure_bytes: Vec<u8>,
    pub evidence_refs: Vec<String>,
    pub status: SafetyCaseRecordStatus,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<i64>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBoundaryViolationRecord {
    pub violation_id: String,
    pub envelope_id: String,
    pub system_id: String,
    pub constraint_ref_violated: String,
    pub violation_description: String,
    pub detected_at: i64,
    pub severity_at_detection: String,
    pub response_taken: String,
    pub resolved_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredShutdownRecord {
    pub shutdown_id: String,
    pub system_id: String,
    pub envelope_id: Option<String>,
    pub trigger_reason: String,
    pub initiated_by: String,
    pub initiated_at: i64,
    pub completed_at: Option<i64>,
    pub shutdown_type: ShutdownType,
    pub reauthorization_required: bool,
    pub reauthorized_by: Option<String>,
    pub reauthorized_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── SafetyBackendInfo ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyBackendInfo {
    pub backend_name: String,
    pub constraint_count: usize,
    pub envelope_count: usize,
    pub case_count: usize,
    pub violation_count: usize,
    pub shutdown_count: usize,
}

// ── SafetyBackend trait ─────────────────────────────────────────────

pub trait SafetyBackend {
    fn store_safety_constraint(
        &mut self,
        constraint: StoredSafetyConstraint,
    ) -> Result<(), SafetyError>;
    fn retrieve_safety_constraint(
        &self,
        constraint_id: &str,
    ) -> Result<StoredSafetyConstraint, SafetyError>;
    fn delete_safety_constraint(&mut self, constraint_id: &str) -> Result<(), SafetyError>;
    fn list_constraints_by_category(
        &self,
        category: &ConstraintCategory,
    ) -> Vec<StoredSafetyConstraint>;
    fn constraint_count(&self) -> usize;

    fn store_safety_envelope(
        &mut self,
        envelope: StoredSafetyEnvelope,
    ) -> Result<(), SafetyError>;
    fn retrieve_safety_envelope(
        &self,
        envelope_id: &str,
    ) -> Result<StoredSafetyEnvelope, SafetyError>;
    fn list_envelopes_by_system(&self, system_id: &str) -> Vec<StoredSafetyEnvelope>;

    fn store_safety_case(
        &mut self,
        case: StoredSafetyCaseRecord,
    ) -> Result<(), SafetyError>;
    fn retrieve_safety_case(
        &self,
        case_id: &str,
    ) -> Result<StoredSafetyCaseRecord, SafetyError>;
    fn list_safety_cases_by_system(&self, system_id: &str) -> Vec<StoredSafetyCaseRecord>;

    fn store_boundary_violation_record(
        &mut self,
        record: StoredBoundaryViolationRecord,
    ) -> Result<(), SafetyError>;
    fn retrieve_boundary_violation_record(
        &self,
        violation_id: &str,
    ) -> Result<StoredBoundaryViolationRecord, SafetyError>;
    fn list_violations_for_envelope(
        &self,
        envelope_id: &str,
    ) -> Vec<StoredBoundaryViolationRecord>;

    fn store_shutdown_record(
        &mut self,
        record: StoredShutdownRecord,
    ) -> Result<(), SafetyError>;
    fn retrieve_shutdown_record(
        &self,
        shutdown_id: &str,
    ) -> Result<StoredShutdownRecord, SafetyError>;
    fn list_shutdowns_by_system(&self, system_id: &str) -> Vec<StoredShutdownRecord>;

    fn flush(&mut self) -> Result<(), SafetyError>;
    fn backend_info(&self) -> SafetyBackendInfo;
}

// ── InMemorySafetyBackend ───────────────────────────────────────────

pub struct InMemorySafetyBackend {
    constraints: HashMap<String, StoredSafetyConstraint>,
    envelopes: HashMap<String, StoredSafetyEnvelope>,
    cases: HashMap<String, StoredSafetyCaseRecord>,
    violations: HashMap<String, StoredBoundaryViolationRecord>,
    shutdowns: HashMap<String, StoredShutdownRecord>,
}

impl InMemorySafetyBackend {
    pub fn new() -> Self {
        Self {
            constraints: HashMap::new(),
            envelopes: HashMap::new(),
            cases: HashMap::new(),
            violations: HashMap::new(),
            shutdowns: HashMap::new(),
        }
    }
}

impl Default for InMemorySafetyBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyBackend for InMemorySafetyBackend {
    fn store_safety_constraint(
        &mut self,
        constraint: StoredSafetyConstraint,
    ) -> Result<(), SafetyError> {
        self.constraints
            .insert(constraint.constraint_id.clone(), constraint);
        Ok(())
    }

    fn retrieve_safety_constraint(
        &self,
        constraint_id: &str,
    ) -> Result<StoredSafetyConstraint, SafetyError> {
        self.constraints
            .get(constraint_id)
            .cloned()
            .ok_or_else(|| SafetyError::ConstraintNotFound(constraint_id.to_string()))
    }

    fn delete_safety_constraint(&mut self, constraint_id: &str) -> Result<(), SafetyError> {
        self.constraints
            .remove(constraint_id)
            .map(|_| ())
            .ok_or_else(|| SafetyError::ConstraintNotFound(constraint_id.to_string()))
    }

    fn list_constraints_by_category(
        &self,
        category: &ConstraintCategory,
    ) -> Vec<StoredSafetyConstraint> {
        self.constraints
            .values()
            .filter(|c| &c.constraint_category == category)
            .cloned()
            .collect()
    }

    fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    fn store_safety_envelope(
        &mut self,
        envelope: StoredSafetyEnvelope,
    ) -> Result<(), SafetyError> {
        self.envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        Ok(())
    }

    fn retrieve_safety_envelope(
        &self,
        envelope_id: &str,
    ) -> Result<StoredSafetyEnvelope, SafetyError> {
        self.envelopes
            .get(envelope_id)
            .cloned()
            .ok_or_else(|| SafetyError::InvalidOperation(format!("envelope not found: {envelope_id}")))
    }

    fn list_envelopes_by_system(&self, system_id: &str) -> Vec<StoredSafetyEnvelope> {
        self.envelopes
            .values()
            .filter(|e| e.system_id == system_id)
            .cloned()
            .collect()
    }

    fn store_safety_case(
        &mut self,
        case: StoredSafetyCaseRecord,
    ) -> Result<(), SafetyError> {
        self.cases.insert(case.case_id.clone(), case);
        Ok(())
    }

    fn retrieve_safety_case(
        &self,
        case_id: &str,
    ) -> Result<StoredSafetyCaseRecord, SafetyError> {
        self.cases
            .get(case_id)
            .cloned()
            .ok_or_else(|| SafetyError::SafetyCaseNotFound(case_id.to_string()))
    }

    fn list_safety_cases_by_system(&self, system_id: &str) -> Vec<StoredSafetyCaseRecord> {
        self.cases
            .values()
            .filter(|c| c.system_id == system_id)
            .cloned()
            .collect()
    }

    fn store_boundary_violation_record(
        &mut self,
        record: StoredBoundaryViolationRecord,
    ) -> Result<(), SafetyError> {
        self.violations
            .insert(record.violation_id.clone(), record);
        Ok(())
    }

    fn retrieve_boundary_violation_record(
        &self,
        violation_id: &str,
    ) -> Result<StoredBoundaryViolationRecord, SafetyError> {
        self.violations
            .get(violation_id)
            .cloned()
            .ok_or_else(|| SafetyError::InvalidOperation(format!("violation not found: {violation_id}")))
    }

    fn list_violations_for_envelope(
        &self,
        envelope_id: &str,
    ) -> Vec<StoredBoundaryViolationRecord> {
        self.violations
            .values()
            .filter(|v| v.envelope_id == envelope_id)
            .cloned()
            .collect()
    }

    fn store_shutdown_record(
        &mut self,
        record: StoredShutdownRecord,
    ) -> Result<(), SafetyError> {
        self.shutdowns
            .insert(record.shutdown_id.clone(), record);
        Ok(())
    }

    fn retrieve_shutdown_record(
        &self,
        shutdown_id: &str,
    ) -> Result<StoredShutdownRecord, SafetyError> {
        self.shutdowns
            .get(shutdown_id)
            .cloned()
            .ok_or_else(|| SafetyError::InvalidOperation(format!("shutdown not found: {shutdown_id}")))
    }

    fn list_shutdowns_by_system(&self, system_id: &str) -> Vec<StoredShutdownRecord> {
        self.shutdowns
            .values()
            .filter(|s| s.system_id == system_id)
            .cloned()
            .collect()
    }

    fn flush(&mut self) -> Result<(), SafetyError> {
        self.constraints.clear();
        self.envelopes.clear();
        self.cases.clear();
        self.violations.clear();
        self.shutdowns.clear();
        Ok(())
    }

    fn backend_info(&self) -> SafetyBackendInfo {
        SafetyBackendInfo {
            backend_name: "InMemorySafetyBackend".to_string(),
            constraint_count: self.constraints.len(),
            envelope_count: self.envelopes.len(),
            case_count: self.cases.len(),
            violation_count: self.violations.len(),
            shutdown_count: self.shutdowns.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_constraint() -> StoredSafetyConstraint {
        StoredSafetyConstraint {
            constraint_id: "sc-001".into(),
            name: "Max latency".into(),
            description: "Response latency must not exceed 100ms".into(),
            constraint_category: ConstraintCategory::OperationalBoundary,
            severity: ConstraintSeverityLevel::Critical,
            referenced_system: "inference-engine-01".into(),
            enforcement_policy: "hard-stop".into(),
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_envelope() -> StoredSafetyEnvelope {
        StoredSafetyEnvelope {
            envelope_id: "env-001".into(),
            system_id: "sys-alpha".into(),
            name: "Production envelope".into(),
            description: "Operational boundaries for production".into(),
            constraint_refs: vec!["sc-001".into()],
            status: StoredEnvelopeStatus::Active,
            safe_state_description: "Return cached fallback response".into(),
            degraded_operation_available: true,
            created_at: 1000,
            last_evaluated_at: 2000,
            metadata: HashMap::new(),
        }
    }

    fn sample_case() -> StoredSafetyCaseRecord {
        StoredSafetyCaseRecord {
            case_id: "case-001".into(),
            system_id: "sys-alpha".into(),
            name: "Production safety case".into(),
            description: "GSN safety case for production deployment".into(),
            methodology: SafetyCaseMethodology::Gsn,
            top_level_claim: "System is acceptably safe for production".into(),
            argument_structure_bytes: vec![1, 2, 3],
            evidence_refs: vec!["ev-001".into()],
            status: SafetyCaseRecordStatus::Draft,
            reviewed_by: None,
            reviewed_at: None,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_violation() -> StoredBoundaryViolationRecord {
        StoredBoundaryViolationRecord {
            violation_id: "viol-001".into(),
            envelope_id: "env-001".into(),
            system_id: "sys-alpha".into(),
            constraint_ref_violated: "sc-001".into(),
            violation_description: "Latency exceeded 100ms".into(),
            detected_at: 3000,
            severity_at_detection: "Critical".into(),
            response_taken: "Degraded operation".into(),
            resolved_at: Some(3500),
            metadata: HashMap::new(),
        }
    }

    fn sample_shutdown() -> StoredShutdownRecord {
        StoredShutdownRecord {
            shutdown_id: "sd-001".into(),
            system_id: "sys-alpha".into(),
            envelope_id: Some("env-001".into()),
            trigger_reason: "Repeated boundary violations".into(),
            initiated_by: "safety-controller".into(),
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
    fn test_store_and_retrieve_constraint() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_constraint(sample_constraint()).unwrap();
        let c = backend.retrieve_safety_constraint("sc-001").unwrap();
        assert_eq!(c.name, "Max latency");
    }

    #[test]
    fn test_delete_constraint() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_constraint(sample_constraint()).unwrap();
        backend.delete_safety_constraint("sc-001").unwrap();
        assert!(backend.retrieve_safety_constraint("sc-001").is_err());
    }

    #[test]
    fn test_list_constraints_by_category() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_constraint(sample_constraint()).unwrap();
        let mut c2 = sample_constraint();
        c2.constraint_id = "sc-002".into();
        c2.constraint_category = ConstraintCategory::BehavioralLimit;
        backend.store_safety_constraint(c2).unwrap();
        assert_eq!(
            backend
                .list_constraints_by_category(&ConstraintCategory::OperationalBoundary)
                .len(),
            1
        );
    }

    #[test]
    fn test_constraint_count() {
        let mut backend = InMemorySafetyBackend::new();
        assert_eq!(backend.constraint_count(), 0);
        backend.store_safety_constraint(sample_constraint()).unwrap();
        assert_eq!(backend.constraint_count(), 1);
    }

    #[test]
    fn test_store_and_retrieve_envelope() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_envelope(sample_envelope()).unwrap();
        let e = backend.retrieve_safety_envelope("env-001").unwrap();
        assert_eq!(e.system_id, "sys-alpha");
    }

    #[test]
    fn test_list_envelopes_by_system() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_envelope(sample_envelope()).unwrap();
        assert_eq!(backend.list_envelopes_by_system("sys-alpha").len(), 1);
        assert_eq!(backend.list_envelopes_by_system("other").len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_safety_case() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_case(sample_case()).unwrap();
        let c = backend.retrieve_safety_case("case-001").unwrap();
        assert_eq!(c.methodology, SafetyCaseMethodology::Gsn);
    }

    #[test]
    fn test_list_safety_cases_by_system() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_case(sample_case()).unwrap();
        assert_eq!(backend.list_safety_cases_by_system("sys-alpha").len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_violation() {
        let mut backend = InMemorySafetyBackend::new();
        backend
            .store_boundary_violation_record(sample_violation())
            .unwrap();
        let v = backend
            .retrieve_boundary_violation_record("viol-001")
            .unwrap();
        assert_eq!(v.constraint_ref_violated, "sc-001");
    }

    #[test]
    fn test_list_violations_for_envelope() {
        let mut backend = InMemorySafetyBackend::new();
        backend
            .store_boundary_violation_record(sample_violation())
            .unwrap();
        assert_eq!(backend.list_violations_for_envelope("env-001").len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_shutdown() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_shutdown_record(sample_shutdown()).unwrap();
        let s = backend.retrieve_shutdown_record("sd-001").unwrap();
        assert_eq!(s.shutdown_type, ShutdownType::EmergencyImmediate);
        assert!(s.reauthorization_required);
    }

    #[test]
    fn test_list_shutdowns_by_system() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_shutdown_record(sample_shutdown()).unwrap();
        assert_eq!(backend.list_shutdowns_by_system("sys-alpha").len(), 1);
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_constraint(sample_constraint()).unwrap();
        backend.store_safety_envelope(sample_envelope()).unwrap();
        backend.flush().unwrap();
        assert_eq!(backend.constraint_count(), 0);
        assert_eq!(backend.backend_info().envelope_count, 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemorySafetyBackend::new();
        backend.store_safety_constraint(sample_constraint()).unwrap();
        backend.store_safety_envelope(sample_envelope()).unwrap();
        backend.store_safety_case(sample_case()).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.backend_name, "InMemorySafetyBackend");
        assert_eq!(info.constraint_count, 1);
        assert_eq!(info.envelope_count, 1);
        assert_eq!(info.case_count, 1);
    }

    #[test]
    fn test_enum_display() {
        assert!(!ConstraintCategory::OperationalBoundary.to_string().is_empty());
        assert!(!ConstraintCategory::Other { name: "x".into() }.to_string().is_empty());
        assert!(!ConstraintSeverityLevel::Absolute.to_string().is_empty());
        assert!(!StoredEnvelopeStatus::Active.to_string().is_empty());
        assert!(!SafetyCaseMethodology::Gsn.to_string().is_empty());
        assert!(!SafetyCaseMethodology::Custom { name: "x".into() }.to_string().is_empty());
        assert!(!SafetyCaseRecordStatus::Draft.to_string().is_empty());
        assert!(!ShutdownType::EmergencyImmediate.to_string().is_empty());
    }
}
