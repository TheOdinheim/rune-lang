// ═══════════════════════════════════════════════════════════════════════
// Security Posture Backend — pluggable storage for vulnerability
// records, security control records, incident records, threat model
// records, and posture snapshots.
//
// Artifact references use opaque strings following the rune-truth
// EvidenceLinker loose-coupling pattern — no direct dependency on
// rune-provenance types.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::SecurityError;

// ── CvssSeverity ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl CvssSeverity {
    pub fn from_score_str(score: &str) -> Self {
        let s: f64 = score.parse().unwrap_or(0.0);
        if s <= 0.0 {
            Self::None
        } else if s < 4.0 {
            Self::Low
        } else if s < 7.0 {
            Self::Medium
        } else if s < 9.0 {
            Self::High
        } else {
            Self::Critical
        }
    }
}

impl fmt::Display for CvssSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── VulnerabilityStatus ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VulnerabilityStatus {
    Discovered,
    Confirmed,
    Remediated,
    Mitigated,
    FalsePositive,
    Accepted,
    Deferred,
}

impl fmt::Display for VulnerabilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ControlImplementationStatus ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ControlImplementationStatus {
    Implemented,
    PartiallyImplemented,
    NotImplemented,
    NotApplicable,
}

impl fmt::Display for ControlImplementationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── IncidentRecordStatus ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IncidentRecordStatus {
    Declared,
    Triaging,
    Containing,
    Eradicating,
    Recovering,
    PostIncident,
    Closed,
}

impl fmt::Display for IncidentRecordStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Stored record types ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVulnerabilityRecord {
    pub vulnerability_id: String,
    pub artifact_ref: String,
    pub cve_identifier: Option<String>,
    pub cvss_base_score: String,
    pub cvss_severity: CvssSeverity,
    pub discovered_at: i64,
    pub remediated_at: Option<i64>,
    pub evidence_attestation_refs: Vec<String>,
    pub current_status: VulnerabilityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSecurityControlRecord {
    pub control_id: String,
    pub framework_name: String,
    pub control_identifier: String,
    pub implementation_status: ControlImplementationStatus,
    pub last_validated_at: i64,
    pub evidence_attestation_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIncidentRecord {
    pub incident_id: String,
    pub severity: String,
    pub status: IncidentRecordStatus,
    pub declared_at: i64,
    pub closed_at: Option<i64>,
    pub description: String,
    pub affected_systems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredThreatModelRecord {
    pub threat_model_id: String,
    pub system_identifier: String,
    pub created_at: i64,
    pub reviewed_at: Option<i64>,
    pub threat_count: usize,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPostureSnapshot {
    pub snapshot_id: String,
    pub system_identifier: String,
    pub captured_at: i64,
    pub vulnerability_subscore: String,
    pub control_subscore: String,
    pub incident_subscore: String,
    pub threat_exposure_subscore: String,
    pub overall_score: String,
    pub posture_class: PostureClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PostureClass {
    Strong,
    Adequate,
    Weak,
    Critical,
    Unknown,
}

impl PostureClass {
    pub fn from_score_str(score: &str) -> Self {
        let s: f64 = score.parse().unwrap_or(0.0);
        if s >= 90.0 {
            Self::Strong
        } else if s >= 70.0 {
            Self::Adequate
        } else if s >= 40.0 {
            Self::Weak
        } else if s > 0.0 {
            Self::Critical
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for PostureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SecurityPostureBackendInfo ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPostureBackendInfo {
    pub backend_id: String,
    pub backend_type: String,
    pub vulnerability_count: usize,
    pub control_count: usize,
    pub incident_count: usize,
    pub threat_model_count: usize,
    pub snapshot_count: usize,
}

// ── SecurityPostureBackend trait ──────────────────────────────────

pub trait SecurityPostureBackend {
    // Vulnerability records
    fn store_vulnerability_record(&mut self, record: StoredVulnerabilityRecord) -> Result<(), SecurityError>;
    fn retrieve_vulnerability_record(&self, vulnerability_id: &str) -> Result<StoredVulnerabilityRecord, SecurityError>;
    fn delete_vulnerability_record(&mut self, vulnerability_id: &str) -> Result<(), SecurityError>;
    fn list_vulnerability_records_for_artifact(&self, artifact_ref: &str) -> Result<Vec<StoredVulnerabilityRecord>, SecurityError>;
    fn list_vulnerability_records_by_severity(&self, severity: CvssSeverity) -> Result<Vec<StoredVulnerabilityRecord>, SecurityError>;
    fn vulnerability_count(&self) -> usize;

    // Security control records
    fn store_security_control_record(&mut self, record: StoredSecurityControlRecord) -> Result<(), SecurityError>;
    fn retrieve_security_control_record(&self, control_id: &str) -> Result<StoredSecurityControlRecord, SecurityError>;
    fn list_security_control_records_by_framework(&self, framework_name: &str) -> Result<Vec<StoredSecurityControlRecord>, SecurityError>;
    fn update_security_control_status(&mut self, control_id: &str, status: ControlImplementationStatus) -> Result<(), SecurityError>;

    // Incident records
    fn store_incident_record(&mut self, record: StoredIncidentRecord) -> Result<(), SecurityError>;
    fn retrieve_incident_record(&self, incident_id: &str) -> Result<StoredIncidentRecord, SecurityError>;
    fn list_incident_records_by_severity(&self, severity: &str) -> Result<Vec<StoredIncidentRecord>, SecurityError>;
    fn list_incident_records_by_status(&self, status: IncidentRecordStatus) -> Result<Vec<StoredIncidentRecord>, SecurityError>;
    fn update_incident_status(&mut self, incident_id: &str, status: IncidentRecordStatus) -> Result<(), SecurityError>;

    // Threat model records
    fn store_threat_model_record(&mut self, record: StoredThreatModelRecord) -> Result<(), SecurityError>;
    fn retrieve_threat_model_record(&self, threat_model_id: &str) -> Result<StoredThreatModelRecord, SecurityError>;
    fn list_threat_model_records_for_system(&self, system_identifier: &str) -> Result<Vec<StoredThreatModelRecord>, SecurityError>;

    // Posture snapshots
    fn store_posture_snapshot(&mut self, snapshot: StoredPostureSnapshot) -> Result<(), SecurityError>;
    fn retrieve_posture_snapshot(&self, snapshot_id: &str) -> Result<StoredPostureSnapshot, SecurityError>;
    fn list_posture_snapshots_chronological(&self, system_identifier: &str) -> Result<Vec<StoredPostureSnapshot>, SecurityError>;

    // Housekeeping
    fn flush(&mut self) -> Result<(), SecurityError>;
    fn backend_info(&self) -> SecurityPostureBackendInfo;
}

// ── InMemorySecurityPostureBackend ────────────────────────────────

pub struct InMemorySecurityPostureBackend {
    id: String,
    vulnerabilities: HashMap<String, StoredVulnerabilityRecord>,
    controls: HashMap<String, StoredSecurityControlRecord>,
    incidents: HashMap<String, StoredIncidentRecord>,
    threat_models: HashMap<String, StoredThreatModelRecord>,
    snapshots: HashMap<String, StoredPostureSnapshot>,
}

impl InMemorySecurityPostureBackend {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            vulnerabilities: HashMap::new(),
            controls: HashMap::new(),
            incidents: HashMap::new(),
            threat_models: HashMap::new(),
            snapshots: HashMap::new(),
        }
    }
}

impl SecurityPostureBackend for InMemorySecurityPostureBackend {
    fn store_vulnerability_record(&mut self, record: StoredVulnerabilityRecord) -> Result<(), SecurityError> {
        if self.vulnerabilities.contains_key(&record.vulnerability_id) {
            return Err(SecurityError::VulnerabilityAlreadyExists(record.vulnerability_id));
        }
        self.vulnerabilities.insert(record.vulnerability_id.clone(), record);
        Ok(())
    }

    fn retrieve_vulnerability_record(&self, vulnerability_id: &str) -> Result<StoredVulnerabilityRecord, SecurityError> {
        self.vulnerabilities.get(vulnerability_id).cloned()
            .ok_or_else(|| SecurityError::VulnerabilityNotFound(vulnerability_id.to_string()))
    }

    fn delete_vulnerability_record(&mut self, vulnerability_id: &str) -> Result<(), SecurityError> {
        self.vulnerabilities.remove(vulnerability_id)
            .map(|_| ())
            .ok_or_else(|| SecurityError::VulnerabilityNotFound(vulnerability_id.to_string()))
    }

    fn list_vulnerability_records_for_artifact(&self, artifact_ref: &str) -> Result<Vec<StoredVulnerabilityRecord>, SecurityError> {
        Ok(self.vulnerabilities.values()
            .filter(|v| v.artifact_ref == artifact_ref)
            .cloned().collect())
    }

    fn list_vulnerability_records_by_severity(&self, severity: CvssSeverity) -> Result<Vec<StoredVulnerabilityRecord>, SecurityError> {
        Ok(self.vulnerabilities.values()
            .filter(|v| v.cvss_severity == severity)
            .cloned().collect())
    }

    fn vulnerability_count(&self) -> usize { self.vulnerabilities.len() }

    fn store_security_control_record(&mut self, record: StoredSecurityControlRecord) -> Result<(), SecurityError> {
        self.controls.insert(record.control_id.clone(), record);
        Ok(())
    }

    fn retrieve_security_control_record(&self, control_id: &str) -> Result<StoredSecurityControlRecord, SecurityError> {
        self.controls.get(control_id).cloned()
            .ok_or_else(|| SecurityError::InvalidOperation(format!("control not found: {control_id}")))
    }

    fn list_security_control_records_by_framework(&self, framework_name: &str) -> Result<Vec<StoredSecurityControlRecord>, SecurityError> {
        Ok(self.controls.values()
            .filter(|c| c.framework_name == framework_name)
            .cloned().collect())
    }

    fn update_security_control_status(&mut self, control_id: &str, status: ControlImplementationStatus) -> Result<(), SecurityError> {
        let record = self.controls.get_mut(control_id)
            .ok_or_else(|| SecurityError::InvalidOperation(format!("control not found: {control_id}")))?;
        record.implementation_status = status;
        Ok(())
    }

    fn store_incident_record(&mut self, record: StoredIncidentRecord) -> Result<(), SecurityError> {
        self.incidents.insert(record.incident_id.clone(), record);
        Ok(())
    }

    fn retrieve_incident_record(&self, incident_id: &str) -> Result<StoredIncidentRecord, SecurityError> {
        self.incidents.get(incident_id).cloned()
            .ok_or_else(|| SecurityError::IncidentNotFound(incident_id.to_string()))
    }

    fn list_incident_records_by_severity(&self, severity: &str) -> Result<Vec<StoredIncidentRecord>, SecurityError> {
        Ok(self.incidents.values()
            .filter(|i| i.severity == severity)
            .cloned().collect())
    }

    fn list_incident_records_by_status(&self, status: IncidentRecordStatus) -> Result<Vec<StoredIncidentRecord>, SecurityError> {
        Ok(self.incidents.values()
            .filter(|i| i.status == status)
            .cloned().collect())
    }

    fn update_incident_status(&mut self, incident_id: &str, status: IncidentRecordStatus) -> Result<(), SecurityError> {
        let record = self.incidents.get_mut(incident_id)
            .ok_or_else(|| SecurityError::IncidentNotFound(incident_id.to_string()))?;
        record.status = status;
        Ok(())
    }

    fn store_threat_model_record(&mut self, record: StoredThreatModelRecord) -> Result<(), SecurityError> {
        self.threat_models.insert(record.threat_model_id.clone(), record);
        Ok(())
    }

    fn retrieve_threat_model_record(&self, threat_model_id: &str) -> Result<StoredThreatModelRecord, SecurityError> {
        self.threat_models.get(threat_model_id).cloned()
            .ok_or_else(|| SecurityError::InvalidOperation(format!("threat model not found: {threat_model_id}")))
    }

    fn list_threat_model_records_for_system(&self, system_identifier: &str) -> Result<Vec<StoredThreatModelRecord>, SecurityError> {
        Ok(self.threat_models.values()
            .filter(|t| t.system_identifier == system_identifier)
            .cloned().collect())
    }

    fn store_posture_snapshot(&mut self, snapshot: StoredPostureSnapshot) -> Result<(), SecurityError> {
        self.snapshots.insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    fn retrieve_posture_snapshot(&self, snapshot_id: &str) -> Result<StoredPostureSnapshot, SecurityError> {
        self.snapshots.get(snapshot_id).cloned()
            .ok_or_else(|| SecurityError::InvalidOperation(format!("snapshot not found: {snapshot_id}")))
    }

    fn list_posture_snapshots_chronological(&self, system_identifier: &str) -> Result<Vec<StoredPostureSnapshot>, SecurityError> {
        let mut snaps: Vec<StoredPostureSnapshot> = self.snapshots.values()
            .filter(|s| s.system_identifier == system_identifier)
            .cloned().collect();
        snaps.sort_by_key(|s| s.captured_at);
        Ok(snaps)
    }

    fn flush(&mut self) -> Result<(), SecurityError> { Ok(()) }

    fn backend_info(&self) -> SecurityPostureBackendInfo {
        SecurityPostureBackendInfo {
            backend_id: self.id.clone(),
            backend_type: "in-memory".to_string(),
            vulnerability_count: self.vulnerabilities.len(),
            control_count: self.controls.len(),
            incident_count: self.incidents.len(),
            threat_model_count: self.threat_models.len(),
            snapshot_count: self.snapshots.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vuln(id: &str, artifact: &str, severity: CvssSeverity) -> StoredVulnerabilityRecord {
        StoredVulnerabilityRecord {
            vulnerability_id: id.to_string(),
            artifact_ref: artifact.to_string(),
            cve_identifier: Some("CVE-2026-0001".to_string()),
            cvss_base_score: "7.5".to_string(),
            cvss_severity: severity,
            discovered_at: 1000,
            remediated_at: None,
            evidence_attestation_refs: vec![],
            current_status: VulnerabilityStatus::Discovered,
        }
    }

    fn make_control(id: &str, framework: &str) -> StoredSecurityControlRecord {
        StoredSecurityControlRecord {
            control_id: id.to_string(),
            framework_name: framework.to_string(),
            control_identifier: format!("{framework}-1.1"),
            implementation_status: ControlImplementationStatus::Implemented,
            last_validated_at: 1000,
            evidence_attestation_refs: vec![],
        }
    }

    #[test]
    fn test_store_and_retrieve_vulnerability() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::High)).unwrap();
        let record = backend.retrieve_vulnerability_record("v1").unwrap();
        assert_eq!(record.vulnerability_id, "v1");
    }

    #[test]
    fn test_duplicate_vulnerability_rejected() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::High)).unwrap();
        assert!(backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::High)).is_err());
    }

    #[test]
    fn test_delete_vulnerability() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::High)).unwrap();
        backend.delete_vulnerability_record("v1").unwrap();
        assert!(backend.retrieve_vulnerability_record("v1").is_err());
    }

    #[test]
    fn test_list_vulnerabilities_by_artifact() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::High)).unwrap();
        backend.store_vulnerability_record(make_vuln("v2", "art-1", CvssSeverity::Low)).unwrap();
        backend.store_vulnerability_record(make_vuln("v3", "art-2", CvssSeverity::Medium)).unwrap();
        let records = backend.list_vulnerability_records_for_artifact("art-1").unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_list_vulnerabilities_by_severity() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::Critical)).unwrap();
        backend.store_vulnerability_record(make_vuln("v2", "art-1", CvssSeverity::Critical)).unwrap();
        backend.store_vulnerability_record(make_vuln("v3", "art-2", CvssSeverity::Low)).unwrap();
        let records = backend.list_vulnerability_records_by_severity(CvssSeverity::Critical).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_control() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_security_control_record(make_control("c1", "NIST-CSF")).unwrap();
        let record = backend.retrieve_security_control_record("c1").unwrap();
        assert_eq!(record.framework_name, "NIST-CSF");
    }

    #[test]
    fn test_update_control_status() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_security_control_record(make_control("c1", "CIS")).unwrap();
        backend.update_security_control_status("c1", ControlImplementationStatus::NotImplemented).unwrap();
        let record = backend.retrieve_security_control_record("c1").unwrap();
        assert_eq!(record.implementation_status, ControlImplementationStatus::NotImplemented);
    }

    #[test]
    fn test_list_controls_by_framework() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_security_control_record(make_control("c1", "NIST-CSF")).unwrap();
        backend.store_security_control_record(make_control("c2", "CIS")).unwrap();
        backend.store_security_control_record(make_control("c3", "NIST-CSF")).unwrap();
        let records = backend.list_security_control_records_by_framework("NIST-CSF").unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_incident() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        let record = StoredIncidentRecord {
            incident_id: "inc-1".to_string(),
            severity: "High".to_string(),
            status: IncidentRecordStatus::Declared,
            declared_at: 1000,
            closed_at: None,
            description: "test".to_string(),
            affected_systems: vec!["sys-1".to_string()],
        };
        backend.store_incident_record(record).unwrap();
        let retrieved = backend.retrieve_incident_record("inc-1").unwrap();
        assert_eq!(retrieved.severity, "High");
    }

    #[test]
    fn test_update_incident_status() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        let record = StoredIncidentRecord {
            incident_id: "inc-1".to_string(),
            severity: "High".to_string(),
            status: IncidentRecordStatus::Declared,
            declared_at: 1000,
            closed_at: None,
            description: "test".to_string(),
            affected_systems: vec![],
        };
        backend.store_incident_record(record).unwrap();
        backend.update_incident_status("inc-1", IncidentRecordStatus::Containing).unwrap();
        let retrieved = backend.retrieve_incident_record("inc-1").unwrap();
        assert_eq!(retrieved.status, IncidentRecordStatus::Containing);
    }

    #[test]
    fn test_store_and_retrieve_threat_model() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        let record = StoredThreatModelRecord {
            threat_model_id: "tm-1".to_string(),
            system_identifier: "api".to_string(),
            created_at: 1000,
            reviewed_at: None,
            threat_count: 5,
            description: "API threat model".to_string(),
        };
        backend.store_threat_model_record(record).unwrap();
        let retrieved = backend.retrieve_threat_model_record("tm-1").unwrap();
        assert_eq!(retrieved.threat_count, 5);
    }

    #[test]
    fn test_store_and_retrieve_posture_snapshot() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        let snapshot = StoredPostureSnapshot {
            snapshot_id: "snap-1".to_string(),
            system_identifier: "api".to_string(),
            captured_at: 1000,
            vulnerability_subscore: "85.0".to_string(),
            control_subscore: "90.0".to_string(),
            incident_subscore: "95.0".to_string(),
            threat_exposure_subscore: "80.0".to_string(),
            overall_score: "87.5".to_string(),
            posture_class: PostureClass::Adequate,
        };
        backend.store_posture_snapshot(snapshot).unwrap();
        let retrieved = backend.retrieve_posture_snapshot("snap-1").unwrap();
        assert_eq!(retrieved.posture_class, PostureClass::Adequate);
    }

    #[test]
    fn test_posture_snapshots_chronological() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        for (i, t) in [(3, 3000), (1, 1000), (2, 2000)] {
            backend.store_posture_snapshot(StoredPostureSnapshot {
                snapshot_id: format!("snap-{i}"),
                system_identifier: "api".to_string(),
                captured_at: t,
                vulnerability_subscore: "80.0".to_string(),
                control_subscore: "80.0".to_string(),
                incident_subscore: "80.0".to_string(),
                threat_exposure_subscore: "80.0".to_string(),
                overall_score: "80.0".to_string(),
                posture_class: PostureClass::Adequate,
            }).unwrap();
        }
        let snaps = backend.list_posture_snapshots_chronological("api").unwrap();
        assert_eq!(snaps[0].captured_at, 1000);
        assert_eq!(snaps[2].captured_at, 3000);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemorySecurityPostureBackend::new("b1");
        backend.store_vulnerability_record(make_vuln("v1", "art-1", CvssSeverity::High)).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.vulnerability_count, 1);
        assert_eq!(info.backend_type, "in-memory");
    }

    #[test]
    fn test_posture_class_from_score() {
        assert_eq!(PostureClass::from_score_str("95.0"), PostureClass::Strong);
        assert_eq!(PostureClass::from_score_str("75.0"), PostureClass::Adequate);
        assert_eq!(PostureClass::from_score_str("50.0"), PostureClass::Weak);
        assert_eq!(PostureClass::from_score_str("20.0"), PostureClass::Critical);
        assert_eq!(PostureClass::from_score_str("0.0"), PostureClass::Unknown);
    }

    #[test]
    fn test_cvss_severity_from_score() {
        assert_eq!(CvssSeverity::from_score_str("0.0"), CvssSeverity::None);
        assert_eq!(CvssSeverity::from_score_str("3.5"), CvssSeverity::Low);
        assert_eq!(CvssSeverity::from_score_str("5.0"), CvssSeverity::Medium);
        assert_eq!(CvssSeverity::from_score_str("8.0"), CvssSeverity::High);
        assert_eq!(CvssSeverity::from_score_str("9.5"), CvssSeverity::Critical);
    }
}
