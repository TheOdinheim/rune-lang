// ═══════════════════════════════════════════════════════════════════════
// Provenance Backend — Pluggable storage for provenance artifacts.
//
// Layer 3 defines the storage contract for attestations, lineage records,
// custody events, and transparency log entries. verify_chain_integrity
// verifies the signature chain links between consecutive attestations
// for the same artifact.
//
// ArtifactRef is a thin newtype decoupling from ArtifactId, following
// the SubjectRef/IdentityRef pattern from rune-privacy/rune-permissions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::ProvenanceError;

// ── ArtifactRef ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactRef(String);

impl ArtifactRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<crate::artifact::ArtifactId> for ArtifactRef {
    fn from(id: crate::artifact::ArtifactId) -> Self {
        Self(id.0)
    }
}

// ── CustodianRef ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustodianRef(String);

impl CustodianRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CustodianRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── StoredAttestation ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredAttestation {
    pub attestation_id: String,
    pub artifact_ref: ArtifactRef,
    pub predicate_type: String,
    pub predicate_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_key_ref: String,
    pub issued_at: i64,
    pub predecessor_attestation_id: Option<String>,
}

// ── StoredLineageRecord ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredLineageRecord {
    pub record_id: String,
    pub artifact_ref: ArtifactRef,
    pub parent_artifact_refs: Vec<ArtifactRef>,
    pub transformation: String,
    pub recorded_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredCustodyEvent ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredCustodyEvent {
    pub event_id: String,
    pub artifact_ref: ArtifactRef,
    pub from_custodian: CustodianRef,
    pub to_custodian: CustodianRef,
    pub timestamp: i64,
    pub reason: String,
    pub signature: Vec<u8>,
}

// ── StoredTransparencyLogEntry ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredTransparencyLogEntry {
    pub entry_id: String,
    pub artifact_ref: ArtifactRef,
    pub log_source: String,
    pub inclusion_proof: String,
    pub logged_at: i64,
}

// ── ProvenanceBackendInfo ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProvenanceBackendInfo {
    pub backend_name: String,
    pub attestation_count: usize,
    pub lineage_record_count: usize,
    pub custody_event_count: usize,
    pub transparency_log_entry_count: usize,
}

// ── ProvenanceBackend trait ─────────────────────────────────────────

pub trait ProvenanceBackend {
    fn store_attestation(&mut self, attestation: StoredAttestation) -> Result<(), ProvenanceError>;
    fn retrieve_attestation(&self, attestation_id: &str) -> Result<Option<StoredAttestation>, ProvenanceError>;
    fn list_attestations_for_subject(&self, artifact_ref: &ArtifactRef) -> Result<Vec<StoredAttestation>, ProvenanceError>;
    fn delete_attestation(&mut self, attestation_id: &str) -> Result<(), ProvenanceError>;
    fn attestation_count(&self) -> usize;

    fn store_lineage_record(&mut self, record: StoredLineageRecord) -> Result<(), ProvenanceError>;
    fn retrieve_lineage_record(&self, record_id: &str) -> Result<Option<StoredLineageRecord>, ProvenanceError>;
    fn list_lineage_records_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<StoredLineageRecord>, ProvenanceError>;

    fn store_custody_event(&mut self, event: StoredCustodyEvent) -> Result<(), ProvenanceError>;
    fn retrieve_custody_event(&self, event_id: &str) -> Result<Option<StoredCustodyEvent>, ProvenanceError>;
    fn list_custody_events_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<StoredCustodyEvent>, ProvenanceError>;

    fn store_transparency_log_entry(&mut self, entry: StoredTransparencyLogEntry) -> Result<(), ProvenanceError>;
    fn retrieve_transparency_log_entry(&self, entry_id: &str) -> Result<Option<StoredTransparencyLogEntry>, ProvenanceError>;
    fn list_transparency_log_entries(&self) -> Result<Vec<StoredTransparencyLogEntry>, ProvenanceError>;

    fn verify_chain_integrity(&self, artifact_ref: &ArtifactRef) -> Result<bool, ProvenanceError>;
    fn flush(&mut self) -> Result<(), ProvenanceError>;
    fn backend_info(&self) -> ProvenanceBackendInfo;
}

// ── InMemoryProvenanceBackend ───────────────────────────────────────

#[derive(Default)]
pub struct InMemoryProvenanceBackend {
    attestations: HashMap<String, StoredAttestation>,
    lineage_records: HashMap<String, StoredLineageRecord>,
    custody_events: HashMap<String, StoredCustodyEvent>,
    transparency_log_entries: HashMap<String, StoredTransparencyLogEntry>,
}

impl InMemoryProvenanceBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProvenanceBackend for InMemoryProvenanceBackend {
    fn store_attestation(&mut self, a: StoredAttestation) -> Result<(), ProvenanceError> {
        if self.attestations.contains_key(&a.attestation_id) {
            return Err(ProvenanceError::InvalidOperation(format!("attestation {} already exists", a.attestation_id)));
        }
        self.attestations.insert(a.attestation_id.clone(), a);
        Ok(())
    }

    fn retrieve_attestation(&self, id: &str) -> Result<Option<StoredAttestation>, ProvenanceError> {
        Ok(self.attestations.get(id).cloned())
    }

    fn list_attestations_for_subject(&self, artifact_ref: &ArtifactRef) -> Result<Vec<StoredAttestation>, ProvenanceError> {
        Ok(self.attestations.values().filter(|a| a.artifact_ref == *artifact_ref).cloned().collect())
    }

    fn delete_attestation(&mut self, id: &str) -> Result<(), ProvenanceError> {
        self.attestations.remove(id)
            .ok_or_else(|| ProvenanceError::InvalidOperation(format!("attestation {id} not found")))?;
        Ok(())
    }

    fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    fn store_lineage_record(&mut self, r: StoredLineageRecord) -> Result<(), ProvenanceError> {
        if self.lineage_records.contains_key(&r.record_id) {
            return Err(ProvenanceError::InvalidOperation(format!("lineage record {} already exists", r.record_id)));
        }
        self.lineage_records.insert(r.record_id.clone(), r);
        Ok(())
    }

    fn retrieve_lineage_record(&self, id: &str) -> Result<Option<StoredLineageRecord>, ProvenanceError> {
        Ok(self.lineage_records.get(id).cloned())
    }

    fn list_lineage_records_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<StoredLineageRecord>, ProvenanceError> {
        Ok(self.lineage_records.values().filter(|r| r.artifact_ref == *artifact_ref).cloned().collect())
    }

    fn store_custody_event(&mut self, e: StoredCustodyEvent) -> Result<(), ProvenanceError> {
        if self.custody_events.contains_key(&e.event_id) {
            return Err(ProvenanceError::InvalidOperation(format!("custody event {} already exists", e.event_id)));
        }
        self.custody_events.insert(e.event_id.clone(), e);
        Ok(())
    }

    fn retrieve_custody_event(&self, id: &str) -> Result<Option<StoredCustodyEvent>, ProvenanceError> {
        Ok(self.custody_events.get(id).cloned())
    }

    fn list_custody_events_for_artifact(&self, artifact_ref: &ArtifactRef) -> Result<Vec<StoredCustodyEvent>, ProvenanceError> {
        Ok(self.custody_events.values().filter(|e| e.artifact_ref == *artifact_ref).cloned().collect())
    }

    fn store_transparency_log_entry(&mut self, entry: StoredTransparencyLogEntry) -> Result<(), ProvenanceError> {
        if self.transparency_log_entries.contains_key(&entry.entry_id) {
            return Err(ProvenanceError::InvalidOperation(format!("transparency log entry {} already exists", entry.entry_id)));
        }
        self.transparency_log_entries.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    fn retrieve_transparency_log_entry(&self, id: &str) -> Result<Option<StoredTransparencyLogEntry>, ProvenanceError> {
        Ok(self.transparency_log_entries.get(id).cloned())
    }

    fn list_transparency_log_entries(&self) -> Result<Vec<StoredTransparencyLogEntry>, ProvenanceError> {
        Ok(self.transparency_log_entries.values().cloned().collect())
    }

    fn verify_chain_integrity(&self, artifact_ref: &ArtifactRef) -> Result<bool, ProvenanceError> {
        let mut attestations: Vec<_> = self.attestations.values()
            .filter(|a| a.artifact_ref == *artifact_ref)
            .collect();
        attestations.sort_by_key(|a| a.issued_at);

        for i in 1..attestations.len() {
            if let Some(ref pred_id) = attestations[i].predecessor_attestation_id {
                if *pred_id != attestations[i - 1].attestation_id {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn flush(&mut self) -> Result<(), ProvenanceError> {
        self.attestations.clear();
        self.lineage_records.clear();
        self.custody_events.clear();
        self.transparency_log_entries.clear();
        Ok(())
    }

    fn backend_info(&self) -> ProvenanceBackendInfo {
        ProvenanceBackendInfo {
            backend_name: "InMemoryProvenanceBackend".to_string(),
            attestation_count: self.attestations.len(),
            lineage_record_count: self.lineage_records.len(),
            custody_event_count: self.custody_events.len(),
            transparency_log_entry_count: self.transparency_log_entries.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(id: &str, artifact: &str, pred: Option<&str>) -> StoredAttestation {
        StoredAttestation {
            attestation_id: id.to_string(),
            artifact_ref: ArtifactRef::new(artifact),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate_bytes: b"{}".to_vec(),
            signature: vec![1, 2, 3],
            signing_key_ref: "key-1".to_string(),
            issued_at: 1000,
            predecessor_attestation_id: pred.map(|s| s.to_string()),
        }
    }

    fn make_lineage_record(id: &str, artifact: &str) -> StoredLineageRecord {
        StoredLineageRecord {
            record_id: id.to_string(),
            artifact_ref: ArtifactRef::new(artifact),
            parent_artifact_refs: vec![ArtifactRef::new("parent-1")],
            transformation: "filter".to_string(),
            recorded_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn make_custody_event(id: &str, artifact: &str) -> StoredCustodyEvent {
        StoredCustodyEvent {
            event_id: id.to_string(),
            artifact_ref: ArtifactRef::new(artifact),
            from_custodian: CustodianRef::new("alice"),
            to_custodian: CustodianRef::new("bob"),
            timestamp: 1000,
            reason: "handoff".to_string(),
            signature: vec![1, 2, 3],
        }
    }

    fn make_log_entry(id: &str, artifact: &str) -> StoredTransparencyLogEntry {
        StoredTransparencyLogEntry {
            entry_id: id.to_string(),
            artifact_ref: ArtifactRef::new(artifact),
            log_source: "rekor".to_string(),
            inclusion_proof: "proof-data".to_string(),
            logged_at: 1000,
        }
    }

    #[test]
    fn test_store_and_retrieve_attestation() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_attestation(make_attestation("a1", "art-1", None)).unwrap();
        let a = backend.retrieve_attestation("a1").unwrap().unwrap();
        assert_eq!(a.attestation_id, "a1");
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_attestation(make_attestation("a1", "art-1", None)).unwrap();
        assert!(backend.store_attestation(make_attestation("a1", "art-1", None)).is_err());
    }

    #[test]
    fn test_list_attestations_for_subject() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_attestation(make_attestation("a1", "art-1", None)).unwrap();
        backend.store_attestation(make_attestation("a2", "art-1", Some("a1"))).unwrap();
        backend.store_attestation(make_attestation("a3", "art-2", None)).unwrap();
        let list = backend.list_attestations_for_subject(&ArtifactRef::new("art-1")).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_delete_attestation() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_attestation(make_attestation("a1", "art-1", None)).unwrap();
        backend.delete_attestation("a1").unwrap();
        assert!(backend.retrieve_attestation("a1").unwrap().is_none());
    }

    #[test]
    fn test_store_and_retrieve_lineage() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_lineage_record(make_lineage_record("l1", "art-1")).unwrap();
        let l = backend.retrieve_lineage_record("l1").unwrap().unwrap();
        assert_eq!(l.record_id, "l1");
    }

    #[test]
    fn test_store_and_retrieve_custody() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_custody_event(make_custody_event("c1", "art-1")).unwrap();
        let c = backend.retrieve_custody_event("c1").unwrap().unwrap();
        assert_eq!(c.event_id, "c1");
    }

    #[test]
    fn test_store_and_list_transparency_log() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_transparency_log_entry(make_log_entry("t1", "art-1")).unwrap();
        backend.store_transparency_log_entry(make_log_entry("t2", "art-2")).unwrap();
        assert_eq!(backend.list_transparency_log_entries().unwrap().len(), 2);
    }

    #[test]
    fn test_verify_chain_integrity_valid() {
        let mut backend = InMemoryProvenanceBackend::new();
        let mut a1 = make_attestation("a1", "art-1", None);
        a1.issued_at = 1000;
        backend.store_attestation(a1).unwrap();
        let mut a2 = make_attestation("a2", "art-1", Some("a1"));
        a2.issued_at = 2000;
        backend.store_attestation(a2).unwrap();
        assert!(backend.verify_chain_integrity(&ArtifactRef::new("art-1")).unwrap());
    }

    #[test]
    fn test_verify_chain_integrity_broken() {
        let mut backend = InMemoryProvenanceBackend::new();
        let mut a1 = make_attestation("a1", "art-1", None);
        a1.issued_at = 1000;
        backend.store_attestation(a1).unwrap();
        let mut a2 = make_attestation("a2", "art-1", Some("wrong-id"));
        a2.issued_at = 2000;
        backend.store_attestation(a2).unwrap();
        assert!(!backend.verify_chain_integrity(&ArtifactRef::new("art-1")).unwrap());
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_attestation(make_attestation("a1", "art-1", None)).unwrap();
        backend.store_lineage_record(make_lineage_record("l1", "art-1")).unwrap();
        backend.flush().unwrap();
        let info = backend.backend_info();
        assert_eq!(info.attestation_count, 0);
        assert_eq!(info.lineage_record_count, 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryProvenanceBackend::new();
        backend.store_attestation(make_attestation("a1", "art-1", None)).unwrap();
        backend.store_lineage_record(make_lineage_record("l1", "art-1")).unwrap();
        backend.store_custody_event(make_custody_event("c1", "art-1")).unwrap();
        backend.store_transparency_log_entry(make_log_entry("t1", "art-1")).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.attestation_count, 1);
        assert_eq!(info.lineage_record_count, 1);
        assert_eq!(info.custody_event_count, 1);
        assert_eq!(info.transparency_log_entry_count, 1);
    }

    #[test]
    fn test_artifact_ref_from_artifact_id() {
        let id = crate::artifact::ArtifactId::new("test");
        let ar = ArtifactRef::from(id);
        assert_eq!(ar.as_str(), "test");
    }

    #[test]
    fn test_custodian_ref_display() {
        let cr = CustodianRef::new("alice");
        assert_eq!(cr.to_string(), "alice");
    }
}
