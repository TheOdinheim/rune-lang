// ═══════════════════════════════════════════════════════════════════════
// Truth Backend — Pluggable storage for claims, contradictions,
// corroborations, and retractions.
//
// Layer 3 defines the storage contract for structured truth claims
// and their relational records. ClaimRef is a thin newtype decoupling
// from TruthClaim's id field. SubjectOfClaimRef is the generic
// reference for whatever a claim is about — an artifact, identity,
// document, event, or any other entity.
//
// StoredClaim carries evidence_attestation_refs linking back to
// rune-provenance's StoredAttestation IDs, closing the epistemic
// loop between "where did this come from" (provenance) and "what
// is claimed about it" (truth).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::TruthError;

// ── ClaimRef ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimRef(String);

impl ClaimRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClaimRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── SubjectOfClaimRef ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectOfClaimRef(String);

impl SubjectOfClaimRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectOfClaimRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── StoredClaim ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredClaim {
    pub claim_id: String,
    pub subject_of_claim_ref: SubjectOfClaimRef,
    pub claim_type: String,
    pub claim_body_bytes: Vec<u8>,
    pub claimant: String,
    pub asserted_at: i64,
    pub confidence_score: String,
    pub evidence_attestation_refs: Vec<String>,
    pub retracted_at: Option<i64>,
}

// ── StoredContradictionRecord ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredContradictionRecord {
    pub record_id: String,
    pub claim_a_ref: ClaimRef,
    pub claim_b_ref: ClaimRef,
    pub contradiction_type: String,
    pub explanation: String,
    pub detected_at: i64,
    pub resolved_at: Option<i64>,
}

// ── StoredCorroborationRecord ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredCorroborationRecord {
    pub record_id: String,
    pub claim_ref: ClaimRef,
    pub corroborating_claimant: String,
    pub corroboration_detail: String,
    pub recorded_at: i64,
}

// ── StoredRetractionRecord ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredRetractionRecord {
    pub record_id: String,
    pub claim_ref: ClaimRef,
    pub retracted_by: String,
    pub reason: String,
    pub retracted_at: i64,
}

// ── TruthBackendInfo ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TruthBackendInfo {
    pub backend_name: String,
    pub claim_count: usize,
    pub contradiction_record_count: usize,
    pub corroboration_record_count: usize,
    pub retraction_record_count: usize,
}

// ── TruthBackend trait ─────────────────────────────────────────────

pub trait TruthBackend {
    fn store_claim(&mut self, claim: StoredClaim) -> Result<(), TruthError>;
    fn retrieve_claim(&self, claim_id: &str) -> Result<Option<StoredClaim>, TruthError>;
    fn delete_claim(&mut self, claim_id: &str) -> Result<(), TruthError>;
    fn list_claims(&self) -> Result<Vec<StoredClaim>, TruthError>;
    fn list_claims_about_subject(&self, subject_ref: &SubjectOfClaimRef) -> Result<Vec<StoredClaim>, TruthError>;
    fn claim_count(&self) -> usize;

    fn store_contradiction_record(&mut self, record: StoredContradictionRecord) -> Result<(), TruthError>;
    fn retrieve_contradiction_record(&self, record_id: &str) -> Result<Option<StoredContradictionRecord>, TruthError>;
    fn list_contradictions_involving_claim(&self, claim_ref: &ClaimRef) -> Result<Vec<StoredContradictionRecord>, TruthError>;

    fn store_corroboration_record(&mut self, record: StoredCorroborationRecord) -> Result<(), TruthError>;
    fn retrieve_corroboration_record(&self, record_id: &str) -> Result<Option<StoredCorroborationRecord>, TruthError>;
    fn list_corroborations_for_claim(&self, claim_ref: &ClaimRef) -> Result<Vec<StoredCorroborationRecord>, TruthError>;

    fn store_retraction_record(&mut self, record: StoredRetractionRecord) -> Result<(), TruthError>;
    fn retrieve_retraction_record(&self, record_id: &str) -> Result<Option<StoredRetractionRecord>, TruthError>;
    fn list_retractions_for_claim(&self, claim_ref: &ClaimRef) -> Result<Vec<StoredRetractionRecord>, TruthError>;

    fn flush(&mut self) -> Result<(), TruthError>;
    fn backend_info(&self) -> TruthBackendInfo;
}

// ── InMemoryTruthBackend ───────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryTruthBackend {
    claims: HashMap<String, StoredClaim>,
    contradictions: HashMap<String, StoredContradictionRecord>,
    corroborations: HashMap<String, StoredCorroborationRecord>,
    retractions: HashMap<String, StoredRetractionRecord>,
}

impl InMemoryTruthBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TruthBackend for InMemoryTruthBackend {
    fn store_claim(&mut self, claim: StoredClaim) -> Result<(), TruthError> {
        if self.claims.contains_key(&claim.claim_id) {
            return Err(TruthError::InvalidOperation(format!("claim {} already exists", claim.claim_id)));
        }
        self.claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    fn retrieve_claim(&self, claim_id: &str) -> Result<Option<StoredClaim>, TruthError> {
        Ok(self.claims.get(claim_id).cloned())
    }

    fn delete_claim(&mut self, claim_id: &str) -> Result<(), TruthError> {
        self.claims.remove(claim_id)
            .ok_or_else(|| TruthError::InvalidOperation(format!("claim {claim_id} not found")))?;
        Ok(())
    }

    fn list_claims(&self) -> Result<Vec<StoredClaim>, TruthError> {
        Ok(self.claims.values().cloned().collect())
    }

    fn list_claims_about_subject(&self, subject_ref: &SubjectOfClaimRef) -> Result<Vec<StoredClaim>, TruthError> {
        Ok(self.claims.values().filter(|c| c.subject_of_claim_ref == *subject_ref).cloned().collect())
    }

    fn claim_count(&self) -> usize {
        self.claims.len()
    }

    fn store_contradiction_record(&mut self, record: StoredContradictionRecord) -> Result<(), TruthError> {
        if self.contradictions.contains_key(&record.record_id) {
            return Err(TruthError::InvalidOperation(format!("contradiction record {} already exists", record.record_id)));
        }
        self.contradictions.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_contradiction_record(&self, record_id: &str) -> Result<Option<StoredContradictionRecord>, TruthError> {
        Ok(self.contradictions.get(record_id).cloned())
    }

    fn list_contradictions_involving_claim(&self, claim_ref: &ClaimRef) -> Result<Vec<StoredContradictionRecord>, TruthError> {
        Ok(self.contradictions.values()
            .filter(|r| r.claim_a_ref == *claim_ref || r.claim_b_ref == *claim_ref)
            .cloned().collect())
    }

    fn store_corroboration_record(&mut self, record: StoredCorroborationRecord) -> Result<(), TruthError> {
        if self.corroborations.contains_key(&record.record_id) {
            return Err(TruthError::InvalidOperation(format!("corroboration record {} already exists", record.record_id)));
        }
        self.corroborations.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_corroboration_record(&self, record_id: &str) -> Result<Option<StoredCorroborationRecord>, TruthError> {
        Ok(self.corroborations.get(record_id).cloned())
    }

    fn list_corroborations_for_claim(&self, claim_ref: &ClaimRef) -> Result<Vec<StoredCorroborationRecord>, TruthError> {
        Ok(self.corroborations.values().filter(|r| r.claim_ref == *claim_ref).cloned().collect())
    }

    fn store_retraction_record(&mut self, record: StoredRetractionRecord) -> Result<(), TruthError> {
        if self.retractions.contains_key(&record.record_id) {
            return Err(TruthError::InvalidOperation(format!("retraction record {} already exists", record.record_id)));
        }
        self.retractions.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_retraction_record(&self, record_id: &str) -> Result<Option<StoredRetractionRecord>, TruthError> {
        Ok(self.retractions.get(record_id).cloned())
    }

    fn list_retractions_for_claim(&self, claim_ref: &ClaimRef) -> Result<Vec<StoredRetractionRecord>, TruthError> {
        Ok(self.retractions.values().filter(|r| r.claim_ref == *claim_ref).cloned().collect())
    }

    fn flush(&mut self) -> Result<(), TruthError> {
        self.claims.clear();
        self.contradictions.clear();
        self.corroborations.clear();
        self.retractions.clear();
        Ok(())
    }

    fn backend_info(&self) -> TruthBackendInfo {
        TruthBackendInfo {
            backend_name: "InMemoryTruthBackend".to_string(),
            claim_count: self.claims.len(),
            contradiction_record_count: self.contradictions.len(),
            corroboration_record_count: self.corroborations.len(),
            retraction_record_count: self.retractions.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claim(id: &str, subject: &str) -> StoredClaim {
        StoredClaim {
            claim_id: id.to_string(),
            subject_of_claim_ref: SubjectOfClaimRef::new(subject),
            claim_type: "factual-accuracy".to_string(),
            claim_body_bytes: b"test claim body".to_vec(),
            claimant: "alice".to_string(),
            asserted_at: 1000,
            confidence_score: "0.90".to_string(),
            evidence_attestation_refs: vec!["att-1".to_string()],
            retracted_at: None,
        }
    }

    fn make_contradiction(id: &str, a: &str, b: &str) -> StoredContradictionRecord {
        StoredContradictionRecord {
            record_id: id.to_string(),
            claim_a_ref: ClaimRef::new(a),
            claim_b_ref: ClaimRef::new(b),
            contradiction_type: "direct".to_string(),
            explanation: "contradictory values".to_string(),
            detected_at: 2000,
            resolved_at: None,
        }
    }

    fn make_corroboration(id: &str, claim: &str) -> StoredCorroborationRecord {
        StoredCorroborationRecord {
            record_id: id.to_string(),
            claim_ref: ClaimRef::new(claim),
            corroborating_claimant: "bob".to_string(),
            corroboration_detail: "confirmed independently".to_string(),
            recorded_at: 3000,
        }
    }

    fn make_retraction(id: &str, claim: &str) -> StoredRetractionRecord {
        StoredRetractionRecord {
            record_id: id.to_string(),
            claim_ref: ClaimRef::new(claim),
            retracted_by: "alice".to_string(),
            reason: "was incorrect".to_string(),
            retracted_at: 4000,
        }
    }

    #[test]
    fn test_store_and_retrieve_claim() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_claim(make_claim("c1", "art-1")).unwrap();
        let c = backend.retrieve_claim("c1").unwrap().unwrap();
        assert_eq!(c.claim_id, "c1");
        assert_eq!(c.claimant, "alice");
    }

    #[test]
    fn test_duplicate_claim_rejected() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_claim(make_claim("c1", "art-1")).unwrap();
        assert!(backend.store_claim(make_claim("c1", "art-1")).is_err());
    }

    #[test]
    fn test_delete_claim() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_claim(make_claim("c1", "art-1")).unwrap();
        backend.delete_claim("c1").unwrap();
        assert!(backend.retrieve_claim("c1").unwrap().is_none());
    }

    #[test]
    fn test_list_claims_about_subject() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_claim(make_claim("c1", "art-1")).unwrap();
        backend.store_claim(make_claim("c2", "art-1")).unwrap();
        backend.store_claim(make_claim("c3", "art-2")).unwrap();
        let list = backend.list_claims_about_subject(&SubjectOfClaimRef::new("art-1")).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_contradiction() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_contradiction_record(make_contradiction("cr1", "c1", "c2")).unwrap();
        let r = backend.retrieve_contradiction_record("cr1").unwrap().unwrap();
        assert_eq!(r.record_id, "cr1");
    }

    #[test]
    fn test_list_contradictions_involving_claim() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_contradiction_record(make_contradiction("cr1", "c1", "c2")).unwrap();
        backend.store_contradiction_record(make_contradiction("cr2", "c3", "c1")).unwrap();
        backend.store_contradiction_record(make_contradiction("cr3", "c4", "c5")).unwrap();
        let list = backend.list_contradictions_involving_claim(&ClaimRef::new("c1")).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_corroboration() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_corroboration_record(make_corroboration("co1", "c1")).unwrap();
        let r = backend.retrieve_corroboration_record("co1").unwrap().unwrap();
        assert_eq!(r.corroborating_claimant, "bob");
    }

    #[test]
    fn test_list_corroborations_for_claim() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_corroboration_record(make_corroboration("co1", "c1")).unwrap();
        backend.store_corroboration_record(make_corroboration("co2", "c1")).unwrap();
        backend.store_corroboration_record(make_corroboration("co3", "c2")).unwrap();
        let list = backend.list_corroborations_for_claim(&ClaimRef::new("c1")).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_retraction() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_retraction_record(make_retraction("rt1", "c1")).unwrap();
        let r = backend.retrieve_retraction_record("rt1").unwrap().unwrap();
        assert_eq!(r.retracted_by, "alice");
    }

    #[test]
    fn test_list_retractions_for_claim() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_retraction_record(make_retraction("rt1", "c1")).unwrap();
        backend.store_retraction_record(make_retraction("rt2", "c2")).unwrap();
        let list = backend.list_retractions_for_claim(&ClaimRef::new("c1")).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_claim(make_claim("c1", "art-1")).unwrap();
        backend.store_contradiction_record(make_contradiction("cr1", "c1", "c2")).unwrap();
        backend.flush().unwrap();
        let info = backend.backend_info();
        assert_eq!(info.claim_count, 0);
        assert_eq!(info.contradiction_record_count, 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryTruthBackend::new();
        backend.store_claim(make_claim("c1", "art-1")).unwrap();
        backend.store_contradiction_record(make_contradiction("cr1", "c1", "c2")).unwrap();
        backend.store_corroboration_record(make_corroboration("co1", "c1")).unwrap();
        backend.store_retraction_record(make_retraction("rt1", "c1")).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.claim_count, 1);
        assert_eq!(info.contradiction_record_count, 1);
        assert_eq!(info.corroboration_record_count, 1);
        assert_eq!(info.retraction_record_count, 1);
    }

    #[test]
    fn test_claim_ref_display() {
        let cr = ClaimRef::new("claim-42");
        assert_eq!(cr.to_string(), "claim-42");
    }

    #[test]
    fn test_subject_of_claim_ref_display() {
        let sr = SubjectOfClaimRef::new("artifact-7");
        assert_eq!(sr.to_string(), "artifact-7");
    }
}
