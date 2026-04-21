// ═══════════════════════════════════════════════════════════════════════
// Evidence Linker — Links claims to attestation evidence and assesses
// whether the evidence backing a claim is adequate.
//
// Claims reference evidence via opaque string attestation_refs, which
// are IDs into the rune-provenance StoredAttestation table.  This
// module does NOT depend on rune-provenance types directly — it works
// with string IDs so that the coupling remains loose and the truth
// layer can be tested independently.
//
// AdequacyAssessment is a three-variant enum (Adequate / Inadequate /
// NotAssessable) rather than a boolean, because many claim types have
// no meaningful adequacy criteria and returning Inadequate for those
// would be misleading.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::TruthError;

// ── AdequacyAssessment ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdequacyAssessment {
    Adequate { linked_count: usize, policy_name: String },
    Inadequate { reason: String, linked_count: usize, required: usize },
    NotAssessable { reason: String },
}

impl AdequacyAssessment {
    pub fn is_adequate(&self) -> bool {
        matches!(self, Self::Adequate { .. })
    }

    pub fn is_inadequate(&self) -> bool {
        matches!(self, Self::Inadequate { .. })
    }
}

impl fmt::Display for AdequacyAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adequate { linked_count, policy_name } => {
                write!(f, "Adequate({linked_count} links, policy={policy_name})")
            }
            Self::Inadequate { reason, linked_count, required } => {
                write!(f, "Inadequate({reason}, {linked_count}/{required})")
            }
            Self::NotAssessable { reason } => write!(f, "NotAssessable({reason})"),
        }
    }
}

// ── EvidenceAdequacyPolicy ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceAdequacyPolicy {
    pub policy_name: String,
    pub min_evidence_count: usize,
    pub require_distinct_sources: bool,
}

impl EvidenceAdequacyPolicy {
    pub fn new(name: &str, min_count: usize) -> Self {
        Self {
            policy_name: name.to_string(),
            min_evidence_count: min_count,
            require_distinct_sources: false,
        }
    }

    pub fn with_distinct_sources(mut self) -> Self {
        self.require_distinct_sources = true;
        self
    }
}

// ── EvidenceLink ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLink {
    pub claim_id: String,
    pub attestation_ref: String,
    pub linked_at: i64,
    pub linked_by: String,
}

// ── EvidenceLinker trait ──────────────────────────────────────────

pub trait EvidenceLinker {
    fn link_evidence(
        &mut self,
        claim_id: &str,
        attestation_ref: &str,
        linked_by: &str,
        timestamp: i64,
    ) -> Result<(), TruthError>;

    fn unlink_evidence(
        &mut self,
        claim_id: &str,
        attestation_ref: &str,
    ) -> Result<(), TruthError>;

    fn list_evidence_for_claim(
        &self,
        claim_id: &str,
    ) -> Result<Vec<EvidenceLink>, TruthError>;

    fn assess_evidence_adequacy(
        &self,
        claim_id: &str,
        policy: &EvidenceAdequacyPolicy,
    ) -> Result<AdequacyAssessment, TruthError>;

    fn linker_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryEvidenceLinker ────────────────────────────────────────

pub struct InMemoryEvidenceLinker {
    id: String,
    links: HashMap<String, Vec<EvidenceLink>>,
}

impl InMemoryEvidenceLinker {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            links: HashMap::new(),
        }
    }
}

impl EvidenceLinker for InMemoryEvidenceLinker {
    fn link_evidence(
        &mut self,
        claim_id: &str,
        attestation_ref: &str,
        linked_by: &str,
        timestamp: i64,
    ) -> Result<(), TruthError> {
        let links = self.links.entry(claim_id.to_string()).or_default();

        // Prevent duplicate links
        if links.iter().any(|l| l.attestation_ref == attestation_ref) {
            return Err(TruthError::InvalidOperation(format!(
                "evidence {attestation_ref} already linked to claim {claim_id}"
            )));
        }

        links.push(EvidenceLink {
            claim_id: claim_id.to_string(),
            attestation_ref: attestation_ref.to_string(),
            linked_at: timestamp,
            linked_by: linked_by.to_string(),
        });
        Ok(())
    }

    fn unlink_evidence(
        &mut self,
        claim_id: &str,
        attestation_ref: &str,
    ) -> Result<(), TruthError> {
        let links = self.links.get_mut(claim_id).ok_or_else(|| {
            TruthError::ClaimNotFound(claim_id.to_string())
        })?;

        let before = links.len();
        links.retain(|l| l.attestation_ref != attestation_ref);
        if links.len() == before {
            return Err(TruthError::InvalidOperation(format!(
                "evidence {attestation_ref} not linked to claim {claim_id}"
            )));
        }
        Ok(())
    }

    fn list_evidence_for_claim(
        &self,
        claim_id: &str,
    ) -> Result<Vec<EvidenceLink>, TruthError> {
        Ok(self.links.get(claim_id).cloned().unwrap_or_default())
    }

    fn assess_evidence_adequacy(
        &self,
        claim_id: &str,
        policy: &EvidenceAdequacyPolicy,
    ) -> Result<AdequacyAssessment, TruthError> {
        let links = self.links.get(claim_id).cloned().unwrap_or_default();
        let count = links.len();

        if count >= policy.min_evidence_count {
            Ok(AdequacyAssessment::Adequate {
                linked_count: count,
                policy_name: policy.policy_name.clone(),
            })
        } else {
            Ok(AdequacyAssessment::Inadequate {
                reason: format!(
                    "only {count} evidence links, policy requires {}",
                    policy.min_evidence_count
                ),
                linked_count: count,
                required: policy.min_evidence_count,
            })
        }
    }

    fn linker_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── CountBasedEvidenceLinker ──────────────────────────────────────
// Delegates storage to InMemoryEvidenceLinker but applies a maximum
// link count per claim.

pub struct CountBasedEvidenceLinker {
    inner: InMemoryEvidenceLinker,
    max_links_per_claim: usize,
}

impl CountBasedEvidenceLinker {
    pub fn new(id: &str, max_links: usize) -> Self {
        Self {
            inner: InMemoryEvidenceLinker::new(id),
            max_links_per_claim: max_links,
        }
    }
}

impl EvidenceLinker for CountBasedEvidenceLinker {
    fn link_evidence(
        &mut self,
        claim_id: &str,
        attestation_ref: &str,
        linked_by: &str,
        timestamp: i64,
    ) -> Result<(), TruthError> {
        let current = self.inner.list_evidence_for_claim(claim_id)?.len();
        if current >= self.max_links_per_claim {
            return Err(TruthError::InvalidOperation(format!(
                "claim {claim_id} already has {current} links (max {})",
                self.max_links_per_claim
            )));
        }
        self.inner.link_evidence(claim_id, attestation_ref, linked_by, timestamp)
    }

    fn unlink_evidence(&mut self, claim_id: &str, attestation_ref: &str) -> Result<(), TruthError> {
        self.inner.unlink_evidence(claim_id, attestation_ref)
    }

    fn list_evidence_for_claim(&self, claim_id: &str) -> Result<Vec<EvidenceLink>, TruthError> {
        self.inner.list_evidence_for_claim(claim_id)
    }

    fn assess_evidence_adequacy(
        &self,
        claim_id: &str,
        policy: &EvidenceAdequacyPolicy,
    ) -> Result<AdequacyAssessment, TruthError> {
        self.inner.assess_evidence_adequacy(claim_id, policy)
    }

    fn linker_id(&self) -> &str { self.inner.linker_id() }
    fn is_active(&self) -> bool { true }
}

// ── DiversityAwareEvidenceLinker ──────────────────────────────────
// Wraps InMemoryEvidenceLinker and adds distinct-source awareness to
// adequacy assessment.

pub struct DiversityAwareEvidenceLinker {
    inner: InMemoryEvidenceLinker,
}

impl DiversityAwareEvidenceLinker {
    pub fn new(id: &str) -> Self {
        Self {
            inner: InMemoryEvidenceLinker::new(id),
        }
    }
}

impl EvidenceLinker for DiversityAwareEvidenceLinker {
    fn link_evidence(
        &mut self,
        claim_id: &str,
        attestation_ref: &str,
        linked_by: &str,
        timestamp: i64,
    ) -> Result<(), TruthError> {
        self.inner.link_evidence(claim_id, attestation_ref, linked_by, timestamp)
    }

    fn unlink_evidence(&mut self, claim_id: &str, attestation_ref: &str) -> Result<(), TruthError> {
        self.inner.unlink_evidence(claim_id, attestation_ref)
    }

    fn list_evidence_for_claim(&self, claim_id: &str) -> Result<Vec<EvidenceLink>, TruthError> {
        self.inner.list_evidence_for_claim(claim_id)
    }

    fn assess_evidence_adequacy(
        &self,
        claim_id: &str,
        policy: &EvidenceAdequacyPolicy,
    ) -> Result<AdequacyAssessment, TruthError> {
        let links = self.inner.list_evidence_for_claim(claim_id)?;
        let count = links.len();

        if policy.require_distinct_sources {
            let distinct: std::collections::HashSet<&str> =
                links.iter().map(|l| l.linked_by.as_str()).collect();
            let distinct_count = distinct.len();

            if distinct_count < policy.min_evidence_count {
                return Ok(AdequacyAssessment::Inadequate {
                    reason: format!(
                        "only {distinct_count} distinct sources, policy requires {}",
                        policy.min_evidence_count
                    ),
                    linked_count: count,
                    required: policy.min_evidence_count,
                });
            }
            return Ok(AdequacyAssessment::Adequate {
                linked_count: count,
                policy_name: policy.policy_name.clone(),
            });
        }

        self.inner.assess_evidence_adequacy(claim_id, policy)
    }

    fn linker_id(&self) -> &str { self.inner.linker_id() }
    fn is_active(&self) -> bool { true }
}

// ── NullEvidenceLinker ────────────────────────────────────────────

pub struct NullEvidenceLinker {
    id: String,
}

impl NullEvidenceLinker {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl EvidenceLinker for NullEvidenceLinker {
    fn link_evidence(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<(), TruthError> {
        Ok(())
    }

    fn unlink_evidence(&mut self, _: &str, _: &str) -> Result<(), TruthError> {
        Ok(())
    }

    fn list_evidence_for_claim(&self, _: &str) -> Result<Vec<EvidenceLink>, TruthError> {
        Ok(Vec::new())
    }

    fn assess_evidence_adequacy(
        &self,
        _: &str,
        _: &EvidenceAdequacyPolicy,
    ) -> Result<AdequacyAssessment, TruthError> {
        Ok(AdequacyAssessment::NotAssessable {
            reason: "null linker does not track evidence".to_string(),
        })
    }

    fn linker_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_and_list() {
        let mut linker = InMemoryEvidenceLinker::new("el-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        linker.link_evidence("c1", "att-2", "bob", 1001).unwrap();

        let links = linker.list_evidence_for_claim("c1").unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].attestation_ref, "att-1");
    }

    #[test]
    fn test_duplicate_link_rejected() {
        let mut linker = InMemoryEvidenceLinker::new("el-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        assert!(linker.link_evidence("c1", "att-1", "alice", 1001).is_err());
    }

    #[test]
    fn test_unlink() {
        let mut linker = InMemoryEvidenceLinker::new("el-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        linker.unlink_evidence("c1", "att-1").unwrap();
        assert!(linker.list_evidence_for_claim("c1").unwrap().is_empty());
    }

    #[test]
    fn test_unlink_nonexistent() {
        let mut linker = InMemoryEvidenceLinker::new("el-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        assert!(linker.unlink_evidence("c1", "att-999").is_err());
    }

    #[test]
    fn test_adequacy_adequate() {
        let mut linker = InMemoryEvidenceLinker::new("el-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        linker.link_evidence("c1", "att-2", "bob", 1001).unwrap();

        let policy = EvidenceAdequacyPolicy::new("min-2", 2);
        let result = linker.assess_evidence_adequacy("c1", &policy).unwrap();
        assert!(result.is_adequate());
    }

    #[test]
    fn test_adequacy_inadequate() {
        let mut linker = InMemoryEvidenceLinker::new("el-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();

        let policy = EvidenceAdequacyPolicy::new("min-3", 3);
        let result = linker.assess_evidence_adequacy("c1", &policy).unwrap();
        assert!(result.is_inadequate());
    }

    #[test]
    fn test_count_based_max_links() {
        let mut linker = CountBasedEvidenceLinker::new("cb-1", 2);
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        linker.link_evidence("c1", "att-2", "bob", 1001).unwrap();
        assert!(linker.link_evidence("c1", "att-3", "carol", 1002).is_err());
    }

    #[test]
    fn test_diversity_aware_distinct_sources() {
        let mut linker = DiversityAwareEvidenceLinker::new("da-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        linker.link_evidence("c1", "att-2", "alice", 1001).unwrap(); // same source

        let policy = EvidenceAdequacyPolicy::new("diverse-2", 2).with_distinct_sources();
        let result = linker.assess_evidence_adequacy("c1", &policy).unwrap();
        assert!(result.is_inadequate());
    }

    #[test]
    fn test_diversity_aware_adequate_with_distinct() {
        let mut linker = DiversityAwareEvidenceLinker::new("da-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        linker.link_evidence("c1", "att-2", "bob", 1001).unwrap();

        let policy = EvidenceAdequacyPolicy::new("diverse-2", 2).with_distinct_sources();
        let result = linker.assess_evidence_adequacy("c1", &policy).unwrap();
        assert!(result.is_adequate());
    }

    #[test]
    fn test_null_linker() {
        let mut linker = NullEvidenceLinker::new("null-1");
        linker.link_evidence("c1", "att-1", "alice", 1000).unwrap();
        assert!(linker.list_evidence_for_claim("c1").unwrap().is_empty());
        assert!(!linker.is_active());
    }

    #[test]
    fn test_adequacy_display() {
        let a = AdequacyAssessment::Adequate { linked_count: 3, policy_name: "p".into() };
        assert!(a.to_string().contains("Adequate"));

        let b = AdequacyAssessment::Inadequate { reason: "few".into(), linked_count: 1, required: 3 };
        assert!(b.to_string().contains("few"));

        let c = AdequacyAssessment::NotAssessable { reason: "n/a".into() };
        assert!(c.to_string().contains("NotAssessable"));
    }

    #[test]
    fn test_linker_metadata() {
        let linker = InMemoryEvidenceLinker::new("el-1");
        assert_eq!(linker.linker_id(), "el-1");
        assert!(linker.is_active());
    }

    #[test]
    fn test_list_empty_claim() {
        let linker = InMemoryEvidenceLinker::new("el-1");
        let links = linker.list_evidence_for_claim("nonexistent").unwrap();
        assert!(links.is_empty());
    }
}
