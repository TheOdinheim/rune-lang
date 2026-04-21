// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — ComplianceEvidenceLinker trait for bridging framework
// requirements to evidence stored in rune-document, rune-audit-ext,
// and external systems via opaque artifact references.
// ═══════════���═════════════��════════════════════════════════════��════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::backend::ComplianceEvidenceType;
use crate::error::FrameworkError;

// ── EvidenceFreshness ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceFreshness {
    Current,
    ExpiringSoon { expires_at: i64 },
    Expired { expired_at: i64 },
    NoExpiration,
    Unknown,
}

impl std::fmt::Display for EvidenceFreshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => f.write_str("Current"),
            Self::ExpiringSoon { expires_at } => write!(f, "ExpiringSoon(at {expires_at})"),
            Self::Expired { expired_at } => write!(f, "Expired(at {expired_at})"),
            Self::NoExpiration => f.write_str("NoExpiration"),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

// ── EvidenceReviewVerdict ─────────���──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceReviewVerdict {
    Adequate,
    Inadequate,
    NeedsUpdate,
}

impl std::fmt::Display for EvidenceReviewVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adequate => f.write_str("Adequate"),
            Self::Inadequate => f.write_str("Inadequate"),
            Self::NeedsUpdate => f.write_str("NeedsUpdate"),
        }
    }
}

// ── EvidenceReview ────────────���──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReview {
    pub reviewer_id: String,
    pub reviewed_at: i64,
    pub verdict: EvidenceReviewVerdict,
    pub notes: String,
}

// ── EvidenceLink ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub link_id: String,
    pub requirement_id: String,
    pub evidence_artifact_ref: String,
    pub evidence_type: ComplianceEvidenceType,
    pub linked_at: i64,
    pub linked_by: String,
    pub expires_at: Option<i64>,
    pub review_history: Vec<EvidenceReview>,
}

// ── ComplianceEvidenceLinker trait ────────────────────────────────────

pub trait ComplianceEvidenceLinker {
    fn link_evidence(&mut self, link: EvidenceLink) -> Result<(), FrameworkError>;

    fn unlink_evidence(&mut self, link_id: &str) -> Result<(), FrameworkError>;

    fn list_evidence_for_requirement(&self, requirement_id: &str) -> Vec<&EvidenceLink>;

    fn list_requirements_for_evidence(&self, evidence_artifact_ref: &str) -> Vec<&EvidenceLink>;

    fn check_evidence_freshness(
        &self,
        link_id: &str,
        now: i64,
        expiry_warning_threshold: i64,
    ) -> EvidenceFreshness;

    fn record_evidence_review(
        &mut self,
        link_id: &str,
        review: EvidenceReview,
    ) -> Result<(), FrameworkError>;

    fn linker_id(&self) -> &str;

    fn is_active(&self) -> bool;
}

// ── InMemoryComplianceEvidenceLinker ─────��────────────────────────────

pub struct InMemoryComplianceEvidenceLinker {
    id: String,
    links: HashMap<String, EvidenceLink>,
}

impl InMemoryComplianceEvidenceLinker {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            links: HashMap::new(),
        }
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }
}

impl ComplianceEvidenceLinker for InMemoryComplianceEvidenceLinker {
    fn link_evidence(&mut self, link: EvidenceLink) -> Result<(), FrameworkError> {
        self.links.insert(link.link_id.clone(), link);
        Ok(())
    }

    fn unlink_evidence(&mut self, link_id: &str) -> Result<(), FrameworkError> {
        self.links.remove(link_id).ok_or_else(|| {
            FrameworkError::ComponentNotFound {
                component_id: link_id.to_string(),
            }
        })?;
        Ok(())
    }

    fn list_evidence_for_requirement(&self, requirement_id: &str) -> Vec<&EvidenceLink> {
        self.links
            .values()
            .filter(|l| l.requirement_id == requirement_id)
            .collect()
    }

    fn list_requirements_for_evidence(&self, evidence_artifact_ref: &str) -> Vec<&EvidenceLink> {
        self.links
            .values()
            .filter(|l| l.evidence_artifact_ref == evidence_artifact_ref)
            .collect()
    }

    fn check_evidence_freshness(
        &self,
        link_id: &str,
        now: i64,
        expiry_warning_threshold: i64,
    ) -> EvidenceFreshness {
        let Some(link) = self.links.get(link_id) else {
            return EvidenceFreshness::Unknown;
        };
        match link.expires_at {
            None => EvidenceFreshness::NoExpiration,
            Some(expires_at) => {
                if now >= expires_at {
                    EvidenceFreshness::Expired {
                        expired_at: expires_at,
                    }
                } else if expires_at - now <= expiry_warning_threshold {
                    EvidenceFreshness::ExpiringSoon { expires_at }
                } else {
                    EvidenceFreshness::Current
                }
            }
        }
    }

    fn record_evidence_review(
        &mut self,
        link_id: &str,
        review: EvidenceReview,
    ) -> Result<(), FrameworkError> {
        let link = self.links.get_mut(link_id).ok_or_else(|| {
            FrameworkError::ComponentNotFound {
                component_id: link_id.to_string(),
            }
        })?;
        link.review_history.push(review);
        Ok(())
    }

    fn linker_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── FreshnessAwareComplianceEvidenceLinker ────────────────────────────

pub struct FreshnessAwareComplianceEvidenceLinker<L: ComplianceEvidenceLinker> {
    inner: L,
    now_fn: fn() -> i64,
}

impl<L: ComplianceEvidenceLinker> FreshnessAwareComplianceEvidenceLinker<L> {
    pub fn new(inner: L, now_fn: fn() -> i64) -> Self {
        Self { inner, now_fn }
    }
}

impl<L: ComplianceEvidenceLinker> ComplianceEvidenceLinker
    for FreshnessAwareComplianceEvidenceLinker<L>
{
    fn link_evidence(&mut self, link: EvidenceLink) -> Result<(), FrameworkError> {
        let now = (self.now_fn)();
        if let Some(expires_at) = link.expires_at {
            if now >= expires_at {
                return Err(FrameworkError::InvalidConfiguration {
                    field: "expires_at".to_string(),
                    reason: "cannot link already-expired evidence".to_string(),
                });
            }
        }
        self.inner.link_evidence(link)
    }

    fn unlink_evidence(&mut self, link_id: &str) -> Result<(), FrameworkError> {
        self.inner.unlink_evidence(link_id)
    }

    fn list_evidence_for_requirement(&self, requirement_id: &str) -> Vec<&EvidenceLink> {
        self.inner.list_evidence_for_requirement(requirement_id)
    }

    fn list_requirements_for_evidence(&self, evidence_artifact_ref: &str) -> Vec<&EvidenceLink> {
        self.inner
            .list_requirements_for_evidence(evidence_artifact_ref)
    }

    fn check_evidence_freshness(
        &self,
        link_id: &str,
        now: i64,
        expiry_warning_threshold: i64,
    ) -> EvidenceFreshness {
        self.inner
            .check_evidence_freshness(link_id, now, expiry_warning_threshold)
    }

    fn record_evidence_review(
        &mut self,
        link_id: &str,
        review: EvidenceReview,
    ) -> Result<(), FrameworkError> {
        self.inner.record_evidence_review(link_id, review)
    }

    fn linker_id(&self) -> &str {
        self.inner.linker_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullComplianceEvidenceLinker ───────���─────────────────────────────

pub struct NullComplianceEvidenceLinker;

impl NullComplianceEvidenceLinker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullComplianceEvidenceLinker {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceEvidenceLinker for NullComplianceEvidenceLinker {
    fn link_evidence(&mut self, _: EvidenceLink) -> Result<(), FrameworkError> {
        Ok(())
    }
    fn unlink_evidence(&mut self, _: &str) -> Result<(), FrameworkError> {
        Ok(())
    }
    fn list_evidence_for_requirement(&self, _: &str) -> Vec<&EvidenceLink> {
        vec![]
    }
    fn list_requirements_for_evidence(&self, _: &str) -> Vec<&EvidenceLink> {
        vec![]
    }
    fn check_evidence_freshness(&self, _: &str, _: i64, _: i64) -> EvidenceFreshness {
        EvidenceFreshness::Unknown
    }
    fn record_evidence_review(&mut self, _: &str, _: EvidenceReview) -> Result<(), FrameworkError> {
        Ok(())
    }
    fn linker_id(&self) -> &str {
        "null"
    }
    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ════════��═════════════════════════════���════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_link(id: &str, req_id: &str, expires: Option<i64>) -> EvidenceLink {
        EvidenceLink {
            link_id: id.to_string(),
            requirement_id: req_id.to_string(),
            evidence_artifact_ref: format!("doc://{id}"),
            evidence_type: ComplianceEvidenceType::PolicyDocument,
            linked_at: 1000,
            linked_by: "tester".to_string(),
            expires_at: expires,
            review_history: vec![],
        }
    }

    #[test]
    fn test_link_and_unlink() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", None)).unwrap();
        assert_eq!(linker.link_count(), 1);
        linker.unlink_evidence("l-1").unwrap();
        assert_eq!(linker.link_count(), 0);
        assert!(linker.unlink_evidence("l-1").is_err());
    }

    #[test]
    fn test_list_for_requirement() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", None)).unwrap();
        linker.link_evidence(test_link("l-2", "req-1", None)).unwrap();
        linker.link_evidence(test_link("l-3", "req-2", None)).unwrap();
        assert_eq!(linker.list_evidence_for_requirement("req-1").len(), 2);
        assert_eq!(linker.list_evidence_for_requirement("req-2").len(), 1);
    }

    #[test]
    fn test_list_requirements_for_evidence() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        let mut link = test_link("l-1", "req-1", None);
        link.evidence_artifact_ref = "doc://shared".to_string();
        linker.link_evidence(link).unwrap();
        let mut link2 = test_link("l-2", "req-2", None);
        link2.evidence_artifact_ref = "doc://shared".to_string();
        linker.link_evidence(link2).unwrap();
        assert_eq!(linker.list_requirements_for_evidence("doc://shared").len(), 2);
    }

    #[test]
    fn test_freshness_current() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", Some(5000))).unwrap();
        let freshness = linker.check_evidence_freshness("l-1", 1000, 1000);
        assert_eq!(freshness, EvidenceFreshness::Current);
    }

    #[test]
    fn test_freshness_expiring_soon() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", Some(1500))).unwrap();
        let freshness = linker.check_evidence_freshness("l-1", 1000, 1000);
        assert_eq!(
            freshness,
            EvidenceFreshness::ExpiringSoon { expires_at: 1500 }
        );
    }

    #[test]
    fn test_freshness_expired() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", Some(500))).unwrap();
        let freshness = linker.check_evidence_freshness("l-1", 1000, 1000);
        assert_eq!(freshness, EvidenceFreshness::Expired { expired_at: 500 });
    }

    #[test]
    fn test_freshness_no_expiration() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", None)).unwrap();
        let freshness = linker.check_evidence_freshness("l-1", 1000, 1000);
        assert_eq!(freshness, EvidenceFreshness::NoExpiration);
    }

    #[test]
    fn test_freshness_unknown() {
        let linker = InMemoryComplianceEvidenceLinker::new("test");
        assert_eq!(
            linker.check_evidence_freshness("nonexistent", 1000, 1000),
            EvidenceFreshness::Unknown
        );
    }

    #[test]
    fn test_record_review() {
        let mut linker = InMemoryComplianceEvidenceLinker::new("test");
        linker.link_evidence(test_link("l-1", "req-1", None)).unwrap();
        linker
            .record_evidence_review(
                "l-1",
                EvidenceReview {
                    reviewer_id: "alice".to_string(),
                    reviewed_at: 2000,
                    verdict: EvidenceReviewVerdict::Adequate,
                    notes: "looks good".to_string(),
                },
            )
            .unwrap();
        let links = linker.list_evidence_for_requirement("req-1");
        assert_eq!(links[0].review_history.len(), 1);
        assert_eq!(links[0].review_history[0].verdict, EvidenceReviewVerdict::Adequate);
    }

    #[test]
    fn test_freshness_aware_rejects_expired() {
        fn now() -> i64 {
            2000
        }
        let inner = InMemoryComplianceEvidenceLinker::new("test");
        let mut linker = FreshnessAwareComplianceEvidenceLinker::new(inner, now);
        // expires_at=1000 < now=2000 → reject
        assert!(linker.link_evidence(test_link("l-1", "req-1", Some(1000))).is_err());
        // expires_at=3000 > now=2000 → accept
        assert!(linker.link_evidence(test_link("l-2", "req-1", Some(3000))).is_ok());
        // no expiration → accept
        assert!(linker.link_evidence(test_link("l-3", "req-1", None)).is_ok());
    }

    #[test]
    fn test_null_linker() {
        let mut linker = NullComplianceEvidenceLinker::new();
        assert!(!linker.is_active());
        assert!(linker.link_evidence(test_link("l-1", "req-1", None)).is_ok());
        assert!(linker.list_evidence_for_requirement("req-1").is_empty());
    }

    #[test]
    fn test_evidence_freshness_display() {
        assert_eq!(EvidenceFreshness::Current.to_string(), "Current");
        assert_eq!(EvidenceFreshness::Unknown.to_string(), "Unknown");
        assert!(EvidenceFreshness::Expired { expired_at: 100 }.to_string().contains("100"));
    }
}
