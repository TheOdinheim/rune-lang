// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Document retention automation.
//
// Retention policies with category-based applicability, legal hold
// management, expiration tracking, and disposal enforcement.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::classification::DocumentCategory;
use crate::error::DocumentError;

// ── DisposalMethod ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisposalMethod {
    Delete,
    Archive,
    Anonymize,
    Review,
}

impl fmt::Display for DisposalMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delete => f.write_str("delete"),
            Self::Archive => f.write_str("archive"),
            Self::Anonymize => f.write_str("anonymize"),
            Self::Review => f.write_str("review"),
        }
    }
}

// ── RetentionPolicy ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub policy_id: String,
    pub name: String,
    pub retention_period_ms: i64,
    pub applies_to: Vec<DocumentCategory>,
    pub disposal_method: DisposalMethod,
    pub legal_basis: String,
}

impl RetentionPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        name: impl Into<String>,
        retention_period_ms: i64,
        disposal_method: DisposalMethod,
        legal_basis: impl Into<String>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            name: name.into(),
            retention_period_ms,
            applies_to: Vec::new(),
            disposal_method,
            legal_basis: legal_basis.into(),
        }
    }

    pub fn with_category(mut self, cat: DocumentCategory) -> Self {
        self.applies_to.push(cat);
        self
    }
}

// ── LegalHold ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LegalHold {
    pub hold_id: String,
    pub reason: String,
    pub placed_by: String,
    pub placed_at: i64,
    pub released_at: Option<i64>,
}

// ── DocumentRetentionRecord ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DocumentRetentionRecord {
    pub doc_id: String,
    pub policy_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub disposed_at: Option<i64>,
    pub disposal_method: Option<DisposalMethod>,
    pub on_legal_hold: bool,
}

// ── RetentionTracker ────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct RetentionTracker {
    pub policies: Vec<RetentionPolicy>,
    pub document_retention: HashMap<String, DocumentRetentionRecord>,
    pub legal_holds: HashMap<String, LegalHold>,
}

impl RetentionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: RetentionPolicy) {
        self.policies.push(policy);
    }

    pub fn track_document(
        &mut self,
        doc_id: &str,
        policy_id: &str,
        created_at: i64,
    ) -> Result<(), DocumentError> {
        let policy = self
            .policies
            .iter()
            .find(|p| p.policy_id == policy_id)
            .ok_or_else(|| {
                DocumentError::InvalidOperation(format!("Policy not found: {policy_id}"))
            })?;

        let expires_at = created_at + policy.retention_period_ms;

        self.document_retention.insert(
            doc_id.into(),
            DocumentRetentionRecord {
                doc_id: doc_id.into(),
                policy_id: policy_id.into(),
                created_at,
                expires_at,
                disposed_at: None,
                disposal_method: None,
                on_legal_hold: false,
            },
        );
        Ok(())
    }

    pub fn expired_documents(&self, now: i64) -> Vec<&DocumentRetentionRecord> {
        self.document_retention
            .values()
            .filter(|r| r.expires_at <= now && !r.on_legal_hold && r.disposed_at.is_none())
            .collect()
    }

    pub fn place_legal_hold(
        &mut self,
        doc_id: &str,
        hold_id: &str,
        reason: &str,
        by: &str,
        now: i64,
    ) -> bool {
        if let Some(record) = self.document_retention.get_mut(doc_id) {
            record.on_legal_hold = true;
            self.legal_holds.insert(
                doc_id.into(),
                LegalHold {
                    hold_id: hold_id.into(),
                    reason: reason.into(),
                    placed_by: by.into(),
                    placed_at: now,
                    released_at: None,
                },
            );
            true
        } else {
            false
        }
    }

    pub fn release_legal_hold(&mut self, doc_id: &str, now: i64) -> bool {
        if let Some(hold) = self.legal_holds.get_mut(doc_id) {
            hold.released_at = Some(now);
            if let Some(record) = self.document_retention.get_mut(doc_id) {
                record.on_legal_hold = false;
            }
            true
        } else {
            false
        }
    }

    pub fn is_on_hold(&self, doc_id: &str) -> bool {
        self.document_retention
            .get(doc_id)
            .is_some_and(|r| r.on_legal_hold)
    }

    pub fn dispose_document(
        &mut self,
        doc_id: &str,
        method: DisposalMethod,
        now: i64,
    ) -> Result<(), DocumentError> {
        let record = self
            .document_retention
            .get_mut(doc_id)
            .ok_or_else(|| DocumentError::DocumentNotFound(doc_id.into()))?;

        if record.on_legal_hold {
            return Err(DocumentError::InvalidOperation(
                "Cannot dispose document on legal hold".into(),
            ));
        }

        if record.expires_at > now {
            return Err(DocumentError::InvalidOperation(
                "Document has not expired yet".into(),
            ));
        }

        record.disposed_at = Some(now);
        record.disposal_method = Some(method);
        Ok(())
    }

    pub fn pending_disposal_count(&self, now: i64) -> usize {
        self.expired_documents(now).len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_tracker() -> RetentionTracker {
        let mut tracker = RetentionTracker::new();
        tracker.add_policy(
            RetentionPolicy::new("p1", "Standard Retention", 10000, DisposalMethod::Archive, "GDPR Art. 5(1)(e)")
                .with_category(DocumentCategory::PersonalData),
        );
        tracker
    }

    #[test]
    fn test_track_document() {
        let mut tracker = setup_tracker();
        assert!(tracker.track_document("doc1", "p1", 1000).is_ok());
        let record = tracker.document_retention.get("doc1").unwrap();
        assert_eq!(record.expires_at, 11000);
    }

    #[test]
    fn test_expired_documents() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        tracker.track_document("doc2", "p1", 5000).unwrap();
        let expired = tracker.expired_documents(12000);
        assert_eq!(expired.len(), 1); // doc1 expired, doc2 not yet
    }

    #[test]
    fn test_expired_excludes_legal_holds() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        tracker.place_legal_hold("doc1", "hold1", "litigation", "legal", 5000);
        let expired = tracker.expired_documents(20000);
        assert!(expired.is_empty()); // on hold, not shown as expired
    }

    #[test]
    fn test_place_legal_hold() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        assert!(tracker.place_legal_hold("doc1", "hold1", "litigation", "legal", 5000));
        assert!(tracker.is_on_hold("doc1"));
    }

    #[test]
    fn test_release_legal_hold() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        tracker.place_legal_hold("doc1", "hold1", "litigation", "legal", 5000);
        assert!(tracker.release_legal_hold("doc1", 8000));
        assert!(!tracker.is_on_hold("doc1"));
    }

    #[test]
    fn test_dispose_document_succeeds() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        assert!(tracker
            .dispose_document("doc1", DisposalMethod::Archive, 20000)
            .is_ok());
        let record = tracker.document_retention.get("doc1").unwrap();
        assert!(record.disposed_at.is_some());
        assert_eq!(record.disposal_method, Some(DisposalMethod::Archive));
    }

    #[test]
    fn test_dispose_fails_on_legal_hold() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        tracker.place_legal_hold("doc1", "hold1", "litigation", "legal", 5000);
        let result = tracker.dispose_document("doc1", DisposalMethod::Delete, 20000);
        assert!(result.is_err());
    }

    #[test]
    fn test_pending_disposal_count() {
        let mut tracker = setup_tracker();
        tracker.track_document("doc1", "p1", 1000).unwrap();
        tracker.track_document("doc2", "p1", 1000).unwrap();
        assert_eq!(tracker.pending_disposal_count(20000), 2);
        tracker
            .dispose_document("doc1", DisposalMethod::Archive, 20000)
            .unwrap();
        assert_eq!(tracker.pending_disposal_count(20000), 1);
    }

    #[test]
    fn test_retention_policy_applies_to() {
        let policy = RetentionPolicy::new("p1", "Test", 10000, DisposalMethod::Delete, "legal")
            .with_category(DocumentCategory::PersonalData)
            .with_category(DocumentCategory::HealthData);
        assert_eq!(policy.applies_to.len(), 2);
    }
}
