// ═══════════════════════════════════════════════════════════════════════
// Retention Policy Linker — Layer 3 trait boundary for connecting
// document lifecycle to retention policies managed by external systems.
//
// Re-uses DisposalMethod from the L2 retention module.
// The linker trait provides an integration seam: concrete policy stores
// (S3 Object Lock / WORM, database-backed schedulers) live in adapter
// crates.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::DocumentError;
use crate::retention::DisposalMethod;

// ── DisposalEligibility ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisposalEligibility {
    Eligible,
    NotYetEligible { earliest_disposal_at: String },
    OnLegalHold { hold_reason: String },
    Indeterminate { reason: String },
}

impl fmt::Display for DisposalEligibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eligible => f.write_str("eligible"),
            Self::NotYetEligible { earliest_disposal_at } => {
                write!(f, "not-yet-eligible (earliest: {earliest_disposal_at})")
            }
            Self::OnLegalHold { hold_reason } => {
                write!(f, "on-legal-hold ({hold_reason})")
            }
            Self::Indeterminate { reason } => {
                write!(f, "indeterminate ({reason})")
            }
        }
    }
}

// ── DisposalRecord ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposalRecord {
    pub document_id: String,
    pub policy_id: String,
    pub disposal_method: DisposalMethod,
    pub disposed_at: String,
    pub disposed_by: String,
    pub retention_policy_ref: String,
    pub notes: String,
}

// ── RetentionPolicyLinker trait ───────────────────────────────────

pub trait RetentionPolicyLinker {
    fn link_policy(
        &mut self,
        document_id: &str,
        policy_id: &str,
        retention_policy_ref: &str,
    ) -> Result<(), DocumentError>;

    fn unlink_policy(
        &mut self,
        document_id: &str,
        policy_id: &str,
    ) -> Result<(), DocumentError>;

    fn check_disposal_eligibility(
        &self,
        document_id: &str,
    ) -> Result<DisposalEligibility, DocumentError>;

    fn record_disposal(
        &mut self,
        record: DisposalRecord,
    ) -> Result<(), DocumentError>;

    fn linked_policies(
        &self,
        document_id: &str,
    ) -> Result<Vec<String>, DocumentError>;

    fn disposal_history(
        &self,
        document_id: &str,
    ) -> Result<Vec<DisposalRecord>, DocumentError>;

    fn linker_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryRetentionPolicyLinker ─────────────────────────────────

pub struct InMemoryRetentionPolicyLinker {
    id: String,
    links: HashMap<String, Vec<(String, String)>>,
    disposals: Vec<DisposalRecord>,
}

impl InMemoryRetentionPolicyLinker {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            links: HashMap::new(),
            disposals: Vec::new(),
        }
    }
}

impl RetentionPolicyLinker for InMemoryRetentionPolicyLinker {
    fn link_policy(
        &mut self,
        document_id: &str,
        policy_id: &str,
        retention_policy_ref: &str,
    ) -> Result<(), DocumentError> {
        self.links
            .entry(document_id.to_string())
            .or_default()
            .push((policy_id.to_string(), retention_policy_ref.to_string()));
        Ok(())
    }

    fn unlink_policy(
        &mut self,
        document_id: &str,
        policy_id: &str,
    ) -> Result<(), DocumentError> {
        if let Some(policies) = self.links.get_mut(document_id) {
            policies.retain(|(pid, _)| pid != policy_id);
            Ok(())
        } else {
            Err(DocumentError::DocumentNotFound(document_id.to_string()))
        }
    }

    fn check_disposal_eligibility(
        &self,
        document_id: &str,
    ) -> Result<DisposalEligibility, DocumentError> {
        if self.links.contains_key(document_id) {
            Ok(DisposalEligibility::Eligible)
        } else {
            Err(DocumentError::DocumentNotFound(document_id.to_string()))
        }
    }

    fn record_disposal(
        &mut self,
        record: DisposalRecord,
    ) -> Result<(), DocumentError> {
        self.disposals.push(record);
        Ok(())
    }

    fn linked_policies(
        &self,
        document_id: &str,
    ) -> Result<Vec<String>, DocumentError> {
        Ok(self
            .links
            .get(document_id)
            .map(|v| v.iter().map(|(pid, _)| pid.clone()).collect())
            .unwrap_or_default())
    }

    fn disposal_history(
        &self,
        document_id: &str,
    ) -> Result<Vec<DisposalRecord>, DocumentError> {
        Ok(self
            .disposals
            .iter()
            .filter(|r| r.document_id == document_id)
            .cloned()
            .collect())
    }

    fn linker_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── LegalHoldAwareRetentionPolicyLinker ───────────────────────────

pub struct LegalHoldAwareRetentionPolicyLinker<L: RetentionPolicyLinker> {
    inner: L,
    id: String,
    holds: HashMap<String, String>,
}

impl<L: RetentionPolicyLinker> LegalHoldAwareRetentionPolicyLinker<L> {
    pub fn new(id: &str, inner: L) -> Self {
        Self {
            inner,
            id: id.to_string(),
            holds: HashMap::new(),
        }
    }

    pub fn place_hold(&mut self, document_id: &str, reason: &str) {
        self.holds
            .insert(document_id.to_string(), reason.to_string());
    }

    pub fn release_hold(&mut self, document_id: &str) {
        self.holds.remove(document_id);
    }
}

impl<L: RetentionPolicyLinker> RetentionPolicyLinker for LegalHoldAwareRetentionPolicyLinker<L> {
    fn link_policy(
        &mut self,
        document_id: &str,
        policy_id: &str,
        retention_policy_ref: &str,
    ) -> Result<(), DocumentError> {
        self.inner.link_policy(document_id, policy_id, retention_policy_ref)
    }

    fn unlink_policy(
        &mut self,
        document_id: &str,
        policy_id: &str,
    ) -> Result<(), DocumentError> {
        self.inner.unlink_policy(document_id, policy_id)
    }

    fn check_disposal_eligibility(
        &self,
        document_id: &str,
    ) -> Result<DisposalEligibility, DocumentError> {
        if let Some(reason) = self.holds.get(document_id) {
            return Ok(DisposalEligibility::OnLegalHold {
                hold_reason: reason.clone(),
            });
        }
        self.inner.check_disposal_eligibility(document_id)
    }

    fn record_disposal(
        &mut self,
        record: DisposalRecord,
    ) -> Result<(), DocumentError> {
        if let Some(reason) = self.holds.get(&record.document_id) {
            return Err(DocumentError::InvalidOperation(format!(
                "cannot dispose document {} — legal hold active: {reason}",
                record.document_id
            )));
        }
        self.inner.record_disposal(record)
    }

    fn linked_policies(
        &self,
        document_id: &str,
    ) -> Result<Vec<String>, DocumentError> {
        self.inner.linked_policies(document_id)
    }

    fn disposal_history(
        &self,
        document_id: &str,
    ) -> Result<Vec<DisposalRecord>, DocumentError> {
        self.inner.disposal_history(document_id)
    }

    fn linker_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ── NullRetentionPolicyLinker ─────────────────────────────────────

pub struct NullRetentionPolicyLinker {
    id: String,
}

impl NullRetentionPolicyLinker {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl RetentionPolicyLinker for NullRetentionPolicyLinker {
    fn link_policy(&mut self, _: &str, _: &str, _: &str) -> Result<(), DocumentError> {
        Ok(())
    }

    fn unlink_policy(&mut self, _: &str, _: &str) -> Result<(), DocumentError> {
        Ok(())
    }

    fn check_disposal_eligibility(&self, _: &str) -> Result<DisposalEligibility, DocumentError> {
        Ok(DisposalEligibility::Indeterminate {
            reason: "null linker".to_string(),
        })
    }

    fn record_disposal(&mut self, _: DisposalRecord) -> Result<(), DocumentError> {
        Ok(())
    }

    fn linked_policies(&self, _: &str) -> Result<Vec<String>, DocumentError> {
        Ok(Vec::new())
    }

    fn disposal_history(&self, _: &str) -> Result<Vec<DisposalRecord>, DocumentError> {
        Ok(Vec::new())
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
    fn test_disposal_eligibility_display() {
        assert_eq!(DisposalEligibility::Eligible.to_string(), "eligible");
        assert!(DisposalEligibility::NotYetEligible {
            earliest_disposal_at: "2027-01-01".into()
        }
        .to_string()
        .contains("2027-01-01"));
        assert!(DisposalEligibility::OnLegalHold {
            hold_reason: "litigation".into()
        }
        .to_string()
        .contains("litigation"));
        assert!(DisposalEligibility::Indeterminate {
            reason: "unknown".into()
        }
        .to_string()
        .contains("unknown"));
    }

    #[test]
    fn test_link_and_unlink_policy() {
        let mut linker = InMemoryRetentionPolicyLinker::new("linker-1");
        linker.link_policy("doc-1", "pol-1", "ref-1").unwrap();
        linker.link_policy("doc-1", "pol-2", "ref-2").unwrap();
        assert_eq!(linker.linked_policies("doc-1").unwrap().len(), 2);

        linker.unlink_policy("doc-1", "pol-1").unwrap();
        assert_eq!(linker.linked_policies("doc-1").unwrap(), vec!["pol-2"]);
    }

    #[test]
    fn test_unlink_unknown_document() {
        let mut linker = InMemoryRetentionPolicyLinker::new("linker-1");
        assert!(linker.unlink_policy("nonexistent", "pol-1").is_err());
    }

    #[test]
    fn test_disposal_eligibility_check() {
        let mut linker = InMemoryRetentionPolicyLinker::new("linker-1");
        linker.link_policy("doc-1", "pol-1", "ref-1").unwrap();
        assert_eq!(
            linker.check_disposal_eligibility("doc-1").unwrap(),
            DisposalEligibility::Eligible
        );
        assert!(linker.check_disposal_eligibility("doc-999").is_err());
    }

    #[test]
    fn test_record_and_retrieve_disposal() {
        let mut linker = InMemoryRetentionPolicyLinker::new("linker-1");
        let record = DisposalRecord {
            document_id: "doc-1".into(),
            policy_id: "pol-1".into(),
            disposal_method: DisposalMethod::Archive,
            disposed_at: "2026-04-20T00:00:00Z".into(),
            disposed_by: "system".into(),
            retention_policy_ref: "ref-1".into(),
            notes: "scheduled disposal".into(),
        };
        linker.record_disposal(record).unwrap();
        let history = linker.disposal_history("doc-1").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].disposal_method, DisposalMethod::Archive);
    }

    #[test]
    fn test_legal_hold_blocks_disposal() {
        let inner = InMemoryRetentionPolicyLinker::new("inner");
        let mut linker = LegalHoldAwareRetentionPolicyLinker::new("hold-linker", inner);
        linker.link_policy("doc-1", "pol-1", "ref-1").unwrap();
        linker.place_hold("doc-1", "active litigation");

        assert_eq!(
            linker.check_disposal_eligibility("doc-1").unwrap(),
            DisposalEligibility::OnLegalHold {
                hold_reason: "active litigation".into()
            }
        );

        let record = DisposalRecord {
            document_id: "doc-1".into(),
            policy_id: "pol-1".into(),
            disposal_method: DisposalMethod::Delete,
            disposed_at: "2026-04-20T00:00:00Z".into(),
            disposed_by: "system".into(),
            retention_policy_ref: "ref-1".into(),
            notes: "".into(),
        };
        assert!(linker.record_disposal(record).is_err());
    }

    #[test]
    fn test_legal_hold_release_allows_disposal() {
        let inner = InMemoryRetentionPolicyLinker::new("inner");
        let mut linker = LegalHoldAwareRetentionPolicyLinker::new("hold-linker", inner);
        linker.link_policy("doc-1", "pol-1", "ref-1").unwrap();
        linker.place_hold("doc-1", "litigation");
        linker.release_hold("doc-1");

        assert_eq!(
            linker.check_disposal_eligibility("doc-1").unwrap(),
            DisposalEligibility::Eligible
        );
    }

    #[test]
    fn test_null_linker() {
        let mut linker = NullRetentionPolicyLinker::new("null-1");
        assert!(!linker.is_active());
        linker.link_policy("d", "p", "r").unwrap();
        assert!(linker.linked_policies("d").unwrap().is_empty());
        assert_eq!(
            linker.check_disposal_eligibility("d").unwrap(),
            DisposalEligibility::Indeterminate {
                reason: "null linker".into()
            }
        );
    }

    #[test]
    fn test_linker_id() {
        let linker = InMemoryRetentionPolicyLinker::new("my-linker");
        assert_eq!(linker.linker_id(), "my-linker");
        assert!(linker.is_active());
    }

    #[test]
    fn test_disposal_method_reused_from_l2() {
        // Verify that DisposalMethod is the same type from crate::retention
        let method = DisposalMethod::Anonymize;
        assert_eq!(method.to_string(), "anonymize");
    }
}
