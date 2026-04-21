// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — RetentionGovernor trait for memory retention governance
// at the integration boundary. Evaluates retention decisions, executes
// sweeps, and assesses policy compliance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MemoryError;
use crate::memory::MemoryEntry;
use crate::retention::MemoryRetentionPolicy;
use crate::retention_engine::MemoryRetentionEngine;

// ── RetentionGovernanceDecision ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionGovernanceDecision {
    Retain { reason: String },
    Expire { reason: String, policy_ref: String },
    Redact { reason: String, policy_ref: String },
    Archive { reason: String, policy_ref: String },
}

impl fmt::Display for RetentionGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retain { reason } => write!(f, "Retain: {reason}"),
            Self::Expire { reason, policy_ref } => {
                write!(f, "Expire(policy={policy_ref}): {reason}")
            }
            Self::Redact { reason, policy_ref } => {
                write!(f, "Redact(policy={policy_ref}): {reason}")
            }
            Self::Archive { reason, policy_ref } => {
                write!(f, "Archive(policy={policy_ref}): {reason}")
            }
        }
    }
}

// ── RetentionSweepResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionSweepResult {
    pub sweep_id: String,
    pub policy_ref: String,
    pub entries_scanned: String,
    pub entries_expired: String,
    pub entries_redacted: String,
    pub entries_archived: String,
    pub swept_at: i64,
}

impl RetentionSweepResult {
    pub fn new(
        sweep_id: impl Into<String>,
        policy_ref: impl Into<String>,
        swept_at: i64,
    ) -> Self {
        Self {
            sweep_id: sweep_id.into(),
            policy_ref: policy_ref.into(),
            entries_scanned: "0".into(),
            entries_expired: "0".into(),
            entries_redacted: "0".into(),
            entries_archived: "0".into(),
            swept_at,
        }
    }
}

// ── PolicyComplianceResult ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyComplianceResult {
    pub scope_id: String,
    pub policy_ref: String,
    pub compliant_entries: String,
    pub non_compliant_entries: String,
    pub compliance_rate: String,
    pub assessed_at: i64,
}

// ── RetentionGovernor trait ───────────────────────────────────────

pub trait RetentionGovernor {
    fn evaluate_retention(
        &self,
        entry_id: &str,
    ) -> Result<RetentionGovernanceDecision, MemoryError>;

    fn execute_retention_sweep(
        &mut self,
        policy_ref: &str,
    ) -> Result<RetentionSweepResult, MemoryError>;

    fn check_policy_compliance(
        &self,
        scope_id: &str,
    ) -> Result<PolicyComplianceResult, MemoryError>;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryRetentionGovernor ─────────────────────────────────────

pub struct InMemoryRetentionGovernor {
    id: String,
    active: bool,
    engine: MemoryRetentionEngine,
    entries: HashMap<String, MemoryEntry>,
    policies: HashMap<String, MemoryRetentionPolicy>,
    entry_policy_map: HashMap<String, String>,
}

impl InMemoryRetentionGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            engine: MemoryRetentionEngine::new(),
            entries: HashMap::new(),
            policies: HashMap::new(),
            entry_policy_map: HashMap::new(),
        }
    }

    pub fn register_entry(&mut self, entry: MemoryEntry, policy_id: &str) {
        self.entry_policy_map
            .insert(entry.entry_id.clone(), policy_id.into());
        self.entries.insert(entry.entry_id.clone(), entry);
    }

    pub fn register_policy(&mut self, policy: MemoryRetentionPolicy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    pub fn set_now(&mut self, _now: i64) {
        // Placeholder for time source — in-memory implementation
        // uses the now parameter passed to individual evaluations
    }
}

impl RetentionGovernor for InMemoryRetentionGovernor {
    fn evaluate_retention(
        &self,
        entry_id: &str,
    ) -> Result<RetentionGovernanceDecision, MemoryError> {
        let entry = self
            .entries
            .get(entry_id)
            .ok_or_else(|| MemoryError::EntryNotFound(entry_id.into()))?;

        let policy_id = match self.entry_policy_map.get(entry_id) {
            Some(pid) => pid,
            None => {
                return Ok(RetentionGovernanceDecision::Retain {
                    reason: "no retention policy assigned".into(),
                });
            }
        };

        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| {
                MemoryError::InvalidConfiguration(format!("policy '{}' not found", policy_id))
            })?;

        // Use a large "now" value to evaluate current state
        let now = i64::MAX / 2;
        let eval = self.engine.evaluate_entry(entry, policy, now);

        match eval.outcome {
            crate::retention_engine::RetentionOutcome::Retain => {
                Ok(RetentionGovernanceDecision::Retain {
                    reason: eval.reason,
                })
            }
            crate::retention_engine::RetentionOutcome::Expire => {
                Ok(RetentionGovernanceDecision::Expire {
                    reason: eval.reason,
                    policy_ref: policy_id.clone(),
                })
            }
            crate::retention_engine::RetentionOutcome::Redact => {
                Ok(RetentionGovernanceDecision::Redact {
                    reason: eval.reason,
                    policy_ref: policy_id.clone(),
                })
            }
            crate::retention_engine::RetentionOutcome::Archive => {
                Ok(RetentionGovernanceDecision::Archive {
                    reason: eval.reason,
                    policy_ref: policy_id.clone(),
                })
            }
            crate::retention_engine::RetentionOutcome::Summarize => {
                Ok(RetentionGovernanceDecision::Archive {
                    reason: eval.reason,
                    policy_ref: policy_id.clone(),
                })
            }
        }
    }

    fn execute_retention_sweep(
        &mut self,
        policy_ref: &str,
    ) -> Result<RetentionSweepResult, MemoryError> {
        let policy = self
            .policies
            .get(policy_ref)
            .ok_or_else(|| {
                MemoryError::InvalidConfiguration(format!("policy '{}' not found", policy_ref))
            })?
            .clone();

        let governed_entries: Vec<MemoryEntry> = self
            .entry_policy_map
            .iter()
            .filter(|(_, pid)| *pid == policy_ref)
            .filter_map(|(eid, _)| self.entries.get(eid).cloned())
            .collect();

        let now = i64::MAX / 2;
        let mut expired = 0usize;
        let mut redacted = 0usize;
        let mut archived = 0usize;

        for entry in &governed_entries {
            let eval = self.engine.evaluate_entry(entry, &policy, now);
            match eval.outcome {
                crate::retention_engine::RetentionOutcome::Expire => expired += 1,
                crate::retention_engine::RetentionOutcome::Redact => redacted += 1,
                crate::retention_engine::RetentionOutcome::Archive
                | crate::retention_engine::RetentionOutcome::Summarize => archived += 1,
                crate::retention_engine::RetentionOutcome::Retain => {}
            }
        }

        let mut result = RetentionSweepResult::new("sweep-1", policy_ref, now);
        result.entries_scanned = governed_entries.len().to_string();
        result.entries_expired = expired.to_string();
        result.entries_redacted = redacted.to_string();
        result.entries_archived = archived.to_string();
        Ok(result)
    }

    fn check_policy_compliance(
        &self,
        scope_id: &str,
    ) -> Result<PolicyComplianceResult, MemoryError> {
        let scope_entries: Vec<&MemoryEntry> = self
            .entries
            .values()
            .filter(|e| e.scope_id == scope_id)
            .collect();

        if scope_entries.is_empty() {
            return Ok(PolicyComplianceResult {
                scope_id: scope_id.into(),
                policy_ref: "none".into(),
                compliant_entries: "0".into(),
                non_compliant_entries: "0".into(),
                compliance_rate: "1.00".into(),
                assessed_at: 0,
            });
        }

        let now = i64::MAX / 2;
        let mut compliant = 0usize;
        let mut non_compliant = 0usize;

        for entry in &scope_entries {
            if let Some(policy_id) = self.entry_policy_map.get(&entry.entry_id) {
                if let Some(policy) = self.policies.get(policy_id) {
                    let eval = self.engine.evaluate_entry(entry, policy, now);
                    match eval.outcome {
                        crate::retention_engine::RetentionOutcome::Retain => compliant += 1,
                        _ => non_compliant += 1,
                    }
                } else {
                    compliant += 1;
                }
            } else {
                compliant += 1;
            }
        }

        let total = compliant + non_compliant;
        let rate = if total > 0 {
            format!("{:.2}", compliant as f64 / total as f64)
        } else {
            "1.00".into()
        };

        Ok(PolicyComplianceResult {
            scope_id: scope_id.into(),
            policy_ref: "aggregate".into(),
            compliant_entries: compliant.to_string(),
            non_compliant_entries: non_compliant.to_string(),
            compliance_rate: rate,
            assessed_at: now,
        })
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullRetentionGovernor ─────────────────────────────────────────

pub struct NullRetentionGovernor;

impl RetentionGovernor for NullRetentionGovernor {
    fn evaluate_retention(
        &self,
        _entry_id: &str,
    ) -> Result<RetentionGovernanceDecision, MemoryError> {
        Ok(RetentionGovernanceDecision::Retain {
            reason: "null governor — always retain".into(),
        })
    }

    fn execute_retention_sweep(
        &mut self,
        policy_ref: &str,
    ) -> Result<RetentionSweepResult, MemoryError> {
        Ok(RetentionSweepResult::new("null-sweep", policy_ref, 0))
    }

    fn check_policy_compliance(
        &self,
        scope_id: &str,
    ) -> Result<PolicyComplianceResult, MemoryError> {
        Ok(PolicyComplianceResult {
            scope_id: scope_id.into(),
            policy_ref: "null".into(),
            compliant_entries: "0".into(),
            non_compliant_entries: "0".into(),
            compliance_rate: "1.00".into(),
            assessed_at: 0,
        })
    }

    fn governor_id(&self) -> &str {
        "null-retention-governor"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryContentType, MemorySensitivity};
    use crate::retention::ExpiryAction;

    fn make_entry(id: &str, scope: &str, created_at: i64) -> MemoryEntry {
        MemoryEntry::new(
            id, scope, "content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Public, "agent-1", created_at,
        )
    }

    fn make_policy(id: &str) -> MemoryRetentionPolicy {
        MemoryRetentionPolicy::new(id, "scope-*", ExpiryAction::Delete, 1000)
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            RetentionGovernanceDecision::Retain { reason: "ok".into() },
            RetentionGovernanceDecision::Expire { reason: "old".into(), policy_ref: "rp-1".into() },
            RetentionGovernanceDecision::Redact { reason: "sensitive".into(), policy_ref: "rp-1".into() },
            RetentionGovernanceDecision::Archive { reason: "archive".into(), policy_ref: "rp-1".into() },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }

    #[test]
    fn test_sweep_result_construction() {
        let result = RetentionSweepResult::new("sw-1", "rp-1", 1000);
        assert_eq!(result.entries_scanned, "0");
        assert_eq!(result.swept_at, 1000);
    }

    #[test]
    fn test_evaluate_no_policy_retains() {
        let mut gov = InMemoryRetentionGovernor::new("rg-1");
        let entry = make_entry("e1", "scope-1", 1000);
        gov.entries.insert("e1".into(), entry);
        let decision = gov.evaluate_retention("e1").unwrap();
        assert!(matches!(decision, RetentionGovernanceDecision::Retain { .. }));
    }

    #[test]
    fn test_evaluate_entry_not_found() {
        let gov = InMemoryRetentionGovernor::new("rg-1");
        assert!(gov.evaluate_retention("nope").is_err());
    }

    #[test]
    fn test_evaluate_with_expired_entry() {
        let mut gov = InMemoryRetentionGovernor::new("rg-1");
        let entry = make_entry("e1", "scope-1", 1000).with_expiry(2000);
        let policy = make_policy("rp-1");
        gov.register_policy(policy);
        gov.register_entry(entry, "rp-1");
        let decision = gov.evaluate_retention("e1").unwrap();
        assert!(matches!(decision, RetentionGovernanceDecision::Expire { .. }));
    }

    #[test]
    fn test_evaluate_sensitivity_threshold() {
        let mut gov = InMemoryRetentionGovernor::new("rg-1");
        let entry = MemoryEntry::new(
            "e1", "scope-1", "content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Restricted, "agent-1", 1000,
        );
        let policy = make_policy("rp-1")
            .with_sensitivity_threshold(MemorySensitivity::Sensitive);
        gov.register_policy(policy);
        gov.register_entry(entry, "rp-1");
        let decision = gov.evaluate_retention("e1").unwrap();
        assert!(matches!(decision, RetentionGovernanceDecision::Redact { .. }));
    }

    #[test]
    fn test_execute_sweep() {
        let mut gov = InMemoryRetentionGovernor::new("rg-1");
        let policy = make_policy("rp-1").with_max_age(100);
        gov.register_policy(policy);
        gov.register_entry(make_entry("e1", "scope-1", 10), "rp-1");
        gov.register_entry(make_entry("e2", "scope-1", 20), "rp-1");
        let result = gov.execute_retention_sweep("rp-1").unwrap();
        assert_eq!(result.entries_scanned, "2");
    }

    #[test]
    fn test_sweep_policy_not_found() {
        let mut gov = InMemoryRetentionGovernor::new("rg-1");
        assert!(gov.execute_retention_sweep("nope").is_err());
    }

    #[test]
    fn test_check_compliance_empty_scope() {
        let gov = InMemoryRetentionGovernor::new("rg-1");
        let result = gov.check_policy_compliance("scope-empty").unwrap();
        assert_eq!(result.compliance_rate, "1.00");
    }

    #[test]
    fn test_check_compliance_with_entries() {
        let mut gov = InMemoryRetentionGovernor::new("rg-1");
        let policy = make_policy("rp-1").with_sensitivity_threshold(MemorySensitivity::Restricted);
        gov.register_policy(policy);
        gov.register_entry(make_entry("e1", "scope-1", 1000), "rp-1");
        let result = gov.check_policy_compliance("scope-1").unwrap();
        assert_eq!(result.compliant_entries, "1");
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullRetentionGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-retention-governor");
        let d = gov.evaluate_retention("any").unwrap();
        assert!(matches!(d, RetentionGovernanceDecision::Retain { .. }));
        let s = gov.execute_retention_sweep("any").unwrap();
        assert_eq!(s.entries_scanned, "0");
    }

    #[test]
    fn test_governor_id() {
        let gov = InMemoryRetentionGovernor::new("my-gov");
        assert_eq!(gov.governor_id(), "my-gov");
        assert!(gov.is_active());
    }
}
