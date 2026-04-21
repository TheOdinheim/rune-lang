// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — MemoryScopeGovernor trait for memory scope lifecycle and
// access governance. Governs what happens at the scope level (access
// decisions, health assessment, scope policies) rather than the
// individual entry level.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MemoryError;
use crate::memory::MemoryAccessRequest;

// ── ScopeAccessDecision ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeAccessDecision {
    Granted { reason: String },
    Denied { reason: String },
    RequiresEscalation { reason: String, escalation_target: String },
    ReadOnly { reason: String },
}

impl fmt::Display for ScopeAccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted { reason } => write!(f, "Granted: {reason}"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::RequiresEscalation {
                reason,
                escalation_target,
            } => write!(f, "RequiresEscalation({escalation_target}): {reason}"),
            Self::ReadOnly { reason } => write!(f, "ReadOnly: {reason}"),
        }
    }
}

// ── ScopeHealthStatus ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeHealthStatus {
    Healthy,
    Degraded { reason: String },
    AtRisk { reason: String },
    Quarantined { reason: String },
}

impl fmt::Display for ScopeHealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "Healthy"),
            Self::Degraded { reason } => write!(f, "Degraded: {reason}"),
            Self::AtRisk { reason } => write!(f, "AtRisk: {reason}"),
            Self::Quarantined { reason } => write!(f, "Quarantined: {reason}"),
        }
    }
}

// ── ScopeHealthAssessment ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeHealthAssessment {
    pub scope_id: String,
    pub entry_count: String,
    pub expired_entry_count: String,
    pub violation_count: String,
    pub health_status: ScopeHealthStatus,
    pub assessed_at: i64,
}

// ── ScopePolicy (internal) ───────────────────────────────────────

#[derive(Debug, Clone)]
struct ScopePolicy {
    _scope_id: String,
    _max_entries: Option<usize>,
    require_escalation: bool,
    escalation_target: String,
    read_only: bool,
    quarantined: bool,
}

// ── MemoryScopeGovernor trait ─────────────────────────────────────

pub trait MemoryScopeGovernor {
    fn evaluate_scope_access(
        &self,
        request: &MemoryAccessRequest,
        scope_context: &HashMap<String, String>,
    ) -> Result<ScopeAccessDecision, MemoryError>;

    fn register_scope_policy(
        &mut self,
        scope_id: &str,
        policy: HashMap<String, String>,
    ) -> Result<(), MemoryError>;

    fn remove_scope_policy(&mut self, scope_id: &str) -> Result<(), MemoryError>;

    fn list_scope_policies(&self) -> Vec<String>;

    fn check_scope_health(
        &self,
        scope_id: &str,
    ) -> Result<ScopeHealthAssessment, MemoryError>;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryMemoryScopeGovernor ───────────────────────────────────

pub struct InMemoryMemoryScopeGovernor {
    id: String,
    active: bool,
    policies: HashMap<String, ScopePolicy>,
    entry_counts: HashMap<String, usize>,
    expired_counts: HashMap<String, usize>,
    violation_counts: HashMap<String, usize>,
}

impl InMemoryMemoryScopeGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            policies: HashMap::new(),
            entry_counts: HashMap::new(),
            expired_counts: HashMap::new(),
            violation_counts: HashMap::new(),
        }
    }

    pub fn set_entry_count(&mut self, scope_id: &str, count: usize) {
        self.entry_counts.insert(scope_id.into(), count);
    }

    pub fn set_expired_count(&mut self, scope_id: &str, count: usize) {
        self.expired_counts.insert(scope_id.into(), count);
    }

    pub fn set_violation_count(&mut self, scope_id: &str, count: usize) {
        self.violation_counts.insert(scope_id.into(), count);
    }
}

impl MemoryScopeGovernor for InMemoryMemoryScopeGovernor {
    fn evaluate_scope_access(
        &self,
        request: &MemoryAccessRequest,
        _scope_context: &HashMap<String, String>,
    ) -> Result<ScopeAccessDecision, MemoryError> {
        let policy = match self.policies.get(&request.scope_id) {
            Some(p) => p,
            None => {
                return Ok(ScopeAccessDecision::Granted {
                    reason: "no scope policy — default grant".into(),
                });
            }
        };

        if policy.quarantined {
            return Ok(ScopeAccessDecision::Denied {
                reason: format!("scope '{}' is quarantined", request.scope_id),
            });
        }

        if policy.read_only {
            return match request.access_type {
                crate::memory::MemoryAccessType::Read
                | crate::memory::MemoryAccessType::Search
                | crate::memory::MemoryAccessType::List => Ok(ScopeAccessDecision::ReadOnly {
                    reason: format!("scope '{}' is read-only", request.scope_id),
                }),
                _ => Ok(ScopeAccessDecision::Denied {
                    reason: format!(
                        "scope '{}' is read-only — {} not permitted",
                        request.scope_id, request.access_type
                    ),
                }),
            };
        }

        if policy.require_escalation {
            return Ok(ScopeAccessDecision::RequiresEscalation {
                reason: format!(
                    "scope '{}' requires escalation for access",
                    request.scope_id
                ),
                escalation_target: policy.escalation_target.clone(),
            });
        }

        Ok(ScopeAccessDecision::Granted {
            reason: format!("scope '{}' access granted", request.scope_id),
        })
    }

    fn register_scope_policy(
        &mut self,
        scope_id: &str,
        policy_config: HashMap<String, String>,
    ) -> Result<(), MemoryError> {
        let policy = ScopePolicy {
            _scope_id: scope_id.into(),
            _max_entries: policy_config
                .get("max_entries")
                .and_then(|v| v.parse().ok()),
            require_escalation: policy_config
                .get("require_escalation")
                .is_some_and(|v| v == "true"),
            escalation_target: policy_config
                .get("escalation_target")
                .cloned()
                .unwrap_or_default(),
            read_only: policy_config
                .get("read_only")
                .is_some_and(|v| v == "true"),
            quarantined: policy_config
                .get("quarantined")
                .is_some_and(|v| v == "true"),
        };
        self.policies.insert(scope_id.into(), policy);
        Ok(())
    }

    fn remove_scope_policy(&mut self, scope_id: &str) -> Result<(), MemoryError> {
        self.policies.remove(scope_id);
        Ok(())
    }

    fn list_scope_policies(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }

    fn check_scope_health(
        &self,
        scope_id: &str,
    ) -> Result<ScopeHealthAssessment, MemoryError> {
        let entry_count = self.entry_counts.get(scope_id).copied().unwrap_or(0);
        let expired_count = self.expired_counts.get(scope_id).copied().unwrap_or(0);
        let violation_count = self.violation_counts.get(scope_id).copied().unwrap_or(0);

        let health_status = if violation_count > 5 {
            ScopeHealthStatus::Quarantined {
                reason: format!("{violation_count} violations detected"),
            }
        } else if violation_count > 0 || (entry_count > 0 && expired_count * 2 > entry_count) {
            ScopeHealthStatus::AtRisk {
                reason: "high violation or expiration rate".into(),
            }
        } else if entry_count > 0 && expired_count > 0 {
            ScopeHealthStatus::Degraded {
                reason: "some expired entries present".into(),
            }
        } else {
            ScopeHealthStatus::Healthy
        };

        Ok(ScopeHealthAssessment {
            scope_id: scope_id.into(),
            entry_count: entry_count.to_string(),
            expired_entry_count: expired_count.to_string(),
            violation_count: violation_count.to_string(),
            health_status,
            assessed_at: 0,
        })
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullMemoryScopeGovernor ───────────────────────────────────────

pub struct NullMemoryScopeGovernor;

impl MemoryScopeGovernor for NullMemoryScopeGovernor {
    fn evaluate_scope_access(
        &self,
        _request: &MemoryAccessRequest,
        _scope_context: &HashMap<String, String>,
    ) -> Result<ScopeAccessDecision, MemoryError> {
        Ok(ScopeAccessDecision::Granted {
            reason: "null governor — always grant".into(),
        })
    }

    fn register_scope_policy(
        &mut self,
        _scope_id: &str,
        _policy: HashMap<String, String>,
    ) -> Result<(), MemoryError> {
        Ok(())
    }

    fn remove_scope_policy(&mut self, _scope_id: &str) -> Result<(), MemoryError> {
        Ok(())
    }

    fn list_scope_policies(&self) -> Vec<String> {
        Vec::new()
    }

    fn check_scope_health(
        &self,
        scope_id: &str,
    ) -> Result<ScopeHealthAssessment, MemoryError> {
        Ok(ScopeHealthAssessment {
            scope_id: scope_id.into(),
            entry_count: "0".into(),
            expired_entry_count: "0".into(),
            violation_count: "0".into(),
            health_status: ScopeHealthStatus::Healthy,
            assessed_at: 0,
        })
    }

    fn governor_id(&self) -> &str {
        "null-scope-governor"
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
    use crate::memory::MemoryAccessType;

    fn make_request(scope: &str, access: MemoryAccessType) -> MemoryAccessRequest {
        MemoryAccessRequest::new("r1", "agent-1", scope, access, 2000)
    }

    fn make_policy_config(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_scope_access_decision_display() {
        let decisions = vec![
            ScopeAccessDecision::Granted { reason: "ok".into() },
            ScopeAccessDecision::Denied { reason: "no".into() },
            ScopeAccessDecision::RequiresEscalation { reason: "esc".into(), escalation_target: "admin".into() },
            ScopeAccessDecision::ReadOnly { reason: "ro".into() },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }

    #[test]
    fn test_scope_health_status_display() {
        let statuses = vec![
            ScopeHealthStatus::Healthy,
            ScopeHealthStatus::Degraded { reason: "x".into() },
            ScopeHealthStatus::AtRisk { reason: "y".into() },
            ScopeHealthStatus::Quarantined { reason: "z".into() },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
    }

    #[test]
    fn test_no_policy_grants() {
        let gov = InMemoryMemoryScopeGovernor::new("sg-1");
        let decision = gov
            .evaluate_scope_access(&make_request("scope-1", MemoryAccessType::Read), &HashMap::new())
            .unwrap();
        assert!(matches!(decision, ScopeAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_quarantined_scope_denies() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.register_scope_policy("scope-1", make_policy_config(&[("quarantined", "true")]))
            .unwrap();
        let decision = gov
            .evaluate_scope_access(&make_request("scope-1", MemoryAccessType::Read), &HashMap::new())
            .unwrap();
        assert!(matches!(decision, ScopeAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_read_only_scope_allows_read() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.register_scope_policy("scope-1", make_policy_config(&[("read_only", "true")]))
            .unwrap();
        let decision = gov
            .evaluate_scope_access(&make_request("scope-1", MemoryAccessType::Read), &HashMap::new())
            .unwrap();
        assert!(matches!(decision, ScopeAccessDecision::ReadOnly { .. }));
    }

    #[test]
    fn test_read_only_scope_denies_write() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.register_scope_policy("scope-1", make_policy_config(&[("read_only", "true")]))
            .unwrap();
        let decision = gov
            .evaluate_scope_access(&make_request("scope-1", MemoryAccessType::Write), &HashMap::new())
            .unwrap();
        assert!(matches!(decision, ScopeAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_escalation_required() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.register_scope_policy(
            "scope-1",
            make_policy_config(&[
                ("require_escalation", "true"),
                ("escalation_target", "admin"),
            ]),
        )
        .unwrap();
        let decision = gov
            .evaluate_scope_access(&make_request("scope-1", MemoryAccessType::Write), &HashMap::new())
            .unwrap();
        assert!(matches!(
            decision,
            ScopeAccessDecision::RequiresEscalation { .. }
        ));
    }

    #[test]
    fn test_remove_scope_policy() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.register_scope_policy("scope-1", make_policy_config(&[("read_only", "true")]))
            .unwrap();
        gov.remove_scope_policy("scope-1").unwrap();
        assert!(gov.list_scope_policies().is_empty());
    }

    #[test]
    fn test_list_scope_policies() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.register_scope_policy("s1", HashMap::new()).unwrap();
        gov.register_scope_policy("s2", HashMap::new()).unwrap();
        assert_eq!(gov.list_scope_policies().len(), 2);
    }

    #[test]
    fn test_scope_health_healthy() {
        let gov = InMemoryMemoryScopeGovernor::new("sg-1");
        let health = gov.check_scope_health("scope-1").unwrap();
        assert_eq!(health.health_status, ScopeHealthStatus::Healthy);
    }

    #[test]
    fn test_scope_health_degraded() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.set_entry_count("scope-1", 10);
        gov.set_expired_count("scope-1", 2);
        let health = gov.check_scope_health("scope-1").unwrap();
        assert!(matches!(health.health_status, ScopeHealthStatus::Degraded { .. }));
    }

    #[test]
    fn test_scope_health_at_risk() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.set_entry_count("scope-1", 10);
        gov.set_expired_count("scope-1", 8);
        let health = gov.check_scope_health("scope-1").unwrap();
        assert!(matches!(health.health_status, ScopeHealthStatus::AtRisk { .. }));
    }

    #[test]
    fn test_scope_health_quarantined() {
        let mut gov = InMemoryMemoryScopeGovernor::new("sg-1");
        gov.set_violation_count("scope-1", 10);
        let health = gov.check_scope_health("scope-1").unwrap();
        assert!(matches!(
            health.health_status,
            ScopeHealthStatus::Quarantined { .. }
        ));
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullMemoryScopeGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-scope-governor");
        let d = gov
            .evaluate_scope_access(&make_request("s", MemoryAccessType::Read), &HashMap::new())
            .unwrap();
        assert!(matches!(d, ScopeAccessDecision::Granted { .. }));
        let h = gov.check_scope_health("s").unwrap();
        assert_eq!(h.health_status, ScopeHealthStatus::Healthy);
        gov.register_scope_policy("s", HashMap::new()).unwrap();
    }

    #[test]
    fn test_governor_id() {
        let gov = InMemoryMemoryScopeGovernor::new("my-sg");
        assert_eq!(gov.governor_id(), "my-sg");
        assert!(gov.is_active());
    }
}
