// ═══════════════════════════════════════════════════════════════════════
// Isolation — Memory isolation enforcement types: boundaries,
// violations, cross-scope policies for governing memory access
// between agents, sessions, and tenants.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::memory::{MemoryAccessType, MemorySensitivity};

// ── IsolationBoundaryType ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationBoundaryType {
    HardIsolation,
    SoftIsolation { leak_policy: String },
    Temporal { valid_from: i64, valid_until: i64 },
}

impl fmt::Display for IsolationBoundaryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardIsolation => write!(f, "HardIsolation"),
            Self::SoftIsolation { leak_policy } => {
                write!(f, "SoftIsolation(policy={leak_policy})")
            }
            Self::Temporal {
                valid_from,
                valid_until,
            } => write!(f, "Temporal({valid_from}..{valid_until})"),
        }
    }
}

// ── IsolationViolationType ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsolationViolationType {
    CrossScopeRead,
    CrossScopeWrite,
    CrossScopeSearch,
    TemporalBoundaryExpired,
}

impl fmt::Display for IsolationViolationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CrossScopeRead => "CrossScopeRead",
            Self::CrossScopeWrite => "CrossScopeWrite",
            Self::CrossScopeSearch => "CrossScopeSearch",
            Self::TemporalBoundaryExpired => "TemporalBoundaryExpired",
        };
        f.write_str(s)
    }
}

// ── IsolationBoundary ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationBoundary {
    pub boundary_id: String,
    pub scope_a: String,
    pub scope_b: String,
    pub boundary_type: IsolationBoundaryType,
    pub created_by: String,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl IsolationBoundary {
    pub fn new(
        boundary_id: impl Into<String>,
        scope_a: impl Into<String>,
        scope_b: impl Into<String>,
        boundary_type: IsolationBoundaryType,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            boundary_id: boundary_id.into(),
            scope_a: scope_a.into(),
            scope_b: scope_b.into(),
            boundary_type,
            created_by: created_by.into(),
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn involves_scope(&self, scope_id: &str) -> bool {
        self.scope_a == scope_id || self.scope_b == scope_id
    }

    pub fn is_temporal_expired(&self, now: i64) -> bool {
        matches!(
            &self.boundary_type,
            IsolationBoundaryType::Temporal { valid_until, .. } if now > *valid_until
        )
    }
}

// ── IsolationViolation ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationViolation {
    pub violation_id: String,
    pub boundary_id: String,
    pub violating_requester: String,
    pub attempted_scope: String,
    pub violation_type: IsolationViolationType,
    pub detected_at: i64,
    pub severity: MemorySensitivity,
    pub metadata: HashMap<String, String>,
}

impl IsolationViolation {
    pub fn new(
        violation_id: impl Into<String>,
        boundary_id: impl Into<String>,
        violating_requester: impl Into<String>,
        attempted_scope: impl Into<String>,
        violation_type: IsolationViolationType,
        detected_at: i64,
        severity: MemorySensitivity,
    ) -> Self {
        Self {
            violation_id: violation_id.into(),
            boundary_id: boundary_id.into(),
            violating_requester: violating_requester.into(),
            attempted_scope: attempted_scope.into(),
            violation_type,
            detected_at,
            severity,
            metadata: HashMap::new(),
        }
    }
}

// ── CrossScopePolicy ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossScopePolicy {
    pub policy_id: String,
    pub source_scope: String,
    pub target_scope: String,
    pub permitted_access_types: Vec<MemoryAccessType>,
    pub requires_audit: bool,
    pub requires_approval: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl CrossScopePolicy {
    pub fn new(
        policy_id: impl Into<String>,
        source_scope: impl Into<String>,
        target_scope: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            source_scope: source_scope.into(),
            target_scope: target_scope.into(),
            permitted_access_types: Vec::new(),
            requires_audit: true,
            requires_approval: false,
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn add_permitted_access(&mut self, access_type: MemoryAccessType) {
        self.permitted_access_types.push(access_type);
    }

    pub fn is_access_permitted(&self, access_type: &MemoryAccessType) -> bool {
        self.permitted_access_types.iter().any(|a| a == access_type)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_boundary_type_display() {
        let types = vec![
            IsolationBoundaryType::HardIsolation,
            IsolationBoundaryType::SoftIsolation {
                leak_policy: "log-only".into(),
            },
            IsolationBoundaryType::Temporal {
                valid_from: 1000,
                valid_until: 5000,
            },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 3);
    }

    #[test]
    fn test_isolation_violation_type_display() {
        let types = vec![
            IsolationViolationType::CrossScopeRead,
            IsolationViolationType::CrossScopeWrite,
            IsolationViolationType::CrossScopeSearch,
            IsolationViolationType::TemporalBoundaryExpired,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 4);
    }

    #[test]
    fn test_isolation_boundary_construction() {
        let boundary = IsolationBoundary::new(
            "ib-1",
            "scope-agent-1",
            "scope-agent-2",
            IsolationBoundaryType::HardIsolation,
            "admin",
            1000,
        );
        assert_eq!(boundary.boundary_id, "ib-1");
        assert_eq!(boundary.scope_a, "scope-agent-1");
        assert_eq!(boundary.scope_b, "scope-agent-2");
    }

    #[test]
    fn test_isolation_boundary_involves_scope() {
        let boundary = IsolationBoundary::new(
            "ib-1",
            "scope-a",
            "scope-b",
            IsolationBoundaryType::HardIsolation,
            "admin",
            1000,
        );
        assert!(boundary.involves_scope("scope-a"));
        assert!(boundary.involves_scope("scope-b"));
        assert!(!boundary.involves_scope("scope-c"));
    }

    #[test]
    fn test_isolation_boundary_temporal_expired() {
        let boundary = IsolationBoundary::new(
            "ib-1",
            "scope-a",
            "scope-b",
            IsolationBoundaryType::Temporal {
                valid_from: 1000,
                valid_until: 5000,
            },
            "admin",
            1000,
        );
        assert!(!boundary.is_temporal_expired(4000));
        assert!(!boundary.is_temporal_expired(5000));
        assert!(boundary.is_temporal_expired(5001));
    }

    #[test]
    fn test_hard_isolation_not_temporal_expired() {
        let boundary = IsolationBoundary::new(
            "ib-1",
            "scope-a",
            "scope-b",
            IsolationBoundaryType::HardIsolation,
            "admin",
            1000,
        );
        assert!(!boundary.is_temporal_expired(i64::MAX));
    }

    #[test]
    fn test_isolation_violation_construction() {
        let violation = IsolationViolation::new(
            "iv-1",
            "ib-1",
            "agent-rogue",
            "scope-restricted",
            IsolationViolationType::CrossScopeRead,
            2000,
            MemorySensitivity::Restricted,
        );
        assert_eq!(violation.violation_id, "iv-1");
        assert_eq!(violation.boundary_id, "ib-1");
        assert_eq!(violation.violating_requester, "agent-rogue");
        assert_eq!(violation.severity, MemorySensitivity::Restricted);
    }

    #[test]
    fn test_cross_scope_policy_construction() {
        let policy = CrossScopePolicy::new("csp-1", "scope-a", "scope-b", 1000);
        assert_eq!(policy.policy_id, "csp-1");
        assert!(policy.requires_audit);
        assert!(!policy.requires_approval);
        assert!(policy.permitted_access_types.is_empty());
    }

    #[test]
    fn test_cross_scope_policy_access_check() {
        let mut policy = CrossScopePolicy::new("csp-1", "scope-a", "scope-b", 1000);
        policy.add_permitted_access(MemoryAccessType::Read);
        policy.add_permitted_access(MemoryAccessType::Search);
        assert!(policy.is_access_permitted(&MemoryAccessType::Read));
        assert!(policy.is_access_permitted(&MemoryAccessType::Search));
        assert!(!policy.is_access_permitted(&MemoryAccessType::Write));
        assert!(!policy.is_access_permitted(&MemoryAccessType::Delete));
    }

    #[test]
    fn test_isolation_violation_eq() {
        let v1 = IsolationViolation::new(
            "iv-1",
            "ib-1",
            "agent-1",
            "scope-x",
            IsolationViolationType::CrossScopeWrite,
            2000,
            MemorySensitivity::Sensitive,
        );
        assert_eq!(v1, v1.clone());
    }

    #[test]
    fn test_cross_scope_policy_eq() {
        let p1 = CrossScopePolicy::new("csp-1", "a", "b", 1000);
        assert_eq!(p1, p1.clone());
    }

    #[test]
    fn test_isolation_boundary_metadata() {
        let mut boundary = IsolationBoundary::new(
            "ib-1", "scope-a", "scope-b",
            IsolationBoundaryType::HardIsolation, "admin", 1000,
        );
        boundary.metadata.insert("reason".into(), "compliance".into());
        assert_eq!(boundary.metadata.len(), 1);
    }

    #[test]
    fn test_isolation_violation_metadata() {
        let mut violation = IsolationViolation::new(
            "iv-1", "ib-1", "agent-1", "scope-x",
            IsolationViolationType::CrossScopeSearch,
            2000, MemorySensitivity::Sensitive,
        );
        violation.metadata.insert("ip".into(), "10.0.0.1".into());
        assert_eq!(violation.metadata.len(), 1);
    }

    #[test]
    fn test_cross_scope_policy_metadata() {
        let mut policy = CrossScopePolicy::new("csp-1", "a", "b", 1000);
        policy.metadata.insert("approved_by".into(), "admin".into());
        assert_eq!(policy.metadata.len(), 1);
    }

    #[test]
    fn test_soft_isolation_display() {
        let bt = IsolationBoundaryType::SoftIsolation {
            leak_policy: "log-and-alert".into(),
        };
        let s = bt.to_string();
        assert!(s.contains("log-and-alert"));
    }
}
