// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Isolation boundary checker. Evaluates memory access
// requests against isolation boundaries, finding applicable boundaries,
// checking temporal validity, and producing isolation check results.
// ═══════════════════════════════════════════════════════════════════════

use crate::isolation::{
    CrossScopePolicy, IsolationBoundary, IsolationBoundaryType, IsolationViolationType,
};
use crate::memory::MemoryAccessType;

// ── IsolationCheckResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationCheckOutcome {
    Allowed,
    Denied { reason: String },
    AllowedWithAudit { reason: String },
    AllowedWithApproval { reason: String },
}

impl std::fmt::Display for IsolationCheckOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "Allowed"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::AllowedWithAudit { reason } => write!(f, "AllowedWithAudit: {reason}"),
            Self::AllowedWithApproval { reason } => {
                write!(f, "AllowedWithApproval: {reason}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct IsolationCheckResult {
    pub requester_scope: String,
    pub target_scope: String,
    pub outcome: IsolationCheckOutcome,
    pub applicable_boundary_ids: Vec<String>,
    pub violation_type: Option<IsolationViolationType>,
    pub checked_at: i64,
}

impl IsolationCheckResult {
    pub fn allowed(
        requester_scope: impl Into<String>,
        target_scope: impl Into<String>,
        checked_at: i64,
    ) -> Self {
        Self {
            requester_scope: requester_scope.into(),
            target_scope: target_scope.into(),
            outcome: IsolationCheckOutcome::Allowed,
            applicable_boundary_ids: Vec::new(),
            violation_type: None,
            checked_at,
        }
    }

    pub fn denied(
        requester_scope: impl Into<String>,
        target_scope: impl Into<String>,
        reason: impl Into<String>,
        violation_type: IsolationViolationType,
        checked_at: i64,
    ) -> Self {
        Self {
            requester_scope: requester_scope.into(),
            target_scope: target_scope.into(),
            outcome: IsolationCheckOutcome::Denied {
                reason: reason.into(),
            },
            applicable_boundary_ids: Vec::new(),
            violation_type: Some(violation_type),
            checked_at,
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(
            self.outcome,
            IsolationCheckOutcome::Allowed
                | IsolationCheckOutcome::AllowedWithAudit { .. }
                | IsolationCheckOutcome::AllowedWithApproval { .. }
        )
    }

    pub fn is_denied(&self) -> bool {
        matches!(self.outcome, IsolationCheckOutcome::Denied { .. })
    }
}

// ── IsolationChecker ──────────────────────────────────────────────

pub struct IsolationChecker;

impl IsolationChecker {
    pub fn new() -> Self {
        Self
    }

    /// Find all isolation boundaries that apply between two scopes.
    pub fn find_applicable_boundaries<'a>(
        &self,
        requester_scope: &str,
        target_scope: &str,
        boundaries: &'a [IsolationBoundary],
    ) -> Vec<&'a IsolationBoundary> {
        boundaries
            .iter()
            .filter(|b| b.involves_scope(requester_scope) && b.involves_scope(target_scope))
            .collect()
    }

    /// Check whether a boundary is currently active (not expired).
    pub fn is_boundary_active(&self, boundary: &IsolationBoundary, now: i64) -> bool {
        match &boundary.boundary_type {
            IsolationBoundaryType::Temporal {
                valid_from,
                valid_until,
            } => now >= *valid_from && now <= *valid_until,
            _ => true,
        }
    }

    /// Evaluate access between scopes given boundaries and cross-scope policies.
    pub fn check_access(
        &self,
        requester_scope: &str,
        target_scope: &str,
        access_type: &MemoryAccessType,
        boundaries: &[IsolationBoundary],
        policies: &[CrossScopePolicy],
        now: i64,
    ) -> IsolationCheckResult {
        // Same scope — always allowed
        if requester_scope == target_scope {
            return IsolationCheckResult::allowed(requester_scope, target_scope, now);
        }

        let applicable = self.find_applicable_boundaries(requester_scope, target_scope, boundaries);

        if applicable.is_empty() {
            // No boundaries defined — allow by default
            return IsolationCheckResult::allowed(requester_scope, target_scope, now);
        }

        let violation_type = match access_type {
            MemoryAccessType::Read | MemoryAccessType::List => {
                IsolationViolationType::CrossScopeRead
            }
            MemoryAccessType::Write | MemoryAccessType::Delete => {
                IsolationViolationType::CrossScopeWrite
            }
            MemoryAccessType::Search => IsolationViolationType::CrossScopeSearch,
        };

        // Collect boundary IDs for the result
        let boundary_ids: Vec<String> = applicable.iter().map(|b| b.boundary_id.clone()).collect();

        // Check each applicable boundary
        for boundary in &applicable {
            if !self.is_boundary_active(boundary, now) {
                // Expired temporal boundary
                let mut result = IsolationCheckResult::denied(
                    requester_scope,
                    target_scope,
                    "temporal boundary has expired",
                    IsolationViolationType::TemporalBoundaryExpired,
                    now,
                );
                result.applicable_boundary_ids = boundary_ids;
                return result;
            }

            match &boundary.boundary_type {
                IsolationBoundaryType::HardIsolation => {
                    let mut result = IsolationCheckResult::denied(
                        requester_scope,
                        target_scope,
                        format!(
                            "hard isolation boundary '{}' prevents cross-scope {}",
                            boundary.boundary_id, access_type
                        ),
                        violation_type,
                        now,
                    );
                    result.applicable_boundary_ids = boundary_ids;
                    return result;
                }
                IsolationBoundaryType::SoftIsolation { .. } => {
                    // Check cross-scope policies for an override
                    if let Some(policy) = policies.iter().find(|p| {
                        (p.source_scope == requester_scope && p.target_scope == target_scope)
                            || (p.source_scope == target_scope
                                && p.target_scope == requester_scope)
                    })
                        && policy.is_access_permitted(access_type)
                    {
                        let outcome = if policy.requires_approval {
                            IsolationCheckOutcome::AllowedWithApproval {
                                reason: format!("policy '{}' requires approval", policy.policy_id),
                            }
                        } else if policy.requires_audit {
                            IsolationCheckOutcome::AllowedWithAudit {
                                reason: format!("policy '{}' requires audit", policy.policy_id),
                            }
                        } else {
                            IsolationCheckOutcome::Allowed
                        };
                        return IsolationCheckResult {
                            requester_scope: requester_scope.into(),
                            target_scope: target_scope.into(),
                            outcome,
                            applicable_boundary_ids: boundary_ids,
                            violation_type: None,
                            checked_at: now,
                        };
                    }
                    // No policy override — deny
                    let mut result = IsolationCheckResult::denied(
                        requester_scope,
                        target_scope,
                        format!(
                            "soft isolation boundary '{}' with no policy override for {}",
                            boundary.boundary_id, access_type
                        ),
                        violation_type,
                        now,
                    );
                    result.applicable_boundary_ids = boundary_ids;
                    return result;
                }
                IsolationBoundaryType::Temporal { .. } => {
                    // Active temporal boundary — continue checking remaining boundaries
                    continue;
                }
            }
        }

        // All boundaries passed (e.g. all were active temporal permits)
        let mut result = IsolationCheckResult::allowed(requester_scope, target_scope, now);
        result.applicable_boundary_ids = boundary_ids;
        result
    }
}

impl Default for IsolationChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn hard_boundary(id: &str, scope_a: &str, scope_b: &str) -> IsolationBoundary {
        IsolationBoundary::new(id, scope_a, scope_b, IsolationBoundaryType::HardIsolation, "admin", 1000)
    }

    fn soft_boundary(id: &str, scope_a: &str, scope_b: &str) -> IsolationBoundary {
        IsolationBoundary::new(
            id, scope_a, scope_b,
            IsolationBoundaryType::SoftIsolation { leak_policy: "log-only".into() },
            "admin", 1000,
        )
    }

    fn temporal_boundary(id: &str, scope_a: &str, scope_b: &str, from: i64, until: i64) -> IsolationBoundary {
        IsolationBoundary::new(
            id, scope_a, scope_b,
            IsolationBoundaryType::Temporal { valid_from: from, valid_until: until },
            "admin", 1000,
        )
    }

    #[test]
    fn test_same_scope_always_allowed() {
        let checker = IsolationChecker::new();
        let result = checker.check_access(
            "scope-a", "scope-a", &MemoryAccessType::Read,
            &[], &[], 2000,
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_no_boundaries_allowed() {
        let checker = IsolationChecker::new();
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &[], &[], 2000,
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_hard_isolation_denied() {
        let checker = IsolationChecker::new();
        let boundaries = vec![hard_boundary("ib-1", "scope-a", "scope-b")];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[], 2000,
        );
        assert!(result.is_denied());
        assert_eq!(result.violation_type, Some(IsolationViolationType::CrossScopeRead));
    }

    #[test]
    fn test_hard_isolation_write_violation() {
        let checker = IsolationChecker::new();
        let boundaries = vec![hard_boundary("ib-1", "scope-a", "scope-b")];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Write,
            &boundaries, &[], 2000,
        );
        assert!(result.is_denied());
        assert_eq!(result.violation_type, Some(IsolationViolationType::CrossScopeWrite));
    }

    #[test]
    fn test_hard_isolation_search_violation() {
        let checker = IsolationChecker::new();
        let boundaries = vec![hard_boundary("ib-1", "scope-a", "scope-b")];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Search,
            &boundaries, &[], 2000,
        );
        assert!(result.is_denied());
        assert_eq!(result.violation_type, Some(IsolationViolationType::CrossScopeSearch));
    }

    #[test]
    fn test_soft_isolation_with_policy_override() {
        let checker = IsolationChecker::new();
        let boundaries = vec![soft_boundary("ib-1", "scope-a", "scope-b")];
        let mut policy = CrossScopePolicy::new("csp-1", "scope-a", "scope-b", 1000);
        policy.add_permitted_access(MemoryAccessType::Read);
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[policy], 2000,
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_soft_isolation_without_policy() {
        let checker = IsolationChecker::new();
        let boundaries = vec![soft_boundary("ib-1", "scope-a", "scope-b")];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[], 2000,
        );
        assert!(result.is_denied());
    }

    #[test]
    fn test_soft_isolation_policy_requires_audit() {
        let checker = IsolationChecker::new();
        let boundaries = vec![soft_boundary("ib-1", "scope-a", "scope-b")];
        let mut policy = CrossScopePolicy::new("csp-1", "scope-a", "scope-b", 1000);
        policy.add_permitted_access(MemoryAccessType::Read);
        policy.requires_audit = true;
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[policy], 2000,
        );
        assert!(result.is_allowed());
        assert!(matches!(result.outcome, IsolationCheckOutcome::AllowedWithAudit { .. }));
    }

    #[test]
    fn test_soft_isolation_policy_requires_approval() {
        let checker = IsolationChecker::new();
        let boundaries = vec![soft_boundary("ib-1", "scope-a", "scope-b")];
        let mut policy = CrossScopePolicy::new("csp-1", "scope-a", "scope-b", 1000);
        policy.add_permitted_access(MemoryAccessType::Write);
        policy.requires_approval = true;
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Write,
            &boundaries, &[policy], 2000,
        );
        assert!(result.is_allowed());
        assert!(matches!(result.outcome, IsolationCheckOutcome::AllowedWithApproval { .. }));
    }

    #[test]
    fn test_temporal_boundary_active() {
        let checker = IsolationChecker::new();
        let boundaries = vec![temporal_boundary("ib-1", "scope-a", "scope-b", 1000, 5000)];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[], 3000,
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_temporal_boundary_expired() {
        let checker = IsolationChecker::new();
        let boundaries = vec![temporal_boundary("ib-1", "scope-a", "scope-b", 1000, 5000)];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[], 6000,
        );
        assert!(result.is_denied());
        assert_eq!(
            result.violation_type,
            Some(IsolationViolationType::TemporalBoundaryExpired)
        );
    }

    #[test]
    fn test_find_applicable_boundaries() {
        let checker = IsolationChecker::new();
        let boundaries = vec![
            hard_boundary("ib-1", "scope-a", "scope-b"),
            hard_boundary("ib-2", "scope-a", "scope-c"),
            hard_boundary("ib-3", "scope-b", "scope-c"),
        ];
        let applicable = checker.find_applicable_boundaries("scope-a", "scope-b", &boundaries);
        assert_eq!(applicable.len(), 1);
        assert_eq!(applicable[0].boundary_id, "ib-1");
    }

    #[test]
    fn test_is_boundary_active_hard() {
        let checker = IsolationChecker::new();
        let boundary = hard_boundary("ib-1", "a", "b");
        assert!(checker.is_boundary_active(&boundary, i64::MAX));
    }

    #[test]
    fn test_is_boundary_active_temporal() {
        let checker = IsolationChecker::new();
        let boundary = temporal_boundary("ib-1", "a", "b", 1000, 5000);
        assert!(!checker.is_boundary_active(&boundary, 500));
        assert!(checker.is_boundary_active(&boundary, 3000));
        assert!(!checker.is_boundary_active(&boundary, 6000));
    }

    #[test]
    fn test_isolation_check_outcome_display() {
        let outcomes = vec![
            IsolationCheckOutcome::Allowed,
            IsolationCheckOutcome::Denied { reason: "blocked".into() },
            IsolationCheckOutcome::AllowedWithAudit { reason: "audit".into() },
            IsolationCheckOutcome::AllowedWithApproval { reason: "approval".into() },
        ];
        for o in &outcomes {
            assert!(!o.to_string().is_empty());
        }
    }

    #[test]
    fn test_isolation_checker_default() {
        let _checker = IsolationChecker;
    }

    #[test]
    fn test_check_result_constructors() {
        let allowed = IsolationCheckResult::allowed("a", "b", 1000);
        assert!(allowed.is_allowed());
        assert!(!allowed.is_denied());

        let denied = IsolationCheckResult::denied(
            "a", "b", "reason", IsolationViolationType::CrossScopeRead, 1000,
        );
        assert!(denied.is_denied());
        assert!(!denied.is_allowed());
    }

    #[test]
    fn test_unrelated_boundary_ignored() {
        let checker = IsolationChecker::new();
        let boundaries = vec![hard_boundary("ib-1", "scope-x", "scope-y")];
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Read,
            &boundaries, &[], 2000,
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_soft_isolation_wrong_access_type() {
        let checker = IsolationChecker::new();
        let boundaries = vec![soft_boundary("ib-1", "scope-a", "scope-b")];
        let mut policy = CrossScopePolicy::new("csp-1", "scope-a", "scope-b", 1000);
        policy.add_permitted_access(MemoryAccessType::Read);
        // Try Write — not permitted by policy
        let result = checker.check_access(
            "scope-a", "scope-b", &MemoryAccessType::Write,
            &boundaries, &[policy], 2000,
        );
        assert!(result.is_denied());
    }
}
