// ═══════════════════════════════════════════════════════════════════════
// Access Decisions
//
// Typed outcomes of permission evaluation with reasoning and
// evaluation trace for audit and debugging.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::grant::GrantId;
use crate::role::RoleId;
use crate::types::{ClassificationLevel, PermissionId};

// ── AccessDecision ─────────────────────────────────────────────────

/// Outcome of an access check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessDecision {
    Allow {
        permission_id: PermissionId,
        matched_role: Option<RoleId>,
        reason: String,
    },
    Deny {
        reason: String,
        checked_roles: Vec<RoleId>,
        nearest_miss: Option<NearestMiss>,
    },
}

impl AccessDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::Allow { reason, .. } => reason,
            Self::Deny { reason, .. } => reason,
        }
    }
}

impl fmt::Display for AccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow { permission_id, reason, .. } => {
                write!(f, "ALLOW ({permission_id}): {reason}")
            }
            Self::Deny { reason, .. } => write!(f, "DENY: {reason}"),
        }
    }
}

// ── NearestMiss ────────────────────────────────────────────────────

/// What almost granted access (useful for debugging and suggestions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearestMiss {
    pub permission_id: PermissionId,
    pub failed_check: FailedCheck,
    pub suggestion: String,
}

// ── FailedCheck ────────────────────────────────────────────────────

/// Why a specific permission check failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailedCheck {
    InsufficientClearance {
        required: ClassificationLevel,
        actual: ClassificationLevel,
    },
    ConditionNotMet { condition: String },
    PermissionExpired { expired_at: i64 },
    RoleNotAssigned,
    MutualExclusionViolation { conflicting_role: RoleId },
    MaxHoldersExceeded { role: RoleId, max: usize, current: usize },
    UsageLimitExceeded { grant_id: GrantId, max: u64, used: u64 },
}

impl fmt::Display for FailedCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientClearance { required, actual } => {
                write!(f, "insufficient clearance: need {required}, have {actual}")
            }
            Self::ConditionNotMet { condition } => {
                write!(f, "condition not met: {condition}")
            }
            Self::PermissionExpired { expired_at } => {
                write!(f, "permission expired at {expired_at}")
            }
            Self::RoleNotAssigned => write!(f, "no matching role assigned"),
            Self::MutualExclusionViolation { conflicting_role } => {
                write!(f, "mutual exclusion with role {conflicting_role}")
            }
            Self::MaxHoldersExceeded { role, max, current } => {
                write!(f, "role {role} at capacity: {current}/{max}")
            }
            Self::UsageLimitExceeded { grant_id, max, used } => {
                write!(f, "grant {grant_id} usage exceeded: {used}/{max}")
            }
        }
    }
}

// ── DetailedAccessDecision ─────────────────────────────────────────

/// Access decision with full evaluation trace for audit/compliance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedAccessDecision {
    pub decision: AccessDecision,
    pub evaluation_trace: Vec<EvaluationStep>,
    pub duration_us: u64,
    pub evaluated_at: i64,
}

/// A single step in the evaluation trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationStep {
    pub step_type: String,
    pub detail: String,
    pub result: bool,
    pub timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_is_allowed() {
        let d = AccessDecision::Allow {
            permission_id: PermissionId::new("file:read"),
            matched_role: Some(RoleId::new("viewer")),
            reason: "role grants access".into(),
        };
        assert!(d.is_allowed());
        assert!(!d.is_denied());
    }

    #[test]
    fn test_deny_is_denied() {
        let d = AccessDecision::Deny {
            reason: "no matching permission".into(),
            checked_roles: vec![RoleId::new("viewer")],
            nearest_miss: None,
        };
        assert!(d.is_denied());
        assert!(!d.is_allowed());
    }

    #[test]
    fn test_reason() {
        let allow = AccessDecision::Allow {
            permission_id: PermissionId::new("p"),
            matched_role: None,
            reason: "allowed".into(),
        };
        assert_eq!(allow.reason(), "allowed");

        let deny = AccessDecision::Deny {
            reason: "denied".into(),
            checked_roles: vec![],
            nearest_miss: None,
        };
        assert_eq!(deny.reason(), "denied");
    }

    #[test]
    fn test_nearest_miss() {
        let miss = NearestMiss {
            permission_id: PermissionId::new("file:read"),
            failed_check: FailedCheck::ConditionNotMet {
                condition: "RequiresMfa".into(),
            },
            suggestion: "Add MFA to satisfy RequiresMfa condition".into(),
        };
        assert!(miss.suggestion.contains("MFA"));
    }

    #[test]
    fn test_detailed_decision_has_trace() {
        let dd = DetailedAccessDecision {
            decision: AccessDecision::Allow {
                permission_id: PermissionId::new("p"),
                matched_role: None,
                reason: "ok".into(),
            },
            evaluation_trace: vec![
                EvaluationStep {
                    step_type: "role_lookup".into(),
                    detail: "found role viewer".into(),
                    result: true,
                    timestamp: 1000,
                },
                EvaluationStep {
                    step_type: "condition_check".into(),
                    detail: "time window OK".into(),
                    result: true,
                    timestamp: 1001,
                },
            ],
            duration_us: 42,
            evaluated_at: 1000,
        };
        assert_eq!(dd.evaluation_trace.len(), 2);
        assert!(dd.evaluation_trace[0].result);
    }

    #[test]
    fn test_failed_check_display() {
        let checks = vec![
            FailedCheck::InsufficientClearance {
                required: ClassificationLevel::TopSecret,
                actual: ClassificationLevel::Public,
            },
            FailedCheck::ConditionNotMet { condition: "MFA".into() },
            FailedCheck::PermissionExpired { expired_at: 100 },
            FailedCheck::RoleNotAssigned,
            FailedCheck::MutualExclusionViolation { conflicting_role: RoleId::new("r") },
            FailedCheck::MaxHoldersExceeded { role: RoleId::new("r"), max: 3, current: 3 },
            FailedCheck::UsageLimitExceeded { grant_id: GrantId::new("g"), max: 10, used: 10 },
        ];
        for c in &checks {
            assert!(!c.to_string().is_empty());
        }
    }
}
