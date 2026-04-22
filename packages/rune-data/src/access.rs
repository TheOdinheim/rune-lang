// ═══════════════════════════════════════════════════════════════════════
// Data access governance types — access policies controlling which
// roles can perform which operations on datasets, access requests
// with purpose declaration, and access decisions with conditional
// grants and escalation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::classification::DataSensitivity;

// ── DataOperation ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataOperation {
    Read,
    Write,
    Transform,
    Delete,
    Export,
    Share,
    Custom { name: String },
}

impl fmt::Display for DataOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("Read"),
            Self::Write => f.write_str("Write"),
            Self::Transform => f.write_str("Transform"),
            Self::Delete => f.write_str("Delete"),
            Self::Export => f.write_str("Export"),
            Self::Share => f.write_str("Share"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DataAccessDecision ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataAccessDecision {
    Granted { reason: String },
    Denied { reason: String },
    ConditionalGrant { conditions: Vec<String>, reason: String },
    RequiresEscalation { reason: String, escalation_target: String },
}

impl fmt::Display for DataAccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted { reason } => write!(f, "Granted: {reason}"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::ConditionalGrant { reason, .. } => write!(f, "ConditionalGrant: {reason}"),
            Self::RequiresEscalation { reason, .. } => write!(f, "RequiresEscalation: {reason}"),
        }
    }
}

// ── DataAccessPolicy ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataAccessPolicy {
    pub policy_id: String,
    pub dataset_ref: String,
    pub allowed_roles: Vec<String>,
    pub denied_roles: Vec<String>,
    pub allowed_operations: Vec<DataOperation>,
    pub require_purpose_declaration: bool,
    pub require_audit: bool,
    pub max_sensitivity_level: Option<DataSensitivity>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── DataAccessRequest ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataAccessRequest {
    pub request_id: String,
    pub requester_id: String,
    pub requester_role: String,
    pub dataset_ref: String,
    pub operation: DataOperation,
    pub purpose: Option<String>,
    pub requested_at: i64,
    pub context: HashMap<String, String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_operation_display() {
        let ops = vec![
            DataOperation::Read,
            DataOperation::Write,
            DataOperation::Transform,
            DataOperation::Delete,
            DataOperation::Export,
            DataOperation::Share,
            DataOperation::Custom { name: "anonymize".into() },
        ];
        for o in &ops {
            assert!(!o.to_string().is_empty());
        }
        assert_eq!(ops.len(), 7);
    }

    #[test]
    fn test_data_access_decision_display() {
        let decisions = vec![
            DataAccessDecision::Granted { reason: "role match".into() },
            DataAccessDecision::Denied { reason: "insufficient clearance".into() },
            DataAccessDecision::ConditionalGrant {
                conditions: vec!["sign NDA".into()],
                reason: "sensitive data".into(),
            },
            DataAccessDecision::RequiresEscalation {
                reason: "restricted dataset".into(),
                escalation_target: "data-owner".into(),
            },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 4);
    }

    #[test]
    fn test_access_policy_construction() {
        let policy = DataAccessPolicy {
            policy_id: "dap-1".into(),
            dataset_ref: "ds-users".into(),
            allowed_roles: vec!["analyst".into(), "engineer".into()],
            denied_roles: vec!["intern".into()],
            allowed_operations: vec![DataOperation::Read, DataOperation::Transform],
            require_purpose_declaration: true,
            require_audit: true,
            max_sensitivity_level: Some(DataSensitivity::Confidential),
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert_eq!(policy.allowed_roles.len(), 2);
        assert_eq!(policy.denied_roles.len(), 1);
        assert_eq!(policy.allowed_operations.len(), 2);
        assert!(policy.require_purpose_declaration);
        assert!(policy.require_audit);
    }

    #[test]
    fn test_access_policy_no_sensitivity_cap() {
        let policy = DataAccessPolicy {
            policy_id: "dap-2".into(),
            dataset_ref: "ds-public".into(),
            allowed_roles: vec!["anyone".into()],
            denied_roles: Vec::new(),
            allowed_operations: vec![DataOperation::Read],
            require_purpose_declaration: false,
            require_audit: false,
            max_sensitivity_level: None,
            created_at: 2000,
            metadata: HashMap::new(),
        };
        assert!(policy.max_sensitivity_level.is_none());
        assert!(!policy.require_purpose_declaration);
    }

    #[test]
    fn test_access_request_construction() {
        let request = DataAccessRequest {
            request_id: "dar-1".into(),
            requester_id: "user-alice".into(),
            requester_role: "analyst".into(),
            dataset_ref: "ds-users".into(),
            operation: DataOperation::Read,
            purpose: Some("quarterly report".into()),
            requested_at: 3000,
            context: HashMap::new(),
        };
        assert_eq!(request.requester_id, "user-alice");
        assert_eq!(request.purpose, Some("quarterly report".into()));
    }

    #[test]
    fn test_access_request_no_purpose() {
        let request = DataAccessRequest {
            request_id: "dar-2".into(),
            requester_id: "user-bob".into(),
            requester_role: "engineer".into(),
            dataset_ref: "ds-logs".into(),
            operation: DataOperation::Write,
            purpose: None,
            requested_at: 4000,
            context: HashMap::new(),
        };
        assert!(request.purpose.is_none());
    }

    #[test]
    fn test_access_request_with_context() {
        let mut ctx = HashMap::new();
        ctx.insert("ticket".into(), "JIRA-123".into());
        let request = DataAccessRequest {
            request_id: "dar-3".into(),
            requester_id: "user-carol".into(),
            requester_role: "admin".into(),
            dataset_ref: "ds-sensitive".into(),
            operation: DataOperation::Export,
            purpose: Some("compliance audit".into()),
            requested_at: 5000,
            context: ctx,
        };
        assert_eq!(request.context.get("ticket"), Some(&"JIRA-123".to_string()));
    }

    #[test]
    fn test_conditional_grant_with_conditions() {
        let decision = DataAccessDecision::ConditionalGrant {
            conditions: vec!["sign NDA".into(), "complete training".into()],
            reason: "restricted data requires preparation".into(),
        };
        if let DataAccessDecision::ConditionalGrant { conditions, .. } = &decision {
            assert_eq!(conditions.len(), 2);
        }
    }

    #[test]
    fn test_escalation_decision() {
        let decision = DataAccessDecision::RequiresEscalation {
            reason: "above clearance level".into(),
            escalation_target: "ciso".into(),
        };
        if let DataAccessDecision::RequiresEscalation { escalation_target, .. } = &decision {
            assert_eq!(escalation_target, "ciso");
        }
    }
}
