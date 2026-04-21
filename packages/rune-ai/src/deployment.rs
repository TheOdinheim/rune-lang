// ═══════════════════════════════════════════════════════════════════════
// Deployment — Deployment approval, lifecycle, rollback policy, and
// deployment record types for AI/ML model governance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── DeploymentEnvironment ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentEnvironment {
    Development,
    Staging,
    Production,
    Edge,
    AirGapped,
    Custom { name: String },
}

impl fmt::Display for DeploymentEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Development => f.write_str("Development"),
            Self::Staging => f.write_str("Staging"),
            Self::Production => f.write_str("Production"),
            Self::Edge => f.write_str("Edge"),
            Self::AirGapped => f.write_str("AirGapped"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DeploymentApprovalStatus ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentApprovalStatus {
    Pending,
    Approved { approved_by: String, approved_at: i64 },
    Denied { denied_by: String, reason: String },
    ConditionalApproval { conditions: Vec<String>, approved_by: String },
}

impl fmt::Display for DeploymentApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::Approved { approved_by, .. } => {
                write!(f, "Approved(by={approved_by})")
            }
            Self::Denied { denied_by, reason } => {
                write!(f, "Denied(by={denied_by}): {reason}")
            }
            Self::ConditionalApproval { conditions, approved_by } => {
                write!(
                    f,
                    "ConditionalApproval(by={approved_by}, conditions={})",
                    conditions.len()
                )
            }
        }
    }
}

// ── RollbackPolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollbackPolicy {
    Automatic { trigger_metric: String, threshold: String },
    Manual,
    NoRollback,
    Custom { name: String },
}

impl fmt::Display for RollbackPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Automatic { trigger_metric, threshold } => {
                write!(f, "Automatic({trigger_metric}>{threshold})")
            }
            Self::Manual => f.write_str("Manual"),
            Self::NoRollback => f.write_str("NoRollback"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DeploymentRequest ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentRequest {
    pub request_id: String,
    pub model_id: String,
    pub model_version: String,
    pub target_environment: DeploymentEnvironment,
    pub requested_by: String,
    pub requested_at: i64,
    pub approval_status: DeploymentApprovalStatus,
    pub rollback_policy: RollbackPolicy,
    pub metadata: HashMap<String, String>,
}

impl DeploymentRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        target_environment: DeploymentEnvironment,
        requested_by: impl Into<String>,
        requested_at: i64,
        rollback_policy: RollbackPolicy,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            target_environment,
            requested_by: requested_by.into(),
            requested_at,
            approval_status: DeploymentApprovalStatus::Pending,
            rollback_policy,
            metadata: HashMap::new(),
        }
    }
}

// ── DeploymentStatus ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Active,
    RolledBack { rolled_back_at: i64, reason: String },
    Superseded { superseded_by: String },
    Decommissioned { decommissioned_at: i64, reason: String },
}

impl fmt::Display for DeploymentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("Active"),
            Self::RolledBack { reason, .. } => write!(f, "RolledBack: {reason}"),
            Self::Superseded { superseded_by } => {
                write!(f, "Superseded(by={superseded_by})")
            }
            Self::Decommissioned { reason, .. } => {
                write!(f, "Decommissioned: {reason}")
            }
        }
    }
}

// ── DeploymentRecord ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentRecord {
    pub deployment_id: String,
    pub request_id: String,
    pub model_id: String,
    pub model_version: String,
    pub environment: DeploymentEnvironment,
    pub deployed_at: i64,
    pub deployed_by: String,
    pub status: DeploymentStatus,
    pub predecessor_deployment_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl DeploymentRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment_id: impl Into<String>,
        request_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        environment: DeploymentEnvironment,
        deployed_at: i64,
        deployed_by: impl Into<String>,
    ) -> Self {
        Self {
            deployment_id: deployment_id.into(),
            request_id: request_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            environment,
            deployed_at,
            deployed_by: deployed_by.into(),
            status: DeploymentStatus::Active,
            predecessor_deployment_id: None,
            metadata: HashMap::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_environment_display() {
        let envs = vec![
            DeploymentEnvironment::Development,
            DeploymentEnvironment::Staging,
            DeploymentEnvironment::Production,
            DeploymentEnvironment::Edge,
            DeploymentEnvironment::AirGapped,
            DeploymentEnvironment::Custom { name: "on-prem".into() },
        ];
        for e in &envs {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(envs.len(), 6);
    }

    #[test]
    fn test_deployment_approval_status_display() {
        let statuses = vec![
            DeploymentApprovalStatus::Pending,
            DeploymentApprovalStatus::Approved { approved_by: "admin".into(), approved_at: 1000 },
            DeploymentApprovalStatus::Denied { denied_by: "sec-team".into(), reason: "risk".into() },
            DeploymentApprovalStatus::ConditionalApproval {
                conditions: vec!["monitoring".into()],
                approved_by: "admin".into(),
            },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_rollback_policy_display() {
        let policies = vec![
            RollbackPolicy::Automatic { trigger_metric: "error_rate".into(), threshold: "0.05".into() },
            RollbackPolicy::Manual,
            RollbackPolicy::NoRollback,
            RollbackPolicy::Custom { name: "canary".into() },
        ];
        for p in &policies {
            assert!(!p.to_string().is_empty());
        }
        assert_eq!(policies.len(), 4);
    }

    #[test]
    fn test_deployment_status_display() {
        let statuses = vec![
            DeploymentStatus::Active,
            DeploymentStatus::RolledBack { rolled_back_at: 5000, reason: "regression".into() },
            DeploymentStatus::Superseded { superseded_by: "dep-2".into() },
            DeploymentStatus::Decommissioned { decommissioned_at: 6000, reason: "eol".into() },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_deployment_request_construction() {
        let req = DeploymentRequest::new(
            "req-1", "model-1", "1.0.0",
            DeploymentEnvironment::Production,
            "alice", 1000,
            RollbackPolicy::Manual,
        );
        assert_eq!(req.request_id, "req-1");
        assert_eq!(req.approval_status, DeploymentApprovalStatus::Pending);
    }

    #[test]
    fn test_deployment_record_construction() {
        let mut record = DeploymentRecord::new(
            "dep-1", "req-1", "model-1", "1.0.0",
            DeploymentEnvironment::Staging,
            2000, "deployer-bot",
        );
        assert_eq!(record.deployment_id, "dep-1");
        assert_eq!(record.status, DeploymentStatus::Active);
        assert!(record.predecessor_deployment_id.is_none());
        record.predecessor_deployment_id = Some("dep-0".into());
    }

    #[test]
    fn test_deployment_request_approval_flow() {
        let mut req = DeploymentRequest::new(
            "req-2", "model-2", "2.0.0",
            DeploymentEnvironment::Staging,
            "bob", 2000,
            RollbackPolicy::Automatic {
                trigger_metric: "error_rate".into(),
                threshold: "0.05".into(),
            },
        );
        assert_eq!(req.approval_status, DeploymentApprovalStatus::Pending);
        req.approval_status = DeploymentApprovalStatus::Approved {
            approved_by: "admin".into(),
            approved_at: 2500,
        };
        assert!(matches!(req.approval_status, DeploymentApprovalStatus::Approved { .. }));
    }

    #[test]
    fn test_deployment_record_status_update() {
        let mut record = DeploymentRecord::new(
            "dep-2", "req-2", "model-2", "2.0.0",
            DeploymentEnvironment::Production,
            3000, "deployer-bot",
        );
        assert_eq!(record.status, DeploymentStatus::Active);
        record.status = DeploymentStatus::RolledBack {
            rolled_back_at: 4000,
            reason: "latency spike".into(),
        };
        assert!(matches!(record.status, DeploymentStatus::RolledBack { .. }));
    }

    #[test]
    fn test_deployment_request_metadata() {
        let mut req = DeploymentRequest::new(
            "req-3", "model-3", "1.0.0",
            DeploymentEnvironment::Edge,
            "carol", 5000,
            RollbackPolicy::NoRollback,
        );
        req.metadata.insert("region".into(), "eu-west-1".into());
        assert_eq!(req.metadata["region"], "eu-west-1");
    }
}
