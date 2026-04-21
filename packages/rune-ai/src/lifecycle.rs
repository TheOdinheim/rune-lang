// ═══════════════════════════════════════════════════════════════════════
// Lifecycle — Model retirement, deprecation, and lifecycle transition
// types for governing model end-of-life policy, replacement tracking,
// sunset schedules, and state machine enforcement.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model_registry::ModelStatus;

// ── RetirementAction ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetirementAction {
    Archive,
    Delete,
    Suspend,
    ReplaceWithSuccessor,
    Custom { name: String },
}

impl fmt::Display for RetirementAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive => f.write_str("Archive"),
            Self::Delete => f.write_str("Delete"),
            Self::Suspend => f.write_str("Suspend"),
            Self::ReplaceWithSuccessor => f.write_str("ReplaceWithSuccessor"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DeprecationSeverity ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeprecationSeverity {
    Advisory,
    Warning,
    Mandatory,
    Immediate,
}

impl fmt::Display for DeprecationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Advisory => "Advisory",
            Self::Warning => "Warning",
            Self::Mandatory => "Mandatory",
            Self::Immediate => "Immediate",
        };
        f.write_str(s)
    }
}

// ── ModelLifecyclePolicy ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelLifecyclePolicy {
    pub policy_id: String,
    pub model_id: String,
    pub max_deployment_age_days: Option<String>,
    pub sunset_date: Option<i64>,
    pub replacement_model_id: Option<String>,
    pub deprecation_notice_days: Option<String>,
    pub retirement_action: RetirementAction,
    pub require_migration_plan: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl ModelLifecyclePolicy {
    pub fn new(
        policy_id: impl Into<String>,
        model_id: impl Into<String>,
        retirement_action: RetirementAction,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            model_id: model_id.into(),
            max_deployment_age_days: None,
            sunset_date: None,
            replacement_model_id: None,
            deprecation_notice_days: None,
            retirement_action,
            require_migration_plan: false,
            created_at,
            metadata: HashMap::new(),
        }
    }
}

// ── DeprecationNotice ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationNotice {
    pub notice_id: String,
    pub model_id: String,
    pub model_version: String,
    pub issued_at: i64,
    pub sunset_date: Option<i64>,
    pub replacement_model_ref: Option<String>,
    pub reason: String,
    pub severity: DeprecationSeverity,
    pub acknowledged_by: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl DeprecationNotice {
    pub fn new(
        notice_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        issued_at: i64,
        reason: impl Into<String>,
        severity: DeprecationSeverity,
    ) -> Self {
        Self {
            notice_id: notice_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            issued_at,
            sunset_date: None,
            replacement_model_ref: None,
            reason: reason.into(),
            severity,
            acknowledged_by: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

// ── ModelLifecycleTransition ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelLifecycleTransition {
    pub transition_id: String,
    pub model_id: String,
    pub from_status: ModelStatus,
    pub to_status: ModelStatus,
    pub transitioned_at: i64,
    pub transitioned_by: String,
    pub reason: String,
    pub metadata: HashMap<String, String>,
}

impl ModelLifecycleTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transition_id: impl Into<String>,
        model_id: impl Into<String>,
        from_status: ModelStatus,
        to_status: ModelStatus,
        transitioned_at: i64,
        transitioned_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            transition_id: transition_id.into(),
            model_id: model_id.into(),
            from_status,
            to_status,
            transitioned_at,
            transitioned_by: transitioned_by.into(),
            reason: reason.into(),
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
    fn test_retirement_action_display() {
        let actions = vec![
            RetirementAction::Archive,
            RetirementAction::Delete,
            RetirementAction::Suspend,
            RetirementAction::ReplaceWithSuccessor,
            RetirementAction::Custom { name: "quarantine".into() },
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(actions.len(), 5);
    }

    #[test]
    fn test_deprecation_severity_display() {
        let sevs = vec![
            DeprecationSeverity::Advisory,
            DeprecationSeverity::Warning,
            DeprecationSeverity::Mandatory,
            DeprecationSeverity::Immediate,
        ];
        for s in &sevs {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(sevs.len(), 4);
    }

    #[test]
    fn test_model_lifecycle_policy_construction() {
        let mut policy = ModelLifecyclePolicy::new(
            "mlp-1", "model-1", RetirementAction::Archive, 1000,
        );
        assert!(policy.max_deployment_age_days.is_none());
        assert!(!policy.require_migration_plan);

        policy.max_deployment_age_days = Some("365".into());
        policy.sunset_date = Some(99999);
        policy.replacement_model_id = Some("model-2".into());
        policy.deprecation_notice_days = Some("90".into());
        policy.require_migration_plan = true;
    }

    #[test]
    fn test_deprecation_notice_construction() {
        let mut notice = DeprecationNotice::new(
            "dn-1", "model-1", "1.0.0", 5000,
            "replaced by v2", DeprecationSeverity::Warning,
        );
        assert!(notice.sunset_date.is_none());
        assert!(notice.replacement_model_ref.is_none());
        assert!(notice.acknowledged_by.is_empty());

        notice.sunset_date = Some(99999);
        notice.replacement_model_ref = Some("model-2".into());
        notice.acknowledged_by.push("team-a".into());
        assert_eq!(notice.acknowledged_by.len(), 1);
    }

    #[test]
    fn test_model_lifecycle_transition_construction() {
        let transition = ModelLifecycleTransition::new(
            "mlt-1", "model-1",
            ModelStatus::Deployed, ModelStatus::Deprecated,
            6000, "admin", "end of support",
        );
        assert_eq!(transition.transition_id, "mlt-1");
        assert_eq!(transition.from_status, ModelStatus::Deployed);
        assert_eq!(transition.to_status, ModelStatus::Deprecated);
    }

    #[test]
    fn test_lifecycle_transition_valid() {
        let t = ModelLifecycleTransition::new(
            "mlt-1", "model-1",
            ModelStatus::Deployed, ModelStatus::Deprecated,
            6000, "admin", "sunset",
        );
        assert!(t.from_status.is_valid_transition(&t.to_status));
    }

    #[test]
    fn test_lifecycle_transition_invalid() {
        let t = ModelLifecycleTransition::new(
            "mlt-2", "model-1",
            ModelStatus::Draft, ModelStatus::Deployed,
            6000, "admin", "skip eval",
        );
        assert!(!t.from_status.is_valid_transition(&t.to_status));
    }
}
