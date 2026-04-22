// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Model lifecycle governor trait. Governs model lifecycle
// transitions, deployment readiness, and model health at the integration
// boundary. Reference implementations: InMemoryModelLifecycleGovernor,
// StrictModelLifecycleGovernor, NullModelLifecycleGovernor.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::model_registry::ModelStatus;

// ── TransitionGovernanceDecision ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionGovernanceDecision {
    Approve { reason: String },
    Deny { reason: String, violated_policy_ref: String },
    RequireAdditionalEvaluation { criteria: Vec<String> },
    DeferToHuman { reason: String, escalation_target: String },
}

impl fmt::Display for TransitionGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approve { reason } => write!(f, "Approve: {reason}"),
            Self::Deny { reason, .. } => write!(f, "Deny: {reason}"),
            Self::RequireAdditionalEvaluation { criteria } => {
                write!(f, "RequireAdditionalEvaluation({})", criteria.join(", "))
            }
            Self::DeferToHuman { reason, .. } => write!(f, "DeferToHuman: {reason}"),
        }
    }
}

// ── DeploymentGovernanceDecision ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentGovernanceDecision {
    Approve { environment: String, conditions: Vec<String> },
    Deny { reason: String },
    RequireApproval { approver_role: String },
    ConditionalApprove { conditions: Vec<String> },
}

impl fmt::Display for DeploymentGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approve { environment, .. } => write!(f, "Approve(env={environment})"),
            Self::Deny { reason } => write!(f, "Deny: {reason}"),
            Self::RequireApproval { approver_role } => {
                write!(f, "RequireApproval(role={approver_role})")
            }
            Self::ConditionalApprove { conditions } => {
                write!(f, "ConditionalApprove({})", conditions.join(", "))
            }
        }
    }
}

// ── ModelHealthStatus ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelHealthStatus {
    Healthy,
    Degraded { reason: String },
    AtRisk { reason: String },
    RequiresRetirement { reason: String },
}

impl fmt::Display for ModelHealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => f.write_str("Healthy"),
            Self::Degraded { reason } => write!(f, "Degraded: {reason}"),
            Self::AtRisk { reason } => write!(f, "AtRisk: {reason}"),
            Self::RequiresRetirement { reason } => write!(f, "RequiresRetirement: {reason}"),
        }
    }
}

// ── ModelHealthAssessment ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelHealthAssessment {
    pub model_id: String,
    pub health_status: ModelHealthStatus,
    pub drift_status: Option<String>,
    pub fairness_status: Option<String>,
    pub last_evaluation_age_days: Option<String>,
    pub assessed_at: i64,
}

// ── ModelLifecycleGovernor trait ────────────────────────────────────

pub trait ModelLifecycleGovernor {
    fn evaluate_transition_request(
        &self,
        model_id: &str,
        current_status: &ModelStatus,
        requested_status: &ModelStatus,
        actor: &str,
        reason: &str,
    ) -> TransitionGovernanceDecision;

    fn evaluate_deployment_readiness(
        &self,
        model_id: &str,
        environment: &str,
    ) -> DeploymentGovernanceDecision;

    fn check_model_health(
        &self,
        model_id: &str,
        assessed_at: i64,
    ) -> ModelHealthAssessment;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryModelLifecycleGovernor ─────────────────────────────────

pub struct InMemoryModelLifecycleGovernor {
    governor_id: String,
    active: bool,
}

impl InMemoryModelLifecycleGovernor {
    pub fn new(governor_id: impl Into<String>) -> Self {
        Self {
            governor_id: governor_id.into(),
            active: true,
        }
    }
}

impl ModelLifecycleGovernor for InMemoryModelLifecycleGovernor {
    fn evaluate_transition_request(
        &self,
        _model_id: &str,
        current_status: &ModelStatus,
        requested_status: &ModelStatus,
        _actor: &str,
        _reason: &str,
    ) -> TransitionGovernanceDecision {
        if current_status.is_valid_transition(requested_status) {
            TransitionGovernanceDecision::Approve {
                reason: format!("Transition from {} to {} is valid", current_status, requested_status),
            }
        } else {
            TransitionGovernanceDecision::Deny {
                reason: format!("Invalid transition from {} to {}", current_status, requested_status),
                violated_policy_ref: "model_status_state_machine".to_string(),
            }
        }
    }

    fn evaluate_deployment_readiness(
        &self,
        model_id: &str,
        environment: &str,
    ) -> DeploymentGovernanceDecision {
        DeploymentGovernanceDecision::Approve {
            environment: environment.to_string(),
            conditions: vec![format!("Model {model_id} approved for deployment")],
        }
    }

    fn check_model_health(
        &self,
        model_id: &str,
        assessed_at: i64,
    ) -> ModelHealthAssessment {
        ModelHealthAssessment {
            model_id: model_id.to_string(),
            health_status: ModelHealthStatus::Healthy,
            drift_status: None,
            fairness_status: None,
            last_evaluation_age_days: None,
            assessed_at,
        }
    }

    fn governor_id(&self) -> &str {
        &self.governor_id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── StrictModelLifecycleGovernor ───────────────────────────────────

/// Denies transitions that skip the evaluation gate — specifically
/// denies Registered→Deployed without going through
/// UnderEvaluation→Approved first. Prevents evaluation-gate bypass.
pub struct StrictModelLifecycleGovernor {
    governor_id: String,
    active: bool,
}

impl StrictModelLifecycleGovernor {
    pub fn new(governor_id: impl Into<String>) -> Self {
        Self {
            governor_id: governor_id.into(),
            active: true,
        }
    }

    fn requires_evaluation_path(current: &ModelStatus, requested: &ModelStatus) -> bool {
        // Deny transitions to Deployed unless coming from Approved.
        // This prevents any future state machine relaxation from
        // bypassing the evaluation gate.
        if matches!(requested, ModelStatus::Deployed) && !matches!(current, ModelStatus::Approved) {
            return true;
        }
        // Deny transitions to Approved unless coming from UnderEvaluation.
        if matches!(requested, ModelStatus::Approved) && !matches!(current, ModelStatus::UnderEvaluation) {
            return true;
        }
        false
    }
}

impl ModelLifecycleGovernor for StrictModelLifecycleGovernor {
    fn evaluate_transition_request(
        &self,
        _model_id: &str,
        current_status: &ModelStatus,
        requested_status: &ModelStatus,
        _actor: &str,
        _reason: &str,
    ) -> TransitionGovernanceDecision {
        if !current_status.is_valid_transition(requested_status) {
            return TransitionGovernanceDecision::Deny {
                reason: format!("Invalid transition from {} to {}", current_status, requested_status),
                violated_policy_ref: "model_status_state_machine".to_string(),
            };
        }

        if Self::requires_evaluation_path(current_status, requested_status) {
            return TransitionGovernanceDecision::Deny {
                reason: format!(
                    "Strict policy requires evaluation path: {} must go through UnderEvaluation before {}",
                    current_status, requested_status
                ),
                violated_policy_ref: "strict_evaluation_gate_policy".to_string(),
            };
        }

        TransitionGovernanceDecision::Approve {
            reason: format!("Transition from {} to {} approved by strict governor", current_status, requested_status),
        }
    }

    fn evaluate_deployment_readiness(
        &self,
        _model_id: &str,
        _environment: &str,
    ) -> DeploymentGovernanceDecision {
        DeploymentGovernanceDecision::RequireApproval {
            approver_role: "model_governance_officer".to_string(),
        }
    }

    fn check_model_health(
        &self,
        model_id: &str,
        assessed_at: i64,
    ) -> ModelHealthAssessment {
        ModelHealthAssessment {
            model_id: model_id.to_string(),
            health_status: ModelHealthStatus::Healthy,
            drift_status: None,
            fairness_status: None,
            last_evaluation_age_days: None,
            assessed_at,
        }
    }

    fn governor_id(&self) -> &str {
        &self.governor_id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullModelLifecycleGovernor ─────────────────────────────────────

pub struct NullModelLifecycleGovernor;

impl ModelLifecycleGovernor for NullModelLifecycleGovernor {
    fn evaluate_transition_request(
        &self,
        _model_id: &str,
        _current_status: &ModelStatus,
        _requested_status: &ModelStatus,
        _actor: &str,
        _reason: &str,
    ) -> TransitionGovernanceDecision {
        TransitionGovernanceDecision::Approve {
            reason: "Null governor approves all transitions".to_string(),
        }
    }

    fn evaluate_deployment_readiness(
        &self,
        _model_id: &str,
        environment: &str,
    ) -> DeploymentGovernanceDecision {
        DeploymentGovernanceDecision::Approve {
            environment: environment.to_string(),
            conditions: Vec::new(),
        }
    }

    fn check_model_health(
        &self,
        model_id: &str,
        assessed_at: i64,
    ) -> ModelHealthAssessment {
        ModelHealthAssessment {
            model_id: model_id.to_string(),
            health_status: ModelHealthStatus::Healthy,
            drift_status: None,
            fairness_status: None,
            last_evaluation_age_days: None,
            assessed_at,
        }
    }

    fn governor_id(&self) -> &str {
        "null-lifecycle-governor"
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

    #[test]
    fn test_inmemory_valid_transition() {
        let gov = InMemoryModelLifecycleGovernor::new("gov-1");
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Draft, &ModelStatus::Registered, "alice", "init",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Approve { .. }));
    }

    #[test]
    fn test_inmemory_invalid_transition() {
        let gov = InMemoryModelLifecycleGovernor::new("gov-1");
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Draft, &ModelStatus::Deployed, "alice", "skip",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Deny { .. }));
    }

    #[test]
    fn test_inmemory_deployment_readiness() {
        let gov = InMemoryModelLifecycleGovernor::new("gov-1");
        let decision = gov.evaluate_deployment_readiness("m-1", "Production");
        assert!(matches!(decision, DeploymentGovernanceDecision::Approve { .. }));
    }

    #[test]
    fn test_inmemory_health_check() {
        let gov = InMemoryModelLifecycleGovernor::new("gov-1");
        let health = gov.check_model_health("m-1", 5000);
        assert_eq!(health.health_status, ModelHealthStatus::Healthy);
        assert_eq!(health.model_id, "m-1");
    }

    #[test]
    fn test_inmemory_governor_identity() {
        let gov = InMemoryModelLifecycleGovernor::new("gov-1");
        assert_eq!(gov.governor_id(), "gov-1");
        assert!(gov.is_active());
    }

    #[test]
    fn test_strict_denies_evaluation_skip() {
        let gov = StrictModelLifecycleGovernor::new("strict-1");
        // Registered→Deployed is invalid per state machine AND would be
        // caught by strict governor's evaluation-gate check. The first
        // check (state machine) denies it.
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Registered, &ModelStatus::Deployed, "alice", "fast-track",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Deny { .. }));
        if let TransitionGovernanceDecision::Deny { violated_policy_ref, .. } = &decision {
            assert_eq!(violated_policy_ref, "model_status_state_machine");
        }
    }

    #[test]
    fn test_strict_allows_valid_non_skip_transition() {
        let gov = StrictModelLifecycleGovernor::new("strict-1");
        // Registered→UnderEvaluation is fine
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Registered, &ModelStatus::UnderEvaluation, "alice", "evaluate",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Approve { .. }));
    }

    #[test]
    fn test_strict_denies_invalid_transition() {
        let gov = StrictModelLifecycleGovernor::new("strict-1");
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Draft, &ModelStatus::Deployed, "alice", "skip",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Deny { .. }));
    }

    #[test]
    fn test_strict_deployment_requires_approval() {
        let gov = StrictModelLifecycleGovernor::new("strict-1");
        let decision = gov.evaluate_deployment_readiness("m-1", "Production");
        assert!(matches!(decision, DeploymentGovernanceDecision::RequireApproval { .. }));
    }

    #[test]
    fn test_null_approves_all() {
        let gov = NullModelLifecycleGovernor;
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Draft, &ModelStatus::Deployed, "alice", "skip",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Approve { .. }));
    }

    #[test]
    fn test_null_is_inactive() {
        let gov = NullModelLifecycleGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-lifecycle-governor");
    }

    #[test]
    fn test_transition_decision_display() {
        let d = TransitionGovernanceDecision::Approve { reason: "ok".into() };
        assert!(d.to_string().contains("Approve"));
        let d = TransitionGovernanceDecision::DeferToHuman {
            reason: "complex".into(), escalation_target: "admin".into(),
        };
        assert!(d.to_string().contains("DeferToHuman"));
    }

    #[test]
    fn test_deployment_decision_display() {
        let d = DeploymentGovernanceDecision::Deny { reason: "no".into() };
        assert!(d.to_string().contains("Deny"));
        let d = DeploymentGovernanceDecision::ConditionalApprove {
            conditions: vec!["load test".into()],
        };
        assert!(d.to_string().contains("ConditionalApprove"));
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(ModelHealthStatus::Healthy.to_string(), "Healthy");
        let d = ModelHealthStatus::RequiresRetirement { reason: "eol".into() };
        assert!(d.to_string().contains("RequiresRetirement"));
    }

    #[test]
    fn test_strict_approved_to_deployed() {
        let gov = StrictModelLifecycleGovernor::new("strict-1");
        // Approved→Deployed is fine — the model passed evaluation
        let decision = gov.evaluate_transition_request(
            "m-1", &ModelStatus::Approved, &ModelStatus::Deployed, "alice", "deploy",
        );
        assert!(matches!(decision, TransitionGovernanceDecision::Approve { .. }));
    }
}
