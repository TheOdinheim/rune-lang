// ═══════════════════════════════════════════════════════════════════════
// Decision — core decision records for explainability.
//
// DecisionStore holds Decision records, each with an outcome, context,
// and weighted factors. DecisionId is a newtype wrapper around String.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::ExplainabilityError;

// ── DecisionId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecisionId(pub String);

impl DecisionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DecisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DecisionId {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

// ── DecisionType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionType {
    AccessControl,
    PolicyEnforcement,
    RiskAssessment,
    ThreatResponse,
    DataClassification,
    PrivacyAction,
    ModelGovernance,
    ComplianceCheck,
    ResourceAllocation,
    EscalationRouting,
    AuditDisposition,
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessControl => f.write_str("access-control"),
            Self::PolicyEnforcement => f.write_str("policy-enforcement"),
            Self::RiskAssessment => f.write_str("risk-assessment"),
            Self::ThreatResponse => f.write_str("threat-response"),
            Self::DataClassification => f.write_str("data-classification"),
            Self::PrivacyAction => f.write_str("privacy-action"),
            Self::ModelGovernance => f.write_str("model-governance"),
            Self::ComplianceCheck => f.write_str("compliance-check"),
            Self::ResourceAllocation => f.write_str("resource-allocation"),
            Self::EscalationRouting => f.write_str("escalation-routing"),
            Self::AuditDisposition => f.write_str("audit-disposition"),
        }
    }
}

// ── DecisionOutcome ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionOutcome {
    Approved,
    Denied,
    Escalated,
    Deferred,
    ConditionallyApproved { conditions: Vec<String> },
    Error { reason: String },
}

impl fmt::Display for DecisionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => f.write_str("approved"),
            Self::Denied => f.write_str("denied"),
            Self::Escalated => f.write_str("escalated"),
            Self::Deferred => f.write_str("deferred"),
            Self::ConditionallyApproved { conditions } => {
                write!(f, "conditionally-approved ({})", conditions.join(", "))
            }
            Self::Error { reason } => write!(f, "error: {reason}"),
        }
    }
}

// ── FactorType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorType {
    SecurityPolicy,
    RiskScore,
    TrustLevel,
    ComplianceRequirement,
    HistoricalPattern,
    UserReputation,
    ContextualSignal,
    ThresholdExceedance,
    PeerDecision,
    TemporalConstraint,
    ResourceAvailability,
}

impl fmt::Display for FactorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityPolicy => f.write_str("security-policy"),
            Self::RiskScore => f.write_str("risk-score"),
            Self::TrustLevel => f.write_str("trust-level"),
            Self::ComplianceRequirement => f.write_str("compliance-requirement"),
            Self::HistoricalPattern => f.write_str("historical-pattern"),
            Self::UserReputation => f.write_str("user-reputation"),
            Self::ContextualSignal => f.write_str("contextual-signal"),
            Self::ThresholdExceedance => f.write_str("threshold-exceedance"),
            Self::PeerDecision => f.write_str("peer-decision"),
            Self::TemporalConstraint => f.write_str("temporal-constraint"),
            Self::ResourceAvailability => f.write_str("resource-availability"),
        }
    }
}

// ── FactorDirection ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorDirection {
    Supporting,
    Opposing,
    Neutral,
}

impl fmt::Display for FactorDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supporting => f.write_str("supporting"),
            Self::Opposing => f.write_str("opposing"),
            Self::Neutral => f.write_str("neutral"),
        }
    }
}

// ── DecisionFactor ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecisionFactor {
    pub name: String,
    pub factor_type: FactorType,
    pub direction: FactorDirection,
    pub weight: f64,
    pub value: String,
    pub description: String,
}

impl DecisionFactor {
    pub fn new(
        name: impl Into<String>,
        factor_type: FactorType,
        direction: FactorDirection,
        weight: f64,
        value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            factor_type,
            direction,
            weight,
            value: value.into(),
            description: String::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ── DecisionContext ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DecisionContext {
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub environment: HashMap<String, String>,
    pub timestamp: i64,
}

impl DecisionContext {
    pub fn new(
        subject: impl Into<String>,
        resource: impl Into<String>,
        action: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            subject: subject.into(),
            resource: resource.into(),
            action: action.into(),
            environment: HashMap::new(),
            timestamp,
        }
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }
}

// ── Decision ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Decision {
    pub id: DecisionId,
    pub decision_type: DecisionType,
    pub outcome: DecisionOutcome,
    pub context: DecisionContext,
    pub factors: Vec<DecisionFactor>,
    pub made_at: i64,
    pub made_by: String,
    pub rationale: String,
    pub parent_decision: Option<DecisionId>,
}

impl Decision {
    pub fn new(
        id: DecisionId,
        decision_type: DecisionType,
        outcome: DecisionOutcome,
        context: DecisionContext,
        made_by: impl Into<String>,
        made_at: i64,
    ) -> Self {
        Self {
            id,
            decision_type,
            outcome,
            context,
            factors: Vec::new(),
            made_at,
            made_by: made_by.into(),
            rationale: String::new(),
            parent_decision: None,
        }
    }

    pub fn with_factor(mut self, factor: DecisionFactor) -> Self {
        self.factors.push(factor);
        self
    }

    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = rationale.into();
        self
    }

    pub fn with_parent(mut self, parent: DecisionId) -> Self {
        self.parent_decision = Some(parent);
        self
    }
}

// ── DecisionStore ───────────────────────────────────────────────────

#[derive(Default)]
pub struct DecisionStore {
    decisions: HashMap<DecisionId, Decision>,
}

impl DecisionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        decision: Decision,
    ) -> Result<(), ExplainabilityError> {
        if self.decisions.contains_key(&decision.id) {
            return Err(ExplainabilityError::DecisionAlreadyExists(
                decision.id.0.clone(),
            ));
        }
        self.decisions.insert(decision.id.clone(), decision);
        Ok(())
    }

    pub fn get(&self, id: &DecisionId) -> Option<&Decision> {
        self.decisions.get(id)
    }

    pub fn get_by_type(&self, dt: &DecisionType) -> Vec<&Decision> {
        self.decisions
            .values()
            .filter(|d| &d.decision_type == dt)
            .collect()
    }

    pub fn get_by_outcome(&self, outcome_tag: &str) -> Vec<&Decision> {
        self.decisions
            .values()
            .filter(|d| {
                let tag = match &d.outcome {
                    DecisionOutcome::Approved => "approved",
                    DecisionOutcome::Denied => "denied",
                    DecisionOutcome::Escalated => "escalated",
                    DecisionOutcome::Deferred => "deferred",
                    DecisionOutcome::ConditionallyApproved { .. } => "conditionally-approved",
                    DecisionOutcome::Error { .. } => "error",
                };
                tag == outcome_tag
            })
            .collect()
    }

    pub fn children_of(&self, parent: &DecisionId) -> Vec<&Decision> {
        self.decisions
            .values()
            .filter(|d| d.parent_decision.as_ref() == Some(parent))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.decisions.len()
    }

    pub fn all(&self) -> Vec<&Decision> {
        self.decisions.values().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> DecisionContext {
        DecisionContext::new("user-alice", "resource-db", "read", 1000)
    }

    fn sample_decision(id: &str) -> Decision {
        Decision::new(
            DecisionId::new(id),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            sample_context(),
            "policy-engine",
            1000,
        )
    }

    #[test]
    fn test_decision_id_display() {
        let id = DecisionId::new("d-123");
        assert_eq!(id.to_string(), "d-123");
        assert_eq!(id.as_str(), "d-123");
    }

    #[test]
    fn test_decision_id_from_str() {
        let id: DecisionId = "d-456".into();
        assert_eq!(id.0, "d-456");
    }

    #[test]
    fn test_decision_type_display() {
        assert_eq!(DecisionType::AccessControl.to_string(), "access-control");
        assert_eq!(DecisionType::PolicyEnforcement.to_string(), "policy-enforcement");
        assert_eq!(DecisionType::RiskAssessment.to_string(), "risk-assessment");
        assert_eq!(DecisionType::ThreatResponse.to_string(), "threat-response");
        assert_eq!(DecisionType::DataClassification.to_string(), "data-classification");
        assert_eq!(DecisionType::PrivacyAction.to_string(), "privacy-action");
        assert_eq!(DecisionType::ModelGovernance.to_string(), "model-governance");
        assert_eq!(DecisionType::ComplianceCheck.to_string(), "compliance-check");
        assert_eq!(DecisionType::ResourceAllocation.to_string(), "resource-allocation");
        assert_eq!(DecisionType::EscalationRouting.to_string(), "escalation-routing");
        assert_eq!(DecisionType::AuditDisposition.to_string(), "audit-disposition");
    }

    #[test]
    fn test_decision_outcome_display() {
        assert_eq!(DecisionOutcome::Approved.to_string(), "approved");
        assert_eq!(DecisionOutcome::Denied.to_string(), "denied");
        assert_eq!(DecisionOutcome::Escalated.to_string(), "escalated");
        assert_eq!(DecisionOutcome::Deferred.to_string(), "deferred");
        let cond = DecisionOutcome::ConditionallyApproved {
            conditions: vec!["mfa".into(), "audit".into()],
        };
        assert!(cond.to_string().contains("mfa"));
        let err = DecisionOutcome::Error { reason: "timeout".into() };
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_factor_type_display() {
        assert_eq!(FactorType::SecurityPolicy.to_string(), "security-policy");
        assert_eq!(FactorType::RiskScore.to_string(), "risk-score");
        assert_eq!(FactorType::TrustLevel.to_string(), "trust-level");
    }

    #[test]
    fn test_factor_direction_display() {
        assert_eq!(FactorDirection::Supporting.to_string(), "supporting");
        assert_eq!(FactorDirection::Opposing.to_string(), "opposing");
        assert_eq!(FactorDirection::Neutral.to_string(), "neutral");
    }

    #[test]
    fn test_decision_factor_builder() {
        let f = DecisionFactor::new(
            "policy-check",
            FactorType::SecurityPolicy,
            FactorDirection::Supporting,
            0.8,
            "pass",
        )
        .with_description("Policy passed all checks");
        assert_eq!(f.name, "policy-check");
        assert_eq!(f.description, "Policy passed all checks");
    }

    #[test]
    fn test_decision_context_builder() {
        let ctx = DecisionContext::new("alice", "db", "read", 1000)
            .with_env("ip", "10.0.0.1")
            .with_env("region", "us-east");
        assert_eq!(ctx.environment.len(), 2);
        assert_eq!(ctx.environment["ip"], "10.0.0.1");
    }

    #[test]
    fn test_decision_builder() {
        let d = sample_decision("d1")
            .with_factor(DecisionFactor::new(
                "risk",
                FactorType::RiskScore,
                FactorDirection::Opposing,
                0.6,
                "high",
            ))
            .with_rationale("Low risk user")
            .with_parent(DecisionId::new("d0"));
        assert_eq!(d.factors.len(), 1);
        assert_eq!(d.rationale, "Low risk user");
        assert_eq!(d.parent_decision.unwrap().0, "d0");
    }

    #[test]
    fn test_store_register_and_get() {
        let mut store = DecisionStore::new();
        store.register(sample_decision("d1")).unwrap();
        assert!(store.get(&DecisionId::new("d1")).is_some());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_store_duplicate_rejected() {
        let mut store = DecisionStore::new();
        store.register(sample_decision("d1")).unwrap();
        let result = store.register(sample_decision("d1"));
        assert!(matches!(
            result,
            Err(ExplainabilityError::DecisionAlreadyExists(_))
        ));
    }

    #[test]
    fn test_store_get_by_type() {
        let mut store = DecisionStore::new();
        store.register(sample_decision("d1")).unwrap();
        store
            .register(Decision::new(
                DecisionId::new("d2"),
                DecisionType::RiskAssessment,
                DecisionOutcome::Denied,
                sample_context(),
                "engine",
                2000,
            ))
            .unwrap();
        assert_eq!(store.get_by_type(&DecisionType::AccessControl).len(), 1);
        assert_eq!(store.get_by_type(&DecisionType::RiskAssessment).len(), 1);
    }

    #[test]
    fn test_store_get_by_outcome() {
        let mut store = DecisionStore::new();
        store.register(sample_decision("d1")).unwrap();
        store
            .register(Decision::new(
                DecisionId::new("d2"),
                DecisionType::AccessControl,
                DecisionOutcome::Denied,
                sample_context(),
                "engine",
                2000,
            ))
            .unwrap();
        assert_eq!(store.get_by_outcome("approved").len(), 1);
        assert_eq!(store.get_by_outcome("denied").len(), 1);
    }

    #[test]
    fn test_store_children_of() {
        let mut store = DecisionStore::new();
        store.register(sample_decision("d1")).unwrap();
        store
            .register(sample_decision("d2").with_parent(DecisionId::new("d1")))
            .unwrap();
        store
            .register(sample_decision("d3").with_parent(DecisionId::new("d1")))
            .unwrap();
        assert_eq!(store.children_of(&DecisionId::new("d1")).len(), 2);
    }

    #[test]
    fn test_store_all() {
        let mut store = DecisionStore::new();
        store.register(sample_decision("d1")).unwrap();
        store.register(sample_decision("d2")).unwrap();
        assert_eq!(store.all().len(), 2);
    }
}
