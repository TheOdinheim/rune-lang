// ═══════════════════════════════════════════════════════════════════════
// Trace — decision trace reconstruction.
//
// DecisionTracer walks backward from a decision outcome through its
// factors to identify root causes. Each step in the trace represents
// one factor's contribution, and root causes explain why the decisive
// factors had the values they did.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::decision::{Decision, DecisionFactor, DecisionId, DecisionStore, FactorDirection};

// ── RootCauseType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootCauseType {
    PolicyRule,
    RiskThreshold,
    TrustDeficiency,
    ComplianceViolation,
    AnomalyDetected,
    ReputationScore,
    ContextMismatch,
    ResourceConstraint,
    TemporalExpiry,
    PrecedentBased,
    Unknown,
}

impl fmt::Display for RootCauseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyRule => f.write_str("policy-rule"),
            Self::RiskThreshold => f.write_str("risk-threshold"),
            Self::TrustDeficiency => f.write_str("trust-deficiency"),
            Self::ComplianceViolation => f.write_str("compliance-violation"),
            Self::AnomalyDetected => f.write_str("anomaly-detected"),
            Self::ReputationScore => f.write_str("reputation-score"),
            Self::ContextMismatch => f.write_str("context-mismatch"),
            Self::ResourceConstraint => f.write_str("resource-constraint"),
            Self::TemporalExpiry => f.write_str("temporal-expiry"),
            Self::PrecedentBased => f.write_str("precedent-based"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ── RootCause ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RootCause {
    pub cause_type: RootCauseType,
    pub description: String,
    pub factor_name: String,
    pub confidence: f64,
}

impl RootCause {
    pub fn new(
        cause_type: RootCauseType,
        factor_name: impl Into<String>,
        description: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            cause_type,
            description: description.into(),
            factor_name: factor_name.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

// ── TraceStep ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TraceStep {
    pub step_index: usize,
    pub factor_name: String,
    pub factor_value: String,
    pub direction: FactorDirection,
    pub weight: f64,
    pub contribution: f64,
    pub explanation: String,
}

// ── DecisionTrace ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecisionTrace {
    pub decision_id: DecisionId,
    pub steps: Vec<TraceStep>,
    pub root_causes: Vec<RootCause>,
    pub summary: String,
    pub traced_at: i64,
}

impl DecisionTrace {
    pub fn decisive_factor(&self) -> Option<&TraceStep> {
        self.steps
            .iter()
            .max_by(|a, b| a.contribution.abs().partial_cmp(&b.contribution.abs()).unwrap())
    }

    pub fn supporting_steps(&self) -> Vec<&TraceStep> {
        self.steps
            .iter()
            .filter(|s| s.direction == FactorDirection::Supporting)
            .collect()
    }

    pub fn opposing_steps(&self) -> Vec<&TraceStep> {
        self.steps
            .iter()
            .filter(|s| s.direction == FactorDirection::Opposing)
            .collect()
    }
}

// ── DecisionTracer ──────────────────────────────────────────────────

pub struct DecisionTracer;

impl DecisionTracer {
    pub fn new() -> Self {
        Self
    }

    pub fn trace(&self, decision: &Decision, now: i64) -> DecisionTrace {
        let total_weight: f64 = decision.factors.iter().map(|f| f.weight.abs()).sum();
        let norm = if total_weight > 0.0 { total_weight } else { 1.0 };

        let steps: Vec<TraceStep> = decision
            .factors
            .iter()
            .enumerate()
            .map(|(i, factor)| {
                let sign = match factor.direction {
                    FactorDirection::Supporting => 1.0,
                    FactorDirection::Opposing => -1.0,
                    FactorDirection::Neutral => 0.0,
                };
                let contribution = (factor.weight / norm) * sign;
                TraceStep {
                    step_index: i,
                    factor_name: factor.name.clone(),
                    factor_value: factor.value.clone(),
                    direction: factor.direction.clone(),
                    weight: factor.weight,
                    contribution,
                    explanation: if factor.description.is_empty() {
                        format!(
                            "{} ({}) contributed {:.1}% to outcome",
                            factor.name,
                            factor.direction,
                            contribution.abs() * 100.0
                        )
                    } else {
                        factor.description.clone()
                    },
                }
            })
            .collect();

        let root_causes = self.identify_root_causes(&decision.factors);

        let summary = format!(
            "Decision {} ({}) resulted in {} based on {} factors",
            decision.id,
            decision.decision_type,
            decision.outcome,
            steps.len()
        );

        DecisionTrace {
            decision_id: decision.id.clone(),
            steps,
            root_causes,
            summary,
            traced_at: now,
        }
    }

    pub fn trace_from_store(
        &self,
        store: &DecisionStore,
        id: &DecisionId,
        now: i64,
    ) -> Option<DecisionTrace> {
        store.get(id).map(|d| self.trace(d, now))
    }

    fn identify_root_causes(&self, factors: &[DecisionFactor]) -> Vec<RootCause> {
        factors
            .iter()
            .filter(|f| f.direction != FactorDirection::Neutral)
            .map(|f| {
                let cause_type = match f.factor_type {
                    crate::decision::FactorType::SecurityPolicy => RootCauseType::PolicyRule,
                    crate::decision::FactorType::RiskScore => RootCauseType::RiskThreshold,
                    crate::decision::FactorType::TrustLevel => RootCauseType::TrustDeficiency,
                    crate::decision::FactorType::ComplianceRequirement => {
                        RootCauseType::ComplianceViolation
                    }
                    crate::decision::FactorType::HistoricalPattern => RootCauseType::PrecedentBased,
                    crate::decision::FactorType::UserReputation => RootCauseType::ReputationScore,
                    crate::decision::FactorType::ContextualSignal => RootCauseType::ContextMismatch,
                    crate::decision::FactorType::ThresholdExceedance => {
                        RootCauseType::RiskThreshold
                    }
                    crate::decision::FactorType::PeerDecision => RootCauseType::PrecedentBased,
                    crate::decision::FactorType::TemporalConstraint => {
                        RootCauseType::TemporalExpiry
                    }
                    crate::decision::FactorType::ResourceAvailability => {
                        RootCauseType::ResourceConstraint
                    }
                };
                RootCause::new(
                    cause_type,
                    &f.name,
                    if f.description.is_empty() {
                        format!("{} was {}", f.name, f.value)
                    } else {
                        f.description.clone()
                    },
                    f.weight.clamp(0.0, 1.0),
                )
            })
            .collect()
    }
}

impl Default for DecisionTracer {
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
    use crate::decision::*;

    fn sample_context() -> DecisionContext {
        DecisionContext::new("alice", "db", "read", 1000)
    }

    fn decision_with_factors() -> Decision {
        Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            sample_context(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "policy-check",
            FactorType::SecurityPolicy,
            FactorDirection::Opposing,
            0.7,
            "deny-rule-matched",
        ))
        .with_factor(DecisionFactor::new(
            "trust-score",
            FactorType::TrustLevel,
            FactorDirection::Supporting,
            0.3,
            "0.85",
        ))
    }

    #[test]
    fn test_trace_basic() {
        let tracer = DecisionTracer::new();
        let trace = tracer.trace(&decision_with_factors(), 2000);
        assert_eq!(trace.decision_id, DecisionId::new("d1"));
        assert_eq!(trace.steps.len(), 2);
        assert!(!trace.summary.is_empty());
    }

    #[test]
    fn test_trace_contributions_normalized() {
        let tracer = DecisionTracer::new();
        let trace = tracer.trace(&decision_with_factors(), 2000);
        let total: f64 = trace.steps.iter().map(|s| s.contribution.abs()).sum();
        assert!((total - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_decisive_factor() {
        let tracer = DecisionTracer::new();
        let trace = tracer.trace(&decision_with_factors(), 2000);
        let decisive = trace.decisive_factor().unwrap();
        assert_eq!(decisive.factor_name, "policy-check");
    }

    #[test]
    fn test_supporting_opposing_steps() {
        let tracer = DecisionTracer::new();
        let trace = tracer.trace(&decision_with_factors(), 2000);
        assert_eq!(trace.supporting_steps().len(), 1);
        assert_eq!(trace.opposing_steps().len(), 1);
    }

    #[test]
    fn test_root_causes_identified() {
        let tracer = DecisionTracer::new();
        let trace = tracer.trace(&decision_with_factors(), 2000);
        assert_eq!(trace.root_causes.len(), 2);
        assert_eq!(trace.root_causes[0].cause_type, RootCauseType::PolicyRule);
        assert_eq!(trace.root_causes[1].cause_type, RootCauseType::TrustDeficiency);
    }

    #[test]
    fn test_root_cause_type_display() {
        assert_eq!(RootCauseType::PolicyRule.to_string(), "policy-rule");
        assert_eq!(RootCauseType::RiskThreshold.to_string(), "risk-threshold");
        assert_eq!(RootCauseType::TrustDeficiency.to_string(), "trust-deficiency");
        assert_eq!(RootCauseType::ComplianceViolation.to_string(), "compliance-violation");
        assert_eq!(RootCauseType::AnomalyDetected.to_string(), "anomaly-detected");
        assert_eq!(RootCauseType::ReputationScore.to_string(), "reputation-score");
        assert_eq!(RootCauseType::ContextMismatch.to_string(), "context-mismatch");
        assert_eq!(RootCauseType::ResourceConstraint.to_string(), "resource-constraint");
        assert_eq!(RootCauseType::TemporalExpiry.to_string(), "temporal-expiry");
        assert_eq!(RootCauseType::PrecedentBased.to_string(), "precedent-based");
        assert_eq!(RootCauseType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_trace_from_store() {
        let tracer = DecisionTracer::new();
        let mut store = DecisionStore::new();
        store.register(decision_with_factors()).unwrap();
        let trace = tracer
            .trace_from_store(&store, &DecisionId::new("d1"), 2000)
            .unwrap();
        assert_eq!(trace.steps.len(), 2);
    }

    #[test]
    fn test_trace_from_store_missing() {
        let tracer = DecisionTracer::new();
        let store = DecisionStore::new();
        assert!(tracer
            .trace_from_store(&store, &DecisionId::new("d1"), 2000)
            .is_none());
    }

    #[test]
    fn test_trace_no_factors() {
        let tracer = DecisionTracer::new();
        let d = Decision::new(
            DecisionId::new("d-empty"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            sample_context(),
            "engine",
            1000,
        );
        let trace = tracer.trace(&d, 2000);
        assert!(trace.steps.is_empty());
        assert!(trace.root_causes.is_empty());
    }

    #[test]
    fn test_neutral_factor_zero_contribution() {
        let tracer = DecisionTracer::new();
        let d = Decision::new(
            DecisionId::new("d-neutral"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            sample_context(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "info",
            FactorType::ContextualSignal,
            FactorDirection::Neutral,
            0.5,
            "noted",
        ));
        let trace = tracer.trace(&d, 2000);
        assert_eq!(trace.steps[0].contribution, 0.0);
        // Neutral factors don't produce root causes
        assert!(trace.root_causes.is_empty());
    }

    #[test]
    fn test_root_cause_confidence_clamped() {
        let rc = RootCause::new(RootCauseType::PolicyRule, "f1", "desc", 1.5);
        assert_eq!(rc.confidence, 1.0);
        let rc2 = RootCause::new(RootCauseType::PolicyRule, "f2", "desc", -0.5);
        assert_eq!(rc2.confidence, 0.0);
    }
}
