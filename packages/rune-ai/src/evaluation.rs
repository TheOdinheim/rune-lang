// ═══════════════════════════════════════════════════════════════════════
// Evaluation — Model evaluation gate types for defining evaluation
// criteria, recording results, and managing pass/fail gates before
// deployment approval.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── ThresholdComparison ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdComparison {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    WithinRange { min: String, max: String },
}

impl fmt::Display for ThresholdComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GreaterThan => f.write_str(">"),
            Self::GreaterThanOrEqual => f.write_str(">="),
            Self::LessThan => f.write_str("<"),
            Self::LessThanOrEqual => f.write_str("<="),
            Self::Equal => f.write_str("=="),
            Self::WithinRange { min, max } => write!(f, "[{min}, {max}]"),
        }
    }
}

// ── EvaluationCriteria ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationCriteria {
    pub criteria_id: String,
    pub criteria_name: String,
    pub metric_name: String,
    pub threshold_value: String,
    pub comparison: ThresholdComparison,
    pub required: bool,
    pub weight: Option<String>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl EvaluationCriteria {
    pub fn new(
        criteria_id: impl Into<String>,
        criteria_name: impl Into<String>,
        metric_name: impl Into<String>,
        threshold_value: impl Into<String>,
        comparison: ThresholdComparison,
        required: bool,
        created_at: i64,
    ) -> Self {
        Self {
            criteria_id: criteria_id.into(),
            criteria_name: criteria_name.into(),
            metric_name: metric_name.into(),
            threshold_value: threshold_value.into(),
            comparison,
            required,
            weight: None,
            created_at,
            metadata: HashMap::new(),
        }
    }
}

// ── EvaluationResult ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationResult {
    pub result_id: String,
    pub model_id: String,
    pub model_version: String,
    pub criteria_id: String,
    pub measured_value: String,
    pub passed: bool,
    pub evaluated_at: i64,
    pub evaluated_by: String,
    pub evidence_ref: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl EvaluationResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        criteria_id: impl Into<String>,
        measured_value: impl Into<String>,
        passed: bool,
        evaluated_at: i64,
        evaluated_by: impl Into<String>,
    ) -> Self {
        Self {
            result_id: result_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            criteria_id: criteria_id.into(),
            measured_value: measured_value.into(),
            passed,
            evaluated_at,
            evaluated_by: evaluated_by.into(),
            evidence_ref: None,
            metadata: HashMap::new(),
        }
    }
}

// ── EvaluationGateStatus ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvaluationGateStatus {
    Open,
    InProgress,
    Passed,
    Failed { failed_criteria: Vec<String> },
    Waived { waived_by: String, reason: String },
}

impl fmt::Display for EvaluationGateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => f.write_str("Open"),
            Self::InProgress => f.write_str("InProgress"),
            Self::Passed => f.write_str("Passed"),
            Self::Failed { failed_criteria } => {
                write!(f, "Failed({})", failed_criteria.join(", "))
            }
            Self::Waived { waived_by, reason } => {
                write!(f, "Waived(by={waived_by}): {reason}")
            }
        }
    }
}

// ── EvaluationGate ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationGate {
    pub gate_id: String,
    pub model_id: String,
    pub required_criteria: Vec<String>,
    pub gate_status: EvaluationGateStatus,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl EvaluationGate {
    pub fn new(
        gate_id: impl Into<String>,
        model_id: impl Into<String>,
        required_criteria: Vec<String>,
        created_at: i64,
    ) -> Self {
        Self {
            gate_id: gate_id.into(),
            model_id: model_id.into(),
            required_criteria,
            gate_status: EvaluationGateStatus::Open,
            created_at,
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
    fn test_threshold_comparison_display() {
        let comps = vec![
            ThresholdComparison::GreaterThan,
            ThresholdComparison::GreaterThanOrEqual,
            ThresholdComparison::LessThan,
            ThresholdComparison::LessThanOrEqual,
            ThresholdComparison::Equal,
            ThresholdComparison::WithinRange { min: "0.0".into(), max: "1.0".into() },
        ];
        for c in &comps {
            assert!(!c.to_string().is_empty());
        }
        assert_eq!(comps.len(), 6);
    }

    #[test]
    fn test_evaluation_gate_status_display() {
        let statuses = vec![
            EvaluationGateStatus::Open,
            EvaluationGateStatus::InProgress,
            EvaluationGateStatus::Passed,
            EvaluationGateStatus::Failed { failed_criteria: vec!["c1".into(), "c2".into()] },
            EvaluationGateStatus::Waived { waived_by: "admin".into(), reason: "emergency".into() },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_evaluation_criteria_construction() {
        let mut criteria = EvaluationCriteria::new(
            "ec-1", "Accuracy Check", "accuracy",
            "0.95", ThresholdComparison::GreaterThanOrEqual,
            true, 1000,
        );
        assert_eq!(criteria.criteria_id, "ec-1");
        assert!(criteria.required);
        assert!(criteria.weight.is_none());
        criteria.weight = Some("1.0".into());
        criteria.metadata.insert("suite".into(), "regression".into());
    }

    #[test]
    fn test_evaluation_result_construction() {
        let mut result = EvaluationResult::new(
            "er-1", "model-1", "1.0.0", "ec-1",
            "0.97", true, 2000, "eval-system",
        );
        assert_eq!(result.result_id, "er-1");
        assert!(result.passed);
        assert!(result.evidence_ref.is_none());
        result.evidence_ref = Some("artifact-123".into());
    }

    #[test]
    fn test_evaluation_gate_construction() {
        let gate = EvaluationGate::new(
            "gate-1", "model-1",
            vec!["ec-1".into(), "ec-2".into()],
            1000,
        );
        assert_eq!(gate.gate_id, "gate-1");
        assert_eq!(gate.gate_status, EvaluationGateStatus::Open);
        assert_eq!(gate.required_criteria.len(), 2);
    }

    #[test]
    fn test_evaluation_result_failed() {
        let result = EvaluationResult::new(
            "er-2", "model-1", "1.0.0", "ec-1",
            "0.80", false, 3000, "eval-system",
        );
        assert!(!result.passed);
        assert_eq!(result.measured_value, "0.80");
    }

    #[test]
    fn test_evaluation_gate_status_transitions() {
        let mut gate = EvaluationGate::new(
            "gate-2", "model-2", vec!["ec-1".into()], 2000,
        );
        assert_eq!(gate.gate_status, EvaluationGateStatus::Open);
        gate.gate_status = EvaluationGateStatus::InProgress;
        assert_eq!(gate.gate_status, EvaluationGateStatus::InProgress);
        gate.gate_status = EvaluationGateStatus::Passed;
        assert_eq!(gate.gate_status, EvaluationGateStatus::Passed);
    }

    #[test]
    fn test_evaluation_criteria_optional_weight() {
        let mut criteria = EvaluationCriteria::new(
            "ec-2", "Latency Check", "p99_latency",
            "100", ThresholdComparison::LessThan,
            false, 1000,
        );
        assert!(!criteria.required);
        assert!(criteria.weight.is_none());
        criteria.weight = Some("0.5".into());
        assert_eq!(criteria.weight, Some("0.5".to_string()));
    }

    #[test]
    fn test_threshold_within_range_display() {
        let comp = ThresholdComparison::WithinRange {
            min: "0.1".into(),
            max: "0.9".into(),
        };
        let display = comp.to_string();
        assert!(display.contains("0.1"));
        assert!(display.contains("0.9"));
    }
}
