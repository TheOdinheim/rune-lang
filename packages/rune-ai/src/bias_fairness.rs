// ═══════════════════════════════════════════════════════════════════════
// Bias & Fairness — Bias and fairness monitoring policy types for
// protected attribute tracking, fairness metric definition, and
// assessment recording. EU AI Act Article 10 and ECOA compliance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evaluation::ThresholdComparison;

// ── ProtectedAttributeType ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectedAttributeType {
    Race,
    Gender,
    Age,
    Disability,
    Religion,
    NationalOrigin,
    SexualOrientation,
    Custom { name: String },
}

impl fmt::Display for ProtectedAttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Race => f.write_str("Race"),
            Self::Gender => f.write_str("Gender"),
            Self::Age => f.write_str("Age"),
            Self::Disability => f.write_str("Disability"),
            Self::Religion => f.write_str("Religion"),
            Self::NationalOrigin => f.write_str("NationalOrigin"),
            Self::SexualOrientation => f.write_str("SexualOrientation"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── MonitoringFrequency ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitoringFrequency {
    PerInference,
    Hourly,
    Daily,
    Weekly,
    Custom { interval_description: String },
}

impl fmt::Display for MonitoringFrequency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerInference => f.write_str("PerInference"),
            Self::Hourly => f.write_str("Hourly"),
            Self::Daily => f.write_str("Daily"),
            Self::Weekly => f.write_str("Weekly"),
            Self::Custom { interval_description } => {
                write!(f, "Custom({interval_description})")
            }
        }
    }
}

// ── FairnessStatus ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FairnessStatus {
    Fair,
    Unfair { violations: Vec<String> },
    Inconclusive { reason: String },
    NotAssessed,
}

impl fmt::Display for FairnessStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fair => f.write_str("Fair"),
            Self::Unfair { violations } => {
                write!(f, "Unfair(violations={})", violations.len())
            }
            Self::Inconclusive { reason } => write!(f, "Inconclusive: {reason}"),
            Self::NotAssessed => f.write_str("NotAssessed"),
        }
    }
}

// ── ProtectedAttribute ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedAttribute {
    pub attribute_name: String,
    pub attribute_type: ProtectedAttributeType,
    pub required_by: Option<String>,
}

impl ProtectedAttribute {
    pub fn new(
        attribute_name: impl Into<String>,
        attribute_type: ProtectedAttributeType,
    ) -> Self {
        Self {
            attribute_name: attribute_name.into(),
            attribute_type,
            required_by: None,
        }
    }
}

// ── FairnessMetricDefinition ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessMetricDefinition {
    pub metric_id: String,
    pub metric_name: String,
    pub threshold_value: String,
    pub comparison: ThresholdComparison,
    pub applies_to_attributes: Vec<String>,
}

impl FairnessMetricDefinition {
    pub fn new(
        metric_id: impl Into<String>,
        metric_name: impl Into<String>,
        threshold_value: impl Into<String>,
        comparison: ThresholdComparison,
    ) -> Self {
        Self {
            metric_id: metric_id.into(),
            metric_name: metric_name.into(),
            threshold_value: threshold_value.into(),
            comparison,
            applies_to_attributes: Vec::new(),
        }
    }
}

// ── FairnessPolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessPolicy {
    pub policy_id: String,
    pub model_id: String,
    pub protected_attributes: Vec<ProtectedAttribute>,
    pub fairness_metrics: Vec<FairnessMetricDefinition>,
    pub monitoring_frequency: MonitoringFrequency,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl FairnessPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        model_id: impl Into<String>,
        monitoring_frequency: MonitoringFrequency,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            model_id: model_id.into(),
            protected_attributes: Vec::new(),
            fairness_metrics: Vec::new(),
            monitoring_frequency,
            created_at,
            metadata: HashMap::new(),
        }
    }
}

// ── FairnessMetricResult ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessMetricResult {
    pub metric_id: String,
    pub attribute_name: String,
    pub measured_value: String,
    pub passed: bool,
    pub direction: Option<String>,
}

// ── FairnessAssessment ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessAssessment {
    pub assessment_id: String,
    pub policy_id: String,
    pub model_id: String,
    pub model_version: String,
    pub results: Vec<FairnessMetricResult>,
    pub overall_status: FairnessStatus,
    pub assessed_at: i64,
    pub assessed_by: String,
    pub metadata: HashMap<String, String>,
}

impl FairnessAssessment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assessment_id: impl Into<String>,
        policy_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        overall_status: FairnessStatus,
        assessed_at: i64,
        assessed_by: impl Into<String>,
    ) -> Self {
        Self {
            assessment_id: assessment_id.into(),
            policy_id: policy_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            results: Vec::new(),
            overall_status,
            assessed_at,
            assessed_by: assessed_by.into(),
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
    fn test_protected_attribute_type_display() {
        let types = vec![
            ProtectedAttributeType::Race,
            ProtectedAttributeType::Gender,
            ProtectedAttributeType::Age,
            ProtectedAttributeType::Disability,
            ProtectedAttributeType::Religion,
            ProtectedAttributeType::NationalOrigin,
            ProtectedAttributeType::SexualOrientation,
            ProtectedAttributeType::Custom { name: "veteran_status".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_monitoring_frequency_display() {
        let freqs = vec![
            MonitoringFrequency::PerInference,
            MonitoringFrequency::Hourly,
            MonitoringFrequency::Daily,
            MonitoringFrequency::Weekly,
            MonitoringFrequency::Custom { interval_description: "every 6 hours".into() },
        ];
        for f in &freqs {
            assert!(!f.to_string().is_empty());
        }
        assert_eq!(freqs.len(), 5);
    }

    #[test]
    fn test_fairness_status_display() {
        let statuses = vec![
            FairnessStatus::Fair,
            FairnessStatus::Unfair { violations: vec!["v1".into()] },
            FairnessStatus::Inconclusive { reason: "insufficient data".into() },
            FairnessStatus::NotAssessed,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_protected_attribute_construction() {
        let mut attr = ProtectedAttribute::new("gender", ProtectedAttributeType::Gender);
        assert_eq!(attr.attribute_name, "gender");
        assert!(attr.required_by.is_none());
        attr.required_by = Some("EU_AI_Act_Article_10".into());
    }

    #[test]
    fn test_fairness_metric_definition_construction() {
        let mut metric = FairnessMetricDefinition::new(
            "fm-1", "demographic_parity", "0.8",
            ThresholdComparison::GreaterThanOrEqual,
        );
        assert_eq!(metric.metric_id, "fm-1");
        metric.applies_to_attributes.push("gender".into());
        assert_eq!(metric.applies_to_attributes.len(), 1);
    }

    #[test]
    fn test_fairness_policy_construction() {
        let mut policy = FairnessPolicy::new(
            "fp-1", "model-1", MonitoringFrequency::Daily, 1000,
        );
        policy.protected_attributes.push(
            ProtectedAttribute::new("race", ProtectedAttributeType::Race),
        );
        policy.fairness_metrics.push(FairnessMetricDefinition::new(
            "fm-1", "equalized_odds", "0.9",
            ThresholdComparison::GreaterThanOrEqual,
        ));
        assert_eq!(policy.protected_attributes.len(), 1);
        assert_eq!(policy.fairness_metrics.len(), 1);
    }

    #[test]
    fn test_fairness_assessment_construction() {
        let mut assessment = FairnessAssessment::new(
            "fa-1", "fp-1", "model-1", "1.0.0",
            FairnessStatus::Fair, 2000, "fairness-engine",
        );
        assessment.results.push(FairnessMetricResult {
            metric_id: "fm-1".into(),
            attribute_name: "gender".into(),
            measured_value: "0.95".into(),
            passed: true,
            direction: Some("neutral".into()),
        });
        assert_eq!(assessment.results.len(), 1);
        assert!(assessment.results[0].passed);
    }

    #[test]
    fn test_fairness_metric_result_fields() {
        let result = FairnessMetricResult {
            metric_id: "fm-1".into(),
            attribute_name: "race".into(),
            measured_value: "0.72".into(),
            passed: false,
            direction: Some("favors_majority".into()),
        };
        assert!(!result.passed);
        assert_eq!(result.direction, Some("favors_majority".to_string()));
    }
}
