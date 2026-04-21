// ═══════════════════════════════════════════════════════════════════════
// Drift — Model drift detection policy types for defining drift
// metrics, detection windows, alerting thresholds, severity levels,
// and remediation actions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::evaluation::ThresholdComparison;

// ── DriftSeverity ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DriftSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── DriftRemediationAction ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftRemediationAction {
    Alert { target: String },
    Retrain,
    Rollback,
    Suspend,
    EscalateToHuman { target: String },
    Custom { name: String },
}

impl fmt::Display for DriftRemediationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alert { target } => write!(f, "Alert({target})"),
            Self::Retrain => f.write_str("Retrain"),
            Self::Rollback => f.write_str("Rollback"),
            Self::Suspend => f.write_str("Suspend"),
            Self::EscalateToHuman { target } => write!(f, "EscalateToHuman({target})"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DriftDetectionWindow ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftDetectionWindow {
    Sliding { window_size_hours: String },
    Tumbling { window_size_hours: String },
    Expanding,
    Custom { name: String },
}

impl fmt::Display for DriftDetectionWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sliding { window_size_hours } => {
                write!(f, "Sliding({window_size_hours}h)")
            }
            Self::Tumbling { window_size_hours } => {
                write!(f, "Tumbling({window_size_hours}h)")
            }
            Self::Expanding => f.write_str("Expanding"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DriftStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftStatus {
    NoDrift,
    MinorDrift { details: String },
    SignificantDrift { details: String },
    SevereDrift { details: String },
    NotAssessed,
}

impl fmt::Display for DriftStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDrift => f.write_str("NoDrift"),
            Self::MinorDrift { details } => write!(f, "MinorDrift: {details}"),
            Self::SignificantDrift { details } => write!(f, "SignificantDrift: {details}"),
            Self::SevereDrift { details } => write!(f, "SevereDrift: {details}"),
            Self::NotAssessed => f.write_str("NotAssessed"),
        }
    }
}

// ── DriftMetricDefinition ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftMetricDefinition {
    pub metric_id: String,
    pub metric_name: String,
    pub baseline_value: Option<String>,
    pub threshold_value: String,
    pub comparison: ThresholdComparison,
}

impl DriftMetricDefinition {
    pub fn new(
        metric_id: impl Into<String>,
        metric_name: impl Into<String>,
        threshold_value: impl Into<String>,
        comparison: ThresholdComparison,
    ) -> Self {
        Self {
            metric_id: metric_id.into(),
            metric_name: metric_name.into(),
            baseline_value: None,
            threshold_value: threshold_value.into(),
            comparison,
        }
    }
}

// ── DriftAlertConfig ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftAlertConfig {
    pub severity_levels: Vec<DriftSeverity>,
    pub remediation_actions: Vec<DriftRemediationAction>,
}

impl DriftAlertConfig {
    pub fn new() -> Self {
        Self {
            severity_levels: Vec::new(),
            remediation_actions: Vec::new(),
        }
    }
}

impl Default for DriftAlertConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── DriftPolicy ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftPolicy {
    pub policy_id: String,
    pub model_id: String,
    pub drift_metrics: Vec<DriftMetricDefinition>,
    pub detection_window: DriftDetectionWindow,
    pub alerting_config: DriftAlertConfig,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl DriftPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        model_id: impl Into<String>,
        detection_window: DriftDetectionWindow,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            model_id: model_id.into(),
            drift_metrics: Vec::new(),
            detection_window,
            alerting_config: DriftAlertConfig::new(),
            created_at,
            metadata: HashMap::new(),
        }
    }
}

// ── DriftMetricResult ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftMetricResult {
    pub metric_id: String,
    pub measured_value: String,
    pub baseline_value: Option<String>,
    pub drift_detected: bool,
    pub severity: DriftSeverity,
}

// ── DriftDetectionResult ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftDetectionResult {
    pub result_id: String,
    pub policy_id: String,
    pub model_id: String,
    pub model_version: String,
    pub metric_results: Vec<DriftMetricResult>,
    pub overall_status: DriftStatus,
    pub detected_at: i64,
    pub detection_window_start: i64,
    pub detection_window_end: i64,
    pub metadata: HashMap<String, String>,
}

impl DriftDetectionResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: impl Into<String>,
        policy_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        overall_status: DriftStatus,
        detected_at: i64,
        window_start: i64,
        window_end: i64,
    ) -> Self {
        Self {
            result_id: result_id.into(),
            policy_id: policy_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            metric_results: Vec::new(),
            overall_status,
            detected_at,
            detection_window_start: window_start,
            detection_window_end: window_end,
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
    fn test_drift_severity_display() {
        let sevs = vec![
            DriftSeverity::Low,
            DriftSeverity::Medium,
            DriftSeverity::High,
            DriftSeverity::Critical,
        ];
        for s in &sevs {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(sevs.len(), 4);
    }

    #[test]
    fn test_drift_severity_ord() {
        assert!(DriftSeverity::Low < DriftSeverity::Medium);
        assert!(DriftSeverity::Medium < DriftSeverity::High);
        assert!(DriftSeverity::High < DriftSeverity::Critical);
        assert!(DriftSeverity::Low < DriftSeverity::Critical);
    }

    #[test]
    fn test_drift_remediation_action_display() {
        let actions = vec![
            DriftRemediationAction::Alert { target: "ops-channel".into() },
            DriftRemediationAction::Retrain,
            DriftRemediationAction::Rollback,
            DriftRemediationAction::Suspend,
            DriftRemediationAction::EscalateToHuman { target: "ml-lead".into() },
            DriftRemediationAction::Custom { name: "shadow-mode".into() },
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(actions.len(), 6);
    }

    #[test]
    fn test_drift_detection_window_display() {
        let windows = vec![
            DriftDetectionWindow::Sliding { window_size_hours: "24".into() },
            DriftDetectionWindow::Tumbling { window_size_hours: "168".into() },
            DriftDetectionWindow::Expanding,
            DriftDetectionWindow::Custom { name: "adaptive".into() },
        ];
        for w in &windows {
            assert!(!w.to_string().is_empty());
        }
        assert_eq!(windows.len(), 4);
    }

    #[test]
    fn test_drift_status_display() {
        let statuses = vec![
            DriftStatus::NoDrift,
            DriftStatus::MinorDrift { details: "slight shift in feature X".into() },
            DriftStatus::SignificantDrift { details: "PSI > 0.2".into() },
            DriftStatus::SevereDrift { details: "complete distribution change".into() },
            DriftStatus::NotAssessed,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_drift_metric_definition_construction() {
        let mut metric = DriftMetricDefinition::new(
            "dm-1", "psi", "0.2", ThresholdComparison::LessThan,
        );
        assert_eq!(metric.metric_id, "dm-1");
        assert!(metric.baseline_value.is_none());
        metric.baseline_value = Some("0.0".into());
    }

    #[test]
    fn test_drift_alert_config() {
        let mut config = DriftAlertConfig::new();
        config.severity_levels.push(DriftSeverity::High);
        config.remediation_actions.push(DriftRemediationAction::Retrain);
        assert_eq!(config.severity_levels.len(), 1);
        assert_eq!(config.remediation_actions.len(), 1);
    }

    #[test]
    fn test_drift_policy_construction() {
        let mut policy = DriftPolicy::new(
            "dp-1", "model-1",
            DriftDetectionWindow::Sliding { window_size_hours: "24".into() },
            1000,
        );
        policy.drift_metrics.push(DriftMetricDefinition::new(
            "dm-1", "psi", "0.2", ThresholdComparison::LessThan,
        ));
        policy.alerting_config.severity_levels.push(DriftSeverity::Critical);
        policy.alerting_config.remediation_actions.push(DriftRemediationAction::Rollback);
        assert_eq!(policy.drift_metrics.len(), 1);
    }

    #[test]
    fn test_drift_detection_result_construction() {
        let mut result = DriftDetectionResult::new(
            "ddr-1", "dp-1", "model-1", "1.0.0",
            DriftStatus::MinorDrift { details: "feature shift".into() },
            3000, 1000, 3000,
        );
        result.metric_results.push(DriftMetricResult {
            metric_id: "dm-1".into(),
            measured_value: "0.15".into(),
            baseline_value: Some("0.0".into()),
            drift_detected: false,
            severity: DriftSeverity::Low,
        });
        assert_eq!(result.metric_results.len(), 1);
        assert!(!result.metric_results[0].drift_detected);
    }

    #[test]
    fn test_drift_alert_config_default() {
        let config = DriftAlertConfig::default();
        assert!(config.severity_levels.is_empty());
        assert!(config.remediation_actions.is_empty());
    }
}
