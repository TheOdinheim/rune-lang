// ═══════════════════════════════════════════════════════════════════════
// Data freshness and staleness monitoring types — freshness policies
// with expected update frequency and staleness thresholds, freshness
// assessments tracking SLA compliance, and freshness alerts with
// acknowledgement tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::quality::QualitySeverity;

// ── UpdateFrequency ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateFrequency {
    RealTime,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Custom { interval_description: String },
}

impl fmt::Display for UpdateFrequency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RealTime => f.write_str("RealTime"),
            Self::Hourly => f.write_str("Hourly"),
            Self::Daily => f.write_str("Daily"),
            Self::Weekly => f.write_str("Weekly"),
            Self::Monthly => f.write_str("Monthly"),
            Self::Custom { interval_description } => write!(f, "Custom({interval_description})"),
        }
    }
}

// ── FreshnessStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessStatus {
    Fresh { hours_since_update: String },
    Stale { hours_since_update: String, threshold_hours: String },
    Unknown { reason: String },
    NotApplicable,
}

impl fmt::Display for FreshnessStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh { hours_since_update } => {
                write!(f, "Fresh({}h since update)", hours_since_update)
            }
            Self::Stale { hours_since_update, threshold_hours } => {
                write!(f, "Stale({}h since update, threshold={}h)", hours_since_update, threshold_hours)
            }
            Self::Unknown { reason } => write!(f, "Unknown({reason})"),
            Self::NotApplicable => f.write_str("NotApplicable"),
        }
    }
}

// ── FreshnessPolicy ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FreshnessPolicy {
    pub policy_id: String,
    pub dataset_ref: String,
    pub expected_update_frequency: UpdateFrequency,
    pub staleness_threshold_hours: String,
    pub alerting_severity: QualitySeverity,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── FreshnessAssessment ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FreshnessAssessment {
    pub assessment_id: String,
    pub policy_id: String,
    pub dataset_ref: String,
    pub last_updated_at: i64,
    pub assessed_at: i64,
    pub freshness_status: FreshnessStatus,
    pub sla_met: bool,
    pub metadata: HashMap<String, String>,
}

// ── FreshnessAlert ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FreshnessAlert {
    pub alert_id: String,
    pub assessment_id: String,
    pub dataset_ref: String,
    pub severity: QualitySeverity,
    pub message: String,
    pub alerted_at: i64,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_frequency_display() {
        let freqs = vec![
            UpdateFrequency::RealTime,
            UpdateFrequency::Hourly,
            UpdateFrequency::Daily,
            UpdateFrequency::Weekly,
            UpdateFrequency::Monthly,
            UpdateFrequency::Custom { interval_description: "every 15 minutes".into() },
        ];
        for f in &freqs {
            assert!(!f.to_string().is_empty());
        }
        assert_eq!(freqs.len(), 6);
    }

    #[test]
    fn test_freshness_status_display() {
        let statuses = vec![
            FreshnessStatus::Fresh { hours_since_update: "2".into() },
            FreshnessStatus::Stale { hours_since_update: "48".into(), threshold_hours: "24".into() },
            FreshnessStatus::Unknown { reason: "no update timestamp".into() },
            FreshnessStatus::NotApplicable,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_freshness_policy_construction() {
        let policy = FreshnessPolicy {
            policy_id: "fp-1".into(),
            dataset_ref: "ds-orders".into(),
            expected_update_frequency: UpdateFrequency::Hourly,
            staleness_threshold_hours: "4".into(),
            alerting_severity: QualitySeverity::Warning,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert_eq!(policy.expected_update_frequency, UpdateFrequency::Hourly);
        assert_eq!(policy.staleness_threshold_hours, "4");
    }

    #[test]
    fn test_freshness_assessment_fresh() {
        let assessment = FreshnessAssessment {
            assessment_id: "fa-1".into(),
            policy_id: "fp-1".into(),
            dataset_ref: "ds-orders".into(),
            last_updated_at: 900,
            assessed_at: 1000,
            freshness_status: FreshnessStatus::Fresh { hours_since_update: "1".into() },
            sla_met: true,
            metadata: HashMap::new(),
        };
        assert!(assessment.sla_met);
        assert_eq!(assessment.freshness_status, FreshnessStatus::Fresh { hours_since_update: "1".into() });
    }

    #[test]
    fn test_freshness_assessment_stale() {
        let assessment = FreshnessAssessment {
            assessment_id: "fa-2".into(),
            policy_id: "fp-1".into(),
            dataset_ref: "ds-orders".into(),
            last_updated_at: 100,
            assessed_at: 1000,
            freshness_status: FreshnessStatus::Stale {
                hours_since_update: "48".into(),
                threshold_hours: "4".into(),
            },
            sla_met: false,
            metadata: HashMap::new(),
        };
        assert!(!assessment.sla_met);
    }

    #[test]
    fn test_freshness_alert_construction() {
        let alert = FreshnessAlert {
            alert_id: "fal-1".into(),
            assessment_id: "fa-2".into(),
            dataset_ref: "ds-orders".into(),
            severity: QualitySeverity::Critical,
            message: "Dataset ds-orders is stale".into(),
            alerted_at: 1000,
            acknowledged_by: None,
            acknowledged_at: None,
            metadata: HashMap::new(),
        };
        assert_eq!(alert.severity, QualitySeverity::Critical);
        assert!(alert.acknowledged_by.is_none());
        assert!(alert.acknowledged_at.is_none());
    }

    #[test]
    fn test_freshness_alert_acknowledged() {
        let alert = FreshnessAlert {
            alert_id: "fal-2".into(),
            assessment_id: "fa-2".into(),
            dataset_ref: "ds-orders".into(),
            severity: QualitySeverity::Warning,
            message: "stale data warning".into(),
            alerted_at: 1000,
            acknowledged_by: Some("alice".into()),
            acknowledged_at: Some(1100),
            metadata: HashMap::new(),
        };
        assert_eq!(alert.acknowledged_by, Some("alice".into()));
        assert_eq!(alert.acknowledged_at, Some(1100));
    }

    #[test]
    fn test_freshness_policy_realtime() {
        let policy = FreshnessPolicy {
            policy_id: "fp-rt".into(),
            dataset_ref: "ds-events".into(),
            expected_update_frequency: UpdateFrequency::RealTime,
            staleness_threshold_hours: "0.5".into(),
            alerting_severity: QualitySeverity::Critical,
            created_at: 2000,
            metadata: HashMap::new(),
        };
        assert_eq!(policy.expected_update_frequency, UpdateFrequency::RealTime);
        assert_eq!(policy.alerting_severity, QualitySeverity::Critical);
    }

    #[test]
    fn test_freshness_alert_with_metadata() {
        let mut meta = HashMap::new();
        meta.insert("oncall".into(), "data-team".into());
        let alert = FreshnessAlert {
            alert_id: "fal-3".into(),
            assessment_id: "fa-3".into(),
            dataset_ref: "ds-metrics".into(),
            severity: QualitySeverity::Advisory,
            message: "approaching staleness threshold".into(),
            alerted_at: 3000,
            acknowledged_by: None,
            acknowledged_at: None,
            metadata: meta,
        };
        assert_eq!(alert.metadata.get("oncall"), Some(&"data-team".to_string()));
    }
}
