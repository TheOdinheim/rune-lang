// ═══════════════════════════════════════════════════════════════════════
// Detection Audit Log — events from the sensing layer
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;

// ── DetectionEventType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DetectionEventType {
    AnomalyDetected { method: String, score: f64 },
    PatternMatched { category: String, confidence: f64 },
    BehaviorDeviation { profile: String, metric: String, deviation: f64 },
    IoCFound { indicator_type: String, value: String },
    RuleTriggered { rule_id: String, rule_name: String },
    AlertRaised { alert_id: String, severity: String },
    AlertAcknowledged { alert_id: String },
    AlertResolved { alert_id: String },
    AlertFalsePositive { alert_id: String },
    PipelineProcessed { pipeline_id: String, detections: usize },
    // Layer 2 event types
    StatisticalAnomalyDetected { method: String, z_score: f64 },
    RegexPatternMatched { pattern_id: String, score: f64 },
    BaselineDeviation { metric: String, deviation: f64 },
    AlertsCorrelated { rule_id: String, alert_count: usize },
    DetectionScoreComputed { total: f64, is_threat: bool },
    BehavioralBaselineEstablished { metric: String, sample_count: u64 },
    // Layer 3 event types
    DetectionBackendChanged { backend_type: String },
    FindingPersisted { finding_id: String },
    FindingQueried { finding_id: String },
    DetectionModelLoaded { model_id: String, architecture: String },
    DetectionModelUnloaded { model_id: String },
    ModelPredictionMade { model_id: String, score: f64 },
    ModelLoadFailed { model_id: String, reason: String },
    AlertExported { format: String, finding_count: usize },
    AlertExportFailed { format: String, reason: String },
    FindingSubscriberRegistered { subscriber_id: String },
    FindingSubscriberRemoved { subscriber_id: String },
    FindingPublished { finding_id: String, subscriber_count: usize },
    CorrelationExecuted { rule_id: String, result_count: usize },
    CorrelationRuleRegistered { rule_id: String },
    BaselineStored { baseline_id: String },
    BaselineUpdated { baseline_id: String, sample_count: u64 },
    BaselineRetrieved { baseline_id: String },
    TimeSeriesIngested { source: String, point_count: usize },
    TimeSeriesIngestFailed { source: String, reason: String },
}

impl DetectionEventType {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AnomalyDetected { .. } => "AnomalyDetected",
            Self::PatternMatched { .. } => "PatternMatched",
            Self::BehaviorDeviation { .. } => "BehaviorDeviation",
            Self::IoCFound { .. } => "IoCFound",
            Self::RuleTriggered { .. } => "RuleTriggered",
            Self::AlertRaised { .. } => "AlertRaised",
            Self::AlertAcknowledged { .. } => "AlertAcknowledged",
            Self::AlertResolved { .. } => "AlertResolved",
            Self::AlertFalsePositive { .. } => "AlertFalsePositive",
            Self::PipelineProcessed { .. } => "PipelineProcessed",
            Self::StatisticalAnomalyDetected { .. } => "StatisticalAnomalyDetected",
            Self::RegexPatternMatched { .. } => "RegexPatternMatched",
            Self::BaselineDeviation { .. } => "BaselineDeviation",
            Self::AlertsCorrelated { .. } => "AlertsCorrelated",
            Self::DetectionScoreComputed { .. } => "DetectionScoreComputed",
            Self::BehavioralBaselineEstablished { .. } => "BehavioralBaselineEstablished",
            Self::DetectionBackendChanged { .. } => "DetectionBackendChanged",
            Self::FindingPersisted { .. } => "FindingPersisted",
            Self::FindingQueried { .. } => "FindingQueried",
            Self::DetectionModelLoaded { .. } => "DetectionModelLoaded",
            Self::DetectionModelUnloaded { .. } => "DetectionModelUnloaded",
            Self::ModelPredictionMade { .. } => "ModelPredictionMade",
            Self::ModelLoadFailed { .. } => "ModelLoadFailed",
            Self::AlertExported { .. } => "AlertExported",
            Self::AlertExportFailed { .. } => "AlertExportFailed",
            Self::FindingSubscriberRegistered { .. } => "FindingSubscriberRegistered",
            Self::FindingSubscriberRemoved { .. } => "FindingSubscriberRemoved",
            Self::FindingPublished { .. } => "FindingPublished",
            Self::CorrelationExecuted { .. } => "CorrelationExecuted",
            Self::CorrelationRuleRegistered { .. } => "CorrelationRuleRegistered",
            Self::BaselineStored { .. } => "BaselineStored",
            Self::BaselineUpdated { .. } => "BaselineUpdated",
            Self::BaselineRetrieved { .. } => "BaselineRetrieved",
            Self::TimeSeriesIngested { .. } => "TimeSeriesIngested",
            Self::TimeSeriesIngestFailed { .. } => "TimeSeriesIngestFailed",
        }
    }

    pub fn is_detection(&self) -> bool {
        matches!(
            self,
            Self::AnomalyDetected { .. }
                | Self::PatternMatched { .. }
                | Self::BehaviorDeviation { .. }
                | Self::IoCFound { .. }
                | Self::RuleTriggered { .. }
                | Self::StatisticalAnomalyDetected { .. }
                | Self::RegexPatternMatched { .. }
                | Self::BaselineDeviation { .. }
                | Self::ModelPredictionMade { .. }
        )
    }

    pub fn is_alert(&self) -> bool {
        matches!(
            self,
            Self::AlertRaised { .. }
                | Self::AlertAcknowledged { .. }
                | Self::AlertResolved { .. }
                | Self::AlertFalsePositive { .. }
                | Self::AlertExported { .. }
                | Self::AlertExportFailed { .. }
        )
    }

    pub fn is_correlation(&self) -> bool {
        matches!(
            self,
            Self::AlertsCorrelated { .. }
                | Self::DetectionScoreComputed { .. }
                | Self::CorrelationExecuted { .. }
                | Self::CorrelationRuleRegistered { .. }
        )
    }

    pub fn is_backend(&self) -> bool {
        matches!(
            self,
            Self::DetectionBackendChanged { .. }
                | Self::FindingPersisted { .. }
                | Self::FindingQueried { .. }
        )
    }

    pub fn is_model(&self) -> bool {
        matches!(
            self,
            Self::DetectionModelLoaded { .. }
                | Self::DetectionModelUnloaded { .. }
                | Self::ModelPredictionMade { .. }
                | Self::ModelLoadFailed { .. }
        )
    }

    pub fn is_streaming(&self) -> bool {
        matches!(
            self,
            Self::FindingSubscriberRegistered { .. }
                | Self::FindingSubscriberRemoved { .. }
                | Self::FindingPublished { .. }
        )
    }

    pub fn is_baseline(&self) -> bool {
        matches!(
            self,
            Self::BaselineStored { .. }
                | Self::BaselineUpdated { .. }
                | Self::BaselineRetrieved { .. }
                | Self::BehavioralBaselineEstablished { .. }
        )
    }

    pub fn is_timeseries(&self) -> bool {
        matches!(
            self,
            Self::TimeSeriesIngested { .. } | Self::TimeSeriesIngestFailed { .. }
        )
    }
}

impl fmt::Display for DetectionEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnomalyDetected { method, score } => {
                write!(f, "AnomalyDetected({method}, {score:.3})")
            }
            Self::PatternMatched { category, confidence } => {
                write!(f, "PatternMatched({category}, {confidence:.3})")
            }
            Self::BehaviorDeviation { profile, metric, deviation } => {
                write!(f, "BehaviorDeviation({profile}, {metric}, {deviation:.3})")
            }
            Self::IoCFound { indicator_type, value } => {
                write!(f, "IoCFound({indicator_type}, {value})")
            }
            Self::RuleTriggered { rule_id, rule_name } => {
                write!(f, "RuleTriggered({rule_id}, {rule_name})")
            }
            Self::AlertRaised { alert_id, severity } => {
                write!(f, "AlertRaised({alert_id}, {severity})")
            }
            Self::AlertAcknowledged { alert_id } => write!(f, "AlertAcknowledged({alert_id})"),
            Self::AlertResolved { alert_id } => write!(f, "AlertResolved({alert_id})"),
            Self::AlertFalsePositive { alert_id } => write!(f, "AlertFalsePositive({alert_id})"),
            Self::PipelineProcessed { pipeline_id, detections } => {
                write!(f, "PipelineProcessed({pipeline_id}, {detections})")
            }
            Self::StatisticalAnomalyDetected { method, z_score } => {
                write!(f, "StatisticalAnomalyDetected({method}, {z_score:.3})")
            }
            Self::RegexPatternMatched { pattern_id, score } => {
                write!(f, "RegexPatternMatched({pattern_id}, {score:.3})")
            }
            Self::BaselineDeviation { metric, deviation } => {
                write!(f, "BaselineDeviation({metric}, {deviation:.3})")
            }
            Self::AlertsCorrelated { rule_id, alert_count } => {
                write!(f, "AlertsCorrelated({rule_id}, {alert_count})")
            }
            Self::DetectionScoreComputed { total, is_threat } => {
                write!(f, "DetectionScoreComputed({total:.3}, threat={is_threat})")
            }
            Self::BehavioralBaselineEstablished { metric, sample_count } => {
                write!(f, "BehavioralBaselineEstablished({metric}, n={sample_count})")
            }
            Self::DetectionBackendChanged { backend_type } => {
                write!(f, "DetectionBackendChanged({backend_type})")
            }
            Self::FindingPersisted { finding_id } => write!(f, "FindingPersisted({finding_id})"),
            Self::FindingQueried { finding_id } => write!(f, "FindingQueried({finding_id})"),
            Self::DetectionModelLoaded { model_id, architecture } => {
                write!(f, "DetectionModelLoaded({model_id}, {architecture})")
            }
            Self::DetectionModelUnloaded { model_id } => {
                write!(f, "DetectionModelUnloaded({model_id})")
            }
            Self::ModelPredictionMade { model_id, score } => {
                write!(f, "ModelPredictionMade({model_id}, {score:.3})")
            }
            Self::ModelLoadFailed { model_id, reason } => {
                write!(f, "ModelLoadFailed({model_id}, {reason})")
            }
            Self::AlertExported { format, finding_count } => {
                write!(f, "AlertExported({format}, n={finding_count})")
            }
            Self::AlertExportFailed { format, reason } => {
                write!(f, "AlertExportFailed({format}, {reason})")
            }
            Self::FindingSubscriberRegistered { subscriber_id } => {
                write!(f, "FindingSubscriberRegistered({subscriber_id})")
            }
            Self::FindingSubscriberRemoved { subscriber_id } => {
                write!(f, "FindingSubscriberRemoved({subscriber_id})")
            }
            Self::FindingPublished { finding_id, subscriber_count } => {
                write!(f, "FindingPublished({finding_id}, n={subscriber_count})")
            }
            Self::CorrelationExecuted { rule_id, result_count } => {
                write!(f, "CorrelationExecuted({rule_id}, n={result_count})")
            }
            Self::CorrelationRuleRegistered { rule_id } => {
                write!(f, "CorrelationRuleRegistered({rule_id})")
            }
            Self::BaselineStored { baseline_id } => write!(f, "BaselineStored({baseline_id})"),
            Self::BaselineUpdated { baseline_id, sample_count } => {
                write!(f, "BaselineUpdated({baseline_id}, n={sample_count})")
            }
            Self::BaselineRetrieved { baseline_id } => {
                write!(f, "BaselineRetrieved({baseline_id})")
            }
            Self::TimeSeriesIngested { source, point_count } => {
                write!(f, "TimeSeriesIngested({source}, n={point_count})")
            }
            Self::TimeSeriesIngestFailed { source, reason } => {
                write!(f, "TimeSeriesIngestFailed({source}, {reason})")
            }
        }
    }
}

// ── DetectionAuditEvent ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionAuditEvent {
    pub event_type: DetectionEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub detail: String,
    pub source: String,
}

// ── DetectionAuditLog ─────────────────────────────────────────────────

#[derive(Default)]
pub struct DetectionAuditLog {
    pub events: Vec<DetectionAuditEvent>,
}

impl DetectionAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: DetectionAuditEvent) {
        self.events.push(event);
    }

    pub fn events_by_severity(&self, severity: SecuritySeverity) -> Vec<&DetectionAuditEvent> {
        self.events.iter().filter(|e| e.severity == severity).collect()
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&DetectionAuditEvent> {
        self.events.iter().filter(|e| e.event_type.kind() == type_name).collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&DetectionAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    pub fn detection_events(&self) -> Vec<&DetectionAuditEvent> {
        self.events.iter().filter(|e| e.event_type.is_detection()).collect()
    }

    pub fn alert_events(&self) -> Vec<&DetectionAuditEvent> {
        self.events.iter().filter(|e| e.event_type.is_alert()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(t: DetectionEventType, sev: SecuritySeverity, ts: i64) -> DetectionAuditEvent {
        DetectionAuditEvent {
            event_type: t,
            severity: sev,
            timestamp: ts,
            detail: "d".into(),
            source: "test".into(),
        }
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut log = DetectionAuditLog::new();
        log.record(ev(
            DetectionEventType::AnomalyDetected {
                method: "zscore".into(),
                score: 5.0,
            },
            SecuritySeverity::High,
            1000,
        ));
        assert_eq!(log.events.len(), 1);
    }

    #[test]
    fn test_events_by_severity() {
        let mut log = DetectionAuditLog::new();
        log.record(ev(
            DetectionEventType::AlertRaised {
                alert_id: "a1".into(),
                severity: "High".into(),
            },
            SecuritySeverity::High,
            1000,
        ));
        log.record(ev(
            DetectionEventType::AlertRaised {
                alert_id: "a2".into(),
                severity: "Low".into(),
            },
            SecuritySeverity::Low,
            1000,
        ));
        assert_eq!(log.events_by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_detection_events_filter() {
        let mut log = DetectionAuditLog::new();
        log.record(ev(
            DetectionEventType::AnomalyDetected {
                method: "zscore".into(),
                score: 5.0,
            },
            SecuritySeverity::High,
            1000,
        ));
        log.record(ev(
            DetectionEventType::AlertRaised {
                alert_id: "a1".into(),
                severity: "High".into(),
            },
            SecuritySeverity::High,
            1000,
        ));
        assert_eq!(log.detection_events().len(), 1);
    }

    #[test]
    fn test_alert_events_filter() {
        let mut log = DetectionAuditLog::new();
        log.record(ev(
            DetectionEventType::AlertRaised {
                alert_id: "a1".into(),
                severity: "High".into(),
            },
            SecuritySeverity::High,
            1000,
        ));
        log.record(ev(
            DetectionEventType::AlertAcknowledged { alert_id: "a1".into() },
            SecuritySeverity::High,
            1500,
        ));
        log.record(ev(
            DetectionEventType::RuleTriggered {
                rule_id: "r1".into(),
                rule_name: "n".into(),
            },
            SecuritySeverity::Low,
            1000,
        ));
        assert_eq!(log.alert_events().len(), 2);
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let events = [
            DetectionEventType::AnomalyDetected {
                method: "z".into(),
                score: 1.0,
            },
            DetectionEventType::PatternMatched {
                category: "SQLi".into(),
                confidence: 0.8,
            },
            DetectionEventType::BehaviorDeviation {
                profile: "u".into(),
                metric: "m".into(),
                deviation: 3.0,
            },
            DetectionEventType::IoCFound {
                indicator_type: "IpAddress".into(),
                value: "1.2.3.4".into(),
            },
            DetectionEventType::RuleTriggered {
                rule_id: "r".into(),
                rule_name: "n".into(),
            },
            DetectionEventType::AlertRaised {
                alert_id: "a".into(),
                severity: "High".into(),
            },
            DetectionEventType::AlertAcknowledged { alert_id: "a".into() },
            DetectionEventType::AlertResolved { alert_id: "a".into() },
            DetectionEventType::AlertFalsePositive { alert_id: "a".into() },
            DetectionEventType::PipelineProcessed {
                pipeline_id: "p".into(),
                detections: 3,
            },
            DetectionEventType::StatisticalAnomalyDetected {
                method: "welford".into(),
                z_score: 4.5,
            },
            DetectionEventType::RegexPatternMatched {
                pattern_id: "rx-01".into(),
                score: 0.9,
            },
            DetectionEventType::BaselineDeviation {
                metric: "latency".into(),
                deviation: 3.2,
            },
            DetectionEventType::AlertsCorrelated {
                rule_id: "r1".into(),
                alert_count: 5,
            },
            DetectionEventType::DetectionScoreComputed {
                total: 0.75,
                is_threat: true,
            },
            DetectionEventType::BehavioralBaselineEstablished {
                metric: "req_rate".into(),
                sample_count: 100,
            },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
    }

    #[test]
    fn test_layer2_detection_events_classified() {
        let stat = DetectionEventType::StatisticalAnomalyDetected {
            method: "z".into(),
            z_score: 4.0,
        };
        let regex = DetectionEventType::RegexPatternMatched {
            pattern_id: "rx".into(),
            score: 0.8,
        };
        let baseline = DetectionEventType::BaselineDeviation {
            metric: "m".into(),
            deviation: 3.0,
        };
        let correlated = DetectionEventType::AlertsCorrelated {
            rule_id: "r".into(),
            alert_count: 3,
        };
        let scored = DetectionEventType::DetectionScoreComputed {
            total: 0.7,
            is_threat: true,
        };
        assert!(stat.is_detection());
        assert!(regex.is_detection());
        assert!(baseline.is_detection());
        assert!(correlated.is_correlation());
        assert!(scored.is_correlation());
        assert!(!stat.is_alert());
    }

    #[test]
    fn test_l3_event_types_display() {
        let events = [
            DetectionEventType::DetectionBackendChanged { backend_type: "in-memory".into() },
            DetectionEventType::FindingPersisted { finding_id: "f1".into() },
            DetectionEventType::FindingQueried { finding_id: "f1".into() },
            DetectionEventType::DetectionModelLoaded { model_id: "m1".into(), architecture: "null".into() },
            DetectionEventType::DetectionModelUnloaded { model_id: "m1".into() },
            DetectionEventType::ModelPredictionMade { model_id: "m1".into(), score: 0.85 },
            DetectionEventType::ModelLoadFailed { model_id: "m1".into(), reason: "bad data".into() },
            DetectionEventType::AlertExported { format: "json".into(), finding_count: 5 },
            DetectionEventType::AlertExportFailed { format: "cef".into(), reason: "encoding".into() },
            DetectionEventType::FindingSubscriberRegistered { subscriber_id: "s1".into() },
            DetectionEventType::FindingSubscriberRemoved { subscriber_id: "s1".into() },
            DetectionEventType::FindingPublished { finding_id: "f1".into(), subscriber_count: 3 },
            DetectionEventType::CorrelationExecuted { rule_id: "r1".into(), result_count: 2 },
            DetectionEventType::CorrelationRuleRegistered { rule_id: "r1".into() },
            DetectionEventType::BaselineStored { baseline_id: "b1".into() },
            DetectionEventType::BaselineUpdated { baseline_id: "b1".into(), sample_count: 200 },
            DetectionEventType::BaselineRetrieved { baseline_id: "b1".into() },
            DetectionEventType::TimeSeriesIngested { source: "src".into(), point_count: 10 },
            DetectionEventType::TimeSeriesIngestFailed { source: "src".into(), reason: "timeout".into() },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
        // Classification checks
        assert!(events[0].is_backend());
        assert!(events[3].is_model());
        assert!(events[5].is_detection()); // ModelPredictionMade is a detection event
        assert!(events[7].is_alert()); // AlertExported
        assert!(events[9].is_streaming());
        assert!(events[12].is_correlation());
        assert!(events[14].is_baseline());
        assert!(events[17].is_timeseries());
    }
}
