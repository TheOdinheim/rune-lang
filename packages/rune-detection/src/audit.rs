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
        )
    }

    pub fn is_alert(&self) -> bool {
        matches!(
            self,
            Self::AlertRaised { .. }
                | Self::AlertAcknowledged { .. }
                | Self::AlertResolved { .. }
                | Self::AlertFalsePositive { .. }
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
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
    }
}
