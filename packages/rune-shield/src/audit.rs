// ═══════════════════════════════════════════════════════════════════════
// Shield Audit Log
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;

// ── ShieldEventType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ShieldEventType {
    InputReceived { length: usize },
    InputValidated,
    InputRejected { reason: String },
    InjectionDetected { confidence: f64 },
    InjectionBlocked { confidence: f64 },
    InjectionNeutralized,
    AdversarialDetected { adversarial_type: String, score: f64 },
    Quarantined { quarantine_id: String, reason: String },
    QuarantineReleased { quarantine_id: String },
    QuarantineConfirmed { quarantine_id: String },
    OutputInspected { length: usize },
    ExfiltrationDetected { finding_type: String, confidence: f64 },
    OutputModified { reason: String },
    OutputBlocked { reason: String },
    Escalated { reason: String },
    // Layer 2 event types
    InjectionPatternMatched { pattern_id: String, score: f64 },
    PiiDetected { pii_type: String, count: usize },
    SecretDetected { secret_type: String },
    ExfiltrationAttempt { risk_score: f64, detail: String },
    FingerprintRecorded { hash: String },
    AttackPatternRecognized { fingerprint: String, seen_count: u64 },
}

impl ShieldEventType {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InputReceived { .. } => "InputReceived",
            Self::InputValidated => "InputValidated",
            Self::InputRejected { .. } => "InputRejected",
            Self::InjectionDetected { .. } => "InjectionDetected",
            Self::InjectionBlocked { .. } => "InjectionBlocked",
            Self::InjectionNeutralized => "InjectionNeutralized",
            Self::AdversarialDetected { .. } => "AdversarialDetected",
            Self::Quarantined { .. } => "Quarantined",
            Self::QuarantineReleased { .. } => "QuarantineReleased",
            Self::QuarantineConfirmed { .. } => "QuarantineConfirmed",
            Self::OutputInspected { .. } => "OutputInspected",
            Self::ExfiltrationDetected { .. } => "ExfiltrationDetected",
            Self::OutputModified { .. } => "OutputModified",
            Self::OutputBlocked { .. } => "OutputBlocked",
            Self::Escalated { .. } => "Escalated",
            Self::InjectionPatternMatched { .. } => "InjectionPatternMatched",
            Self::PiiDetected { .. } => "PiiDetected",
            Self::SecretDetected { .. } => "SecretDetected",
            Self::ExfiltrationAttempt { .. } => "ExfiltrationAttempt",
            Self::FingerprintRecorded { .. } => "FingerprintRecorded",
            Self::AttackPatternRecognized { .. } => "AttackPatternRecognized",
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(
            self,
            Self::InputRejected { .. } | Self::InjectionBlocked { .. } | Self::OutputBlocked { .. }
        )
    }

    pub fn is_quarantine(&self) -> bool {
        matches!(
            self,
            Self::Quarantined { .. }
                | Self::QuarantineReleased { .. }
                | Self::QuarantineConfirmed { .. }
        )
    }

    pub fn is_injection(&self) -> bool {
        matches!(
            self,
            Self::InjectionDetected { .. }
                | Self::InjectionBlocked { .. }
                | Self::InjectionNeutralized
        )
    }

    pub fn is_exfiltration(&self) -> bool {
        matches!(self, Self::ExfiltrationDetected { .. })
    }
}

impl fmt::Display for ShieldEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputReceived { length } => write!(f, "InputReceived({length})"),
            Self::InputValidated => f.write_str("InputValidated"),
            Self::InputRejected { reason } => write!(f, "InputRejected({reason})"),
            Self::InjectionDetected { confidence } => {
                write!(f, "InjectionDetected({confidence:.3})")
            }
            Self::InjectionBlocked { confidence } => {
                write!(f, "InjectionBlocked({confidence:.3})")
            }
            Self::InjectionNeutralized => f.write_str("InjectionNeutralized"),
            Self::AdversarialDetected { adversarial_type, score } => {
                write!(f, "AdversarialDetected({adversarial_type}, {score:.3})")
            }
            Self::Quarantined { quarantine_id, reason } => {
                write!(f, "Quarantined({quarantine_id}, {reason})")
            }
            Self::QuarantineReleased { quarantine_id } => {
                write!(f, "QuarantineReleased({quarantine_id})")
            }
            Self::QuarantineConfirmed { quarantine_id } => {
                write!(f, "QuarantineConfirmed({quarantine_id})")
            }
            Self::OutputInspected { length } => write!(f, "OutputInspected({length})"),
            Self::ExfiltrationDetected { finding_type, confidence } => {
                write!(f, "ExfiltrationDetected({finding_type}, {confidence:.3})")
            }
            Self::OutputModified { reason } => write!(f, "OutputModified({reason})"),
            Self::OutputBlocked { reason } => write!(f, "OutputBlocked({reason})"),
            Self::Escalated { reason } => write!(f, "Escalated({reason})"),
            Self::InjectionPatternMatched { pattern_id, score } => {
                write!(f, "InjectionPatternMatched({pattern_id}, {score:.3})")
            }
            Self::PiiDetected { pii_type, count } => {
                write!(f, "PiiDetected({pii_type}, {count})")
            }
            Self::SecretDetected { secret_type } => {
                write!(f, "SecretDetected({secret_type})")
            }
            Self::ExfiltrationAttempt { risk_score, detail } => {
                write!(f, "ExfiltrationAttempt({risk_score:.3}, {detail})")
            }
            Self::FingerprintRecorded { hash } => {
                write!(f, "FingerprintRecorded({})", &hash[..8.min(hash.len())])
            }
            Self::AttackPatternRecognized { fingerprint, seen_count } => {
                write!(f, "AttackPatternRecognized({}, {seen_count})", &fingerprint[..8.min(fingerprint.len())])
            }
        }
    }
}

// ── ShieldAuditEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ShieldAuditEvent {
    pub event_type: ShieldEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub detail: String,
}

impl ShieldAuditEvent {
    pub fn new(
        event_type: ShieldEventType,
        severity: SecuritySeverity,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self { event_type, severity, timestamp, detail: detail.into() }
    }
}

// ── ShieldAuditLog ────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ShieldAuditLog {
    pub events: Vec<ShieldAuditEvent>,
}

impl ShieldAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: ShieldAuditEvent) {
        self.events.push(event);
    }

    pub fn record_simple(
        &mut self,
        event_type: ShieldEventType,
        severity: SecuritySeverity,
        timestamp: i64,
    ) {
        self.events.push(ShieldAuditEvent::new(event_type, severity, timestamp, ""));
    }

    pub fn blocks(&self) -> Vec<&ShieldAuditEvent> {
        self.events.iter().filter(|e| e.event_type.is_block()).collect()
    }

    pub fn quarantines(&self) -> Vec<&ShieldAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.is_quarantine())
            .collect()
    }

    pub fn injections(&self) -> Vec<&ShieldAuditEvent> {
        self.events.iter().filter(|e| e.event_type.is_injection()).collect()
    }

    pub fn exfiltrations(&self) -> Vec<&ShieldAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.is_exfiltration())
            .collect()
    }

    pub fn by_severity(&self, severity: SecuritySeverity) -> Vec<&ShieldAuditEvent> {
        self.events.iter().filter(|e| e.severity == severity).collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&ShieldAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_kind_helpers() {
        let mut log = ShieldAuditLog::new();
        log.record_simple(
            ShieldEventType::InjectionBlocked { confidence: 0.9 },
            SecuritySeverity::High,
            1000,
        );
        log.record_simple(
            ShieldEventType::Quarantined {
                quarantine_id: "Q-1".into(),
                reason: "injection".into(),
            },
            SecuritySeverity::High,
            1001,
        );
        assert_eq!(log.blocks().len(), 1);
        assert_eq!(log.quarantines().len(), 1);
        assert_eq!(log.injections().len(), 1);
    }

    #[test]
    fn test_exfiltration_filter() {
        let mut log = ShieldAuditLog::new();
        log.record_simple(
            ShieldEventType::ExfiltrationDetected {
                finding_type: "ApiKeyLeak".into(),
                confidence: 0.9,
            },
            SecuritySeverity::Critical,
            1000,
        );
        assert_eq!(log.exfiltrations().len(), 1);
    }

    #[test]
    fn test_by_severity_filter() {
        let mut log = ShieldAuditLog::new();
        log.record_simple(ShieldEventType::InputValidated, SecuritySeverity::Info, 1);
        log.record_simple(
            ShieldEventType::InputRejected { reason: "too long".into() },
            SecuritySeverity::High,
            2,
        );
        assert_eq!(log.by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_since_filter() {
        let mut log = ShieldAuditLog::new();
        log.record_simple(ShieldEventType::InputValidated, SecuritySeverity::Info, 100);
        log.record_simple(ShieldEventType::InputValidated, SecuritySeverity::Info, 200);
        assert_eq!(log.since(150).len(), 1);
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let events = [
            ShieldEventType::InputReceived { length: 10 },
            ShieldEventType::InputValidated,
            ShieldEventType::InputRejected { reason: "r".into() },
            ShieldEventType::InjectionDetected { confidence: 0.8 },
            ShieldEventType::InjectionBlocked { confidence: 0.9 },
            ShieldEventType::InjectionNeutralized,
            ShieldEventType::AdversarialDetected {
                adversarial_type: "Repetition".into(),
                score: 0.8,
            },
            ShieldEventType::Quarantined {
                quarantine_id: "Q1".into(),
                reason: "r".into(),
            },
            ShieldEventType::QuarantineReleased { quarantine_id: "Q1".into() },
            ShieldEventType::QuarantineConfirmed { quarantine_id: "Q1".into() },
            ShieldEventType::OutputInspected { length: 100 },
            ShieldEventType::ExfiltrationDetected {
                finding_type: "ApiKey".into(),
                confidence: 0.9,
            },
            ShieldEventType::OutputModified { reason: "redact".into() },
            ShieldEventType::OutputBlocked { reason: "leak".into() },
            ShieldEventType::Escalated { reason: "review".into() },
            ShieldEventType::InjectionPatternMatched { pattern_id: "pi-01".into(), score: 0.9 },
            ShieldEventType::PiiDetected { pii_type: "Email".into(), count: 1 },
            ShieldEventType::SecretDetected { secret_type: "AwsKey".into() },
            ShieldEventType::ExfiltrationAttempt { risk_score: 0.8, detail: "pii+secrets".into() },
            ShieldEventType::FingerprintRecorded { hash: "abcdef1234567890".into() },
            ShieldEventType::AttackPatternRecognized { fingerprint: "abcdef1234567890".into(), seen_count: 3 },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
            assert!(!e.kind().is_empty());
        }
    }

    #[test]
    fn test_new_event_types_kind_names() {
        assert_eq!(
            ShieldEventType::InjectionPatternMatched { pattern_id: "x".into(), score: 0.5 }.kind(),
            "InjectionPatternMatched"
        );
        assert_eq!(
            ShieldEventType::PiiDetected { pii_type: "Email".into(), count: 1 }.kind(),
            "PiiDetected"
        );
        assert_eq!(
            ShieldEventType::SecretDetected { secret_type: "ApiKey".into() }.kind(),
            "SecretDetected"
        );
        assert_eq!(
            ShieldEventType::FingerprintRecorded { hash: "abc".into() }.kind(),
            "FingerprintRecorded"
        );
    }
}
