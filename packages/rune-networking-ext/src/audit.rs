// ═══════════════════════════════════════════════════════════════════════
// Audit — Networking-specific audit events for connection lifecycle,
// protocol enforcement, traffic classification, segmentation,
// certificate validation, DNS governance, and firewall decisions.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

// ── NetworkEventType ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEventType {
    ConnectionOpened { protocol: String },
    ConnectionAuthenticated { identity: String },
    ConnectionEstablished { tls_version: String },
    ConnectionClosed { reason: String },
    ConnectionRejected { reason: String },
    ProtocolViolation { check: String, version: String },
    CipherSuiteRejected { cipher: String },
    TrafficClassified { trust_level: String },
    SegmentationViolation { source_zone: String, dest_zone: String },
    CertificateValidated { subject: String, valid: bool },
    CertificateExpiring { subject: String, days_remaining: u64 },
    DnsQueryBlocked { domain: String },
    DnsQueryAllowed { domain: String },
    RateLimitExceeded { limit_type: String, source: String },
    FirewallRuleMatched { rule_id: String, action: String },
}

impl fmt::Display for NetworkEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionOpened { protocol } => write!(f, "ConnectionOpened({protocol})"),
            Self::ConnectionAuthenticated { identity } => {
                write!(f, "ConnectionAuthenticated({identity})")
            }
            Self::ConnectionEstablished { tls_version } => {
                write!(f, "ConnectionEstablished({tls_version})")
            }
            Self::ConnectionClosed { reason } => write!(f, "ConnectionClosed({reason})"),
            Self::ConnectionRejected { reason } => write!(f, "ConnectionRejected({reason})"),
            Self::ProtocolViolation { check, version } => {
                write!(f, "ProtocolViolation({check}: {version})")
            }
            Self::CipherSuiteRejected { cipher } => {
                write!(f, "CipherSuiteRejected({cipher})")
            }
            Self::TrafficClassified { trust_level } => {
                write!(f, "TrafficClassified({trust_level})")
            }
            Self::SegmentationViolation {
                source_zone,
                dest_zone,
            } => write!(f, "SegmentationViolation({source_zone}→{dest_zone})"),
            Self::CertificateValidated { subject, valid } => {
                write!(f, "CertificateValidated({subject}, valid={valid})")
            }
            Self::CertificateExpiring {
                subject,
                days_remaining,
            } => write!(f, "CertificateExpiring({subject}, {days_remaining}d)"),
            Self::DnsQueryBlocked { domain } => write!(f, "DnsQueryBlocked({domain})"),
            Self::DnsQueryAllowed { domain } => write!(f, "DnsQueryAllowed({domain})"),
            Self::RateLimitExceeded { limit_type, source } => {
                write!(f, "RateLimitExceeded({limit_type}: {source})")
            }
            Self::FirewallRuleMatched { rule_id, action } => {
                write!(f, "FirewallRuleMatched({rule_id}: {action})")
            }
        }
    }
}

// ── NetworkAuditEvent ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NetworkAuditEvent {
    pub event_type: NetworkEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub detail: String,
}

// ── NetworkAuditLog ─────────────────────────────────────────────────

pub struct NetworkAuditLog {
    events: Vec<NetworkAuditEvent>,
}

impl NetworkAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: NetworkAuditEvent) {
        self.events.push(event);
    }

    pub fn events_by_severity(&self, severity: SecuritySeverity) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn connection_events(&self) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    NetworkEventType::ConnectionOpened { .. }
                        | NetworkEventType::ConnectionAuthenticated { .. }
                        | NetworkEventType::ConnectionEstablished { .. }
                        | NetworkEventType::ConnectionClosed { .. }
                        | NetworkEventType::ConnectionRejected { .. }
                )
            })
            .collect()
    }

    pub fn protocol_events(&self) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    NetworkEventType::ProtocolViolation { .. }
                        | NetworkEventType::CipherSuiteRejected { .. }
                )
            })
            .collect()
    }

    pub fn dns_events(&self) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    NetworkEventType::DnsQueryBlocked { .. }
                        | NetworkEventType::DnsQueryAllowed { .. }
                )
            })
            .collect()
    }

    pub fn firewall_events(&self) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, NetworkEventType::FirewallRuleMatched { .. }))
            .collect()
    }

    pub fn segmentation_events(&self) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, NetworkEventType::SegmentationViolation { .. }))
            .collect()
    }

    pub fn certificate_events(&self) -> Vec<&NetworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    NetworkEventType::CertificateValidated { .. }
                        | NetworkEventType::CertificateExpiring { .. }
                )
            })
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for NetworkAuditLog {
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

    fn event(event_type: NetworkEventType, severity: SecuritySeverity) -> NetworkAuditEvent {
        NetworkAuditEvent {
            event_type,
            severity,
            timestamp: 1000,
            source: Some("1.2.3.4".into()),
            destination: Some("5.6.7.8".into()),
            detail: "test".into(),
        }
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::ConnectionOpened { protocol: "TCP".into() },
            SecuritySeverity::Info,
        ));
        assert_eq!(log.event_count(), 1);
    }

    #[test]
    fn test_events_by_severity() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::ConnectionOpened { protocol: "TCP".into() },
            SecuritySeverity::Info,
        ));
        log.record(event(
            NetworkEventType::ProtocolViolation { check: "version".into(), version: "TLS 1.0".into() },
            SecuritySeverity::Critical,
        ));
        assert_eq!(log.events_by_severity(SecuritySeverity::Info).len(), 1);
        assert_eq!(log.events_by_severity(SecuritySeverity::Critical).len(), 1);
    }

    #[test]
    fn test_connection_events() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::ConnectionOpened { protocol: "TCP".into() },
            SecuritySeverity::Info,
        ));
        log.record(event(
            NetworkEventType::ConnectionClosed { reason: "done".into() },
            SecuritySeverity::Info,
        ));
        log.record(event(
            NetworkEventType::DnsQueryBlocked { domain: "evil.com".into() },
            SecuritySeverity::High,
        ));
        assert_eq!(log.connection_events().len(), 2);
    }

    #[test]
    fn test_protocol_events() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::ProtocolViolation { check: "version".into(), version: "TLS 1.0".into() },
            SecuritySeverity::Critical,
        ));
        log.record(event(
            NetworkEventType::CipherSuiteRejected { cipher: "RC4-SHA".into() },
            SecuritySeverity::Critical,
        ));
        log.record(event(
            NetworkEventType::ConnectionOpened { protocol: "TCP".into() },
            SecuritySeverity::Info,
        ));
        assert_eq!(log.protocol_events().len(), 2);
    }

    #[test]
    fn test_dns_events() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::DnsQueryBlocked { domain: "evil.com".into() },
            SecuritySeverity::High,
        ));
        log.record(event(
            NetworkEventType::DnsQueryAllowed { domain: "good.com".into() },
            SecuritySeverity::Info,
        ));
        assert_eq!(log.dns_events().len(), 2);
    }

    #[test]
    fn test_firewall_events() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::FirewallRuleMatched { rule_id: "r1".into(), action: "Deny".into() },
            SecuritySeverity::Medium,
        ));
        assert_eq!(log.firewall_events().len(), 1);
    }

    #[test]
    fn test_segmentation_events() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::SegmentationViolation { source_zone: "public".into(), dest_zone: "restricted".into() },
            SecuritySeverity::High,
        ));
        assert_eq!(log.segmentation_events().len(), 1);
    }

    #[test]
    fn test_certificate_events() {
        let mut log = NetworkAuditLog::new();
        log.record(event(
            NetworkEventType::CertificateValidated { subject: "CN=test".into(), valid: true },
            SecuritySeverity::Info,
        ));
        log.record(event(
            NetworkEventType::CertificateExpiring { subject: "CN=test".into(), days_remaining: 7 },
            SecuritySeverity::Medium,
        ));
        assert_eq!(log.certificate_events().len(), 2);
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let types: Vec<NetworkEventType> = vec![
            NetworkEventType::ConnectionOpened { protocol: "TCP".into() },
            NetworkEventType::ConnectionAuthenticated { identity: "user".into() },
            NetworkEventType::ConnectionEstablished { tls_version: "TLS 1.3".into() },
            NetworkEventType::ConnectionClosed { reason: "done".into() },
            NetworkEventType::ConnectionRejected { reason: "policy".into() },
            NetworkEventType::ProtocolViolation { check: "version".into(), version: "TLS 1.0".into() },
            NetworkEventType::CipherSuiteRejected { cipher: "RC4-SHA".into() },
            NetworkEventType::TrafficClassified { trust_level: "Trusted".into() },
            NetworkEventType::SegmentationViolation { source_zone: "public".into(), dest_zone: "restricted".into() },
            NetworkEventType::CertificateValidated { subject: "CN=test".into(), valid: true },
            NetworkEventType::CertificateExpiring { subject: "CN=test".into(), days_remaining: 7 },
            NetworkEventType::DnsQueryBlocked { domain: "evil.com".into() },
            NetworkEventType::DnsQueryAllowed { domain: "good.com".into() },
            NetworkEventType::RateLimitExceeded { limit_type: "per-source".into(), source: "1.2.3.4".into() },
            NetworkEventType::FirewallRuleMatched { rule_id: "r1".into(), action: "Deny".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 15);
    }
}
