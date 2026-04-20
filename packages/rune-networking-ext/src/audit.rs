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
    // Layer 2
    CertificateAdded { cert_id: String, subject: String, expires_at: String },
    CertificateExpiringL2 { cert_id: String, days_remaining: String },
    CertificateValidatedL2 { cert_id: String, valid: bool, issues: String },
    NetworkPolicyEvaluated { policy_id: String, action: String },
    NetworkPolicyAdded { policy_id: String, rules: String },
    ConnectionAcquired { pool_id: String, connection_id: String },
    ConnectionReleased { pool_id: String, connection_id: String },
    ConnectionPoolEvicted { pool_id: String, evicted: String },
    TrafficRecorded { source: String, destination: String, action: String },
    TrafficChainVerified { chain_length: String, valid: bool },
    DnsDomainChecked { hostname: String, allowed: bool },
    DnsCacheHit { hostname: String },
    DnsCacheMiss { hostname: String },
    ZoneCommunicationChecked { from_zone: String, to_zone: String, allowed: bool },
    SegmentationViolationDetected { from_zone: String, to_zone: String },
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
            Self::CertificateAdded { cert_id, subject, expires_at } => {
                write!(f, "CertificateAdded({cert_id}, {subject}, expires={expires_at})")
            }
            Self::CertificateExpiringL2 { cert_id, days_remaining } => {
                write!(f, "CertificateExpiring({cert_id}, {days_remaining}d)")
            }
            Self::CertificateValidatedL2 { cert_id, valid, issues } => {
                write!(f, "CertificateValidated({cert_id}, valid={valid}, issues={issues})")
            }
            Self::NetworkPolicyEvaluated { policy_id, action } => {
                write!(f, "NetworkPolicyEvaluated({policy_id}, {action})")
            }
            Self::NetworkPolicyAdded { policy_id, rules } => {
                write!(f, "NetworkPolicyAdded({policy_id}, rules={rules})")
            }
            Self::ConnectionAcquired { pool_id, connection_id } => {
                write!(f, "ConnectionAcquired({pool_id}, {connection_id})")
            }
            Self::ConnectionReleased { pool_id, connection_id } => {
                write!(f, "ConnectionReleased({pool_id}, {connection_id})")
            }
            Self::ConnectionPoolEvicted { pool_id, evicted } => {
                write!(f, "ConnectionPoolEvicted({pool_id}, evicted={evicted})")
            }
            Self::TrafficRecorded { source, destination, action } => {
                write!(f, "TrafficRecorded({source}→{destination}, {action})")
            }
            Self::TrafficChainVerified { chain_length, valid } => {
                write!(f, "TrafficChainVerified(len={chain_length}, valid={valid})")
            }
            Self::DnsDomainChecked { hostname, allowed } => {
                write!(f, "DnsDomainChecked({hostname}, allowed={allowed})")
            }
            Self::DnsCacheHit { hostname } => {
                write!(f, "DnsCacheHit({hostname})")
            }
            Self::DnsCacheMiss { hostname } => {
                write!(f, "DnsCacheMiss({hostname})")
            }
            Self::ZoneCommunicationChecked { from_zone, to_zone, allowed } => {
                write!(f, "ZoneCommunicationChecked({from_zone}→{to_zone}, allowed={allowed})")
            }
            Self::SegmentationViolationDetected { from_zone, to_zone } => {
                write!(f, "SegmentationViolationDetected({from_zone}→{to_zone})")
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
            // Layer 2
            NetworkEventType::CertificateAdded { cert_id: "c1".into(), subject: "CN=test".into(), expires_at: "2025-01-01".into() },
            NetworkEventType::CertificateExpiringL2 { cert_id: "c1".into(), days_remaining: "7".into() },
            NetworkEventType::CertificateValidatedL2 { cert_id: "c1".into(), valid: true, issues: "none".into() },
            NetworkEventType::NetworkPolicyEvaluated { policy_id: "p1".into(), action: "Allow".into() },
            NetworkEventType::NetworkPolicyAdded { policy_id: "p1".into(), rules: "3".into() },
            NetworkEventType::ConnectionAcquired { pool_id: "pool1".into(), connection_id: "c1".into() },
            NetworkEventType::ConnectionReleased { pool_id: "pool1".into(), connection_id: "c1".into() },
            NetworkEventType::ConnectionPoolEvicted { pool_id: "pool1".into(), evicted: "2".into() },
            NetworkEventType::TrafficRecorded { source: "1.2.3.4".into(), destination: "5.6.7.8".into(), action: "allow".into() },
            NetworkEventType::TrafficChainVerified { chain_length: "10".into(), valid: true },
            NetworkEventType::DnsDomainChecked { hostname: "example.com".into(), allowed: true },
            NetworkEventType::DnsCacheHit { hostname: "example.com".into() },
            NetworkEventType::DnsCacheMiss { hostname: "new.com".into() },
            NetworkEventType::ZoneCommunicationChecked { from_zone: "dmz".into(), to_zone: "internal".into(), allowed: true },
            NetworkEventType::SegmentationViolationDetected { from_zone: "untrusted".into(), to_zone: "secure".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 30);
    }
}
