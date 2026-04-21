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
    // Layer 3
    StoredTlsPolicyCreated { policy_id: String, service_ref: String },
    StoredConnectionRecordCreated { record_id: String, connection_id: String },
    StoredSegmentationPolicyCreated { policy_id: String, policy_name: String },
    StoredDnsPolicyCreated { policy_id: String, policy_name: String },
    StoredCertificateRecordCreated { record_id: String, subject: String },
    StoredNetworkGovernanceSnapshotCaptured { snapshot_id: String },
    TlsPolicyConnectionEvaluated { enforcer_id: String, connection_id: String, decision: String },
    TlsPolicyNonCompliant { enforcer_id: String, connection_id: String, reason: String },
    TlsCertificateGovernanceEvaluated { enforcer_id: String, subject: String, decision: String },
    TlsCertificateIssueDetected { enforcer_id: String, subject: String, issue: String },
    SegmentationFlowVerified { verifier_id: String, source_zone: String, dest_zone: String, decision: String },
    SegmentationFlowDeniedByVerifier { verifier_id: String, source_zone: String, dest_zone: String },
    SegmentationComplianceAssessed { verifier_id: String, improvement_count: String },
    DnsQueryEvaluatedByGovernor { governor_id: String, domain: String, decision: String },
    DnsQueryBlockedByGovernor { governor_id: String, domain: String },
    DnsResolverComplianceChecked { governor_id: String, resolver_addr: String, compliant: bool },
    NetworkGovernanceExported { format: String, content_type: String },
    NetworkGovernanceExportFailed { format: String, reason: String },
    NetworkGovernanceMetricsComputed { collector_id: String, metric_type: String },
    NetworkGovernanceEventPublished { event_type: String, source_id: String },
    NetworkGovernanceFlushed { record_count: String },
    NetworkGovernanceBackendInfo { backend_id: String, backend_type: String },
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
            // Layer 3
            Self::StoredTlsPolicyCreated { policy_id, service_ref } => {
                write!(f, "StoredTlsPolicyCreated({policy_id}, service={service_ref})")
            }
            Self::StoredConnectionRecordCreated { record_id, connection_id } => {
                write!(f, "StoredConnectionRecordCreated({record_id}, conn={connection_id})")
            }
            Self::StoredSegmentationPolicyCreated { policy_id, policy_name } => {
                write!(f, "StoredSegmentationPolicyCreated({policy_id}, {policy_name})")
            }
            Self::StoredDnsPolicyCreated { policy_id, policy_name } => {
                write!(f, "StoredDnsPolicyCreated({policy_id}, {policy_name})")
            }
            Self::StoredCertificateRecordCreated { record_id, subject } => {
                write!(f, "StoredCertificateRecordCreated({record_id}, {subject})")
            }
            Self::StoredNetworkGovernanceSnapshotCaptured { snapshot_id } => {
                write!(f, "StoredNetworkGovernanceSnapshotCaptured({snapshot_id})")
            }
            Self::TlsPolicyConnectionEvaluated { enforcer_id, connection_id, decision } => {
                write!(f, "TlsPolicyConnectionEvaluated({enforcer_id}, {connection_id}, {decision})")
            }
            Self::TlsPolicyNonCompliant { enforcer_id, connection_id, reason } => {
                write!(f, "TlsPolicyNonCompliant({enforcer_id}, {connection_id}): {reason}")
            }
            Self::TlsCertificateGovernanceEvaluated { enforcer_id, subject, decision } => {
                write!(f, "TlsCertificateGovernanceEvaluated({enforcer_id}, {subject}, {decision})")
            }
            Self::TlsCertificateIssueDetected { enforcer_id, subject, issue } => {
                write!(f, "TlsCertificateIssueDetected({enforcer_id}, {subject}): {issue}")
            }
            Self::SegmentationFlowVerified { verifier_id, source_zone, dest_zone, decision } => {
                write!(f, "SegmentationFlowVerified({verifier_id}, {source_zone}→{dest_zone}, {decision})")
            }
            Self::SegmentationFlowDeniedByVerifier { verifier_id, source_zone, dest_zone } => {
                write!(f, "SegmentationFlowDeniedByVerifier({verifier_id}, {source_zone}→{dest_zone})")
            }
            Self::SegmentationComplianceAssessed { verifier_id, improvement_count } => {
                write!(f, "SegmentationComplianceAssessed({verifier_id}, improvements={improvement_count})")
            }
            Self::DnsQueryEvaluatedByGovernor { governor_id, domain, decision } => {
                write!(f, "DnsQueryEvaluatedByGovernor({governor_id}, {domain}, {decision})")
            }
            Self::DnsQueryBlockedByGovernor { governor_id, domain } => {
                write!(f, "DnsQueryBlockedByGovernor({governor_id}, {domain})")
            }
            Self::DnsResolverComplianceChecked { governor_id, resolver_addr, compliant } => {
                write!(f, "DnsResolverComplianceChecked({governor_id}, {resolver_addr}, compliant={compliant})")
            }
            Self::NetworkGovernanceExported { format, content_type } => {
                write!(f, "NetworkGovernanceExported({format}, {content_type})")
            }
            Self::NetworkGovernanceExportFailed { format, reason } => {
                write!(f, "NetworkGovernanceExportFailed({format}): {reason}")
            }
            Self::NetworkGovernanceMetricsComputed { collector_id, metric_type } => {
                write!(f, "NetworkGovernanceMetricsComputed({collector_id}, {metric_type})")
            }
            Self::NetworkGovernanceEventPublished { event_type, source_id } => {
                write!(f, "NetworkGovernanceEventPublished({event_type}, {source_id})")
            }
            Self::NetworkGovernanceFlushed { record_count } => {
                write!(f, "NetworkGovernanceFlushed(records={record_count})")
            }
            Self::NetworkGovernanceBackendInfo { backend_id, backend_type } => {
                write!(f, "NetworkGovernanceBackendInfo({backend_id}, {backend_type})")
            }
        }
    }
}

impl NetworkEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::ConnectionOpened { .. } => "ConnectionOpened",
            Self::ConnectionAuthenticated { .. } => "ConnectionAuthenticated",
            Self::ConnectionEstablished { .. } => "ConnectionEstablished",
            Self::ConnectionClosed { .. } => "ConnectionClosed",
            Self::ConnectionRejected { .. } => "ConnectionRejected",
            Self::ProtocolViolation { .. } => "ProtocolViolation",
            Self::CipherSuiteRejected { .. } => "CipherSuiteRejected",
            Self::TrafficClassified { .. } => "TrafficClassified",
            Self::SegmentationViolation { .. } => "SegmentationViolation",
            Self::CertificateValidated { .. } => "CertificateValidated",
            Self::CertificateExpiring { .. } => "CertificateExpiring",
            Self::DnsQueryBlocked { .. } => "DnsQueryBlocked",
            Self::DnsQueryAllowed { .. } => "DnsQueryAllowed",
            Self::RateLimitExceeded { .. } => "RateLimitExceeded",
            Self::FirewallRuleMatched { .. } => "FirewallRuleMatched",
            Self::CertificateAdded { .. } => "CertificateAdded",
            Self::CertificateExpiringL2 { .. } => "CertificateExpiringL2",
            Self::CertificateValidatedL2 { .. } => "CertificateValidatedL2",
            Self::NetworkPolicyEvaluated { .. } => "NetworkPolicyEvaluated",
            Self::NetworkPolicyAdded { .. } => "NetworkPolicyAdded",
            Self::ConnectionAcquired { .. } => "ConnectionAcquired",
            Self::ConnectionReleased { .. } => "ConnectionReleased",
            Self::ConnectionPoolEvicted { .. } => "ConnectionPoolEvicted",
            Self::TrafficRecorded { .. } => "TrafficRecorded",
            Self::TrafficChainVerified { .. } => "TrafficChainVerified",
            Self::DnsDomainChecked { .. } => "DnsDomainChecked",
            Self::DnsCacheHit { .. } => "DnsCacheHit",
            Self::DnsCacheMiss { .. } => "DnsCacheMiss",
            Self::ZoneCommunicationChecked { .. } => "ZoneCommunicationChecked",
            Self::SegmentationViolationDetected { .. } => "SegmentationViolationDetected",
            Self::StoredTlsPolicyCreated { .. } => "StoredTlsPolicyCreated",
            Self::StoredConnectionRecordCreated { .. } => "StoredConnectionRecordCreated",
            Self::StoredSegmentationPolicyCreated { .. } => "StoredSegmentationPolicyCreated",
            Self::StoredDnsPolicyCreated { .. } => "StoredDnsPolicyCreated",
            Self::StoredCertificateRecordCreated { .. } => "StoredCertificateRecordCreated",
            Self::StoredNetworkGovernanceSnapshotCaptured { .. } => "StoredNetworkGovernanceSnapshotCaptured",
            Self::TlsPolicyConnectionEvaluated { .. } => "TlsPolicyConnectionEvaluated",
            Self::TlsPolicyNonCompliant { .. } => "TlsPolicyNonCompliant",
            Self::TlsCertificateGovernanceEvaluated { .. } => "TlsCertificateGovernanceEvaluated",
            Self::TlsCertificateIssueDetected { .. } => "TlsCertificateIssueDetected",
            Self::SegmentationFlowVerified { .. } => "SegmentationFlowVerified",
            Self::SegmentationFlowDeniedByVerifier { .. } => "SegmentationFlowDeniedByVerifier",
            Self::SegmentationComplianceAssessed { .. } => "SegmentationComplianceAssessed",
            Self::DnsQueryEvaluatedByGovernor { .. } => "DnsQueryEvaluatedByGovernor",
            Self::DnsQueryBlockedByGovernor { .. } => "DnsQueryBlockedByGovernor",
            Self::DnsResolverComplianceChecked { .. } => "DnsResolverComplianceChecked",
            Self::NetworkGovernanceExported { .. } => "NetworkGovernanceExported",
            Self::NetworkGovernanceExportFailed { .. } => "NetworkGovernanceExportFailed",
            Self::NetworkGovernanceMetricsComputed { .. } => "NetworkGovernanceMetricsComputed",
            Self::NetworkGovernanceEventPublished { .. } => "NetworkGovernanceEventPublished",
            Self::NetworkGovernanceFlushed { .. } => "NetworkGovernanceFlushed",
            Self::NetworkGovernanceBackendInfo { .. } => "NetworkGovernanceBackendInfo",
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Self::ConnectionOpened { .. }
            | Self::ConnectionAuthenticated { .. }
            | Self::ConnectionEstablished { .. }
            | Self::ConnectionClosed { .. }
            | Self::ConnectionRejected { .. } => "connection",
            Self::ProtocolViolation { .. }
            | Self::CipherSuiteRejected { .. } => "protocol",
            Self::TrafficClassified { .. } => "traffic",
            Self::SegmentationViolation { .. } => "segmentation",
            Self::CertificateValidated { .. }
            | Self::CertificateExpiring { .. } => "certificate",
            Self::DnsQueryBlocked { .. }
            | Self::DnsQueryAllowed { .. } => "dns",
            Self::RateLimitExceeded { .. } => "rate_limit",
            Self::FirewallRuleMatched { .. } => "firewall",
            // Layer 2
            Self::CertificateAdded { .. }
            | Self::CertificateExpiringL2 { .. }
            | Self::CertificateValidatedL2 { .. } => "l2_certificate",
            Self::NetworkPolicyEvaluated { .. }
            | Self::NetworkPolicyAdded { .. } => "l2_policy",
            Self::ConnectionAcquired { .. }
            | Self::ConnectionReleased { .. }
            | Self::ConnectionPoolEvicted { .. } => "l2_pool",
            Self::TrafficRecorded { .. }
            | Self::TrafficChainVerified { .. } => "l2_traffic_chain",
            Self::DnsDomainChecked { .. }
            | Self::DnsCacheHit { .. }
            | Self::DnsCacheMiss { .. } => "l2_dns",
            Self::ZoneCommunicationChecked { .. }
            | Self::SegmentationViolationDetected { .. } => "l2_segmentation",
            // Layer 3
            Self::StoredTlsPolicyCreated { .. }
            | Self::StoredConnectionRecordCreated { .. }
            | Self::StoredSegmentationPolicyCreated { .. }
            | Self::StoredDnsPolicyCreated { .. }
            | Self::StoredCertificateRecordCreated { .. }
            | Self::StoredNetworkGovernanceSnapshotCaptured { .. }
            | Self::NetworkGovernanceFlushed { .. }
            | Self::NetworkGovernanceBackendInfo { .. } => "governance_backend",
            Self::TlsPolicyConnectionEvaluated { .. }
            | Self::TlsPolicyNonCompliant { .. }
            | Self::TlsCertificateGovernanceEvaluated { .. }
            | Self::TlsCertificateIssueDetected { .. } => "tls_governance",
            Self::SegmentationFlowVerified { .. }
            | Self::SegmentationFlowDeniedByVerifier { .. }
            | Self::SegmentationComplianceAssessed { .. } => "segmentation_governance",
            Self::DnsQueryEvaluatedByGovernor { .. }
            | Self::DnsQueryBlockedByGovernor { .. }
            | Self::DnsResolverComplianceChecked { .. } => "dns_governance",
            Self::NetworkGovernanceExported { .. }
            | Self::NetworkGovernanceExportFailed { .. } => "governance_export",
            Self::NetworkGovernanceMetricsComputed { .. } => "governance_metrics",
            Self::NetworkGovernanceEventPublished { .. } => "governance_stream",
        }
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::StoredTlsPolicyCreated { .. }
                | Self::StoredConnectionRecordCreated { .. }
                | Self::StoredSegmentationPolicyCreated { .. }
                | Self::StoredDnsPolicyCreated { .. }
                | Self::StoredCertificateRecordCreated { .. }
                | Self::StoredNetworkGovernanceSnapshotCaptured { .. }
                | Self::NetworkGovernanceFlushed { .. }
                | Self::NetworkGovernanceBackendInfo { .. }
        )
    }

    pub fn is_tls_governance_event(&self) -> bool {
        matches!(
            self,
            Self::TlsPolicyConnectionEvaluated { .. }
                | Self::TlsPolicyNonCompliant { .. }
                | Self::TlsCertificateGovernanceEvaluated { .. }
                | Self::TlsCertificateIssueDetected { .. }
        )
    }

    pub fn is_segmentation_governance_event(&self) -> bool {
        matches!(
            self,
            Self::SegmentationFlowVerified { .. }
                | Self::SegmentationFlowDeniedByVerifier { .. }
                | Self::SegmentationComplianceAssessed { .. }
        )
    }

    pub fn is_dns_governance_event(&self) -> bool {
        matches!(
            self,
            Self::DnsQueryEvaluatedByGovernor { .. }
                | Self::DnsQueryBlockedByGovernor { .. }
                | Self::DnsResolverComplianceChecked { .. }
        )
    }

    pub fn is_governance_export_event(&self) -> bool {
        matches!(
            self,
            Self::NetworkGovernanceExported { .. }
                | Self::NetworkGovernanceExportFailed { .. }
        )
    }

    pub fn is_governance_metrics_event(&self) -> bool {
        matches!(self, Self::NetworkGovernanceMetricsComputed { .. })
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
            // Layer 3
            NetworkEventType::StoredTlsPolicyCreated { policy_id: "tp1".into(), service_ref: "svc-a".into() },
            NetworkEventType::StoredConnectionRecordCreated { record_id: "cr1".into(), connection_id: "c1".into() },
            NetworkEventType::StoredSegmentationPolicyCreated { policy_id: "sp1".into(), policy_name: "default".into() },
            NetworkEventType::StoredDnsPolicyCreated { policy_id: "dp1".into(), policy_name: "corp".into() },
            NetworkEventType::StoredCertificateRecordCreated { record_id: "cert1".into(), subject: "CN=test".into() },
            NetworkEventType::StoredNetworkGovernanceSnapshotCaptured { snapshot_id: "snap1".into() },
            NetworkEventType::TlsPolicyConnectionEvaluated { enforcer_id: "e1".into(), connection_id: "c1".into(), decision: "Compliant".into() },
            NetworkEventType::TlsPolicyNonCompliant { enforcer_id: "e1".into(), connection_id: "c1".into(), reason: "TLS 1.0".into() },
            NetworkEventType::TlsCertificateGovernanceEvaluated { enforcer_id: "e1".into(), subject: "CN=test".into(), decision: "Compliant".into() },
            NetworkEventType::TlsCertificateIssueDetected { enforcer_id: "e1".into(), subject: "CN=test".into(), issue: "Expired".into() },
            NetworkEventType::SegmentationFlowVerified { verifier_id: "v1".into(), source_zone: "dmz".into(), dest_zone: "internal".into(), decision: "Allowed".into() },
            NetworkEventType::SegmentationFlowDeniedByVerifier { verifier_id: "v1".into(), source_zone: "dmz".into(), dest_zone: "restricted".into() },
            NetworkEventType::SegmentationComplianceAssessed { verifier_id: "v1".into(), improvement_count: "3".into() },
            NetworkEventType::DnsQueryEvaluatedByGovernor { governor_id: "g1".into(), domain: "example.com".into(), decision: "Allow".into() },
            NetworkEventType::DnsQueryBlockedByGovernor { governor_id: "g1".into(), domain: "evil.com".into() },
            NetworkEventType::DnsResolverComplianceChecked { governor_id: "g1".into(), resolver_addr: "8.8.8.8".into(), compliant: true },
            NetworkEventType::NetworkGovernanceExported { format: "json".into(), content_type: "application/json".into() },
            NetworkEventType::NetworkGovernanceExportFailed { format: "json".into(), reason: "serialization error".into() },
            NetworkEventType::NetworkGovernanceMetricsComputed { collector_id: "m1".into(), metric_type: "tls_compliance".into() },
            NetworkEventType::NetworkGovernanceEventPublished { event_type: "TlsPolicyCreated".into(), source_id: "enforcer-1".into() },
            NetworkEventType::NetworkGovernanceFlushed { record_count: "42".into() },
            NetworkEventType::NetworkGovernanceBackendInfo { backend_id: "b1".into(), backend_type: "in-memory".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 52);
    }

    #[test]
    fn test_type_name() {
        let e = NetworkEventType::ConnectionOpened { protocol: "TCP".into() };
        assert_eq!(e.type_name(), "ConnectionOpened");
        let e2 = NetworkEventType::StoredTlsPolicyCreated { policy_id: "tp1".into(), service_ref: "svc".into() };
        assert_eq!(e2.type_name(), "StoredTlsPolicyCreated");
    }

    #[test]
    fn test_kind() {
        let e = NetworkEventType::ConnectionOpened { protocol: "TCP".into() };
        assert_eq!(e.kind(), "connection");
        let e2 = NetworkEventType::TlsPolicyConnectionEvaluated {
            enforcer_id: "e1".into(),
            connection_id: "c1".into(),
            decision: "Compliant".into(),
        };
        assert_eq!(e2.kind(), "tls_governance");
        let e3 = NetworkEventType::DnsQueryBlockedByGovernor {
            governor_id: "g1".into(),
            domain: "evil.com".into(),
        };
        assert_eq!(e3.kind(), "dns_governance");
    }

    #[test]
    fn test_is_backend_event() {
        let e = NetworkEventType::StoredTlsPolicyCreated { policy_id: "tp1".into(), service_ref: "svc".into() };
        assert!(e.is_backend_event());
        let e2 = NetworkEventType::ConnectionOpened { protocol: "TCP".into() };
        assert!(!e2.is_backend_event());
    }

    #[test]
    fn test_is_tls_governance_event() {
        let e = NetworkEventType::TlsPolicyNonCompliant {
            enforcer_id: "e1".into(),
            connection_id: "c1".into(),
            reason: "TLS 1.0".into(),
        };
        assert!(e.is_tls_governance_event());
    }

    #[test]
    fn test_is_segmentation_governance_event() {
        let e = NetworkEventType::SegmentationFlowVerified {
            verifier_id: "v1".into(),
            source_zone: "dmz".into(),
            dest_zone: "internal".into(),
            decision: "Allowed".into(),
        };
        assert!(e.is_segmentation_governance_event());
    }

    #[test]
    fn test_is_dns_governance_event() {
        let e = NetworkEventType::DnsQueryEvaluatedByGovernor {
            governor_id: "g1".into(),
            domain: "example.com".into(),
            decision: "Allow".into(),
        };
        assert!(e.is_dns_governance_event());
    }

    #[test]
    fn test_is_governance_export_event() {
        let e = NetworkEventType::NetworkGovernanceExported {
            format: "json".into(),
            content_type: "application/json".into(),
        };
        assert!(e.is_governance_export_event());
    }

    #[test]
    fn test_is_governance_metrics_event() {
        let e = NetworkEventType::NetworkGovernanceMetricsComputed {
            collector_id: "m1".into(),
            metric_type: "tls_compliance".into(),
        };
        assert!(e.is_governance_metrics_event());
    }
}
