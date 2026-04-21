// ═══════════════════════════════════════════════════════════════════════
// rune-networking-ext — Network-layer governance, protocol enforcement,
// traffic classification, network segmentation, certificate management,
// DNS governance, rate limiting, firewall rules, and connection
// auditing for the RUNE governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod certificate;
pub mod connection;
pub mod dns;
pub mod error;
pub mod firewall;
pub mod protocol;
pub mod rate_limit;
pub mod segmentation;
pub mod traffic;

// Layer 2 modules
pub mod l2_certificate;
pub mod l2_dns;
pub mod l2_policy;
pub mod l2_pool;
pub mod l2_segmentation;
pub mod l2_traffic_chain;

// Layer 3 modules
pub mod backend;
pub mod dns_security;
pub mod network_export;
pub mod network_metrics;
pub mod network_stream;
pub mod segmentation_verifier;
pub mod tls_policy_enforcer;

// ── Re-exports ───────────────────────────────────────────────────────

pub use audit::{NetworkAuditEvent, NetworkAuditLog, NetworkEventType};
pub use certificate::{
    CertificateCheck, CertificateInfo, CertificateStatus, CertificateStore,
    CertificateValidationResult, KeyType,
};
pub use connection::{
    Connection, ConnectionId, ConnectionProtocol, ConnectionState, ConnectionStore,
};
pub use dns::{DnsDecision, DnsGovernor, DnsPolicy, DnsQuery, DnsQueryType};
pub use error::NetworkError;
pub use firewall::{
    Direction, Firewall, FirewallAction, FirewallCondition, FirewallDecision, FirewallRule,
};
pub use protocol::{
    CertificateValidation, CipherSuite, ProtocolCheckResult, ProtocolChecker, TlsPolicy,
    TlsVersion,
};
pub use rate_limit::{
    NetworkRateLimitConfig, NetworkRateLimiter, NetworkRateResult, RateCounter, RateLimitType,
};
pub use segmentation::{
    NetworkZone, SegmentationAction, SegmentationDecision, SegmentationEnforcer,
    SegmentationPolicy, ZoneFlow, ZoneType,
};
pub use traffic::{
    TrafficClassification, TrafficClassifier, TrafficCondition, TrafficRule, TrustLevel,
    evaluate_traffic_condition, is_in_cidr,
};

// ── Layer 2 re-exports ──────────────────────────────────────────────

pub use l2_certificate::{
    CertificateIssue, L2Certificate, L2CertificateStore, L2CertificateValidation,
    L2KeyAlgorithm, validate_certificate,
};
pub use l2_dns::{DnsCache, DnsCheckResult, DnsRecord, DnsRecordType, DnsSecurityChecker};
pub use l2_policy::{
    L2NetworkPolicy, NetworkAction, NetworkMatch, NetworkPolicyDecision, NetworkPolicyEngine,
    NetworkRule, TrafficDirection,
};
pub use l2_pool::{
    GovernedConnectionPool, L2ConnectionState, PoolStats, PooledConnection,
};
pub use l2_segmentation::{
    InterZoneRule, L2NetworkZone, L2SegmentationPolicy, SegmentationViolation, ZoneTrustLevel,
};
pub use l2_traffic_chain::{TrafficAuditChain, TrafficChainVerification, TrafficRecord};

// ── Layer 3 re-exports ──────────────────────────────────────────────

pub use backend::{
    InMemoryNetworkGovernanceBackend, NetworkGovernanceBackend, StoredCertificateRecord,
    StoredCertificateRecordStatus, StoredConnectionRecord, StoredConnectionStatus,
    StoredDnsPolicy, StoredEnforcementMode, StoredMinTlsVersion,
    StoredNetworkGovernanceSnapshot, StoredSegmentationDefaultAction, StoredSegmentationPolicy,
    StoredTlsPolicy, TlsPolicyScope,
};
pub use dns_security::{
    BlocklistDnsSecurityGovernor, DnsQueryDecision, DnsQueryEvaluation, DnsSecurityGovernor,
    DnssecStatus, InMemoryDnsSecurityGovernor, NullDnsSecurityGovernor,
    ResolverComplianceResult,
};
pub use network_export::{
    CjisNetworkSecurityExporter, JsonNetworkGovernanceExporter, NetworkGovernanceExporter,
    PciDssNetworkComplianceExporter, TlsCertificateInventoryExporter,
    ZeroTrustAssessmentExporter,
};
pub use network_metrics::{
    CertificateHealthRecord, DnsQueryRecord, InMemoryNetworkGovernanceMetricsCollector,
    NetworkGovernanceMetricSnapshot, NetworkGovernanceMetricsCollector,
    NullNetworkGovernanceMetricsCollector, SegmentationFlowRecord, TlsConnectionRecord,
};
pub use network_stream::{
    FilteredNetworkGovernanceEventSubscriber, NetworkGovernanceEventCollector,
    NetworkGovernanceEventSubscriber, NetworkGovernanceEventSubscriberRegistry,
    NetworkGovernanceLifecycleEvent, NetworkGovernanceLifecycleEventType,
};
pub use segmentation_verifier::{
    DenyByDefaultSegmentationVerifier, InMemoryNetworkSegmentationVerifier,
    NetworkSegmentationVerifier, NullNetworkSegmentationVerifier, SegmentationImprovement,
    SegmentationVerification, SegmentationVerificationDecision,
};
pub use tls_policy_enforcer::{
    CertificateExpirationStatus, InMemoryTlsPolicyEnforcer, NullTlsPolicyEnforcer,
    StrictTlsPolicyEnforcer, TlsCertificateIssue, TlsPolicyDecision, TlsPolicyEnforcer,
};
