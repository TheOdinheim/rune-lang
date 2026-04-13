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
