// ═══════════════════════════════════════════════════════════════════════
// Error — Network governance error types.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone)]
pub enum NetworkError {
    ConnectionNotFound(String),
    ConnectionAlreadyExists(String),
    ConnectionLimitReached { max: usize },
    ConnectionNotActive(String),
    ProtocolViolation { detail: String },
    CertificateNotFound(String),
    CertificateInvalid { subject: String, reason: String },
    DnsBlocked { domain: String, reason: String },
    SegmentationViolation { source: String, dest: String, reason: String },
    RateLimitExceeded { source: String, limit_type: String },
    FirewallDenied { source: String, dest: String, reason: String },
    ZoneNotFound(String),
    InvalidCidr(String),
    InvalidConfiguration(String),
    InvalidOperation(String),
    // Layer 3
    SerializationFailed(String),
    TlsPolicyNotFound(String),
    SegmentationPolicyNotFound(String),
    DnsPolicyNotFound(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionNotFound(id) => write!(f, "Connection not found: {id}"),
            Self::ConnectionAlreadyExists(id) => write!(f, "Connection already exists: {id}"),
            Self::ConnectionLimitReached { max } => {
                write!(f, "Connection limit reached: max {max}")
            }
            Self::ConnectionNotActive(id) => write!(f, "Connection not active: {id}"),
            Self::ProtocolViolation { detail } => write!(f, "Protocol violation: {detail}"),
            Self::CertificateNotFound(id) => write!(f, "Certificate not found: {id}"),
            Self::CertificateInvalid { subject, reason } => {
                write!(f, "Certificate invalid ({subject}): {reason}")
            }
            Self::DnsBlocked { domain, reason } => {
                write!(f, "DNS blocked ({domain}): {reason}")
            }
            Self::SegmentationViolation {
                source,
                dest,
                reason,
            } => write!(f, "Segmentation violation ({source}→{dest}): {reason}"),
            Self::RateLimitExceeded { source, limit_type } => {
                write!(f, "Rate limit exceeded ({limit_type}): {source}")
            }
            Self::FirewallDenied {
                source,
                dest,
                reason,
            } => write!(f, "Firewall denied ({source}→{dest}): {reason}"),
            Self::ZoneNotFound(id) => write!(f, "Zone not found: {id}"),
            Self::InvalidCidr(cidr) => write!(f, "Invalid CIDR: {cidr}"),
            Self::InvalidConfiguration(detail) => {
                write!(f, "Invalid configuration: {detail}")
            }
            Self::InvalidOperation(detail) => write!(f, "Invalid operation: {detail}"),
            Self::SerializationFailed(detail) => {
                write!(f, "Serialization failed: {detail}")
            }
            Self::TlsPolicyNotFound(id) => write!(f, "TLS policy not found: {id}"),
            Self::SegmentationPolicyNotFound(id) => {
                write!(f, "Segmentation policy not found: {id}")
            }
            Self::DnsPolicyNotFound(id) => write!(f, "DNS policy not found: {id}"),
        }
    }
}

impl std::error::Error for NetworkError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<NetworkError> = vec![
            NetworkError::ConnectionNotFound("c1".into()),
            NetworkError::ConnectionAlreadyExists("c1".into()),
            NetworkError::ConnectionLimitReached { max: 100 },
            NetworkError::ConnectionNotActive("c1".into()),
            NetworkError::ProtocolViolation { detail: "bad".into() },
            NetworkError::CertificateNotFound("cert1".into()),
            NetworkError::CertificateInvalid { subject: "cn".into(), reason: "expired".into() },
            NetworkError::DnsBlocked { domain: "evil.com".into(), reason: "blocked".into() },
            NetworkError::SegmentationViolation { source: "z1".into(), dest: "z2".into(), reason: "denied".into() },
            NetworkError::RateLimitExceeded { source: "1.2.3.4".into(), limit_type: "per-source".into() },
            NetworkError::FirewallDenied { source: "1.2.3.4".into(), dest: "5.6.7.8".into(), reason: "rule".into() },
            NetworkError::ZoneNotFound("z1".into()),
            NetworkError::InvalidCidr("bad/cidr".into()),
            NetworkError::InvalidConfiguration("bad config".into()),
            NetworkError::InvalidOperation("bad op".into()),
            // Layer 3
            NetworkError::SerializationFailed("json error".into()),
            NetworkError::TlsPolicyNotFound("tls-1".into()),
            NetworkError::SegmentationPolicyNotFound("seg-1".into()),
            NetworkError::DnsPolicyNotFound("dns-1".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(errors.len(), 19);
    }
}
