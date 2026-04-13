// ═══════════════════════════════════════════════════════════════════════
// Error — Web error types for rune-web
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone)]
pub enum WebError {
    EndpointNotFound(String),
    EndpointAlreadyExists(String),
    SessionNotFound(String),
    SessionExpired(String),
    SessionInvalid(String),
    RateLimitExceeded { key: String, retry_after_ms: u64 },
    ValidationFailed { checks: Vec<String> },
    SignatureInvalid(String),
    SignatureExpired { skew_ms: i64, max_ms: i64 },
    CorsViolation { origin: String, reason: String },
    ThreatDetected { threat_type: String },
    InvalidConfiguration(String),
    InvalidOperation(String),
}

impl fmt::Display for WebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointNotFound(id) => write!(f, "Endpoint not found: {id}"),
            Self::EndpointAlreadyExists(id) => write!(f, "Endpoint already exists: {id}"),
            Self::SessionNotFound(id) => write!(f, "Session not found: {id}"),
            Self::SessionExpired(id) => write!(f, "Session expired: {id}"),
            Self::SessionInvalid(id) => write!(f, "Session invalid: {id}"),
            Self::RateLimitExceeded { key, retry_after_ms } => {
                write!(f, "Rate limit exceeded for {key}, retry after {retry_after_ms}ms")
            }
            Self::ValidationFailed { checks } => {
                write!(f, "Validation failed: {}", checks.join(", "))
            }
            Self::SignatureInvalid(reason) => write!(f, "Signature invalid: {reason}"),
            Self::SignatureExpired { skew_ms, max_ms } => {
                write!(f, "Signature expired: skew {skew_ms}ms exceeds max {max_ms}ms")
            }
            Self::CorsViolation { origin, reason } => {
                write!(f, "CORS violation from {origin}: {reason}")
            }
            Self::ThreatDetected { threat_type } => {
                write!(f, "Threat detected: {threat_type}")
            }
            Self::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {msg}"),
            Self::InvalidOperation(msg) => write!(f, "Invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for WebError {}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<WebError> = vec![
            WebError::EndpointNotFound("ep1".into()),
            WebError::EndpointAlreadyExists("ep1".into()),
            WebError::SessionNotFound("s1".into()),
            WebError::SessionExpired("s1".into()),
            WebError::SessionInvalid("s1".into()),
            WebError::RateLimitExceeded { key: "ip:1.2.3.4".into(), retry_after_ms: 5000 },
            WebError::ValidationFailed { checks: vec!["path too long".into()] },
            WebError::SignatureInvalid("wrong key".into()),
            WebError::SignatureExpired { skew_ms: 600000, max_ms: 300000 },
            WebError::CorsViolation { origin: "evil.com".into(), reason: "not allowed".into() },
            WebError::ThreatDetected { threat_type: "CSRF".into() },
            WebError::InvalidConfiguration("bad config".into()),
            WebError::InvalidOperation("cannot do that".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
            // Verify Debug and Error trait
            let _ = format!("{e:?}");
            let _: &dyn std::error::Error = e;
        }
        assert_eq!(errors.len(), 13);
    }
}
