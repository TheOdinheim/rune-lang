// ═══════════════════════════════════════════════════════════════════════
// Identity Error Types
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::credential::CredentialId;
use crate::identity::IdentityId;
use crate::identity_type::PasswordViolation;
use crate::authn::AuthnFailureReason;
use crate::session::SessionId;
use crate::trust::TrustLevel;

#[derive(Debug, Clone)]
pub enum IdentityError {
    IdentityNotFound(IdentityId),
    IdentityAlreadyExists(IdentityId),
    IdentitySuspended(IdentityId),
    IdentityLocked(IdentityId),
    IdentityRevoked(IdentityId),
    IdentityExpired(IdentityId),
    CredentialNotFound(CredentialId),
    CredentialAlreadyExists(CredentialId),
    CredentialExpired(CredentialId),
    CredentialRevoked(CredentialId),
    CredentialCompromised(CredentialId),
    SessionNotFound(SessionId),
    SessionExpired(SessionId),
    SessionRevoked(SessionId),
    MaxConcurrentSessions { max: u32, current: u32 },
    AuthenticationFailed(AuthnFailureReason),
    RateLimited { retry_after_ms: i64 },
    InvalidPassword(Vec<PasswordViolation>),
    InsufficientTrust { required: TrustLevel, actual: TrustLevel },
    InvalidTransition { from: String, to: String },
    InvalidOperation(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityNotFound(id) => write!(f, "identity not found: {id}"),
            Self::IdentityAlreadyExists(id) => write!(f, "identity already exists: {id}"),
            Self::IdentitySuspended(id) => write!(f, "identity suspended: {id}"),
            Self::IdentityLocked(id) => write!(f, "identity locked: {id}"),
            Self::IdentityRevoked(id) => write!(f, "identity revoked: {id}"),
            Self::IdentityExpired(id) => write!(f, "identity expired: {id}"),
            Self::CredentialNotFound(id) => write!(f, "credential not found: {id}"),
            Self::CredentialAlreadyExists(id) => write!(f, "credential already exists: {id}"),
            Self::CredentialExpired(id) => write!(f, "credential expired: {id}"),
            Self::CredentialRevoked(id) => write!(f, "credential revoked: {id}"),
            Self::CredentialCompromised(id) => write!(f, "credential compromised: {id}"),
            Self::SessionNotFound(id) => write!(f, "session not found: {id}"),
            Self::SessionExpired(id) => write!(f, "session expired: {id}"),
            Self::SessionRevoked(id) => write!(f, "session revoked: {id}"),
            Self::MaxConcurrentSessions { max, current } => {
                write!(f, "max concurrent sessions exceeded: {current}/{max}")
            }
            Self::AuthenticationFailed(reason) => write!(f, "authentication failed: {reason}"),
            Self::RateLimited { retry_after_ms } => {
                write!(f, "rate limited, retry after {retry_after_ms}ms")
            }
            Self::InvalidPassword(violations) => {
                let msgs: Vec<String> = violations.iter().map(|v| v.to_string()).collect();
                write!(f, "invalid password: {}", msgs.join(", "))
            }
            Self::InsufficientTrust { required, actual } => {
                write!(f, "insufficient trust: required {required}, actual {actual}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid state transition: {from} → {to}")
            }
            Self::InvalidOperation(msg) => write!(f, "invalid operation: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let errors: Vec<IdentityError> = vec![
            IdentityError::IdentityNotFound(IdentityId::new("user:x")),
            IdentityError::IdentityAlreadyExists(IdentityId::new("user:x")),
            IdentityError::IdentitySuspended(IdentityId::new("user:x")),
            IdentityError::IdentityLocked(IdentityId::new("user:x")),
            IdentityError::IdentityRevoked(IdentityId::new("user:x")),
            IdentityError::IdentityExpired(IdentityId::new("user:x")),
            IdentityError::CredentialNotFound(CredentialId::new("c1")),
            IdentityError::CredentialAlreadyExists(CredentialId::new("c1")),
            IdentityError::CredentialExpired(CredentialId::new("c1")),
            IdentityError::CredentialRevoked(CredentialId::new("c1")),
            IdentityError::CredentialCompromised(CredentialId::new("c1")),
            IdentityError::SessionNotFound(SessionId::new("s1")),
            IdentityError::SessionExpired(SessionId::new("s1")),
            IdentityError::SessionRevoked(SessionId::new("s1")),
            IdentityError::MaxConcurrentSessions { max: 5, current: 5 },
            IdentityError::AuthenticationFailed(AuthnFailureReason::InvalidCredentials),
            IdentityError::RateLimited { retry_after_ms: 1000 },
            IdentityError::InvalidPassword(vec![PasswordViolation::TooShort { min: 12, actual: 5 }]),
            IdentityError::InsufficientTrust { required: TrustLevel::High, actual: TrustLevel::Low },
            IdentityError::InvalidTransition { from: "Active".into(), to: "Active".into() },
            IdentityError::InvalidOperation("test".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }
}
