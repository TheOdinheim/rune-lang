use std::fmt;
use crate::secret::SecretId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    SecretNotFound(SecretId),
    SecretAlreadyExists(SecretId),
    SecretCompromised(SecretId),
    SecretDestroyed(SecretId),
    SecretExpired { id: SecretId, expired_at: i64 },
    VersionNotFound { id: SecretId, version: u32 },
    EncryptionFailed(String),
    DecryptionFailed(String),
    KeyDerivationFailed(String),
    InvalidShares(String),
    InsufficientShares { required: u8, provided: u8 },
    TransitExpired { created_at: i64, expired_at: i64 },
    IntegrityCheckFailed { expected: String, actual: String },
    AccessDenied(String),
    InvalidClassification(String),
    RotationFailed(String),
    UsageLimitExceeded { id: SecretId },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretNotFound(id) => write!(f, "secret not found: {id}"),
            Self::SecretAlreadyExists(id) => write!(f, "secret already exists: {id}"),
            Self::SecretCompromised(id) => write!(f, "secret compromised: {id}"),
            Self::SecretDestroyed(id) => write!(f, "secret destroyed: {id}"),
            Self::SecretExpired { id, expired_at } => {
                write!(f, "secret {id} expired at {expired_at}")
            }
            Self::VersionNotFound { id, version } => {
                write!(f, "secret {id} version {version} not found")
            }
            Self::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            Self::KeyDerivationFailed(msg) => write!(f, "key derivation failed: {msg}"),
            Self::InvalidShares(msg) => write!(f, "invalid shares: {msg}"),
            Self::InsufficientShares { required, provided } => {
                write!(f, "insufficient shares: need {required}, have {provided}")
            }
            Self::TransitExpired { created_at, expired_at } => {
                write!(f, "transit package expired: created {created_at}, expired {expired_at}")
            }
            Self::IntegrityCheckFailed { expected, actual } => {
                write!(f, "integrity check failed: expected {expected}, got {actual}")
            }
            Self::AccessDenied(msg) => write!(f, "access denied: {msg}"),
            Self::InvalidClassification(msg) => write!(f, "invalid classification: {msg}"),
            Self::RotationFailed(msg) => write!(f, "rotation failed: {msg}"),
            Self::UsageLimitExceeded { id } => write!(f, "usage limit exceeded: {id}"),
        }
    }
}

impl std::error::Error for SecretError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_display() {
        let errors: Vec<SecretError> = vec![
            SecretError::SecretNotFound(SecretId::new("x")),
            SecretError::SecretAlreadyExists(SecretId::new("x")),
            SecretError::SecretCompromised(SecretId::new("x")),
            SecretError::SecretDestroyed(SecretId::new("x")),
            SecretError::SecretExpired { id: SecretId::new("x"), expired_at: 100 },
            SecretError::VersionNotFound { id: SecretId::new("x"), version: 2 },
            SecretError::EncryptionFailed("bad".into()),
            SecretError::DecryptionFailed("bad".into()),
            SecretError::KeyDerivationFailed("bad".into()),
            SecretError::InvalidShares("bad".into()),
            SecretError::InsufficientShares { required: 3, provided: 2 },
            SecretError::TransitExpired { created_at: 1, expired_at: 2 },
            SecretError::IntegrityCheckFailed { expected: "a".into(), actual: "b".into() },
            SecretError::AccessDenied("no".into()),
            SecretError::InvalidClassification("bad".into()),
            SecretError::RotationFailed("bad".into()),
            SecretError::UsageLimitExceeded { id: SecretId::new("x") },
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }
}
