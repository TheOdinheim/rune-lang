// ═══════════════════════════════════════════════════════════════════════
// Crypto Error Types
// ═══════════════════════════════════════════════════════════════════════

/// Errors from cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Key length does not match algorithm requirements.
    InvalidKeyLength { expected: usize, actual: usize },
    /// Signature length does not match algorithm output.
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Signature or MAC verification failed.
    VerificationFailed,
    /// The requested algorithm is not supported.
    UnsupportedAlgorithm(String),
    /// The operation is defined but not yet implemented (KEM placeholder).
    NotImplemented(String),
    /// Internal cryptographic error.
    InternalError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected} bytes, got {actual}")
            }
            Self::InvalidSignatureLength { expected, actual } => {
                write!(f, "invalid signature length: expected {expected} bytes, got {actual}")
            }
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported algorithm: {alg}")
            }
            Self::NotImplemented(op) => {
                write!(f, "not implemented: {op}")
            }
            Self::InternalError(msg) => write!(f, "crypto error: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}
