// ═══════════════════════════════════════════════════════════════════════
// Model Attestation Checker — Runtime Trust Chain Verification
//
// Verifies model trust chains before execution. An AttestedModel carries
// cryptographic proof — the type system refuses to load or invoke
// unattested models. Models that fail attestation are rejected before
// they can process any input.
//
// Cryptographic primitives (M10 Layer 4 PQC swap):
//   - HMAC-SHA3-256 for signing (ML-DSA placeholder)
//   - SHA3-256 (FIPS 202) for hashing
//
// Uses the same crypto module as audit.rs — both now use PQC-first
// implementations from stdlib::crypto.
//
// Pillar: Zero Trust Throughout — every model must prove its identity
// and provenance before the runtime will invoke it.
//
// Pillar: Security Baked In — attestation is not optional. The type
// system enforces that only AttestedModel values can be invoked.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;

use crate::runtime::audit::crypto;

// ── Model attestation ─────────────────────────────────────────────────

/// Cryptographic attestation for a model artifact.
#[derive(Debug, Clone)]
pub struct ModelAttestation {
    /// Unique identifier for the model.
    pub model_id: String,
    /// Hash of the model artifact (SHA3-256).
    pub model_hash: String,
    /// Identity of who signed the attestation.
    pub signer: String,
    /// Cryptographic signature (HMAC-SHA3-256, ML-DSA placeholder).
    pub signature: String,
    /// When the attestation was created.
    pub timestamp: SystemTime,
    /// Supply chain provenance metadata.
    pub provenance: ModelProvenance,
    /// Governance policies this model must satisfy.
    pub policy_requirements: Vec<String>,
}

/// Supply chain provenance metadata for a model.
#[derive(Debug, Clone)]
pub struct ModelProvenance {
    /// Where the model came from.
    pub source_repository: String,
    /// Hash of the training data manifest (if available).
    pub training_data_hash: Option<String>,
    /// ML framework used (e.g., "pytorch", "onnx", "tensorflow").
    pub framework: String,
    /// Model architecture (e.g., "transformer", "cnn", "diffusion").
    pub architecture: String,
    /// SLSA build provenance level (0-4).
    pub slsa_level: Option<u8>,
}

// ── Attestation policy ────────────────────────────────────────────────

/// Policy governing which model attestations are acceptable.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    /// At least one of these signers must have signed the attestation.
    pub required_signers: Vec<String>,
    /// Minimum acceptable SLSA build provenance level.
    pub minimum_slsa_level: Option<u8>,
    /// If set, the model's framework must be in this list.
    pub allowed_frameworks: Option<Vec<String>>,
    /// Whether training data provenance hash is required.
    pub require_training_data_hash: bool,
    /// Maximum age of attestation in seconds (None = no limit).
    pub max_age_seconds: Option<u64>,
}

impl AttestationPolicy {
    /// A permissive policy that only checks the signature.
    pub fn permissive() -> Self {
        Self {
            required_signers: Vec::new(),
            minimum_slsa_level: None,
            allowed_frameworks: None,
            require_training_data_hash: false,
            max_age_seconds: None,
        }
    }
}

// ── Verdict and errors ────────────────────────────────────────────────

/// The outcome of an attestation verification.
#[derive(Debug, Clone)]
pub enum AttestationVerdict {
    /// The model's attestation is valid and trusted.
    Trusted {
        signer: String,
        verified_at: SystemTime,
    },
    /// The model's attestation was rejected.
    Rejected {
        reason: AttestationError,
    },
}

/// Errors that can occur during attestation verification.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestationError {
    /// The signer is not in the trusted keys set.
    UnknownSigner { signer: String },
    /// The signature does not verify against the signer's key.
    InvalidSignature { signer: String, model_id: String },
    /// SLSA level is below the minimum required.
    InsufficientSLSALevel { required: u8, actual: u8 },
    /// The model's framework is not in the allowed list.
    DisallowedFramework { framework: String, allowed: Vec<String> },
    /// Training data hash is required but missing.
    MissingTrainingDataHash { model_id: String },
    /// The attestation has expired.
    ExpiredAttestation { age_seconds: u64, max_age_seconds: u64 },
    /// No required signer has signed this attestation.
    NoTrustedSigner { model_id: String, required_signers: Vec<String> },
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::UnknownSigner { signer } => {
                write!(f, "unknown signer '{signer}': not in trusted keys")
            }
            AttestationError::InvalidSignature { signer, model_id } => {
                write!(f, "invalid signature from '{signer}' for model '{model_id}'")
            }
            AttestationError::InsufficientSLSALevel { required, actual } => {
                write!(f, "SLSA level {actual} below minimum required level {required}")
            }
            AttestationError::DisallowedFramework { framework, allowed } => {
                write!(f, "framework '{framework}' not in allowed list: {allowed:?}")
            }
            AttestationError::MissingTrainingDataHash { model_id } => {
                write!(f, "model '{model_id}' missing required training data hash")
            }
            AttestationError::ExpiredAttestation { age_seconds, max_age_seconds } => {
                write!(f, "attestation expired: age {age_seconds}s exceeds max {max_age_seconds}s")
            }
            AttestationError::NoTrustedSigner { model_id, required_signers } => {
                write!(
                    f,
                    "model '{model_id}' not signed by any required signer: {required_signers:?}"
                )
            }
        }
    }
}

impl std::error::Error for AttestationError {}

// ── Attestation checker ───────────────────────────────────────────────

/// Verifies model attestations against a policy and trusted key set.
///
/// The checker enforces three layers of verification:
/// 1. Signature — the attestation must be signed by a known key
/// 2. Provenance — SLSA level, framework, training data requirements
/// 3. Policy — required signers, attestation freshness
pub struct AttestationChecker {
    policy: AttestationPolicy,
    trusted_keys: HashMap<String, Vec<u8>>,
}

impl AttestationChecker {
    /// Create a new checker with the given policy.
    pub fn new(policy: AttestationPolicy) -> Self {
        Self {
            policy,
            trusted_keys: HashMap::new(),
        }
    }

    /// Register a trusted signer's verification key.
    pub fn add_trusted_key(&mut self, signer: &str, key: Vec<u8>) -> &mut Self {
        self.trusted_keys.insert(signer.to_string(), key);
        self
    }

    /// Run all verification checks: signature, provenance, policy.
    ///
    /// Returns `Trusted` if all checks pass, `Rejected` on first failure.
    /// Any failure rejects the model before it can process input.
    pub fn verify(
        &self,
        attestation: &ModelAttestation,
    ) -> Result<AttestationVerdict, AttestationError> {
        self.verify_signature(attestation)?;
        self.verify_provenance(attestation)?;
        self.verify_policy(attestation)?;

        Ok(AttestationVerdict::Trusted {
            signer: attestation.signer.clone(),
            verified_at: SystemTime::now(),
        })
    }

    /// Verify the cryptographic signature on the attestation.
    pub fn verify_signature(
        &self,
        attestation: &ModelAttestation,
    ) -> Result<(), AttestationError> {
        let key = self.trusted_keys.get(&attestation.signer).ok_or_else(|| {
            AttestationError::UnknownSigner {
                signer: attestation.signer.clone(),
            }
        })?;

        let expected = sign_attestation(
            key,
            &attestation.model_hash,
            &attestation.signer,
            attestation.timestamp,
        );

        if attestation.signature != expected {
            return Err(AttestationError::InvalidSignature {
                signer: attestation.signer.clone(),
                model_id: attestation.model_id.clone(),
            });
        }

        Ok(())
    }

    /// Verify provenance metadata against the policy.
    pub fn verify_provenance(
        &self,
        attestation: &ModelAttestation,
    ) -> Result<(), AttestationError> {
        // Check SLSA level.
        if let Some(min_slsa) = self.policy.minimum_slsa_level {
            let actual = attestation.provenance.slsa_level.unwrap_or(0);
            if actual < min_slsa {
                return Err(AttestationError::InsufficientSLSALevel {
                    required: min_slsa,
                    actual,
                });
            }
        }

        // Check framework allowlist.
        if let Some(ref allowed) = self.policy.allowed_frameworks {
            if !allowed.contains(&attestation.provenance.framework) {
                return Err(AttestationError::DisallowedFramework {
                    framework: attestation.provenance.framework.clone(),
                    allowed: allowed.clone(),
                });
            }
        }

        // Check training data hash requirement.
        if self.policy.require_training_data_hash
            && attestation.provenance.training_data_hash.is_none()
        {
            return Err(AttestationError::MissingTrainingDataHash {
                model_id: attestation.model_id.clone(),
            });
        }

        Ok(())
    }

    /// Verify policy constraints (freshness, required signers).
    pub fn verify_policy(
        &self,
        attestation: &ModelAttestation,
    ) -> Result<(), AttestationError> {
        // Check attestation freshness.
        if let Some(max_age) = self.policy.max_age_seconds {
            let age = attestation
                .timestamp
                .elapsed()
                .map(|d| d.as_secs())
                .unwrap_or(u64::MAX);
            if age > max_age {
                return Err(AttestationError::ExpiredAttestation {
                    age_seconds: age,
                    max_age_seconds: max_age,
                });
            }
        }

        // Check required signers.
        if !self.policy.required_signers.is_empty()
            && !self.policy.required_signers.contains(&attestation.signer)
        {
            return Err(AttestationError::NoTrustedSigner {
                model_id: attestation.model_id.clone(),
                required_signers: self.policy.required_signers.clone(),
            });
        }

        Ok(())
    }
}

impl fmt::Debug for AttestationChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationChecker")
            .field("policy", &self.policy)
            .field("trusted_signers", &self.trusted_keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

// ── Signature creation ────────────────────────────────────────────────

/// Create a placeholder signature for a model attestation.
///
/// Uses HMAC-SHA3-256 (ML-DSA placeholder, FIPS 204 interface).
/// Uses the same crypto module as audit.rs (PQC-first).
pub fn sign_attestation(
    key: &[u8],
    model_hash: &str,
    signer: &str,
    timestamp: SystemTime,
) -> String {
    let ts = timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());

    let payload = format!("{model_hash}||{signer}||{ts}");
    crypto::sign(key, &payload)
}
