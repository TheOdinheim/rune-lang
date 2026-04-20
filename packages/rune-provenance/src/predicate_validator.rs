// ═══════════════════════════════════════════════════════════════════════
// Predicate Validator — Validate predicate content against known schemas.
//
// PredicateValidator validates the predicate_bytes of an attestation
// against the expected schema for a given predicate type. Layer 3
// validators check structural validity (required fields present,
// correct nesting) — full schema validation belongs in adapter crates.
//
// ModelAttestationVerifier lives here (not in rune-detection) because
// model attestation verification is fundamentally a provenance concern:
// it binds a model artifact to a cryptographic attestation. The
// detection crate's DetectionModelAdapter.attestation_hash() produces
// the hash; this crate verifies it against stored attestations.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use sha3::{Digest, Sha3_256};

use crate::backend::{ArtifactRef, StoredAttestation};
use crate::error::ProvenanceError;

// ── PredicateType ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateType {
    SlsaProvenanceV1,
    InTotoStatementV1,
    SpdxSbomV23,
    CycloneDxBomV15,
    Custom { uri: String },
}

impl PredicateType {
    pub fn from_uri(uri: &str) -> Self {
        match uri {
            "https://slsa.dev/provenance/v1" => Self::SlsaProvenanceV1,
            "https://in-toto.io/Statement/v1" => Self::InTotoStatementV1,
            "https://spdx.dev/Document/v2.3" => Self::SpdxSbomV23,
            "https://cyclonedx.org/bom/v1.5" => Self::CycloneDxBomV15,
            other => Self::Custom { uri: other.to_string() },
        }
    }

    pub fn uri(&self) -> &str {
        match self {
            Self::SlsaProvenanceV1 => "https://slsa.dev/provenance/v1",
            Self::InTotoStatementV1 => "https://in-toto.io/Statement/v1",
            Self::SpdxSbomV23 => "https://spdx.dev/Document/v2.3",
            Self::CycloneDxBomV15 => "https://cyclonedx.org/bom/v1.5",
            Self::Custom { uri } => uri,
        }
    }
}

impl fmt::Display for PredicateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri())
    }
}

// ── ValidationResult ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid { reason: String },
    UnsupportedPredicateType { predicate_type: String },
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("Valid"),
            Self::Invalid { reason } => write!(f, "Invalid({reason})"),
            Self::UnsupportedPredicateType { predicate_type } => {
                write!(f, "UnsupportedPredicateType({predicate_type})")
            }
        }
    }
}

// ── PredicateValidator trait ───────────────────────────────────────

pub trait PredicateValidator {
    fn validate(&self, predicate_type: &str, predicate_bytes: &[u8]) -> Result<ValidationResult, ProvenanceError>;
    fn supported_types(&self) -> Vec<PredicateType>;
    fn validator_id(&self) -> &str;
}

// ── SlsaProvenanceV1Validator ──────────────────────────────────────

pub struct SlsaProvenanceV1Validator {
    id: String,
}

impl SlsaProvenanceV1Validator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PredicateValidator for SlsaProvenanceV1Validator {
    fn validate(&self, predicate_type: &str, predicate_bytes: &[u8]) -> Result<ValidationResult, ProvenanceError> {
        if predicate_type != PredicateType::SlsaProvenanceV1.uri() {
            return Ok(ValidationResult::UnsupportedPredicateType {
                predicate_type: predicate_type.to_string(),
            });
        }
        let text = std::str::from_utf8(predicate_bytes).map_err(|_| {
            ProvenanceError::InvalidOperation("predicate bytes are not valid UTF-8".to_string())
        })?;
        // Structural check: must contain buildDefinition and runDetails
        if !text.contains("buildDefinition") {
            return Ok(ValidationResult::Invalid {
                reason: "missing required field: buildDefinition".to_string(),
            });
        }
        if !text.contains("runDetails") {
            return Ok(ValidationResult::Invalid {
                reason: "missing required field: runDetails".to_string(),
            });
        }
        Ok(ValidationResult::Valid)
    }

    fn supported_types(&self) -> Vec<PredicateType> {
        vec![PredicateType::SlsaProvenanceV1]
    }

    fn validator_id(&self) -> &str { &self.id }
}

// ── InTotoStatementValidator ───────────────────────────────────────

pub struct InTotoStatementValidator {
    id: String,
}

impl InTotoStatementValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PredicateValidator for InTotoStatementValidator {
    fn validate(&self, predicate_type: &str, predicate_bytes: &[u8]) -> Result<ValidationResult, ProvenanceError> {
        if predicate_type != PredicateType::InTotoStatementV1.uri() {
            return Ok(ValidationResult::UnsupportedPredicateType {
                predicate_type: predicate_type.to_string(),
            });
        }
        let text = std::str::from_utf8(predicate_bytes).map_err(|_| {
            ProvenanceError::InvalidOperation("predicate bytes are not valid UTF-8".to_string())
        })?;
        if !text.contains("subject") {
            return Ok(ValidationResult::Invalid {
                reason: "missing required field: subject".to_string(),
            });
        }
        if !text.contains("predicateType") {
            return Ok(ValidationResult::Invalid {
                reason: "missing required field: predicateType".to_string(),
            });
        }
        Ok(ValidationResult::Valid)
    }

    fn supported_types(&self) -> Vec<PredicateType> {
        vec![PredicateType::InTotoStatementV1]
    }

    fn validator_id(&self) -> &str { &self.id }
}

// ── SpdxSbomValidator ──────────────────────────────────────────────

pub struct SpdxSbomValidator {
    id: String,
}

impl SpdxSbomValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PredicateValidator for SpdxSbomValidator {
    fn validate(&self, predicate_type: &str, predicate_bytes: &[u8]) -> Result<ValidationResult, ProvenanceError> {
        if predicate_type != PredicateType::SpdxSbomV23.uri() {
            return Ok(ValidationResult::UnsupportedPredicateType {
                predicate_type: predicate_type.to_string(),
            });
        }
        let text = std::str::from_utf8(predicate_bytes).map_err(|_| {
            ProvenanceError::InvalidOperation("predicate bytes are not valid UTF-8".to_string())
        })?;
        if !text.contains("spdxVersion") {
            return Ok(ValidationResult::Invalid {
                reason: "missing required field: spdxVersion".to_string(),
            });
        }
        if !text.contains("SPDXID") {
            return Ok(ValidationResult::Invalid {
                reason: "missing required field: SPDXID".to_string(),
            });
        }
        Ok(ValidationResult::Valid)
    }

    fn supported_types(&self) -> Vec<PredicateType> {
        vec![PredicateType::SpdxSbomV23]
    }

    fn validator_id(&self) -> &str { &self.id }
}

// ── NullPredicateValidator ─────────────────────────────────────────

pub struct NullPredicateValidator {
    id: String,
}

impl NullPredicateValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PredicateValidator for NullPredicateValidator {
    fn validate(&self, predicate_type: &str, _predicate_bytes: &[u8]) -> Result<ValidationResult, ProvenanceError> {
        Ok(ValidationResult::UnsupportedPredicateType {
            predicate_type: predicate_type.to_string(),
        })
    }

    fn supported_types(&self) -> Vec<PredicateType> { vec![] }
    fn validator_id(&self) -> &str { &self.id }
}

// ── PermissivePredicateValidator ───────────────────────────────────

/// **WARNING: Not for production use.**
///
/// PermissivePredicateValidator accepts any predicate as valid without
/// performing any structural or semantic checks. This is intended
/// exclusively for testing and local development. Using this validator
/// in a production deployment disables all predicate validation,
/// allowing malformed or malicious predicates to pass unchecked.
pub struct PermissivePredicateValidator {
    id: String,
}

impl PermissivePredicateValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PredicateValidator for PermissivePredicateValidator {
    fn validate(&self, _predicate_type: &str, _predicate_bytes: &[u8]) -> Result<ValidationResult, ProvenanceError> {
        Ok(ValidationResult::Valid)
    }

    fn supported_types(&self) -> Vec<PredicateType> {
        // Accepts everything
        vec![
            PredicateType::SlsaProvenanceV1,
            PredicateType::InTotoStatementV1,
            PredicateType::SpdxSbomV23,
            PredicateType::CycloneDxBomV15,
        ]
    }

    fn validator_id(&self) -> &str { &self.id }
}

// ── ModelAttestationVerifier ───────────────────────────────────────

/// Verifies that a model artifact's content hash matches the hash
/// recorded in a stored attestation. This bridges rune-detection's
/// DetectionModelAdapter.attestation_hash() with rune-provenance's
/// attestation storage.
pub trait ModelAttestationVerifier {
    fn verify_model_attestation(
        &self,
        model_artifact_ref: &ArtifactRef,
        model_content_hash: &str,
        attestation: &StoredAttestation,
    ) -> Result<ModelAttestationResult, ProvenanceError>;

    fn verifier_id(&self) -> &str;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelAttestationResult {
    Valid { artifact_ref: String, hash_algorithm: String },
    HashMismatch { expected: String, actual: String },
    ArtifactMismatch { expected: String, actual: String },
}

impl ModelAttestationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

impl fmt::Display for ModelAttestationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid { artifact_ref, hash_algorithm } => {
                write!(f, "Valid(artifact={artifact_ref}, algo={hash_algorithm})")
            }
            Self::HashMismatch { expected, actual } => {
                write!(f, "HashMismatch(expected={expected}, actual={actual})")
            }
            Self::ArtifactMismatch { expected, actual } => {
                write!(f, "ArtifactMismatch(expected={expected}, actual={actual})")
            }
        }
    }
}

// ── Sha3ModelAttestationVerifier ───────────────────────────────────

pub struct Sha3ModelAttestationVerifier {
    id: String,
}

impl Sha3ModelAttestationVerifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }

    pub fn compute_model_hash(content: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }
}

impl ModelAttestationVerifier for Sha3ModelAttestationVerifier {
    fn verify_model_attestation(
        &self,
        model_artifact_ref: &ArtifactRef,
        model_content_hash: &str,
        attestation: &StoredAttestation,
    ) -> Result<ModelAttestationResult, ProvenanceError> {
        // Check artifact ref matches
        if attestation.artifact_ref != *model_artifact_ref {
            return Ok(ModelAttestationResult::ArtifactMismatch {
                expected: model_artifact_ref.as_str().to_string(),
                actual: attestation.artifact_ref.as_str().to_string(),
            });
        }
        // Compute SHA3-256 of predicate_bytes and compare with provided hash
        let predicate_hash = Self::compute_model_hash(&attestation.predicate_bytes);
        if predicate_hash != model_content_hash {
            return Ok(ModelAttestationResult::HashMismatch {
                expected: model_content_hash.to_string(),
                actual: predicate_hash,
            });
        }
        Ok(ModelAttestationResult::Valid {
            artifact_ref: model_artifact_ref.as_str().to_string(),
            hash_algorithm: "SHA3-256".to_string(),
        })
    }

    fn verifier_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predicate_type_from_uri() {
        assert_eq!(PredicateType::from_uri("https://slsa.dev/provenance/v1"), PredicateType::SlsaProvenanceV1);
        assert_eq!(PredicateType::from_uri("https://in-toto.io/Statement/v1"), PredicateType::InTotoStatementV1);
        assert_eq!(PredicateType::from_uri("https://spdx.dev/Document/v2.3"), PredicateType::SpdxSbomV23);
        assert_eq!(PredicateType::from_uri("https://cyclonedx.org/bom/v1.5"), PredicateType::CycloneDxBomV15);
        assert!(matches!(PredicateType::from_uri("custom://foo"), PredicateType::Custom { .. }));
    }

    #[test]
    fn test_predicate_type_roundtrip() {
        let types = [
            PredicateType::SlsaProvenanceV1,
            PredicateType::InTotoStatementV1,
            PredicateType::SpdxSbomV23,
            PredicateType::CycloneDxBomV15,
            PredicateType::Custom { uri: "custom://test".to_string() },
        ];
        for t in &types {
            assert_eq!(PredicateType::from_uri(t.uri()), *t);
        }
    }

    #[test]
    fn test_slsa_validator_valid() {
        let v = SlsaProvenanceV1Validator::new("v1");
        let predicate = br#"{"buildDefinition": {}, "runDetails": {}}"#;
        let result = v.validate("https://slsa.dev/provenance/v1", predicate).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_slsa_validator_missing_field() {
        let v = SlsaProvenanceV1Validator::new("v1");
        let predicate = br#"{"buildDefinition": {}}"#;
        let result = v.validate("https://slsa.dev/provenance/v1", predicate).unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_slsa_validator_wrong_type() {
        let v = SlsaProvenanceV1Validator::new("v1");
        let result = v.validate("https://in-toto.io/Statement/v1", b"{}").unwrap();
        assert!(matches!(result, ValidationResult::UnsupportedPredicateType { .. }));
    }

    #[test]
    fn test_intoto_validator_valid() {
        let v = InTotoStatementValidator::new("v1");
        let predicate = br#"{"subject": [], "predicateType": "test"}"#;
        let result = v.validate("https://in-toto.io/Statement/v1", predicate).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_intoto_validator_missing_subject() {
        let v = InTotoStatementValidator::new("v1");
        let predicate = br#"{"predicateType": "test"}"#;
        let result = v.validate("https://in-toto.io/Statement/v1", predicate).unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_spdx_validator_valid() {
        let v = SpdxSbomValidator::new("v1");
        let predicate = br#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let result = v.validate("https://spdx.dev/Document/v2.3", predicate).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_spdx_validator_missing_spdxid() {
        let v = SpdxSbomValidator::new("v1");
        let predicate = br#"{"spdxVersion": "SPDX-2.3"}"#;
        let result = v.validate("https://spdx.dev/Document/v2.3", predicate).unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_null_validator() {
        let v = NullPredicateValidator::new("n1");
        let result = v.validate("anything", b"{}").unwrap();
        assert!(matches!(result, ValidationResult::UnsupportedPredicateType { .. }));
        assert!(v.supported_types().is_empty());
    }

    #[test]
    fn test_permissive_validator() {
        let v = PermissivePredicateValidator::new("p1");
        let result = v.validate("anything", b"garbage").unwrap();
        assert!(result.is_valid());
        assert!(!v.supported_types().is_empty());
    }

    #[test]
    fn test_validation_result_display() {
        assert_eq!(ValidationResult::Valid.to_string(), "Valid");
        assert!(ValidationResult::Invalid { reason: "bad".into() }.to_string().contains("Invalid"));
        assert!(ValidationResult::UnsupportedPredicateType { predicate_type: "x".into() }.to_string().contains("Unsupported"));
    }

    #[test]
    fn test_sha3_model_verifier_valid() {
        let verifier = Sha3ModelAttestationVerifier::new("mv1");
        let content = b"model-content";
        let hash = Sha3ModelAttestationVerifier::compute_model_hash(content);
        let att = StoredAttestation {
            attestation_id: "att-1".to_string(),
            artifact_ref: ArtifactRef::new("model-1"),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate_bytes: content.to_vec(),
            signature: vec![1, 2, 3],
            signing_key_ref: "key-1".to_string(),
            issued_at: 1000,
            predecessor_attestation_id: None,
        };
        let result = verifier.verify_model_attestation(
            &ArtifactRef::new("model-1"), &hash, &att,
        ).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_sha3_model_verifier_hash_mismatch() {
        let verifier = Sha3ModelAttestationVerifier::new("mv1");
        let att = StoredAttestation {
            attestation_id: "att-1".to_string(),
            artifact_ref: ArtifactRef::new("model-1"),
            predicate_type: "test".to_string(),
            predicate_bytes: b"content".to_vec(),
            signature: vec![],
            signing_key_ref: "key-1".to_string(),
            issued_at: 1000,
            predecessor_attestation_id: None,
        };
        let result = verifier.verify_model_attestation(
            &ArtifactRef::new("model-1"), "wrong-hash", &att,
        ).unwrap();
        assert!(matches!(result, ModelAttestationResult::HashMismatch { .. }));
    }

    #[test]
    fn test_sha3_model_verifier_artifact_mismatch() {
        let verifier = Sha3ModelAttestationVerifier::new("mv1");
        let att = StoredAttestation {
            attestation_id: "att-1".to_string(),
            artifact_ref: ArtifactRef::new("other-model"),
            predicate_type: "test".to_string(),
            predicate_bytes: b"content".to_vec(),
            signature: vec![],
            signing_key_ref: "key-1".to_string(),
            issued_at: 1000,
            predecessor_attestation_id: None,
        };
        let result = verifier.verify_model_attestation(
            &ArtifactRef::new("model-1"), "any", &att,
        ).unwrap();
        assert!(matches!(result, ModelAttestationResult::ArtifactMismatch { .. }));
    }

    #[test]
    fn test_model_attestation_result_display() {
        let valid = ModelAttestationResult::Valid {
            artifact_ref: "m1".into(),
            hash_algorithm: "SHA3-256".into(),
        };
        assert!(valid.to_string().contains("Valid"));
        let mismatch = ModelAttestationResult::HashMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert!(mismatch.to_string().contains("HashMismatch"));
    }

    #[test]
    fn test_compute_model_hash_deterministic() {
        let h1 = Sha3ModelAttestationVerifier::compute_model_hash(b"test");
        let h2 = Sha3ModelAttestationVerifier::compute_model_hash(b"test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA3-256 hex
    }

    #[test]
    fn test_predicate_type_display() {
        assert_eq!(PredicateType::SlsaProvenanceV1.to_string(), "https://slsa.dev/provenance/v1");
        assert_eq!(
            PredicateType::Custom { uri: "custom://x".to_string() }.to_string(),
            "custom://x"
        );
    }
}
