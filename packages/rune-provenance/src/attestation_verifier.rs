// ═══════════════════════════════════════════════════════════════════════
// Attestation Signature Verifier — Signature verification for provenance
// attestations.
//
// Separate from rune-identity's JwtSignatureVerifier because attestation
// signatures use different envelope formats: DSSE, in-toto, Sigstore
// bundles, x.509 chains, SCITT receipts — all structures that JWT
// does not model.
//
// HmacSha3AttestationVerifier is the reference implementation matching
// RUNE's PQC-first posture. DsseEnvelopeStructureVerifier validates
// DSSE structure only — actual signature verification requires
// asymmetric crypto which belongs in adapter crates.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

use crate::backend::StoredAttestation;
use crate::error::ProvenanceError;

type HmacSha3_256 = Hmac<Sha3_256>;

// ── EnvelopeFormat ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeFormat {
    Dsse,
    InTotoLink,
    InTotoLayout,
    SlsaProvenance,
    SigstoreBundle,
    ScittReceipt,
    Raw,
}

impl fmt::Display for EnvelopeFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AttestationVerificationResult ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationVerificationResult {
    Valid { envelope_format: EnvelopeFormat, signing_key_id: String },
    Invalid { reason: String },
    UnsupportedEnvelopeFormat { format: String },
    KeyUnknown { key_id_attempted: String },
}

impl AttestationVerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

impl fmt::Display for AttestationVerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid { envelope_format, signing_key_id } => write!(f, "Valid({envelope_format}, key={signing_key_id})"),
            Self::Invalid { reason } => write!(f, "Invalid({reason})"),
            Self::UnsupportedEnvelopeFormat { format } => write!(f, "UnsupportedEnvelopeFormat({format})"),
            Self::KeyUnknown { key_id_attempted } => write!(f, "KeyUnknown({key_id_attempted})"),
        }
    }
}

// ── AttestationSignatureVerifier trait ───────────────────────────────

pub trait AttestationSignatureVerifier {
    fn verify_attestation_signature(
        &self,
        attestation: &StoredAttestation,
        verification_key_ref: &str,
    ) -> Result<AttestationVerificationResult, ProvenanceError>;

    fn supported_envelope_formats(&self) -> Vec<EnvelopeFormat>;
    fn verifier_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── Constant-time comparison ────────────────────────────────────────

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Canonical attestation bytes ─────────────────────────────────────

fn canonical_attestation_bytes(attestation: &StoredAttestation) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(attestation.attestation_id.as_bytes());
    payload.extend_from_slice(attestation.artifact_ref.as_str().as_bytes());
    payload.extend_from_slice(attestation.predicate_type.as_bytes());
    payload.extend_from_slice(&attestation.predicate_bytes);
    payload.extend_from_slice(attestation.signing_key_ref.as_bytes());
    payload.extend_from_slice(&attestation.issued_at.to_le_bytes());
    if let Some(ref pred_id) = attestation.predecessor_attestation_id {
        payload.extend_from_slice(pred_id.as_bytes());
    }
    payload
}

// ── HmacSha3AttestationVerifier ─────────────────────────────────────

pub struct HmacSha3AttestationVerifier {
    id: String,
    key: Vec<u8>,
}

impl HmacSha3AttestationVerifier {
    pub fn new(id: &str, key: &[u8]) -> Self {
        Self { id: id.to_string(), key: key.to_vec() }
    }

    pub fn sign_attestation(&self, attestation: &mut StoredAttestation) {
        let payload = canonical_attestation_bytes(attestation);
        let mut mac = HmacSha3_256::new_from_slice(&self.key).expect("HMAC key can be any length");
        mac.update(&payload);
        attestation.signature = mac.finalize().into_bytes().to_vec();
    }
}

impl AttestationSignatureVerifier for HmacSha3AttestationVerifier {
    fn verify_attestation_signature(
        &self,
        attestation: &StoredAttestation,
        _verification_key_ref: &str,
    ) -> Result<AttestationVerificationResult, ProvenanceError> {
        let payload = canonical_attestation_bytes(attestation);
        let mut mac = HmacSha3_256::new_from_slice(&self.key).expect("HMAC key can be any length");
        mac.update(&payload);
        let expected = mac.finalize().into_bytes();

        if !constant_time_eq(&attestation.signature, &expected) {
            return Ok(AttestationVerificationResult::Invalid {
                reason: "HMAC-SHA3-256 signature verification failed".to_string(),
            });
        }

        Ok(AttestationVerificationResult::Valid {
            envelope_format: EnvelopeFormat::Raw,
            signing_key_id: attestation.signing_key_ref.clone(),
        })
    }

    fn supported_envelope_formats(&self) -> Vec<EnvelopeFormat> {
        vec![EnvelopeFormat::Raw]
    }

    fn verifier_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── DsseEnvelopeStructureVerifier ───────────────────────────────────

pub struct DsseEnvelopeStructureVerifier {
    id: String,
}

impl DsseEnvelopeStructureVerifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl AttestationSignatureVerifier for DsseEnvelopeStructureVerifier {
    fn verify_attestation_signature(
        &self,
        attestation: &StoredAttestation,
        _verification_key_ref: &str,
    ) -> Result<AttestationVerificationResult, ProvenanceError> {
        // Validate DSSE structure: predicate_type must be set, predicate_bytes non-empty, signature non-empty
        if attestation.predicate_type.is_empty() {
            return Ok(AttestationVerificationResult::Invalid {
                reason: "DSSE payloadType (predicate_type) is empty".to_string(),
            });
        }
        if attestation.predicate_bytes.is_empty() {
            return Ok(AttestationVerificationResult::Invalid {
                reason: "DSSE payload (predicate_bytes) is empty".to_string(),
            });
        }
        if attestation.signature.is_empty() {
            return Ok(AttestationVerificationResult::Invalid {
                reason: "DSSE signatures array is empty".to_string(),
            });
        }
        Ok(AttestationVerificationResult::Valid {
            envelope_format: EnvelopeFormat::Dsse,
            signing_key_id: attestation.signing_key_ref.clone(),
        })
    }

    fn supported_envelope_formats(&self) -> Vec<EnvelopeFormat> {
        vec![EnvelopeFormat::Dsse]
    }

    fn verifier_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullAttestationVerifier ─────────────────────────────────────────

pub struct NullAttestationVerifier {
    id: String,
}

impl NullAttestationVerifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl AttestationSignatureVerifier for NullAttestationVerifier {
    fn verify_attestation_signature(
        &self,
        _attestation: &StoredAttestation,
        _verification_key_ref: &str,
    ) -> Result<AttestationVerificationResult, ProvenanceError> {
        Ok(AttestationVerificationResult::Invalid {
            reason: "null verifier always rejects".to_string(),
        })
    }

    fn supported_envelope_formats(&self) -> Vec<EnvelopeFormat> { vec![] }
    fn verifier_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ArtifactRef;

    fn make_attestation() -> StoredAttestation {
        StoredAttestation {
            attestation_id: "att-1".to_string(),
            artifact_ref: ArtifactRef::new("art-1"),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate_bytes: b"{\"builder\":{\"id\":\"test\"}}".to_vec(),
            signature: Vec::new(),
            signing_key_ref: "key-1".to_string(),
            issued_at: 1000,
            predecessor_attestation_id: None,
        }
    }

    #[test]
    fn test_hmac_sign_and_verify() {
        let verifier = HmacSha3AttestationVerifier::new("v1", b"secret-key");
        let mut att = make_attestation();
        verifier.sign_attestation(&mut att);
        assert!(!att.signature.is_empty());
        let result = verifier.verify_attestation_signature(&att, "key-1").unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_hmac_wrong_key_rejects() {
        let signer = HmacSha3AttestationVerifier::new("s1", b"key-a");
        let verifier = HmacSha3AttestationVerifier::new("v1", b"key-b");
        let mut att = make_attestation();
        signer.sign_attestation(&mut att);
        let result = verifier.verify_attestation_signature(&att, "key-1").unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_hmac_deterministic() {
        let verifier = HmacSha3AttestationVerifier::new("v1", b"key");
        let mut a1 = make_attestation();
        let mut a2 = make_attestation();
        verifier.sign_attestation(&mut a1);
        verifier.sign_attestation(&mut a2);
        assert_eq!(a1.signature, a2.signature);
    }

    #[test]
    fn test_dsse_structure_valid() {
        let verifier = DsseEnvelopeStructureVerifier::new("dsse-1");
        let att = make_attestation();
        let mut signed = att;
        signed.signature = vec![1, 2, 3];
        let result = verifier.verify_attestation_signature(&signed, "key-1").unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_dsse_structure_empty_predicate_type() {
        let verifier = DsseEnvelopeStructureVerifier::new("dsse-1");
        let mut att = make_attestation();
        att.predicate_type = String::new();
        att.signature = vec![1];
        let result = verifier.verify_attestation_signature(&att, "key-1").unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_dsse_structure_empty_signature() {
        let verifier = DsseEnvelopeStructureVerifier::new("dsse-1");
        let att = make_attestation();
        let result = verifier.verify_attestation_signature(&att, "key-1").unwrap();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_null_verifier_always_rejects() {
        let verifier = NullAttestationVerifier::new("null-1");
        let att = make_attestation();
        let result = verifier.verify_attestation_signature(&att, "key-1").unwrap();
        assert!(!result.is_valid());
        assert!(!verifier.is_active());
    }

    #[test]
    fn test_envelope_format_display() {
        assert_eq!(EnvelopeFormat::Dsse.to_string(), "Dsse");
        assert_eq!(EnvelopeFormat::SlsaProvenance.to_string(), "SlsaProvenance");
        assert_eq!(EnvelopeFormat::ScittReceipt.to_string(), "ScittReceipt");
    }

    #[test]
    fn test_verification_result_display() {
        assert!(AttestationVerificationResult::Valid { envelope_format: EnvelopeFormat::Raw, signing_key_id: "k1".into() }.to_string().contains("Valid"));
        assert!(AttestationVerificationResult::Invalid { reason: "bad".into() }.to_string().contains("Invalid"));
        assert!(AttestationVerificationResult::UnsupportedEnvelopeFormat { format: "x".into() }.to_string().contains("Unsupported"));
        assert!(AttestationVerificationResult::KeyUnknown { key_id_attempted: "k".into() }.to_string().contains("KeyUnknown"));
    }

    #[test]
    fn test_verifier_metadata() {
        let v = HmacSha3AttestationVerifier::new("v1", b"key");
        assert_eq!(v.verifier_id(), "v1");
        assert!(v.is_active());
        assert!(v.supported_envelope_formats().contains(&EnvelopeFormat::Raw));
    }
}
