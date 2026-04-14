// ═══════════════════════════════════════════════════════════════════════
// Identity Attestation Chains
//
// Links an identity to its authentication evidence via a hash chain.
// Each attestation is signed and linked to the previous one.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_lang::stdlib::crypto::hash::sha3_256_hex;
use rune_lang::stdlib::crypto::sign::hmac_sha3_256;
use serde::{Deserialize, Serialize};

use crate::identity::IdentityId;

// ── AttestationType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationType {
    EmailVerified,
    PhoneVerified,
    DocumentVerified,
    OrganizationVerified,
    DeviceAttested,
    ModelAttested,
    CertificateIssued,
    BiometricEnrolled,
    // Layer 2
    BiometricVerification,
    HardwareToken,
    CertificateChain,
    CrossReferenceAttestation,
}

impl fmt::Display for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── IdentityAttestation ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAttestation {
    pub identity_id: IdentityId,
    pub attestation_type: AttestationType,
    pub evidence: String,
    pub verified_by: String,
    pub verified_at: i64,
    pub expires_at: Option<i64>,
    pub signature: String,
    pub previous_hash: Option<String>,
}

impl IdentityAttestation {
    pub fn new(
        identity_id: IdentityId,
        attestation_type: AttestationType,
        evidence: impl Into<String>,
        verified_by: impl Into<String>,
        verified_at: i64,
        key: &[u8],
    ) -> Self {
        let evidence = evidence.into();
        let verified_by = verified_by.into();
        let content = format!("{}:{}:{}:{}:{}", identity_id, attestation_type, evidence, verified_by, verified_at);
        let signature = hex::encode(hmac_sha3_256(key, content.as_bytes()));
        Self {
            identity_id,
            attestation_type,
            evidence,
            verified_by,
            verified_at,
            expires_at: None,
            signature,
            previous_hash: None,
        }
    }

    pub fn with_expiry(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn hash(&self) -> String {
        let content = format!(
            "{}:{}:{}:{}:{}:{}",
            self.identity_id, self.attestation_type, self.evidence,
            self.verified_by, self.verified_at, self.signature
        );
        sha3_256_hex(content.as_bytes())
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let content = format!(
            "{}:{}:{}:{}:{}",
            self.identity_id, self.attestation_type, self.evidence,
            self.verified_by, self.verified_at
        );
        let expected = hex::encode(hmac_sha3_256(key, content.as_bytes()));
        expected == self.signature
    }
}

// ── AttestationChain ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttestationChain {
    pub identity_id: IdentityId,
    pub attestations: Vec<IdentityAttestation>,
}

impl AttestationChain {
    pub fn new(identity_id: IdentityId) -> Self {
        Self { identity_id, attestations: Vec::new() }
    }

    pub fn add(&mut self, mut attestation: IdentityAttestation) {
        attestation.previous_hash = self.attestations.last().map(|a| a.hash());
        self.attestations.push(attestation);
    }

    pub fn verify_chain(&self) -> bool {
        if self.attestations.is_empty() {
            return true;
        }
        // First attestation should have no previous_hash
        if self.attestations[0].previous_hash.is_some() {
            return false;
        }
        for i in 1..self.attestations.len() {
            let expected_hash = self.attestations[i - 1].hash();
            match &self.attestations[i].previous_hash {
                Some(h) if h == &expected_hash => {}
                _ => return false,
            }
        }
        true
    }

    pub fn latest(&self) -> Option<&IdentityAttestation> {
        self.attestations.last()
    }

    pub fn has_type(&self, atype: &AttestationType) -> bool {
        self.attestations.iter().any(|a| &a.attestation_type == atype)
    }

    pub fn attestations_of_type(&self, atype: &AttestationType) -> Vec<&IdentityAttestation> {
        self.attestations.iter().filter(|a| &a.attestation_type == atype).collect()
    }

    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

// ── ChainVerificationResult (Layer 2) ────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    pub valid: bool,
    pub verified_links: usize,
    pub broken_at: Option<usize>,
    pub timestamps: Vec<i64>,
}

pub fn verify_attestation_chain(chain: &AttestationChain) -> ChainVerificationResult {
    if chain.attestations.is_empty() {
        return ChainVerificationResult {
            valid: true,
            verified_links: 0,
            broken_at: None,
            timestamps: Vec::new(),
        };
    }

    let timestamps: Vec<i64> = chain.attestations.iter().map(|a| a.verified_at).collect();

    // First attestation should have no previous_hash
    if chain.attestations[0].previous_hash.is_some() {
        return ChainVerificationResult {
            valid: false,
            verified_links: 0,
            broken_at: Some(0),
            timestamps,
        };
    }

    let mut verified = 0;
    for i in 1..chain.attestations.len() {
        let expected_hash = chain.attestations[i - 1].hash();
        match &chain.attestations[i].previous_hash {
            Some(h) if h == &expected_hash => {
                verified += 1;
            }
            _ => {
                return ChainVerificationResult {
                    valid: false,
                    verified_links: verified,
                    broken_at: Some(i),
                    timestamps,
                };
            }
        }
    }

    ChainVerificationResult {
        valid: true,
        verified_links: if chain.attestations.len() > 1 { chain.attestations.len() - 1 } else { 0 },
        broken_at: None,
        timestamps,
    }
}

// ── ChainAnchor (Layer 2) ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainAnchor {
    pub root_hash: String,
    pub tip_hash: String,
    pub chain_length: usize,
}

pub fn anchor_chain(chain: &AttestationChain) -> Option<ChainAnchor> {
    if chain.attestations.is_empty() {
        return None;
    }
    Some(ChainAnchor {
        root_hash: chain.attestations[0].hash(),
        tip_hash: chain.attestations.last().unwrap().hash(),
        chain_length: chain.attestations.len(),
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0xAA; 32]
    }

    #[test]
    fn test_attestation_chain_add_builds_hash_chain() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        let a1 = IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "alice@example.com", "email-service", 1000, &test_key(),
        );
        chain.add(a1);
        assert!(chain.attestations[0].previous_hash.is_none());

        let a2 = IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::PhoneVerified,
            "+1-555-0100", "sms-service", 2000, &test_key(),
        );
        chain.add(a2);
        assert!(chain.attestations[1].previous_hash.is_some());
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_attestation_chain_verify_valid() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::DocumentVerified,
            "passport", "id-service", 2000, &test_key(),
        ));
        assert!(chain.verify_chain());
    }

    #[test]
    fn test_attestation_chain_verify_tampered() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::PhoneVerified,
            "phone", "svc", 2000, &test_key(),
        ));
        // Tamper with first attestation's evidence
        chain.attestations[0].evidence = "tampered@evil.com".into();
        // Now the hash of [0] doesn't match what [1] expects
        assert!(!chain.verify_chain());
    }

    #[test]
    fn test_attestation_chain_has_type() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        assert!(chain.has_type(&AttestationType::EmailVerified));
        assert!(!chain.has_type(&AttestationType::PhoneVerified));
    }

    #[test]
    fn test_attestation_chain_of_type() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a2@b.com", "svc", 2000, &test_key(),
        ));
        assert_eq!(chain.attestations_of_type(&AttestationType::EmailVerified).len(), 2);
    }

    #[test]
    fn test_attestation_verify_signature() {
        let key = test_key();
        let a = IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &key,
        );
        assert!(a.verify_signature(&key));
        assert!(!a.verify_signature(b"wrong-key"));
    }

    #[test]
    fn test_attestation_chain_empty_is_valid() {
        let chain = AttestationChain::new(IdentityId::new("user:alice"));
        assert!(chain.verify_chain());
        assert!(chain.is_empty());
    }

    // ── Part 4: Attestation Chain Verification Tests ─────────────────

    #[test]
    fn test_verify_attestation_chain_valid() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::PhoneVerified,
            "phone", "svc", 2000, &test_key(),
        ));
        let result = verify_attestation_chain(&chain);
        assert!(result.valid);
        assert_eq!(result.verified_links, 1);
        assert!(result.broken_at.is_none());
        assert_eq!(result.timestamps, vec![1000, 2000]);
    }

    #[test]
    fn test_verify_attestation_chain_tampered() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::PhoneVerified,
            "phone", "svc", 2000, &test_key(),
        ));
        chain.attestations[0].evidence = "tampered".into();
        let result = verify_attestation_chain(&chain);
        assert!(!result.valid);
        assert_eq!(result.broken_at, Some(1));
    }

    #[test]
    fn test_anchor_chain_returns_root_and_tip() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::EmailVerified,
            "a@b.com", "svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::DocumentVerified,
            "doc", "svc", 2000, &test_key(),
        ));
        let anchor = anchor_chain(&chain).unwrap();
        assert_eq!(anchor.chain_length, 2);
        assert_ne!(anchor.root_hash, anchor.tip_hash);
        assert_eq!(anchor.root_hash.len(), 64);
    }

    #[test]
    fn test_anchor_chain_empty_returns_none() {
        let chain = AttestationChain::new(IdentityId::new("user:alice"));
        assert!(anchor_chain(&chain).is_none());
    }

    #[test]
    fn test_new_attestation_types_layer2() {
        let mut chain = AttestationChain::new(IdentityId::new("user:alice"));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::BiometricVerification,
            "face_scan", "bio-svc", 1000, &test_key(),
        ));
        chain.add(IdentityAttestation::new(
            IdentityId::new("user:alice"), AttestationType::HardwareToken,
            "yubikey_123", "hw-svc", 2000, &test_key(),
        ));
        assert!(chain.has_type(&AttestationType::BiometricVerification));
        assert!(chain.has_type(&AttestationType::HardwareToken));
        assert!(chain.verify_chain());
    }
}
