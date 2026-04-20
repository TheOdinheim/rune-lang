// ═══════════════════════════════════════════════════════════════════════
// HSM — Hardware Security Module abstraction trait.
//
// Layer 3 defines the trait boundary for HSM integration. The arch
// spec references Intel SGX and ARM TrustZone — the HSM trait
// provides the interface that maps to these and to traditional HSMs.
// RUNE provides the contract — the customer provides the hardware.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_lang::stdlib::crypto::sign::hmac_sha3_256;

use crate::error::SecretError;

// ── HsmKeyRef ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HsmKeyRef {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: i64,
    pub exportable: bool,
}

// ── HsmInfo ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HsmInfo {
    pub provider: String,
    pub is_hardware: bool,
    pub fips_certified: bool,
    pub max_keys: Option<usize>,
}

// ── HsmProvider trait ────────────────────────────────────────────

pub trait HsmProvider {
    fn is_available(&self) -> bool;
    fn provider_name(&self) -> &str;
    fn supported_algorithms(&self) -> Vec<String>;
    fn generate_key_in_hsm(
        &mut self,
        key_id: &str,
        algorithm: &str,
    ) -> Result<HsmKeyRef, SecretError>;
    fn sign_in_hsm(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, SecretError>;
    fn verify_in_hsm(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecretError>;
    fn delete_key_from_hsm(&mut self, key_id: &str) -> Result<bool, SecretError>;
    fn hsm_info(&self) -> HsmInfo;
}

// ── SoftwareHsm (reference implementation) ──────────────────────

/// Software emulation HSM for testing. Uses HMAC-SHA3-256 for signing.
/// This is explicitly NOT secure — it's a testing reference implementation.
pub struct SoftwareHsm {
    keys: HashMap<String, HsmKeyRef>,
    /// Placeholder key material derived from key_id
    key_material: HashMap<String, Vec<u8>>,
}

impl SoftwareHsm {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            key_material: HashMap::new(),
        }
    }

    fn derive_material(key_id: &str) -> Vec<u8> {
        use rune_lang::stdlib::crypto::hash::sha3_256;
        let input = format!("hsm-software:{key_id}:material");
        sha3_256(input.as_bytes()).to_vec()
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmProvider for SoftwareHsm {
    fn is_available(&self) -> bool {
        true
    }

    fn provider_name(&self) -> &str {
        "software"
    }

    fn supported_algorithms(&self) -> Vec<String> {
        vec![
            "HMAC-SHA3-256".to_string(),
            "ECDSA-P256".to_string(),
            "RSA-2048".to_string(),
        ]
    }

    fn generate_key_in_hsm(
        &mut self,
        key_id: &str,
        algorithm: &str,
    ) -> Result<HsmKeyRef, SecretError> {
        if self.keys.contains_key(key_id) {
            return Err(SecretError::EncryptionFailed(format!(
                "HSM key already exists: {key_id}"
            )));
        }
        let key_ref = HsmKeyRef {
            key_id: key_id.to_string(),
            algorithm: algorithm.to_string(),
            created_at: 0,
            exportable: false,
        };
        let material = Self::derive_material(key_id);
        self.keys.insert(key_id.to_string(), key_ref.clone());
        self.key_material.insert(key_id.to_string(), material);
        Ok(key_ref)
    }

    fn sign_in_hsm(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, SecretError> {
        let material = self
            .key_material
            .get(key_id)
            .ok_or_else(|| SecretError::EncryptionFailed(format!("HSM key not found: {key_id}")))?;
        Ok(hmac_sha3_256(material, data))
    }

    fn verify_in_hsm(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecretError> {
        let computed = self.sign_in_hsm(key_id, data)?;
        // Constant-time comparison
        if computed.len() != signature.len() {
            return Ok(false);
        }
        let mut result = 0u8;
        for (a, b) in computed.iter().zip(signature.iter()) {
            result |= a ^ b;
        }
        Ok(result == 0)
    }

    fn delete_key_from_hsm(&mut self, key_id: &str) -> Result<bool, SecretError> {
        let removed = self.keys.remove(key_id).is_some();
        self.key_material.remove(key_id);
        Ok(removed)
    }

    fn hsm_info(&self) -> HsmInfo {
        HsmInfo {
            provider: "software".to_string(),
            is_hardware: false,
            fips_certified: false,
            max_keys: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_hsm_is_available() {
        let hsm = SoftwareHsm::new();
        assert!(hsm.is_available());
    }

    #[test]
    fn test_software_hsm_generate_key() {
        let mut hsm = SoftwareHsm::new();
        let key_ref = hsm
            .generate_key_in_hsm("k1", "HMAC-SHA3-256")
            .unwrap();
        assert_eq!(key_ref.key_id, "k1");
        assert_eq!(key_ref.algorithm, "HMAC-SHA3-256");
        assert!(!key_ref.exportable);
    }

    #[test]
    fn test_software_hsm_sign_and_verify() {
        let mut hsm = SoftwareHsm::new();
        hsm.generate_key_in_hsm("k1", "HMAC-SHA3-256").unwrap();
        let data = b"important message";
        let signature = hsm.sign_in_hsm("k1", data).unwrap();
        assert!(!signature.is_empty());
        let valid = hsm.verify_in_hsm("k1", data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_software_hsm_verify_fails_with_wrong_data() {
        let mut hsm = SoftwareHsm::new();
        hsm.generate_key_in_hsm("k1", "HMAC-SHA3-256").unwrap();
        let signature = hsm.sign_in_hsm("k1", b"original").unwrap();
        let valid = hsm.verify_in_hsm("k1", b"tampered", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_software_hsm_delete_key() {
        let mut hsm = SoftwareHsm::new();
        hsm.generate_key_in_hsm("k1", "HMAC-SHA3-256").unwrap();
        assert!(hsm.delete_key_from_hsm("k1").unwrap());
        assert!(!hsm.delete_key_from_hsm("k1").unwrap());
        assert!(hsm.sign_in_hsm("k1", b"data").is_err());
    }

    #[test]
    fn test_software_hsm_info() {
        let hsm = SoftwareHsm::new();
        let info = hsm.hsm_info();
        assert_eq!(info.provider, "software");
        assert!(!info.is_hardware);
        assert!(!info.fips_certified);
    }

    #[test]
    fn test_software_hsm_supported_algorithms() {
        let hsm = SoftwareHsm::new();
        let algos = hsm.supported_algorithms();
        assert!(algos.contains(&"HMAC-SHA3-256".to_string()));
    }

    #[test]
    fn test_software_hsm_provider_name() {
        let hsm = SoftwareHsm::new();
        assert_eq!(hsm.provider_name(), "software");
    }
}
