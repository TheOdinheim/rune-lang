// ═══════════════════════════════════════════════════════════════════════
// Certificate — Certificate validation, lifecycle, and pinning.
// Manages certificate state, validates expiry/revocation/key size,
// and enforces certificate pinning.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

// ── KeyType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
    Custom(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa => write!(f, "RSA"),
            Self::Ecdsa => write!(f, "ECDSA"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── CertificateStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateStatus {
    Valid,
    Expired,
    NotYetValid,
    Revoked { reason: String },
    Unknown,
}

impl fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Expired => write!(f, "Expired"),
            Self::NotYetValid => write!(f, "NotYetValid"),
            Self::Revoked { reason } => write!(f, "Revoked: {reason}"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── CertificateInfo ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub id: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
    pub public_key_hash: String,
    pub key_type: KeyType,
    pub key_size_bits: u32,
    pub is_ca: bool,
    pub san: Vec<String>,
    pub status: CertificateStatus,
}

// ── CertificateCheck ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CertificateCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

// ── CertificateValidationResult ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CertificateValidationResult {
    pub valid: bool,
    pub checks: Vec<CertificateCheck>,
    pub detail: String,
}

// ── CertificateStore ────────────────────────────────────────────────

pub struct CertificateStore {
    certificates: HashMap<String, CertificateInfo>,
    pinned_keys: Vec<String>,
    min_key_size: HashMap<String, u32>,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            pinned_keys: Vec::new(),
            min_key_size: HashMap::new(),
        }
    }

    pub fn add(&mut self, cert: CertificateInfo) -> Result<(), NetworkError> {
        if self.certificates.contains_key(&cert.id) {
            return Err(NetworkError::InvalidOperation(format!(
                "Certificate {} already exists",
                cert.id
            )));
        }
        self.certificates.insert(cert.id.clone(), cert);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&CertificateInfo> {
        self.certificates.get(id)
    }

    pub fn validate(&self, cert: &CertificateInfo, now: i64) -> CertificateValidationResult {
        let mut checks = Vec::new();
        let mut all_passed = true;

        // Expiry check
        let expiry_ok = now <= cert.not_after;
        checks.push(CertificateCheck {
            name: "expiry".into(),
            passed: expiry_ok,
            detail: if expiry_ok {
                "Certificate not expired".into()
            } else {
                "Certificate has expired".into()
            },
        });
        if !expiry_ok {
            all_passed = false;
        }

        // Not-before check
        let not_before_ok = now >= cert.not_before;
        checks.push(CertificateCheck {
            name: "not_before".into(),
            passed: not_before_ok,
            detail: if not_before_ok {
                "Certificate is valid (past not-before)".into()
            } else {
                "Certificate not yet valid".into()
            },
        });
        if !not_before_ok {
            all_passed = false;
        }

        // Revocation check
        let revoked = matches!(cert.status, CertificateStatus::Revoked { .. });
        checks.push(CertificateCheck {
            name: "revocation".into(),
            passed: !revoked,
            detail: if revoked {
                "Certificate is revoked".into()
            } else {
                "Certificate not revoked".into()
            },
        });
        if revoked {
            all_passed = false;
        }

        // Key size check
        let key_type_str = match &cert.key_type {
            KeyType::Rsa => "RSA",
            KeyType::Ecdsa => "ECDSA",
            KeyType::Ed25519 => "Ed25519",
            KeyType::Custom(n) => n.as_str(),
        };
        if let Some(&min_size) = self.min_key_size.get(key_type_str) {
            let key_ok = cert.key_size_bits >= min_size;
            checks.push(CertificateCheck {
                name: "key_size".into(),
                passed: key_ok,
                detail: if key_ok {
                    format!("{} bits >= minimum {min_size}", cert.key_size_bits)
                } else {
                    format!("{} bits < minimum {min_size}", cert.key_size_bits)
                },
            });
            if !key_ok {
                all_passed = false;
            }
        }

        // Pinning check
        if !self.pinned_keys.is_empty() {
            let pinned_ok = self.pinned_keys.contains(&cert.public_key_hash);
            checks.push(CertificateCheck {
                name: "pinning".into(),
                passed: pinned_ok,
                detail: if pinned_ok {
                    "Public key hash matches a pinned key".into()
                } else {
                    "Public key hash not in pinned set".into()
                },
            });
            if !pinned_ok {
                all_passed = false;
            }
        }

        let detail = if all_passed {
            "All checks passed".into()
        } else {
            let failed: Vec<&str> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.as_str())
                .collect();
            format!("Failed checks: {}", failed.join(", "))
        };

        CertificateValidationResult {
            valid: all_passed,
            checks,
            detail,
        }
    }

    pub fn expiring_soon(&self, within_days: u64, now: i64) -> Vec<&CertificateInfo> {
        let threshold = now + (within_days as i64 * 86_400_000);
        self.certificates
            .values()
            .filter(|c| c.not_after > now && c.not_after <= threshold)
            .collect()
    }

    pub fn expired(&self, now: i64) -> Vec<&CertificateInfo> {
        self.certificates
            .values()
            .filter(|c| c.not_after < now)
            .collect()
    }

    pub fn pin_key(&mut self, public_key_hash: &str) {
        if !self.pinned_keys.contains(&public_key_hash.to_string()) {
            self.pinned_keys.push(public_key_hash.into());
        }
    }

    pub fn is_pinned(&self, public_key_hash: &str) -> bool {
        self.pinned_keys.iter().any(|k| k == public_key_hash)
    }

    pub fn set_min_key_size(&mut self, key_type: &str, min_bits: u32) {
        self.min_key_size.insert(key_type.into(), min_bits);
    }

    pub fn by_status(&self, status: &CertificateStatus) -> Vec<&CertificateInfo> {
        self.certificates
            .values()
            .filter(|c| &c.status == status)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.certificates.len()
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert(id: &str) -> CertificateInfo {
        CertificateInfo {
            id: id.into(),
            subject: "CN=example.com".into(),
            issuer: "CN=TestCA".into(),
            serial: "001".into(),
            not_before: 1000,
            not_after: 100_000,
            fingerprint: "sha256:abc123".into(),
            public_key_hash: "pin-sha256:xyz789".into(),
            key_type: KeyType::Rsa,
            key_size_bits: 2048,
            is_ca: false,
            san: vec!["example.com".into(), "www.example.com".into()],
            status: CertificateStatus::Valid,
        }
    }

    #[test]
    fn test_add_and_get() {
        let mut store = CertificateStore::new();
        store.add(sample_cert("c1")).unwrap();
        assert!(store.get("c1").is_some());
        assert!(store.get("c2").is_none());
    }

    #[test]
    fn test_validate_succeeds_for_valid() {
        let store = CertificateStore::new();
        let cert = sample_cert("c1");
        let result = store.validate(&cert, 50_000);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_fails_for_expired() {
        let store = CertificateStore::new();
        let cert = sample_cert("c1");
        let result = store.validate(&cert, 200_000);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_fails_for_not_yet_valid() {
        let store = CertificateStore::new();
        let cert = sample_cert("c1");
        let result = store.validate(&cert, 500);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_fails_for_revoked() {
        let store = CertificateStore::new();
        let mut cert = sample_cert("c1");
        cert.status = CertificateStatus::Revoked { reason: "compromised".into() };
        let result = store.validate(&cert, 50_000);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_fails_for_key_size_below_minimum() {
        let mut store = CertificateStore::new();
        store.set_min_key_size("RSA", 4096);
        let cert = sample_cert("c1"); // 2048 bits
        let result = store.validate(&cert, 50_000);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_fails_when_pinned_key_doesnt_match() {
        let mut store = CertificateStore::new();
        store.pin_key("pin-sha256:other_hash");
        let cert = sample_cert("c1");
        let result = store.validate(&cert, 50_000);
        assert!(!result.valid);
    }

    #[test]
    fn test_expiring_soon() {
        let mut store = CertificateStore::new();
        let mut cert = sample_cert("c1");
        cert.not_after = 50_000 + 5 * 86_400_000; // 5 days from now
        store.add(cert).unwrap();
        let mut cert2 = sample_cert("c2");
        cert2.not_after = 50_000 + 60 * 86_400_000; // 60 days from now
        store.add(cert2).unwrap();
        assert_eq!(store.expiring_soon(30, 50_000).len(), 1);
    }

    #[test]
    fn test_expired() {
        let mut store = CertificateStore::new();
        store.add(sample_cert("c1")).unwrap(); // expires at 100_000
        assert_eq!(store.expired(200_000).len(), 1);
        assert_eq!(store.expired(50_000).len(), 0);
    }

    #[test]
    fn test_pin_key_and_is_pinned() {
        let mut store = CertificateStore::new();
        store.pin_key("hash1");
        assert!(store.is_pinned("hash1"));
        assert!(!store.is_pinned("hash2"));
    }

    #[test]
    fn test_set_min_key_size_enforces_minimum() {
        let mut store = CertificateStore::new();
        store.set_min_key_size("RSA", 2048);
        let cert = sample_cert("c1"); // 2048 bits
        let result = store.validate(&cert, 50_000);
        assert!(result.valid);
    }

    #[test]
    fn test_key_type_display() {
        let types = vec![
            KeyType::Rsa,
            KeyType::Ecdsa,
            KeyType::Ed25519,
            KeyType::Custom("ML-KEM".into()),
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 4);
    }

    #[test]
    fn test_certificate_status_display() {
        let statuses = vec![
            CertificateStatus::Valid,
            CertificateStatus::Expired,
            CertificateStatus::NotYetValid,
            CertificateStatus::Revoked { reason: "compromised".into() },
            CertificateStatus::Unknown,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }
}
