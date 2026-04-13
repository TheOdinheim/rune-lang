// ═══════════════════════════════════════════════════════════════════════
// Protocol — TLS/protocol version enforcement and cipher suite governance.
// Enforces minimum TLS versions, acceptable cipher suites, PFS
// requirements, and mTLS policies.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

// ── TlsVersion ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    fn ordinal(self) -> u8 {
        match self {
            Self::Tls10 => 0,
            Self::Tls11 => 1,
            Self::Tls12 => 2,
            Self::Tls13 => 3,
        }
    }

    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::Tls10 | Self::Tls11)
    }

    pub fn supports_forward_secrecy(&self) -> bool {
        matches!(self, Self::Tls12 | Self::Tls13)
    }
}

impl Ord for TlsVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal().cmp(&other.ordinal())
    }
}

impl PartialOrd for TlsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls10 => write!(f, "TLS 1.0"),
            Self::Tls11 => write!(f, "TLS 1.1"),
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

// ── CipherSuite ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
    Aes128CbcSha256,
    Aes256CbcSha384,
    EcdheRsaAes128GcmSha256,
    EcdheRsaAes256GcmSha384,
    EcdheEcdsaAes128GcmSha256,
    EcdheEcdsaAes256GcmSha384,
    Rc4Sha,
    DesCbcSha,
    TripleDesCbcSha,
    Custom(String),
}

impl CipherSuite {
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::Rc4Sha | Self::DesCbcSha)
    }

    pub fn is_weak(&self) -> bool {
        self.is_insecure() || matches!(self, Self::TripleDesCbcSha)
    }

    pub fn provides_forward_secrecy(&self) -> bool {
        matches!(
            self,
            Self::Chacha20Poly1305Sha256
                | Self::EcdheRsaAes128GcmSha256
                | Self::EcdheRsaAes256GcmSha384
                | Self::EcdheEcdsaAes128GcmSha256
                | Self::EcdheEcdsaAes256GcmSha384
        )
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128GcmSha256 => write!(f, "AES-128-GCM-SHA256"),
            Self::Aes256GcmSha384 => write!(f, "AES-256-GCM-SHA384"),
            Self::Chacha20Poly1305Sha256 => write!(f, "CHACHA20-POLY1305-SHA256"),
            Self::Aes128CbcSha256 => write!(f, "AES-128-CBC-SHA256"),
            Self::Aes256CbcSha384 => write!(f, "AES-256-CBC-SHA384"),
            Self::EcdheRsaAes128GcmSha256 => write!(f, "ECDHE-RSA-AES128-GCM-SHA256"),
            Self::EcdheRsaAes256GcmSha384 => write!(f, "ECDHE-RSA-AES256-GCM-SHA384"),
            Self::EcdheEcdsaAes128GcmSha256 => write!(f, "ECDHE-ECDSA-AES128-GCM-SHA256"),
            Self::EcdheEcdsaAes256GcmSha384 => write!(f, "ECDHE-ECDSA-AES256-GCM-SHA384"),
            Self::Rc4Sha => write!(f, "RC4-SHA"),
            Self::DesCbcSha => write!(f, "DES-CBC-SHA"),
            Self::TripleDesCbcSha => write!(f, "3DES-CBC-SHA"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── CertificateValidation ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateValidation {
    None,
    Standard,
    Strict,
    Pinned { pins: Vec<String> },
}

impl fmt::Display for CertificateValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Standard => write!(f, "Standard"),
            Self::Strict => write!(f, "Strict"),
            Self::Pinned { pins } => write!(f, "Pinned({} keys)", pins.len()),
        }
    }
}

// ── TlsPolicy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsPolicy {
    pub id: String,
    pub name: String,
    pub min_tls_version: TlsVersion,
    pub max_tls_version: Option<TlsVersion>,
    pub allowed_cipher_suites: Vec<CipherSuite>,
    pub denied_cipher_suites: Vec<CipherSuite>,
    pub require_forward_secrecy: bool,
    pub require_certificate: bool,
    pub certificate_validation: CertificateValidation,
    pub max_session_duration_ms: Option<i64>,
    pub enforce_ocsp_stapling: bool,
    pub metadata: HashMap<String, String>,
}

impl TlsPolicy {
    pub fn modern() -> Self {
        Self {
            id: "modern".into(),
            name: "Modern TLS Policy".into(),
            min_tls_version: TlsVersion::Tls13,
            max_tls_version: None,
            allowed_cipher_suites: vec![
                CipherSuite::Aes128GcmSha256,
                CipherSuite::Aes256GcmSha384,
                CipherSuite::Chacha20Poly1305Sha256,
            ],
            denied_cipher_suites: vec![
                CipherSuite::Rc4Sha,
                CipherSuite::DesCbcSha,
                CipherSuite::TripleDesCbcSha,
            ],
            require_forward_secrecy: true,
            require_certificate: false,
            certificate_validation: CertificateValidation::Strict,
            max_session_duration_ms: None,
            enforce_ocsp_stapling: false,
            metadata: HashMap::new(),
        }
    }

    pub fn intermediate() -> Self {
        Self {
            id: "intermediate".into(),
            name: "Intermediate TLS Policy".into(),
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: None,
            allowed_cipher_suites: vec![
                CipherSuite::Aes128GcmSha256,
                CipherSuite::Aes256GcmSha384,
                CipherSuite::Chacha20Poly1305Sha256,
                CipherSuite::EcdheRsaAes128GcmSha256,
                CipherSuite::EcdheRsaAes256GcmSha384,
                CipherSuite::EcdheEcdsaAes128GcmSha256,
                CipherSuite::EcdheEcdsaAes256GcmSha384,
            ],
            denied_cipher_suites: vec![
                CipherSuite::Rc4Sha,
                CipherSuite::DesCbcSha,
                CipherSuite::TripleDesCbcSha,
            ],
            require_forward_secrecy: true,
            require_certificate: false,
            certificate_validation: CertificateValidation::Standard,
            max_session_duration_ms: None,
            enforce_ocsp_stapling: false,
            metadata: HashMap::new(),
        }
    }

    pub fn legacy() -> Self {
        Self {
            id: "legacy".into(),
            name: "Legacy TLS Policy".into(),
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: None,
            allowed_cipher_suites: Vec::new(), // all non-denied allowed
            denied_cipher_suites: vec![CipherSuite::Rc4Sha, CipherSuite::DesCbcSha],
            require_forward_secrecy: false,
            require_certificate: false,
            certificate_validation: CertificateValidation::Standard,
            max_session_duration_ms: None,
            enforce_ocsp_stapling: false,
            metadata: HashMap::new(),
        }
    }

    pub fn air_gapped() -> Self {
        Self {
            id: "air_gapped".into(),
            name: "Air-Gapped TLS Policy".into(),
            min_tls_version: TlsVersion::Tls13,
            max_tls_version: Some(TlsVersion::Tls13),
            allowed_cipher_suites: vec![
                CipherSuite::Aes256GcmSha384,
                CipherSuite::Chacha20Poly1305Sha256,
            ],
            denied_cipher_suites: vec![
                CipherSuite::Rc4Sha,
                CipherSuite::DesCbcSha,
                CipherSuite::TripleDesCbcSha,
            ],
            require_forward_secrecy: true,
            require_certificate: true,
            certificate_validation: CertificateValidation::Pinned { pins: Vec::new() },
            max_session_duration_ms: Some(3_600_000),
            enforce_ocsp_stapling: true,
            metadata: HashMap::new(),
        }
    }
}

// ── ProtocolCheckResult ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProtocolCheckResult {
    pub passed: bool,
    pub check_name: String,
    pub detail: String,
    pub severity: SecuritySeverity,
}

// ── ProtocolChecker ─────────────────────────────────────────────────

pub struct ProtocolChecker {
    policy: TlsPolicy,
}

impl ProtocolChecker {
    pub fn new(policy: TlsPolicy) -> Self {
        Self { policy }
    }

    pub fn check_version(&self, version: TlsVersion) -> ProtocolCheckResult {
        if version < self.policy.min_tls_version {
            return ProtocolCheckResult {
                passed: false,
                check_name: "tls_version".into(),
                detail: format!(
                    "{version} below minimum {}",
                    self.policy.min_tls_version
                ),
                severity: if version.is_deprecated() {
                    SecuritySeverity::Critical
                } else {
                    SecuritySeverity::High
                },
            };
        }
        if let Some(max) = self.policy.max_tls_version {
            if version > max {
                return ProtocolCheckResult {
                    passed: false,
                    check_name: "tls_version".into(),
                    detail: format!("{version} above maximum {max}"),
                    severity: SecuritySeverity::Medium,
                };
            }
        }
        ProtocolCheckResult {
            passed: true,
            check_name: "tls_version".into(),
            detail: format!("{version} accepted"),
            severity: SecuritySeverity::Info,
        }
    }

    pub fn check_cipher(&self, cipher: &CipherSuite) -> ProtocolCheckResult {
        if self.policy.denied_cipher_suites.contains(cipher) || cipher.is_insecure() {
            return ProtocolCheckResult {
                passed: false,
                check_name: "cipher_suite".into(),
                detail: format!("{cipher} is denied or insecure"),
                severity: SecuritySeverity::Critical,
            };
        }
        if !self.policy.allowed_cipher_suites.is_empty()
            && !self.policy.allowed_cipher_suites.contains(cipher)
        {
            return ProtocolCheckResult {
                passed: false,
                check_name: "cipher_suite".into(),
                detail: format!("{cipher} not in allowed list"),
                severity: SecuritySeverity::High,
            };
        }
        if self.policy.require_forward_secrecy && !cipher.provides_forward_secrecy() {
            return ProtocolCheckResult {
                passed: false,
                check_name: "cipher_suite".into(),
                detail: format!("{cipher} does not provide forward secrecy"),
                severity: SecuritySeverity::High,
            };
        }
        ProtocolCheckResult {
            passed: true,
            check_name: "cipher_suite".into(),
            detail: format!("{cipher} accepted"),
            severity: SecuritySeverity::Info,
        }
    }

    pub fn check_connection(
        &self,
        version: TlsVersion,
        cipher: &CipherSuite,
        has_client_cert: bool,
    ) -> ProtocolCheckResult {
        let ver = self.check_version(version);
        if !ver.passed {
            return ver;
        }
        let cip = self.check_cipher(cipher);
        if !cip.passed {
            return cip;
        }
        if self.policy.require_certificate && !has_client_cert {
            return ProtocolCheckResult {
                passed: false,
                check_name: "client_certificate".into(),
                detail: "Client certificate required (mTLS)".into(),
                severity: SecuritySeverity::High,
            };
        }
        ProtocolCheckResult {
            passed: true,
            check_name: "connection".into(),
            detail: "All protocol checks passed".into(),
            severity: SecuritySeverity::Info,
        }
    }

    pub fn validate_full(
        &self,
        version: TlsVersion,
        cipher: &CipherSuite,
        has_client_cert: bool,
    ) -> Vec<ProtocolCheckResult> {
        let mut results = Vec::new();
        results.push(self.check_version(version));
        results.push(self.check_cipher(cipher));
        if self.policy.require_certificate {
            results.push(ProtocolCheckResult {
                passed: has_client_cert,
                check_name: "client_certificate".into(),
                detail: if has_client_cert {
                    "Client certificate present".into()
                } else {
                    "Client certificate required (mTLS)".into()
                },
                severity: if has_client_cert {
                    SecuritySeverity::Info
                } else {
                    SecuritySeverity::High
                },
            });
        }
        results
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls10 < TlsVersion::Tls11);
        assert!(TlsVersion::Tls11 < TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_version_is_deprecated() {
        assert!(TlsVersion::Tls10.is_deprecated());
        assert!(TlsVersion::Tls11.is_deprecated());
        assert!(!TlsVersion::Tls12.is_deprecated());
        assert!(!TlsVersion::Tls13.is_deprecated());
    }

    #[test]
    fn test_tls_version_supports_forward_secrecy() {
        assert!(!TlsVersion::Tls10.supports_forward_secrecy());
        assert!(!TlsVersion::Tls11.supports_forward_secrecy());
        assert!(TlsVersion::Tls12.supports_forward_secrecy());
        assert!(TlsVersion::Tls13.supports_forward_secrecy());
    }

    #[test]
    fn test_cipher_is_insecure() {
        assert!(CipherSuite::Rc4Sha.is_insecure());
        assert!(CipherSuite::DesCbcSha.is_insecure());
        assert!(!CipherSuite::Aes128GcmSha256.is_insecure());
        assert!(!CipherSuite::TripleDesCbcSha.is_insecure());
    }

    #[test]
    fn test_cipher_is_weak() {
        assert!(CipherSuite::Rc4Sha.is_weak());
        assert!(CipherSuite::DesCbcSha.is_weak());
        assert!(CipherSuite::TripleDesCbcSha.is_weak());
        assert!(!CipherSuite::Aes256GcmSha384.is_weak());
    }

    #[test]
    fn test_cipher_provides_forward_secrecy() {
        assert!(CipherSuite::Chacha20Poly1305Sha256.provides_forward_secrecy());
        assert!(CipherSuite::EcdheRsaAes128GcmSha256.provides_forward_secrecy());
        assert!(CipherSuite::EcdheRsaAes256GcmSha384.provides_forward_secrecy());
        assert!(CipherSuite::EcdheEcdsaAes128GcmSha256.provides_forward_secrecy());
        assert!(CipherSuite::EcdheEcdsaAes256GcmSha384.provides_forward_secrecy());
        assert!(!CipherSuite::Aes128GcmSha256.provides_forward_secrecy());
        assert!(!CipherSuite::Aes128CbcSha256.provides_forward_secrecy());
    }

    #[test]
    fn test_check_version_rejects_below_minimum() {
        let checker = ProtocolChecker::new(TlsPolicy::modern());
        let r = checker.check_version(TlsVersion::Tls12);
        assert!(!r.passed);
    }

    #[test]
    fn test_check_version_allows_at_minimum() {
        let checker = ProtocolChecker::new(TlsPolicy::intermediate());
        let r = checker.check_version(TlsVersion::Tls12);
        assert!(r.passed);
    }

    #[test]
    fn test_check_cipher_rejects_insecure() {
        let checker = ProtocolChecker::new(TlsPolicy::modern());
        let r = checker.check_cipher(&CipherSuite::Rc4Sha);
        assert!(!r.passed);
    }

    #[test]
    fn test_check_cipher_rejects_no_pfs_when_required() {
        let checker = ProtocolChecker::new(TlsPolicy::modern());
        let r = checker.check_cipher(&CipherSuite::Aes128CbcSha256);
        assert!(!r.passed);
    }

    #[test]
    fn test_check_connection_full() {
        let checker = ProtocolChecker::new(TlsPolicy::intermediate());
        let r = checker.check_connection(
            TlsVersion::Tls12,
            &CipherSuite::EcdheRsaAes256GcmSha384,
            false,
        );
        assert!(r.passed);
    }

    #[test]
    fn test_modern_enforces_tls13_only() {
        let policy = TlsPolicy::modern();
        assert_eq!(policy.min_tls_version, TlsVersion::Tls13);
        assert!(policy.require_forward_secrecy);
    }

    #[test]
    fn test_intermediate_allows_tls12() {
        let policy = TlsPolicy::intermediate();
        assert_eq!(policy.min_tls_version, TlsVersion::Tls12);
    }

    #[test]
    fn test_air_gapped_requires_mtls() {
        let policy = TlsPolicy::air_gapped();
        assert!(policy.require_certificate);
        assert!(policy.enforce_ocsp_stapling);
        assert!(matches!(policy.certificate_validation, CertificateValidation::Pinned { .. }));
    }

    #[test]
    fn test_certificate_validation_display() {
        let variants = vec![
            CertificateValidation::None,
            CertificateValidation::Standard,
            CertificateValidation::Strict,
            CertificateValidation::Pinned { pins: vec!["hash1".into()] },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 4);
    }
}
