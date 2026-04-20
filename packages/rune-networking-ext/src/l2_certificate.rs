// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — TLS certificate management and validation.
//
// Structured certificate lifecycle management with SHA3-256
// fingerprinting, validation, and expiration tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use sha3::{Digest, Sha3_256};

// ── L2KeyAlgorithm ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2KeyAlgorithm {
    Rsa,
    Ecdsa,
    Ed25519,
    Unknown(String),
}

impl fmt::Display for L2KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa => write!(f, "RSA"),
            Self::Ecdsa => write!(f, "ECDSA"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Unknown(name) => write!(f, "Unknown({name})"),
        }
    }
}

// ── L2Certificate ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2Certificate {
    pub id: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
    pub key_algorithm: L2KeyAlgorithm,
    pub key_size_bits: u32,
    pub is_ca: bool,
    pub san_entries: Vec<String>,
}

impl L2Certificate {
    pub fn new(
        id: impl Into<String>,
        subject: impl Into<String>,
        issuer: impl Into<String>,
        content: &[u8],
        key_algorithm: L2KeyAlgorithm,
        key_size_bits: u32,
        not_before: i64,
        not_after: i64,
    ) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(content);
        let fingerprint = hex::encode(hasher.finalize());

        Self {
            id: id.into(),
            subject: subject.into(),
            issuer: issuer.into(),
            serial_number: String::new(),
            not_before,
            not_after,
            fingerprint,
            key_algorithm,
            key_size_bits,
            is_ca: false,
            san_entries: Vec::new(),
        }
    }

    pub fn with_serial(mut self, serial: impl Into<String>) -> Self {
        self.serial_number = serial.into();
        self
    }

    pub fn with_ca(mut self, is_ca: bool) -> Self {
        self.is_ca = is_ca;
        self
    }

    pub fn with_san(mut self, san: Vec<String>) -> Self {
        self.san_entries = san;
        self
    }
}

// ── L2CertificateStore ───────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2CertificateStore {
    certificates: HashMap<String, L2Certificate>,
}

impl L2CertificateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, cert: L2Certificate) {
        self.certificates.insert(cert.id.clone(), cert);
    }

    pub fn get(&self, id: &str) -> Option<&L2Certificate> {
        self.certificates.get(id)
    }

    pub fn is_valid(&self, id: &str, now: i64) -> bool {
        self.certificates
            .get(id)
            .is_some_and(|c| c.not_before <= now && now <= c.not_after)
    }

    pub fn expiring_within(&self, now: i64, window_ms: i64) -> Vec<&L2Certificate> {
        let threshold = now + window_ms;
        self.certificates
            .values()
            .filter(|c| c.not_after > now && c.not_after <= threshold)
            .collect()
    }

    pub fn expired(&self, now: i64) -> Vec<&L2Certificate> {
        self.certificates
            .values()
            .filter(|c| c.not_after < now)
            .collect()
    }

    pub fn certificates_for_subject(&self, subject: &str) -> Vec<&L2Certificate> {
        self.certificates
            .values()
            .filter(|c| c.subject == subject)
            .collect()
    }

    pub fn ca_certificates(&self) -> Vec<&L2Certificate> {
        self.certificates
            .values()
            .filter(|c| c.is_ca)
            .collect()
    }

    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }
}

// ── CertificateIssue ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CertificateIssue {
    Expired,
    NotYetValid,
    WeakKeySize { bits: u32, minimum: u32 },
    WeakAlgorithm { algorithm: String },
    MissingSan,
    SelfSigned,
    ExpiresWithinDays(u32),
}

impl fmt::Display for CertificateIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "Certificate has expired"),
            Self::NotYetValid => write!(f, "Certificate not yet valid"),
            Self::WeakKeySize { bits, minimum } => {
                write!(f, "Key size {bits} bits below minimum {minimum}")
            }
            Self::WeakAlgorithm { algorithm } => {
                write!(f, "Weak algorithm: {algorithm}")
            }
            Self::MissingSan => write!(f, "Missing Subject Alternative Name"),
            Self::SelfSigned => write!(f, "Certificate is self-signed"),
            Self::ExpiresWithinDays(days) => {
                write!(f, "Expires within {days} days")
            }
        }
    }
}

// ── CertificateValidation ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2CertificateValidation {
    pub certificate_id: String,
    pub valid: bool,
    pub issues: Vec<CertificateIssue>,
    pub validated_at: i64,
}

pub fn validate_certificate(
    cert: &L2Certificate,
    now: i64,
    min_key_bits: u32,
) -> L2CertificateValidation {
    let mut issues = Vec::new();

    if now > cert.not_after {
        issues.push(CertificateIssue::Expired);
    }

    if now < cert.not_before {
        issues.push(CertificateIssue::NotYetValid);
    }

    if cert.key_size_bits < min_key_bits {
        issues.push(CertificateIssue::WeakKeySize {
            bits: cert.key_size_bits,
            minimum: min_key_bits,
        });
    }

    if cert.san_entries.is_empty() {
        issues.push(CertificateIssue::MissingSan);
    }

    if cert.subject == cert.issuer {
        issues.push(CertificateIssue::SelfSigned);
    }

    // Check if expiring within 30 days (30 * 86_400_000 ms)
    let thirty_days_ms: i64 = 30 * 86_400_000;
    if now <= cert.not_after && cert.not_after - now < thirty_days_ms {
        issues.push(CertificateIssue::ExpiresWithinDays(30));
    }

    let valid = !issues
        .iter()
        .any(|i| matches!(i, CertificateIssue::Expired | CertificateIssue::NotYetValid | CertificateIssue::WeakKeySize { .. }));

    L2CertificateValidation {
        certificate_id: cert.id.clone(),
        valid,
        issues,
        validated_at: now,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert(id: &str) -> L2Certificate {
        L2Certificate::new(
            id,
            "CN=example.com",
            "CN=TestCA",
            b"cert-content",
            L2KeyAlgorithm::Rsa,
            2048,
            1000,
            100_000_000,
        )
        .with_serial("001")
        .with_san(vec!["example.com".into(), "www.example.com".into()])
    }

    #[test]
    fn test_certificate_construction() {
        let cert = sample_cert("c1");
        assert_eq!(cert.id, "c1");
        assert_eq!(cert.subject, "CN=example.com");
        assert!(!cert.fingerprint.is_empty());
        assert_eq!(cert.fingerprint.len(), 64); // SHA3-256 hex
        assert_eq!(cert.san_entries.len(), 2);
    }

    #[test]
    fn test_store_add_and_get() {
        let mut store = L2CertificateStore::new();
        store.add(sample_cert("c1"));
        assert!(store.get("c1").is_some());
        assert!(store.get("c2").is_none());
    }

    #[test]
    fn test_store_is_valid_true() {
        let mut store = L2CertificateStore::new();
        store.add(sample_cert("c1"));
        assert!(store.is_valid("c1", 50_000));
    }

    #[test]
    fn test_store_is_valid_false_expired() {
        let mut store = L2CertificateStore::new();
        store.add(sample_cert("c1")); // not_after = 100_000_000
        assert!(!store.is_valid("c1", 200_000_000));
    }

    #[test]
    fn test_store_expiring_within() {
        let mut store = L2CertificateStore::new();
        let mut cert = sample_cert("c1");
        cert.not_after = 50_000 + 5 * 86_400_000; // 5 days from now
        store.add(cert);
        let mut cert2 = sample_cert("c2");
        cert2.not_after = 50_000 + 60 * 86_400_000; // 60 days
        store.add(cert2);
        let expiring = store.expiring_within(50_000, 30 * 86_400_000);
        assert_eq!(expiring.len(), 1);
    }

    #[test]
    fn test_store_expired() {
        let mut store = L2CertificateStore::new();
        store.add(sample_cert("c1")); // not_after = 100_000_000
        assert_eq!(store.expired(200_000_000).len(), 1);
        assert_eq!(store.expired(50_000).len(), 0);
    }

    #[test]
    fn test_store_ca_certificates() {
        let mut store = L2CertificateStore::new();
        store.add(sample_cert("c1").with_ca(true));
        store.add(sample_cert("c2"));
        assert_eq!(store.ca_certificates().len(), 1);
    }

    #[test]
    fn test_validate_passes_for_valid() {
        let cert = sample_cert("c1");
        let result = validate_certificate(&cert, 50_000, 2048);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_detects_expired() {
        let cert = sample_cert("c1");
        let result = validate_certificate(&cert, 200_000_000, 2048);
        assert!(!result.valid);
        assert!(result.issues.iter().any(|i| matches!(i, CertificateIssue::Expired)));
    }

    #[test]
    fn test_validate_detects_weak_key() {
        let cert = sample_cert("c1"); // 2048 bits
        let result = validate_certificate(&cert, 50_000, 4096);
        assert!(!result.valid);
        assert!(result.issues.iter().any(|i| matches!(i, CertificateIssue::WeakKeySize { .. })));
    }

    #[test]
    fn test_validate_detects_missing_san() {
        let cert = L2Certificate::new(
            "c1", "CN=example.com", "CN=TestCA", b"content",
            L2KeyAlgorithm::Rsa, 2048, 1000, 100_000_000,
        ); // no SAN
        let result = validate_certificate(&cert, 50_000, 2048);
        assert!(result.issues.iter().any(|i| matches!(i, CertificateIssue::MissingSan)));
    }
}
