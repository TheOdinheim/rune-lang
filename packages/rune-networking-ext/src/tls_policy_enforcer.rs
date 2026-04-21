// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — TlsPolicyEnforcer trait for evaluating TLS connections
// against governance policies: version compliance, cipher suite
// validation, certificate evaluation, expiration monitoring.
// Includes StrictTlsPolicyEnforcer composable wrapper (TLS 1.3 + CT).
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

// ── TlsPolicyDecision ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsPolicyDecision {
    Compliant,
    NonCompliant,
    RequiresUpgrade,
    CertificateIssueDetected,
    ConnectionRejected,
}

impl fmt::Display for TlsPolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Compliant => "Compliant",
            Self::NonCompliant => "NonCompliant",
            Self::RequiresUpgrade => "RequiresUpgrade",
            Self::CertificateIssueDetected => "CertificateIssueDetected",
            Self::ConnectionRejected => "ConnectionRejected",
        };
        f.write_str(s)
    }
}

// ── TlsPolicyEvaluation ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicyEvaluation {
    pub connection_id: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub decision: TlsPolicyDecision,
    pub justification: String,
    pub evaluated_at: i64,
}

// ── CertificateEvaluation ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateEvaluation {
    pub certificate_id: String,
    pub subject: String,
    pub issues: Vec<TlsCertificateIssue>,
    pub expiration_status: CertificateExpirationStatus,
    pub certificate_transparency_logged: bool,
    pub evaluated_at: i64,
}

// ── TlsCertificateIssue ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsCertificateIssue {
    Expired,
    NotYetValid,
    WeakKeySize,
    WeakAlgorithm,
    MissingSan,
    SelfSigned,
    NoCertificateTransparency,
    OcspStaplingMissing,
}

impl fmt::Display for TlsCertificateIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Expired => "Expired",
            Self::NotYetValid => "NotYetValid",
            Self::WeakKeySize => "WeakKeySize",
            Self::WeakAlgorithm => "WeakAlgorithm",
            Self::MissingSan => "MissingSan",
            Self::SelfSigned => "SelfSigned",
            Self::NoCertificateTransparency => "NoCertificateTransparency",
            Self::OcspStaplingMissing => "OcspStaplingMissing",
        };
        f.write_str(s)
    }
}

// ── CertificateExpirationStatus ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertificateExpirationStatus {
    Valid,
    ExpiringSoon,
    Expired,
    NotYetValid,
}

impl fmt::Display for CertificateExpirationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Valid => "Valid",
            Self::ExpiringSoon => "ExpiringSoon",
            Self::Expired => "Expired",
            Self::NotYetValid => "NotYetValid",
        };
        f.write_str(s)
    }
}

// ── TlsPolicyEnforcer trait ────────────────────────────────────────

pub trait TlsPolicyEnforcer {
    fn evaluate_connection(
        &self,
        connection_id: &str,
        tls_version: &str,
        cipher_suite: &str,
        has_client_cert: bool,
    ) -> Result<TlsPolicyEvaluation, NetworkError>;

    fn evaluate_certificate(
        &self,
        certificate_id: &str,
        subject: &str,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<CertificateEvaluation, NetworkError>;

    fn is_version_compliant(&self, tls_version: &str) -> bool;
    fn is_cipher_compliant(&self, cipher_suite: &str) -> bool;

    fn enforcer_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryTlsPolicyEnforcer ──────────────────────────────────────

pub struct InMemoryTlsPolicyEnforcer {
    id: String,
    min_tls_version: String,
    denied_ciphers: Vec<String>,
    require_client_cert: bool,
    require_ct: bool,
    #[allow(dead_code)]
    expiry_warning_days: u32,
}

impl InMemoryTlsPolicyEnforcer {
    pub fn new(id: impl Into<String>, min_tls_version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            min_tls_version: min_tls_version.into(),
            denied_ciphers: Vec::new(),
            require_client_cert: false,
            require_ct: false,
            expiry_warning_days: 30,
        }
    }

    pub fn add_denied_cipher(&mut self, cipher: impl Into<String>) {
        self.denied_ciphers.push(cipher.into());
    }

    pub fn set_require_client_cert(&mut self, required: bool) {
        self.require_client_cert = required;
    }

    pub fn set_require_ct(&mut self, required: bool) {
        self.require_ct = required;
    }
}

impl TlsPolicyEnforcer for InMemoryTlsPolicyEnforcer {
    fn evaluate_connection(
        &self,
        connection_id: &str,
        tls_version: &str,
        cipher_suite: &str,
        has_client_cert: bool,
    ) -> Result<TlsPolicyEvaluation, NetworkError> {
        // Check TLS version
        if !self.is_version_compliant(tls_version) {
            return Ok(TlsPolicyEvaluation {
                connection_id: connection_id.into(),
                tls_version: tls_version.into(),
                cipher_suite: cipher_suite.into(),
                decision: TlsPolicyDecision::RequiresUpgrade,
                justification: format!(
                    "TLS version {tls_version} below minimum {}",
                    self.min_tls_version
                ),
                evaluated_at: 0,
            });
        }

        // Check cipher suite
        if !self.is_cipher_compliant(cipher_suite) {
            return Ok(TlsPolicyEvaluation {
                connection_id: connection_id.into(),
                tls_version: tls_version.into(),
                cipher_suite: cipher_suite.into(),
                decision: TlsPolicyDecision::NonCompliant,
                justification: format!("Cipher suite {cipher_suite} is denied"),
                evaluated_at: 0,
            });
        }

        // Check client certificate
        if self.require_client_cert && !has_client_cert {
            return Ok(TlsPolicyEvaluation {
                connection_id: connection_id.into(),
                tls_version: tls_version.into(),
                cipher_suite: cipher_suite.into(),
                decision: TlsPolicyDecision::ConnectionRejected,
                justification: "Client certificate required (mTLS)".into(),
                evaluated_at: 0,
            });
        }

        Ok(TlsPolicyEvaluation {
            connection_id: connection_id.into(),
            tls_version: tls_version.into(),
            cipher_suite: cipher_suite.into(),
            decision: TlsPolicyDecision::Compliant,
            justification: "Connection meets TLS policy requirements".into(),
            evaluated_at: 0,
        })
    }

    fn evaluate_certificate(
        &self,
        certificate_id: &str,
        subject: &str,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<CertificateEvaluation, NetworkError> {
        let mut issues = Vec::new();

        let expiration_status = if now > not_after {
            issues.push(TlsCertificateIssue::Expired);
            CertificateExpirationStatus::Expired
        } else if now < not_before {
            issues.push(TlsCertificateIssue::NotYetValid);
            CertificateExpirationStatus::NotYetValid
        } else {
            let thirty_days_ms: i64 = 30 * 86_400_000;
            if not_after - now < thirty_days_ms {
                CertificateExpirationStatus::ExpiringSoon
            } else {
                CertificateExpirationStatus::Valid
            }
        };

        Ok(CertificateEvaluation {
            certificate_id: certificate_id.into(),
            subject: subject.into(),
            issues,
            expiration_status,
            certificate_transparency_logged: !self.require_ct,
            evaluated_at: now,
        })
    }

    fn is_version_compliant(&self, tls_version: &str) -> bool {
        let version_rank = |v: &str| -> u8 {
            match v {
                "TLS 1.0" => 1,
                "TLS 1.1" => 2,
                "TLS 1.2" => 3,
                "TLS 1.3" => 4,
                _ => 0,
            }
        };
        version_rank(tls_version) >= version_rank(&self.min_tls_version)
    }

    fn is_cipher_compliant(&self, cipher_suite: &str) -> bool {
        !self
            .denied_ciphers
            .iter()
            .any(|c| c == cipher_suite)
    }

    fn enforcer_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── StrictTlsPolicyEnforcer ────────────────────────────────────────
// Composable wrapper enforcing TLS 1.3 minimum and Certificate
// Transparency (RFC 6962) for all evaluations.

pub struct StrictTlsPolicyEnforcer<E: TlsPolicyEnforcer> {
    inner: E,
}

impl<E: TlsPolicyEnforcer> StrictTlsPolicyEnforcer<E> {
    pub fn new(inner: E) -> Self {
        Self { inner }
    }
}

impl<E: TlsPolicyEnforcer> TlsPolicyEnforcer for StrictTlsPolicyEnforcer<E> {
    fn evaluate_connection(
        &self,
        connection_id: &str,
        tls_version: &str,
        cipher_suite: &str,
        has_client_cert: bool,
    ) -> Result<TlsPolicyEvaluation, NetworkError> {
        // Enforce TLS 1.3 minimum
        if tls_version != "TLS 1.3" {
            return Ok(TlsPolicyEvaluation {
                connection_id: connection_id.into(),
                tls_version: tls_version.into(),
                cipher_suite: cipher_suite.into(),
                decision: TlsPolicyDecision::RequiresUpgrade,
                justification: format!(
                    "StrictTlsPolicyEnforcer: TLS 1.3 required, got {tls_version}"
                ),
                evaluated_at: 0,
            });
        }
        self.inner
            .evaluate_connection(connection_id, tls_version, cipher_suite, has_client_cert)
    }

    fn evaluate_certificate(
        &self,
        certificate_id: &str,
        subject: &str,
        not_before: i64,
        not_after: i64,
        now: i64,
    ) -> Result<CertificateEvaluation, NetworkError> {
        let mut eval = self
            .inner
            .evaluate_certificate(certificate_id, subject, not_before, not_after, now)?;
        // Enforce Certificate Transparency
        if !eval.certificate_transparency_logged {
            eval.issues
                .push(TlsCertificateIssue::NoCertificateTransparency);
        }
        Ok(eval)
    }

    fn is_version_compliant(&self, tls_version: &str) -> bool {
        tls_version == "TLS 1.3"
    }

    fn is_cipher_compliant(&self, cipher_suite: &str) -> bool {
        self.inner.is_cipher_compliant(cipher_suite)
    }

    fn enforcer_id(&self) -> &str {
        self.inner.enforcer_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullTlsPolicyEnforcer ──────────────────────────────────────────

pub struct NullTlsPolicyEnforcer;

impl TlsPolicyEnforcer for NullTlsPolicyEnforcer {
    fn evaluate_connection(
        &self,
        connection_id: &str,
        tls_version: &str,
        cipher_suite: &str,
        _has_client_cert: bool,
    ) -> Result<TlsPolicyEvaluation, NetworkError> {
        Ok(TlsPolicyEvaluation {
            connection_id: connection_id.into(),
            tls_version: tls_version.into(),
            cipher_suite: cipher_suite.into(),
            decision: TlsPolicyDecision::Compliant,
            justification: "Null enforcer — no TLS policy enforcement".into(),
            evaluated_at: 0,
        })
    }

    fn evaluate_certificate(
        &self,
        certificate_id: &str,
        subject: &str,
        _not_before: i64,
        _not_after: i64,
        now: i64,
    ) -> Result<CertificateEvaluation, NetworkError> {
        Ok(CertificateEvaluation {
            certificate_id: certificate_id.into(),
            subject: subject.into(),
            issues: Vec::new(),
            expiration_status: CertificateExpirationStatus::Valid,
            certificate_transparency_logged: true,
            evaluated_at: now,
        })
    }

    fn is_version_compliant(&self, _tls_version: &str) -> bool {
        true
    }

    fn is_cipher_compliant(&self, _cipher_suite: &str) -> bool {
        true
    }

    fn enforcer_id(&self) -> &str {
        "null-tls-policy-enforcer"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_compliant_connection() {
        let enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        let eval = enforcer
            .evaluate_connection("c1", "TLS 1.3", "AES_256_GCM", false)
            .unwrap();
        assert_eq!(eval.decision, TlsPolicyDecision::Compliant);
    }

    #[test]
    fn test_in_memory_version_too_low() {
        let enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.3");
        let eval = enforcer
            .evaluate_connection("c1", "TLS 1.2", "AES_256_GCM", false)
            .unwrap();
        assert_eq!(eval.decision, TlsPolicyDecision::RequiresUpgrade);
    }

    #[test]
    fn test_in_memory_denied_cipher() {
        let mut enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        enforcer.add_denied_cipher("RC4_SHA");
        let eval = enforcer
            .evaluate_connection("c1", "TLS 1.3", "RC4_SHA", false)
            .unwrap();
        assert_eq!(eval.decision, TlsPolicyDecision::NonCompliant);
    }

    #[test]
    fn test_in_memory_requires_client_cert() {
        let mut enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        enforcer.set_require_client_cert(true);
        let eval = enforcer
            .evaluate_connection("c1", "TLS 1.3", "AES_256_GCM", false)
            .unwrap();
        assert_eq!(eval.decision, TlsPolicyDecision::ConnectionRejected);
        let eval2 = enforcer
            .evaluate_connection("c1", "TLS 1.3", "AES_256_GCM", true)
            .unwrap();
        assert_eq!(eval2.decision, TlsPolicyDecision::Compliant);
    }

    #[test]
    fn test_in_memory_certificate_valid() {
        let enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        let eval = enforcer
            .evaluate_certificate("cert-1", "CN=test", 1000, 10_000_000_000, 50_000)
            .unwrap();
        assert_eq!(eval.expiration_status, CertificateExpirationStatus::Valid);
        assert!(eval.issues.is_empty());
    }

    #[test]
    fn test_in_memory_certificate_expired() {
        let enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        let eval = enforcer
            .evaluate_certificate("cert-1", "CN=test", 1000, 50_000, 100_000)
            .unwrap();
        assert_eq!(
            eval.expiration_status,
            CertificateExpirationStatus::Expired
        );
        assert!(eval.issues.contains(&TlsCertificateIssue::Expired));
    }

    #[test]
    fn test_in_memory_certificate_expiring_soon() {
        let enforcer = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        let now = 100_000;
        let not_after = now + 10 * 86_400_000; // 10 days
        let eval = enforcer
            .evaluate_certificate("cert-1", "CN=test", 1000, not_after, now)
            .unwrap();
        assert_eq!(
            eval.expiration_status,
            CertificateExpirationStatus::ExpiringSoon
        );
    }

    #[test]
    fn test_strict_wrapper_enforces_tls13() {
        let inner = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        let strict = StrictTlsPolicyEnforcer::new(inner);
        let eval = strict
            .evaluate_connection("c1", "TLS 1.2", "AES_256_GCM", false)
            .unwrap();
        assert_eq!(eval.decision, TlsPolicyDecision::RequiresUpgrade);
        let eval2 = strict
            .evaluate_connection("c1", "TLS 1.3", "AES_256_GCM", false)
            .unwrap();
        assert_eq!(eval2.decision, TlsPolicyDecision::Compliant);
    }

    #[test]
    fn test_strict_wrapper_version_compliant() {
        let inner = InMemoryTlsPolicyEnforcer::new("e1", "TLS 1.2");
        let strict = StrictTlsPolicyEnforcer::new(inner);
        assert!(strict.is_version_compliant("TLS 1.3"));
        assert!(!strict.is_version_compliant("TLS 1.2"));
    }

    #[test]
    fn test_null_enforcer() {
        let enforcer = NullTlsPolicyEnforcer;
        assert!(!enforcer.is_active());
        assert_eq!(enforcer.enforcer_id(), "null-tls-policy-enforcer");
        let eval = enforcer
            .evaluate_connection("c1", "TLS 1.0", "RC4_SHA", false)
            .unwrap();
        assert_eq!(eval.decision, TlsPolicyDecision::Compliant);
        assert!(enforcer.is_version_compliant("TLS 1.0"));
        assert!(enforcer.is_cipher_compliant("anything"));
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            TlsPolicyDecision::Compliant,
            TlsPolicyDecision::NonCompliant,
            TlsPolicyDecision::RequiresUpgrade,
            TlsPolicyDecision::CertificateIssueDetected,
            TlsPolicyDecision::ConnectionRejected,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 5);
    }

    #[test]
    fn test_certificate_issue_display() {
        let issues = vec![
            TlsCertificateIssue::Expired,
            TlsCertificateIssue::NotYetValid,
            TlsCertificateIssue::WeakKeySize,
            TlsCertificateIssue::WeakAlgorithm,
            TlsCertificateIssue::MissingSan,
            TlsCertificateIssue::SelfSigned,
            TlsCertificateIssue::NoCertificateTransparency,
            TlsCertificateIssue::OcspStaplingMissing,
        ];
        for i in &issues {
            assert!(!i.to_string().is_empty());
        }
        assert_eq!(issues.len(), 8);
    }

    #[test]
    fn test_enforcer_id() {
        let enforcer = InMemoryTlsPolicyEnforcer::new("my-enforcer", "TLS 1.2");
        assert_eq!(enforcer.enforcer_id(), "my-enforcer");
        assert!(enforcer.is_active());
    }
}
