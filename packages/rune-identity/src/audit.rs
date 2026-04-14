// ═══════════════════════════════════════════════════════════════════════
// Identity Audit — Event Logging
//
// Records identity lifecycle events: creation, authentication,
// credential changes, session activity, and security incidents.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::authn::AuthnFailureReason;
use crate::identity::IdentityId;

// ── IdentityEventType ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityEventType {
    IdentityCreated,
    IdentityUpdated,
    IdentitySuspended,
    IdentityLocked,
    IdentityReactivated,
    IdentityRevoked,
    AuthenticationSuccess,
    AuthenticationFailed { reason: AuthnFailureReason },
    CredentialCreated { credential_type: String },
    CredentialRevoked,
    CredentialCompromised,
    SessionCreated,
    SessionRevoked,
    SessionExpired,
    MfaVerified,
    MfaFailed,
    TrustScoreChanged { old_score: f64, new_score: f64 },
    AttestationAdded { attestation_type: String },
    ClaimIssued { claim_type: String },
    // Layer 2
    CredentialHashed,
    CredentialVerified,
    CredentialStrengthChecked,
    CredentialRotated,
    SessionTokenHashed,
    SessionFingerprintCreated,
    SessionFingerprintMismatch,
    TrustScoreAdjusted { reason: String, delta: f64 },
    TrustDecayApplied { old_score: f64, new_score: f64 },
    AttestationChainVerified { valid: bool, links: usize },
    TotpVerified,
    BackupCodeUsed,
    FederatedIdentityLinked { provider: String },
    FederatedIdentityUnlinked { provider: String },
    MfaPolicyEnforced { operation: String },
}

impl IdentityEventType {
    pub fn is_security_event(&self) -> bool {
        matches!(
            self,
            Self::IdentityLocked
                | Self::IdentityRevoked
                | Self::AuthenticationFailed { .. }
                | Self::CredentialCompromised
                | Self::MfaFailed
                | Self::SessionFingerprintMismatch
                | Self::TrustDecayApplied { .. }
        )
    }
}

impl fmt::Display for IdentityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityCreated => write!(f, "IdentityCreated"),
            Self::IdentityUpdated => write!(f, "IdentityUpdated"),
            Self::IdentitySuspended => write!(f, "IdentitySuspended"),
            Self::IdentityLocked => write!(f, "IdentityLocked"),
            Self::IdentityReactivated => write!(f, "IdentityReactivated"),
            Self::IdentityRevoked => write!(f, "IdentityRevoked"),
            Self::AuthenticationSuccess => write!(f, "AuthenticationSuccess"),
            Self::AuthenticationFailed { reason } => write!(f, "AuthenticationFailed({reason})"),
            Self::CredentialCreated { credential_type } => write!(f, "CredentialCreated({credential_type})"),
            Self::CredentialRevoked => write!(f, "CredentialRevoked"),
            Self::CredentialCompromised => write!(f, "CredentialCompromised"),
            Self::SessionCreated => write!(f, "SessionCreated"),
            Self::SessionRevoked => write!(f, "SessionRevoked"),
            Self::SessionExpired => write!(f, "SessionExpired"),
            Self::MfaVerified => write!(f, "MfaVerified"),
            Self::MfaFailed => write!(f, "MfaFailed"),
            Self::TrustScoreChanged { old_score, new_score } => {
                write!(f, "TrustScoreChanged({old_score:.2}→{new_score:.2})")
            }
            Self::AttestationAdded { attestation_type } => write!(f, "AttestationAdded({attestation_type})"),
            Self::ClaimIssued { claim_type } => write!(f, "ClaimIssued({claim_type})"),
            Self::CredentialHashed => write!(f, "CredentialHashed"),
            Self::CredentialVerified => write!(f, "CredentialVerified"),
            Self::CredentialStrengthChecked => write!(f, "CredentialStrengthChecked"),
            Self::CredentialRotated => write!(f, "CredentialRotated"),
            Self::SessionTokenHashed => write!(f, "SessionTokenHashed"),
            Self::SessionFingerprintCreated => write!(f, "SessionFingerprintCreated"),
            Self::SessionFingerprintMismatch => write!(f, "SessionFingerprintMismatch"),
            Self::TrustScoreAdjusted { reason, delta } => {
                write!(f, "TrustScoreAdjusted({reason}, {delta:+.2})")
            }
            Self::TrustDecayApplied { old_score, new_score } => {
                write!(f, "TrustDecayApplied({old_score:.2}->{new_score:.2})")
            }
            Self::AttestationChainVerified { valid, links } => {
                write!(f, "AttestationChainVerified(valid={valid}, links={links})")
            }
            Self::TotpVerified => write!(f, "TotpVerified"),
            Self::BackupCodeUsed => write!(f, "BackupCodeUsed"),
            Self::FederatedIdentityLinked { provider } => {
                write!(f, "FederatedIdentityLinked({provider})")
            }
            Self::FederatedIdentityUnlinked { provider } => {
                write!(f, "FederatedIdentityUnlinked({provider})")
            }
            Self::MfaPolicyEnforced { operation } => {
                write!(f, "MfaPolicyEnforced({operation})")
            }
        }
    }
}

// ── IdentityAuditEvent ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAuditEvent {
    pub event_type: IdentityEventType,
    pub identity_id: IdentityId,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
    pub source_ip: Option<String>,
    pub success: bool,
}

impl IdentityAuditEvent {
    pub fn new(
        event_type: IdentityEventType,
        identity_id: IdentityId,
        timestamp: i64,
        actor: impl Into<String>,
        detail: impl Into<String>,
        success: bool,
    ) -> Self {
        Self {
            event_type,
            identity_id,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
            source_ip: None,
            success,
        }
    }

    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }
}

impl fmt::Display for IdentityAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "[{}] {} {} by {}: {}",
            self.timestamp, self.event_type, self.identity_id, self.actor, self.detail
        )
    }
}

// ── IdentityAuditLog ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct IdentityAuditLog {
    events: Vec<IdentityAuditEvent>,
}

impl IdentityAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: IdentityAuditEvent) {
        self.events.push(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn all(&self) -> &[IdentityAuditEvent] {
        &self.events
    }

    pub fn events_for_identity(&self, id: &IdentityId) -> Vec<&IdentityAuditEvent> {
        self.events.iter().filter(|e| &e.identity_id == id).collect()
    }

    pub fn events_by_type(&self, event_type_name: &str) -> Vec<&IdentityAuditEvent> {
        self.events.iter()
            .filter(|e| e.event_type.to_string().starts_with(event_type_name))
            .collect()
    }

    pub fn failed_authentications(&self, id: &IdentityId) -> Vec<&IdentityAuditEvent> {
        self.events.iter()
            .filter(|e| &e.identity_id == id && matches!(e.event_type, IdentityEventType::AuthenticationFailed { .. }))
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&IdentityAuditEvent> {
        self.events.iter().filter(|e| e.timestamp >= timestamp).collect()
    }

    pub fn security_events(&self) -> Vec<&IdentityAuditEvent> {
        self.events.iter().filter(|e| e.event_type.is_security_event()).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(etype: IdentityEventType, id: &str, ts: i64, success: bool) -> IdentityAuditEvent {
        IdentityAuditEvent::new(etype, IdentityId::new(id), ts, "admin", "test", success)
    }

    #[test]
    fn test_audit_log_record_and_retrieve() {
        let mut log = IdentityAuditLog::new();
        log.record(make_event(IdentityEventType::IdentityCreated, "user:alice", 1000, true));
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_audit_log_events_for_identity() {
        let mut log = IdentityAuditLog::new();
        log.record(make_event(IdentityEventType::IdentityCreated, "user:alice", 1000, true));
        log.record(make_event(IdentityEventType::AuthenticationSuccess, "user:alice", 2000, true));
        log.record(make_event(IdentityEventType::IdentityCreated, "user:bob", 1500, true));
        assert_eq!(log.events_for_identity(&IdentityId::new("user:alice")).len(), 2);
    }

    #[test]
    fn test_audit_log_failed_authentications() {
        let mut log = IdentityAuditLog::new();
        log.record(make_event(IdentityEventType::AuthenticationSuccess, "user:alice", 1000, true));
        log.record(make_event(
            IdentityEventType::AuthenticationFailed { reason: AuthnFailureReason::InvalidCredentials },
            "user:alice", 2000, false,
        ));
        log.record(make_event(
            IdentityEventType::AuthenticationFailed { reason: AuthnFailureReason::RateLimited },
            "user:alice", 3000, false,
        ));
        assert_eq!(log.failed_authentications(&IdentityId::new("user:alice")).len(), 2);
    }

    #[test]
    fn test_audit_log_security_events() {
        let mut log = IdentityAuditLog::new();
        log.record(make_event(IdentityEventType::IdentityCreated, "user:alice", 1000, true));
        log.record(make_event(IdentityEventType::IdentityLocked, "user:alice", 2000, true));
        log.record(make_event(IdentityEventType::CredentialCompromised, "user:alice", 3000, true));
        log.record(make_event(
            IdentityEventType::AuthenticationFailed { reason: AuthnFailureReason::InvalidCredentials },
            "user:alice", 4000, false,
        ));
        assert_eq!(log.security_events().len(), 3);
    }

    #[test]
    fn test_audit_log_since() {
        let mut log = IdentityAuditLog::new();
        log.record(make_event(IdentityEventType::IdentityCreated, "user:alice", 1000, true));
        log.record(make_event(IdentityEventType::AuthenticationSuccess, "user:alice", 2000, true));
        assert_eq!(log.since(1500).len(), 1);
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(IdentityEventType::IdentityCreated.to_string(), "IdentityCreated");
        assert_eq!(IdentityEventType::AuthenticationSuccess.to_string(), "AuthenticationSuccess");
        let failed = IdentityEventType::AuthenticationFailed {
            reason: AuthnFailureReason::InvalidCredentials,
        };
        assert!(failed.to_string().contains("invalid credentials"));
    }

    #[test]
    fn test_audit_event_display() {
        let event = make_event(IdentityEventType::IdentityCreated, "user:alice", 1000, true);
        let s = event.to_string();
        assert!(s.contains("1000"));
        assert!(s.contains("IdentityCreated"));
        assert!(s.contains("user:alice"));
    }

    // ── Part 7: Audit Enhancement Tests ──────────────────────────────

    #[test]
    fn test_layer2_event_types_display() {
        let events: Vec<IdentityEventType> = vec![
            IdentityEventType::CredentialHashed,
            IdentityEventType::CredentialVerified,
            IdentityEventType::CredentialStrengthChecked,
            IdentityEventType::CredentialRotated,
            IdentityEventType::SessionTokenHashed,
            IdentityEventType::SessionFingerprintCreated,
            IdentityEventType::SessionFingerprintMismatch,
            IdentityEventType::TrustScoreAdjusted { reason: "mfa".into(), delta: 0.15 },
            IdentityEventType::TrustDecayApplied { old_score: 0.8, new_score: 0.6 },
            IdentityEventType::AttestationChainVerified { valid: true, links: 3 },
            IdentityEventType::TotpVerified,
            IdentityEventType::BackupCodeUsed,
            IdentityEventType::FederatedIdentityLinked { provider: "okta".into() },
            IdentityEventType::FederatedIdentityUnlinked { provider: "okta".into() },
            IdentityEventType::MfaPolicyEnforced { operation: "admin".into() },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(events.len(), 15); // 15 new Layer 2 variants
    }

    #[test]
    fn test_layer2_security_events() {
        assert!(IdentityEventType::SessionFingerprintMismatch.is_security_event());
        assert!(IdentityEventType::TrustDecayApplied { old_score: 0.8, new_score: 0.5 }.is_security_event());
        assert!(!IdentityEventType::CredentialHashed.is_security_event());
        assert!(!IdentityEventType::TotpVerified.is_security_event());
    }
}
