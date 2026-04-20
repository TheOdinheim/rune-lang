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
    // Layer 3
    IdentityBackendChanged { backend_type: String },
    IdentityPersisted,
    IdentityQueried,
    IdentityExported { format: String },
    IdentityExportFailed { format: String, reason: String },
    CredentialStoreChanged { store_type: String },
    PasswordHashStored,
    PasswordHashUpdated,
    TotpSecretEnrolled,
    WebAuthnKeyEnrolled,
    RecoveryCodesGenerated { count: usize },
    RecoveryCodeConsumedEvent,
    AuthenticatorInvoked { authenticator_id: String },
    AuthenticationOutcomeRecorded { outcome: String },
    JwtSigned { algorithm: String },
    JwtSignatureVerified,
    JwtSignatureRejected { reason: String },
    FederationFlowStarted { provider_id: String },
    FederationFlowCompleted { provider_id: String },
    FederationFlowFailed { provider_id: String, reason: String },
    IdentitySubscriberRegistered { subscriber_id: String },
    IdentitySubscriberRemoved { subscriber_id: String },
    IdentityEventPublished { event_type: String },
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
                | Self::JwtSignatureRejected { .. }
                | Self::FederationFlowFailed { .. }
                | Self::IdentityExportFailed { .. }
        )
    }

    pub fn is_credential_event(&self) -> bool {
        matches!(
            self,
            Self::CredentialStoreChanged { .. }
                | Self::PasswordHashStored
                | Self::PasswordHashUpdated
                | Self::TotpSecretEnrolled
                | Self::WebAuthnKeyEnrolled
                | Self::RecoveryCodesGenerated { .. }
                | Self::RecoveryCodeConsumedEvent
        )
    }

    pub fn is_authentication_event(&self) -> bool {
        matches!(
            self,
            Self::AuthenticatorInvoked { .. }
                | Self::AuthenticationOutcomeRecorded { .. }
                | Self::JwtSigned { .. }
                | Self::JwtSignatureVerified
                | Self::JwtSignatureRejected { .. }
        )
    }

    pub fn is_federation_event(&self) -> bool {
        matches!(
            self,
            Self::FederationFlowStarted { .. }
                | Self::FederationFlowCompleted { .. }
                | Self::FederationFlowFailed { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::IdentityExported { .. }
                | Self::IdentityExportFailed { .. }
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
            Self::IdentityBackendChanged { backend_type } => {
                write!(f, "IdentityBackendChanged({backend_type})")
            }
            Self::IdentityPersisted => write!(f, "IdentityPersisted"),
            Self::IdentityQueried => write!(f, "IdentityQueried"),
            Self::IdentityExported { format } => write!(f, "IdentityExported({format})"),
            Self::IdentityExportFailed { format, reason } => {
                write!(f, "IdentityExportFailed({format}: {reason})")
            }
            Self::CredentialStoreChanged { store_type } => {
                write!(f, "CredentialStoreChanged({store_type})")
            }
            Self::PasswordHashStored => write!(f, "PasswordHashStored"),
            Self::PasswordHashUpdated => write!(f, "PasswordHashUpdated"),
            Self::TotpSecretEnrolled => write!(f, "TotpSecretEnrolled"),
            Self::WebAuthnKeyEnrolled => write!(f, "WebAuthnKeyEnrolled"),
            Self::RecoveryCodesGenerated { count } => {
                write!(f, "RecoveryCodesGenerated({count})")
            }
            Self::RecoveryCodeConsumedEvent => write!(f, "RecoveryCodeConsumedEvent"),
            Self::AuthenticatorInvoked { authenticator_id } => {
                write!(f, "AuthenticatorInvoked({authenticator_id})")
            }
            Self::AuthenticationOutcomeRecorded { outcome } => {
                write!(f, "AuthenticationOutcomeRecorded({outcome})")
            }
            Self::JwtSigned { algorithm } => write!(f, "JwtSigned({algorithm})"),
            Self::JwtSignatureVerified => write!(f, "JwtSignatureVerified"),
            Self::JwtSignatureRejected { reason } => {
                write!(f, "JwtSignatureRejected({reason})")
            }
            Self::FederationFlowStarted { provider_id } => {
                write!(f, "FederationFlowStarted({provider_id})")
            }
            Self::FederationFlowCompleted { provider_id } => {
                write!(f, "FederationFlowCompleted({provider_id})")
            }
            Self::FederationFlowFailed { provider_id, reason } => {
                write!(f, "FederationFlowFailed({provider_id}: {reason})")
            }
            Self::IdentitySubscriberRegistered { subscriber_id } => {
                write!(f, "IdentitySubscriberRegistered({subscriber_id})")
            }
            Self::IdentitySubscriberRemoved { subscriber_id } => {
                write!(f, "IdentitySubscriberRemoved({subscriber_id})")
            }
            Self::IdentityEventPublished { event_type } => {
                write!(f, "IdentityEventPublished({event_type})")
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

    // ── Layer 3: Audit Enhancement Tests ─────────────────────────────

    #[test]
    fn test_layer3_event_types_display() {
        let events: Vec<IdentityEventType> = vec![
            IdentityEventType::IdentityBackendChanged { backend_type: "postgres".into() },
            IdentityEventType::IdentityPersisted,
            IdentityEventType::IdentityQueried,
            IdentityEventType::IdentityExported { format: "SCIM".into() },
            IdentityEventType::IdentityExportFailed { format: "LDIF".into(), reason: "io".into() },
            IdentityEventType::CredentialStoreChanged { store_type: "vault".into() },
            IdentityEventType::PasswordHashStored,
            IdentityEventType::PasswordHashUpdated,
            IdentityEventType::TotpSecretEnrolled,
            IdentityEventType::WebAuthnKeyEnrolled,
            IdentityEventType::RecoveryCodesGenerated { count: 10 },
            IdentityEventType::RecoveryCodeConsumedEvent,
            IdentityEventType::AuthenticatorInvoked { authenticator_id: "pwd-1".into() },
            IdentityEventType::AuthenticationOutcomeRecorded { outcome: "success".into() },
            IdentityEventType::JwtSigned { algorithm: "HS256".into() },
            IdentityEventType::JwtSignatureVerified,
            IdentityEventType::JwtSignatureRejected { reason: "expired".into() },
            IdentityEventType::FederationFlowStarted { provider_id: "oidc-1".into() },
            IdentityEventType::FederationFlowCompleted { provider_id: "oidc-1".into() },
            IdentityEventType::FederationFlowFailed { provider_id: "saml-1".into(), reason: "timeout".into() },
            IdentityEventType::IdentitySubscriberRegistered { subscriber_id: "sub-1".into() },
            IdentityEventType::IdentitySubscriberRemoved { subscriber_id: "sub-1".into() },
            IdentityEventType::IdentityEventPublished { event_type: "Created".into() },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(events.len(), 23);
    }

    #[test]
    fn test_layer3_security_events() {
        assert!(IdentityEventType::JwtSignatureRejected { reason: "tampered".into() }.is_security_event());
        assert!(IdentityEventType::FederationFlowFailed { provider_id: "x".into(), reason: "y".into() }.is_security_event());
        assert!(IdentityEventType::IdentityExportFailed { format: "x".into(), reason: "y".into() }.is_security_event());
        assert!(!IdentityEventType::PasswordHashStored.is_security_event());
        assert!(!IdentityEventType::JwtSignatureVerified.is_security_event());
    }

    #[test]
    fn test_credential_event_classification() {
        assert!(IdentityEventType::PasswordHashStored.is_credential_event());
        assert!(IdentityEventType::TotpSecretEnrolled.is_credential_event());
        assert!(IdentityEventType::WebAuthnKeyEnrolled.is_credential_event());
        assert!(IdentityEventType::RecoveryCodesGenerated { count: 8 }.is_credential_event());
        assert!(IdentityEventType::RecoveryCodeConsumedEvent.is_credential_event());
        assert!(!IdentityEventType::JwtSigned { algorithm: "x".into() }.is_credential_event());
    }

    #[test]
    fn test_authentication_event_classification() {
        assert!(IdentityEventType::AuthenticatorInvoked { authenticator_id: "x".into() }.is_authentication_event());
        assert!(IdentityEventType::JwtSigned { algorithm: "HS256".into() }.is_authentication_event());
        assert!(IdentityEventType::JwtSignatureVerified.is_authentication_event());
        assert!(IdentityEventType::JwtSignatureRejected { reason: "x".into() }.is_authentication_event());
        assert!(!IdentityEventType::PasswordHashStored.is_authentication_event());
    }

    #[test]
    fn test_federation_event_classification() {
        assert!(IdentityEventType::FederationFlowStarted { provider_id: "x".into() }.is_federation_event());
        assert!(IdentityEventType::FederationFlowCompleted { provider_id: "x".into() }.is_federation_event());
        assert!(IdentityEventType::FederationFlowFailed { provider_id: "x".into(), reason: "y".into() }.is_federation_event());
        assert!(!IdentityEventType::JwtSigned { algorithm: "x".into() }.is_federation_event());
    }

    #[test]
    fn test_export_event_classification() {
        assert!(IdentityEventType::IdentityExported { format: "SCIM".into() }.is_export_event());
        assert!(IdentityEventType::IdentityExportFailed { format: "x".into(), reason: "y".into() }.is_export_event());
        assert!(!IdentityEventType::IdentityPersisted.is_export_event());
    }
}
