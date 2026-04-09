// ═══════════════════════════════════════════════════════════════════════
// Authentication — Identity Verification
//
// Verifies that an entity is who they claim to be.
// Supports password, API key, token, certificate, and MFA methods.
// Includes rate limiting and lockout protection.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_lang::stdlib::crypto::hash::sha3_256;
use rune_secrets::derivation::verify_password;
use serde::{Deserialize, Serialize};

use crate::credential::{CredentialId, CredentialStatus, CredentialStore, CredentialType};
use crate::identity::{IdentityId, IdentityStatus, IdentityStore};

// ── AuthnMethod ───────────────────────────────────────────────────────

#[derive(Clone)]
pub enum AuthnMethod {
    Password { password_bytes: Vec<u8> },
    ApiKey { key: String },
    BearerToken { token: String },
    Certificate { fingerprint: String },
    Mfa { code: String, method: MfaMethod },
}

impl fmt::Display for AuthnMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password { .. } => write!(f, "Password"),
            Self::ApiKey { .. } => write!(f, "ApiKey"),
            Self::BearerToken { .. } => write!(f, "BearerToken"),
            Self::Certificate { .. } => write!(f, "Certificate"),
            Self::Mfa { method, .. } => write!(f, "MFA({method})"),
        }
    }
}

impl fmt::Debug for AuthnMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password { .. } => write!(f, "Password([REDACTED])"),
            Self::ApiKey { .. } => write!(f, "ApiKey([REDACTED])"),
            Self::BearerToken { .. } => write!(f, "BearerToken([REDACTED])"),
            Self::Certificate { fingerprint } => write!(f, "Certificate({fingerprint})"),
            Self::Mfa { method, .. } => write!(f, "Mfa({method:?}, [REDACTED])"),
        }
    }
}

// ── MfaMethod ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
    WebAuthn,
    Recovery,
}

impl fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AuthnRequest ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuthnRequest {
    pub identity_id: IdentityId,
    pub method: AuthnMethod,
    pub timestamp: i64,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,
}

impl AuthnRequest {
    pub fn new(identity_id: IdentityId, method: AuthnMethod, timestamp: i64) -> Self {
        Self {
            identity_id,
            method,
            timestamp,
            source_ip: None,
            user_agent: None,
            device_id: None,
        }
    }

    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }
}

// ── AuthnResult ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AuthnResult {
    Success {
        identity_id: IdentityId,
        credential_id: CredentialId,
        authenticated_at: i64,
        trust_score: f64,
    },
    Failure {
        identity_id: IdentityId,
        reason: AuthnFailureReason,
        attempted_at: i64,
    },
    MfaRequired {
        identity_id: IdentityId,
        methods_available: Vec<MfaMethod>,
    },
}

impl AuthnResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failure { .. })
    }

    pub fn requires_mfa(&self) -> bool {
        matches!(self, Self::MfaRequired { .. })
    }

    pub fn trust_score(&self) -> Option<f64> {
        match self {
            Self::Success { trust_score, .. } => Some(*trust_score),
            _ => None,
        }
    }
}

// ── AuthnFailureReason ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthnFailureReason {
    InvalidCredentials,
    CredentialExpired,
    CredentialRevoked,
    CredentialCompromised,
    IdentityNotFound,
    IdentitySuspended,
    IdentityLocked,
    IdentityRevoked,
    MfaFailed,
    RateLimited,
    IpNotAllowed,
}

impl fmt::Display for AuthnFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => write!(f, "invalid credentials"),
            Self::CredentialExpired => write!(f, "credential expired"),
            Self::CredentialRevoked => write!(f, "credential revoked"),
            Self::CredentialCompromised => write!(f, "credential compromised"),
            Self::IdentityNotFound => write!(f, "identity not found"),
            Self::IdentitySuspended => write!(f, "identity suspended"),
            Self::IdentityLocked => write!(f, "identity locked"),
            Self::IdentityRevoked => write!(f, "identity revoked"),
            Self::MfaFailed => write!(f, "MFA verification failed"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::IpNotAllowed => write!(f, "IP not allowed"),
        }
    }
}

// ── Authenticator ─────────────────────────────────────────────────────

pub struct Authenticator {
    pub identity_store: IdentityStore,
    pub credential_store: CredentialStore,
    failed_attempts: HashMap<IdentityId, Vec<i64>>,
    pub lockout_threshold: u32,
    pub lockout_window_ms: i64,
    pub rate_limit_per_minute: u32,
}

impl Authenticator {
    pub fn new(identity_store: IdentityStore, credential_store: CredentialStore) -> Self {
        Self {
            identity_store,
            credential_store,
            failed_attempts: HashMap::new(),
            lockout_threshold: 5,
            lockout_window_ms: 15 * 60 * 1000, // 15 minutes
            rate_limit_per_minute: 10,
        }
    }

    pub fn authenticate(&mut self, request: &AuthnRequest) -> AuthnResult {
        let now = request.timestamp;

        // 1. Look up identity
        let identity = match self.identity_store.get(&request.identity_id) {
            Some(id) => id,
            None => return self.record_failure(
                &request.identity_id, AuthnFailureReason::IdentityNotFound, now
            ),
        };

        // 2. Check identity status
        match &identity.status {
            IdentityStatus::Suspended => return self.record_failure(
                &request.identity_id, AuthnFailureReason::IdentitySuspended, now
            ),
            IdentityStatus::Locked => return self.record_failure(
                &request.identity_id, AuthnFailureReason::IdentityLocked, now
            ),
            IdentityStatus::Revoked => return self.record_failure(
                &request.identity_id, AuthnFailureReason::IdentityRevoked, now
            ),
            _ => {}
        }

        // 3. Check rate limit
        if self.is_rate_limited(&request.identity_id, now) {
            return self.record_failure(
                &request.identity_id, AuthnFailureReason::RateLimited, now
            );
        }

        // 4. Check lockout
        if self.is_locked_out(&request.identity_id, now) {
            return self.record_failure(
                &request.identity_id, AuthnFailureReason::IdentityLocked, now
            );
        }

        // 5. Check IP allowlist for services
        if let crate::identity_type::IdentityType::Service { ip_allowlist, .. } = &identity.identity_type {
            if !ip_allowlist.is_empty() {
                if let Some(source_ip) = &request.source_ip {
                    if !ip_allowlist.contains(source_ip) {
                        return self.record_failure(
                            &request.identity_id, AuthnFailureReason::IpNotAllowed, now
                        );
                    }
                }
            }
        }

        // 6. Find matching credential and verify
        let mfa_required = identity.identity_type.requires_mfa();
        let active_creds = self.credential_store.active_credentials(&request.identity_id);

        let matched_cred = match &request.method {
            AuthnMethod::Password { password_bytes } => {
                active_creds.iter().find(|c| {
                    if let CredentialType::Password { hash, salt, .. } = &c.credential_type {
                        Self::verify_password_hash(hash, salt, password_bytes)
                    } else {
                        false
                    }
                }).map(|c| c.id.clone())
            }
            AuthnMethod::ApiKey { key } => {
                active_creds.iter().find(|c| {
                    if let CredentialType::ApiKey { key_hash, .. } = &c.credential_type {
                        Self::verify_api_key_hash(key_hash, key)
                    } else {
                        false
                    }
                }).map(|c| c.id.clone())
            }
            AuthnMethod::BearerToken { token } => {
                active_creds.iter().find(|c| {
                    if let CredentialType::Token { token_hash, .. } = &c.credential_type {
                        Self::verify_token_hash(token_hash, token)
                    } else {
                        false
                    }
                }).map(|c| c.id.clone())
            }
            AuthnMethod::Certificate { fingerprint } => {
                active_creds.iter().find(|c| {
                    if let CredentialType::Certificate { fingerprint: fp, .. } = &c.credential_type {
                        fp == fingerprint
                    } else {
                        false
                    }
                }).map(|c| c.id.clone())
            }
            AuthnMethod::Mfa { .. } => {
                // MFA alone is not primary authentication
                return self.record_failure(
                    &request.identity_id, AuthnFailureReason::InvalidCredentials, now
                );
            }
        };

        let credential_id = match matched_cred {
            Some(id) => id,
            None => return self.record_failure(
                &request.identity_id, AuthnFailureReason::InvalidCredentials, now
            ),
        };

        // 7. Check credential status (expiry, revoked, etc.)
        if let Some(cred) = self.credential_store.get_credential(&credential_id) {
            if cred.is_expired(now) {
                return self.record_failure(
                    &request.identity_id, AuthnFailureReason::CredentialExpired, now
                );
            }
            match &cred.status {
                CredentialStatus::Revoked { .. } => return self.record_failure(
                    &request.identity_id, AuthnFailureReason::CredentialRevoked, now
                ),
                CredentialStatus::Compromised { .. } => return self.record_failure(
                    &request.identity_id, AuthnFailureReason::CredentialCompromised, now
                ),
                _ => {}
            }
        }

        // 8. Check if MFA is required but not provided
        if mfa_required {
            if !matches!(request.method, AuthnMethod::Mfa { .. }) {
                return AuthnResult::MfaRequired {
                    identity_id: request.identity_id.clone(),
                    methods_available: vec![MfaMethod::Totp, MfaMethod::WebAuthn],
                };
            }
        }

        // 9. Record success
        self.clear_failed_attempts(&request.identity_id);
        let _ = self.credential_store.record_usage(&credential_id, now);
        if let Some(identity) = self.identity_store.get_mut(&request.identity_id) {
            identity.record_authentication(now);
        }

        // 10. Calculate trust score
        let trust_score = Self::initial_trust_score(&request.method);

        AuthnResult::Success {
            identity_id: request.identity_id.clone(),
            credential_id,
            authenticated_at: now,
            trust_score,
        }
    }

    fn record_failure(&mut self, id: &IdentityId, reason: AuthnFailureReason, now: i64) -> AuthnResult {
        self.failed_attempts.entry(id.clone()).or_default().push(now);

        // Check if we should lock out
        if self.failed_attempts_in_window(id, now) >= self.lockout_threshold as usize {
            if let Some(identity) = self.identity_store.get_mut(id) {
                let _ = identity.lock("too many failed attempts");
            }
        }

        AuthnResult::Failure {
            identity_id: id.clone(),
            reason,
            attempted_at: now,
        }
    }

    pub fn verify_password_hash(stored_hash: &[u8], stored_salt: &[u8], provided: &[u8]) -> bool {
        verify_password(provided, stored_salt, stored_hash).unwrap_or(false)
    }

    pub fn verify_api_key_hash(stored_hash: &[u8], provided: &str) -> bool {
        let computed = sha3_256(provided.as_bytes());
        constant_time_eq(&computed, stored_hash)
    }

    pub fn verify_token_hash(stored_hash: &[u8], provided: &str) -> bool {
        let computed = sha3_256(provided.as_bytes());
        constant_time_eq(&computed, stored_hash)
    }

    fn initial_trust_score(method: &AuthnMethod) -> f64 {
        match method {
            AuthnMethod::Password { .. } => 0.4,
            AuthnMethod::ApiKey { .. } => 0.5,
            AuthnMethod::BearerToken { .. } => 0.5,
            AuthnMethod::Certificate { .. } => 0.8,
            AuthnMethod::Mfa { .. } => 0.7,
        }
    }

    pub fn failed_attempts_count(&self, identity_id: &IdentityId) -> usize {
        self.failed_attempts.get(identity_id).map_or(0, |v| v.len())
    }

    fn failed_attempts_in_window(&self, identity_id: &IdentityId, now: i64) -> usize {
        self.failed_attempts.get(identity_id).map_or(0, |attempts| {
            attempts.iter().filter(|&&t| now - t < self.lockout_window_ms).count()
        })
    }

    pub fn clear_failed_attempts(&mut self, identity_id: &IdentityId) {
        self.failed_attempts.remove(identity_id);
    }

    pub fn is_locked_out(&self, identity_id: &IdentityId, now: i64) -> bool {
        self.failed_attempts_in_window(identity_id, now) >= self.lockout_threshold as usize
    }

    fn is_rate_limited(&self, identity_id: &IdentityId, now: i64) -> bool {
        let one_minute = 60_000;
        let recent = self.failed_attempts.get(identity_id).map_or(0, |attempts| {
            attempts.iter().filter(|&&t| now - t < one_minute).count()
        });
        recent >= self.rate_limit_per_minute as usize
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;
    use crate::identity::Identity;
    use crate::identity_type::IdentityType;
    use rune_permissions::ClassificationLevel;
    use rune_secrets::derivation::hash_password;

    fn setup_authenticator() -> Authenticator {
        let mut identity_store = IdentityStore::new();
        let mut credential_store = CredentialStore::new();

        // Create identity
        let alice = Identity::new(IdentityId::new("user:alice"), IdentityType::default_user())
            .display_name("Alice")
            .clearance(ClassificationLevel::Confidential)
            .created_at(1000)
            .build();
        identity_store.register(alice).unwrap();

        // Create password credential
        let salt = b"alice-salt";
        let hash = hash_password(b"correct-password", salt).unwrap();
        let cred = Credential::new(
            CredentialId::new("alice-password"),
            IdentityId::new("user:alice"),
            CredentialType::Password {
                hash,
                salt: salt.to_vec(),
                algorithm: "hkdf-placeholder".into(),
            },
            1000,
        );
        credential_store.add_credential(cred).unwrap();

        // Create API key credential
        let key_hash = sha3_256(b"sk_live_test_key_123").to_vec();
        let api_cred = Credential::new(
            CredentialId::new("alice-apikey"),
            IdentityId::new("user:alice"),
            CredentialType::ApiKey {
                key_hash,
                prefix: "sk_live_test".into(),
            },
            1000,
        );
        credential_store.add_credential(api_cred).unwrap();

        Authenticator::new(identity_store, credential_store)
    }

    #[test]
    fn test_authenticate_valid_password() {
        let mut auth = setup_authenticator();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"correct-password".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_success());
        assert!(result.trust_score().unwrap() > 0.0);
    }

    #[test]
    fn test_authenticate_wrong_password() {
        let mut auth = setup_authenticator();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"wrong-password".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_failure());
    }

    #[test]
    fn test_authenticate_valid_api_key() {
        let mut auth = setup_authenticator();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::ApiKey { key: "sk_live_test_key_123".into() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_success());
    }

    #[test]
    fn test_authenticate_wrong_api_key() {
        let mut auth = setup_authenticator();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::ApiKey { key: "sk_live_wrong_key".into() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_failure());
    }

    #[test]
    fn test_authenticate_identity_not_found() {
        let mut auth = setup_authenticator();
        let req = AuthnRequest::new(
            IdentityId::new("user:nobody"),
            AuthnMethod::Password { password_bytes: b"test".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_failure());
        if let AuthnResult::Failure { reason, .. } = result {
            assert_eq!(reason, AuthnFailureReason::IdentityNotFound);
        }
    }

    #[test]
    fn test_authenticate_suspended_identity() {
        let mut auth = setup_authenticator();
        auth.identity_store.get_mut(&IdentityId::new("user:alice")).unwrap()
            .suspend("test").unwrap();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"correct-password".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_failure());
        if let AuthnResult::Failure { reason, .. } = result {
            assert_eq!(reason, AuthnFailureReason::IdentitySuspended);
        }
    }

    #[test]
    fn test_authenticate_locked_identity() {
        let mut auth = setup_authenticator();
        auth.identity_store.get_mut(&IdentityId::new("user:alice")).unwrap()
            .lock("incident").unwrap();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"correct-password".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_failure());
    }

    #[test]
    fn test_authenticate_expired_credential() {
        let mut auth = setup_authenticator();
        // Add an expired credential
        let salt = b"exp-salt";
        let hash = hash_password(b"expired-pass", salt).unwrap();
        let cred = Credential::new(
            CredentialId::new("alice-expired"),
            IdentityId::new("user:alice"),
            CredentialType::Password {
                hash,
                salt: salt.to_vec(),
                algorithm: "hkdf".into(),
            },
            1000,
        ).with_expiry(1500);
        auth.credential_store.add_credential(cred).unwrap();
        // The expired credential won't be in active_credentials, so it won't match
        // The non-expired password credential will be checked instead
        // This tests that expired creds are filtered out
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"expired-pass".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        // The matching active cred has different password, so it should fail
        assert!(result.is_failure());
    }

    #[test]
    fn test_authenticate_mfa_required() {
        let mut auth = setup_authenticator();
        // Update alice to require MFA
        let alice_mfa = Identity::new(
            IdentityId::new("user:bob"),
            IdentityType::User {
                mfa_required: true,
                max_sessions: 5,
                password_policy: crate::identity_type::PasswordPolicy::default(),
            },
        )
            .display_name("Bob")
            .clearance(ClassificationLevel::Confidential)
            .created_at(1000)
            .build();
        auth.identity_store.register(alice_mfa).unwrap();

        let salt = b"bob-salt";
        let hash = hash_password(b"bob-pass", salt).unwrap();
        let cred = Credential::new(
            CredentialId::new("bob-password"),
            IdentityId::new("user:bob"),
            CredentialType::Password {
                hash,
                salt: salt.to_vec(),
                algorithm: "hkdf".into(),
            },
            1000,
        );
        auth.credential_store.add_credential(cred).unwrap();

        let req = AuthnRequest::new(
            IdentityId::new("user:bob"),
            AuthnMethod::Password { password_bytes: b"bob-pass".to_vec() },
            2000,
        );
        let result = auth.authenticate(&req);
        assert!(result.requires_mfa());
    }

    #[test]
    fn test_lockout_after_threshold() {
        let mut auth = setup_authenticator();
        auth.lockout_threshold = 3;

        for i in 0..3 {
            let req = AuthnRequest::new(
                IdentityId::new("user:alice"),
                AuthnMethod::Password { password_bytes: b"wrong".to_vec() },
                2000 + i,
            );
            auth.authenticate(&req);
        }

        assert!(auth.is_locked_out(&IdentityId::new("user:alice"), 2010));
    }

    #[test]
    fn test_rate_limiting() {
        let mut auth = setup_authenticator();
        auth.rate_limit_per_minute = 3;

        // Fill up rate limit window
        for i in 0..3 {
            let req = AuthnRequest::new(
                IdentityId::new("user:alice"),
                AuthnMethod::Password { password_bytes: b"wrong".to_vec() },
                2000 + i,
            );
            auth.authenticate(&req);
        }

        // Next attempt should be rate limited
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"correct-password".to_vec() },
            2003,
        );
        let result = auth.authenticate(&req);
        assert!(result.is_failure());
    }

    #[test]
    fn test_verify_password_correct() {
        let salt = b"test-salt";
        let hash = hash_password(b"my-password", salt).unwrap();
        assert!(Authenticator::verify_password_hash(&hash, salt, b"my-password"));
    }

    #[test]
    fn test_verify_password_wrong() {
        let salt = b"test-salt";
        let hash = hash_password(b"my-password", salt).unwrap();
        assert!(!Authenticator::verify_password_hash(&hash, salt, b"wrong-password"));
    }

    #[test]
    fn test_verify_api_key_correct() {
        let key_hash = sha3_256(b"my-api-key").to_vec();
        assert!(Authenticator::verify_api_key_hash(&key_hash, "my-api-key"));
    }

    #[test]
    fn test_verify_api_key_wrong() {
        let key_hash = sha3_256(b"my-api-key").to_vec();
        assert!(!Authenticator::verify_api_key_hash(&key_hash, "wrong-key"));
    }

    #[test]
    fn test_authn_result_methods() {
        let success = AuthnResult::Success {
            identity_id: IdentityId::new("user:x"),
            credential_id: CredentialId::new("c1"),
            authenticated_at: 1000,
            trust_score: 0.8,
        };
        assert!(success.is_success());
        assert!(!success.is_failure());
        assert!(!success.requires_mfa());

        let failure = AuthnResult::Failure {
            identity_id: IdentityId::new("user:x"),
            reason: AuthnFailureReason::InvalidCredentials,
            attempted_at: 1000,
        };
        assert!(!failure.is_success());
        assert!(failure.is_failure());

        let mfa = AuthnResult::MfaRequired {
            identity_id: IdentityId::new("user:x"),
            methods_available: vec![MfaMethod::Totp],
        };
        assert!(mfa.requires_mfa());
    }

    #[test]
    fn test_clear_failed_attempts() {
        let mut auth = setup_authenticator();
        let req = AuthnRequest::new(
            IdentityId::new("user:alice"),
            AuthnMethod::Password { password_bytes: b"wrong".to_vec() },
            2000,
        );
        auth.authenticate(&req);
        assert_eq!(auth.failed_attempts_count(&IdentityId::new("user:alice")), 1);
        auth.clear_failed_attempts(&IdentityId::new("user:alice"));
        assert_eq!(auth.failed_attempts_count(&IdentityId::new("user:alice")), 0);
    }

    #[test]
    fn test_authn_failure_reason_display() {
        assert_eq!(AuthnFailureReason::InvalidCredentials.to_string(), "invalid credentials");
        assert_eq!(AuthnFailureReason::IdentityLocked.to_string(), "identity locked");
        assert_eq!(AuthnFailureReason::RateLimited.to_string(), "rate limited");
    }
}
