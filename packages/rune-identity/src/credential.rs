// ═══════════════════════════════════════════════════════════════════════
// Credential Management — Proof of Identity
//
// Each identity can have multiple credentials of different types.
// Credential data (hashes, keys) is stored securely; raw secrets
// are never persisted.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::IdentityError;
use crate::identity::IdentityId;

// ── CredentialId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(String);

impl CredentialId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── CredentialType ────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub enum CredentialType {
    Password { hash: Vec<u8>, salt: Vec<u8>, algorithm: String },
    ApiKey { key_hash: Vec<u8>, prefix: String },
    Token { token_hash: Vec<u8>, token_type: TokenType, scope: Vec<String> },
    Certificate { subject: String, issuer: String, serial: String, fingerprint: String, not_before: i64, not_after: i64 },
    SshKey { public_key: String, fingerprint: String, key_type: String },
    MfaTotp { secret_hash: Vec<u8>, verified: bool },
    MfaWebauthn { credential_id_hash: Vec<u8>, public_key: String },
}

impl CredentialType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::Password { .. } => "Password",
            Self::ApiKey { .. } => "ApiKey",
            Self::Token { .. } => "Token",
            Self::Certificate { .. } => "Certificate",
            Self::SshKey { .. } => "SshKey",
            Self::MfaTotp { .. } => "MfaTotp",
            Self::MfaWebauthn { .. } => "MfaWebauthn",
        }
    }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

impl fmt::Debug for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialType::{}", self.type_name())
    }
}

// ── TokenType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Bearer,
    Refresh,
    Access,
    ApiToken,
    ServiceToken,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── CredentialStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CredentialStatus {
    Active,
    Expired,
    Revoked { reason: String, revoked_at: i64 },
    Compromised { reported_at: i64, reported_by: String },
}

impl CredentialStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked { reason, .. } => write!(f, "Revoked: {reason}"),
            Self::Compromised { reported_by, .. } => write!(f, "Compromised (reported by {reported_by})"),
        }
    }
}

// ── Credential ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: CredentialId,
    pub identity_id: IdentityId,
    pub credential_type: CredentialType,
    pub status: CredentialStatus,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub usage_count: u64,
    pub metadata: HashMap<String, String>,
}

impl Credential {
    pub fn new(
        id: CredentialId,
        identity_id: IdentityId,
        credential_type: CredentialType,
        created_at: i64,
    ) -> Self {
        Self {
            id,
            identity_id,
            credential_type,
            status: CredentialStatus::Active,
            created_at,
            expires_at: None,
            last_used_at: None,
            usage_count: 0,
            metadata: HashMap::new(),
        }
    }

    pub fn with_expiry(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

// ── CredentialStore ───────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CredentialStore {
    credentials: HashMap<CredentialId, Credential>,
    identity_index: HashMap<IdentityId, Vec<CredentialId>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_credential(&mut self, credential: Credential) -> Result<(), IdentityError> {
        if self.credentials.contains_key(&credential.id) {
            return Err(IdentityError::CredentialAlreadyExists(credential.id.clone()));
        }
        let cred_id = credential.id.clone();
        let identity_id = credential.identity_id.clone();
        self.credentials.insert(cred_id.clone(), credential);
        self.identity_index.entry(identity_id).or_default().push(cred_id);
        Ok(())
    }

    pub fn get_credential(&self, id: &CredentialId) -> Option<&Credential> {
        self.credentials.get(id)
    }

    pub fn credentials_for_identity(&self, identity_id: &IdentityId) -> Vec<&Credential> {
        self.identity_index.get(identity_id)
            .map(|ids| ids.iter().filter_map(|id| self.credentials.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn active_credentials(&self, identity_id: &IdentityId) -> Vec<&Credential> {
        self.credentials_for_identity(identity_id)
            .into_iter()
            .filter(|c| c.status.is_active())
            .collect()
    }

    pub fn revoke_credential(
        &mut self,
        id: &CredentialId,
        reason: &str,
        _revoked_by: &str,
        now: i64,
    ) -> Result<(), IdentityError> {
        let cred = self.credentials.get_mut(id)
            .ok_or_else(|| IdentityError::CredentialNotFound(id.clone()))?;
        cred.status = CredentialStatus::Revoked {
            reason: reason.into(),
            revoked_at: now,
        };
        Ok(())
    }

    pub fn mark_compromised(
        &mut self,
        id: &CredentialId,
        reported_by: &str,
        now: i64,
    ) -> Result<(), IdentityError> {
        let cred = self.credentials.get_mut(id)
            .ok_or_else(|| IdentityError::CredentialNotFound(id.clone()))?;
        cred.status = CredentialStatus::Compromised {
            reported_at: now,
            reported_by: reported_by.into(),
        };
        Ok(())
    }

    pub fn expired_credentials(&self, now: i64) -> Vec<&Credential> {
        self.credentials.values()
            .filter(|c| c.is_expired(now))
            .collect()
    }

    pub fn credentials_by_type(&self, identity_id: &IdentityId, type_name: &str) -> Vec<&Credential> {
        self.credentials_for_identity(identity_id)
            .into_iter()
            .filter(|c| c.credential_type.type_name() == type_name)
            .collect()
    }

    pub fn record_usage(&mut self, id: &CredentialId, now: i64) -> Result<(), IdentityError> {
        let cred = self.credentials.get_mut(id)
            .ok_or_else(|| IdentityError::CredentialNotFound(id.clone()))?;
        cred.last_used_at = Some(now);
        cred.usage_count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.credentials.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_password_cred(id: &str, identity: &str) -> Credential {
        Credential::new(
            CredentialId::new(id),
            IdentityId::new(identity),
            CredentialType::Password {
                hash: vec![1, 2, 3],
                salt: vec![4, 5, 6],
                algorithm: "argon2id".into(),
            },
            1000,
        )
    }

    fn test_api_key_cred(id: &str, identity: &str) -> Credential {
        Credential::new(
            CredentialId::new(id),
            IdentityId::new(identity),
            CredentialType::ApiKey {
                key_hash: vec![10, 20, 30],
                prefix: "sk_live_abc".into(),
            },
            1000,
        )
    }

    #[test]
    fn test_credential_construction() {
        let cred = test_password_cred("c1", "user:alice");
        assert_eq!(cred.id.as_str(), "c1");
        assert_eq!(cred.identity_id.as_str(), "user:alice");
        assert!(cred.status.is_active());
        assert_eq!(cred.usage_count, 0);
    }

    #[test]
    fn test_credential_type_display() {
        let cred = test_password_cred("c1", "user:alice");
        assert_eq!(cred.credential_type.to_string(), "Password");
        let cred = test_api_key_cred("c2", "user:alice");
        assert_eq!(cred.credential_type.to_string(), "ApiKey");
    }

    #[test]
    fn test_credential_type_debug_redacted() {
        let cred = test_password_cred("c1", "user:alice");
        let debug = format!("{:?}", cred.credential_type);
        assert!(debug.contains("Password"));
        assert!(!debug.contains("1, 2, 3")); // no raw hash data
    }

    #[test]
    fn test_credential_with_expiry() {
        let cred = test_password_cred("c1", "user:alice").with_expiry(2000);
        assert!(!cred.is_expired(1500));
        assert!(cred.is_expired(2000));
    }

    #[test]
    fn test_credential_store_add_and_retrieve() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        assert_eq!(store.count(), 1);
        assert!(store.get_credential(&CredentialId::new("c1")).is_some());
    }

    #[test]
    fn test_credential_store_duplicate() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        assert!(store.add_credential(test_password_cred("c1", "user:alice")).is_err());
    }

    #[test]
    fn test_credential_store_for_identity() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        store.add_credential(test_api_key_cred("c2", "user:alice")).unwrap();
        store.add_credential(test_password_cred("c3", "user:bob")).unwrap();
        assert_eq!(store.credentials_for_identity(&IdentityId::new("user:alice")).len(), 2);
        assert_eq!(store.credentials_for_identity(&IdentityId::new("user:bob")).len(), 1);
    }

    #[test]
    fn test_credential_store_active_credentials() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        store.add_credential(test_api_key_cred("c2", "user:alice")).unwrap();
        store.revoke_credential(&CredentialId::new("c1"), "test", "admin", 1500).unwrap();
        assert_eq!(store.active_credentials(&IdentityId::new("user:alice")).len(), 1);
    }

    #[test]
    fn test_credential_store_revoke() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        store.revoke_credential(&CredentialId::new("c1"), "policy", "admin", 1500).unwrap();
        let cred = store.get_credential(&CredentialId::new("c1")).unwrap();
        assert!(matches!(cred.status, CredentialStatus::Revoked { .. }));
    }

    #[test]
    fn test_credential_store_mark_compromised() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        store.mark_compromised(&CredentialId::new("c1"), "security", 1500).unwrap();
        let cred = store.get_credential(&CredentialId::new("c1")).unwrap();
        assert!(matches!(cred.status, CredentialStatus::Compromised { .. }));
    }

    #[test]
    fn test_credential_store_record_usage() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        store.record_usage(&CredentialId::new("c1"), 2000).unwrap();
        let cred = store.get_credential(&CredentialId::new("c1")).unwrap();
        assert_eq!(cred.usage_count, 1);
        assert_eq!(cred.last_used_at, Some(2000));
    }

    #[test]
    fn test_credential_store_expired() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice").with_expiry(1500)).unwrap();
        store.add_credential(test_password_cred("c2", "user:bob").with_expiry(3000)).unwrap();
        assert_eq!(store.expired_credentials(2000).len(), 1);
    }

    #[test]
    fn test_credential_store_by_type() {
        let mut store = CredentialStore::new();
        store.add_credential(test_password_cred("c1", "user:alice")).unwrap();
        store.add_credential(test_api_key_cred("c2", "user:alice")).unwrap();
        assert_eq!(store.credentials_by_type(&IdentityId::new("user:alice"), "Password").len(), 1);
        assert_eq!(store.credentials_by_type(&IdentityId::new("user:alice"), "ApiKey").len(), 1);
        assert_eq!(store.credentials_by_type(&IdentityId::new("user:alice"), "Token").len(), 0);
    }
}
