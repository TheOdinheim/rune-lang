// ═══════════════════════════════════════════════════════════════════════
// Credential Management — Proof of Identity
//
// Each identity can have multiple credentials of different types.
// Credential data (hashes, keys) is stored securely; raw secrets
// are never persisted.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

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

// ── HashedCredential (Layer 2) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedCredential {
    pub hash: String,
    pub salt: String,
    pub algorithm: String,
    pub created_at: i64,
}

impl HashedCredential {
    pub fn from_password(password: &str, now: i64) -> Self {
        let mut salt_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt_hex = hex::encode(salt_bytes);
        let hash_hex = hash_credential_sha3(password, &salt_bytes);
        Self {
            hash: hash_hex,
            salt: salt_hex,
            algorithm: "SHA3-256".into(),
            created_at: now,
        }
    }
}

fn hash_credential_sha3(password: &str, salt: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_credential(password: &str, stored: &HashedCredential) -> bool {
    let salt = match hex::decode(&stored.salt) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let computed = hash_credential_sha3(password, &salt);
    // Constant-time comparison via XOR accumulation
    if computed.len() != stored.hash.len() {
        return false;
    }
    let mut result = 0u8;
    for (a, b) in computed.as_bytes().iter().zip(stored.hash.as_bytes()) {
        result |= a ^ b;
    }
    result == 0
}

// ── Credential Strength Validation (Layer 2) ───────────────────────

#[derive(Debug, Clone)]
pub struct CredentialStrengthResult {
    pub score: u8,
    pub meets_minimum: bool,
    pub issues: Vec<String>,
}

const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "michael", "shadow", "123123",
    "654321", "superman", "qazwsx", "football", "password1", "password123",
    "admin", "welcome", "login", "princess", "starwars", "passw0rd",
];

pub fn validate_credential_strength(password: &str) -> CredentialStrengthResult {
    validate_credential_strength_with_username(password, None)
}

pub fn validate_credential_strength_with_username(password: &str, username: Option<&str>) -> CredentialStrengthResult {
    let mut issues = Vec::new();
    let mut score: u8 = 0;

    // Length check (min 12)
    if password.len() < 12 {
        issues.push(format!("minimum length 12, got {}", password.len()));
    } else {
        score += 20;
        if password.len() >= 16 {
            score += 10;
        }
    }

    // Uppercase
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        score += 15;
    } else {
        issues.push("missing uppercase letter".into());
    }

    // Lowercase
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        score += 15;
    } else {
        issues.push("missing lowercase letter".into());
    }

    // Digit
    if password.chars().any(|c| c.is_ascii_digit()) {
        score += 15;
    } else {
        issues.push("missing digit".into());
    }

    // Special character
    if password.chars().any(|c| !c.is_alphanumeric()) {
        score += 15;
    } else {
        issues.push("missing special character".into());
    }

    // Repeated characters (no more than 3 in a row)
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(4) {
        if window.iter().all(|c| *c == window[0]) {
            issues.push("more than 3 repeated characters in a row".into());
            score = score.saturating_sub(10);
            break;
        }
    }

    // Common password check
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.iter().any(|p| lower == *p) {
        issues.push("password is in common password list".into());
        score = score.saturating_sub(30);
    }

    // Username match check
    if let Some(uname) = username {
        if !uname.is_empty() && lower.contains(&uname.to_lowercase()) {
            issues.push("password contains username".into());
            score = score.saturating_sub(20);
        }
    }

    // Bonus for entropy diversity
    let unique: std::collections::HashSet<char> = password.chars().collect();
    if unique.len() > 10 {
        score += 10;
    }

    score = score.min(100);
    let meets_minimum = issues.is_empty();

    CredentialStrengthResult {
        score,
        meets_minimum,
        issues,
    }
}

// ── Credential History (Layer 2) ───────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CredentialHistory {
    pub previous_hashes: Vec<String>,
    pub last_changed_at: i64,
    pub change_count: u64,
    pub max_history: usize,
}

impl CredentialHistory {
    pub fn new(max_history: usize) -> Self {
        Self {
            previous_hashes: Vec::new(),
            last_changed_at: 0,
            change_count: 0,
            max_history,
        }
    }

    pub fn is_reused(&self, new_hash: &str) -> bool {
        self.previous_hashes.iter().any(|h| h == new_hash)
    }

    pub fn record_change(&mut self, old_hash: &str, now: i64) {
        self.previous_hashes.push(old_hash.to_string());
        if self.previous_hashes.len() > self.max_history {
            self.previous_hashes.remove(0);
        }
        self.last_changed_at = now;
        self.change_count += 1;
    }

    pub fn days_since_change(&self, now: i64) -> u64 {
        if self.last_changed_at == 0 {
            return u64::MAX;
        }
        let ms = (now - self.last_changed_at).max(0) as u64;
        ms / 86_400_000
    }

    pub fn needs_rotation(&self, max_age_days: u64, now: i64) -> bool {
        self.days_since_change(now) >= max_age_days
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

    // ── Part 1: Real Credential Hashing Tests ────────────────────────

    #[test]
    fn test_sha3_256_credential_hash_produces_64_char_hex() {
        let hashed = HashedCredential::from_password("my-secure-password", 1000);
        assert_eq!(hashed.hash.len(), 64);
        assert!(hashed.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_same_password_same_salt_produces_same_hash() {
        let salt = hex::decode("aabbccdd00112233aabbccdd00112233").unwrap();
        let h1 = hash_credential_sha3("password123", &salt);
        let h2 = hash_credential_sha3("password123", &salt);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_same_password_different_salt_produces_different_hash() {
        let h1 = HashedCredential::from_password("password123", 1000);
        let h2 = HashedCredential::from_password("password123", 1000);
        // Overwhelmingly likely to have different salts
        assert_ne!(h1.hash, h2.hash);
    }

    #[test]
    fn test_verify_credential_succeeds_with_correct_password() {
        let hashed = HashedCredential::from_password("correct-horse-battery", 1000);
        assert!(verify_credential("correct-horse-battery", &hashed));
    }

    #[test]
    fn test_verify_credential_fails_with_wrong_password() {
        let hashed = HashedCredential::from_password("correct-horse-battery", 1000);
        assert!(!verify_credential("wrong-password", &hashed));
    }

    #[test]
    fn test_hashed_credential_stores_algorithm_as_sha3_256() {
        let hashed = HashedCredential::from_password("test", 1000);
        assert_eq!(hashed.algorithm, "SHA3-256");
    }

    #[test]
    fn test_validate_credential_strength_rejects_short_passwords() {
        let result = validate_credential_strength("short");
        assert!(!result.meets_minimum);
        assert!(result.issues.iter().any(|i| i.contains("minimum length")));
    }

    #[test]
    fn test_validate_credential_strength_flags_missing_categories() {
        let result = validate_credential_strength("alllowercase!!");
        assert!(result.issues.iter().any(|i| i.contains("uppercase")));
        assert!(result.issues.iter().any(|i| i.contains("digit")));
    }

    #[test]
    fn test_validate_credential_strength_scores_strong_password_high() {
        let result = validate_credential_strength("MyStr0ng!Pass#2024x");
        assert!(result.score >= 80);
        assert!(result.meets_minimum);
    }

    #[test]
    fn test_validate_credential_strength_catches_common_passwords() {
        let result = validate_credential_strength("password");
        assert!(!result.meets_minimum);
        assert!(result.issues.iter().any(|i| i.contains("common password")));
    }

    #[test]
    fn test_credential_history_is_reused_detects_previously_used() {
        let mut history = CredentialHistory::new(10);
        history.record_change("oldhash123", 1000);
        assert!(history.is_reused("oldhash123"));
    }

    #[test]
    fn test_credential_history_is_reused_allows_new() {
        let mut history = CredentialHistory::new(10);
        history.record_change("oldhash123", 1000);
        assert!(!history.is_reused("newhash456"));
    }

    #[test]
    fn test_credential_history_record_change_adds_to_history() {
        let mut history = CredentialHistory::new(10);
        history.record_change("hash1", 1000);
        history.record_change("hash2", 2000);
        assert_eq!(history.previous_hashes.len(), 2);
        assert_eq!(history.change_count, 2);
    }

    #[test]
    fn test_credential_history_record_change_respects_max_history() {
        let mut history = CredentialHistory::new(2);
        history.record_change("hash1", 1000);
        history.record_change("hash2", 2000);
        history.record_change("hash3", 3000);
        assert_eq!(history.previous_hashes.len(), 2);
        assert!(!history.is_reused("hash1")); // evicted
        assert!(history.is_reused("hash2"));
        assert!(history.is_reused("hash3"));
    }

    #[test]
    fn test_credential_history_days_since_change() {
        let history = CredentialHistory {
            previous_hashes: vec![],
            last_changed_at: 1000,
            change_count: 1,
            max_history: 10,
        };
        // 2 days = 2 * 86_400_000 ms
        let now = 1000 + 2 * 86_400_000;
        assert_eq!(history.days_since_change(now), 2);
    }

    #[test]
    fn test_credential_history_needs_rotation_when_expired() {
        let history = CredentialHistory {
            previous_hashes: vec![],
            last_changed_at: 1000,
            change_count: 1,
            max_history: 10,
        };
        let now = 1000 + 91 * 86_400_000; // 91 days later
        assert!(history.needs_rotation(90, now));
        let now2 = 1000 + 30 * 86_400_000; // 30 days later
        assert!(!history.needs_rotation(90, now2));
    }
}
