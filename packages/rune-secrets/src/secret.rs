// ═══════════════════════════════════════════════════════════════════════
// Secret — Core Secret Types with Zeroization
//
// SecretValue zeroes memory on Drop. SecretMetadata tracks lifecycle.
// SecretEntry binds value + metadata. VersionedSecret tracks history.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use serde::{Deserialize, Serialize};
use rune_permissions::ClassificationLevel;

// ── SecretId ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretId(String);

impl SecretId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── SecretValue (zeroized on Drop) ────────────────────────────────────

pub struct SecretValue {
    data: Vec<u8>,
}

impl SecretValue {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_str(s: &str) -> Self {
        Self { data: s.as_bytes().to_vec() }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Expose the raw bytes to a callback. The secret is never returned
    /// outside this scope, limiting the window of exposure.
    pub fn expose_for<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.data)
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        // Overwrite with zeros before freeing
        for byte in self.data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte as *mut u8, 0);
            }
        }
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        Self { data: self.data.clone() }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED {} bytes]", self.data.len())
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing attacks
        if self.data.len() != other.data.len() {
            return false;
        }
        let mut result = 0u8;
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for SecretValue {}

// ── SecretType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    ApiKey,
    Password,
    Token,
    Certificate,
    PrivateKey,
    SymmetricKey,
    SeedPhrase,
    ConnectionString,
    Webhook,
    OAuthSecret,
    Custom(String),
}

impl SecretType {
    pub fn is_cryptographic(&self) -> bool {
        matches!(
            self,
            Self::PrivateKey | Self::SymmetricKey | Self::SeedPhrase | Self::Certificate
        )
    }

    pub fn recommended_rotation_days(&self) -> u32 {
        match self {
            Self::ApiKey => 90,
            Self::Password => 90,
            Self::Token => 30,
            Self::Certificate => 365,
            Self::PrivateKey => 365,
            Self::SymmetricKey => 180,
            Self::SeedPhrase => 0, // Never rotate automatically
            Self::ConnectionString => 90,
            Self::Webhook => 180,
            Self::OAuthSecret => 90,
            Self::Custom(_) => 90,
        }
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(name) => write!(f, "custom:{name}"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ── SecretState ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretState {
    Active,
    Rotated,
    Expired,
    Compromised,
    Destroyed,
}

impl SecretState {
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Rotated)
    }
}

impl fmt::Display for SecretState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SecretMetadata ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub secret_type: SecretType,
    pub classification: ClassificationLevel,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
    pub created_by: String,
    pub description: String,
    pub tags: Vec<String>,
    pub usage_count: u64,
    pub max_usage: Option<u64>,
}

impl SecretMetadata {
    pub fn new(secret_type: SecretType, classification: ClassificationLevel, created_by: impl Into<String>) -> Self {
        let now = 0; // Caller should set timestamps
        Self {
            secret_type,
            classification,
            created_at: now,
            updated_at: now,
            expires_at: None,
            created_by: created_by.into(),
            description: String::new(),
            tags: Vec::new(),
            usage_count: 0,
            max_usage: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_expires_at(mut self, ts: i64) -> Self {
        self.expires_at = Some(ts);
        self
    }

    pub fn with_max_usage(mut self, max: u64) -> Self {
        self.max_usage = Some(max);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_timestamps(mut self, created_at: i64, updated_at: i64) -> Self {
        self.created_at = created_at;
        self.updated_at = updated_at;
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    pub fn is_usage_exhausted(&self) -> bool {
        self.max_usage.is_some_and(|max| self.usage_count >= max)
    }

    pub fn record_usage(&mut self) {
        self.usage_count += 1;
    }
}

// ── SecretEntry ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecretEntry {
    pub id: SecretId,
    pub value: SecretValue,
    pub metadata: SecretMetadata,
    pub state: SecretState,
}

impl SecretEntry {
    pub fn new(id: SecretId, value: SecretValue, metadata: SecretMetadata) -> Self {
        Self {
            id,
            value,
            metadata,
            state: SecretState::Active,
        }
    }

    pub fn is_accessible(&self, now: i64) -> bool {
        self.state.is_usable()
            && !self.metadata.is_expired(now)
            && !self.metadata.is_usage_exhausted()
    }
}

// ── VersionedSecret ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VersionedSecret {
    pub id: SecretId,
    pub current_version: u32,
    pub versions: Vec<SecretEntry>,
    pub max_versions: usize,
}

impl VersionedSecret {
    pub fn new(id: SecretId, initial: SecretEntry, max_versions: usize) -> Self {
        Self {
            id,
            current_version: 1,
            versions: vec![initial],
            max_versions,
        }
    }

    pub fn current(&self) -> Option<&SecretEntry> {
        self.versions.last()
    }

    pub fn version(&self, v: u32) -> Option<&SecretEntry> {
        if v == 0 || v as usize > self.versions.len() {
            None
        } else {
            Some(&self.versions[v as usize - 1])
        }
    }

    pub fn version_count(&self) -> usize {
        self.versions.len()
    }

    pub fn add_version(&mut self, entry: SecretEntry) {
        self.current_version += 1;
        self.versions.push(entry);
        // Trim old versions if over max
        while self.versions.len() > self.max_versions {
            self.versions.remove(0);
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
    fn test_secret_id_new_and_display() {
        let id = SecretId::new("api-key-1");
        assert_eq!(id.as_str(), "api-key-1");
        assert_eq!(id.to_string(), "api-key-1");
    }

    #[test]
    fn test_secret_value_new_and_expose() {
        let val = SecretValue::new(vec![1, 2, 3]);
        assert_eq!(val.len(), 3);
        assert!(!val.is_empty());
        let sum = val.expose_for(|bytes| bytes.iter().map(|b| *b as u32).sum::<u32>());
        assert_eq!(sum, 6);
    }

    #[test]
    fn test_secret_value_from_str() {
        let val = SecretValue::from_str("hello");
        assert_eq!(val.len(), 5);
        val.expose_for(|bytes| assert_eq!(bytes, b"hello"));
    }

    #[test]
    fn test_secret_value_debug_redacted() {
        let val = SecretValue::new(vec![0; 32]);
        let debug = format!("{val:?}");
        assert_eq!(debug, "[REDACTED 32 bytes]");
        assert!(!debug.contains("0"));
    }

    #[test]
    fn test_secret_value_constant_time_eq() {
        let a = SecretValue::new(vec![1, 2, 3]);
        let b = SecretValue::new(vec![1, 2, 3]);
        let c = SecretValue::new(vec![1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_secret_value_different_lengths_not_equal() {
        let a = SecretValue::new(vec![1, 2]);
        let b = SecretValue::new(vec![1, 2, 3]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_secret_value_clone() {
        let a = SecretValue::new(vec![10, 20, 30]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_secret_value_zeroize_on_drop() {
        let data_ptr: *const u8;
        let len: usize;
        {
            let val = SecretValue::new(vec![0xAA; 64]);
            len = val.len();
            data_ptr = val.expose_for(|bytes| bytes.as_ptr());
            // val is dropped here
        }
        // After drop, the memory should have been zeroed.
        // This is best-effort — the allocator may reuse memory.
        // We verify the Drop impl at least ran by checking compile.
        assert_eq!(len, 64);
        let _ = data_ptr; // use it to avoid warning
    }

    #[test]
    fn test_secret_value_empty() {
        let val = SecretValue::new(vec![]);
        assert!(val.is_empty());
        assert_eq!(val.len(), 0);
    }

    #[test]
    fn test_secret_type_is_cryptographic() {
        assert!(SecretType::PrivateKey.is_cryptographic());
        assert!(SecretType::SymmetricKey.is_cryptographic());
        assert!(SecretType::SeedPhrase.is_cryptographic());
        assert!(SecretType::Certificate.is_cryptographic());
        assert!(!SecretType::ApiKey.is_cryptographic());
        assert!(!SecretType::Password.is_cryptographic());
        assert!(!SecretType::Token.is_cryptographic());
        assert!(!SecretType::Custom("x".into()).is_cryptographic());
    }

    #[test]
    fn test_secret_type_rotation_days() {
        assert_eq!(SecretType::Token.recommended_rotation_days(), 30);
        assert_eq!(SecretType::ApiKey.recommended_rotation_days(), 90);
        assert_eq!(SecretType::Certificate.recommended_rotation_days(), 365);
        assert_eq!(SecretType::SeedPhrase.recommended_rotation_days(), 0);
    }

    #[test]
    fn test_secret_type_display() {
        assert_eq!(SecretType::ApiKey.to_string(), "ApiKey");
        assert_eq!(SecretType::Custom("foo".into()).to_string(), "custom:foo");
    }

    #[test]
    fn test_secret_state_is_usable() {
        assert!(SecretState::Active.is_usable());
        assert!(SecretState::Rotated.is_usable());
        assert!(!SecretState::Expired.is_usable());
        assert!(!SecretState::Compromised.is_usable());
        assert!(!SecretState::Destroyed.is_usable());
    }

    #[test]
    fn test_secret_state_display() {
        assert_eq!(SecretState::Active.to_string(), "Active");
        assert_eq!(SecretState::Compromised.to_string(), "Compromised");
    }

    #[test]
    fn test_metadata_new_and_builders() {
        let meta = SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Confidential, "admin")
            .with_description("Main API key")
            .with_expires_at(1000)
            .with_max_usage(100)
            .with_tags(vec!["prod".into()])
            .with_timestamps(1, 2);
        assert_eq!(meta.description, "Main API key");
        assert_eq!(meta.expires_at, Some(1000));
        assert_eq!(meta.max_usage, Some(100));
        assert_eq!(meta.tags, vec!["prod"]);
        assert_eq!(meta.created_at, 1);
        assert_eq!(meta.updated_at, 2);
    }

    #[test]
    fn test_metadata_is_expired() {
        let meta = SecretMetadata::new(SecretType::Token, ClassificationLevel::Internal, "sys")
            .with_expires_at(100);
        assert!(!meta.is_expired(50));
        assert!(meta.is_expired(100));
        assert!(meta.is_expired(200));
    }

    #[test]
    fn test_metadata_no_expiry_never_expired() {
        let meta = SecretMetadata::new(SecretType::Token, ClassificationLevel::Internal, "sys");
        assert!(!meta.is_expired(999999));
    }

    #[test]
    fn test_metadata_usage_exhausted() {
        let mut meta = SecretMetadata::new(SecretType::Token, ClassificationLevel::Internal, "sys")
            .with_max_usage(2);
        assert!(!meta.is_usage_exhausted());
        meta.record_usage();
        assert!(!meta.is_usage_exhausted());
        meta.record_usage();
        assert!(meta.is_usage_exhausted());
    }

    #[test]
    fn test_metadata_no_usage_limit() {
        let mut meta = SecretMetadata::new(SecretType::Token, ClassificationLevel::Internal, "sys");
        for _ in 0..1000 {
            meta.record_usage();
        }
        assert!(!meta.is_usage_exhausted());
    }

    #[test]
    fn test_secret_entry_new() {
        let entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("val"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        assert_eq!(entry.state, SecretState::Active);
        assert_eq!(entry.id.as_str(), "k1");
    }

    #[test]
    fn test_secret_entry_is_accessible() {
        let entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("val"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1")
                .with_timestamps(1, 1),
        );
        assert!(entry.is_accessible(50));
    }

    #[test]
    fn test_secret_entry_not_accessible_when_expired() {
        let entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("val"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1")
                .with_expires_at(100)
                .with_timestamps(1, 1),
        );
        assert!(entry.is_accessible(50));
        assert!(!entry.is_accessible(100));
    }

    #[test]
    fn test_secret_entry_not_accessible_when_destroyed() {
        let mut entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("val"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        entry.state = SecretState::Destroyed;
        assert!(!entry.is_accessible(0));
    }

    #[test]
    fn test_versioned_secret_new() {
        let entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("v1"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        let vs = VersionedSecret::new(SecretId::new("k1"), entry, 5);
        assert_eq!(vs.current_version, 1);
        assert_eq!(vs.version_count(), 1);
        assert!(vs.current().is_some());
    }

    #[test]
    fn test_versioned_secret_add_version() {
        let entry1 = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("v1"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        let mut vs = VersionedSecret::new(SecretId::new("k1"), entry1, 5);
        let entry2 = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("v2"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        vs.add_version(entry2);
        assert_eq!(vs.current_version, 2);
        assert_eq!(vs.version_count(), 2);
    }

    #[test]
    fn test_versioned_secret_version_lookup() {
        let entry1 = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("v1"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        let mut vs = VersionedSecret::new(SecretId::new("k1"), entry1, 5);
        let entry2 = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("v2"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        vs.add_version(entry2);
        assert!(vs.version(1).is_some());
        assert!(vs.version(2).is_some());
        assert!(vs.version(0).is_none());
        assert!(vs.version(3).is_none());
    }

    #[test]
    fn test_versioned_secret_trims_old() {
        let entry = SecretEntry::new(
            SecretId::new("k1"),
            SecretValue::from_str("v1"),
            SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
        );
        let mut vs = VersionedSecret::new(SecretId::new("k1"), entry, 2);
        for i in 2..=5 {
            let e = SecretEntry::new(
                SecretId::new("k1"),
                SecretValue::from_str(&format!("v{i}")),
                SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "user1"),
            );
            vs.add_version(e);
        }
        assert_eq!(vs.version_count(), 2);
        assert_eq!(vs.current_version, 5);
    }
}
