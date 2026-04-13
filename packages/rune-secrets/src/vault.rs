// ═══════════════════════════════════════════════════════════════════════
// SecretVault — In-Memory Secret Store with Access Control
//
// Stores secrets with classification-based access, rotation,
// compromise marking, health checks, and full audit logging.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_permissions::ClassificationLevel;

use crate::audit::{SecretAuditLog, SecretEvent, SecretEventType};
use crate::error::SecretError;
use crate::rotation::{
    RotationPolicy, RotationResult, RotationStatus, check_rotation_status,
};
use std::fmt;
use crate::secret::{
    SecretEntry, SecretId, SecretMetadata, SecretState, SecretType, SecretValue, VersionedSecret,
};

// ── VaultAccessPolicy ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VaultAccessPolicy {
    pub max_clearance: ClassificationLevel,
}

impl VaultAccessPolicy {
    pub fn new(max_clearance: ClassificationLevel) -> Self {
        Self { max_clearance }
    }

    /// Bell-LaPadula: subject clearance must dominate secret classification.
    pub fn can_access(&self, secret_classification: &ClassificationLevel) -> bool {
        self.max_clearance >= *secret_classification
    }
}

// ── SecretVault ───────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SecretVault {
    secrets: HashMap<SecretId, VersionedSecret>,
    master_key: Vec<u8>,
    audit_log: SecretAuditLog,
}

impl SecretVault {
    pub fn new(master_key: Vec<u8>) -> Self {
        Self {
            secrets: HashMap::new(),
            master_key,
            audit_log: SecretAuditLog::new(),
        }
    }

    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    pub fn audit_log(&self) -> &SecretAuditLog {
        &self.audit_log
    }

    pub fn count(&self) -> usize {
        self.secrets.len()
    }

    pub fn contains(&self, id: &SecretId) -> bool {
        self.secrets.contains_key(id)
    }

    /// Store a new secret.
    pub fn store(
        &mut self,
        id: SecretId,
        value: SecretValue,
        metadata: SecretMetadata,
        actor: &str,
        now: i64,
    ) -> Result<(), SecretError> {
        if self.secrets.contains_key(&id) {
            return Err(SecretError::SecretAlreadyExists(id));
        }

        let entry = SecretEntry::new(id.clone(), value, metadata);
        let versioned = VersionedSecret::new(id.clone(), entry, 5);
        self.secrets.insert(id.clone(), versioned);

        self.audit_log.record(SecretEvent::new(
            SecretEventType::Created,
            id,
            now,
            actor,
            "secret stored",
        ));

        Ok(())
    }

    /// Retrieve a secret, checking clearance and recording access.
    pub fn retrieve(
        &mut self,
        id: &SecretId,
        policy: &VaultAccessPolicy,
        actor: &str,
        now: i64,
    ) -> Result<&SecretValue, SecretError> {
        let versioned = self.secrets.get(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;

        let current = versioned.current()
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;

        // Classification check
        if !policy.can_access(&current.metadata.classification) {
            self.audit_log.record(SecretEvent::new(
                SecretEventType::AccessDenied,
                id.clone(),
                now,
                actor,
                "insufficient clearance",
            ));
            return Err(SecretError::AccessDenied(
                format!("clearance {:?} insufficient for {:?} secret",
                    policy.max_clearance, current.metadata.classification)
            ));
        }

        // State check
        if !current.is_accessible(now) {
            if current.metadata.is_expired(now) {
                return Err(SecretError::SecretExpired {
                    id: id.clone(),
                    expired_at: current.metadata.expires_at.unwrap_or(0),
                });
            }
            if current.metadata.is_usage_exhausted() {
                return Err(SecretError::UsageLimitExceeded { id: id.clone() });
            }
            match &current.state {
                SecretState::Compromised => return Err(SecretError::SecretCompromised(id.clone())),
                SecretState::Destroyed => return Err(SecretError::SecretDestroyed(id.clone())),
                _ => {}
            }
        }

        self.audit_log.record(SecretEvent::new(
            SecretEventType::Accessed,
            id.clone(),
            now,
            actor,
            "secret retrieved",
        ));

        // Record usage on the mutable metadata
        let versioned = self.secrets.get_mut(id).unwrap();
        let current = versioned.versions.last_mut().unwrap();
        current.metadata.record_usage();

        Ok(&self.secrets[id].current().unwrap().value)
    }

    /// Remove a secret (mark as destroyed).
    pub fn remove(
        &mut self,
        id: &SecretId,
        actor: &str,
        now: i64,
    ) -> Result<(), SecretError> {
        let versioned = self.secrets.get_mut(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;

        for entry in &mut versioned.versions {
            entry.state = SecretState::Destroyed;
        }

        self.audit_log.record(SecretEvent::new(
            SecretEventType::Destroyed,
            id.clone(),
            now,
            actor,
            "secret destroyed",
        ));

        Ok(())
    }

    /// Mark a secret as compromised.
    pub fn mark_compromised(
        &mut self,
        id: &SecretId,
        actor: &str,
        now: i64,
    ) -> Result<(), SecretError> {
        let versioned = self.secrets.get_mut(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;

        for entry in &mut versioned.versions {
            entry.state = SecretState::Compromised;
        }

        self.audit_log.record(SecretEvent::new(
            SecretEventType::Compromised,
            id.clone(),
            now,
            actor,
            "secret marked compromised",
        ));

        Ok(())
    }

    /// Rotate a secret with a new value.
    pub fn rotate(
        &mut self,
        id: &SecretId,
        new_value: SecretValue,
        actor: &str,
        now: i64,
    ) -> Result<RotationResult, SecretError> {
        let versioned = self.secrets.get_mut(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;

        let old_version = versioned.current_version;

        // Mark current as rotated
        if let Some(current) = versioned.versions.last_mut() {
            current.state = SecretState::Rotated;
        }

        // Create new entry with same metadata but updated timestamps
        let old_meta = &versioned.versions.last().unwrap().metadata;
        let new_meta = SecretMetadata::new(
            old_meta.secret_type.clone(),
            old_meta.classification.clone(),
            actor,
        )
        .with_timestamps(now, now)
        .with_description(old_meta.description.clone());

        if let Some(exp) = old_meta.expires_at {
            // Extend expiry by same duration
            let duration = exp - old_meta.created_at;
            let new_entry = SecretEntry::new(id.clone(), new_value, new_meta.with_expires_at(now + duration));
            versioned.add_version(new_entry);
        } else {
            let new_entry = SecretEntry::new(id.clone(), new_value, new_meta);
            versioned.add_version(new_entry);
        }

        let new_version = versioned.current_version;

        self.audit_log.record(SecretEvent::new(
            SecretEventType::Rotated,
            id.clone(),
            now,
            actor,
            format!("rotated v{old_version} → v{new_version}"),
        ));

        Ok(RotationResult {
            id: id.clone(),
            old_version,
            new_version,
            old_state: SecretState::Rotated,
            rotated_at: now,
        })
    }

    /// Check rotation status for a secret.
    pub fn rotation_status(
        &self,
        id: &SecretId,
        policy: &RotationPolicy,
        now: i64,
    ) -> Result<RotationStatus, SecretError> {
        let versioned = self.secrets.get(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        let current = versioned.current()
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        Ok(check_rotation_status(current.metadata.updated_at, now, policy))
    }

    /// Set expiration for a secret.
    pub fn set_expiration(
        &mut self,
        id: &SecretId,
        expires_at: i64,
        actor: &str,
        now: i64,
    ) -> Result<(), SecretError> {
        let versioned = self.secrets.get_mut(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        let current = versioned.versions.last_mut()
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        current.metadata.expires_at = Some(expires_at);
        current.metadata.updated_at = now;

        self.audit_log.record(SecretEvent::new(
            SecretEventType::Updated,
            id.clone(),
            now,
            actor,
            format!("expiration set to {expires_at}"),
        ));

        Ok(())
    }

    /// Check expiration status for a secret.
    pub fn check_expiration(
        &self,
        id: &SecretId,
        now: i64,
        expiring_soon_threshold: i64,
    ) -> Result<ExpirationStatus, SecretError> {
        let versioned = self.secrets.get(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        let current = versioned.current()
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;

        match current.metadata.expires_at {
            None => Ok(ExpirationStatus::NoExpiry),
            Some(exp) if now >= exp => Ok(ExpirationStatus::Expired { expired_at: exp }),
            Some(exp) if exp - now <= expiring_soon_threshold => {
                Ok(ExpirationStatus::ExpiringSoon {
                    expires_at: exp,
                    seconds_remaining: exp - now,
                })
            }
            Some(exp) => Ok(ExpirationStatus::Active { expires_at: exp }),
        }
    }

    /// Return IDs of all expired secrets.
    pub fn expired_secrets(&self, now: i64) -> Vec<&SecretId> {
        self.secrets.iter()
            .filter(|(_, vs)| {
                vs.current().is_some_and(|c| c.metadata.is_expired(now) && c.state.is_usable())
            })
            .map(|(id, _)| id)
            .collect()
    }

    /// Mark all expired secrets as Expired state and return count cleaned up.
    pub fn cleanup_expired(
        &mut self,
        actor: &str,
        now: i64,
    ) -> usize {
        let expired_ids: Vec<SecretId> = self.secrets.iter()
            .filter(|(_, vs)| {
                vs.current().is_some_and(|c| {
                    c.metadata.is_expired(now) && c.state == SecretState::Active
                })
            })
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(vs) = self.secrets.get_mut(id) {
                if let Some(current) = vs.versions.last_mut() {
                    current.state = SecretState::Expired;
                }
            }
            self.audit_log.record(SecretEvent::new(
                SecretEventType::SecretExpired,
                id.clone(),
                now,
                actor,
                "expired secret cleaned up",
            ));
        }
        count
    }

    /// Get access count for a secret.
    pub fn access_count(&self, id: &SecretId) -> Result<u64, SecretError> {
        let versioned = self.secrets.get(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        let current = versioned.current()
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        Ok(current.metadata.usage_count)
    }

    /// Get last accessed timestamp for a secret.
    pub fn last_accessed(&self, id: &SecretId) -> Result<i64, SecretError> {
        let versioned = self.secrets.get(id)
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        let current = versioned.current()
            .ok_or_else(|| SecretError::SecretNotFound(id.clone()))?;
        Ok(current.metadata.updated_at)
    }

    /// Vault health: count of secrets by state.
    pub fn health(&self) -> VaultHealth {
        let mut h = VaultHealth::default();
        for vs in self.secrets.values() {
            if let Some(current) = vs.current() {
                match current.state {
                    SecretState::Active => h.active += 1,
                    SecretState::Rotated => h.rotated += 1,
                    SecretState::Expired => h.expired += 1,
                    SecretState::Compromised => h.compromised += 1,
                    SecretState::Destroyed => h.destroyed += 1,
                }
            }
        }
        h.total = self.secrets.len();
        h
    }
}

// ── ExpirationStatus ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpirationStatus {
    NoExpiry,
    Active { expires_at: i64 },
    ExpiringSoon { expires_at: i64, seconds_remaining: i64 },
    Expired { expired_at: i64 },
}

impl ExpirationStatus {
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Expired { .. })
    }

    pub fn is_expiring_soon(&self) -> bool {
        matches!(self, Self::ExpiringSoon { .. })
    }
}

impl fmt::Display for ExpirationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExpiry => write!(f, "no expiry"),
            Self::Active { expires_at } => write!(f, "active (expires at {expires_at})"),
            Self::ExpiringSoon { seconds_remaining, .. } => {
                write!(f, "expiring in {seconds_remaining}s")
            }
            Self::Expired { expired_at } => write!(f, "expired at {expired_at}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultHealth {
    pub total: usize,
    pub active: usize,
    pub rotated: usize,
    pub expired: usize,
    pub compromised: usize,
    pub destroyed: usize,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> SecretVault {
        SecretVault::new(vec![0xAA; 32])
    }

    fn test_meta() -> SecretMetadata {
        SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::Internal, "admin")
            .with_timestamps(100, 100)
    }

    fn admin_policy() -> VaultAccessPolicy {
        VaultAccessPolicy::new(ClassificationLevel::TopSecret)
    }

    #[test]
    fn test_vault_store_and_retrieve() {
        let mut vault = test_vault();
        vault.store(
            SecretId::new("k1"),
            SecretValue::from_str("secret-value"),
            test_meta(),
            "admin",
            100,
        ).unwrap();

        assert_eq!(vault.count(), 1);
        assert!(vault.contains(&SecretId::new("k1")));

        let val = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "user", 200).unwrap();
        val.expose_for(|bytes| assert_eq!(bytes, b"secret-value"));
    }

    #[test]
    fn test_vault_store_duplicate() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 1).unwrap();
        let result = vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 2);
        assert!(matches!(result, Err(SecretError::SecretAlreadyExists(_))));
    }

    #[test]
    fn test_vault_retrieve_not_found() {
        let mut vault = test_vault();
        let result = vault.retrieve(&SecretId::new("nope"), &admin_policy(), "u", 1);
        assert!(matches!(result, Err(SecretError::SecretNotFound(_))));
    }

    #[test]
    fn test_vault_access_denied_clearance() {
        let mut vault = test_vault();
        let meta = SecretMetadata::new(SecretType::ApiKey, ClassificationLevel::TopSecret, "admin")
            .with_timestamps(1, 1);
        vault.store(SecretId::new("top"), SecretValue::from_str("v"), meta, "admin", 1).unwrap();

        let low_policy = VaultAccessPolicy::new(ClassificationLevel::Internal);
        let result = vault.retrieve(&SecretId::new("top"), &low_policy, "low-user", 2);
        assert!(matches!(result, Err(SecretError::AccessDenied(_))));

        // Should have logged access denied
        assert_eq!(vault.audit_log().denied_count(), 1);
    }

    #[test]
    fn test_vault_remove() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 1).unwrap();
        vault.remove(&SecretId::new("k1"), "admin", 2).unwrap();

        // Should exist but not be accessible
        let result = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 3);
        assert!(matches!(result, Err(SecretError::SecretDestroyed(_))));
    }

    #[test]
    fn test_vault_mark_compromised() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 1).unwrap();
        vault.mark_compromised(&SecretId::new("k1"), "security", 2).unwrap();

        let result = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 3);
        assert!(matches!(result, Err(SecretError::SecretCompromised(_))));
        assert_eq!(vault.audit_log().compromise_count(), 1);
    }

    #[test]
    fn test_vault_rotate() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("old"), test_meta(), "a", 100).unwrap();

        let result = vault.rotate(
            &SecretId::new("k1"),
            SecretValue::from_str("new"),
            "admin",
            200,
        ).unwrap();

        assert_eq!(result.old_version, 1);
        assert_eq!(result.new_version, 2);

        let val = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 300).unwrap();
        val.expose_for(|bytes| assert_eq!(bytes, b"new"));
    }

    #[test]
    fn test_vault_rotation_status() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 100).unwrap();

        let policy = RotationPolicy::standard();
        let status = vault.rotation_status(&SecretId::new("k1"), &policy, 100 + 86400 * 10).unwrap();
        assert_eq!(status, RotationStatus::Current);
    }

    #[test]
    fn test_vault_health() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 1).unwrap();
        vault.store(SecretId::new("k2"), SecretValue::from_str("v"), test_meta(), "a", 1).unwrap();
        vault.mark_compromised(&SecretId::new("k2"), "sec", 2).unwrap();

        let h = vault.health();
        assert_eq!(h.total, 2);
        assert_eq!(h.active, 1);
        assert_eq!(h.compromised, 1);
    }

    #[test]
    fn test_vault_audit_log_tracks_operations() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "admin", 1).unwrap();
        vault.retrieve(&SecretId::new("k1"), &admin_policy(), "user", 2).unwrap();
        vault.rotate(&SecretId::new("k1"), SecretValue::from_str("new"), "admin", 3).unwrap();
        vault.remove(&SecretId::new("k1"), "admin", 4).unwrap();

        assert_eq!(vault.audit_log().len(), 4);
    }

    #[test]
    fn test_vault_expired_secret() {
        let mut vault = test_vault();
        let meta = SecretMetadata::new(SecretType::Token, ClassificationLevel::Internal, "admin")
            .with_timestamps(100, 100)
            .with_expires_at(200);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta, "a", 100).unwrap();

        // Before expiry
        assert!(vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 150).is_ok());

        // After expiry
        let result = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 200);
        assert!(matches!(result, Err(SecretError::SecretExpired { .. })));
    }

    #[test]
    fn test_vault_usage_limit() {
        let mut vault = test_vault();
        let meta = SecretMetadata::new(SecretType::Token, ClassificationLevel::Internal, "admin")
            .with_timestamps(1, 1)
            .with_max_usage(2);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta, "a", 1).unwrap();

        assert!(vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 2).is_ok());
        assert!(vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 3).is_ok());
        let result = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 4);
        assert!(matches!(result, Err(SecretError::UsageLimitExceeded { .. })));
    }

    // ── Lifecycle management tests ─────────────────────────────────────

    #[test]
    fn test_set_expiration() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 100).unwrap();
        vault.set_expiration(&SecretId::new("k1"), 500, "admin", 200).unwrap();

        let result = vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 600);
        assert!(matches!(result, Err(SecretError::SecretExpired { .. })));
    }

    #[test]
    fn test_check_expiration_no_expiry() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 100).unwrap();
        let status = vault.check_expiration(&SecretId::new("k1"), 200, 3600).unwrap();
        assert_eq!(status, ExpirationStatus::NoExpiry);
    }

    #[test]
    fn test_check_expiration_active() {
        let mut vault = test_vault();
        let meta = test_meta().with_expires_at(10000);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta, "a", 100).unwrap();
        let status = vault.check_expiration(&SecretId::new("k1"), 200, 3600).unwrap();
        assert!(matches!(status, ExpirationStatus::Active { .. }));
    }

    #[test]
    fn test_check_expiration_expiring_soon() {
        let mut vault = test_vault();
        let meta = test_meta().with_expires_at(1000);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta, "a", 100).unwrap();
        let status = vault.check_expiration(&SecretId::new("k1"), 800, 3600).unwrap();
        assert!(status.is_expiring_soon());
    }

    #[test]
    fn test_check_expiration_expired() {
        let mut vault = test_vault();
        let meta = test_meta().with_expires_at(500);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta, "a", 100).unwrap();
        let status = vault.check_expiration(&SecretId::new("k1"), 600, 3600).unwrap();
        assert!(status.is_expired());
    }

    #[test]
    fn test_expired_secrets() {
        let mut vault = test_vault();
        let meta1 = test_meta().with_expires_at(500);
        let meta2 = test_meta().with_expires_at(10000);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta1, "a", 100).unwrap();
        vault.store(SecretId::new("k2"), SecretValue::from_str("v"), meta2, "a", 100).unwrap();
        let expired = vault.expired_secrets(600);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut vault = test_vault();
        let meta = test_meta().with_expires_at(500);
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), meta, "a", 100).unwrap();
        let count = vault.cleanup_expired("system", 600);
        assert_eq!(count, 1);
        // After cleanup, state should be Expired
        let h = vault.health();
        assert_eq!(h.expired, 1);
    }

    #[test]
    fn test_access_count() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 100).unwrap();
        assert_eq!(vault.access_count(&SecretId::new("k1")).unwrap(), 0);
        vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 200).unwrap();
        assert_eq!(vault.access_count(&SecretId::new("k1")).unwrap(), 1);
        vault.retrieve(&SecretId::new("k1"), &admin_policy(), "u", 300).unwrap();
        assert_eq!(vault.access_count(&SecretId::new("k1")).unwrap(), 2);
    }

    #[test]
    fn test_last_accessed() {
        let mut vault = test_vault();
        vault.store(SecretId::new("k1"), SecretValue::from_str("v"), test_meta(), "a", 100).unwrap();
        let ts = vault.last_accessed(&SecretId::new("k1")).unwrap();
        assert_eq!(ts, 100);
    }

    #[test]
    fn test_expiration_status_display() {
        assert_eq!(ExpirationStatus::NoExpiry.to_string(), "no expiry");
        assert!(ExpirationStatus::Expired { expired_at: 100 }.to_string().contains("100"));
        assert!(ExpirationStatus::ExpiringSoon { expires_at: 200, seconds_remaining: 50 }
            .to_string().contains("50"));
    }

    #[test]
    fn test_vault_access_policy_bell_lapadula() {
        let policy = VaultAccessPolicy::new(ClassificationLevel::Confidential);
        assert!(policy.can_access(&ClassificationLevel::Public));
        assert!(policy.can_access(&ClassificationLevel::Internal));
        assert!(policy.can_access(&ClassificationLevel::Confidential));
        assert!(!policy.can_access(&ClassificationLevel::Restricted));
        assert!(!policy.can_access(&ClassificationLevel::TopSecret));
    }
}
