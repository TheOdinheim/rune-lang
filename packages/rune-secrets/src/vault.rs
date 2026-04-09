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
