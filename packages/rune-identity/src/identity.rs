// ═══════════════════════════════════════════════════════════════════════
// Core Identity Type — IdentityId, Identity, IdentityStore
//
// Every entity that interacts with a RUNE-governed system has an Identity.
// Users, services, devices, AI agents — all represented uniformly.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use rune_permissions::ClassificationLevel;

use crate::error::IdentityError;
use crate::identity_type::IdentityType;

// ── IdentityId ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(String);

impl IdentityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn namespace(&self) -> &str {
        self.0.split(':').next().unwrap_or(&self.0)
    }

    pub fn local_part(&self) -> &str {
        match self.0.find(':') {
            Some(i) => &self.0[i + 1..],
            None => "",
        }
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── IdentityStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    Active,
    Suspended,
    Locked,
    PendingVerification,
    Revoked,
    Expired,
}

impl IdentityStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active | Self::PendingVerification)
    }
}

impl fmt::Display for IdentityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Identity ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: IdentityId,
    pub identity_type: IdentityType,
    pub display_name: String,
    pub email: Option<String>,
    pub organization: Option<String>,
    pub clearance: ClassificationLevel,
    pub status: IdentityStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_authenticated_at: Option<i64>,
    pub authentication_count: u64,
    pub metadata: HashMap<String, String>,
    pub tags: Vec<String>,
}

// ── Identity builder ──────────────────────────────────────────────────

pub struct IdentityBuilder {
    id: IdentityId,
    identity_type: IdentityType,
    display_name: String,
    email: Option<String>,
    organization: Option<String>,
    clearance: ClassificationLevel,
    tags: Vec<String>,
    metadata: HashMap<String, String>,
    created_at: i64,
}

impl IdentityBuilder {
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    pub fn clearance(mut self, level: ClassificationLevel) -> Self {
        self.clearance = level;
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn created_at(mut self, ts: i64) -> Self {
        self.created_at = ts;
        self
    }

    pub fn build(self) -> Identity {
        Identity {
            id: self.id,
            identity_type: self.identity_type,
            display_name: self.display_name,
            email: self.email,
            organization: self.organization,
            clearance: self.clearance,
            status: IdentityStatus::Active,
            created_at: self.created_at,
            updated_at: self.created_at,
            last_authenticated_at: None,
            authentication_count: 0,
            metadata: self.metadata,
            tags: self.tags,
        }
    }
}

impl Identity {
    pub fn new(id: IdentityId, identity_type: IdentityType) -> IdentityBuilder {
        IdentityBuilder {
            id,
            identity_type,
            display_name: String::new(),
            email: None,
            organization: None,
            clearance: ClassificationLevel::Internal,
            tags: Vec::new(),
            metadata: HashMap::new(),
            created_at: 0,
        }
    }

    pub fn suspend(&mut self, _reason: &str) -> Result<(), IdentityError> {
        match self.status {
            IdentityStatus::Active | IdentityStatus::PendingVerification => {
                self.status = IdentityStatus::Suspended;
                Ok(())
            }
            _ => Err(IdentityError::InvalidTransition {
                from: self.status.to_string(),
                to: "Suspended".into(),
            }),
        }
    }

    pub fn lock(&mut self, _reason: &str) -> Result<(), IdentityError> {
        match self.status {
            IdentityStatus::Active | IdentityStatus::Suspended => {
                self.status = IdentityStatus::Locked;
                Ok(())
            }
            _ => Err(IdentityError::InvalidTransition {
                from: self.status.to_string(),
                to: "Locked".into(),
            }),
        }
    }

    pub fn reactivate(&mut self) -> Result<(), IdentityError> {
        match self.status {
            IdentityStatus::Suspended | IdentityStatus::Locked => {
                self.status = IdentityStatus::Active;
                Ok(())
            }
            _ => Err(IdentityError::InvalidTransition {
                from: self.status.to_string(),
                to: "Active".into(),
            }),
        }
    }

    pub fn revoke(&mut self, _reason: &str) -> Result<(), IdentityError> {
        if self.status == IdentityStatus::Revoked {
            return Err(IdentityError::InvalidTransition {
                from: "Revoked".into(),
                to: "Revoked".into(),
            });
        }
        self.status = IdentityStatus::Revoked;
        Ok(())
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.status == IdentityStatus::Expired
            || self.metadata.get("expires_at")
                .and_then(|v| v.parse::<i64>().ok())
                .is_some_and(|exp| now >= exp)
    }

    pub fn record_authentication(&mut self, now: i64) {
        self.last_authenticated_at = Some(now);
        self.authentication_count += 1;
        self.updated_at = now;
    }

    pub fn age_ms(&self, now: i64) -> i64 {
        now - self.created_at
    }
}

// ── IdentityStore ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct IdentityStore {
    identities: HashMap<IdentityId, Identity>,
}

impl IdentityStore {
    pub fn new() -> Self {
        Self { identities: HashMap::new() }
    }

    pub fn register(&mut self, identity: Identity) -> Result<(), IdentityError> {
        if self.identities.contains_key(&identity.id) {
            return Err(IdentityError::IdentityAlreadyExists(identity.id.clone()));
        }
        self.identities.insert(identity.id.clone(), identity);
        Ok(())
    }

    pub fn get(&self, id: &IdentityId) -> Option<&Identity> {
        self.identities.get(id)
    }

    pub fn get_mut(&mut self, id: &IdentityId) -> Option<&mut Identity> {
        self.identities.get_mut(id)
    }

    pub fn find_by_email(&self, email: &str) -> Option<&Identity> {
        self.identities.values().find(|i| i.email.as_deref() == Some(email))
    }

    pub fn list(&self) -> Vec<&Identity> {
        self.identities.values().collect()
    }

    pub fn list_by_type(&self, type_name: &str) -> Vec<&Identity> {
        self.identities.values()
            .filter(|i| i.identity_type.type_name() == type_name)
            .collect()
    }

    pub fn list_by_status(&self, status: &IdentityStatus) -> Vec<&Identity> {
        self.identities.values()
            .filter(|i| &i.status == status)
            .collect()
    }

    pub fn list_by_organization(&self, org: &str) -> Vec<&Identity> {
        self.identities.values()
            .filter(|i| i.organization.as_deref() == Some(org))
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.identities.values().filter(|i| i.status.is_active()).count()
    }

    pub fn deactivate(&mut self, id: &IdentityId, reason: &str) -> Result<(), IdentityError> {
        let identity = self.identities.get_mut(id)
            .ok_or_else(|| IdentityError::IdentityNotFound(id.clone()))?;
        identity.suspend(reason)
    }

    pub fn remove(&mut self, id: &IdentityId) -> Result<Identity, IdentityError> {
        self.identities.remove(id)
            .ok_or_else(|| IdentityError::IdentityNotFound(id.clone()))
    }

    pub fn count(&self) -> usize {
        self.identities.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Identity {
        Identity::new(IdentityId::new("user:alice"), IdentityType::default_user())
            .display_name("Alice")
            .email("alice@example.com")
            .organization("Odin's LLC")
            .clearance(ClassificationLevel::Confidential)
            .tag("department:engineering")
            .created_at(1000)
            .build()
    }

    #[test]
    fn test_identity_id_new_and_display() {
        let id = IdentityId::new("user:dr-rose");
        assert_eq!(id.as_str(), "user:dr-rose");
        assert_eq!(id.to_string(), "user:dr-rose");
    }

    #[test]
    fn test_identity_id_namespace() {
        assert_eq!(IdentityId::new("user:dr-rose").namespace(), "user");
        assert_eq!(IdentityId::new("service:aegis-v2").namespace(), "service");
        assert_eq!(IdentityId::new("nocolon").namespace(), "nocolon");
    }

    #[test]
    fn test_identity_id_local_part() {
        assert_eq!(IdentityId::new("user:dr-rose").local_part(), "dr-rose");
        assert_eq!(IdentityId::new("device:lanner-p375-001").local_part(), "lanner-p375-001");
        assert_eq!(IdentityId::new("nocolon").local_part(), "");
    }

    #[test]
    fn test_identity_builder_all_fields() {
        let id = alice();
        assert_eq!(id.display_name, "Alice");
        assert_eq!(id.email.as_deref(), Some("alice@example.com"));
        assert_eq!(id.organization.as_deref(), Some("Odin's LLC"));
        assert_eq!(id.clearance, ClassificationLevel::Confidential);
        assert_eq!(id.tags, vec!["department:engineering"]);
        assert_eq!(id.created_at, 1000);
        assert_eq!(id.status, IdentityStatus::Active);
        assert_eq!(id.authentication_count, 0);
    }

    #[test]
    fn test_identity_builder_minimal() {
        let id = Identity::new(IdentityId::new("service:svc"), IdentityType::default_service())
            .build();
        assert_eq!(id.clearance, ClassificationLevel::Internal);
        assert!(id.email.is_none());
        assert!(id.tags.is_empty());
    }

    #[test]
    fn test_identity_status_is_active() {
        assert!(IdentityStatus::Active.is_active());
        assert!(!IdentityStatus::Suspended.is_active());
        assert!(!IdentityStatus::Locked.is_active());
    }

    #[test]
    fn test_identity_status_can_authenticate() {
        assert!(IdentityStatus::Active.can_authenticate());
        assert!(IdentityStatus::PendingVerification.can_authenticate());
        assert!(!IdentityStatus::Suspended.can_authenticate());
        assert!(!IdentityStatus::Locked.can_authenticate());
        assert!(!IdentityStatus::Revoked.can_authenticate());
    }

    #[test]
    fn test_identity_suspend_and_reactivate() {
        let mut id = alice();
        assert!(id.suspend("test").is_ok());
        assert_eq!(id.status, IdentityStatus::Suspended);
        assert!(id.reactivate().is_ok());
        assert_eq!(id.status, IdentityStatus::Active);
    }

    #[test]
    fn test_identity_lock() {
        let mut id = alice();
        assert!(id.lock("security incident").is_ok());
        assert_eq!(id.status, IdentityStatus::Locked);
        assert!(id.reactivate().is_ok());
    }

    #[test]
    fn test_identity_revoke_terminal() {
        let mut id = alice();
        assert!(id.revoke("terminated").is_ok());
        assert_eq!(id.status, IdentityStatus::Revoked);
        // Cannot reactivate from revoked
        assert!(id.reactivate().is_err());
        // Cannot revoke again
        assert!(id.revoke("again").is_err());
    }

    #[test]
    fn test_identity_record_authentication() {
        let mut id = alice();
        id.record_authentication(2000);
        assert_eq!(id.authentication_count, 1);
        assert_eq!(id.last_authenticated_at, Some(2000));
        id.record_authentication(3000);
        assert_eq!(id.authentication_count, 2);
    }

    #[test]
    fn test_identity_age_ms() {
        let id = alice();
        assert_eq!(id.age_ms(2000), 1000);
    }

    #[test]
    fn test_identity_store_register_and_get() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        assert_eq!(store.count(), 1);
        assert!(store.get(&IdentityId::new("user:alice")).is_some());
    }

    #[test]
    fn test_identity_store_duplicate() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        assert!(store.register(alice()).is_err());
    }

    #[test]
    fn test_identity_store_find_by_email() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        let found = store.find_by_email("alice@example.com");
        assert!(found.is_some());
        assert!(store.find_by_email("bob@example.com").is_none());
    }

    #[test]
    fn test_identity_store_list_by_type() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        let svc = Identity::new(IdentityId::new("service:svc1"), IdentityType::default_service())
            .build();
        store.register(svc).unwrap();
        assert_eq!(store.list_by_type("User").len(), 1);
        assert_eq!(store.list_by_type("Service").len(), 1);
    }

    #[test]
    fn test_identity_store_list_by_status() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        assert_eq!(store.list_by_status(&IdentityStatus::Active).len(), 1);
        assert_eq!(store.list_by_status(&IdentityStatus::Suspended).len(), 0);
    }

    #[test]
    fn test_identity_store_list_by_organization() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        assert_eq!(store.list_by_organization("Odin's LLC").len(), 1);
        assert_eq!(store.list_by_organization("Other").len(), 0);
    }

    #[test]
    fn test_identity_store_deactivate() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        store.deactivate(&IdentityId::new("user:alice"), "test").unwrap();
        let id = store.get(&IdentityId::new("user:alice")).unwrap();
        assert_eq!(id.status, IdentityStatus::Suspended);
    }

    #[test]
    fn test_identity_store_remove() {
        let mut store = IdentityStore::new();
        store.register(alice()).unwrap();
        let removed = store.remove(&IdentityId::new("user:alice")).unwrap();
        assert_eq!(removed.display_name, "Alice");
        assert_eq!(store.count(), 0);
    }
}
