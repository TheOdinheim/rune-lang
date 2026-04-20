// ═══════════════════════════════════════════════════════════════════════
// Permission Backend — Pluggable permission storage trait.
//
// Layer 3 defines the contract for storing and retrieving policy
// definitions, role definitions, and permission grants. This
// separates the storage concern from the evaluation concern
// (handled by AuthorizationDecisionEngine).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::PermissionError;

// ── IdentityRef ──────────────────────────────────────────────

/// Opaque identity reference for Layer 3 trait boundaries.
/// Decouples rune-permissions from rune-identity's internal types.
/// Can be converted from rune-identity's IdentityId or from SubjectId.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityRef(String);

impl IdentityRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentityRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<crate::types::SubjectId> for IdentityRef {
    fn from(id: crate::types::SubjectId) -> Self {
        Self(id.as_str().to_string())
    }
}

// ── RoleRef ──────────────────────────────────────────────────

/// Opaque role reference for Layer 3 trait boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleRef(String);

impl RoleRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RoleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<crate::role::RoleId> for RoleRef {
    fn from(id: crate::role::RoleId) -> Self {
        Self(id.as_str().to_string())
    }
}

// ── StoredPolicyDefinition ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicyDefinition {
    pub policy_id: String,
    pub name: String,
    pub description: String,
    pub policy_type: String,
    pub rules_json: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub active: bool,
    pub metadata: HashMap<String, String>,
}

impl StoredPolicyDefinition {
    pub fn new(policy_id: &str, name: &str, policy_type: &str) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            name: name.to_string(),
            description: String::new(),
            policy_type: policy_type.to_string(),
            rules_json: String::new(),
            created_at: 0,
            updated_at: 0,
            active: true,
            metadata: HashMap::new(),
        }
    }
}

// ── StoredRoleDefinition ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRoleDefinition {
    pub role_id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub parent_roles: Vec<String>,
    pub created_at: i64,
    pub active: bool,
    pub metadata: HashMap<String, String>,
}

impl StoredRoleDefinition {
    pub fn new(role_id: &str, name: &str) -> Self {
        Self {
            role_id: role_id.to_string(),
            name: name.to_string(),
            description: String::new(),
            permissions: Vec::new(),
            parent_roles: Vec::new(),
            created_at: 0,
            active: true,
            metadata: HashMap::new(),
        }
    }
}

// ── PermissionGrantRecord ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrantRecord {
    pub grant_id: String,
    pub identity_ref: IdentityRef,
    pub permission: String,
    pub grantor: IdentityRef,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub metadata: HashMap<String, String>,
}

impl PermissionGrantRecord {
    pub fn new(
        grant_id: &str,
        identity_ref: IdentityRef,
        permission: &str,
        grantor: IdentityRef,
        granted_at: i64,
    ) -> Self {
        Self {
            grant_id: grant_id.to_string(),
            identity_ref,
            permission: permission.to_string(),
            grantor,
            granted_at,
            expires_at: None,
            revoked: false,
            metadata: HashMap::new(),
        }
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    pub fn with_expires_at(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

// ── BackendInfo ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionBackendInfo {
    pub backend_type: String,
    pub supports_policy_definitions: bool,
    pub supports_role_definitions: bool,
}

// ── PermissionBackend trait ──────────────────────────────────

pub trait PermissionBackend {
    fn store_policy_definition(&mut self, policy: &StoredPolicyDefinition) -> Result<(), PermissionError>;
    fn retrieve_policy_definition(&self, policy_id: &str) -> Option<&StoredPolicyDefinition>;
    fn delete_policy_definition(&mut self, policy_id: &str) -> Result<bool, PermissionError>;
    fn list_policy_definitions(&self) -> Vec<&StoredPolicyDefinition>;
    fn policy_definition_count(&self) -> usize;
    fn policy_definition_exists(&self, policy_id: &str) -> bool;

    fn store_role_definition(&mut self, role: &StoredRoleDefinition) -> Result<(), PermissionError>;
    fn retrieve_role_definition(&self, role_id: &str) -> Option<&StoredRoleDefinition>;
    fn list_role_definitions(&self) -> Vec<&StoredRoleDefinition>;
    fn delete_role_definition(&mut self, role_id: &str) -> Result<bool, PermissionError>;

    fn store_permission_grant(&mut self, grant: &PermissionGrantRecord) -> Result<(), PermissionError>;
    fn retrieve_permission_grant(&self, grant_id: &str) -> Option<&PermissionGrantRecord>;
    fn list_permission_grants_for_identity(&self, identity: &IdentityRef) -> Vec<&PermissionGrantRecord>;
    fn list_permission_grants_for_role(&self, role_id: &str) -> Vec<&PermissionGrantRecord>;
    fn revoke_permission_grant(&mut self, grant_id: &str) -> Result<bool, PermissionError>;

    fn flush(&mut self);
    fn backend_info(&self) -> PermissionBackendInfo;
}

// ── InMemoryPermissionBackend ────────────────────────────────

pub struct InMemoryPermissionBackend {
    policies: HashMap<String, StoredPolicyDefinition>,
    roles: HashMap<String, StoredRoleDefinition>,
    grants: HashMap<String, PermissionGrantRecord>,
}

impl InMemoryPermissionBackend {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            roles: HashMap::new(),
            grants: HashMap::new(),
        }
    }
}

impl Default for InMemoryPermissionBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionBackend for InMemoryPermissionBackend {
    fn store_policy_definition(&mut self, policy: &StoredPolicyDefinition) -> Result<(), PermissionError> {
        self.policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_policy_definition(&self, policy_id: &str) -> Option<&StoredPolicyDefinition> {
        self.policies.get(policy_id)
    }

    fn delete_policy_definition(&mut self, policy_id: &str) -> Result<bool, PermissionError> {
        Ok(self.policies.remove(policy_id).is_some())
    }

    fn list_policy_definitions(&self) -> Vec<&StoredPolicyDefinition> {
        self.policies.values().collect()
    }

    fn policy_definition_count(&self) -> usize {
        self.policies.len()
    }

    fn policy_definition_exists(&self, policy_id: &str) -> bool {
        self.policies.contains_key(policy_id)
    }

    fn store_role_definition(&mut self, role: &StoredRoleDefinition) -> Result<(), PermissionError> {
        self.roles.insert(role.role_id.clone(), role.clone());
        Ok(())
    }

    fn retrieve_role_definition(&self, role_id: &str) -> Option<&StoredRoleDefinition> {
        self.roles.get(role_id)
    }

    fn list_role_definitions(&self) -> Vec<&StoredRoleDefinition> {
        self.roles.values().collect()
    }

    fn delete_role_definition(&mut self, role_id: &str) -> Result<bool, PermissionError> {
        Ok(self.roles.remove(role_id).is_some())
    }

    fn store_permission_grant(&mut self, grant: &PermissionGrantRecord) -> Result<(), PermissionError> {
        self.grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(())
    }

    fn retrieve_permission_grant(&self, grant_id: &str) -> Option<&PermissionGrantRecord> {
        self.grants.get(grant_id)
    }

    fn list_permission_grants_for_identity(&self, identity: &IdentityRef) -> Vec<&PermissionGrantRecord> {
        self.grants.values()
            .filter(|g| g.identity_ref == *identity && !g.revoked)
            .collect()
    }

    fn list_permission_grants_for_role(&self, role_id: &str) -> Vec<&PermissionGrantRecord> {
        self.grants.values()
            .filter(|g| g.permission.starts_with(&format!("role:{role_id}:")) && !g.revoked)
            .collect()
    }

    fn revoke_permission_grant(&mut self, grant_id: &str) -> Result<bool, PermissionError> {
        if let Some(grant) = self.grants.get_mut(grant_id) {
            grant.revoked = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn flush(&mut self) {
        self.policies.clear();
        self.roles.clear();
        self.grants.clear();
    }

    fn backend_info(&self) -> PermissionBackendInfo {
        PermissionBackendInfo {
            backend_type: "in-memory".to_string(),
            supports_policy_definitions: true,
            supports_role_definitions: true,
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
    fn test_identity_ref() {
        let r = IdentityRef::new("user:alice");
        assert_eq!(r.as_str(), "user:alice");
        assert_eq!(r.to_string(), "user:alice");
    }

    #[test]
    fn test_role_ref() {
        let r = RoleRef::new("admin");
        assert_eq!(r.as_str(), "admin");
    }

    #[test]
    fn test_identity_ref_from_subject_id() {
        let sid = crate::types::SubjectId::new("user:bob");
        let iref: IdentityRef = sid.into();
        assert_eq!(iref.as_str(), "user:bob");
    }

    #[test]
    fn test_store_and_retrieve_policy() {
        let mut backend = InMemoryPermissionBackend::new();
        let policy = StoredPolicyDefinition::new("pol-1", "Read Policy", "rbac");
        backend.store_policy_definition(&policy).unwrap();
        let retrieved = backend.retrieve_policy_definition("pol-1").unwrap();
        assert_eq!(retrieved.name, "Read Policy");
        assert!(backend.policy_definition_exists("pol-1"));
        assert_eq!(backend.policy_definition_count(), 1);
    }

    #[test]
    fn test_delete_policy() {
        let mut backend = InMemoryPermissionBackend::new();
        backend.store_policy_definition(&StoredPolicyDefinition::new("pol-1", "P", "rbac")).unwrap();
        assert!(backend.delete_policy_definition("pol-1").unwrap());
        assert!(!backend.delete_policy_definition("pol-1").unwrap());
    }

    #[test]
    fn test_list_policies() {
        let mut backend = InMemoryPermissionBackend::new();
        backend.store_policy_definition(&StoredPolicyDefinition::new("p1", "A", "rbac")).unwrap();
        backend.store_policy_definition(&StoredPolicyDefinition::new("p2", "B", "abac")).unwrap();
        assert_eq!(backend.list_policy_definitions().len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_role_definition() {
        let mut backend = InMemoryPermissionBackend::new();
        let role = StoredRoleDefinition::new("admin", "Administrator");
        backend.store_role_definition(&role).unwrap();
        let retrieved = backend.retrieve_role_definition("admin").unwrap();
        assert_eq!(retrieved.name, "Administrator");
    }

    #[test]
    fn test_delete_role_definition() {
        let mut backend = InMemoryPermissionBackend::new();
        backend.store_role_definition(&StoredRoleDefinition::new("r1", "R")).unwrap();
        assert!(backend.delete_role_definition("r1").unwrap());
        assert!(!backend.delete_role_definition("r1").unwrap());
    }

    #[test]
    fn test_permission_grant_store_and_retrieve() {
        let mut backend = InMemoryPermissionBackend::new();
        let grant = PermissionGrantRecord::new(
            "g-1",
            IdentityRef::new("user:alice"),
            "file:read",
            IdentityRef::new("admin"),
            1000,
        );
        backend.store_permission_grant(&grant).unwrap();
        let retrieved = backend.retrieve_permission_grant("g-1").unwrap();
        assert_eq!(retrieved.permission, "file:read");
    }

    #[test]
    fn test_grants_for_identity() {
        let mut backend = InMemoryPermissionBackend::new();
        backend.store_permission_grant(&PermissionGrantRecord::new(
            "g-1", IdentityRef::new("alice"), "file:read", IdentityRef::new("admin"), 1000,
        )).unwrap();
        backend.store_permission_grant(&PermissionGrantRecord::new(
            "g-2", IdentityRef::new("alice"), "file:write", IdentityRef::new("admin"), 1000,
        )).unwrap();
        backend.store_permission_grant(&PermissionGrantRecord::new(
            "g-3", IdentityRef::new("bob"), "file:read", IdentityRef::new("admin"), 1000,
        )).unwrap();
        assert_eq!(backend.list_permission_grants_for_identity(&IdentityRef::new("alice")).len(), 2);
    }

    #[test]
    fn test_revoke_grant() {
        let mut backend = InMemoryPermissionBackend::new();
        backend.store_permission_grant(&PermissionGrantRecord::new(
            "g-1", IdentityRef::new("alice"), "perm", IdentityRef::new("admin"), 1000,
        )).unwrap();
        assert!(backend.revoke_permission_grant("g-1").unwrap());
        assert_eq!(backend.list_permission_grants_for_identity(&IdentityRef::new("alice")).len(), 0);
    }

    #[test]
    fn test_grant_expiry() {
        let grant = PermissionGrantRecord::new(
            "g-1", IdentityRef::new("alice"), "perm", IdentityRef::new("admin"), 1000,
        ).with_expires_at(5000);
        assert!(!grant.is_expired(3000));
        assert!(grant.is_expired(5000));
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryPermissionBackend::new();
        backend.store_policy_definition(&StoredPolicyDefinition::new("p", "P", "t")).unwrap();
        backend.store_role_definition(&StoredRoleDefinition::new("r", "R")).unwrap();
        backend.store_permission_grant(&PermissionGrantRecord::new(
            "g", IdentityRef::new("a"), "p", IdentityRef::new("b"), 0,
        )).unwrap();
        backend.flush();
        assert_eq!(backend.policy_definition_count(), 0);
        assert!(backend.list_role_definitions().is_empty());
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryPermissionBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(info.supports_policy_definitions);
        assert!(info.supports_role_definitions);
    }
}
