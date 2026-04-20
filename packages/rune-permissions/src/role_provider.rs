// ═══════════════════════════════════════════════════════════════════════
// Role Provider — External role membership data source.
//
// Layer 3 defines how external role membership data (LDAP groups,
// AD groups, SCIM role assignments) flows into rune-permissions.
// CachedRoleProvider is a first-class architectural component because
// role lookups against external directories are the classic
// performance bottleneck in authorization systems.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::{IdentityRef, RoleRef};
use crate::error::PermissionError;

// ── RoleProvider trait ───────────────────────────────────────

pub trait RoleProvider {
    fn get_roles_for_identity(&self, identity: &IdentityRef) -> Result<Vec<RoleRef>, PermissionError>;
    fn list_all_roles(&self) -> Result<Vec<RoleRef>, PermissionError>;
    fn role_exists(&self, role: &RoleRef) -> Result<bool, PermissionError>;
    fn is_member(&self, identity: &IdentityRef, role: &RoleRef) -> Result<bool, PermissionError>;
    fn provider_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryRoleProvider ─────────────────────────────────────

pub struct InMemoryRoleProvider {
    id: String,
    memberships: HashMap<String, Vec<RoleRef>>,
    all_roles: Vec<RoleRef>,
    active: bool,
}

impl InMemoryRoleProvider {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            memberships: HashMap::new(),
            all_roles: Vec::new(),
            active: true,
        }
    }

    pub fn add_role(&mut self, role: RoleRef) {
        if !self.all_roles.contains(&role) {
            self.all_roles.push(role);
        }
    }

    pub fn assign_role(&mut self, identity: &IdentityRef, role: RoleRef) {
        self.add_role(role.clone());
        self.memberships
            .entry(identity.as_str().to_string())
            .or_default()
            .push(role);
    }
}

impl RoleProvider for InMemoryRoleProvider {
    fn get_roles_for_identity(&self, identity: &IdentityRef) -> Result<Vec<RoleRef>, PermissionError> {
        Ok(self.memberships
            .get(identity.as_str())
            .cloned()
            .unwrap_or_default())
    }

    fn list_all_roles(&self) -> Result<Vec<RoleRef>, PermissionError> {
        Ok(self.all_roles.clone())
    }

    fn role_exists(&self, role: &RoleRef) -> Result<bool, PermissionError> {
        Ok(self.all_roles.contains(role))
    }

    fn is_member(&self, identity: &IdentityRef, role: &RoleRef) -> Result<bool, PermissionError> {
        Ok(self.memberships
            .get(identity.as_str())
            .is_some_and(|roles| roles.contains(role)))
    }

    fn provider_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── CacheEntry ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    roles: Vec<RoleRef>,
    cached_at: i64,
    ttl_seconds: i64,
}

impl CacheEntry {
    fn is_valid(&self, now: i64) -> bool {
        now - self.cached_at < self.ttl_seconds
    }
}

// ── CachedRoleProvider ───────────────────────────────────────

pub struct CachedRoleProvider {
    id: String,
    inner: Box<dyn RoleProvider>,
    cache: std::cell::RefCell<HashMap<String, CacheEntry>>,
    ttl_seconds: i64,
    now_fn: Box<dyn Fn() -> i64>,
}

impl CachedRoleProvider {
    pub fn new(id: &str, inner: Box<dyn RoleProvider>, ttl_seconds: i64) -> Self {
        Self {
            id: id.to_string(),
            inner,
            cache: std::cell::RefCell::new(HashMap::new()),
            ttl_seconds,
            now_fn: Box::new(|| 0),
        }
    }

    pub fn with_clock(mut self, now_fn: impl Fn() -> i64 + 'static) -> Self {
        self.now_fn = Box::new(now_fn);
        self
    }

    pub fn cache_size(&self) -> usize {
        self.cache.borrow().len()
    }

    pub fn invalidate(&self, identity: &IdentityRef) {
        self.cache.borrow_mut().remove(identity.as_str());
    }

    pub fn invalidate_all(&self) {
        self.cache.borrow_mut().clear();
    }
}

impl RoleProvider for CachedRoleProvider {
    fn get_roles_for_identity(&self, identity: &IdentityRef) -> Result<Vec<RoleRef>, PermissionError> {
        let now = (self.now_fn)();
        let key = identity.as_str().to_string();

        if let Some(entry) = self.cache.borrow().get(&key) {
            if entry.is_valid(now) {
                return Ok(entry.roles.clone());
            }
        }

        let roles = self.inner.get_roles_for_identity(identity)?;
        self.cache.borrow_mut().insert(key, CacheEntry {
            roles: roles.clone(),
            cached_at: now,
            ttl_seconds: self.ttl_seconds,
        });
        Ok(roles)
    }

    fn list_all_roles(&self) -> Result<Vec<RoleRef>, PermissionError> {
        self.inner.list_all_roles()
    }

    fn role_exists(&self, role: &RoleRef) -> Result<bool, PermissionError> {
        self.inner.role_exists(role)
    }

    fn is_member(&self, identity: &IdentityRef, role: &RoleRef) -> Result<bool, PermissionError> {
        let roles = self.get_roles_for_identity(identity)?;
        Ok(roles.contains(role))
    }

    fn provider_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_provider_assign_and_query() {
        let mut provider = InMemoryRoleProvider::new("mem-1");
        let identity = IdentityRef::new("alice");
        provider.assign_role(&identity, RoleRef::new("admin"));
        provider.assign_role(&identity, RoleRef::new("viewer"));

        let roles = provider.get_roles_for_identity(&identity).unwrap();
        assert_eq!(roles.len(), 2);
    }

    #[test]
    fn test_in_memory_provider_is_member() {
        let mut provider = InMemoryRoleProvider::new("mem-1");
        let identity = IdentityRef::new("alice");
        provider.assign_role(&identity, RoleRef::new("admin"));

        assert!(provider.is_member(&identity, &RoleRef::new("admin")).unwrap());
        assert!(!provider.is_member(&identity, &RoleRef::new("viewer")).unwrap());
    }

    #[test]
    fn test_in_memory_provider_list_all_roles() {
        let mut provider = InMemoryRoleProvider::new("mem-1");
        provider.add_role(RoleRef::new("admin"));
        provider.add_role(RoleRef::new("viewer"));
        provider.add_role(RoleRef::new("admin")); // duplicate
        assert_eq!(provider.list_all_roles().unwrap().len(), 2);
    }

    #[test]
    fn test_in_memory_provider_role_exists() {
        let mut provider = InMemoryRoleProvider::new("mem-1");
        provider.add_role(RoleRef::new("admin"));
        assert!(provider.role_exists(&RoleRef::new("admin")).unwrap());
        assert!(!provider.role_exists(&RoleRef::new("nonexistent")).unwrap());
    }

    #[test]
    fn test_in_memory_provider_no_roles() {
        let provider = InMemoryRoleProvider::new("mem-1");
        let roles = provider.get_roles_for_identity(&IdentityRef::new("nobody")).unwrap();
        assert!(roles.is_empty());
    }

    #[test]
    fn test_cached_provider_caches_result() {
        let mut inner = InMemoryRoleProvider::new("inner");
        inner.assign_role(&IdentityRef::new("alice"), RoleRef::new("admin"));
        let cached = CachedRoleProvider::new("cached-1", Box::new(inner), 60)
            .with_clock(|| 100);

        // First call populates cache
        let roles = cached.get_roles_for_identity(&IdentityRef::new("alice")).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(cached.cache_size(), 1);

        // Second call hits cache
        let roles2 = cached.get_roles_for_identity(&IdentityRef::new("alice")).unwrap();
        assert_eq!(roles2.len(), 1);
    }

    #[test]
    fn test_cached_provider_is_member() {
        let mut inner = InMemoryRoleProvider::new("inner");
        inner.assign_role(&IdentityRef::new("alice"), RoleRef::new("admin"));
        let cached = CachedRoleProvider::new("cached-1", Box::new(inner), 60);

        assert!(cached.is_member(&IdentityRef::new("alice"), &RoleRef::new("admin")).unwrap());
        assert!(!cached.is_member(&IdentityRef::new("alice"), &RoleRef::new("viewer")).unwrap());
    }

    #[test]
    fn test_cached_provider_invalidate() {
        let mut inner = InMemoryRoleProvider::new("inner");
        inner.assign_role(&IdentityRef::new("alice"), RoleRef::new("admin"));
        let cached = CachedRoleProvider::new("cached-1", Box::new(inner), 60);

        cached.get_roles_for_identity(&IdentityRef::new("alice")).unwrap();
        assert_eq!(cached.cache_size(), 1);

        cached.invalidate(&IdentityRef::new("alice"));
        assert_eq!(cached.cache_size(), 0);
    }

    #[test]
    fn test_cached_provider_invalidate_all() {
        let mut inner = InMemoryRoleProvider::new("inner");
        inner.assign_role(&IdentityRef::new("alice"), RoleRef::new("admin"));
        inner.assign_role(&IdentityRef::new("bob"), RoleRef::new("viewer"));
        let cached = CachedRoleProvider::new("cached-1", Box::new(inner), 60);

        cached.get_roles_for_identity(&IdentityRef::new("alice")).unwrap();
        cached.get_roles_for_identity(&IdentityRef::new("bob")).unwrap();
        assert_eq!(cached.cache_size(), 2);

        cached.invalidate_all();
        assert_eq!(cached.cache_size(), 0);
    }

    #[test]
    fn test_cached_provider_delegates_metadata() {
        let inner = InMemoryRoleProvider::new("inner");
        let cached = CachedRoleProvider::new("cached-1", Box::new(inner), 60);
        assert_eq!(cached.provider_id(), "cached-1");
        assert!(cached.is_active());
    }

    #[test]
    fn test_provider_id() {
        let provider = InMemoryRoleProvider::new("my-provider");
        assert_eq!(provider.provider_id(), "my-provider");
        assert!(provider.is_active());
    }
}
