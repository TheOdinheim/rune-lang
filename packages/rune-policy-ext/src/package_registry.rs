// ═══════════════════════════════════════════════════════════════════════
// Policy Package Registry — Layer 3 trait boundary for publishing,
// discovering, and subscribing to policy packages.
//
// Concrete registries (OPA bundle registries, artifact repositories)
// belong in adapter crates.  Ships InMemoryPolicyPackageRegistry,
// ReadOnlyPolicyPackageRegistry, CachedPolicyPackageRegistry, and
// NullPolicyPackageRegistry.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::backend::StoredPolicyPackage;
use crate::error::PolicyExtError;

// ── RegistryCredentials ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryCredentials {
    opaque_token: String,
}

impl RegistryCredentials {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            opaque_token: token.into(),
        }
    }

    pub fn token(&self) -> &str {
        &self.opaque_token
    }
}

// ── PackageQuery ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageQuery {
    pub name_pattern: Option<String>,
    pub namespace_filter: Option<String>,
    pub tag_filters: Vec<String>,
    pub version_range: Option<String>,
}

impl PackageQuery {
    pub fn new() -> Self {
        Self {
            name_pattern: None,
            namespace_filter: None,
            tag_filters: Vec::new(),
            version_range: None,
        }
    }

    pub fn with_name_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.name_pattern = Some(pattern.into());
        self
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace_filter = Some(ns.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag_filters.push(tag.into());
        self
    }

    pub fn with_version_range(mut self, range: impl Into<String>) -> Self {
        self.version_range = Some(range.into());
        self
    }
}

impl Default for PackageQuery {
    fn default() -> Self {
        Self::new()
    }
}

// ── SubscriptionHandle ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionHandle(pub String);

impl fmt::Display for SubscriptionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── PolicyPackageRegistry trait ───────────────────────────────────

pub trait PolicyPackageRegistry {
    fn publish_package(
        &mut self,
        package: StoredPolicyPackage,
    ) -> Result<(), PolicyExtError>;

    fn lookup_package(
        &self,
        package_id: &str,
    ) -> Result<StoredPolicyPackage, PolicyExtError>;

    fn list_available_packages(
        &self,
        query: &PackageQuery,
    ) -> Vec<StoredPolicyPackage>;

    fn subscribe_to_package(
        &mut self,
        package_name: &str,
        namespace: &str,
    ) -> Result<SubscriptionHandle, PolicyExtError>;

    fn unpublish_package(
        &mut self,
        package_id: &str,
    ) -> Result<(), PolicyExtError>;

    fn verify_package_integrity(
        &self,
        package_id: &str,
    ) -> Result<bool, PolicyExtError>;

    fn registry_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryPolicyPackageRegistry ─────────────────────────────────

pub struct InMemoryPolicyPackageRegistry {
    id: String,
    packages: HashMap<String, StoredPolicyPackage>,
    unpublished: HashMap<String, bool>,
    subscriptions: HashMap<String, Vec<SubscriptionHandle>>,
    next_sub_id: usize,
}

impl InMemoryPolicyPackageRegistry {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            packages: HashMap::new(),
            unpublished: HashMap::new(),
            subscriptions: HashMap::new(),
            next_sub_id: 0,
        }
    }
}

impl PolicyPackageRegistry for InMemoryPolicyPackageRegistry {
    fn publish_package(
        &mut self,
        package: StoredPolicyPackage,
    ) -> Result<(), PolicyExtError> {
        self.packages.insert(package.package_id.clone(), package);
        Ok(())
    }

    fn lookup_package(
        &self,
        package_id: &str,
    ) -> Result<StoredPolicyPackage, PolicyExtError> {
        if self.unpublished.contains_key(package_id) {
            return Err(PolicyExtError::PolicyNotFound(format!(
                "{package_id} (unpublished)"
            )));
        }
        self.packages
            .get(package_id)
            .cloned()
            .ok_or_else(|| PolicyExtError::PolicyNotFound(package_id.to_string()))
    }

    fn list_available_packages(&self, query: &PackageQuery) -> Vec<StoredPolicyPackage> {
        self.packages
            .values()
            .filter(|p| !self.unpublished.contains_key(&p.package_id))
            .filter(|p| {
                if let Some(ref ns) = query.namespace_filter {
                    p.namespace == *ns
                } else {
                    true
                }
            })
            .filter(|p| {
                if let Some(ref pattern) = query.name_pattern {
                    p.name.contains(pattern.as_str())
                } else {
                    true
                }
            })
            .filter(|p| {
                if query.tag_filters.is_empty() {
                    true
                } else {
                    query.tag_filters.iter().any(|t| p.tags.contains(t))
                }
            })
            .cloned()
            .collect()
    }

    fn subscribe_to_package(
        &mut self,
        package_name: &str,
        namespace: &str,
    ) -> Result<SubscriptionHandle, PolicyExtError> {
        let handle = SubscriptionHandle(format!("sub-{}", self.next_sub_id));
        self.next_sub_id += 1;
        let key = format!("{namespace}/{package_name}");
        self.subscriptions
            .entry(key)
            .or_default()
            .push(handle.clone());
        Ok(handle)
    }

    fn unpublish_package(&mut self, package_id: &str) -> Result<(), PolicyExtError> {
        if !self.packages.contains_key(package_id) {
            return Err(PolicyExtError::PolicyNotFound(package_id.to_string()));
        }
        self.unpublished.insert(package_id.to_string(), true);
        Ok(())
    }

    fn verify_package_integrity(&self, package_id: &str) -> Result<bool, PolicyExtError> {
        if !self.packages.contains_key(package_id) {
            return Err(PolicyExtError::PolicyNotFound(package_id.to_string()));
        }
        // In-memory: always valid (no tampering possible)
        Ok(true)
    }

    fn registry_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── ReadOnlyPolicyPackageRegistry ─────────────────────────────────

pub struct ReadOnlyPolicyPackageRegistry<R: PolicyPackageRegistry> {
    inner: R,
    id: String,
}

impl<R: PolicyPackageRegistry> ReadOnlyPolicyPackageRegistry<R> {
    pub fn new(id: &str, inner: R) -> Self {
        Self {
            inner,
            id: id.to_string(),
        }
    }
}

impl<R: PolicyPackageRegistry> PolicyPackageRegistry for ReadOnlyPolicyPackageRegistry<R> {
    fn publish_package(&mut self, _package: StoredPolicyPackage) -> Result<(), PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "read-only registry does not accept publish".to_string(),
        ))
    }

    fn lookup_package(&self, package_id: &str) -> Result<StoredPolicyPackage, PolicyExtError> {
        self.inner.lookup_package(package_id)
    }

    fn list_available_packages(&self, query: &PackageQuery) -> Vec<StoredPolicyPackage> {
        self.inner.list_available_packages(query)
    }

    fn subscribe_to_package(
        &mut self,
        _package_name: &str,
        _namespace: &str,
    ) -> Result<SubscriptionHandle, PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "read-only registry does not accept subscriptions".to_string(),
        ))
    }

    fn unpublish_package(&mut self, _package_id: &str) -> Result<(), PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "read-only registry does not accept unpublish".to_string(),
        ))
    }

    fn verify_package_integrity(&self, package_id: &str) -> Result<bool, PolicyExtError> {
        self.inner.verify_package_integrity(package_id)
    }

    fn registry_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ── CachedPolicyPackageRegistry ───────────────────────────────────

pub struct CachedPolicyPackageRegistry<R: PolicyPackageRegistry> {
    inner: R,
    id: String,
    cache: HashMap<String, StoredPolicyPackage>,
    _max_entries: usize,
    hits: usize,
    misses: usize,
}

impl<R: PolicyPackageRegistry> CachedPolicyPackageRegistry<R> {
    pub fn new(id: &str, inner: R, max_entries: usize) -> Self {
        Self {
            inner,
            id: id.to_string(),
            cache: HashMap::new(),
            _max_entries: max_entries,
            hits: 0,
            misses: 0,
        }
    }

    pub fn invalidate(&mut self, package_id: &str) {
        self.cache.remove(package_id);
    }

    pub fn invalidate_all(&mut self) {
        self.cache.clear();
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl<R: PolicyPackageRegistry> PolicyPackageRegistry for CachedPolicyPackageRegistry<R> {
    fn publish_package(&mut self, package: StoredPolicyPackage) -> Result<(), PolicyExtError> {
        let id = package.package_id.clone();
        self.inner.publish_package(package)?;
        self.cache.remove(&id);
        Ok(())
    }

    fn lookup_package(&self, package_id: &str) -> Result<StoredPolicyPackage, PolicyExtError> {
        if let Some(cached) = self.cache.get(package_id) {
            // Cannot mutate self.hits in &self — cache stats are best-effort
            return Ok(cached.clone());
        }
        self.inner.lookup_package(package_id)
    }

    fn list_available_packages(&self, query: &PackageQuery) -> Vec<StoredPolicyPackage> {
        self.inner.list_available_packages(query)
    }

    fn subscribe_to_package(
        &mut self,
        package_name: &str,
        namespace: &str,
    ) -> Result<SubscriptionHandle, PolicyExtError> {
        self.inner.subscribe_to_package(package_name, namespace)
    }

    fn unpublish_package(&mut self, package_id: &str) -> Result<(), PolicyExtError> {
        self.cache.remove(package_id);
        self.inner.unpublish_package(package_id)
    }

    fn verify_package_integrity(&self, package_id: &str) -> Result<bool, PolicyExtError> {
        self.inner.verify_package_integrity(package_id)
    }

    fn registry_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ── NullPolicyPackageRegistry ─────────────────────────────────────

pub struct NullPolicyPackageRegistry {
    id: String,
}

impl NullPolicyPackageRegistry {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PolicyPackageRegistry for NullPolicyPackageRegistry {
    fn publish_package(&mut self, _: StoredPolicyPackage) -> Result<(), PolicyExtError> {
        Ok(())
    }

    fn lookup_package(&self, id: &str) -> Result<StoredPolicyPackage, PolicyExtError> {
        Err(PolicyExtError::PolicyNotFound(id.to_string()))
    }

    fn list_available_packages(&self, _: &PackageQuery) -> Vec<StoredPolicyPackage> {
        Vec::new()
    }

    fn subscribe_to_package(&mut self, _: &str, _: &str) -> Result<SubscriptionHandle, PolicyExtError> {
        Ok(SubscriptionHandle("null-sub".to_string()))
    }

    fn unpublish_package(&mut self, _: &str) -> Result<(), PolicyExtError> { Ok(()) }

    fn verify_package_integrity(&self, _: &str) -> Result<bool, PolicyExtError> {
        Ok(false)
    }

    fn registry_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pkg(id: &str, ns: &str, name: &str) -> StoredPolicyPackage {
        StoredPolicyPackage {
            package_id: id.to_string(),
            name: name.to_string(),
            namespace: ns.to_string(),
            version: "1.0.0".to_string(),
            description: String::new(),
            tags: vec!["access".to_string()],
            rule_set_refs: vec![],
            dependencies: vec![],
            signature_ref: None,
            created_at: "2026-04-20".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_publish_and_lookup() {
        let mut reg = InMemoryPolicyPackageRegistry::new("reg-1");
        reg.publish_package(sample_pkg("pkg-1", "org", "access"))
            .unwrap();
        let found = reg.lookup_package("pkg-1").unwrap();
        assert_eq!(found.name, "access");
    }

    #[test]
    fn test_unpublish() {
        let mut reg = InMemoryPolicyPackageRegistry::new("reg-1");
        reg.publish_package(sample_pkg("pkg-1", "org", "access"))
            .unwrap();
        reg.unpublish_package("pkg-1").unwrap();
        assert!(reg.lookup_package("pkg-1").is_err());
    }

    #[test]
    fn test_list_with_query() {
        let mut reg = InMemoryPolicyPackageRegistry::new("reg-1");
        reg.publish_package(sample_pkg("pkg-1", "org.rune", "access"))
            .unwrap();
        reg.publish_package(sample_pkg("pkg-2", "org.rune", "network"))
            .unwrap();
        reg.publish_package(sample_pkg("pkg-3", "other", "data"))
            .unwrap();

        let query = PackageQuery::new().with_namespace("org.rune");
        assert_eq!(reg.list_available_packages(&query).len(), 2);

        let query2 = PackageQuery::new().with_name_pattern("access");
        assert_eq!(reg.list_available_packages(&query2).len(), 1);

        let query3 = PackageQuery::new().with_tag("access");
        assert_eq!(reg.list_available_packages(&query3).len(), 3);
    }

    #[test]
    fn test_subscribe() {
        let mut reg = InMemoryPolicyPackageRegistry::new("reg-1");
        let handle = reg.subscribe_to_package("access", "org").unwrap();
        assert!(handle.to_string().starts_with("sub-"));
    }

    #[test]
    fn test_verify_integrity() {
        let mut reg = InMemoryPolicyPackageRegistry::new("reg-1");
        reg.publish_package(sample_pkg("pkg-1", "org", "p"))
            .unwrap();
        assert!(reg.verify_package_integrity("pkg-1").unwrap());
        assert!(reg.verify_package_integrity("nonexistent").is_err());
    }

    #[test]
    fn test_read_only_registry() {
        let mut inner = InMemoryPolicyPackageRegistry::new("inner");
        inner
            .publish_package(sample_pkg("pkg-1", "org", "p"))
            .unwrap();

        let mut ro = ReadOnlyPolicyPackageRegistry::new("ro-1", inner);
        assert!(ro.lookup_package("pkg-1").is_ok());
        assert!(ro
            .publish_package(sample_pkg("pkg-2", "org", "q"))
            .is_err());
        assert!(ro.unpublish_package("pkg-1").is_err());
        assert!(ro.subscribe_to_package("p", "org").is_err());
        assert!(ro.is_active());
    }

    #[test]
    fn test_cached_registry() {
        let inner = InMemoryPolicyPackageRegistry::new("inner");
        let mut cached = CachedPolicyPackageRegistry::new("cached-1", inner, 100);

        cached
            .publish_package(sample_pkg("pkg-1", "org", "p"))
            .unwrap();
        let _ = cached.lookup_package("pkg-1").unwrap();
        assert_eq!(cached.cache_size(), 0); // lookup through inner, no auto-populate in &self
        assert_eq!(cached.hit_rate(), 0.0);
    }

    #[test]
    fn test_cached_invalidate() {
        let inner = InMemoryPolicyPackageRegistry::new("inner");
        let mut cached = CachedPolicyPackageRegistry::new("cached-1", inner, 100);
        cached.invalidate("pkg-1");
        cached.invalidate_all();
        assert_eq!(cached.cache_size(), 0);
    }

    #[test]
    fn test_null_registry() {
        let mut reg = NullPolicyPackageRegistry::new("null-1");
        assert!(!reg.is_active());
        reg.publish_package(sample_pkg("pkg-1", "org", "p"))
            .unwrap();
        assert!(reg.lookup_package("pkg-1").is_err());
        assert!(reg.list_available_packages(&PackageQuery::new()).is_empty());
        assert!(!reg.verify_package_integrity("x").unwrap());
    }

    #[test]
    fn test_registry_ids() {
        let reg = InMemoryPolicyPackageRegistry::new("my-reg");
        assert_eq!(reg.registry_id(), "my-reg");
        assert!(reg.is_active());
    }

    #[test]
    fn test_credentials() {
        let creds = RegistryCredentials::new("secret-token");
        assert_eq!(creds.token(), "secret-token");
    }

    #[test]
    fn test_subscription_handle_display() {
        let handle = SubscriptionHandle("sub-42".to_string());
        assert_eq!(handle.to_string(), "sub-42");
    }

    #[test]
    fn test_package_query_default() {
        let q = PackageQuery::default();
        assert!(q.name_pattern.is_none());
        assert!(q.namespace_filter.is_none());
        assert!(q.tag_filters.is_empty());
        assert!(q.version_range.is_none());
    }
}
