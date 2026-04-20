// ═══════════════════════════════════════════════════════════════════════
// Web Backend — Storage trait for sessions, route policies, and
// API key bindings.
//
// Layer 3 extracts the storage contract for web governance state
// into a trait so customers can provide their own persistence
// backend. API key bindings store only SHA3-256 hashes — never
// the raw key. RUNE provides the contract; the customer provides
// the storage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::error::WebError;
use crate::session::WebSession;

// ── RoutePolicy ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    pub route_pattern: String,
    pub methods: Vec<String>,
    pub classification: String,
    pub require_auth: bool,
    pub rate_limit_rpm: Option<u64>,
    pub metadata: HashMap<String, String>,
}

impl RoutePolicy {
    pub fn new(route_pattern: &str, classification: &str) -> Self {
        Self {
            route_pattern: route_pattern.to_string(),
            methods: Vec::new(),
            classification: classification.to_string(),
            require_auth: false,
            rate_limit_rpm: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_methods(mut self, methods: &[&str]) -> Self {
        self.methods = methods.iter().map(|m| m.to_string()).collect();
        self
    }

    pub fn with_auth_required(mut self) -> Self {
        self.require_auth = true;
        self
    }

    pub fn with_rate_limit(mut self, rpm: u64) -> Self {
        self.rate_limit_rpm = Some(rpm);
        self
    }
}

// ── ApiKeyBinding ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyBinding {
    pub key_id: String,
    pub key_hash: String, // SHA3-256 hash, never the raw key
    pub owner: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub scopes: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl ApiKeyBinding {
    pub fn new(key_id: &str, raw_key: &str, owner: &str, created_at: i64) -> Self {
        Self {
            key_id: key_id.to_string(),
            key_hash: Self::hash_key(raw_key),
            owner: owner.to_string(),
            created_at,
            expires_at: None,
            revoked: false,
            scopes: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn hash_key(raw_key: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(raw_key.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn with_expires_at(mut self, ts: i64) -> Self {
        self.expires_at = Some(ts);
        self
    }

    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        if let Some(exp) = self.expires_at {
            now >= exp
        } else {
            false
        }
    }

    pub fn is_valid(&self, now: i64) -> bool {
        !self.revoked && !self.is_expired(now)
    }
}

// ── BackendInfo ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInfo {
    pub backend_type: String,
    pub supports_persistence: bool,
    pub supports_clustering: bool,
    pub max_sessions: Option<usize>,
}

// ── WebBackend trait ───────────────────────────────────────────

pub trait WebBackend {
    fn store_session(&mut self, session: &WebSession) -> Result<(), WebError>;
    fn retrieve_session(&self, id: &str) -> Option<&WebSession>;
    fn delete_session(&mut self, id: &str) -> Result<bool, WebError>;
    fn list_sessions(&self) -> Vec<&str>;
    fn session_count(&self) -> usize;
    fn session_exists(&self, id: &str) -> bool;
    fn touch_session(&mut self, id: &str, now: i64) -> Result<(), WebError>;

    fn store_route_policy(&mut self, policy: &RoutePolicy) -> Result<(), WebError>;
    fn retrieve_route_policy(&self, route_pattern: &str) -> Option<&RoutePolicy>;
    fn list_route_policies(&self) -> Vec<&str>;

    fn store_api_key_binding(&mut self, binding: &ApiKeyBinding) -> Result<(), WebError>;
    fn retrieve_api_key_binding(&self, key_id: &str) -> Option<&ApiKeyBinding>;
    fn list_api_key_bindings(&self) -> Vec<&str>;
    fn revoke_api_key_binding(&mut self, key_id: &str) -> Result<bool, WebError>;

    fn flush(&mut self) -> Result<(), WebError>;
    fn backend_info(&self) -> BackendInfo;
}

// ── InMemoryWebBackend ─────────────────────────────────────────

pub struct InMemoryWebBackend {
    sessions: HashMap<String, WebSession>,
    route_policies: HashMap<String, RoutePolicy>,
    api_key_bindings: HashMap<String, ApiKeyBinding>,
}

impl InMemoryWebBackend {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            route_policies: HashMap::new(),
            api_key_bindings: HashMap::new(),
        }
    }
}

impl Default for InMemoryWebBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl WebBackend for InMemoryWebBackend {
    fn store_session(&mut self, session: &WebSession) -> Result<(), WebError> {
        if self.sessions.contains_key(&session.id) {
            return Err(WebError::InvalidOperation(format!(
                "session already exists: {}",
                session.id
            )));
        }
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(())
    }

    fn retrieve_session(&self, id: &str) -> Option<&WebSession> {
        self.sessions.get(id)
    }

    fn delete_session(&mut self, id: &str) -> Result<bool, WebError> {
        Ok(self.sessions.remove(id).is_some())
    }

    fn list_sessions(&self) -> Vec<&str> {
        self.sessions.keys().map(|k| k.as_str()).collect()
    }

    fn session_count(&self) -> usize {
        self.sessions.len()
    }

    fn session_exists(&self, id: &str) -> bool {
        self.sessions.contains_key(id)
    }

    fn touch_session(&mut self, id: &str, now: i64) -> Result<(), WebError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?;
        session.last_activity = now;
        Ok(())
    }

    fn store_route_policy(&mut self, policy: &RoutePolicy) -> Result<(), WebError> {
        self.route_policies
            .insert(policy.route_pattern.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_route_policy(&self, route_pattern: &str) -> Option<&RoutePolicy> {
        self.route_policies.get(route_pattern)
    }

    fn list_route_policies(&self) -> Vec<&str> {
        self.route_policies.keys().map(|k| k.as_str()).collect()
    }

    fn store_api_key_binding(&mut self, binding: &ApiKeyBinding) -> Result<(), WebError> {
        if self.api_key_bindings.contains_key(&binding.key_id) {
            return Err(WebError::InvalidOperation(format!(
                "API key binding already exists: {}",
                binding.key_id
            )));
        }
        self.api_key_bindings
            .insert(binding.key_id.clone(), binding.clone());
        Ok(())
    }

    fn retrieve_api_key_binding(&self, key_id: &str) -> Option<&ApiKeyBinding> {
        self.api_key_bindings.get(key_id)
    }

    fn list_api_key_bindings(&self) -> Vec<&str> {
        self.api_key_bindings.keys().map(|k| k.as_str()).collect()
    }

    fn revoke_api_key_binding(&mut self, key_id: &str) -> Result<bool, WebError> {
        if let Some(binding) = self.api_key_bindings.get_mut(key_id) {
            binding.revoked = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn flush(&mut self) -> Result<(), WebError> {
        self.sessions.clear();
        self.route_policies.clear();
        self.api_key_bindings.clear();
        Ok(())
    }

    fn backend_info(&self) -> BackendInfo {
        BackendInfo {
            backend_type: "in-memory".to_string(),
            supports_persistence: false,
            supports_clustering: false,
            max_sessions: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_session(id: &str) -> WebSession {
        WebSession {
            id: id.to_string(),
            identity: None,
            created_at: 1000,
            last_activity: 1000,
            expires_at: 100_000,
            source_ip: "1.2.3.4".to_string(),
            user_agent: None,
            authenticated: false,
            mfa_verified: false,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_session() {
        let mut b = InMemoryWebBackend::new();
        b.store_session(&make_session("s1")).unwrap();
        assert!(b.retrieve_session("s1").is_some());
        assert!(b.session_exists("s1"));
    }

    #[test]
    fn test_duplicate_session_rejected() {
        let mut b = InMemoryWebBackend::new();
        b.store_session(&make_session("s1")).unwrap();
        assert!(b.store_session(&make_session("s1")).is_err());
    }

    #[test]
    fn test_delete_session() {
        let mut b = InMemoryWebBackend::new();
        b.store_session(&make_session("s1")).unwrap();
        assert!(b.delete_session("s1").unwrap());
        assert!(!b.delete_session("s1").unwrap());
    }

    #[test]
    fn test_session_count_and_list() {
        let mut b = InMemoryWebBackend::new();
        b.store_session(&make_session("s1")).unwrap();
        b.store_session(&make_session("s2")).unwrap();
        assert_eq!(b.session_count(), 2);
        assert_eq!(b.list_sessions().len(), 2);
    }

    #[test]
    fn test_touch_session() {
        let mut b = InMemoryWebBackend::new();
        b.store_session(&make_session("s1")).unwrap();
        b.touch_session("s1", 5000).unwrap();
        assert_eq!(b.retrieve_session("s1").unwrap().last_activity, 5000);
    }

    #[test]
    fn test_touch_session_not_found() {
        let mut b = InMemoryWebBackend::new();
        assert!(b.touch_session("nope", 5000).is_err());
    }

    #[test]
    fn test_store_and_retrieve_route_policy() {
        let mut b = InMemoryWebBackend::new();
        let policy = RoutePolicy::new("/api/v1/*", "Authenticated")
            .with_methods(&["GET", "POST"])
            .with_auth_required()
            .with_rate_limit(100);
        b.store_route_policy(&policy).unwrap();
        let p = b.retrieve_route_policy("/api/v1/*").unwrap();
        assert_eq!(p.classification, "Authenticated");
        assert!(p.require_auth);
    }

    #[test]
    fn test_list_route_policies() {
        let mut b = InMemoryWebBackend::new();
        b.store_route_policy(&RoutePolicy::new("/api/*", "Public")).unwrap();
        b.store_route_policy(&RoutePolicy::new("/admin/*", "Critical")).unwrap();
        assert_eq!(b.list_route_policies().len(), 2);
    }

    #[test]
    fn test_api_key_binding_hash() {
        let binding = ApiKeyBinding::new("key-1", "super-secret-key", "owner-1", 1000);
        assert_ne!(binding.key_hash, "super-secret-key");
        assert_eq!(binding.key_hash.len(), 64); // SHA3-256 = 64 hex chars
        // Same key produces same hash
        assert_eq!(binding.key_hash, ApiKeyBinding::hash_key("super-secret-key"));
    }

    #[test]
    fn test_store_and_retrieve_api_key_binding() {
        let mut b = InMemoryWebBackend::new();
        let binding = ApiKeyBinding::new("key-1", "secret", "owner", 1000)
            .with_scopes(&["read", "write"]);
        b.store_api_key_binding(&binding).unwrap();
        let retrieved = b.retrieve_api_key_binding("key-1").unwrap();
        assert_eq!(retrieved.owner, "owner");
        assert_eq!(retrieved.scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_duplicate_api_key_rejected() {
        let mut b = InMemoryWebBackend::new();
        let binding = ApiKeyBinding::new("key-1", "secret", "owner", 1000);
        b.store_api_key_binding(&binding).unwrap();
        assert!(b.store_api_key_binding(&binding).is_err());
    }

    #[test]
    fn test_revoke_api_key_binding() {
        let mut b = InMemoryWebBackend::new();
        let binding = ApiKeyBinding::new("key-1", "secret", "owner", 1000);
        b.store_api_key_binding(&binding).unwrap();
        assert!(b.revoke_api_key_binding("key-1").unwrap());
        assert!(b.retrieve_api_key_binding("key-1").unwrap().revoked);
        assert!(!b.revoke_api_key_binding("nope").unwrap());
    }

    #[test]
    fn test_api_key_validity() {
        let binding = ApiKeyBinding::new("key-1", "secret", "owner", 1000)
            .with_expires_at(5000);
        assert!(binding.is_valid(3000));
        assert!(!binding.is_valid(5000)); // expired
        let mut revoked = binding.clone();
        revoked.revoked = true;
        assert!(!revoked.is_valid(3000));
    }

    #[test]
    fn test_flush() {
        let mut b = InMemoryWebBackend::new();
        b.store_session(&make_session("s1")).unwrap();
        b.store_route_policy(&RoutePolicy::new("/api/*", "Public")).unwrap();
        b.store_api_key_binding(&ApiKeyBinding::new("k1", "s", "o", 1000)).unwrap();
        b.flush().unwrap();
        assert_eq!(b.session_count(), 0);
        assert!(b.list_route_policies().is_empty());
        assert!(b.list_api_key_bindings().is_empty());
    }

    #[test]
    fn test_backend_info() {
        let b = InMemoryWebBackend::new();
        let info = b.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(!info.supports_persistence);
    }
}
