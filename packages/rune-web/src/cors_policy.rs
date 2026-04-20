// ═══════════════════════════════════════════════════════════════════════
// CORS Policy Store — Pluggable CORS policy backend trait.
//
// Layer 3 defines the contract for storing and matching CORS policies.
// The existing CorsPolicy struct in cors.rs defines policy presets;
// this module adds a storage trait with wildcard origin matching and
// best-match resolution (exact matches win over wildcards).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::WebError;

// ── StoredCorsPolicy ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCorsPolicy {
    pub policy_id: String,
    pub origin: String, // exact or wildcard pattern (e.g., "*.example.com")
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_secs: u64,
}

impl StoredCorsPolicy {
    pub fn new(policy_id: &str, origin: &str) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            origin: origin.to_string(),
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            exposed_headers: Vec::new(),
            allow_credentials: false,
            max_age_secs: 3600,
        }
    }

    pub fn with_methods(mut self, methods: &[&str]) -> Self {
        self.allowed_methods = methods.iter().map(|m| m.to_string()).collect();
        self
    }

    pub fn with_headers(mut self, headers: &[&str]) -> Self {
        self.allowed_headers = headers.iter().map(|h| h.to_string()).collect();
        self
    }

    pub fn with_credentials(mut self) -> Self {
        self.allow_credentials = true;
        self
    }

    pub fn with_max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = secs;
        self
    }

    /// Returns true if origin is a wildcard pattern (starts with "*.")
    pub fn is_wildcard(&self) -> bool {
        self.origin.starts_with("*.")
    }
}

// ── CorsDecision ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsDecision {
    Allow { response_headers: HashMap<String, String> },
    Deny { reason: String },
}

impl CorsDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

// ── CorsPolicyBackendInfo ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsPolicyBackendInfo {
    pub backend_type: String,
    pub supports_wildcards: bool,
}

// ── CorsPolicyStore trait ──────────────────────────────────────

pub trait CorsPolicyStore {
    fn store_policy(&mut self, policy: &StoredCorsPolicy) -> Result<(), WebError>;
    fn retrieve_policy_for_origin(&self, origin: &str) -> Option<&StoredCorsPolicy>;
    fn list_policies(&self) -> Vec<&str>;
    fn policy_count(&self) -> usize;
    fn delete_policy(&mut self, policy_id: &str) -> Result<bool, WebError>;
    fn match_origin(&self, origin: &str) -> Option<CorsDecision>;
    fn backend_info(&self) -> CorsPolicyBackendInfo;
}

// ── InMemoryCorsPolicyStore ────────────────────────────────────

pub struct InMemoryCorsPolicyStore {
    policies: HashMap<String, StoredCorsPolicy>,
}

impl InMemoryCorsPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }
}

impl Default for InMemoryCorsPolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if origin matches a wildcard pattern like "*.example.com".
fn matches_wildcard(pattern: &str, origin: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Extract the host part from origin (strip scheme)
        let host = if let Some(rest) = origin.strip_prefix("https://") {
            rest
        } else if let Some(rest) = origin.strip_prefix("http://") {
            rest
        } else {
            origin
        };
        host.ends_with(suffix) && host.len() > suffix.len()
    } else {
        false
    }
}

fn build_response_headers(policy: &StoredCorsPolicy, origin: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Access-Control-Allow-Origin".to_string(), origin.to_string());
    if !policy.allowed_methods.is_empty() {
        headers.insert(
            "Access-Control-Allow-Methods".to_string(),
            policy.allowed_methods.join(", "),
        );
    }
    if !policy.allowed_headers.is_empty() {
        headers.insert(
            "Access-Control-Allow-Headers".to_string(),
            policy.allowed_headers.join(", "),
        );
    }
    if !policy.exposed_headers.is_empty() {
        headers.insert(
            "Access-Control-Expose-Headers".to_string(),
            policy.exposed_headers.join(", "),
        );
    }
    if policy.allow_credentials {
        headers.insert(
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        );
    }
    if policy.max_age_secs > 0 {
        headers.insert(
            "Access-Control-Max-Age".to_string(),
            policy.max_age_secs.to_string(),
        );
    }
    headers
}

impl CorsPolicyStore for InMemoryCorsPolicyStore {
    fn store_policy(&mut self, policy: &StoredCorsPolicy) -> Result<(), WebError> {
        self.policies
            .insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_policy_for_origin(&self, origin: &str) -> Option<&StoredCorsPolicy> {
        // Exact match first
        if let Some(p) = self.policies.values().find(|p| p.origin == origin) {
            return Some(p);
        }
        // Wildcard match
        self.policies.values().find(|p| p.is_wildcard() && matches_wildcard(&p.origin, origin))
    }

    fn list_policies(&self) -> Vec<&str> {
        self.policies.keys().map(|k| k.as_str()).collect()
    }

    fn policy_count(&self) -> usize {
        self.policies.len()
    }

    fn delete_policy(&mut self, policy_id: &str) -> Result<bool, WebError> {
        Ok(self.policies.remove(policy_id).is_some())
    }

    fn match_origin(&self, origin: &str) -> Option<CorsDecision> {
        if let Some(policy) = self.retrieve_policy_for_origin(origin) {
            Some(CorsDecision::Allow {
                response_headers: build_response_headers(policy, origin),
            })
        } else {
            Some(CorsDecision::Deny {
                reason: format!("No CORS policy matches origin '{origin}'"),
            })
        }
    }

    fn backend_info(&self) -> CorsPolicyBackendInfo {
        CorsPolicyBackendInfo {
            backend_type: "in-memory".to_string(),
            supports_wildcards: true,
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
    fn test_store_and_retrieve_exact() {
        let mut store = InMemoryCorsPolicyStore::new();
        let policy = StoredCorsPolicy::new("p1", "https://app.example.com")
            .with_methods(&["GET", "POST", "PUT"])
            .with_credentials();
        store.store_policy(&policy).unwrap();
        let retrieved = store.retrieve_policy_for_origin("https://app.example.com").unwrap();
        assert_eq!(retrieved.policy_id, "p1");
        assert!(retrieved.allow_credentials);
    }

    #[test]
    fn test_exact_match_wins_over_wildcard() {
        let mut store = InMemoryCorsPolicyStore::new();
        store.store_policy(&StoredCorsPolicy::new("wild", "*.example.com")
            .with_methods(&["GET"])).unwrap();
        store.store_policy(&StoredCorsPolicy::new("exact", "https://app.example.com")
            .with_methods(&["GET", "POST"])).unwrap();
        let matched = store.retrieve_policy_for_origin("https://app.example.com").unwrap();
        assert_eq!(matched.policy_id, "exact");
    }

    #[test]
    fn test_wildcard_match() {
        let mut store = InMemoryCorsPolicyStore::new();
        store.store_policy(&StoredCorsPolicy::new("wild", "*.example.com")).unwrap();
        let matched = store.retrieve_policy_for_origin("https://sub.example.com");
        assert!(matched.is_some());
    }

    #[test]
    fn test_wildcard_no_match_self() {
        let mut store = InMemoryCorsPolicyStore::new();
        store.store_policy(&StoredCorsPolicy::new("wild", "*.example.com")).unwrap();
        // "example.com" alone should not match "*.example.com"
        assert!(store.retrieve_policy_for_origin("https://example.com").is_none());
    }

    #[test]
    fn test_no_match_returns_deny() {
        let store = InMemoryCorsPolicyStore::new();
        let decision = store.match_origin("https://evil.com").unwrap();
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_match_returns_allow_with_headers() {
        let mut store = InMemoryCorsPolicyStore::new();
        store.store_policy(&StoredCorsPolicy::new("p1", "https://app.com")
            .with_methods(&["GET", "POST"])
            .with_credentials()
            .with_max_age(7200)
        ).unwrap();
        let decision = store.match_origin("https://app.com").unwrap();
        assert!(decision.is_allowed());
        if let CorsDecision::Allow { response_headers } = decision {
            assert_eq!(response_headers.get("Access-Control-Allow-Origin").unwrap(), "https://app.com");
            assert!(response_headers.get("Access-Control-Allow-Methods").unwrap().contains("GET"));
            assert_eq!(response_headers.get("Access-Control-Allow-Credentials").unwrap(), "true");
            assert_eq!(response_headers.get("Access-Control-Max-Age").unwrap(), "7200");
        }
    }

    #[test]
    fn test_delete_policy() {
        let mut store = InMemoryCorsPolicyStore::new();
        store.store_policy(&StoredCorsPolicy::new("p1", "https://app.com")).unwrap();
        assert!(store.delete_policy("p1").unwrap());
        assert!(!store.delete_policy("p1").unwrap());
        assert_eq!(store.policy_count(), 0);
    }

    #[test]
    fn test_list_and_count() {
        let mut store = InMemoryCorsPolicyStore::new();
        store.store_policy(&StoredCorsPolicy::new("p1", "https://a.com")).unwrap();
        store.store_policy(&StoredCorsPolicy::new("p2", "https://b.com")).unwrap();
        assert_eq!(store.policy_count(), 2);
        assert_eq!(store.list_policies().len(), 2);
    }

    #[test]
    fn test_backend_info() {
        let store = InMemoryCorsPolicyStore::new();
        let info = store.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(info.supports_wildcards);
    }

    #[test]
    fn test_is_wildcard() {
        assert!(StoredCorsPolicy::new("p1", "*.example.com").is_wildcard());
        assert!(!StoredCorsPolicy::new("p1", "https://example.com").is_wildcard());
    }

    #[test]
    fn test_cors_decision_is_allowed() {
        let allow = CorsDecision::Allow { response_headers: HashMap::new() };
        let deny = CorsDecision::Deny { reason: "nope".into() };
        assert!(allow.is_allowed());
        assert!(!deny.is_allowed());
    }
}
