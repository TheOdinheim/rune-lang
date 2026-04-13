// ═══════════════════════════════════════════════════════════════════════
// Endpoint — Endpoint classification and access control.
// Classifies API endpoints by sensitivity and access requirements.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::WebError;

// ── EndpointId ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointId(pub String);

impl EndpointId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── HttpMethod ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Delete => write!(f, "DELETE"),
            Self::Patch => write!(f, "PATCH"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
        }
    }
}

// ── EndpointClassification ───────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum EndpointClassification {
    Public = 0,
    Authenticated = 1,
    Privileged = 2,
    Internal = 3,
    Sensitive = 4,
    Critical = 5,
}

impl fmt::Display for EndpointClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Authenticated => write!(f, "Authenticated"),
            Self::Privileged => write!(f, "Privileged"),
            Self::Internal => write!(f, "Internal"),
            Self::Sensitive => write!(f, "Sensitive"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ── RateLimitConfig ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u64,
    pub burst_size: u64,
    pub per_ip: bool,
    pub per_identity: bool,
}

impl RateLimitConfig {
    pub fn default_public() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
            per_ip: true,
            per_identity: false,
        }
    }

    pub fn default_authenticated() -> Self {
        Self {
            requests_per_minute: 300,
            burst_size: 30,
            per_ip: false,
            per_identity: true,
        }
    }

    pub fn default_internal() -> Self {
        Self {
            requests_per_minute: 1000,
            burst_size: 100,
            per_ip: false,
            per_identity: false,
        }
    }
}

// ── Endpoint ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: EndpointId,
    pub path_pattern: String,
    pub method: HttpMethod,
    pub classification: EndpointClassification,
    pub auth_required: bool,
    pub mfa_required: bool,
    pub rate_limit: Option<RateLimitConfig>,
    pub allowed_roles: Vec<String>,
    pub allowed_content_types: Vec<String>,
    pub max_request_body_bytes: Option<u64>,
    pub deprecated: bool,
    pub deprecated_at: Option<i64>,
    pub successor: Option<String>,
    pub description: String,
    pub tags: HashMap<String, String>,
}

impl Endpoint {
    pub fn new(
        id: impl Into<String>,
        path_pattern: impl Into<String>,
        method: HttpMethod,
        classification: EndpointClassification,
    ) -> Self {
        let classification_auth = classification >= EndpointClassification::Authenticated;
        let classification_mfa = classification >= EndpointClassification::Critical;
        Self {
            id: EndpointId::new(id),
            path_pattern: path_pattern.into(),
            method,
            classification,
            auth_required: classification_auth,
            mfa_required: classification_mfa,
            rate_limit: None,
            allowed_roles: Vec::new(),
            allowed_content_types: Vec::new(),
            max_request_body_bytes: None,
            deprecated: false,
            deprecated_at: None,
            successor: None,
            description: String::new(),
            tags: HashMap::new(),
        }
    }

    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.allowed_roles = roles;
        self
    }

    pub fn with_deprecated(mut self, at: i64, successor: impl Into<String>) -> Self {
        self.deprecated = true;
        self.deprecated_at = Some(at);
        self.successor = Some(successor.into());
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_max_body(mut self, bytes: u64) -> Self {
        self.max_request_body_bytes = Some(bytes);
        self
    }
}

// ── EndpointRegistry ─────────────────────────────────────────────────

pub struct EndpointRegistry {
    endpoints: HashMap<EndpointId, Endpoint>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
        }
    }

    pub fn register(&mut self, endpoint: Endpoint) -> Result<(), WebError> {
        if self.endpoints.contains_key(&endpoint.id) {
            return Err(WebError::EndpointAlreadyExists(endpoint.id.0.clone()));
        }
        self.endpoints.insert(endpoint.id.clone(), endpoint);
        Ok(())
    }

    pub fn get(&self, id: &EndpointId) -> Option<&Endpoint> {
        self.endpoints.get(id)
    }

    /// Matches a request path against registered endpoint patterns.
    /// Exact match first, then pattern match ({param} segments match any value).
    pub fn match_path(&self, path: &str, method: HttpMethod) -> Option<&Endpoint> {
        // Exact match first
        for ep in self.endpoints.values() {
            if ep.method == method && ep.path_pattern == path {
                return Some(ep);
            }
        }
        // Pattern match: segments with {param} match any value
        for ep in self.endpoints.values() {
            if ep.method == method && Self::pattern_matches(&ep.path_pattern, path) {
                return Some(ep);
            }
        }
        None
    }

    fn pattern_matches(pattern: &str, path: &str) -> bool {
        let pattern_segments: Vec<&str> = pattern.split('/').collect();
        let path_segments: Vec<&str> = path.split('/').collect();
        if pattern_segments.len() != path_segments.len() {
            return false;
        }
        pattern_segments
            .iter()
            .zip(path_segments.iter())
            .all(|(pat, seg)| {
                pat.starts_with('{') && pat.ends_with('}') || pat == seg
            })
    }

    pub fn by_classification(&self, classification: EndpointClassification) -> Vec<&Endpoint> {
        self.endpoints
            .values()
            .filter(|ep| ep.classification == classification)
            .collect()
    }

    pub fn deprecated_endpoints(&self) -> Vec<&Endpoint> {
        self.endpoints.values().filter(|ep| ep.deprecated).collect()
    }

    pub fn sensitive_endpoints(&self) -> Vec<&Endpoint> {
        self.endpoints
            .values()
            .filter(|ep| ep.classification >= EndpointClassification::Sensitive)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.endpoints.len()
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_endpoint(id: &str, path: &str, method: HttpMethod, class: EndpointClassification) -> Endpoint {
        Endpoint::new(id, path, method, class)
    }

    #[test]
    fn test_endpoint_id_construction_and_display() {
        let id = EndpointId::new("/api/v1/models");
        assert_eq!(id.to_string(), "/api/v1/models");
        assert_eq!(id.0, "/api/v1/models");
    }

    #[test]
    fn test_endpoint_construction_all_fields() {
        let ep = Endpoint::new("ep1", "/api/v1/data", HttpMethod::Get, EndpointClassification::Authenticated)
            .with_rate_limit(RateLimitConfig::default_authenticated())
            .with_roles(vec!["admin".into()])
            .with_description("Get data")
            .with_max_body(1024);
        assert_eq!(ep.id.0, "ep1");
        assert_eq!(ep.path_pattern, "/api/v1/data");
        assert!(ep.auth_required);
        assert!(!ep.mfa_required);
        assert_eq!(ep.allowed_roles, vec!["admin"]);
        assert_eq!(ep.max_request_body_bytes, Some(1024));
    }

    #[test]
    fn test_http_method_display() {
        let methods = vec![
            (HttpMethod::Get, "GET"),
            (HttpMethod::Post, "POST"),
            (HttpMethod::Put, "PUT"),
            (HttpMethod::Delete, "DELETE"),
            (HttpMethod::Patch, "PATCH"),
            (HttpMethod::Head, "HEAD"),
            (HttpMethod::Options, "OPTIONS"),
        ];
        for (m, expected) in &methods {
            assert_eq!(m.to_string(), *expected);
        }
        assert_eq!(methods.len(), 7);
    }

    #[test]
    fn test_endpoint_classification_ordering() {
        assert!(EndpointClassification::Public < EndpointClassification::Authenticated);
        assert!(EndpointClassification::Authenticated < EndpointClassification::Privileged);
        assert!(EndpointClassification::Privileged < EndpointClassification::Internal);
        assert!(EndpointClassification::Internal < EndpointClassification::Sensitive);
        assert!(EndpointClassification::Sensitive < EndpointClassification::Critical);
    }

    #[test]
    fn test_rate_limit_defaults() {
        let public = RateLimitConfig::default_public();
        assert_eq!(public.requests_per_minute, 60);
        assert_eq!(public.burst_size, 10);
        assert!(public.per_ip);

        let auth = RateLimitConfig::default_authenticated();
        assert_eq!(auth.requests_per_minute, 300);
        assert!(auth.per_identity);

        let internal = RateLimitConfig::default_internal();
        assert_eq!(internal.requests_per_minute, 1000);
        assert!(!internal.per_ip);
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = EndpointRegistry::new();
        reg.register(sample_endpoint("ep1", "/api/v1/test", HttpMethod::Get, EndpointClassification::Public))
            .unwrap();
        assert!(reg.get(&EndpointId::new("ep1")).is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_registry_match_path_exact() {
        let mut reg = EndpointRegistry::new();
        reg.register(sample_endpoint("ep1", "/api/v1/test", HttpMethod::Get, EndpointClassification::Public))
            .unwrap();
        let matched = reg.match_path("/api/v1/test", HttpMethod::Get);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().id.0, "ep1");
    }

    #[test]
    fn test_registry_match_path_pattern() {
        let mut reg = EndpointRegistry::new();
        reg.register(sample_endpoint("ep1", "/api/v1/models/{id}", HttpMethod::Get, EndpointClassification::Authenticated))
            .unwrap();
        let matched = reg.match_path("/api/v1/models/abc123", HttpMethod::Get);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().id.0, "ep1");
    }

    #[test]
    fn test_registry_match_path_returns_none() {
        let reg = EndpointRegistry::new();
        assert!(reg.match_path("/nonexistent", HttpMethod::Get).is_none());
    }

    #[test]
    fn test_registry_by_classification() {
        let mut reg = EndpointRegistry::new();
        reg.register(sample_endpoint("ep1", "/public", HttpMethod::Get, EndpointClassification::Public)).unwrap();
        reg.register(sample_endpoint("ep2", "/auth", HttpMethod::Get, EndpointClassification::Authenticated)).unwrap();
        reg.register(sample_endpoint("ep3", "/pub2", HttpMethod::Post, EndpointClassification::Public)).unwrap();
        assert_eq!(reg.by_classification(EndpointClassification::Public).len(), 2);
        assert_eq!(reg.by_classification(EndpointClassification::Authenticated).len(), 1);
    }

    #[test]
    fn test_registry_deprecated_endpoints() {
        let mut reg = EndpointRegistry::new();
        let ep = sample_endpoint("ep1", "/old", HttpMethod::Get, EndpointClassification::Public)
            .with_deprecated(1000, "/new");
        reg.register(ep).unwrap();
        reg.register(sample_endpoint("ep2", "/current", HttpMethod::Get, EndpointClassification::Public)).unwrap();
        assert_eq!(reg.deprecated_endpoints().len(), 1);
    }

    #[test]
    fn test_registry_sensitive_endpoints() {
        let mut reg = EndpointRegistry::new();
        reg.register(sample_endpoint("ep1", "/pub", HttpMethod::Get, EndpointClassification::Public)).unwrap();
        reg.register(sample_endpoint("ep2", "/sens", HttpMethod::Get, EndpointClassification::Sensitive)).unwrap();
        reg.register(sample_endpoint("ep3", "/crit", HttpMethod::Post, EndpointClassification::Critical)).unwrap();
        let sensitive = reg.sensitive_endpoints();
        assert_eq!(sensitive.len(), 2);
    }

    #[test]
    fn test_registry_duplicate_register_fails() {
        let mut reg = EndpointRegistry::new();
        reg.register(sample_endpoint("ep1", "/test", HttpMethod::Get, EndpointClassification::Public)).unwrap();
        let result = reg.register(sample_endpoint("ep1", "/test2", HttpMethod::Post, EndpointClassification::Public));
        assert!(result.is_err());
    }
}
