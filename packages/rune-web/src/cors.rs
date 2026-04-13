// ═══════════════════════════════════════════════════════════════════════
// CORS — Cross-Origin Resource Sharing policy definition and
// enforcement.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::endpoint::HttpMethod;

// ── CorsPolicy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicy {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<HttpMethod>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_seconds: u64,
}

impl CorsPolicy {
    pub fn permissive() -> Self {
        Self {
            allowed_origins: vec!["*".into()],
            allowed_methods: vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Delete,
                HttpMethod::Patch,
                HttpMethod::Head,
                HttpMethod::Options,
            ],
            allowed_headers: vec!["*".into()],
            exposed_headers: Vec::new(),
            allow_credentials: false, // credentials cannot be used with wildcard origin
            max_age_seconds: 3600,
        }
    }

    pub fn strict(origins: Vec<String>) -> Self {
        Self {
            allowed_origins: origins,
            allowed_methods: vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Delete,
            ],
            allowed_headers: vec![
                "Content-Type".into(),
                "Authorization".into(),
                "X-Request-ID".into(),
            ],
            exposed_headers: Vec::new(),
            allow_credentials: true,
            max_age_seconds: 3600,
        }
    }

    pub fn none() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            exposed_headers: Vec::new(),
            allow_credentials: false,
            max_age_seconds: 0,
        }
    }
}

// ── CorsResult ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorsResult {
    pub allowed: bool,
    pub headers: HashMap<String, String>,
    pub reason: Option<String>,
}

// ── CorsChecker ──────────────────────────────────────────────────────

pub struct CorsChecker {
    policy: CorsPolicy,
}

impl CorsChecker {
    pub fn new(policy: CorsPolicy) -> Self {
        Self { policy }
    }

    pub fn check_preflight(
        &self,
        origin: &str,
        method: HttpMethod,
        request_headers: &[String],
    ) -> CorsResult {
        // Is origin allowed?
        if !self.is_origin_allowed(origin) {
            return CorsResult {
                allowed: false,
                headers: HashMap::new(),
                reason: Some(format!("Origin '{origin}' not allowed")),
            };
        }

        // Is method allowed?
        if !self.policy.allowed_methods.contains(&method) {
            return CorsResult {
                allowed: false,
                headers: HashMap::new(),
                reason: Some(format!("Method '{}' not allowed", method)),
            };
        }

        // Are requested headers allowed?
        if !self.policy.allowed_headers.contains(&"*".to_string()) {
            let allowed_lower: Vec<String> = self
                .policy
                .allowed_headers
                .iter()
                .map(|h| h.to_lowercase())
                .collect();
            for header in request_headers {
                if !allowed_lower.contains(&header.to_lowercase()) {
                    return CorsResult {
                        allowed: false,
                        headers: HashMap::new(),
                        reason: Some(format!("Header '{header}' not allowed")),
                    };
                }
            }
        }

        CorsResult {
            allowed: true,
            headers: self.response_headers(origin),
            reason: None,
        }
    }

    pub fn check_simple(&self, origin: &str) -> CorsResult {
        if !self.is_origin_allowed(origin) {
            return CorsResult {
                allowed: false,
                headers: HashMap::new(),
                reason: Some(format!("Origin '{origin}' not allowed")),
            };
        }

        CorsResult {
            allowed: true,
            headers: self.response_headers(origin),
            reason: None,
        }
    }

    pub fn response_headers(&self, origin: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        // Access-Control-Allow-Origin
        if self.policy.allowed_origins.contains(&"*".to_string()) {
            // When credentials are not allowed, use wildcard
            if !self.policy.allow_credentials {
                headers.insert(
                    "Access-Control-Allow-Origin".into(),
                    "*".into(),
                );
            } else {
                // Credentials + wildcard not allowed per spec; echo origin
                headers.insert(
                    "Access-Control-Allow-Origin".into(),
                    origin.into(),
                );
            }
        } else {
            headers.insert(
                "Access-Control-Allow-Origin".into(),
                origin.into(),
            );
        }

        // Access-Control-Allow-Methods
        if !self.policy.allowed_methods.is_empty() {
            let methods: Vec<String> = self
                .policy
                .allowed_methods
                .iter()
                .map(|m| m.to_string())
                .collect();
            headers.insert(
                "Access-Control-Allow-Methods".into(),
                methods.join(", "),
            );
        }

        // Access-Control-Allow-Headers
        if !self.policy.allowed_headers.is_empty() {
            headers.insert(
                "Access-Control-Allow-Headers".into(),
                self.policy.allowed_headers.join(", "),
            );
        }

        // Access-Control-Expose-Headers
        if !self.policy.exposed_headers.is_empty() {
            headers.insert(
                "Access-Control-Expose-Headers".into(),
                self.policy.exposed_headers.join(", "),
            );
        }

        // Access-Control-Allow-Credentials
        if self.policy.allow_credentials {
            headers.insert(
                "Access-Control-Allow-Credentials".into(),
                "true".into(),
            );
        }

        // Access-Control-Max-Age
        if self.policy.max_age_seconds > 0 {
            headers.insert(
                "Access-Control-Max-Age".into(),
                self.policy.max_age_seconds.to_string(),
            );
        }

        headers
    }

    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.policy.allowed_origins.contains(&"*".to_string()) {
            return true;
        }
        self.policy.allowed_origins.iter().any(|o| o == origin)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_preflight_allows_listed_origin() {
        let checker = CorsChecker::new(CorsPolicy::strict(vec!["https://app.example.com".into()]));
        let result = checker.check_preflight(
            "https://app.example.com",
            HttpMethod::Get,
            &["Content-Type".into()],
        );
        assert!(result.allowed);
    }

    #[test]
    fn test_check_preflight_denies_unlisted_origin() {
        let checker = CorsChecker::new(CorsPolicy::strict(vec!["https://app.example.com".into()]));
        let result = checker.check_preflight(
            "https://evil.com",
            HttpMethod::Get,
            &[],
        );
        assert!(!result.allowed);
        assert!(result.reason.is_some());
    }

    #[test]
    fn test_check_preflight_allows_wildcard() {
        let checker = CorsChecker::new(CorsPolicy::permissive());
        let result = checker.check_preflight(
            "https://anything.com",
            HttpMethod::Post,
            &["X-Custom".into()],
        );
        assert!(result.allowed);
    }

    #[test]
    fn test_check_preflight_denies_disallowed_method() {
        let checker = CorsChecker::new(CorsPolicy::strict(vec!["https://app.example.com".into()]));
        let result = checker.check_preflight(
            "https://app.example.com",
            HttpMethod::Patch, // not in strict
            &[],
        );
        assert!(!result.allowed);
    }

    #[test]
    fn test_check_simple_allows_listed_origin() {
        let checker = CorsChecker::new(CorsPolicy::strict(vec!["https://app.example.com".into()]));
        let result = checker.check_simple("https://app.example.com");
        assert!(result.allowed);
        assert!(result.headers.contains_key("Access-Control-Allow-Origin"));
    }

    #[test]
    fn test_response_headers_correct() {
        let checker = CorsChecker::new(CorsPolicy::strict(vec!["https://app.example.com".into()]));
        let headers = checker.response_headers("https://app.example.com");
        assert_eq!(
            headers.get("Access-Control-Allow-Origin").unwrap(),
            "https://app.example.com"
        );
        assert!(headers.contains_key("Access-Control-Allow-Methods"));
        assert!(headers.contains_key("Access-Control-Allow-Credentials"));
    }

    #[test]
    fn test_permissive_allows_everything() {
        let checker = CorsChecker::new(CorsPolicy::permissive());
        let result = checker.check_simple("https://anything.com");
        assert!(result.allowed);
    }

    #[test]
    fn test_strict_allows_only_specified() {
        let checker = CorsChecker::new(CorsPolicy::strict(vec!["https://myapp.com".into()]));
        assert!(checker.check_simple("https://myapp.com").allowed);
        assert!(!checker.check_simple("https://other.com").allowed);
    }

    #[test]
    fn test_none_denies_all() {
        let checker = CorsChecker::new(CorsPolicy::none());
        assert!(!checker.check_simple("https://anything.com").allowed);
    }

    #[test]
    fn test_no_credentials_with_wildcard() {
        let policy = CorsPolicy::permissive();
        // Permissive has allow_credentials = false
        assert!(!policy.allow_credentials);
        let checker = CorsChecker::new(policy);
        let headers = checker.response_headers("https://example.com");
        assert_eq!(headers.get("Access-Control-Allow-Origin").unwrap(), "*");
        assert!(!headers.contains_key("Access-Control-Allow-Credentials"));
    }
}
