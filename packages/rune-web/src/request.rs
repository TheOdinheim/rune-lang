// ═══════════════════════════════════════════════════════════════════════
// Request — HTTP request governance: validation and sanitization.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::endpoint::{EndpointClassification, HttpMethod};

// ── WebRequest ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRequest {
    pub id: String,
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
    pub body_size_bytes: u64,
    pub source_ip: String,
    pub identity: Option<String>,
    pub timestamp: i64,
}

impl WebRequest {
    pub fn new(
        id: impl Into<String>,
        method: HttpMethod,
        path: impl Into<String>,
        source_ip: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            id: id.into(),
            method,
            path: path.into(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            body_size_bytes: 0,
            source_ip: source_ip.into(),
            identity: None,
            timestamp,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        let b: String = body.into();
        self.body_size_bytes = b.len() as u64;
        self.body = Some(b);
        self
    }

    pub fn with_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    pub fn with_query(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.insert(key.into(), value.into());
        self
    }
}

// ── RequestValidation ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestValidation {
    pub valid: bool,
    pub checks: Vec<RequestCheck>,
    pub sanitized_path: String,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct RequestCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

// ── RequestValidator ─────────────────────────────────────────────────

pub struct RequestValidator {
    pub max_path_length: usize,
    pub max_header_count: usize,
    pub max_header_value_length: usize,
    pub max_query_params: usize,
    pub max_body_size: u64,
    pub blocked_paths: Vec<String>,
    pub required_headers: Vec<String>,
    pub blocked_patterns: Vec<(String, Regex)>,
}

impl RequestValidator {
    pub fn new() -> Self {
        Self {
            max_path_length: 2048,
            max_header_count: 100,
            max_header_value_length: 8192,
            max_query_params: 50,
            max_body_size: 10_485_760,
            blocked_paths: vec![
                "/.env".into(),
                "/.git".into(),
                "/.htaccess".into(),
                "/wp-admin".into(),
                "/wp-login".into(),
            ],
            required_headers: vec!["host".into()],
            blocked_patterns: Vec::new(),
        }
    }

    pub fn with_defaults(classification: EndpointClassification) -> Self {
        let mut v = Self::new();
        match classification {
            EndpointClassification::Public => {
                v.max_body_size = 1_048_576; // 1MB
            }
            EndpointClassification::Authenticated => {
                v.max_body_size = 5_242_880; // 5MB
            }
            EndpointClassification::Privileged | EndpointClassification::Internal => {
                v.max_body_size = 10_485_760; // 10MB
            }
            EndpointClassification::Sensitive => {
                v.max_body_size = 5_242_880;
                v.max_path_length = 1024;
                v.max_header_count = 50;
            }
            EndpointClassification::Critical => {
                v.max_body_size = 524_288; // 512KB
                v.max_path_length = 512;
                v.max_header_count = 30;
                v.max_query_params = 20;
            }
        }
        v
    }

    pub fn validate(&self, request: &WebRequest) -> RequestValidation {
        let mut checks = Vec::new();
        let mut risk_score = 0.0;

        // a. Path length
        let path_len_ok = request.path.len() <= self.max_path_length;
        checks.push(RequestCheck {
            name: "path_length".into(),
            passed: path_len_ok,
            detail: format!("path length {} (max {})", request.path.len(), self.max_path_length),
        });
        if !path_len_ok {
            risk_score += 0.3;
        }

        // b. Path traversal
        let traversal = self.is_path_traversal(&request.path);
        checks.push(RequestCheck {
            name: "path_traversal".into(),
            passed: !traversal,
            detail: if traversal {
                "path traversal detected".into()
            } else {
                "no path traversal".into()
            },
        });
        if traversal {
            risk_score += 0.5;
        }

        // c. Blocked path
        let blocked = self.is_blocked_path(&request.path);
        checks.push(RequestCheck {
            name: "blocked_path".into(),
            passed: !blocked,
            detail: if blocked {
                "blocked path".into()
            } else {
                "path not blocked".into()
            },
        });
        if blocked {
            risk_score += 0.4;
        }

        // d. Header count
        let header_count_ok = request.headers.len() <= self.max_header_count;
        checks.push(RequestCheck {
            name: "header_count".into(),
            passed: header_count_ok,
            detail: format!("header count {} (max {})", request.headers.len(), self.max_header_count),
        });
        if !header_count_ok {
            risk_score += 0.2;
        }

        // d2. Header value length
        let header_value_ok = request
            .headers
            .values()
            .all(|v| v.len() <= self.max_header_value_length);
        checks.push(RequestCheck {
            name: "header_value_length".into(),
            passed: header_value_ok,
            detail: format!("max header value length {}", self.max_header_value_length),
        });

        // e. Required headers (case-insensitive)
        let lower_headers: Vec<String> = request.headers.keys().map(|k| k.to_lowercase()).collect();
        let required_ok = self
            .required_headers
            .iter()
            .all(|h| lower_headers.contains(&h.to_lowercase()));
        checks.push(RequestCheck {
            name: "required_headers".into(),
            passed: required_ok,
            detail: if required_ok {
                "all required headers present".into()
            } else {
                "missing required headers".into()
            },
        });
        if !required_ok {
            risk_score += 0.1;
        }

        // f. Query param count
        let query_ok = request.query_params.len() <= self.max_query_params;
        checks.push(RequestCheck {
            name: "query_param_count".into(),
            passed: query_ok,
            detail: format!(
                "query params {} (max {})",
                request.query_params.len(),
                self.max_query_params
            ),
        });

        // g. Body size
        let body_ok = request.body_size_bytes <= self.max_body_size;
        checks.push(RequestCheck {
            name: "body_size".into(),
            passed: body_ok,
            detail: format!(
                "body {} bytes (max {})",
                request.body_size_bytes, self.max_body_size
            ),
        });
        if !body_ok {
            risk_score += 0.3;
        }

        // h. Content-Type if body present
        let content_type_ok = if request.body.is_some() {
            let has_ct = request
                .headers
                .keys()
                .any(|k| k.to_lowercase() == "content-type");
            checks.push(RequestCheck {
                name: "content_type".into(),
                passed: has_ct,
                detail: if has_ct {
                    "Content-Type present".into()
                } else {
                    "body present without Content-Type".into()
                },
            });
            has_ct
        } else {
            true
        };

        // i. Sanitize path
        let sanitized_path = self.sanitize_path(&request.path);

        if risk_score > 1.0 {
            risk_score = 1.0;
        }

        let valid = checks.iter().all(|c| c.passed) && content_type_ok;

        RequestValidation {
            valid,
            checks,
            sanitized_path,
            risk_score,
        }
    }

    pub fn sanitize_path(&self, path: &str) -> String {
        let mut result = path.to_string();
        // Collapse double slashes
        while result.contains("//") {
            result = result.replace("//", "/");
        }
        // Remove trailing slash (except root)
        if result.len() > 1 && result.ends_with('/') {
            result.pop();
        }
        result
    }

    pub fn is_path_traversal(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        lower.contains("../")
            || lower.contains("..\\")
            || lower.contains("%2e%2e")
            || lower.contains("%2e.")
            || lower.contains(".%2e")
            || lower.contains("..%2f")
            || lower.contains("..%5c")
    }

    pub fn is_blocked_path(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        self.blocked_paths
            .iter()
            .any(|bp| lower.starts_with(&bp.to_lowercase()))
    }
}

impl RequestValidator {
    // ── Layer 2 additions ────────────────────────────────────────────

    pub fn with_default_blocked_patterns(mut self) -> Self {
        let patterns = [
            ("null_byte_injection", r"\x00|%00"),
            ("unicode_normalization_attack", r"%c0%ae|%e0%80%ae|%c0%af"),
            ("http_response_splitting", r"%0d%0a|%0d|%0a|\r\n"),
            ("ssti", r"\{\{.*\}\}|\$\{.*\}|<%.*%>"),
        ];
        for (name, pat) in &patterns {
            if let Ok(re) = Regex::new(pat) {
                self.blocked_patterns.push((name.to_string(), re));
            }
        }
        self
    }

    pub fn add_blocked_pattern(&mut self, name: &str, pattern: &str) -> Result<(), String> {
        let re = Regex::new(pattern).map_err(|e| format!("Invalid regex: {e}"))?;
        self.blocked_patterns.push((name.to_string(), re));
        Ok(())
    }

    pub fn check_blocked_patterns(&self, input: &str) -> Option<String> {
        for (name, re) in &self.blocked_patterns {
            if re.is_match(input) {
                return Some(name.clone());
            }
        }
        None
    }

    pub fn validate_body_content_type(
        &self,
        request: &WebRequest,
        allowed_types: &[&str],
    ) -> bool {
        if request.body.is_none() {
            return true;
        }
        let ct = request
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.to_lowercase());
        match ct {
            Some(ct_val) => allowed_types.iter().any(|t| ct_val.contains(&t.to_lowercase())),
            None => false,
        }
    }

    pub fn validate_body_size_by_method(&self, request: &WebRequest) -> bool {
        match request.method {
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Delete | HttpMethod::Options => {
                request.body.is_none() || request.body_size_bytes == 0
            }
            _ => request.body_size_bytes <= self.max_body_size,
        }
    }
}

// ── IP validation helpers ────────────────────────────────────────────

pub fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() || (p.len() > 1 && p.starts_with('0')) {
            return false;
        }
        p.parse::<u8>().is_ok()
    })
}

pub fn is_private_ip(s: &str) -> bool {
    if !is_valid_ipv4(s) {
        return false;
    }
    let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }
    // 10.0.0.0/8
    if parts[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if parts[0] == 172 && (16..=31).contains(&parts[1]) {
        return true;
    }
    // 192.168.0.0/16
    if parts[0] == 192 && parts[1] == 168 {
        return true;
    }
    false
}

pub fn is_loopback(s: &str) -> bool {
    if !is_valid_ipv4(s) {
        return false;
    }
    s.starts_with("127.")
}

impl Default for RequestValidator {
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

    fn clean_request() -> WebRequest {
        WebRequest::new("req1", HttpMethod::Get, "/api/v1/test", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
    }

    #[test]
    fn test_web_request_construction() {
        let req = clean_request();
        assert_eq!(req.id, "req1");
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, "/api/v1/test");
        assert_eq!(req.source_ip, "1.2.3.4");
    }

    #[test]
    fn test_validator_passes_clean_request() {
        let v = RequestValidator::new();
        let result = v.validate(&clean_request());
        assert!(result.valid);
        assert!(result.risk_score < 0.01);
    }

    #[test]
    fn test_validator_rejects_path_too_long() {
        let v = RequestValidator::new();
        let long_path = "/".to_string() + &"a".repeat(3000);
        let req = WebRequest::new("req1", HttpMethod::Get, long_path, "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        let result = v.validate(&req);
        assert!(!result.valid);
    }

    #[test]
    fn test_validator_rejects_path_traversal() {
        let v = RequestValidator::new();
        let req = WebRequest::new("req1", HttpMethod::Get, "/api/../etc/passwd", "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        let result = v.validate(&req);
        assert!(!result.valid);
    }

    #[test]
    fn test_validator_rejects_path_traversal_encoded() {
        let v = RequestValidator::new();
        let req = WebRequest::new("req1", HttpMethod::Get, "/api/%2e%2e/etc/passwd", "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        let result = v.validate(&req);
        assert!(!result.valid);
    }

    #[test]
    fn test_validator_rejects_blocked_path() {
        let v = RequestValidator::new();
        for blocked in &["/.env", "/.git/config", "/.htaccess"] {
            let req = WebRequest::new("req1", HttpMethod::Get, *blocked, "1.2.3.4", 1000)
                .with_header("Host", "example.com");
            let result = v.validate(&req);
            assert!(!result.valid, "should block {blocked}");
        }
    }

    #[test]
    fn test_validator_rejects_too_many_headers() {
        let v = RequestValidator { max_header_count: 2, ..RequestValidator::new() };
        let req = WebRequest::new("req1", HttpMethod::Get, "/test", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Accept", "application/json")
            .with_header("X-Custom", "value");
        let result = v.validate(&req);
        assert!(!result.valid);
    }

    #[test]
    fn test_validator_rejects_oversized_body() {
        let v = RequestValidator { max_body_size: 10, ..RequestValidator::new() };
        let mut req = WebRequest::new("req1", HttpMethod::Post, "/test", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Content-Type", "text/plain")
            .with_body("a".repeat(100));
        req.body_size_bytes = 100;
        let result = v.validate(&req);
        assert!(!result.valid);
    }

    #[test]
    fn test_validator_rejects_missing_required_headers() {
        let v = RequestValidator::new();
        let req = WebRequest::new("req1", HttpMethod::Get, "/test", "1.2.3.4", 1000);
        // No Host header
        let result = v.validate(&req);
        assert!(!result.valid);
    }

    #[test]
    fn test_sanitize_path_double_slashes() {
        let v = RequestValidator::new();
        assert_eq!(v.sanitize_path("/api//v1///test"), "/api/v1/test");
    }

    #[test]
    fn test_sanitize_path_trailing_slash() {
        let v = RequestValidator::new();
        assert_eq!(v.sanitize_path("/api/v1/test/"), "/api/v1/test");
        assert_eq!(v.sanitize_path("/"), "/"); // root stays
    }

    #[test]
    fn test_is_path_traversal_patterns() {
        let v = RequestValidator::new();
        assert!(v.is_path_traversal("../etc/passwd"));
        assert!(v.is_path_traversal("/foo/..\\bar"));
        assert!(v.is_path_traversal("/foo/%2e%2e/bar"));
        assert!(v.is_path_traversal("/foo/..%2f/bar"));
        assert!(!v.is_path_traversal("/api/v1/test"));
    }

    #[test]
    fn test_validator_with_defaults_varies() {
        let public = RequestValidator::with_defaults(EndpointClassification::Public);
        let critical = RequestValidator::with_defaults(EndpointClassification::Critical);
        assert!(public.max_body_size > critical.max_body_size);
        assert!(public.max_path_length > critical.max_path_length);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_blocked_pattern_null_byte() {
        let v = RequestValidator::new().with_default_blocked_patterns();
        let matched = v.check_blocked_patterns("/api/test%00admin");
        assert_eq!(matched, Some("null_byte_injection".into()));
    }

    #[test]
    fn test_blocked_pattern_ssti() {
        let v = RequestValidator::new().with_default_blocked_patterns();
        let matched = v.check_blocked_patterns("{{config.__class__}}");
        assert_eq!(matched, Some("ssti".into()));
    }

    #[test]
    fn test_blocked_pattern_http_response_splitting() {
        let v = RequestValidator::new().with_default_blocked_patterns();
        let matched = v.check_blocked_patterns("value%0d%0aInjected-Header: evil");
        assert_eq!(matched, Some("http_response_splitting".into()));
    }

    #[test]
    fn test_blocked_pattern_clean_input() {
        let v = RequestValidator::new().with_default_blocked_patterns();
        let matched = v.check_blocked_patterns("/api/v1/users/123");
        assert!(matched.is_none());
    }

    #[test]
    fn test_add_custom_blocked_pattern() {
        let mut v = RequestValidator::new();
        v.add_blocked_pattern("sql_union", r"(?i)union\s+select").unwrap();
        assert!(v.check_blocked_patterns("1 UNION SELECT * FROM users").is_some());
        assert!(v.check_blocked_patterns("normal query").is_none());
    }

    #[test]
    fn test_validate_body_content_type() {
        let v = RequestValidator::new();
        let req = WebRequest::new("r1", HttpMethod::Post, "/api", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"key":"value"}"#);
        assert!(v.validate_body_content_type(&req, &["application/json", "text/plain"]));
        assert!(!v.validate_body_content_type(&req, &["text/xml"]));
    }

    #[test]
    fn test_validate_body_size_by_method() {
        let v = RequestValidator::new();
        let get_with_body = WebRequest::new("r1", HttpMethod::Get, "/api", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_body("should not have body");
        assert!(!v.validate_body_size_by_method(&get_with_body));

        let post_with_body = WebRequest::new("r2", HttpMethod::Post, "/api", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Content-Type", "text/plain")
            .with_body("valid body");
        assert!(v.validate_body_size_by_method(&post_with_body));
    }

    #[test]
    fn test_is_valid_ipv4() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("10.0.0.1"));
        assert!(is_valid_ipv4("255.255.255.255"));
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("1.2.3"));
        assert!(!is_valid_ipv4("abc.def.ghi.jkl"));
        assert!(!is_valid_ipv4("01.02.03.04")); // leading zeros
    }

    #[test]
    fn test_is_private_ip() {
        use super::is_private_ip;
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("192.168.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("172.15.0.1"));
        assert!(!is_private_ip("172.32.0.1"));
    }

    #[test]
    fn test_is_loopback() {
        use super::is_loopback;
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.255.255.255"));
        assert!(!is_loopback("128.0.0.1"));
        assert!(!is_loopback("10.0.0.1"));
    }
}
