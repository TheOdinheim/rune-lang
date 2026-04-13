// ═══════════════════════════════════════════════════════════════════════
// Request — HTTP request governance: validation and sanitization.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

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
}
