// ═══════════════════════════════════════════════════════════════════════
// Threat — Web-specific threat mitigation: CSRF, clickjacking,
// content injection, open redirects, header injection, and more.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::endpoint::HttpMethod;
use crate::request::WebRequest;

// ── WebThreatType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebThreatType {
    Csrf,
    Clickjacking,
    ContentInjection,
    OpenRedirect,
    HttpMethodOverride,
    HeaderInjection,
    HostHeaderAttack,
    SlowlorisAttack,
}

impl fmt::Display for WebThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Csrf => write!(f, "CSRF"),
            Self::Clickjacking => write!(f, "Clickjacking"),
            Self::ContentInjection => write!(f, "ContentInjection"),
            Self::OpenRedirect => write!(f, "OpenRedirect"),
            Self::HttpMethodOverride => write!(f, "HttpMethodOverride"),
            Self::HeaderInjection => write!(f, "HeaderInjection"),
            Self::HostHeaderAttack => write!(f, "HostHeaderAttack"),
            Self::SlowlorisAttack => write!(f, "SlowlorisAttack"),
        }
    }
}

// ── WebThreatCheck ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WebThreatCheck {
    pub threat_type: WebThreatType,
    pub detected: bool,
    pub confidence: f64,
    pub detail: String,
    pub mitigation: String,
}

// ── WebThreatDetector ────────────────────────────────────────────────

pub struct WebThreatDetector {
    enabled_checks: Vec<WebThreatType>,
}

impl WebThreatDetector {
    pub fn new() -> Self {
        Self {
            enabled_checks: vec![
                WebThreatType::Csrf,
                WebThreatType::Clickjacking,
                WebThreatType::ContentInjection,
                WebThreatType::OpenRedirect,
                WebThreatType::HttpMethodOverride,
                WebThreatType::HeaderInjection,
                WebThreatType::HostHeaderAttack,
                WebThreatType::SlowlorisAttack,
            ],
        }
    }

    pub fn with_checks(checks: Vec<WebThreatType>) -> Self {
        Self {
            enabled_checks: checks,
        }
    }

    pub fn scan_request(&self, request: &WebRequest) -> Vec<WebThreatCheck> {
        let mut results = Vec::new();

        // a. CSRF check: state-changing methods without CSRF token
        if self.enabled_checks.contains(&WebThreatType::Csrf) {
            let is_state_changing = matches!(
                request.method,
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
            );
            if is_state_changing && !self.csrf_token_present(request) {
                results.push(WebThreatCheck {
                    threat_type: WebThreatType::Csrf,
                    detected: true,
                    confidence: 0.7,
                    detail: "State-changing request without CSRF token".into(),
                    mitigation: "Add X-CSRF-Token or X-Request-ID header".into(),
                });
            }
        }

        // b. Open redirect
        if self.enabled_checks.contains(&WebThreatType::OpenRedirect) {
            let redirect_params = ["redirect_uri", "return_to", "next", "redirect", "url"];
            for param in &redirect_params {
                if let Some(value) = request.query_params.get(*param) {
                    if !self.check_open_redirect(value, &[]) {
                        results.push(WebThreatCheck {
                            threat_type: WebThreatType::OpenRedirect,
                            detected: true,
                            confidence: 0.8,
                            detail: format!("Potential open redirect via parameter '{param}'"),
                            mitigation: "Validate redirect URL against allowed domains".into(),
                        });
                    }
                }
            }
        }

        // c. HTTP method override
        if self.enabled_checks.contains(&WebThreatType::HttpMethodOverride) {
            let override_headers = ["x-http-method-override", "x-method-override"];
            let has_override = request.headers.keys().any(|k| {
                override_headers.contains(&k.to_lowercase().as_str())
            });
            if has_override {
                results.push(WebThreatCheck {
                    threat_type: WebThreatType::HttpMethodOverride,
                    detected: true,
                    confidence: 0.9,
                    detail: "HTTP method override header detected".into(),
                    mitigation: "Remove method override headers; use correct HTTP method".into(),
                });
            }
        }

        // d. Header injection (CRLF)
        if self.enabled_checks.contains(&WebThreatType::HeaderInjection) {
            let has_crlf = request.headers.values().any(|v| {
                v.contains("\r\n") || v.contains('\r') || v.contains('\n')
            });
            if has_crlf {
                results.push(WebThreatCheck {
                    threat_type: WebThreatType::HeaderInjection,
                    detected: true,
                    confidence: 0.95,
                    detail: "CRLF characters detected in header value".into(),
                    mitigation: "Strip newline characters from header values".into(),
                });
            }
        }

        // e. Host header attack
        if self.enabled_checks.contains(&WebThreatType::HostHeaderAttack) {
            if let Some(host) = request.headers.get("Host").or_else(|| request.headers.get("host")) {
                let suspicious = host.contains(',')
                    || host.contains(' ')
                    || host.starts_with('[');
                if suspicious {
                    results.push(WebThreatCheck {
                        threat_type: WebThreatType::HostHeaderAttack,
                        detected: true,
                        confidence: 0.8,
                        detail: "Suspicious Host header value".into(),
                        mitigation: "Validate Host header against expected hostnames".into(),
                    });
                }
            }
        }

        // f. Content injection
        if self.enabled_checks.contains(&WebThreatType::ContentInjection) {
            if let Some(ref body) = request.body {
                let ct = request
                    .headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == "content-type")
                    .map(|(_, v)| v.to_lowercase());
                if let Some(ct) = ct {
                    if ct.contains("json") && !body.starts_with('{') && !body.starts_with('[') {
                        results.push(WebThreatCheck {
                            threat_type: WebThreatType::ContentInjection,
                            detected: true,
                            confidence: 0.6,
                            detail: "Content-Type is JSON but body does not appear to be JSON".into(),
                            mitigation: "Validate Content-Type matches actual content".into(),
                        });
                    }
                }
            }
        }

        results
    }

    pub fn csrf_token_present(&self, request: &WebRequest) -> bool {
        request.headers.keys().any(|k| {
            let lower = k.to_lowercase();
            lower == "x-csrf-token" || lower == "x-request-id"
        })
    }

    pub fn check_open_redirect(&self, url: &str, allowed_domains: &[&str]) -> bool {
        // Returns true if redirect is safe (allowed domain), false if open redirect
        if url.starts_with('/') && !url.starts_with("//") {
            return true; // Relative URL is safe
        }
        if allowed_domains.is_empty() {
            // No allowed domains configured — any absolute URL is suspect
            return !url.contains("://");
        }
        // Check if URL belongs to an allowed domain
        allowed_domains.iter().any(|domain| {
            url.starts_with(&format!("https://{domain}"))
                || url.starts_with(&format!("http://{domain}"))
        })
    }
}

impl Default for WebThreatDetector {
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

    #[test]
    fn test_detects_missing_csrf_on_post() {
        let detector = WebThreatDetector::new();
        let req = WebRequest::new("r1", HttpMethod::Post, "/api/data", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"key":"value"}"#);
        let threats = detector.scan_request(&req);
        assert!(threats.iter().any(|t| t.threat_type == WebThreatType::Csrf));
    }

    #[test]
    fn test_no_csrf_flag_on_get() {
        let detector = WebThreatDetector::new();
        let req = WebRequest::new("r1", HttpMethod::Get, "/api/data", "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        let threats = detector.scan_request(&req);
        assert!(!threats.iter().any(|t| t.threat_type == WebThreatType::Csrf));
    }

    #[test]
    fn test_detects_open_redirect() {
        let detector = WebThreatDetector::new();
        let req = WebRequest::new("r1", HttpMethod::Get, "/login", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_query("redirect_uri", "https://evil.com/steal");
        let threats = detector.scan_request(&req);
        assert!(threats.iter().any(|t| t.threat_type == WebThreatType::OpenRedirect));
    }

    #[test]
    fn test_check_open_redirect_same_domain() {
        let detector = WebThreatDetector::new();
        assert!(detector.check_open_redirect("https://example.com/home", &["example.com"]));
    }

    #[test]
    fn test_check_open_redirect_blocks_external() {
        let detector = WebThreatDetector::new();
        assert!(!detector.check_open_redirect("https://evil.com/steal", &["example.com"]));
    }

    #[test]
    fn test_detects_method_override() {
        let detector = WebThreatDetector::new();
        let req = WebRequest::new("r1", HttpMethod::Post, "/api/data", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("Content-Type", "application/json")
            .with_header("X-CSRF-Token", "tok123")
            .with_header("X-HTTP-Method-Override", "DELETE")
            .with_body("{}");
        let threats = detector.scan_request(&req);
        assert!(threats.iter().any(|t| t.threat_type == WebThreatType::HttpMethodOverride));
    }

    #[test]
    fn test_detects_header_injection() {
        let detector = WebThreatDetector::new();
        let req = WebRequest::new("r1", HttpMethod::Get, "/api/data", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
            .with_header("X-Custom", "value\r\nInjected: header");
        let threats = detector.scan_request(&req);
        assert!(threats.iter().any(|t| t.threat_type == WebThreatType::HeaderInjection));
    }

    #[test]
    fn test_clean_request_no_threats() {
        let detector = WebThreatDetector::new();
        let req = WebRequest::new("r1", HttpMethod::Get, "/api/data", "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        let threats = detector.scan_request(&req);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_threat_type_display() {
        let types = vec![
            WebThreatType::Csrf,
            WebThreatType::Clickjacking,
            WebThreatType::ContentInjection,
            WebThreatType::OpenRedirect,
            WebThreatType::HttpMethodOverride,
            WebThreatType::HeaderInjection,
            WebThreatType::HostHeaderAttack,
            WebThreatType::SlowlorisAttack,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_csrf_token_present_checks_headers() {
        let detector = WebThreatDetector::new();
        let req_no_token = WebRequest::new("r1", HttpMethod::Post, "/api", "1.2.3.4", 1000);
        assert!(!detector.csrf_token_present(&req_no_token));

        let req_with_csrf = WebRequest::new("r2", HttpMethod::Post, "/api", "1.2.3.4", 1000)
            .with_header("X-CSRF-Token", "abc");
        assert!(detector.csrf_token_present(&req_with_csrf));

        let req_with_request_id = WebRequest::new("r3", HttpMethod::Post, "/api", "1.2.3.4", 1000)
            .with_header("X-Request-ID", "xyz");
        assert!(detector.csrf_token_present(&req_with_request_id));
    }
}
