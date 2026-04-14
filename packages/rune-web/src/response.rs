// ═══════════════════════════════════════════════════════════════════════
// Response — HTTP response governance: header enforcement, data
// leakage detection, and security hardening.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

// ── WebResponse ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WebResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_size_bytes: u64,
}

impl WebResponse {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            headers: HashMap::new(),
            body: None,
            body_size_bytes: 0,
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
}

// ── DataLeakageType ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataLeakageType {
    InternalIpAddress,
    StackTrace,
    InternalPath,
    SecretExposure,
    DebugInformation,
    // Layer 2 additions
    DatabaseConnectionString,
    AwsCredential,
    PrivateKey,
    ErrorDetail,
}

impl fmt::Display for DataLeakageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InternalIpAddress => write!(f, "InternalIpAddress"),
            Self::StackTrace => write!(f, "StackTrace"),
            Self::InternalPath => write!(f, "InternalPath"),
            Self::SecretExposure => write!(f, "SecretExposure"),
            Self::DebugInformation => write!(f, "DebugInformation"),
            Self::DatabaseConnectionString => write!(f, "DatabaseConnectionString"),
            Self::AwsCredential => write!(f, "AwsCredential"),
            Self::PrivateKey => write!(f, "PrivateKey"),
            Self::ErrorDetail => write!(f, "ErrorDetail"),
        }
    }
}

// ── DataLeakageFind ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataLeakageFind {
    pub leak_type: DataLeakageType,
    pub detail: String,
    pub severity: SecuritySeverity,
}

// ── ResponseGovernanceResult ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResponseGovernanceResult {
    pub headers_added: Vec<String>,
    pub headers_removed: Vec<String>,
    pub data_leaks_found: Vec<DataLeakageFind>,
    pub body_truncated: bool,
    pub clean: bool,
}

// ── ResponsePolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResponsePolicy {
    pub enforce_security_headers: bool,
    pub remove_server_header: bool,
    pub remove_powered_by: bool,
    pub max_response_body_bytes: Option<u64>,
    pub check_data_leakage: bool,
    pub required_headers: Vec<(String, String)>,
}

impl ResponsePolicy {
    pub fn new() -> Self {
        Self {
            enforce_security_headers: true,
            remove_server_header: true,
            remove_powered_by: true,
            max_response_body_bytes: None,
            check_data_leakage: true,
            required_headers: Vec::new(),
        }
    }

    pub fn strict() -> Self {
        Self {
            enforce_security_headers: true,
            remove_server_header: true,
            remove_powered_by: true,
            max_response_body_bytes: Some(10_485_760),
            check_data_leakage: true,
            required_headers: Vec::new(),
        }
    }
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ── ResponseGovernor ─────────────────────────────────────────────────

pub struct ResponseGovernor {
    policy: ResponsePolicy,
}

impl ResponseGovernor {
    pub fn new(policy: ResponsePolicy) -> Self {
        Self { policy }
    }

    pub fn govern(&self, response: &mut WebResponse) -> ResponseGovernanceResult {
        let mut headers_added = Vec::new();
        let mut headers_removed = Vec::new();
        let mut body_truncated = false;

        // a. Security headers
        if self.policy.enforce_security_headers {
            let security_headers = [
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("X-XSS-Protection", "0"),
                ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                ("Cache-Control", "no-store"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ];
            for (name, value) in &security_headers {
                if !response.headers.contains_key(*name) {
                    response.headers.insert(name.to_string(), value.to_string());
                    headers_added.push(name.to_string());
                }
            }
        }

        // b. Remove Server header
        if self.policy.remove_server_header && response.headers.remove("Server").is_some() {
            headers_removed.push("Server".into());
        }

        // b2. Remove X-Powered-By
        if self.policy.remove_powered_by && response.headers.remove("X-Powered-By").is_some() {
            headers_removed.push("X-Powered-By".into());
        }

        // c. Add required headers
        for (name, value) in &self.policy.required_headers {
            response.headers.insert(name.clone(), value.clone());
            headers_added.push(name.clone());
        }

        // d. Body size limit
        if let Some(max) = self.policy.max_response_body_bytes {
            if response.body_size_bytes > max {
                if let Some(ref mut body) = response.body {
                    body.truncate(max as usize);
                    response.body_size_bytes = max;
                    body_truncated = true;
                }
            }
        }

        // e. Data leakage scan
        let data_leaks_found = if self.policy.check_data_leakage {
            if let Some(ref body) = response.body {
                self.check_data_leakage(body)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let clean = headers_removed.is_empty() && data_leaks_found.is_empty() && !body_truncated;

        ResponseGovernanceResult {
            headers_added,
            headers_removed,
            data_leaks_found,
            body_truncated,
            clean,
        }
    }

    pub fn check_data_leakage(&self, body: &str) -> Vec<DataLeakageFind> {
        let mut findings = Vec::new();
        let lower = body.to_lowercase();

        // Internal IP addresses
        if body.contains("10.") || body.contains("192.168.") || body.contains("172.16.")
            || body.contains("172.17.") || body.contains("172.18.") || body.contains("172.19.")
            || body.contains("172.20.") || body.contains("172.21.") || body.contains("172.22.")
            || body.contains("172.23.") || body.contains("172.24.") || body.contains("172.25.")
            || body.contains("172.26.") || body.contains("172.27.") || body.contains("172.28.")
            || body.contains("172.29.") || body.contains("172.30.") || body.contains("172.31.")
        {
            // More refined check: look for IP-like patterns
            let has_internal_ip = body.split_whitespace().any(|word| {
                let trimmed = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
                Self::is_internal_ip(trimmed)
            }) || body.split('"').any(|s| Self::is_internal_ip(s.trim()));
            if has_internal_ip {
                findings.push(DataLeakageFind {
                    leak_type: DataLeakageType::InternalIpAddress,
                    detail: "Internal IP address detected in response body".into(),
                    severity: SecuritySeverity::Medium,
                });
            }
        }

        // Stack traces
        let stack_keywords = ["at line", "traceback", "stack trace", "panic", "rust_backtrace"];
        if stack_keywords.iter().any(|kw| lower.contains(kw)) {
            findings.push(DataLeakageFind {
                leak_type: DataLeakageType::StackTrace,
                detail: "Stack trace or error details detected in response body".into(),
                severity: SecuritySeverity::High,
            });
        }

        // Internal paths
        let path_patterns = ["/home/", "/var/", "c:\\users\\", "/usr/local/", "/opt/"];
        if path_patterns.iter().any(|p| lower.contains(p)) {
            findings.push(DataLeakageFind {
                leak_type: DataLeakageType::InternalPath,
                detail: "Internal file system path detected in response body".into(),
                severity: SecuritySeverity::Medium,
            });
        }

        // Secret patterns
        let secret_patterns = ["api_key", "secret_key", "password", "bearer ", "authorization:"];
        if secret_patterns.iter().any(|p| lower.contains(p)) {
            findings.push(DataLeakageFind {
                leak_type: DataLeakageType::SecretExposure,
                detail: "Potential secret or credential detected in response body".into(),
                severity: SecuritySeverity::Critical,
            });
        }

        // Debug information
        let debug_patterns = ["debug mode", "development mode", "debug=true", "stack_trace"];
        if debug_patterns.iter().any(|p| lower.contains(p)) {
            findings.push(DataLeakageFind {
                leak_type: DataLeakageType::DebugInformation,
                detail: "Debug information detected in response body".into(),
                severity: SecuritySeverity::Low,
            });
        }

        findings
    }

    pub fn is_internal_ip(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        if parts.iter().any(|p| p.parse::<u8>().is_err()) {
            return false;
        }
        s.starts_with("10.")
            || s.starts_with("192.168.")
            || {
                if let Some(second) = s.strip_prefix("172.") {
                    if let Some(octet) = second.split('.').next() {
                        if let Ok(n) = octet.parse::<u8>() {
                            return (16..=31).contains(&n);
                        }
                    }
                }
                false
            }
    }
}

// ── DataLeakageScanner (Layer 2) ────────────────────────────────────

pub struct DataLeakageScanner {
    patterns: Vec<(DataLeakageType, Regex, SecuritySeverity)>,
}

impl DataLeakageScanner {
    pub fn new() -> Self {
        let patterns = vec![
            (
                DataLeakageType::InternalIpAddress,
                Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b").unwrap(),
                SecuritySeverity::Medium,
            ),
            (
                DataLeakageType::StackTrace,
                Regex::new(r"(?i)(at\s+line\s+\d+|traceback\s*\(most recent|stack\s*trace|panic\b|rust_backtrace|\.go:\d+|\.java:\d+|\.py:\d+|\.rs:\d+)").unwrap(),
                SecuritySeverity::High,
            ),
            (
                DataLeakageType::InternalPath,
                Regex::new(r"(/home/\w+|/var/(log|www|lib)|/usr/local/|/opt/\w+|/etc/(passwd|shadow|nginx)|[Cc]:\\[Uu]sers\\)").unwrap(),
                SecuritySeverity::Medium,
            ),
            (
                DataLeakageType::SecretExposure,
                Regex::new(r"(?i)(api[_-]?key|secret[_-]?key|password|bearer\s+[a-zA-Z0-9._\-]+|authorization:\s*\S+)").unwrap(),
                SecuritySeverity::Critical,
            ),
            (
                DataLeakageType::DebugInformation,
                Regex::new(r"(?i)(debug\s*mode|development\s*mode|debug\s*=\s*true|stack_trace|verbose\s*error)").unwrap(),
                SecuritySeverity::Low,
            ),
            (
                DataLeakageType::DatabaseConnectionString,
                Regex::new(r"(?i)(mongodb://|postgres://|mysql://|redis://|jdbc:)").unwrap(),
                SecuritySeverity::Critical,
            ),
            (
                DataLeakageType::AwsCredential,
                Regex::new(r"(AKIA[0-9A-Z]{16}|aws_secret_access_key|aws_access_key_id)").unwrap(),
                SecuritySeverity::Critical,
            ),
            (
                DataLeakageType::PrivateKey,
                Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
                SecuritySeverity::Critical,
            ),
            (
                DataLeakageType::ErrorDetail,
                Regex::new(r"(?i)(internal server error.*detail|exception\s*in\s*thread|unhandled\s*exception|fatal\s*error)").unwrap(),
                SecuritySeverity::Medium,
            ),
        ];
        Self { patterns }
    }

    pub fn scan(&self, body: &str) -> Vec<DataLeakageFind> {
        let mut findings = Vec::new();
        for (leak_type, re, severity) in &self.patterns {
            if re.is_match(body) {
                findings.push(DataLeakageFind {
                    leak_type: leak_type.clone(),
                    detail: format!("{} detected via regex pattern", leak_type),
                    severity: severity.clone(),
                });
            }
        }
        findings
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for DataLeakageScanner {
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
    fn test_governor_adds_security_headers() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let mut resp = WebResponse::new(200);
        let result = gov.govern(&mut resp);
        assert!(resp.headers.contains_key("X-Content-Type-Options"));
        assert!(resp.headers.contains_key("X-Frame-Options"));
        assert!(resp.headers.contains_key("Strict-Transport-Security"));
        assert!(resp.headers.contains_key("Referrer-Policy"));
        assert!(resp.headers.contains_key("Permissions-Policy"));
        assert!(!result.headers_added.is_empty());
    }

    #[test]
    fn test_governor_removes_server_header() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let mut resp = WebResponse::new(200).with_header("Server", "nginx/1.19");
        let result = gov.govern(&mut resp);
        assert!(!resp.headers.contains_key("Server"));
        assert!(result.headers_removed.contains(&"Server".to_string()));
    }

    #[test]
    fn test_governor_removes_powered_by() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let mut resp = WebResponse::new(200).with_header("X-Powered-By", "Express");
        let result = gov.govern(&mut resp);
        assert!(!resp.headers.contains_key("X-Powered-By"));
        assert!(result.headers_removed.contains(&"X-Powered-By".to_string()));
    }

    #[test]
    fn test_governor_adds_required_headers() {
        let policy = ResponsePolicy {
            required_headers: vec![("X-Request-Id".into(), "abc123".into())],
            ..ResponsePolicy::new()
        };
        let gov = ResponseGovernor::new(policy);
        let mut resp = WebResponse::new(200);
        gov.govern(&mut resp);
        assert_eq!(resp.headers.get("X-Request-Id").unwrap(), "abc123");
    }

    #[test]
    fn test_governor_truncates_oversized_body() {
        let policy = ResponsePolicy {
            max_response_body_bytes: Some(10),
            ..ResponsePolicy::new()
        };
        let gov = ResponseGovernor::new(policy);
        let mut resp = WebResponse::new(200).with_body("a".repeat(100));
        let result = gov.govern(&mut resp);
        assert!(result.body_truncated);
        assert_eq!(resp.body.unwrap().len(), 10);
    }

    #[test]
    fn test_check_data_leakage_internal_ip() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let findings = gov.check_data_leakage("server at 10.0.1.5 responded");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::InternalIpAddress));
    }

    #[test]
    fn test_check_data_leakage_stack_trace() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let findings = gov.check_data_leakage("Error: panic at line 42 in module.rs");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::StackTrace));
    }

    #[test]
    fn test_check_data_leakage_internal_path() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let findings = gov.check_data_leakage("file not found: /home/deploy/app/config.yml");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::InternalPath));
    }

    #[test]
    fn test_check_data_leakage_secret_exposure() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let findings = gov.check_data_leakage(r#"{"api_key": "sk-12345"}"#);
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::SecretExposure));
    }

    #[test]
    fn test_check_data_leakage_debug_info() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let findings = gov.check_data_leakage("running in debug mode");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::DebugInformation));
    }

    #[test]
    fn test_check_data_leakage_clean_body() {
        let gov = ResponseGovernor::new(ResponsePolicy::new());
        let findings = gov.check_data_leakage(r#"{"status":"ok","data":[1,2,3]}"#);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_response_policy_strict() {
        let strict = ResponsePolicy::strict();
        assert!(strict.enforce_security_headers);
        assert!(strict.remove_server_header);
        assert!(strict.remove_powered_by);
        assert!(strict.check_data_leakage);
        assert!(strict.max_response_body_bytes.is_some());
    }

    #[test]
    fn test_data_leakage_type_display() {
        let types = vec![
            DataLeakageType::InternalIpAddress,
            DataLeakageType::StackTrace,
            DataLeakageType::InternalPath,
            DataLeakageType::SecretExposure,
            DataLeakageType::DebugInformation,
            DataLeakageType::DatabaseConnectionString,
            DataLeakageType::AwsCredential,
            DataLeakageType::PrivateKey,
            DataLeakageType::ErrorDetail,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 9);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_scanner_detects_internal_ip() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan("connecting to 10.0.1.5 on port 8080");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::InternalIpAddress));
    }

    #[test]
    fn test_scanner_detects_stack_trace() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan("error at line 42 in main.rs");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::StackTrace));
    }

    #[test]
    fn test_scanner_detects_db_connection_string() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan("connecting to postgres://user:pass@host/db");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::DatabaseConnectionString));
    }

    #[test]
    fn test_scanner_detects_aws_credential() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan("key=AKIAIOSFODNN7EXAMPLE");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::AwsCredential));
    }

    #[test]
    fn test_scanner_detects_private_key() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::PrivateKey));
    }

    #[test]
    fn test_scanner_detects_error_detail() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan("unhandled exception in request handler");
        assert!(findings.iter().any(|f| f.leak_type == DataLeakageType::ErrorDetail));
    }

    #[test]
    fn test_scanner_clean_body() {
        let scanner = DataLeakageScanner::new();
        let findings = scanner.scan(r#"{"status":"ok","count":42}"#);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scanner_multiple_findings() {
        let scanner = DataLeakageScanner::new();
        let body = "connecting to postgres://admin:secret_key@10.0.1.5/mydb";
        let findings = scanner.scan(body);
        assert!(findings.len() >= 2);
    }

    #[test]
    fn test_scanner_pattern_count() {
        let scanner = DataLeakageScanner::new();
        assert_eq!(scanner.pattern_count(), 9);
    }
}
