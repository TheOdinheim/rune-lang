// ═══════════════════════════════════════════════════════════════════════
// Token Classification — Regex-Based PII & Secret Detection (Layer 2)
//
// Classifies input tokens as PII (email, phone, SSN, credit card, IP)
// or secrets (AWS keys, GitHub tokens, JWT, API keys). Provides
// detection, enumeration, and redaction capabilities.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ── PII token types ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiTokenType {
    Email,
    PhoneNumber,
    SocialSecurityNumber,
    CreditCardNumber,
    IpAddress,
    DateOfBirth,
    StreetAddress,
    Name,
    Custom(String),
}

impl fmt::Display for PiiTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ── Secret token types ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretTokenType {
    ApiKey,
    AwsAccessKey,
    AwsSecretKey,
    GitHubToken,
    JwtToken,
    PrivateKey,
    Password,
    ConnectionString,
    Custom(String),
}

impl fmt::Display for SecretTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ── Unified token type ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
    Pii(PiiTokenType),
    Secret(SecretTokenType),
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pii(p) => write!(f, "PII:{p}"),
            Self::Secret(s) => write!(f, "Secret:{s}"),
        }
    }
}

// ── Token classification result ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TokenClassification {
    pub token_type: TokenType,
    pub matched_text: String,
    pub start: usize,
    pub end: usize,
}

// ── Internal pattern entry ──────────────────────────────────────────

struct TokenPattern {
    token_type: TokenType,
    compiled: Regex,
    redaction_label: String,
}

// ── TokenClassifier ─────────────────────────────────────────────────

pub struct TokenClassifier {
    patterns: Vec<TokenPattern>,
}

impl TokenClassifier {
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // PII patterns
        let pii_defs: Vec<(PiiTokenType, &str, &str)> = vec![
            (PiiTokenType::Email, r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL]"),
            (PiiTokenType::PhoneNumber, r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[PHONE]"),
            (PiiTokenType::SocialSecurityNumber, r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
            (PiiTokenType::CreditCardNumber, r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "[CC]"),
            (PiiTokenType::IpAddress, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]"),
        ];

        for (pii_type, pat, label) in pii_defs {
            patterns.push(TokenPattern {
                token_type: TokenType::Pii(pii_type),
                compiled: Regex::new(pat).unwrap(),
                redaction_label: label.to_string(),
            });
        }

        // Secret patterns
        let secret_defs: Vec<(SecretTokenType, &str, &str)> = vec![
            (SecretTokenType::AwsAccessKey, r"\bAKIA[0-9A-Z]{16}\b", "[AWS_KEY]"),
            (SecretTokenType::GitHubToken, r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b", "[GITHUB_TOKEN]"),
            (SecretTokenType::JwtToken, r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b", "[JWT]"),
            (SecretTokenType::ApiKey, r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9_-]{20,}"#, "[API_KEY]"),
        ];

        for (secret_type, pat, label) in secret_defs {
            patterns.push(TokenPattern {
                token_type: TokenType::Secret(secret_type),
                compiled: Regex::new(pat).unwrap(),
                redaction_label: label.to_string(),
            });
        }

        Self { patterns }
    }

    pub fn classify(&self, input: &str) -> Vec<TokenClassification> {
        let mut results = Vec::new();
        for pat in &self.patterns {
            for m in pat.compiled.find_iter(input) {
                results.push(TokenClassification {
                    token_type: pat.token_type.clone(),
                    matched_text: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
        results.sort_by_key(|r| r.start);
        results
    }

    pub fn contains_pii(&self, input: &str) -> bool {
        self.patterns.iter().any(|p| {
            matches!(p.token_type, TokenType::Pii(_)) && p.compiled.is_match(input)
        })
    }

    pub fn contains_secrets(&self, input: &str) -> bool {
        self.patterns.iter().any(|p| {
            matches!(p.token_type, TokenType::Secret(_)) && p.compiled.is_match(input)
        })
    }

    pub fn pii_types_found(&self, input: &str) -> Vec<PiiTokenType> {
        let mut types = Vec::new();
        for pat in &self.patterns {
            if let TokenType::Pii(ref pii_type) = pat.token_type {
                if pat.compiled.is_match(input) {
                    types.push(pii_type.clone());
                }
            }
        }
        types
    }

    pub fn secret_types_found(&self, input: &str) -> Vec<SecretTokenType> {
        let mut types = Vec::new();
        for pat in &self.patterns {
            if let TokenType::Secret(ref secret_type) = pat.token_type {
                if pat.compiled.is_match(input) {
                    types.push(secret_type.clone());
                }
            }
        }
        types
    }

    pub fn redact_pii(&self, input: &str) -> String {
        let mut result = input.to_string();
        for pat in &self.patterns {
            if matches!(pat.token_type, TokenType::Pii(_)) {
                result = pat.compiled.replace_all(&result, pat.redaction_label.as_str()).to_string();
            }
        }
        result
    }

    pub fn redact_secrets(&self, input: &str) -> String {
        let mut result = input.to_string();
        for pat in &self.patterns {
            if matches!(pat.token_type, TokenType::Secret(_)) {
                result = pat.compiled.replace_all(&result, pat.redaction_label.as_str()).to_string();
            }
        }
        result
    }

    pub fn redact_all(&self, input: &str) -> String {
        let mut result = input.to_string();
        for pat in &self.patterns {
            result = pat.compiled.replace_all(&result, pat.redaction_label.as_str()).to_string();
        }
        result
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for TokenClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TokenClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenClassifier")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn email_str() -> String { "user@example.com".to_string() }
    fn email_input() -> String { format!("contact us at {}", email_str()) }
    fn phone_input() -> String { "call 555-123-4567 please".to_string() }
    fn ip_str() -> String { "192.168.1.100".to_string() }
    fn aws_key() -> String { "AKIAIOSFODNN7EXAMPLE".to_string() }
    fn jwt_str() -> String {
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456".to_string()
    }
    fn api_key_input() -> String { "api_key=abcdefghijklmnopqrstuvwxyz".to_string() }

    #[test]
    fn test_classifier_has_builtin_patterns() {
        let c = TokenClassifier::new();
        assert!(c.pattern_count() >= 9);
    }

    #[test]
    fn test_detect_email() {
        let c = TokenClassifier::new();
        assert!(c.contains_pii(&email_input()));
        let types = c.pii_types_found(&email_str());
        assert!(types.contains(&PiiTokenType::Email));
    }

    #[test]
    fn test_detect_phone() {
        let c = TokenClassifier::new();
        assert!(c.contains_pii(&phone_input()));
        let types = c.pii_types_found("555-123-4567");
        assert!(types.contains(&PiiTokenType::PhoneNumber));
    }

    #[test]
    fn test_detect_ssn() {
        let c = TokenClassifier::new();
        assert!(c.contains_pii("SSN: 123-45-6789"));
        let types = c.pii_types_found("123-45-6789");
        assert!(types.contains(&PiiTokenType::SocialSecurityNumber));
    }

    #[test]
    fn test_detect_credit_card() {
        let c = TokenClassifier::new();
        assert!(c.contains_pii("card: 4111 1111 1111 1111"));
        let types = c.pii_types_found("4111 1111 1111 1111");
        assert!(types.contains(&PiiTokenType::CreditCardNumber));
    }

    #[test]
    fn test_detect_ip_address() {
        let c = TokenClassifier::new();
        let input = format!("server at {}", ip_str());
        assert!(c.contains_pii(&input));
        let types = c.pii_types_found(&ip_str());
        assert!(types.contains(&PiiTokenType::IpAddress));
    }

    #[test]
    fn test_detect_aws_key() {
        let c = TokenClassifier::new();
        let input = format!("key: {}", aws_key());
        assert!(c.contains_secrets(&input));
        let types = c.secret_types_found(&aws_key());
        assert!(types.contains(&SecretTokenType::AwsAccessKey));
    }

    #[test]
    fn test_detect_github_token() {
        let c = TokenClassifier::new();
        let token = format!("ghp_{}", "a".repeat(40));
        assert!(c.contains_secrets(&token));
        let types = c.secret_types_found(&token);
        assert!(types.contains(&SecretTokenType::GitHubToken));
    }

    #[test]
    fn test_detect_jwt() {
        let c = TokenClassifier::new();
        let jwt = jwt_str();
        assert!(c.contains_secrets(&jwt));
        let types = c.secret_types_found(&jwt);
        assert!(types.contains(&SecretTokenType::JwtToken));
    }

    #[test]
    fn test_detect_api_key() {
        let c = TokenClassifier::new();
        let input = api_key_input();
        assert!(c.contains_secrets(&input));
        let types = c.secret_types_found(&input);
        assert!(types.contains(&SecretTokenType::ApiKey));
    }

    #[test]
    fn test_no_pii_in_clean_text() {
        let c = TokenClassifier::new();
        assert!(!c.contains_pii("The weather is nice."));
    }

    #[test]
    fn test_no_secrets_in_clean_text() {
        let c = TokenClassifier::new();
        assert!(!c.contains_secrets("The weather is nice."));
    }

    #[test]
    fn test_classify_returns_sorted_by_position() {
        let c = TokenClassifier::new();
        let input = format!("email {} and call 555-123-4567", email_str());
        let results = c.classify(&input);
        assert!(results.len() >= 2);
        for w in results.windows(2) {
            assert!(w[0].start <= w[1].start);
        }
    }

    #[test]
    fn test_redact_pii() {
        let c = TokenClassifier::new();
        let input = format!("email: {}", email_str());
        let redacted = c.redact_pii(&input);
        assert!(redacted.contains("[EMAIL]"));
        assert!(!redacted.contains(&email_str()));
    }

    #[test]
    fn test_redact_secrets() {
        let c = TokenClassifier::new();
        let input = format!("key: {}", aws_key());
        let redacted = c.redact_secrets(&input);
        assert!(redacted.contains("[AWS_KEY]"));
        assert!(!redacted.contains(&aws_key()));
    }

    #[test]
    fn test_redact_all() {
        let c = TokenClassifier::new();
        let input = format!("{} has key {}", email_str(), aws_key());
        let redacted = c.redact_all(&input);
        assert!(redacted.contains("[EMAIL]"));
        assert!(redacted.contains("[AWS_KEY]"));
    }

    #[test]
    fn test_token_type_display() {
        let pii_str = TokenType::Pii(PiiTokenType::Email).to_string();
        assert!(pii_str.contains("PII") && pii_str.contains("Email"));
        let secret_str = TokenType::Secret(SecretTokenType::ApiKey).to_string();
        assert!(secret_str.contains("Secret") && secret_str.contains("ApiKey"));
    }
}
