// ═══════════════════════════════════════════════════════════════════════
// Data Exfiltration Detection
//
// Scans outputs for internal data leakage. Wraps rune-privacy's
// PiiDetector for PII categories, plus a library of sensitive
// patterns covering internal system prompts, training data, internal
// architecture references, API keys, and internal URLs.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_privacy::{PiiCategory, PiiDetection, PiiDetector};
use rune_security::SecuritySeverity;
use serde::{Deserialize, Serialize};

// ── SensitivePatternType ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivePatternType {
    InternalSystemPrompt,
    TrainingData,
    InternalArchitecture,
    ApiKeys,
    InternalUrls,
}

impl SensitivePatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InternalSystemPrompt => "InternalSystemPrompt",
            Self::TrainingData => "TrainingData",
            Self::InternalArchitecture => "InternalArchitecture",
            Self::ApiKeys => "ApiKeys",
            Self::InternalUrls => "InternalUrls",
        }
    }

    pub fn default_severity(&self) -> SecuritySeverity {
        match self {
            Self::ApiKeys => SecuritySeverity::Critical,
            Self::InternalSystemPrompt | Self::TrainingData => SecuritySeverity::High,
            Self::InternalArchitecture | Self::InternalUrls => SecuritySeverity::Medium,
        }
    }
}

impl fmt::Display for SensitivePatternType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── SensitivePattern ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SensitivePattern {
    pub pattern_type: SensitivePatternType,
    pub indicators: Vec<&'static str>,
    pub severity: SecuritySeverity,
}

impl SensitivePattern {
    pub fn builtin() -> Vec<Self> {
        vec![
            Self {
                pattern_type: SensitivePatternType::InternalSystemPrompt,
                indicators: vec![
                    "you are an ai assistant",
                    "your instructions are",
                    "system prompt:",
                    "<|system|>",
                    "### system",
                    "i am not allowed to",
                    "i cannot reveal my",
                    "my initial instructions",
                ],
                severity: SecuritySeverity::High,
            },
            Self {
                pattern_type: SensitivePatternType::TrainingData,
                indicators: vec![
                    "training data",
                    "training cutoff",
                    "fine-tuned on",
                    "pretraining corpus",
                    "trained on",
                    "verbatim from",
                ],
                severity: SecuritySeverity::High,
            },
            Self {
                pattern_type: SensitivePatternType::InternalArchitecture,
                indicators: vec![
                    "internal service",
                    "backend service",
                    "database schema",
                    "kubernetes namespace",
                    "internal api",
                    "staging cluster",
                    "production cluster",
                ],
                severity: SecuritySeverity::Medium,
            },
            Self {
                pattern_type: SensitivePatternType::ApiKeys,
                indicators: vec![
                    "api_key=",
                    "apikey=",
                    "api-key:",
                    "bearer ",
                    "sk-",
                    "aws_secret",
                    "aws_access_key",
                    "authorization:",
                    "private_key",
                    "-----begin ",
                ],
                severity: SecuritySeverity::Critical,
            },
            Self {
                pattern_type: SensitivePatternType::InternalUrls,
                indicators: vec![
                    ".internal",
                    ".local",
                    "localhost",
                    "127.0.0.1",
                    "10.0.",
                    "192.168.",
                    "172.16.",
                    ".svc.cluster.local",
                ],
                severity: SecuritySeverity::Medium,
            },
        ]
    }
}

// ── ExfiltrationFinding ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExfiltrationFinding {
    pub pattern_type: Option<SensitivePatternType>,
    pub pii_category: Option<PiiCategory>,
    pub severity: SecuritySeverity,
    pub confidence: f64,
    pub matched: String,
}

// ── ExfiltrationResult ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExfiltrationResult {
    pub findings: Vec<ExfiltrationFinding>,
    pub max_severity: SecuritySeverity,
    pub confidence: f64,
}

impl Default for ExfiltrationResult {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            max_severity: SecuritySeverity::Info,
            confidence: 0.0,
        }
    }
}

impl ExfiltrationResult {
    pub fn is_leaking(&self, threshold: f64) -> bool {
        !self.findings.is_empty() && self.confidence >= threshold
    }
}

// ── ExfiltrationDetector ──────────────────────────────────────────────

pub struct ExfiltrationDetector {
    pub patterns: Vec<SensitivePattern>,
    pub pii_detector: PiiDetector,
}

impl Default for ExfiltrationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExfiltrationDetector {
    pub fn new() -> Self {
        Self {
            patterns: SensitivePattern::builtin(),
            pii_detector: PiiDetector::new(),
        }
    }

    pub fn scan_output(&self, output: &str) -> ExfiltrationResult {
        let mut findings = Vec::new();
        let lower = output.to_lowercase();

        // Sensitive pattern scan.
        for p in &self.patterns {
            let mut hits = 0usize;
            let mut first_match: Option<String> = None;
            for ind in &p.indicators {
                if lower.contains(ind) {
                    hits += 1;
                    if first_match.is_none() {
                        first_match = Some((*ind).to_string());
                    }
                }
            }
            if hits > 0 {
                let confidence = (0.4 + 0.2 * hits as f64).min(0.95);
                findings.push(ExfiltrationFinding {
                    pattern_type: Some(p.pattern_type),
                    pii_category: None,
                    severity: p.severity,
                    confidence,
                    matched: first_match.unwrap_or_default(),
                });
            }
        }

        // PII scan via rune-privacy.
        for d in self.pii_detector.detect_in_text(output) {
            findings.push(pii_to_finding(d));
        }

        let max_severity = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(SecuritySeverity::Info);
        let confidence = findings.iter().map(|f| f.confidence).fold(0.0_f64, f64::max);

        ExfiltrationResult { findings, max_severity, confidence }
    }
}

fn pii_to_finding(d: PiiDetection) -> ExfiltrationFinding {
    let severity = if d.category.is_special_category() {
        SecuritySeverity::Critical
    } else {
        match d.category {
            PiiCategory::Ssn | PiiCategory::FinancialAccount | PiiCategory::Authentication => {
                SecuritySeverity::Critical
            }
            PiiCategory::Email | PiiCategory::Phone | PiiCategory::Address => {
                SecuritySeverity::High
            }
            _ => SecuritySeverity::Medium,
        }
    };
    ExfiltrationFinding {
        pattern_type: None,
        pii_category: Some(d.category),
        severity,
        confidence: d.confidence,
        matched: d.sample.unwrap_or_else(|| d.field_name.clone()),
    }
}

// ── redact_pii ────────────────────────────────────────────────────────

/// Replace common PII patterns in text with redaction markers. Token-
/// based: each whitespace-delimited token is classified and redacted
/// in place. This is best-effort and deliberately simple.
pub fn redact_pii(text: &str) -> String {
    // Phone pass first — phones may span tokens like "555 123 4567".
    let text = redact_phones_in_text(text);
    let text = text.as_str();
    let mut out = String::with_capacity(text.len());
    let mut first = true;
    let mut pending_ws = String::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            if !current.is_empty() {
                if !first {
                    out.push_str(&pending_ws);
                }
                out.push_str(&redact_token(&current));
                current.clear();
                first = false;
                pending_ws.clear();
            }
            pending_ws.push(c);
        } else {
            current.push(c);
        }
        i += 1;
    }
    if !current.is_empty() {
        if !first {
            out.push_str(&pending_ws);
        }
        out.push_str(&redact_token(&current));
    } else {
        out.push_str(&pending_ws);
    }
    out
}

fn redact_token(token: &str) -> String {
    // Strip surrounding punctuation for classification, keep to reattach.
    let leading: String = token
        .chars()
        .take_while(|c| !c.is_alphanumeric() && *c != '@' && *c != '+')
        .collect();
    let trailing: String = token
        .chars()
        .rev()
        .take_while(|c| !c.is_alphanumeric())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let start = leading.len();
    let end = token.len() - trailing.len();
    if start > end {
        return token.to_string();
    }
    let core = &token[start..end];

    let replacement = if looks_like_email(core) {
        Some("[EMAIL REDACTED]")
    } else if looks_like_ssn(core) {
        Some("[SSN REDACTED]")
    } else if looks_like_ip(core) {
        Some("[IP REDACTED]")
    } else if looks_like_credit_card(core) {
        Some("[CC REDACTED]")
    } else {
        None
    };

    if let Some(r) = replacement {
        format!("{leading}{r}{trailing}")
    } else {
        token.to_string()
    }
}

fn looks_like_email(s: &str) -> bool {
    let at_count = s.matches('@').count();
    if at_count != 1 {
        return false;
    }
    let (local, domain) = s.split_once('@').unwrap();
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && local.chars().all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c))
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn looks_like_ssn(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 11 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            3 | 6 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_digit() {
                    return false;
                }
            }
        }
    }
    true
}

fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if let Ok(n) = p.parse::<u32>() {
            if n > 255 {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

fn looks_like_credit_card(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    // Remaining chars must be only digits, '-', or nothing.
    s.chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Redact phone numbers — called as a whole-text pass because phone
/// numbers often span multiple whitespace-separated tokens.
fn redact_phones_in_text(text: &str) -> String {
    // Replace runs of digits + phone separators that contain 10-15 digits.
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Start of a potential phone: digit or '+'.
        if chars[i].is_ascii_digit() || chars[i] == '+' {
            // Scan forward while we see phone chars.
            let start = i;
            let mut j = i;
            let mut digit_count = 0usize;
            while j < chars.len() {
                let c = chars[j];
                if c.is_ascii_digit() {
                    digit_count += 1;
                    j += 1;
                } else if "+-.() ".contains(c) {
                    // Only continue if the next char is a digit, otherwise stop.
                    if j + 1 < chars.len() && chars[j + 1].is_ascii_digit() {
                        j += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            if (10..=15).contains(&digit_count) {
                out.push_str("[PHONE REDACTED]");
                i = j;
                continue;
            }
            // Not a phone: consume only the first char so we can re-scan.
            out.push(chars[start]);
            i = start + 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

// ── Encoded data helpers ─────────────────────────────────────────────

/// Check if input contains a base64-encoded block (min 32 chars).
pub fn contains_base64_block(input: &str) -> bool {
    use regex::Regex;
    let re = Regex::new(r"[A-Za-z0-9+/]{32,}={0,2}").unwrap();
    re.is_match(input)
}

/// Check if input contains a hex-encoded block (min 32 hex chars).
pub fn contains_hex_block(input: &str) -> bool {
    use regex::Regex;
    let re = Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap();
    re.is_match(input)
}

/// Check if input contains JSON keys commonly associated with sensitive data.
pub fn contains_sensitive_json_keys(input: &str) -> bool {
    let lower = input.to_lowercase();
    let keys = [
        "\"password\"", "\"secret\"", "\"api_key\"", "\"apikey\"",
        "\"token\"", "\"access_token\"", "\"private_key\"",
        "\"authorization\"", "\"credential\"", "\"ssn\"",
    ];
    keys.iter().any(|k| lower.contains(k))
}

// ── ExfiltrationAnalysis ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExfiltrationAnalysis {
    pub pii_found: bool,
    pub secrets_found: bool,
    pub encoded_data_found: bool,
    pub sensitive_json_found: bool,
    pub pii_types: Vec<crate::token::PiiTokenType>,
    pub secret_types: Vec<crate::token::SecretTokenType>,
    pub risk_score: f64,
    pub detail: String,
}

// ── ExfiltrationAnalyzer ────────────────────────────────────────────

pub struct ExfiltrationAnalyzer {
    classifier: crate::token::TokenClassifier,
}

impl ExfiltrationAnalyzer {
    pub fn new() -> Self {
        Self {
            classifier: crate::token::TokenClassifier::new(),
        }
    }

    pub fn analyze(&self, input: &str) -> ExfiltrationAnalysis {
        let pii_found = self.classifier.contains_pii(input);
        let secrets_found = self.classifier.contains_secrets(input);
        let encoded_data_found = contains_base64_block(input) || contains_hex_block(input);
        let sensitive_json_found = contains_sensitive_json_keys(input);

        let pii_types = self.classifier.pii_types_found(input);
        let secret_types = self.classifier.secret_types_found(input);

        let mut risk_score = 0.0_f64;
        if pii_found { risk_score += 0.3; }
        if secrets_found { risk_score += 0.5; }
        if encoded_data_found { risk_score += 0.2; }
        if sensitive_json_found { risk_score += 0.2; }
        let risk_score = risk_score.min(1.0);

        let mut parts = Vec::new();
        if pii_found { parts.push(format!("PII({} types)", pii_types.len())); }
        if secrets_found { parts.push(format!("secrets({} types)", secret_types.len())); }
        if encoded_data_found { parts.push("encoded_data".to_string()); }
        if sensitive_json_found { parts.push("sensitive_json".to_string()); }
        let detail = if parts.is_empty() {
            "no exfiltration indicators".to_string()
        } else {
            parts.join(", ")
        };

        ExfiltrationAnalysis {
            pii_found,
            secrets_found,
            encoded_data_found,
            sensitive_json_found,
            pii_types,
            secret_types,
            risk_score,
            detail,
        }
    }
}

impl Default for ExfiltrationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ExfiltrationAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExfiltrationAnalyzer").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_prompt_leak() {
        let d = ExfiltrationDetector::new();
        let r = d.scan_output("You are an AI assistant. Your instructions are to be helpful.");
        assert!(r
            .findings
            .iter()
            .any(|f| f.pattern_type == Some(SensitivePatternType::InternalSystemPrompt)));
    }

    #[test]
    fn test_api_key_leak_critical() {
        let d = ExfiltrationDetector::new();
        let r = d.scan_output("here is your api_key=sk-abc123xyz");
        assert_eq!(r.max_severity, SecuritySeverity::Critical);
    }

    #[test]
    fn test_training_data_leak() {
        let d = ExfiltrationDetector::new();
        let r = d.scan_output("This is verbatim from the training data corpus.");
        assert!(r
            .findings
            .iter()
            .any(|f| f.pattern_type == Some(SensitivePatternType::TrainingData)));
    }

    #[test]
    fn test_internal_url_leak() {
        let d = ExfiltrationDetector::new();
        let r = d.scan_output("contact service at api.internal:8080");
        assert!(r
            .findings
            .iter()
            .any(|f| f.pattern_type == Some(SensitivePatternType::InternalUrls)));
    }

    #[test]
    fn test_no_leak_normal_output() {
        let d = ExfiltrationDetector::new();
        let r = d.scan_output("The capital of France is Paris.");
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_is_leaking_threshold() {
        let d = ExfiltrationDetector::new();
        let r = d.scan_output("api_key=sk-abc123 authorization: bearer xyz");
        assert!(r.is_leaking(0.5));
    }

    #[test]
    fn test_builtin_pattern_count() {
        assert_eq!(SensitivePattern::builtin().len(), 5);
    }

    #[test]
    fn test_redact_emails() {
        let r = redact_pii("contact me at alice@example.com please");
        assert!(r.contains("[EMAIL REDACTED]"));
        assert!(!r.contains("alice@example.com"));
    }

    #[test]
    fn test_redact_ssns() {
        let r = redact_pii("my ssn is 123-45-6789 ok");
        assert!(r.contains("[SSN REDACTED]"));
    }

    #[test]
    fn test_redact_ips() {
        let r = redact_pii("server at 192.168.1.1 is up");
        assert!(r.contains("[IP REDACTED]"));
    }

    #[test]
    fn test_redact_phones() {
        let r = redact_pii("call 555-123-4567 now");
        assert!(r.contains("[PHONE REDACTED]"));
    }

    #[test]
    fn test_redact_leaves_normal_text() {
        let r = redact_pii("The quick brown fox jumps over the lazy dog.");
        assert_eq!(r, "The quick brown fox jumps over the lazy dog.");
    }

    #[test]
    fn test_pattern_type_severity() {
        assert_eq!(
            SensitivePatternType::ApiKeys.default_severity(),
            SecuritySeverity::Critical
        );
        assert_eq!(
            SensitivePatternType::InternalUrls.default_severity(),
            SecuritySeverity::Medium
        );
    }

    // ── ExfiltrationAnalyzer tests (Layer 2) ────────────────────────

    #[test]
    fn test_analyzer_detects_pii() {
        let a = ExfiltrationAnalyzer::new();
        let r = a.analyze(&format!("contact {}", "user@example.com"));
        assert!(r.pii_found);
        assert!(r.risk_score > 0.0);
    }

    #[test]
    fn test_analyzer_detects_secrets() {
        let a = ExfiltrationAnalyzer::new();
        let r = a.analyze(&format!("key: {}", "AKIAIOSFODNN7EXAMPLE"));
        assert!(r.secrets_found);
        assert!(r.risk_score >= 0.5);
    }

    #[test]
    fn test_analyzer_clean_input() {
        let a = ExfiltrationAnalyzer::new();
        let r = a.analyze("The weather is nice.");
        assert!(!r.pii_found);
        assert!(!r.secrets_found);
        assert!(!r.encoded_data_found);
        assert_eq!(r.risk_score, 0.0);
    }

    #[test]
    fn test_contains_base64_block() {
        assert!(contains_base64_block(
            "data: dGhpcyBpcyBhIGxvbmcgZW5vdWdoIGJhc2U2NCBzdHJpbmc="
        ));
        assert!(!contains_base64_block("short"));
    }

    #[test]
    fn test_contains_hex_block() {
        assert!(contains_hex_block(
            "hash: 0123456789abcdef0123456789abcdef"
        ));
        assert!(!contains_hex_block("not hex"));
    }

    #[test]
    fn test_contains_sensitive_json_keys() {
        assert!(contains_sensitive_json_keys(
            "{\"password\": \"hunter2\"}"
        ));
        assert!(contains_sensitive_json_keys(
            "{\"api_key\": \"xyz\"}"
        ));
        assert!(!contains_sensitive_json_keys(
            "{\"name\": \"Alice\"}"
        ));
    }

    #[test]
    fn test_analyzer_encoded_data() {
        let a = ExfiltrationAnalyzer::new();
        let r = a.analyze(
            "payload: dGhpcyBpcyBhIGxvbmcgZW5vdWdoIGJhc2U2NCBzdHJpbmc="
        );
        assert!(r.encoded_data_found);
    }

    #[test]
    fn test_analyzer_sensitive_json() {
        let a = ExfiltrationAnalyzer::new();
        let r = a.analyze("{\"token\": \"abc123\"}");
        assert!(r.sensitive_json_found);
    }

    #[test]
    fn test_analyzer_risk_score_capped() {
        let a = ExfiltrationAnalyzer::new();
        let input = format!(
            "{} {} {} {}",
            "user@test.com",
            "AKIAIOSFODNN7EXAMPLE",
            "dGhpcyBpcyBhIGxvbmcgZW5vdWdoIGJhc2U2NCBzdHJpbmc=",
            "{\"password\":\"x\"}"
        );
        let r = a.analyze(&input);
        assert!(r.risk_score <= 1.0);
    }
}
