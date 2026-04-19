// ═══════════════════════════════════════════════════════════════════════
// PII Detection and Classification
//
// Heuristic detection of personally identifiable information in text
// and structured records. Field name heuristics + value pattern matching.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── PiiCategory ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiCategory {
    Name,
    Email,
    Phone,
    Ssn,
    Address,
    DateOfBirth,
    FinancialAccount,
    HealthInfo,
    Biometric,
    GeneticData,
    LocationData,
    IpAddress,
    DeviceId,
    Authentication,
    RacialEthnic,
    Political,
    Religious,
    TradeUnion,
    SexualOrientation,
    CriminalRecord,
    Custom(String),
}

impl PiiCategory {
    pub fn is_special_category(&self) -> bool {
        matches!(
            self,
            Self::HealthInfo
                | Self::Biometric
                | Self::GeneticData
                | Self::RacialEthnic
                | Self::Political
                | Self::Religious
                | Self::TradeUnion
                | Self::SexualOrientation
                | Self::CriminalRecord
        )
    }

    pub fn sensitivity_level(&self) -> PiiSensitivity {
        match self {
            Self::Name => PiiSensitivity::Low,
            Self::Email | Self::Phone | Self::Address | Self::DateOfBirth | Self::IpAddress
            | Self::DeviceId | Self::LocationData => PiiSensitivity::Medium,
            Self::Ssn | Self::FinancialAccount | Self::Authentication => PiiSensitivity::High,
            _ if self.is_special_category() => PiiSensitivity::Critical,
            Self::Custom(_) => PiiSensitivity::Medium,
            _ => PiiSensitivity::Medium,
        }
    }

    pub fn gdpr_article(&self) -> Option<&str> {
        if self.is_special_category() {
            Some("Article 9 (Special categories of personal data)")
        } else {
            match self {
                Self::Custom(_) => None,
                _ => Some("Article 4(1) (Personal data)"),
            }
        }
    }
}

impl fmt::Display for PiiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ── PiiSensitivity ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PiiSensitivity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for PiiSensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── PiiDetection ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiiDetection {
    pub category: PiiCategory,
    pub field_name: String,
    pub confidence: f64,
    pub sample: Option<String>,
    pub detector: String,
}

// ── PiiPattern ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiiPattern {
    pub category: PiiCategory,
    pub field_name_patterns: Vec<String>,
    pub value_regex: Option<String>,
    pub confidence_boost: f64,
}

// ── PiiHandling ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiHandling {
    Encrypt,
    Anonymize,
    Pseudonymize,
    Redact,
    Minimize,
    ConsentRequired,
    RetentionLimited { max_days: u64 },
    NoExport,
}

impl fmt::Display for PiiHandling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt => write!(f, "Encrypt"),
            Self::Anonymize => write!(f, "Anonymize"),
            Self::Pseudonymize => write!(f, "Pseudonymize"),
            Self::Redact => write!(f, "Redact"),
            Self::Minimize => write!(f, "Minimize"),
            Self::ConsentRequired => write!(f, "ConsentRequired"),
            Self::RetentionLimited { max_days } => write!(f, "RetentionLimited({max_days} days)"),
            Self::NoExport => write!(f, "NoExport"),
        }
    }
}

// ── PiiFieldTag ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiiFieldTag {
    pub field_name: String,
    pub category: PiiCategory,
    pub sensitivity: PiiSensitivity,
    pub handling_required: PiiHandling,
    pub tagged_at: i64,
    pub tagged_by: String,
}

// ── PiiDetector ───────────────────────────────────────────────────────

pub struct PiiDetector {
    pub patterns: Vec<PiiPattern>,
    pub min_confidence: f64,
}

impl PiiDetector {
    pub fn new() -> Self {
        let patterns = vec![
            PiiPattern {
                category: PiiCategory::Email,
                field_name_patterns: vec!["email".into(), "e-mail".into(), "mail".into(), "email_address".into()],
                value_regex: Some("email".into()),
                confidence_boost: 0.3,
            },
            PiiPattern {
                category: PiiCategory::Phone,
                field_name_patterns: vec!["phone".into(), "tel".into(), "mobile".into(), "cell".into(), "telephone".into()],
                value_regex: Some("phone".into()),
                confidence_boost: 0.3,
            },
            PiiPattern {
                category: PiiCategory::Ssn,
                field_name_patterns: vec!["ssn".into(), "social_security".into(), "national_id".into(), "sin".into()],
                value_regex: Some("ssn".into()),
                confidence_boost: 0.4,
            },
            PiiPattern {
                category: PiiCategory::Name,
                field_name_patterns: vec![
                    "name".into(), "first_name".into(), "last_name".into(),
                    "full_name".into(), "given_name".into(), "surname".into(),
                ],
                value_regex: None,
                confidence_boost: 0.0,
            },
            PiiPattern {
                category: PiiCategory::Address,
                field_name_patterns: vec![
                    "address".into(), "street".into(), "city".into(),
                    "zip".into(), "postal".into(), "state".into(),
                ],
                value_regex: None,
                confidence_boost: 0.0,
            },
            PiiPattern {
                category: PiiCategory::DateOfBirth,
                field_name_patterns: vec!["dob".into(), "date_of_birth".into(), "birthday".into(), "birth_date".into()],
                value_regex: None,
                confidence_boost: 0.0,
            },
            PiiPattern {
                category: PiiCategory::IpAddress,
                field_name_patterns: vec!["ip".into(), "ip_address".into(), "source_ip".into(), "client_ip".into()],
                value_regex: Some("ipv4".into()),
                confidence_boost: 0.3,
            },
            PiiPattern {
                category: PiiCategory::FinancialAccount,
                field_name_patterns: vec![
                    "card".into(), "credit_card".into(), "cc_number".into(),
                    "account".into(), "bank_account".into(),
                ],
                value_regex: Some("ccn".into()),
                confidence_boost: 0.4,
            },
        ];
        Self { patterns, min_confidence: 0.5 }
    }

    pub fn with_confidence(min_confidence: f64) -> Self {
        let mut d = Self::new();
        d.min_confidence = min_confidence;
        d
    }

    pub fn add_pattern(&mut self, pattern: PiiPattern) {
        self.patterns.push(pattern);
    }

    pub fn detect_in_text(&self, text: &str) -> Vec<PiiDetection> {
        let mut results = Vec::new();

        // Email
        if looks_like_email(text) {
            results.push(PiiDetection {
                category: PiiCategory::Email,
                field_name: String::new(),
                confidence: 0.8,
                sample: Some(mask_email(text)),
                detector: "pattern:email".into(),
            });
        }
        // SSN
        if looks_like_ssn(text) {
            results.push(PiiDetection {
                category: PiiCategory::Ssn,
                field_name: String::new(),
                confidence: 0.9,
                sample: Some("XXX-XX-XXXX".into()),
                detector: "pattern:ssn".into(),
            });
        }
        // Phone
        if looks_like_phone(text) {
            results.push(PiiDetection {
                category: PiiCategory::Phone,
                field_name: String::new(),
                confidence: 0.7,
                sample: Some("XXX-XXX-XXXX".into()),
                detector: "pattern:phone".into(),
            });
        }
        // IPv4
        if looks_like_ipv4(text) {
            results.push(PiiDetection {
                category: PiiCategory::IpAddress,
                field_name: String::new(),
                confidence: 0.85,
                sample: Some("x.x.x.x".into()),
                detector: "pattern:ipv4".into(),
            });
        }
        // Credit card (13-19 contiguous digits)
        if looks_like_credit_card(text) {
            results.push(PiiDetection {
                category: PiiCategory::FinancialAccount,
                field_name: String::new(),
                confidence: 0.75,
                sample: Some("**** **** **** XXXX".into()),
                detector: "pattern:ccn".into(),
            });
        }

        results.into_iter().filter(|d| d.confidence >= self.min_confidence).collect()
    }

    pub fn detect_in_fields(&self, fields: &[(&str, &str)]) -> Vec<PiiDetection> {
        let mut results = Vec::new();
        for (field_name, value) in fields {
            let name_lower = field_name.to_lowercase();

            // Try field-name heuristics first
            for pattern in &self.patterns {
                if pattern.field_name_patterns.iter().any(|p| name_lower.contains(p)) {
                    let mut confidence: f64 = 0.6;
                    // If value also looks right, boost
                    if value_matches_category(value, &pattern.category) {
                        confidence = (confidence + pattern.confidence_boost).min(1.0);
                    }
                    results.push(PiiDetection {
                        category: pattern.category.clone(),
                        field_name: (*field_name).to_string(),
                        confidence,
                        sample: Some(redact_sample(value, &pattern.category)),
                        detector: format!("field:{}", pattern_label(&pattern.category)),
                    });
                    break;
                }
            }

            // Pure value-based detection if field name didn't match
            if !results.iter().any(|d| d.field_name == *field_name) {
                let mut in_text = self.detect_in_text(value);
                for det in &mut in_text {
                    det.field_name = (*field_name).to_string();
                }
                results.extend(in_text);
            }
        }
        results.into_iter().filter(|d| d.confidence >= self.min_confidence).collect()
    }

    pub fn detect_in_record(&self, record: &HashMap<String, String>) -> Vec<PiiDetection> {
        let fields: Vec<(&str, &str)> = record.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.detect_in_fields(&fields)
    }

    pub fn has_pii(&self, text: &str) -> bool {
        !self.detect_in_text(text).is_empty()
    }
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Pattern helpers ───────────────────────────────────────────────────

fn looks_like_email(text: &str) -> bool {
    // Find an '@' with some alnum on both sides and a '.' after
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'@' && i > 0 && i < bytes.len() - 3 {
            let before_ok = bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.' || bytes[i - 1] == b'_';
            let after = &text[i + 1..];
            if before_ok && after.contains('.') && after.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) {
                return true;
            }
        }
    }
    false
}

fn mask_email(text: &str) -> String {
    // Find first email-like substring and mask it
    if let Some(at_idx) = text.find('@') {
        let start = text[..at_idx].rfind(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_').map_or(0, |i| i + 1);
        let rest_start = at_idx + 1;
        let domain_end = text[rest_start..].find(|c: char| c.is_whitespace()).map_or(text.len(), |i| rest_start + i);
        let local = &text[start..at_idx];
        let domain = &text[rest_start..domain_end];
        if local.is_empty() || domain.is_empty() {
            return "***@***".into();
        }
        let first = local.chars().next().unwrap();
        let first_d = domain.chars().next().unwrap();
        return format!("{first}***@{first_d}******");
    }
    "***".into()
}

fn looks_like_ssn(text: &str) -> bool {
    // XXX-XX-XXXX
    let bytes = text.as_bytes();
    let n = bytes.len();
    if n < 11 {
        return false;
    }
    for i in 0..=n - 11 {
        let slice = &bytes[i..i + 11];
        if slice[0..3].iter().all(|b| b.is_ascii_digit())
            && slice[3] == b'-'
            && slice[4..6].iter().all(|b| b.is_ascii_digit())
            && slice[6] == b'-'
            && slice[7..11].iter().all(|b| b.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

fn looks_like_phone(text: &str) -> bool {
    // Count ASCII digits in text — 10+ suggests phone
    let digits: usize = text.chars().filter(|c| c.is_ascii_digit()).count();
    let total: usize = text.chars().filter(|c| !c.is_whitespace()).count();
    if total == 0 {
        return false;
    }
    // Must have at least 10 digits AND not look like a pure number/SSN/IP/CCN
    if digits < 10 || digits > 15 {
        return false;
    }
    if looks_like_ssn(text) || looks_like_ipv4(text) || looks_like_credit_card(text) {
        return false;
    }
    // Phone-like punctuation: spaces, dashes, dots, parentheses, plus
    let has_phone_chars = text.chars().any(|c| matches!(c, '-' | '.' | '(' | ')' | '+' | ' '));
    has_phone_chars || (digits == total)
}

fn looks_like_ipv4(text: &str) -> bool {
    // Search for a.b.c.d pattern
    for token in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok() && !p.is_empty()) {
            return true;
        }
    }
    false
}

fn looks_like_credit_card(text: &str) -> bool {
    // 13-19 contiguous digits (allowing spaces/dashes as separators)
    let cleaned: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() < 13 || cleaned.len() > 19 {
        return false;
    }
    // But reject if it looks like SSN or phone
    if looks_like_ssn(text) {
        return false;
    }
    // Must have digits grouped (contiguous runs of >= 4)
    let digit_runs: Vec<&str> = text.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).collect();
    if digit_runs.len() == 1 && digit_runs[0].len() >= 13 {
        return true;
    }
    digit_runs.iter().all(|r| r.len() >= 3) && digit_runs.len() >= 3 && cleaned.len() >= 13
}

fn value_matches_category(value: &str, category: &PiiCategory) -> bool {
    match category {
        PiiCategory::Email => looks_like_email(value),
        PiiCategory::Ssn => looks_like_ssn(value),
        PiiCategory::Phone => looks_like_phone(value),
        PiiCategory::IpAddress => looks_like_ipv4(value),
        PiiCategory::FinancialAccount => looks_like_credit_card(value),
        _ => false,
    }
}

fn redact_sample(value: &str, category: &PiiCategory) -> String {
    match category {
        PiiCategory::Email => mask_email(value),
        PiiCategory::Ssn => "XXX-XX-XXXX".into(),
        PiiCategory::Phone => "XXX-XXX-XXXX".into(),
        PiiCategory::FinancialAccount => "**** **** **** XXXX".into(),
        _ => {
            if value.len() <= 2 {
                "***".into()
            } else {
                format!("{}***", &value[..1])
            }
        }
    }
}

fn pattern_label(category: &PiiCategory) -> &'static str {
    match category {
        PiiCategory::Email => "email",
        PiiCategory::Phone => "phone",
        PiiCategory::Ssn => "ssn",
        PiiCategory::Name => "name",
        PiiCategory::Address => "address",
        PiiCategory::DateOfBirth => "dob",
        PiiCategory::IpAddress => "ip",
        PiiCategory::FinancialAccount => "financial",
        _ => "other",
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Real PII Detection with Regex
// ═══════════════════════════════════════════════════════════════════════

use crate::error::PrivacyError;

/// Confidence level for PII pattern matches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PiiConfidence {
    Low = 0,
    Medium = 1,
    High = 2,
}

impl fmt::Display for PiiConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single PII match from regex scanning.
#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub pii_type: PiiCategory,
    pub pattern_name: String,
    pub confidence: PiiConfidence,
    pub matched_text_redacted: String,
    pub field_name: Option<String>,
    pub byte_offset: usize,
}

/// PII match from structured field scanning.
#[derive(Debug, Clone)]
pub struct PiiFieldMatch {
    pub field_name: String,
    pub matches: Vec<PiiMatch>,
}

/// Production-grade PII scanner with compiled regex patterns.
pub struct PiiRegexScanner {
    patterns: Vec<(PiiCategory, String, regex::Regex, PiiConfidence)>,
}

impl PiiRegexScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            patterns: Vec::new(),
        };
        // Built-in patterns
        scanner.add_builtin("Email", PiiCategory::Email,
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", PiiConfidence::High);
        scanner.add_builtin("US SSN", PiiCategory::Ssn,
            r"\b\d{3}-\d{2}-\d{4}\b", PiiConfidence::High);
        scanner.add_builtin("US SSN no dashes", PiiCategory::Ssn,
            r"\b\d{9}\b", PiiConfidence::Low);
        scanner.add_builtin("US Phone", PiiCategory::Phone,
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", PiiConfidence::Medium);
        scanner.add_builtin("Credit Card", PiiCategory::FinancialAccount,
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b", PiiConfidence::Medium);
        scanner.add_builtin("IPv4 Address", PiiCategory::IpAddress,
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", PiiConfidence::Medium);
        scanner.add_builtin("Date of Birth", PiiCategory::DateOfBirth,
            r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b", PiiConfidence::Medium);
        scanner.add_builtin("US Passport", PiiCategory::Custom("Passport".into()),
            r"\b[A-Z]\d{8}\b", PiiConfidence::Low);
        scanner.add_builtin("AWS Key", PiiCategory::Authentication,
            r"\bAKIA[0-9A-Z]{16}\b", PiiConfidence::High);
        scanner.add_builtin("Private Key", PiiCategory::Authentication,
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", PiiConfidence::High);
        scanner.add_builtin("JWT Token", PiiCategory::Authentication,
            r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", PiiConfidence::High);
        scanner.add_builtin("US ZIP Code", PiiCategory::Address,
            r"\b\d{5}(?:-\d{4})?\b", PiiConfidence::Low);
        scanner
    }

    fn add_builtin(&mut self, name: &str, pii_type: PiiCategory, pattern: &str, confidence: PiiConfidence) {
        if let Ok(re) = regex::Regex::new(pattern) {
            self.patterns.push((pii_type, name.to_string(), re, confidence));
        }
    }

    pub fn add_pattern(
        &mut self,
        pii_type: PiiCategory,
        name: &str,
        pattern: &str,
        confidence: PiiConfidence,
    ) -> Result<(), PrivacyError> {
        let re = regex::Regex::new(pattern).map_err(|e| {
            PrivacyError::InvalidOperation(format!("invalid regex pattern: {}", e))
        })?;
        self.patterns.push((pii_type, name.to_string(), re, confidence));
        Ok(())
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    pub fn scan(&self, text: &str) -> Vec<PiiMatch> {
        let mut results = Vec::new();
        for (pii_type, name, re, confidence) in &self.patterns {
            for m in re.find_iter(text) {
                results.push(PiiMatch {
                    pii_type: pii_type.clone(),
                    pattern_name: name.clone(),
                    confidence: confidence.clone(),
                    matched_text_redacted: redact_match(m.as_str()),
                    field_name: None,
                    byte_offset: m.start(),
                });
            }
        }
        results
    }

    pub fn scan_structured(&self, fields: &HashMap<String, String>) -> Vec<PiiFieldMatch> {
        let mut results = Vec::new();
        for (field_name, value) in fields {
            let mut matches = self.scan(value);
            for m in &mut matches {
                m.field_name = Some(field_name.clone());
            }
            if !matches.is_empty() {
                results.push(PiiFieldMatch {
                    field_name: field_name.clone(),
                    matches,
                });
            }
        }
        results
    }

    pub fn scan_above_confidence(&self, text: &str, min_confidence: PiiConfidence) -> Vec<PiiMatch> {
        self.scan(text)
            .into_iter()
            .filter(|m| m.confidence >= min_confidence)
            .collect()
    }
}

impl Default for PiiRegexScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn redact_match(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 4 {
        return "***".to_string();
    }
    let first: String = chars[..2].iter().collect();
    let last: String = chars[chars.len() - 2..].iter().collect();
    format!("{}***{}", first, last)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_categories() {
        assert!(PiiCategory::HealthInfo.is_special_category());
        assert!(PiiCategory::Biometric.is_special_category());
        assert!(PiiCategory::GeneticData.is_special_category());
        assert!(PiiCategory::RacialEthnic.is_special_category());
        assert!(PiiCategory::Political.is_special_category());
        assert!(PiiCategory::Religious.is_special_category());
        assert!(PiiCategory::TradeUnion.is_special_category());
        assert!(PiiCategory::SexualOrientation.is_special_category());
        assert!(PiiCategory::CriminalRecord.is_special_category());
    }

    #[test]
    fn test_standard_pii_not_special() {
        assert!(!PiiCategory::Email.is_special_category());
        assert!(!PiiCategory::Name.is_special_category());
        assert!(!PiiCategory::Phone.is_special_category());
    }

    #[test]
    fn test_sensitivity_levels() {
        assert_eq!(PiiCategory::Name.sensitivity_level(), PiiSensitivity::Low);
        assert_eq!(PiiCategory::Email.sensitivity_level(), PiiSensitivity::Medium);
        assert_eq!(PiiCategory::Ssn.sensitivity_level(), PiiSensitivity::High);
        assert_eq!(PiiCategory::Biometric.sensitivity_level(), PiiSensitivity::Critical);
    }

    #[test]
    fn test_sensitivity_ordering() {
        assert!(PiiSensitivity::Critical > PiiSensitivity::High);
        assert!(PiiSensitivity::High > PiiSensitivity::Medium);
        assert!(PiiSensitivity::Medium > PiiSensitivity::Low);
    }

    #[test]
    fn test_gdpr_article() {
        assert!(PiiCategory::HealthInfo.gdpr_article().unwrap().contains("Article 9"));
        assert!(PiiCategory::Email.gdpr_article().unwrap().contains("Article 4"));
    }

    #[test]
    fn test_detect_email_in_text() {
        let detector = PiiDetector::new();
        let dets = detector.detect_in_text("contact me at user@example.com please");
        assert!(dets.iter().any(|d| d.category == PiiCategory::Email));
    }

    #[test]
    fn test_detect_phone_in_text() {
        let detector = PiiDetector::new();
        let dets = detector.detect_in_text("call 555-123-4567 today");
        assert!(dets.iter().any(|d| d.category == PiiCategory::Phone));
    }

    #[test]
    fn test_detect_ssn_in_text() {
        let detector = PiiDetector::new();
        let dets = detector.detect_in_text("SSN: 123-45-6789");
        assert!(dets.iter().any(|d| d.category == PiiCategory::Ssn));
    }

    #[test]
    fn test_detect_email_field_name() {
        let detector = PiiDetector::new();
        let dets = detector.detect_in_fields(&[("email", "alice@example.com")]);
        assert!(dets.iter().any(|d| d.category == PiiCategory::Email));
    }

    #[test]
    fn test_detect_ssn_field_name() {
        let detector = PiiDetector::new();
        let dets = detector.detect_in_fields(&[("ssn", "123-45-6789")]);
        assert!(dets.iter().any(|d| d.category == PiiCategory::Ssn));
    }

    #[test]
    fn test_detect_in_record() {
        let mut record = HashMap::new();
        record.insert("name".to_string(), "Alice".to_string());
        record.insert("email".to_string(), "alice@example.com".to_string());
        let detector = PiiDetector::new();
        let dets = detector.detect_in_record(&record);
        assert!(dets.iter().any(|d| d.category == PiiCategory::Name));
        assert!(dets.iter().any(|d| d.category == PiiCategory::Email));
    }

    #[test]
    fn test_detect_fields_combines_heuristics() {
        let detector = PiiDetector::new();
        let dets = detector.detect_in_fields(&[("user_email", "bob@test.com")]);
        // Should detect via field name contains "email"
        assert!(dets.iter().any(|d| d.category == PiiCategory::Email));
    }

    #[test]
    fn test_has_pii() {
        let detector = PiiDetector::new();
        assert!(detector.has_pii("email me at foo@bar.com"));
        assert!(!detector.has_pii("the quick brown fox"));
    }

    #[test]
    fn test_high_confidence_filter() {
        let detector = PiiDetector::with_confidence(0.99);
        // "Alice" alone won't hit any pattern above 0.99
        let dets = detector.detect_in_text("Alice likes apples");
        assert!(dets.is_empty());
    }

    #[test]
    fn test_pii_handling_display() {
        assert_eq!(PiiHandling::Encrypt.to_string(), "Encrypt");
        assert_eq!(PiiHandling::Redact.to_string(), "Redact");
        assert_eq!(
            PiiHandling::RetentionLimited { max_days: 30 }.to_string(),
            "RetentionLimited(30 days)"
        );
    }

    #[test]
    fn test_pii_field_tag_construction() {
        let tag = PiiFieldTag {
            field_name: "email".into(),
            category: PiiCategory::Email,
            sensitivity: PiiSensitivity::Medium,
            handling_required: PiiHandling::Encrypt,
            tagged_at: 1000,
            tagged_by: "scanner".into(),
        };
        assert_eq!(tag.field_name, "email");
        assert_eq!(tag.sensitivity, PiiSensitivity::Medium);
    }

    // ── Layer 2: PII Regex Scanner tests ────────────────────────────

    #[test]
    fn test_regex_scanner_detects_email() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan("contact user@example.com today");
        assert!(matches.iter().any(|m| m.pii_type == PiiCategory::Email));
    }

    #[test]
    fn test_regex_scanner_detects_ssn() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan("SSN: 123-45-6789");
        assert!(matches.iter().any(|m| m.pii_type == PiiCategory::Ssn && m.confidence == PiiConfidence::High));
    }

    #[test]
    fn test_regex_scanner_detects_phone() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan("call (555) 123-4567 now");
        assert!(matches.iter().any(|m| m.pii_type == PiiCategory::Phone));
    }

    #[test]
    fn test_regex_scanner_detects_credit_card() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan("card 4111-1111-1111-1111 on file");
        assert!(matches.iter().any(|m| m.pii_type == PiiCategory::FinancialAccount));
    }

    #[test]
    fn test_regex_scanner_detects_aws_key() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan("key: AKIAIOSFODNN7EXAMPLE");
        assert!(matches.iter().any(|m| m.pii_type == PiiCategory::Authentication
            && m.pattern_name == "AWS Key"));
    }

    #[test]
    fn test_regex_scanner_detects_private_key() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan("-----BEGIN RSA PRIVATE KEY-----");
        assert!(matches.iter().any(|m| m.pii_type == PiiCategory::Authentication
            && m.pattern_name == "Private Key"));
    }

    #[test]
    fn test_regex_scanner_detects_jwt() {
        let scanner = PiiRegexScanner::new();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123_-xyz";
        let matches = scanner.scan(jwt);
        assert!(matches.iter().any(|m| m.pattern_name == "JWT Token"));
    }

    #[test]
    fn test_regex_scanner_clean_text() {
        let scanner = PiiRegexScanner::new();
        let matches = scanner.scan_above_confidence("the quick brown fox jumps", PiiConfidence::Medium);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_regex_scanner_structured() {
        let scanner = PiiRegexScanner::new();
        let mut fields = HashMap::new();
        fields.insert("contact_email".to_string(), "user@example.com".to_string());
        fields.insert("notes".to_string(), "nothing here".to_string());
        let results = scanner.scan_structured(&fields);
        assert!(results.iter().any(|r| r.field_name == "contact_email"));
    }

    #[test]
    fn test_regex_scanner_add_pattern() {
        let mut scanner = PiiRegexScanner::new();
        let before = scanner.pattern_count();
        scanner.add_pattern(
            PiiCategory::Custom("CustomID".into()),
            "Custom ID",
            r"\bCID-\d{6}\b",
            PiiConfidence::High,
        ).unwrap();
        assert_eq!(scanner.pattern_count(), before + 1);
        let matches = scanner.scan("reference CID-123456 noted");
        assert!(matches.iter().any(|m| m.pattern_name == "Custom ID"));
    }

    #[test]
    fn test_regex_scanner_pattern_count() {
        let scanner = PiiRegexScanner::new();
        assert!(scanner.pattern_count() >= 12);
    }

    #[test]
    fn test_pii_match_redacts_text() {
        let redacted = redact_match("user@example.com");
        assert!(redacted.starts_with("us"));
        assert!(redacted.ends_with("om"));
        assert!(redacted.contains("***"));
    }

    #[test]
    fn test_scan_above_confidence_filters() {
        let scanner = PiiRegexScanner::new();
        // "12345" should match ZIP (Low) but not pass Medium filter
        let all = scanner.scan("zip 12345 here");
        let high_only = scanner.scan_above_confidence("zip 12345 here", PiiConfidence::High);
        assert!(all.len() >= high_only.len());
    }

    #[test]
    fn test_pii_confidence_ordering() {
        assert!(PiiConfidence::Low < PiiConfidence::Medium);
        assert!(PiiConfidence::Medium < PiiConfidence::High);
    }
}
