// ═══════════════════════════════════════════════════════════════════════
// PII Classifier — Pluggable PII detection contract.
//
// Detection of personal information is fundamentally data-dependent and
// may require regex engines, ML models, or external services (AWS Macie,
// Google DLP, Microsoft Presidio). This trait defines the integration
// contract without implementing detection. ML/external integration
// belongs in adapter crates — the dependency surface is too large for
// a trait boundary layer.
//
// ClassifiedPiiCategory extends the existing PiiCategory enum with
// additional categories relevant to external classifiers while reusing
// PiiCategory for the core set.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::PrivacyError;

// ── ClassifiedPiiCategory ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifiedPiiCategory {
    EmailAddress,
    PhoneNumber,
    GovernmentId,
    PaymentCard,
    FinancialAccount,
    IpAddress,
    GeoLocation,
    DateOfBirth,
    FullName,
    MedicalRecord,
    BiometricIdentifier,
    Custom { label: String },
}

impl fmt::Display for ClassifiedPiiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom { label } => write!(f, "Custom({label})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ── PiiClassificationResult ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiClassificationResult {
    pub category: ClassifiedPiiCategory,
    pub confidence: String,
    pub start_byte: usize,
    pub end_byte_exclusive: usize,
    pub classifier_id: String,
}

// ── ClassifierType ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifierType {
    Regex,
    Heuristic,
    Ml,
    External,
}

impl fmt::Display for ClassifierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── PiiClassifier trait ─────────────────────────────────────────────

pub trait PiiClassifier {
    fn classify(&self, input: &str) -> Result<Vec<PiiClassificationResult>, PrivacyError>;
    fn classify_batch(&self, inputs: &[&str]) -> Result<Vec<Vec<PiiClassificationResult>>, PrivacyError> {
        inputs.iter().map(|input| self.classify(input)).collect()
    }
    fn classifier_id(&self) -> &str;
    fn classifier_type(&self) -> ClassifierType;
    fn supported_categories(&self) -> Vec<ClassifiedPiiCategory>;
    fn confidence_threshold(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── RegexPiiClassifier ──────────────────────────────────────────────

pub struct RegexPiiClassifier {
    id: String,
    threshold: String,
    email_re: regex::Regex,
    phone_re: regex::Regex,
    ssn_re: regex::Regex,
    cc_re: regex::Regex,
    ipv4_re: regex::Regex,
    ipv6_re: regex::Regex,
}

impl RegexPiiClassifier {
    pub fn new(id: &str, threshold: &str) -> Self {
        Self {
            id: id.to_string(),
            threshold: threshold.to_string(),
            email_re: regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            phone_re: regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap(),
            ssn_re: regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            cc_re: regex::Regex::new(r"\b\d{13,19}\b").unwrap(),
            ipv4_re: regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
            ipv6_re: regex::Regex::new(r"(?i)\b[0-9a-f]{1,4}(:[0-9a-f]{1,4}){7}\b").unwrap(),
        }
    }

    fn find_matches(&self, input: &str, re: &regex::Regex, category: ClassifiedPiiCategory, confidence: &str) -> Vec<PiiClassificationResult> {
        re.find_iter(input).map(|m| {
            PiiClassificationResult {
                category: category.clone(),
                confidence: confidence.to_string(),
                start_byte: m.start(),
                end_byte_exclusive: m.end(),
                classifier_id: self.id.clone(),
            }
        }).collect()
    }
}

impl PiiClassifier for RegexPiiClassifier {
    fn classify(&self, input: &str) -> Result<Vec<PiiClassificationResult>, PrivacyError> {
        let mut results = Vec::new();
        results.extend(self.find_matches(input, &self.email_re, ClassifiedPiiCategory::EmailAddress, "0.90"));
        results.extend(self.find_matches(input, &self.phone_re, ClassifiedPiiCategory::PhoneNumber, "0.75"));
        results.extend(self.find_matches(input, &self.ssn_re, ClassifiedPiiCategory::GovernmentId, "0.95"));
        results.extend(self.find_matches(input, &self.ipv4_re, ClassifiedPiiCategory::IpAddress, "0.85"));
        results.extend(self.find_matches(input, &self.ipv6_re, ClassifiedPiiCategory::IpAddress, "0.85"));

        // Credit card with Luhn check
        for m in self.cc_re.find_iter(input) {
            let digits = m.as_str();
            if luhn_check(digits) {
                results.push(PiiClassificationResult {
                    category: ClassifiedPiiCategory::PaymentCard,
                    confidence: "0.90".to_string(),
                    start_byte: m.start(),
                    end_byte_exclusive: m.end(),
                    classifier_id: self.id.clone(),
                });
            }
        }

        Ok(results)
    }

    fn classifier_id(&self) -> &str { &self.id }
    fn classifier_type(&self) -> ClassifierType { ClassifierType::Regex }
    fn supported_categories(&self) -> Vec<ClassifiedPiiCategory> {
        vec![
            ClassifiedPiiCategory::EmailAddress,
            ClassifiedPiiCategory::PhoneNumber,
            ClassifiedPiiCategory::GovernmentId,
            ClassifiedPiiCategory::PaymentCard,
            ClassifiedPiiCategory::IpAddress,
        ]
    }
    fn confidence_threshold(&self) -> &str { &self.threshold }
    fn is_active(&self) -> bool { true }
}

// ── HeuristicPiiClassifier ──────────────────────────────────────────

pub struct HeuristicPiiClassifier {
    id: String,
    min_digit_run: usize,
}

impl HeuristicPiiClassifier {
    pub fn new(id: &str, min_digit_run: usize) -> Self {
        Self { id: id.to_string(), min_digit_run }
    }
}

impl PiiClassifier for HeuristicPiiClassifier {
    fn classify(&self, input: &str) -> Result<Vec<PiiClassificationResult>, PrivacyError> {
        let mut results = Vec::new();
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i - start >= self.min_digit_run {
                    results.push(PiiClassificationResult {
                        category: ClassifiedPiiCategory::FinancialAccount,
                        confidence: "0.50".to_string(),
                        start_byte: start,
                        end_byte_exclusive: i,
                        classifier_id: self.id.clone(),
                    });
                }
            } else {
                i += 1;
            }
        }
        Ok(results)
    }

    fn classifier_id(&self) -> &str { &self.id }
    fn classifier_type(&self) -> ClassifierType { ClassifierType::Heuristic }
    fn supported_categories(&self) -> Vec<ClassifiedPiiCategory> {
        vec![ClassifiedPiiCategory::FinancialAccount]
    }
    fn confidence_threshold(&self) -> &str { "0.50" }
    fn is_active(&self) -> bool { true }
}

// ── NullPiiClassifier ───────────────────────────────────────────────

pub struct NullPiiClassifier {
    id: String,
}

impl NullPiiClassifier {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PiiClassifier for NullPiiClassifier {
    fn classify(&self, _input: &str) -> Result<Vec<PiiClassificationResult>, PrivacyError> {
        Ok(Vec::new())
    }

    fn classifier_id(&self) -> &str { &self.id }
    fn classifier_type(&self) -> ClassifierType { ClassifierType::Regex }
    fn supported_categories(&self) -> Vec<ClassifiedPiiCategory> { vec![] }
    fn confidence_threshold(&self) -> &str { "1.0" }
    fn is_active(&self) -> bool { false }
}

// ── Luhn check ──────────────────────────────────────────────────────

fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        if let Some(d) = ch.to_digit(10) {
            let val = if double {
                let v = d * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d
            };
            sum += val;
            double = !double;
        }
    }
    sum % 10 == 0
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_detects_email() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let results = classifier.classify("contact alice@example.com for info").unwrap();
        assert!(results.iter().any(|r| r.category == ClassifiedPiiCategory::EmailAddress));
    }

    #[test]
    fn test_regex_detects_phone() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let results = classifier.classify("call 555-123-4567 today").unwrap();
        assert!(results.iter().any(|r| r.category == ClassifiedPiiCategory::PhoneNumber));
    }

    #[test]
    fn test_regex_detects_ssn() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let results = classifier.classify("SSN: 123-45-6789").unwrap();
        assert!(results.iter().any(|r| r.category == ClassifiedPiiCategory::GovernmentId));
    }

    #[test]
    fn test_regex_detects_ipv4() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let results = classifier.classify("from 192.168.1.1").unwrap();
        assert!(results.iter().any(|r| r.category == ClassifiedPiiCategory::IpAddress));
    }

    #[test]
    fn test_regex_luhn_valid_cc() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        // 4532015112830366 passes Luhn
        let results = classifier.classify("card: 4532015112830366").unwrap();
        assert!(results.iter().any(|r| r.category == ClassifiedPiiCategory::PaymentCard));
    }

    #[test]
    fn test_regex_no_false_positive_on_non_luhn() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let results = classifier.classify("number: 1234567890123").unwrap();
        // Should not match PaymentCard since it won't pass Luhn
        let cc_results: Vec<_> = results.iter().filter(|r| r.category == ClassifiedPiiCategory::PaymentCard).collect();
        // The 13-digit number 1234567890123 fails Luhn
        assert!(cc_results.is_empty());
    }

    #[test]
    fn test_regex_span_positions() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let input = "hi alice@example.com bye";
        let results = classifier.classify(input).unwrap();
        let email = results.iter().find(|r| r.category == ClassifiedPiiCategory::EmailAddress).unwrap();
        assert_eq!(&input[email.start_byte..email.end_byte_exclusive], "alice@example.com");
    }

    #[test]
    fn test_heuristic_detects_digit_runs() {
        let classifier = HeuristicPiiClassifier::new("h1", 8);
        let results = classifier.classify("account 12345678901234 here").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, ClassifiedPiiCategory::FinancialAccount);
    }

    #[test]
    fn test_heuristic_ignores_short_runs() {
        let classifier = HeuristicPiiClassifier::new("h1", 8);
        let results = classifier.classify("code 12345").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_null_classifier() {
        let classifier = NullPiiClassifier::new("null-1");
        let results = classifier.classify("alice@example.com 123-45-6789").unwrap();
        assert!(results.is_empty());
        assert!(!classifier.is_active());
    }

    #[test]
    fn test_classify_batch() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        let results = classifier.classify_batch(&["alice@example.com", "no pii here"]).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[0].is_empty());
        assert!(results[1].is_empty());
    }

    #[test]
    fn test_classifier_metadata() {
        let classifier = RegexPiiClassifier::new("r1", "0.70");
        assert_eq!(classifier.classifier_id(), "r1");
        assert_eq!(classifier.classifier_type(), ClassifierType::Regex);
        assert!(classifier.is_active());
        assert!(!classifier.supported_categories().is_empty());
    }

    #[test]
    fn test_classified_pii_category_display() {
        assert_eq!(ClassifiedPiiCategory::EmailAddress.to_string(), "EmailAddress");
        assert_eq!(ClassifiedPiiCategory::Custom { label: "test".into() }.to_string(), "Custom(test)");
    }

    #[test]
    fn test_classifier_type_display() {
        assert_eq!(ClassifierType::Regex.to_string(), "Regex");
        assert_eq!(ClassifierType::Ml.to_string(), "Ml");
        assert_eq!(ClassifierType::External.to_string(), "External");
    }

    #[test]
    fn test_luhn_check_valid() {
        assert!(luhn_check("4532015112830366"));
        assert!(luhn_check("79927398713"));
    }

    #[test]
    fn test_luhn_check_invalid() {
        assert!(!luhn_check("1234567890123"));
        assert!(!luhn_check("4532015112830367"));
    }
}
