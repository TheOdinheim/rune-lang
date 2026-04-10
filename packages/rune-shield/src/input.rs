// ═══════════════════════════════════════════════════════════════════════
// Input validation and sanitization
// ═══════════════════════════════════════════════════════════════════════

use crate::error::ShieldError;

// ── InputValidation ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InputValidation {
    pub valid: bool,
    pub issues: Vec<String>,
}

impl InputValidation {
    pub fn ok() -> Self {
        Self { valid: true, issues: Vec::new() }
    }

    pub fn fail(issue: impl Into<String>) -> Self {
        Self { valid: false, issues: vec![issue.into()] }
    }

    pub fn push(&mut self, issue: impl Into<String>) {
        self.valid = false;
        self.issues.push(issue.into());
    }
}

// ── InputValidator ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InputValidator {
    pub max_length: usize,
    pub reject_null_bytes: bool,
    pub reject_control_chars: bool,
    pub blocked_patterns: Vec<String>,
}

impl InputValidator {
    pub fn new(max_length: usize) -> Self {
        Self {
            max_length,
            reject_null_bytes: true,
            reject_control_chars: false,
            blocked_patterns: Vec::new(),
        }
    }

    pub fn with_blocked(mut self, patterns: Vec<String>) -> Self {
        self.blocked_patterns = patterns;
        self
    }

    pub fn strict(mut self) -> Self {
        self.reject_control_chars = true;
        self
    }

    pub fn validate(&self, input: &str) -> InputValidation {
        let mut v = InputValidation::ok();
        if input.len() > self.max_length {
            v.push(format!(
                "input length {} exceeds max {}",
                input.len(),
                self.max_length
            ));
        }
        if !input.is_ascii() && std::str::from_utf8(input.as_bytes()).is_err() {
            v.push("invalid UTF-8 encoding");
        }
        if self.reject_null_bytes && input.contains('\0') {
            v.push("contains null byte");
        }
        if self.reject_control_chars {
            if input
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
            {
                v.push("contains control characters");
            }
        }
        let lower = input.to_lowercase();
        for p in &self.blocked_patterns {
            if lower.contains(&p.to_lowercase()) {
                v.push(format!("blocked pattern: {p}"));
            }
        }
        v
    }

    pub fn validate_or_err(&self, input: &str) -> Result<(), ShieldError> {
        let v = self.validate(input);
        if v.valid {
            Ok(())
        } else if input.len() > self.max_length {
            Err(ShieldError::InputTooLarge {
                len: input.len(),
                max: self.max_length,
            })
        } else {
            Err(ShieldError::BlockedPattern(v.issues.join("; ")))
        }
    }
}

// ── InputSanitizer ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct InputSanitizer;

impl InputSanitizer {
    pub fn new() -> Self {
        Self
    }

    pub fn strip_control_chars(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
            .collect()
    }

    pub fn normalize_whitespace(&self, input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut last_ws = false;
        for c in input.chars() {
            if c.is_whitespace() {
                if !last_ws {
                    out.push(' ');
                }
                last_ws = true;
            } else {
                out.push(c);
                last_ws = false;
            }
        }
        out.trim().to_string()
    }

    pub fn truncate(&self, input: &str, max: usize) -> String {
        if input.len() <= max {
            return input.to_string();
        }
        let mut end = max;
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        input[..end].to_string()
    }

    pub fn escape_html(&self, input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for c in input.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                _ => out.push(c),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_accepts_normal() {
        let v = InputValidator::new(100);
        assert!(v.validate("hello world").valid);
    }

    #[test]
    fn test_validator_rejects_too_long() {
        let v = InputValidator::new(5);
        let r = v.validate("hello world");
        assert!(!r.valid);
        assert!(r.issues.iter().any(|i| i.contains("exceeds")));
    }

    #[test]
    fn test_validator_rejects_null_byte() {
        let v = InputValidator::new(100);
        assert!(!v.validate("hi\0there").valid);
    }

    #[test]
    fn test_validator_strict_rejects_control_chars() {
        let v = InputValidator::new(100).strict();
        assert!(!v.validate("hi\x07there").valid);
        assert!(v.validate("hi\nthere").valid);
    }

    #[test]
    fn test_validator_blocked_patterns() {
        let v = InputValidator::new(100).with_blocked(vec!["forbidden".into()]);
        assert!(!v.validate("this is FORBIDDEN text").valid);
    }

    #[test]
    fn test_validator_or_err_too_large() {
        let v = InputValidator::new(3);
        let r = v.validate_or_err("hello");
        assert!(matches!(r, Err(ShieldError::InputTooLarge { .. })));
    }

    #[test]
    fn test_sanitizer_strip_control() {
        let s = InputSanitizer::new();
        assert_eq!(s.strip_control_chars("hi\x07there"), "hithere");
        assert_eq!(s.strip_control_chars("a\nb"), "a\nb");
    }

    #[test]
    fn test_sanitizer_normalize_whitespace() {
        let s = InputSanitizer::new();
        assert_eq!(s.normalize_whitespace("  hi   there  "), "hi there");
    }

    #[test]
    fn test_sanitizer_truncate() {
        let s = InputSanitizer::new();
        assert_eq!(s.truncate("hello", 3), "hel");
        assert_eq!(s.truncate("hi", 10), "hi");
    }

    #[test]
    fn test_sanitizer_truncate_utf8_boundary() {
        let s = InputSanitizer::new();
        let out = s.truncate("héllo", 2);
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn test_sanitizer_escape_html() {
        let s = InputSanitizer::new();
        assert_eq!(s.escape_html("<b>&\"'</b>"), "&lt;b&gt;&amp;&quot;&#39;&lt;/b&gt;");
    }
}
