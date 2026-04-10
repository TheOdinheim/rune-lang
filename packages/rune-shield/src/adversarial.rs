// ═══════════════════════════════════════════════════════════════════════
// Adversarial Input Detection
//
// Detects adversarial / noise / low-information-density inputs using
// statistical properties of the text. Covers:
//   - AbnormalCharDistribution (Shannon entropy extremes)
//   - ExcessiveRepetition
//   - UnicodeAnomaly (control chars, zero-width, RTL override, mixed scripts)
//   - LowInformationDensity (unique-token ratio)
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── AdversarialType ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdversarialType {
    AbnormalCharDistribution,
    ExcessiveRepetition,
    UnicodeAnomaly,
    LowInformationDensity,
}

impl AdversarialType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AbnormalCharDistribution => "AbnormalCharDistribution",
            Self::ExcessiveRepetition => "ExcessiveRepetition",
            Self::UnicodeAnomaly => "UnicodeAnomaly",
            Self::LowInformationDensity => "LowInformationDensity",
        }
    }
}

impl fmt::Display for AdversarialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── AdversarialFinding ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdversarialFinding {
    pub adversarial_type: AdversarialType,
    pub score: f64,
    pub detail: String,
}

// ── AdversarialResult ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AdversarialResult {
    pub findings: Vec<AdversarialFinding>,
    pub confidence: f64,
}

impl AdversarialResult {
    pub fn is_adversarial(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }
}

// ── AdversarialDetector ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdversarialDetector {
    pub min_length_for_entropy: usize,
}

impl Default for AdversarialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AdversarialDetector {
    pub fn new() -> Self {
        Self { min_length_for_entropy: 20 }
    }

    pub fn analyze(&self, input: &str) -> AdversarialResult {
        let mut findings = Vec::new();

        if let Some(f) = self.check_char_distribution(input) {
            findings.push(f);
        }
        if let Some(f) = self.check_repetition(input) {
            findings.push(f);
        }
        if let Some(f) = self.check_unicode_anomaly(input) {
            findings.push(f);
        }
        if let Some(f) = self.check_info_density(input) {
            findings.push(f);
        }

        let confidence = findings.iter().map(|f| f.score).fold(0.0_f64, f64::max);
        AdversarialResult { findings, confidence }
    }

    fn check_char_distribution(&self, input: &str) -> Option<AdversarialFinding> {
        if input.chars().count() < self.min_length_for_entropy {
            return None;
        }
        let entropy = shannon_entropy(input);
        // Natural English ≈ 3.5–4.5 bits/char over character set.
        // Very low entropy = repetitive; very high entropy = random noise.
        if entropy < 1.5 {
            Some(AdversarialFinding {
                adversarial_type: AdversarialType::AbnormalCharDistribution,
                score: ((1.5 - entropy) / 1.5).min(1.0),
                detail: format!("low entropy {entropy:.2}"),
            })
        } else if entropy > 5.5 {
            Some(AdversarialFinding {
                adversarial_type: AdversarialType::AbnormalCharDistribution,
                score: ((entropy - 5.5) / 2.0).min(1.0),
                detail: format!("high entropy {entropy:.2}"),
            })
        } else {
            None
        }
    }

    fn check_repetition(&self, input: &str) -> Option<AdversarialFinding> {
        if input.len() < 10 {
            return None;
        }
        // Max run of same character.
        let mut max_run = 1usize;
        let mut cur = 1usize;
        let chars: Vec<char> = input.chars().collect();
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] {
                cur += 1;
                if cur > max_run {
                    max_run = cur;
                }
            } else {
                cur = 1;
            }
        }
        // Repeated substring detection: check 3-char windows.
        let mut counts: HashMap<&str, usize> = HashMap::new();
        if input.len() >= 3 {
            for i in 0..=input.len().saturating_sub(3) {
                if let Some(s) = input.get(i..i + 3) {
                    *counts.entry(s).or_insert(0) += 1;
                }
            }
        }
        let max_substring = counts.values().copied().max().unwrap_or(0);

        let run_score = if max_run >= 10 {
            (max_run as f64 / 30.0).min(1.0)
        } else {
            0.0
        };
        let sub_score = if max_substring >= 10 {
            (max_substring as f64 / 50.0).min(1.0)
        } else {
            0.0
        };
        let score = run_score.max(sub_score);
        if score > 0.0 {
            Some(AdversarialFinding {
                adversarial_type: AdversarialType::ExcessiveRepetition,
                score,
                detail: format!("max run {max_run}, max substring count {max_substring}"),
            })
        } else {
            None
        }
    }

    fn check_unicode_anomaly(&self, input: &str) -> Option<AdversarialFinding> {
        let mut flags = Vec::new();
        let mut score = 0.0_f64;

        for c in input.chars() {
            // Zero-width, LTR/RTL marks, bidi overrides.
            if matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{FEFF}'
            ) {
                score = score.max(0.9);
                if !flags.contains(&"bidi/zwsp") {
                    flags.push("bidi/zwsp");
                }
            }
        }

        // Abnormal control char density.
        let ctrl = input
            .chars()
            .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
            .count();
        if ctrl > 0 {
            score = score.max((ctrl as f64 / 5.0).min(0.8));
            flags.push("control chars");
        }

        if score > 0.0 {
            Some(AdversarialFinding {
                adversarial_type: AdversarialType::UnicodeAnomaly,
                score,
                detail: flags.join(","),
            })
        } else {
            None
        }
    }

    fn check_info_density(&self, input: &str) -> Option<AdversarialFinding> {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.len() < 10 {
            return None;
        }
        let mut unique = std::collections::HashSet::new();
        for t in &tokens {
            unique.insert(*t);
        }
        let ratio = unique.len() as f64 / tokens.len() as f64;
        if ratio < 0.2 {
            Some(AdversarialFinding {
                adversarial_type: AdversarialType::LowInformationDensity,
                score: ((0.2 - ratio) / 0.2).min(1.0),
                detail: format!("unique ratio {ratio:.2}"),
            })
        } else {
            None
        }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let mut h = 0.0_f64;
    for &c in counts.values() {
        let p = c as f64 / total as f64;
        if p > 0.0 {
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_entropy_flagged() {
        let d = AdversarialDetector::new();
        let r = d.analyze("aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(r.findings.iter().any(|f| {
            f.adversarial_type == AdversarialType::AbnormalCharDistribution
                || f.adversarial_type == AdversarialType::ExcessiveRepetition
        }));
    }

    #[test]
    fn test_repetition_detected() {
        let d = AdversarialDetector::new();
        let r = d.analyze("foofoofoofoofoofoofoofoofoofoo");
        assert!(r
            .findings
            .iter()
            .any(|f| f.adversarial_type == AdversarialType::ExcessiveRepetition));
    }

    #[test]
    fn test_unicode_zero_width() {
        let d = AdversarialDetector::new();
        let r = d.analyze("hello\u{200B}world\u{202E}");
        assert!(r
            .findings
            .iter()
            .any(|f| f.adversarial_type == AdversarialType::UnicodeAnomaly));
    }

    #[test]
    fn test_low_info_density() {
        let d = AdversarialDetector::new();
        let r = d.analyze("the the the the the the the the the the the the");
        assert!(r
            .findings
            .iter()
            .any(|f| f.adversarial_type == AdversarialType::LowInformationDensity));
    }

    #[test]
    fn test_normal_text_clean() {
        let d = AdversarialDetector::new();
        let r = d.analyze("The quick brown fox jumps over the lazy dog repeatedly each day.");
        assert!(r.confidence < 0.5);
    }

    #[test]
    fn test_is_adversarial_threshold() {
        let d = AdversarialDetector::new();
        let r = d.analyze("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(r.is_adversarial(0.3));
    }

    #[test]
    fn test_shannon_entropy_bounds() {
        assert!((shannon_entropy("aaaa") - 0.0).abs() < 1e-9);
        assert!(shannon_entropy("abcdefgh") > 2.0);
    }
}
