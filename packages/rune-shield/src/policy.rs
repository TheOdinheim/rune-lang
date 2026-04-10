// ═══════════════════════════════════════════════════════════════════════
// ShieldPolicy + ShieldLevel — graduated protection levels and the
// tunable thresholds used across the shield engine.
//
// Levels graduate Bronze → Silver → Gold → Platinum matching the RUNE
// graduation model. Each level tightens input limits, confidence
// thresholds, and detection sensitivity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── ShieldLevel ───────────────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum ShieldLevel {
    Bronze = 0,
    Silver = 1,
    Gold = 2,
    Platinum = 3,
}

impl ShieldLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bronze => "Bronze",
            Self::Silver => "Silver",
            Self::Gold => "Gold",
            Self::Platinum => "Platinum",
        }
    }
}

impl fmt::Display for ShieldLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ShieldPolicy ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ShieldPolicy {
    pub level: ShieldLevel,
    /// Maximum accepted input length in bytes.
    pub max_input_length: usize,
    /// Maximum accepted output length in bytes.
    pub max_output_length: usize,
    /// Block when injection confidence >= this threshold.
    pub injection_block_threshold: f64,
    /// Quarantine when injection confidence >= this threshold.
    pub injection_quarantine_threshold: f64,
    /// Adversarial detection sensitivity (higher = stricter).
    pub adversarial_threshold: f64,
    /// Block output when exfiltration confidence >= this threshold.
    pub exfiltration_block_threshold: f64,
    /// Enable PII redaction in outputs.
    pub redact_pii_in_output: bool,
    /// Enable immune memory.
    pub enable_immune_memory: bool,
    /// Quarantine entries auto-released after this duration (ms).
    pub quarantine_auto_release_ms: i64,
    /// Blocked raw substrings (evaluated before any detection).
    pub blocked_patterns: Vec<String>,
}

impl Default for ShieldPolicy {
    fn default() -> Self {
        Self::silver()
    }
}

impl ShieldPolicy {
    pub fn from_level(level: ShieldLevel) -> Self {
        match level {
            ShieldLevel::Bronze => Self::bronze(),
            ShieldLevel::Silver => Self::silver(),
            ShieldLevel::Gold => Self::gold(),
            ShieldLevel::Platinum => Self::platinum(),
        }
    }

    pub fn bronze() -> Self {
        Self {
            level: ShieldLevel::Bronze,
            max_input_length: 10_000,
            max_output_length: 50_000,
            injection_block_threshold: 0.9,
            injection_quarantine_threshold: 0.7,
            adversarial_threshold: 0.85,
            exfiltration_block_threshold: 0.85,
            redact_pii_in_output: false,
            enable_immune_memory: true,
            quarantine_auto_release_ms: 3_600_000, // 1 hour
            blocked_patterns: Vec::new(),
        }
    }

    pub fn silver() -> Self {
        Self {
            level: ShieldLevel::Silver,
            max_input_length: 8_000,
            max_output_length: 40_000,
            injection_block_threshold: 0.8,
            injection_quarantine_threshold: 0.6,
            adversarial_threshold: 0.75,
            exfiltration_block_threshold: 0.75,
            redact_pii_in_output: true,
            enable_immune_memory: true,
            quarantine_auto_release_ms: 7_200_000, // 2 hours
            blocked_patterns: Vec::new(),
        }
    }

    pub fn gold() -> Self {
        Self {
            level: ShieldLevel::Gold,
            max_input_length: 5_000,
            max_output_length: 25_000,
            injection_block_threshold: 0.7,
            injection_quarantine_threshold: 0.5,
            adversarial_threshold: 0.65,
            exfiltration_block_threshold: 0.65,
            redact_pii_in_output: true,
            enable_immune_memory: true,
            quarantine_auto_release_ms: 14_400_000, // 4 hours
            blocked_patterns: Vec::new(),
        }
    }

    pub fn platinum() -> Self {
        Self {
            level: ShieldLevel::Platinum,
            max_input_length: 3_000,
            max_output_length: 15_000,
            injection_block_threshold: 0.6,
            injection_quarantine_threshold: 0.4,
            adversarial_threshold: 0.55,
            exfiltration_block_threshold: 0.55,
            redact_pii_in_output: true,
            enable_immune_memory: true,
            quarantine_auto_release_ms: 86_400_000, // 24 hours
            blocked_patterns: Vec::new(),
        }
    }

    pub fn with_blocked_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.blocked_patterns.push(pattern.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levels_ordered() {
        assert!(ShieldLevel::Bronze < ShieldLevel::Silver);
        assert!(ShieldLevel::Silver < ShieldLevel::Gold);
        assert!(ShieldLevel::Gold < ShieldLevel::Platinum);
    }

    #[test]
    fn test_presets_tighten_monotonically() {
        let b = ShieldPolicy::bronze();
        let s = ShieldPolicy::silver();
        let g = ShieldPolicy::gold();
        let p = ShieldPolicy::platinum();
        assert!(b.max_input_length > s.max_input_length);
        assert!(s.max_input_length > g.max_input_length);
        assert!(g.max_input_length > p.max_input_length);
        assert!(b.injection_block_threshold > p.injection_block_threshold);
        assert!(b.adversarial_threshold > p.adversarial_threshold);
    }

    #[test]
    fn test_from_level() {
        assert_eq!(
            ShieldPolicy::from_level(ShieldLevel::Gold).max_input_length,
            5_000
        );
    }

    #[test]
    fn test_default_is_silver() {
        assert_eq!(ShieldPolicy::default().level, ShieldLevel::Silver);
    }

    #[test]
    fn test_with_blocked_pattern() {
        let p = ShieldPolicy::silver().with_blocked_pattern("forbidden");
        assert_eq!(p.blocked_patterns.len(), 1);
    }

    #[test]
    fn test_level_display() {
        assert_eq!(ShieldLevel::Platinum.to_string(), "Platinum");
    }
}
