// ═══════════════════════════════════════════════════════════════════════
// Immune Memory
//
// Learns from past confirmed attacks and recorded false positives.
// Boosts confidence on known attack signatures and suppresses known
// false-positive patterns.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_security::{SecuritySeverity, ThreatCategory};

// ── AttackSignature ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttackSignature {
    pub signature: String,
    pub category: ThreatCategory,
    pub severity: SecuritySeverity,
    /// Number of times this signature has been confirmed.
    pub confirmation_count: usize,
    pub first_seen: i64,
    pub last_seen: i64,
}

impl AttackSignature {
    pub fn confidence_boost(&self) -> f64 {
        // Log-based boost, capped at 0.3.
        let x = (self.confirmation_count as f64).ln_1p();
        (x * 0.1).min(0.3)
    }
}

// ── FalsePositivePattern ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FalsePositivePattern {
    pub pattern: String,
    pub seen_count: usize,
    pub last_seen: i64,
}

// ── ImmuneMemory ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ImmuneMemory {
    attack_signatures: HashMap<String, AttackSignature>,
    false_positives: HashMap<String, FalsePositivePattern>,
    /// Threshold: if a signature has been seen >= this many times as a
    /// false positive, suppress its detection.
    pub suppress_threshold: usize,
}

impl ImmuneMemory {
    pub fn new() -> Self {
        Self {
            attack_signatures: HashMap::new(),
            false_positives: HashMap::new(),
            suppress_threshold: 3,
        }
    }

    pub fn record_attack(
        &mut self,
        signature: impl Into<String>,
        category: ThreatCategory,
        severity: SecuritySeverity,
        timestamp: i64,
    ) {
        let sig = signature.into();
        self.attack_signatures
            .entry(sig.clone())
            .and_modify(|e| {
                e.last_seen = timestamp;
            })
            .or_insert(AttackSignature {
                signature: sig,
                category,
                severity,
                confirmation_count: 0,
                first_seen: timestamp,
                last_seen: timestamp,
            });
    }

    pub fn confirm_attack(&mut self, signature: &str, timestamp: i64) {
        if let Some(e) = self.attack_signatures.get_mut(signature) {
            e.confirmation_count += 1;
            e.last_seen = timestamp;
        }
    }

    pub fn record_false_positive(&mut self, signature: impl Into<String>, timestamp: i64) {
        let sig = signature.into();
        self.false_positives
            .entry(sig.clone())
            .and_modify(|e| {
                e.seen_count += 1;
                e.last_seen = timestamp;
            })
            .or_insert(FalsePositivePattern {
                pattern: sig,
                seen_count: 1,
                last_seen: timestamp,
            });
    }

    pub fn should_suppress(&self, signature: &str) -> bool {
        self.false_positives
            .get(signature)
            .is_some_and(|fp| fp.seen_count >= self.suppress_threshold)
    }

    pub fn boost_confidence(&self, signature: &str, base: f64) -> f64 {
        if let Some(sig) = self.attack_signatures.get(signature) {
            (base + sig.confidence_boost()).min(1.0)
        } else {
            base
        }
    }

    pub fn known_attack(&self, signature: &str) -> Option<&AttackSignature> {
        self.attack_signatures.get(signature)
    }

    pub fn attack_count(&self) -> usize {
        self.attack_signatures.len()
    }

    pub fn false_positive_count(&self) -> usize {
        self.false_positives.len()
    }

    // ── Layer 2: fingerprint recording and statistics ────────────────

    /// Record a content fingerprint hash for an attack.
    pub fn record_fingerprint(
        &mut self,
        fingerprint_hash: impl Into<String>,
        category: ThreatCategory,
        severity: SecuritySeverity,
        timestamp: i64,
    ) {
        let hash = fingerprint_hash.into();
        let sig = format!("fp:{hash}");
        self.record_attack(sig, category, severity, timestamp);
    }

    /// Count attacks recorded within a time window.
    pub fn attack_frequency(&self, window_ms: i64, now: i64) -> usize {
        let cutoff = now - window_ms;
        self.attack_signatures
            .values()
            .filter(|a| a.last_seen >= cutoff)
            .count()
    }

    /// Return the top N attack categories by frequency.
    pub fn top_attack_categories(&self, n: usize) -> Vec<(ThreatCategory, usize)> {
        let mut counts: HashMap<ThreatCategory, usize> = HashMap::new();
        for sig in self.attack_signatures.values() {
            *counts.entry(sig.category.clone()).or_insert(0) += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Count unique fingerprint-based attack signatures.
    pub fn unique_attack_fingerprints(&self) -> usize {
        self.attack_signatures
            .keys()
            .filter(|k| k.starts_with("fp:"))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_recall_attack() {
        let mut m = ImmuneMemory::new();
        m.record_attack(
            "ignore previous",
            ThreatCategory::PromptInjection,
            SecuritySeverity::High,
            1000,
        );
        assert!(m.known_attack("ignore previous").is_some());
        assert_eq!(m.attack_count(), 1);
    }

    #[test]
    fn test_confirm_increases_count_and_boosts() {
        let mut m = ImmuneMemory::new();
        m.record_attack(
            "sig",
            ThreatCategory::PromptInjection,
            SecuritySeverity::High,
            1000,
        );
        m.confirm_attack("sig", 1500);
        m.confirm_attack("sig", 1600);
        m.confirm_attack("sig", 1700);
        let boosted = m.boost_confidence("sig", 0.5);
        assert!(boosted > 0.5);
    }

    #[test]
    fn test_record_false_positive() {
        let mut m = ImmuneMemory::new();
        m.record_false_positive("benign", 1000);
        assert_eq!(m.false_positive_count(), 1);
    }

    #[test]
    fn test_should_suppress_after_threshold() {
        let mut m = ImmuneMemory::new();
        m.record_false_positive("benign", 1000);
        m.record_false_positive("benign", 1100);
        assert!(!m.should_suppress("benign"));
        m.record_false_positive("benign", 1200);
        assert!(m.should_suppress("benign"));
    }

    #[test]
    fn test_boost_unknown_signature_is_noop() {
        let m = ImmuneMemory::new();
        assert_eq!(m.boost_confidence("unknown", 0.5), 0.5);
    }

    #[test]
    fn test_boost_capped_at_one() {
        let mut m = ImmuneMemory::new();
        m.record_attack(
            "sig",
            ThreatCategory::PromptInjection,
            SecuritySeverity::High,
            1000,
        );
        for i in 0..100 {
            m.confirm_attack("sig", 1000 + i);
        }
        assert!(m.boost_confidence("sig", 0.95) <= 1.0);
    }

    #[test]
    fn test_signature_confidence_boost_monotone() {
        let mut s = AttackSignature {
            signature: "x".into(),
            category: ThreatCategory::PromptInjection,
            severity: SecuritySeverity::High,
            confirmation_count: 1,
            first_seen: 0,
            last_seen: 0,
        };
        let a = s.confidence_boost();
        s.confirmation_count = 10;
        let b = s.confidence_boost();
        assert!(b >= a);
    }

    // ── Layer 2 tests ───────────────────────────────────────────────

    #[test]
    fn test_record_fingerprint() {
        let mut m = ImmuneMemory::new();
        m.record_fingerprint("abc123", ThreatCategory::PromptInjection, SecuritySeverity::High, 1000);
        assert_eq!(m.unique_attack_fingerprints(), 1);
        assert!(m.known_attack("fp:abc123").is_some());
    }

    #[test]
    fn test_attack_frequency_window() {
        let mut m = ImmuneMemory::new();
        m.record_attack("a", ThreatCategory::PromptInjection, SecuritySeverity::High, 100);
        m.record_attack("b", ThreatCategory::ModelExfiltration, SecuritySeverity::Medium, 500);
        m.record_attack("c", ThreatCategory::PromptInjection, SecuritySeverity::High, 900);
        assert_eq!(m.attack_frequency(500, 1000), 2); // b and c within window
        assert_eq!(m.attack_frequency(1000, 1000), 3); // all within window
    }

    #[test]
    fn test_top_attack_categories() {
        let mut m = ImmuneMemory::new();
        m.record_attack("a", ThreatCategory::PromptInjection, SecuritySeverity::High, 100);
        m.record_attack("b", ThreatCategory::PromptInjection, SecuritySeverity::High, 200);
        m.record_attack("c", ThreatCategory::ModelExfiltration, SecuritySeverity::Medium, 300);
        let top = m.top_attack_categories(5);
        assert!(!top.is_empty());
        assert_eq!(top[0].0, ThreatCategory::PromptInjection);
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_unique_attack_fingerprints_only_counts_fp_prefix() {
        let mut m = ImmuneMemory::new();
        m.record_attack("regular-sig", ThreatCategory::PromptInjection, SecuritySeverity::High, 100);
        m.record_fingerprint("hash1", ThreatCategory::PromptInjection, SecuritySeverity::High, 200);
        m.record_fingerprint("hash2", ThreatCategory::ModelExfiltration, SecuritySeverity::Medium, 300);
        assert_eq!(m.unique_attack_fingerprints(), 2);
        assert_eq!(m.attack_count(), 3);
    }
}
