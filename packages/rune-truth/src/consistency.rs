// ═══════════════════════════════════════════════════════════════════════
// Consistency — output consistency checking across runs.
//
// ConsistencyChecker tracks model outputs grouped by input hash and
// measures how consistently a model produces the same output for the
// same input using dominant-output ratio and Jaccard word similarity.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ── OutputRecord ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OutputRecord {
    pub output_hash: String,
    pub output_summary: String,
    pub produced_at: i64,
    pub model_version: Option<String>,
    pub metadata: HashMap<String, String>,
}

// ── ConsistencyCheck ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConsistencyCheck {
    pub id: String,
    pub model_id: String,
    pub input_hash: String,
    pub outputs: Vec<OutputRecord>,
    pub consistency_score: f64,
    pub checked_at: i64,
}

// ── ConsistencyResult ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyResult {
    pub consistent: bool,
    pub score: f64,
    pub unique_outputs: usize,
    pub total_outputs: usize,
    pub dominant_output_ratio: f64,
    pub detail: String,
}

impl ConsistencyResult {
    pub fn is_consistent(&self, threshold: f64) -> bool {
        self.score >= threshold
    }
}

// ── ConsistencyChecker ───────────────────────────────────────────────

#[derive(Default)]
pub struct ConsistencyChecker {
    records: HashMap<String, Vec<OutputRecord>>,
    consistency_threshold: f64,
}

impl ConsistencyChecker {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            consistency_threshold: 0.7,
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            records: HashMap::new(),
            consistency_threshold: threshold,
        }
    }

    pub fn record_output(&mut self, input_hash: &str, record: OutputRecord) {
        self.records
            .entry(input_hash.to_string())
            .or_default()
            .push(record);
    }

    pub fn check(&self, input_hash: &str) -> ConsistencyResult {
        let outputs = match self.records.get(input_hash) {
            Some(o) if !o.is_empty() => o,
            _ => {
                return ConsistencyResult {
                    consistent: true,
                    score: 1.0,
                    unique_outputs: 0,
                    total_outputs: 0,
                    dominant_output_ratio: 1.0,
                    detail: "no outputs recorded".into(),
                };
            }
        };

        let total = outputs.len();
        if total == 1 {
            return ConsistencyResult {
                consistent: true,
                score: 1.0,
                unique_outputs: 1,
                total_outputs: 1,
                dominant_output_ratio: 1.0,
                detail: "single output, no inconsistency basis".into(),
            };
        }

        // Count occurrences of each output hash.
        let mut hash_counts: HashMap<&str, usize> = HashMap::new();
        for o in outputs {
            *hash_counts.entry(&o.output_hash).or_insert(0) += 1;
        }

        let unique = hash_counts.len();
        let max_count = hash_counts.values().copied().max().unwrap_or(0);
        let dominant_ratio = max_count as f64 / total as f64;

        let score = dominant_ratio;
        let consistent = score >= self.consistency_threshold;

        ConsistencyResult {
            consistent,
            score,
            unique_outputs: unique,
            total_outputs: total,
            dominant_output_ratio: dominant_ratio,
            detail: format!(
                "{unique} unique outputs from {total} total, dominant ratio {dominant_ratio:.2}"
            ),
        }
    }

    pub fn check_pair(&self, output_a: &str, output_b: &str) -> f64 {
        if output_a == output_b {
            return 1.0;
        }
        jaccard_word_similarity(output_a, output_b)
    }

    pub fn inconsistent_inputs(&self) -> Vec<(&str, ConsistencyResult)> {
        self.records
            .keys()
            .filter_map(|k| {
                let result = self.check(k);
                if !result.consistent {
                    Some((k.as_str(), result))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn model_consistency(&self) -> f64 {
        if self.records.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.records.keys().map(|k| self.check(k).score).sum();
        sum / self.records.len() as f64
    }

    pub fn input_count(&self) -> usize {
        self.records.len()
    }

    pub fn total_outputs(&self) -> usize {
        self.records.values().map(|v| v.len()).sum()
    }
}

fn tokenize(text: &str) -> HashSet<String> {
    text.split_whitespace()
        .map(|w| w.to_lowercase())
        .collect()
}

fn jaccard_word_similarity(a: &str, b: &str) -> f64 {
    let set_a = tokenize(a);
    let set_b = tokenize(b);
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return 1.0;
    }
    intersection as f64 / union as f64
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn record(hash: &str, summary: &str) -> OutputRecord {
        OutputRecord {
            output_hash: hash.into(),
            output_summary: summary.into(),
            produced_at: 1000,
            model_version: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_record_output_adds_to_group() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("input1", record("h1", "out1"));
        checker.record_output("input1", record("h2", "out2"));
        checker.record_output("input2", record("h3", "out3"));
        assert_eq!(checker.input_count(), 2);
        assert_eq!(checker.total_outputs(), 3);
    }

    #[test]
    fn test_check_all_identical() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("i1", record("same", "output"));
        checker.record_output("i1", record("same", "output"));
        checker.record_output("i1", record("same", "output"));
        let result = checker.check("i1");
        assert_eq!(result.score, 1.0);
        assert!(result.consistent);
        assert_eq!(result.unique_outputs, 1);
    }

    #[test]
    fn test_check_all_different() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("i1", record("a", "out-a"));
        checker.record_output("i1", record("b", "out-b"));
        checker.record_output("i1", record("c", "out-c"));
        checker.record_output("i1", record("d", "out-d"));
        let result = checker.check("i1");
        assert_eq!(result.score, 0.25); // 1/4
        assert!(!result.consistent);
    }

    #[test]
    fn test_check_majority_same() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("i1", record("a", "out-a"));
        checker.record_output("i1", record("a", "out-a"));
        checker.record_output("i1", record("a", "out-a"));
        checker.record_output("i1", record("b", "out-b"));
        let result = checker.check("i1");
        assert_eq!(result.score, 0.75); // 3/4
        assert!(result.consistent);
    }

    #[test]
    fn test_check_single_output() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("i1", record("a", "out-a"));
        let result = checker.check("i1");
        assert_eq!(result.score, 1.0);
        assert!(result.consistent);
    }

    #[test]
    fn test_check_pair_exact_match() {
        let checker = ConsistencyChecker::new();
        assert_eq!(checker.check_pair("hello world", "hello world"), 1.0);
    }

    #[test]
    fn test_check_pair_different() {
        let checker = ConsistencyChecker::new();
        let sim = checker.check_pair("the cat sat", "a dog ran fast");
        assert!(sim < 0.2);
    }

    #[test]
    fn test_check_pair_partial_overlap() {
        let checker = ConsistencyChecker::new();
        let sim = checker.check_pair("the big red cat", "the big blue cat");
        // shared: the, big, cat (3), union: the, big, red, blue, cat (5)
        assert!((sim - 0.6).abs() < 1e-9);
    }

    #[test]
    fn test_inconsistent_inputs() {
        let mut checker = ConsistencyChecker::with_threshold(0.7);
        checker.record_output("good", record("a", "a"));
        checker.record_output("good", record("a", "a"));
        checker.record_output("bad", record("a", "a"));
        checker.record_output("bad", record("b", "b"));
        checker.record_output("bad", record("c", "c"));
        checker.record_output("bad", record("d", "d"));
        let incon = checker.inconsistent_inputs();
        assert_eq!(incon.len(), 1);
        assert_eq!(incon[0].0, "bad");
    }

    #[test]
    fn test_model_consistency() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("i1", record("a", "a"));
        checker.record_output("i1", record("a", "a"));
        checker.record_output("i2", record("x", "x"));
        checker.record_output("i2", record("y", "y"));
        // i1 score = 1.0, i2 score = 0.5, avg = 0.75
        assert!((checker.model_consistency() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_input_count_and_total_outputs() {
        let mut checker = ConsistencyChecker::new();
        checker.record_output("i1", record("a", "a"));
        checker.record_output("i1", record("b", "b"));
        checker.record_output("i2", record("c", "c"));
        assert_eq!(checker.input_count(), 2);
        assert_eq!(checker.total_outputs(), 3);
    }
}
