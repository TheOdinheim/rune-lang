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
// Layer 2: Enhanced Consistency Checking
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};
use crate::confidence::RunningStats;

/// Type of statistical consistency test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyTestType {
    MeanDrift,
    VarianceDrift,
    DistributionShift,
    OutlierDetection,
}

/// Result of a statistical consistency test.
#[derive(Debug, Clone)]
pub struct ConsistencyTest {
    pub test_name: String,
    pub test_type: ConsistencyTestType,
    pub passed: bool,
    pub p_value: f64,
    pub detail: String,
}

/// Check if current mean is consistent with baseline.
pub fn check_mean_consistency(
    baseline: &RunningStats,
    current: &RunningStats,
    threshold_sigma: f64,
) -> ConsistencyTest {
    if baseline.count() < 2 || current.count() < 2 {
        return ConsistencyTest {
            test_name: "mean-consistency".into(),
            test_type: ConsistencyTestType::MeanDrift,
            passed: true,
            p_value: 1.0,
            detail: "insufficient data".into(),
        };
    }
    let se = (baseline.variance() / baseline.count() as f64
        + current.variance() / current.count() as f64)
        .sqrt();
    let z = if se > 0.0 {
        (current.mean() - baseline.mean()).abs() / se
    } else {
        0.0
    };
    let passed = z < threshold_sigma;
    ConsistencyTest {
        test_name: "mean-consistency".into(),
        test_type: ConsistencyTestType::MeanDrift,
        passed,
        p_value: z,
        detail: format!("z={z:.4}, threshold={threshold_sigma}"),
    }
}

/// A time window for tracking consistency.
#[derive(Debug, Clone)]
pub struct ConsistencyWindow {
    pub start_ms: i64,
    pub end_ms: i64,
    pub stats: RunningStats,
    pub sample_count: u64,
}

/// Drift event detected between adjacent windows.
#[derive(Debug, Clone)]
pub struct DriftEvent {
    pub window_index: usize,
    pub drift_type: ConsistencyTestType,
    pub magnitude: f64,
    pub timestamp_ms: i64,
}

/// Trend direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trend {
    Increasing,
    Decreasing,
    Stable,
    Oscillating,
    Insufficient,
}

/// Tracks consistency over time using sliding windows.
pub struct TemporalConsistencyTracker {
    pub windows: Vec<ConsistencyWindow>,
    pub window_size_ms: i64,
    pub max_windows: usize,
}

impl TemporalConsistencyTracker {
    pub fn new(window_size_ms: i64, max_windows: usize) -> Self {
        Self {
            windows: Vec::new(),
            window_size_ms,
            max_windows,
        }
    }

    pub fn record(&mut self, value: f64, timestamp_ms: i64) {
        // Find or create the appropriate window
        let window_start = (timestamp_ms / self.window_size_ms) * self.window_size_ms;
        let window_end = window_start + self.window_size_ms;

        if let Some(w) = self.windows.iter_mut().find(|w| w.start_ms == window_start) {
            w.stats.update(value);
            w.sample_count += 1;
        } else {
            let mut stats = RunningStats::new();
            stats.update(value);
            self.windows.push(ConsistencyWindow {
                start_ms: window_start,
                end_ms: window_end,
                stats,
                sample_count: 1,
            });
            self.windows.sort_by_key(|w| w.start_ms);
            if self.windows.len() > self.max_windows {
                self.windows.remove(0);
            }
        }
    }

    pub fn detect_drift(&self, threshold_sigma: f64) -> Vec<DriftEvent> {
        let mut events = Vec::new();
        for i in 1..self.windows.len() {
            let test = check_mean_consistency(
                &self.windows[i - 1].stats,
                &self.windows[i].stats,
                threshold_sigma,
            );
            if !test.passed {
                events.push(DriftEvent {
                    window_index: i,
                    drift_type: ConsistencyTestType::MeanDrift,
                    magnitude: test.p_value,
                    timestamp_ms: self.windows[i].start_ms,
                });
            }
        }
        events
    }

    pub fn trend(&self) -> Trend {
        if self.windows.len() < 3 {
            return Trend::Insufficient;
        }
        let means: Vec<f64> = self.windows.iter().map(|w| w.stats.mean()).collect();
        let mut increases = 0;
        let mut decreases = 0;
        for i in 1..means.len() {
            if means[i] > means[i - 1] + 1e-9 {
                increases += 1;
            } else if means[i] < means[i - 1] - 1e-9 {
                decreases += 1;
            }
        }
        let n = means.len() - 1;
        if increases > n * 2 / 3 {
            Trend::Increasing
        } else if decreases > n * 2 / 3 {
            Trend::Decreasing
        } else if increases > 0 && decreases > 0 && (increases + decreases) > n * 2 / 3 {
            Trend::Oscillating
        } else {
            Trend::Stable
        }
    }
}

/// Fingerprint of a model output.
#[derive(Debug, Clone)]
pub struct OutputFingerprint {
    pub hash: String,
    pub output_type: String,
    pub dimensions: Vec<usize>,
    pub created_at: i64,
}

/// Create a fingerprint for an output string.
pub fn fingerprint_output(output: &str, output_type: &str, now: i64) -> OutputFingerprint {
    let mut hasher = Sha3_256::new();
    hasher.update(output.as_bytes());
    OutputFingerprint {
        hash: hex::encode(hasher.finalize()),
        output_type: output_type.to_string(),
        dimensions: Vec::new(),
        created_at: now,
    }
}

/// Check if two fingerprints match exactly.
pub fn outputs_match(a: &OutputFingerprint, b: &OutputFingerprint) -> bool {
    a.hash == b.hash
}

/// Cosine similarity between two numeric vectors.
pub fn similarity_score(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_check_mean_consistency_passes() {
        let mut baseline = RunningStats::new();
        for v in [10.0, 11.0, 9.0, 10.5, 10.0] {
            baseline.update(v);
        }
        let mut current = RunningStats::new();
        for v in [10.1, 10.3, 9.8, 10.2, 10.0] {
            current.update(v);
        }
        let test = check_mean_consistency(&baseline, &current, 2.0);
        assert!(test.passed);
    }

    #[test]
    fn test_check_mean_consistency_fails() {
        let mut baseline = RunningStats::new();
        for v in [10.0, 10.1, 9.9, 10.0, 10.0] {
            baseline.update(v);
        }
        let mut current = RunningStats::new();
        for v in [50.0, 50.1, 49.9, 50.0, 50.0] {
            current.update(v);
        }
        let test = check_mean_consistency(&baseline, &current, 2.0);
        assert!(!test.passed);
    }

    #[test]
    fn test_temporal_tracker_records() {
        let mut tracker = TemporalConsistencyTracker::new(1000, 10);
        tracker.record(5.0, 100);
        tracker.record(6.0, 200);
        tracker.record(7.0, 1100);
        assert_eq!(tracker.windows.len(), 2);
        assert_eq!(tracker.windows[0].sample_count, 2);
        assert_eq!(tracker.windows[1].sample_count, 1);
    }

    #[test]
    fn test_temporal_tracker_detect_drift() {
        let mut tracker = TemporalConsistencyTracker::new(1000, 10);
        // Window 0: stable around 10
        for i in 0..10 {
            tracker.record(10.0 + (i as f64) * 0.01, i * 50);
        }
        // Window 1: jumped to 50
        for i in 0..10 {
            tracker.record(50.0 + (i as f64) * 0.01, 1000 + i * 50);
        }
        let drifts = tracker.detect_drift(2.0);
        assert!(!drifts.is_empty());
    }

    #[test]
    fn test_temporal_tracker_trend_stable() {
        let mut tracker = TemporalConsistencyTracker::new(100, 10);
        for w in 0..5 {
            for _ in 0..5 {
                tracker.record(10.0, w * 100 + 10);
            }
        }
        assert_eq!(tracker.trend(), Trend::Stable);
    }

    #[test]
    fn test_output_fingerprint_deterministic() {
        let a = fingerprint_output("hello world", "text", 1000);
        let b = fingerprint_output("hello world", "text", 2000);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn test_output_fingerprint_different() {
        let a = fingerprint_output("hello", "text", 1000);
        let b = fingerprint_output("world", "text", 1000);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn test_similarity_score_identical() {
        let v = vec![1.0, 2.0, 3.0];
        assert!((similarity_score(&v, &v) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_similarity_score_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(similarity_score(&a, &b).abs() < 1e-9);
    }
}
