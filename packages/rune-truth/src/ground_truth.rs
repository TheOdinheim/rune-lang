// ═══════════════════════════════════════════════════════════════════════
// Ground Truth — comparison against known-correct reference data.
//
// GroundTruthStore holds reference entries and compares actual model
// outputs against expected outputs using exact, partial, and semantic
// (Jaccard word overlap) matching. Provides accuracy metrics overall
// and by category.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── MatchType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchType {
    ExactMatch,
    SemanticMatch,
    PartialMatch,
    Mismatch,
}

impl fmt::Display for MatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactMatch => f.write_str("exact-match"),
            Self::SemanticMatch => f.write_str("semantic-match"),
            Self::PartialMatch => f.write_str("partial-match"),
            Self::Mismatch => f.write_str("mismatch"),
        }
    }
}

// ── GroundTruthEntry ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GroundTruthEntry {
    pub id: String,
    pub input: String,
    pub expected_output: String,
    pub category: Option<String>,
    pub source: String,
    pub added_at: i64,
    pub metadata: HashMap<String, String>,
}

impl GroundTruthEntry {
    pub fn new(
        id: impl Into<String>,
        input: impl Into<String>,
        expected_output: impl Into<String>,
        source: impl Into<String>,
        added_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            input: input.into(),
            expected_output: expected_output.into(),
            category: None,
            source: source.into(),
            added_at,
            metadata: HashMap::new(),
        }
    }

    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }
}

// ── ComparisonResult ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub ground_truth_id: String,
    pub input: String,
    pub expected: String,
    pub actual: String,
    pub match_type: MatchType,
    pub similarity: f64,
    pub correct: bool,
    pub detail: String,
    pub compared_at: i64,
}

// ── GroundTruthStore ─────────────────────────────────────────────────

#[derive(Default)]
pub struct GroundTruthStore {
    entries: HashMap<String, GroundTruthEntry>,
    results: Vec<ComparisonResult>,
}

impl GroundTruthStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entry(&mut self, entry: GroundTruthEntry) {
        self.entries.insert(entry.id.clone(), entry);
    }

    pub fn get_entry(&self, id: &str) -> Option<&GroundTruthEntry> {
        self.entries.get(id)
    }

    pub fn compare(
        &mut self,
        ground_truth_id: &str,
        actual_output: &str,
        now: i64,
    ) -> Option<ComparisonResult> {
        let entry = self.entries.get(ground_truth_id)?;

        let expected_norm = normalize_whitespace(&entry.expected_output);
        let actual_norm = normalize_whitespace(actual_output);

        let (match_type, similarity) = if expected_norm == actual_norm {
            (MatchType::ExactMatch, 1.0)
        } else if actual_norm.contains(&expected_norm) {
            let sim = jaccard_similarity(&expected_norm, &actual_norm);
            (MatchType::PartialMatch, sim.max(0.7))
        } else {
            let sim = jaccard_similarity(&expected_norm, &actual_norm);
            if sim >= 0.7 {
                (MatchType::SemanticMatch, sim)
            } else {
                (MatchType::Mismatch, sim)
            }
        };

        let correct = match_type != MatchType::Mismatch;

        let result = ComparisonResult {
            ground_truth_id: ground_truth_id.into(),
            input: entry.input.clone(),
            expected: entry.expected_output.clone(),
            actual: actual_output.into(),
            match_type,
            similarity,
            correct,
            detail: format!("similarity: {similarity:.3}"),
            compared_at: now,
        };

        self.results.push(result.clone());
        Some(result)
    }

    pub fn compare_all(
        &mut self,
        outputs: &[(&str, &str)],
        now: i64,
    ) -> Vec<ComparisonResult> {
        outputs
            .iter()
            .filter_map(|&(gt_id, actual)| self.compare(gt_id, actual, now))
            .collect()
    }

    pub fn accuracy(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let correct = self.results.iter().filter(|r| r.correct).count();
        correct as f64 / self.results.len() as f64
    }

    pub fn accuracy_by_category(&self) -> HashMap<String, f64> {
        let mut category_counts: HashMap<String, (usize, usize)> = HashMap::new();
        for result in &self.results {
            if let Some(entry) = self.entries.get(&result.ground_truth_id) {
                let cat = entry.category.clone().unwrap_or_else(|| "uncategorized".into());
                let (correct, total) = category_counts.entry(cat).or_insert((0, 0));
                if result.correct {
                    *correct += 1;
                }
                *total += 1;
            }
        }
        category_counts
            .into_iter()
            .map(|(cat, (correct, total))| {
                (cat, if total > 0 { correct as f64 / total as f64 } else { 0.0 })
            })
            .collect()
    }

    pub fn incorrect_results(&self) -> Vec<&ComparisonResult> {
        self.results.iter().filter(|r| !r.correct).collect()
    }

    pub fn results_for(&self, ground_truth_id: &str) -> Vec<&ComparisonResult> {
        self.results
            .iter()
            .filter(|r| r.ground_truth_id == ground_truth_id)
            .collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let set_a: HashSet<String> = a.split_whitespace().map(|w| w.to_lowercase()).collect();
    let set_b: HashSet<String> = b.split_whitespace().map(|w| w.to_lowercase()).collect();
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
// Layer 2: Enhanced Ground Truth Verification
// ═══════════════════════════════════════════════════════════════════════

use crate::contradiction::ClaimValue;
use crate::consistency::Trend;

/// A typed ground truth entry with expiration.
#[derive(Debug, Clone)]
pub struct TypedGroundTruth {
    pub key: String,
    pub value: ClaimValue,
    pub source: String,
    pub established_at: i64,
    pub expires_at: Option<i64>,
    pub confidence: f64,
}

/// Store for typed ground truths.
#[derive(Default)]
pub struct TypedGroundTruthStore {
    truths: HashMap<String, TypedGroundTruth>,
}

/// Verification result against ground truth.
#[derive(Debug, Clone)]
pub struct GroundTruthVerification {
    pub key: String,
    pub matches: bool,
    pub ground_truth_value: Option<ClaimValue>,
    pub claimed_value: ClaimValue,
    pub ground_truth_expired: bool,
    pub deviation: Option<f64>,
}

impl TypedGroundTruthStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(
        &mut self,
        key: &str,
        value: ClaimValue,
        source: &str,
        now: i64,
    ) -> &TypedGroundTruth {
        self.truths.insert(
            key.to_string(),
            TypedGroundTruth {
                key: key.to_string(),
                value,
                source: source.to_string(),
                established_at: now,
                expires_at: None,
                confidence: 1.0,
            },
        );
        self.truths.get(key).unwrap()
    }

    pub fn set_with_expiry(
        &mut self,
        key: &str,
        value: ClaimValue,
        source: &str,
        now: i64,
        expires_at: i64,
    ) -> &TypedGroundTruth {
        self.truths.insert(
            key.to_string(),
            TypedGroundTruth {
                key: key.to_string(),
                value,
                source: source.to_string(),
                established_at: now,
                expires_at: Some(expires_at),
                confidence: 1.0,
            },
        );
        self.truths.get(key).unwrap()
    }

    pub fn get(&self, key: &str) -> Option<&TypedGroundTruth> {
        self.truths.get(key)
    }

    pub fn is_valid(&self, key: &str, now: i64) -> bool {
        match self.truths.get(key) {
            Some(gt) => match gt.expires_at {
                Some(exp) => now < exp,
                None => true,
            },
            None => false,
        }
    }

    pub fn expired_count(&self, now: i64) -> usize {
        self.truths.values()
            .filter(|gt| gt.expires_at.map(|exp| now >= exp).unwrap_or(false))
            .count()
    }

    pub fn verify_against_ground_truth(
        &self,
        key: &str,
        claimed_value: &ClaimValue,
        now: i64,
    ) -> GroundTruthVerification {
        let gt = self.truths.get(key);
        let expired = gt.as_ref()
            .and_then(|g| g.expires_at.map(|exp| now >= exp))
            .unwrap_or(false);

        let (matches, deviation) = match gt {
            Some(g) => match (&g.value, claimed_value) {
                (ClaimValue::Boolean(a), ClaimValue::Boolean(b)) => (*a == *b, None),
                (ClaimValue::Numeric(a), ClaimValue::Numeric(b)) => {
                    let dev = (a - b).abs();
                    let tol = a.abs().max(1e-6) * 1e-6;
                    (dev <= tol, Some(dev))
                }
                (ClaimValue::Text(a), ClaimValue::Text(b)) => (a == b, None),
                (ClaimValue::Category(a), ClaimValue::Category(b)) => (a == b, None),
                _ => (false, None),
            },
            None => (false, None),
        };

        GroundTruthVerification {
            key: key.to_string(),
            matches: matches && !expired,
            ground_truth_value: gt.map(|g| g.value.clone()),
            claimed_value: claimed_value.clone(),
            ground_truth_expired: expired,
            deviation,
        }
    }
}

/// Tracks accuracy over time.
#[derive(Default)]
pub struct AccuracyTracker {
    pub total_verifications: u64,
    pub correct: u64,
    pub incorrect: u64,
    pub by_subject: HashMap<String, (u64, u64)>,
    recent_results: Vec<bool>,
}

impl AccuracyTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_verification(&mut self, subject: &str, correct: bool) {
        self.total_verifications += 1;
        if correct {
            self.correct += 1;
        } else {
            self.incorrect += 1;
        }
        let entry = self.by_subject.entry(subject.to_string()).or_insert((0, 0));
        if correct {
            entry.0 += 1;
        }
        entry.1 += 1;
        self.recent_results.push(correct);
    }

    pub fn overall_accuracy(&self) -> f64 {
        if self.total_verifications == 0 {
            return 0.0;
        }
        self.correct as f64 / self.total_verifications as f64
    }

    pub fn accuracy_for_subject(&self, subject: &str) -> Option<f64> {
        self.by_subject.get(subject).map(|(correct, total)| {
            if *total == 0 { 0.0 } else { *correct as f64 / *total as f64 }
        })
    }

    pub fn worst_subjects(&self, n: usize) -> Vec<(String, f64)> {
        let mut subjects: Vec<(String, f64)> = self.by_subject.iter()
            .map(|(subj, (correct, total))| {
                let acc = if *total == 0 { 0.0 } else { *correct as f64 / *total as f64 };
                (subj.clone(), acc)
            })
            .collect();
        subjects.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        subjects.truncate(n);
        subjects
    }

    pub fn accuracy_trend(&self) -> Trend {
        if self.recent_results.len() < 10 {
            return Trend::Insufficient;
        }
        let half = self.recent_results.len() / 2;
        let first_half: f64 = self.recent_results[..half].iter()
            .map(|&b| if b { 1.0 } else { 0.0 }).sum::<f64>() / half as f64;
        let second_half: f64 = self.recent_results[half..].iter()
            .map(|&b| if b { 1.0 } else { 0.0 }).sum::<f64>() / (self.recent_results.len() - half) as f64;

        if second_half > first_half + 0.05 {
            Trend::Increasing
        } else if second_half < first_half - 0.05 {
            Trend::Decreasing
        } else {
            Trend::Stable
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, input: &str, expected: &str) -> GroundTruthEntry {
        GroundTruthEntry::new(id, input, expected, "test-suite", 1000)
    }

    #[test]
    fn test_add_and_get_entry() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "What is 2+2?", "4"));
        assert!(store.get_entry("gt1").is_some());
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn test_compare_exact_match() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "What is 2+2?", "4"));
        let result = store.compare("gt1", "4", 2000).unwrap();
        assert_eq!(result.match_type, MatchType::ExactMatch);
        assert!(result.correct);
        assert_eq!(result.similarity, 1.0);
    }

    #[test]
    fn test_compare_partial_match() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "Capital of France?", "Paris"));
        let result = store.compare("gt1", "The capital of France is Paris", 2000).unwrap();
        assert_eq!(result.match_type, MatchType::PartialMatch);
        assert!(result.correct);
    }

    #[test]
    fn test_compare_semantic_match() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry(
            "gt1",
            "Describe photosynthesis",
            "Plants convert sunlight water carbon dioxide into glucose oxygen",
        ));
        let result = store
            .compare(
                "gt1",
                "Plants convert sunlight water and carbon dioxide into oxygen and glucose",
                2000,
            )
            .unwrap();
        assert_eq!(result.match_type, MatchType::SemanticMatch);
        assert!(result.correct);
    }

    #[test]
    fn test_compare_mismatch() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "What is 2+2?", "4"));
        let result = store.compare("gt1", "The answer is elephants", 2000).unwrap();
        assert_eq!(result.match_type, MatchType::Mismatch);
        assert!(!result.correct);
    }

    #[test]
    fn test_compare_normalizes_whitespace() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "q", "hello  world"));
        let result = store.compare("gt1", "hello world", 2000).unwrap();
        assert_eq!(result.match_type, MatchType::ExactMatch);
    }

    #[test]
    fn test_accuracy() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "q1", "yes"));
        store.add_entry(entry("gt2", "q2", "no"));
        store.compare("gt1", "yes", 2000);
        store.compare("gt2", "completely wrong answer", 2000);
        assert!((store.accuracy() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_accuracy_by_category() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "q1", "yes").with_category("math"));
        store.add_entry(entry("gt2", "q2", "no").with_category("math"));
        store.add_entry(entry("gt3", "q3", "blue").with_category("science"));
        store.compare("gt1", "yes", 2000);
        store.compare("gt2", "wrong", 2000);
        store.compare("gt3", "blue", 2000);
        let by_cat = store.accuracy_by_category();
        assert!((by_cat["math"] - 0.5).abs() < 1e-9);
        assert!((by_cat["science"] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_incorrect_results() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "q1", "yes"));
        store.add_entry(entry("gt2", "q2", "no"));
        store.compare("gt1", "yes", 2000);
        store.compare("gt2", "wrong", 2000);
        assert_eq!(store.incorrect_results().len(), 1);
    }

    #[test]
    fn test_compare_all() {
        let mut store = GroundTruthStore::new();
        store.add_entry(entry("gt1", "q1", "yes"));
        store.add_entry(entry("gt2", "q2", "no"));
        let results = store.compare_all(&[("gt1", "yes"), ("gt2", "no")], 2000);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.correct));
    }

    #[test]
    fn test_match_type_display() {
        assert_eq!(MatchType::ExactMatch.to_string(), "exact-match");
        assert_eq!(MatchType::SemanticMatch.to_string(), "semantic-match");
        assert_eq!(MatchType::PartialMatch.to_string(), "partial-match");
        assert_eq!(MatchType::Mismatch.to_string(), "mismatch");
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_typed_ground_truth_set_and_get() {
        let mut store = TypedGroundTruthStore::new();
        store.set("key1", ClaimValue::Boolean(true), "test", 1000);
        assert!(store.get("key1").is_some());
        assert_eq!(store.get("key1").unwrap().value, ClaimValue::Boolean(true));
    }

    #[test]
    fn test_typed_ground_truth_is_valid_before_expiry() {
        let mut store = TypedGroundTruthStore::new();
        store.set_with_expiry("key1", ClaimValue::Boolean(true), "test", 1000, 5000);
        assert!(store.is_valid("key1", 3000));
    }

    #[test]
    fn test_typed_ground_truth_is_valid_after_expiry() {
        let mut store = TypedGroundTruthStore::new();
        store.set_with_expiry("key1", ClaimValue::Boolean(true), "test", 1000, 5000);
        assert!(!store.is_valid("key1", 6000));
    }

    #[test]
    fn test_verify_matches_equal_values() {
        let mut store = TypedGroundTruthStore::new();
        store.set("temp", ClaimValue::Numeric(72.0), "sensor", 1000);
        let v = store.verify_against_ground_truth("temp", &ClaimValue::Numeric(72.0), 2000);
        assert!(v.matches);
    }

    #[test]
    fn test_verify_fails_different_values() {
        let mut store = TypedGroundTruthStore::new();
        store.set("status", ClaimValue::Boolean(true), "monitor", 1000);
        let v = store.verify_against_ground_truth("status", &ClaimValue::Boolean(false), 2000);
        assert!(!v.matches);
    }

    #[test]
    fn test_verify_numeric_tolerance() {
        let mut store = TypedGroundTruthStore::new();
        store.set("val", ClaimValue::Numeric(100.0), "sensor", 1000);
        // Within relative tolerance of 1e-6
        let v = store.verify_against_ground_truth("val", &ClaimValue::Numeric(100.00000001), 2000);
        assert!(v.matches);
    }

    #[test]
    fn test_accuracy_tracker_overall() {
        let mut tracker = AccuracyTracker::new();
        tracker.record_verification("a", true);
        tracker.record_verification("a", true);
        tracker.record_verification("a", false);
        assert!((tracker.overall_accuracy() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_accuracy_tracker_by_subject() {
        let mut tracker = AccuracyTracker::new();
        tracker.record_verification("good", true);
        tracker.record_verification("good", true);
        tracker.record_verification("bad", false);
        tracker.record_verification("bad", false);
        assert!((tracker.accuracy_for_subject("good").unwrap() - 1.0).abs() < 1e-9);
        assert!((tracker.accuracy_for_subject("bad").unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_accuracy_tracker_worst_subjects() {
        let mut tracker = AccuracyTracker::new();
        tracker.record_verification("good", true);
        tracker.record_verification("good", true);
        tracker.record_verification("bad", false);
        tracker.record_verification("bad", false);
        tracker.record_verification("medium", true);
        tracker.record_verification("medium", false);
        let worst = tracker.worst_subjects(2);
        assert_eq!(worst[0].0, "bad");
        assert!((worst[0].1 - 0.0).abs() < 1e-9);
    }
}
