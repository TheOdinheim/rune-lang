// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Model behavior summarization.
//
// DecisionPatternTracker aggregates decision records for pattern
// analysis. BehaviorSummary and ConfidenceTrend describe aggregate
// behavior. FairnessIndicator and demographic_parity_difference
// support fairness analysis.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── DecisionRecord ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DecisionRecord {
    pub decision_id: String,
    pub outcome: String,
    pub confidence: f64,
    pub factors: Vec<String>,
    pub timestamp: i64,
    pub group: Option<String>,
}

impl DecisionRecord {
    pub fn new(
        decision_id: impl Into<String>,
        outcome: impl Into<String>,
        confidence: f64,
        timestamp: i64,
    ) -> Self {
        Self {
            decision_id: decision_id.into(),
            outcome: outcome.into(),
            confidence,
            factors: Vec::new(),
            timestamp,
            group: None,
        }
    }

    pub fn with_factors(mut self, factors: Vec<String>) -> Self {
        self.factors = factors;
        self
    }

    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }
}

// ── ConfidenceTrend ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidenceTrend {
    Improving,
    Stable,
    Declining,
    InsufficientData,
}

impl fmt::Display for ConfidenceTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Improving => f.write_str("improving"),
            Self::Stable => f.write_str("stable"),
            Self::Declining => f.write_str("declining"),
            Self::InsufficientData => f.write_str("insufficient-data"),
        }
    }
}

// ── DecisionPatternTracker ──────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DecisionPatternTracker {
    pub records: Vec<DecisionRecord>,
}

impl DecisionPatternTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, record: DecisionRecord) {
        self.records.push(record);
    }

    pub fn total_decisions(&self) -> usize {
        self.records.len()
    }

    pub fn outcome_distribution(&self) -> HashMap<String, usize> {
        let mut dist = HashMap::new();
        for r in &self.records {
            *dist.entry(r.outcome.clone()).or_insert(0) += 1;
        }
        dist
    }

    pub fn most_common_factors(&self, top_k: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in &self.records {
            for factor in &r.factors {
                *counts.entry(factor.clone()).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(top_k);
        sorted
    }

    pub fn average_confidence(&self) -> f64 {
        if self.records.is_empty() {
            return 0.0;
        }
        let total: f64 = self.records.iter().map(|r| r.confidence).sum();
        total / self.records.len() as f64
    }

    pub fn decisions_since(&self, timestamp: i64) -> Vec<&DecisionRecord> {
        self.records
            .iter()
            .filter(|r| r.timestamp >= timestamp)
            .collect()
    }

    pub fn generate_summary(&self) -> BehaviorSummary {
        let trend = self.compute_confidence_trend();
        let dist = self.outcome_distribution();
        let top_factors = self.most_common_factors(5);
        let avg_confidence = self.average_confidence();

        BehaviorSummary {
            total_decisions: self.total_decisions(),
            outcome_distribution: dist,
            top_factors,
            average_confidence: avg_confidence,
            confidence_trend: trend,
        }
    }

    fn compute_confidence_trend(&self) -> ConfidenceTrend {
        if self.records.len() < 4 {
            return ConfidenceTrend::InsufficientData;
        }
        let half = self.records.len() / 2;
        let first_half_avg: f64 =
            self.records[..half].iter().map(|r| r.confidence).sum::<f64>() / half as f64;
        let second_half_avg: f64 =
            self.records[half..].iter().map(|r| r.confidence).sum::<f64>()
                / (self.records.len() - half) as f64;
        let diff = second_half_avg - first_half_avg;
        if diff > 0.05 {
            ConfidenceTrend::Improving
        } else if diff < -0.05 {
            ConfidenceTrend::Declining
        } else {
            ConfidenceTrend::Stable
        }
    }
}

// ── BehaviorSummary ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorSummary {
    pub total_decisions: usize,
    pub outcome_distribution: HashMap<String, usize>,
    pub top_factors: Vec<(String, usize)>,
    pub average_confidence: f64,
    pub confidence_trend: ConfidenceTrend,
}

// ── GroupOutcome ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GroupOutcome {
    pub group_name: String,
    pub positive_count: usize,
    pub total_count: usize,
}

impl GroupOutcome {
    pub fn new(group_name: impl Into<String>, positive_count: usize, total_count: usize) -> Self {
        Self {
            group_name: group_name.into(),
            positive_count,
            total_count,
        }
    }

    pub fn positive_rate(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }
        self.positive_count as f64 / self.total_count as f64
    }
}

// ── FairnessIndicator ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FairnessIndicator {
    pub group_outcomes: Vec<GroupOutcome>,
    pub demographic_parity_diff: f64,
    pub within_tolerance: bool,
}

/// Compute the max absolute difference in positive rates across groups.
pub fn demographic_parity_difference(groups: &[GroupOutcome]) -> f64 {
    if groups.len() < 2 {
        return 0.0;
    }
    let rates: Vec<f64> = groups.iter().map(|g| g.positive_rate()).collect();
    let max = rates.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min = rates.iter().cloned().fold(f64::INFINITY, f64::min);
    max - min
}

/// Check if demographic parity difference is within the given tolerance.
pub fn is_within_tolerance(groups: &[GroupOutcome], tolerance: f64) -> bool {
    demographic_parity_difference(groups) <= tolerance
}

/// Compute a full fairness indicator from group outcomes and tolerance.
pub fn compute_fairness(groups: Vec<GroupOutcome>, tolerance: f64) -> FairnessIndicator {
    let dpd = demographic_parity_difference(&groups);
    FairnessIndicator {
        group_outcomes: groups,
        demographic_parity_diff: dpd,
        within_tolerance: dpd <= tolerance,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tracker() -> DecisionPatternTracker {
        let mut tracker = DecisionPatternTracker::new();
        tracker.record(
            DecisionRecord::new("d1", "approved", 0.9, 1000)
                .with_factors(vec!["income".into(), "credit".into()]),
        );
        tracker.record(
            DecisionRecord::new("d2", "denied", 0.7, 2000)
                .with_factors(vec!["income".into(), "debt".into()]),
        );
        tracker.record(
            DecisionRecord::new("d3", "approved", 0.85, 3000)
                .with_factors(vec!["credit".into()]),
        );
        tracker.record(
            DecisionRecord::new("d4", "approved", 0.95, 4000)
                .with_factors(vec!["income".into(), "credit".into()]),
        );
        tracker
    }

    #[test]
    fn test_total_decisions() {
        let tracker = sample_tracker();
        assert_eq!(tracker.total_decisions(), 4);
    }

    #[test]
    fn test_outcome_distribution() {
        let tracker = sample_tracker();
        let dist = tracker.outcome_distribution();
        assert_eq!(dist.get("approved"), Some(&3));
        assert_eq!(dist.get("denied"), Some(&1));
    }

    #[test]
    fn test_most_common_factors() {
        let tracker = sample_tracker();
        let top = tracker.most_common_factors(2);
        assert_eq!(top.len(), 2);
        // income appears 3 times, credit appears 3 times
        assert!(top[0].1 >= top[1].1);
    }

    #[test]
    fn test_average_confidence() {
        let tracker = sample_tracker();
        let avg = tracker.average_confidence();
        let expected = (0.9 + 0.7 + 0.85 + 0.95) / 4.0;
        assert!((avg - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_decisions_since() {
        let tracker = sample_tracker();
        assert_eq!(tracker.decisions_since(3000).len(), 2);
        assert_eq!(tracker.decisions_since(5000).len(), 0);
    }

    #[test]
    fn test_generate_summary() {
        let tracker = sample_tracker();
        let summary = tracker.generate_summary();
        assert_eq!(summary.total_decisions, 4);
        assert!(!summary.outcome_distribution.is_empty());
        assert!(!summary.top_factors.is_empty());
    }

    #[test]
    fn test_confidence_trend_improving() {
        let mut tracker = DecisionPatternTracker::new();
        // First half: low confidence
        tracker.record(DecisionRecord::new("d1", "ok", 0.5, 1000));
        tracker.record(DecisionRecord::new("d2", "ok", 0.5, 2000));
        // Second half: high confidence
        tracker.record(DecisionRecord::new("d3", "ok", 0.9, 3000));
        tracker.record(DecisionRecord::new("d4", "ok", 0.9, 4000));
        let summary = tracker.generate_summary();
        assert_eq!(summary.confidence_trend, ConfidenceTrend::Improving);
    }

    #[test]
    fn test_confidence_trend_declining() {
        let mut tracker = DecisionPatternTracker::new();
        tracker.record(DecisionRecord::new("d1", "ok", 0.9, 1000));
        tracker.record(DecisionRecord::new("d2", "ok", 0.9, 2000));
        tracker.record(DecisionRecord::new("d3", "ok", 0.5, 3000));
        tracker.record(DecisionRecord::new("d4", "ok", 0.5, 4000));
        let summary = tracker.generate_summary();
        assert_eq!(summary.confidence_trend, ConfidenceTrend::Declining);
    }

    #[test]
    fn test_confidence_trend_stable() {
        let mut tracker = DecisionPatternTracker::new();
        tracker.record(DecisionRecord::new("d1", "ok", 0.8, 1000));
        tracker.record(DecisionRecord::new("d2", "ok", 0.8, 2000));
        tracker.record(DecisionRecord::new("d3", "ok", 0.8, 3000));
        tracker.record(DecisionRecord::new("d4", "ok", 0.8, 4000));
        let summary = tracker.generate_summary();
        assert_eq!(summary.confidence_trend, ConfidenceTrend::Stable);
    }

    #[test]
    fn test_confidence_trend_insufficient() {
        let mut tracker = DecisionPatternTracker::new();
        tracker.record(DecisionRecord::new("d1", "ok", 0.8, 1000));
        let summary = tracker.generate_summary();
        assert_eq!(summary.confidence_trend, ConfidenceTrend::InsufficientData);
    }

    #[test]
    fn test_decision_record_with_group() {
        let record = DecisionRecord::new("d1", "approved", 0.9, 1000).with_group("group_a");
        assert_eq!(record.group, Some("group_a".into()));
    }

    #[test]
    fn test_group_outcome_positive_rate() {
        let g = GroupOutcome::new("a", 30, 100);
        assert!((g.positive_rate() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_group_outcome_empty() {
        let g = GroupOutcome::new("a", 0, 0);
        assert!((g.positive_rate()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_demographic_parity_difference() {
        let groups = vec![
            GroupOutcome::new("a", 80, 100), // 0.8
            GroupOutcome::new("b", 60, 100), // 0.6
        ];
        let dpd = demographic_parity_difference(&groups);
        assert!((dpd - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_demographic_parity_single_group() {
        let groups = vec![GroupOutcome::new("a", 80, 100)];
        assert!((demographic_parity_difference(&groups)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_is_within_tolerance_true() {
        let groups = vec![
            GroupOutcome::new("a", 80, 100),
            GroupOutcome::new("b", 75, 100),
        ];
        assert!(is_within_tolerance(&groups, 0.1));
    }

    #[test]
    fn test_is_within_tolerance_false() {
        let groups = vec![
            GroupOutcome::new("a", 80, 100),
            GroupOutcome::new("b", 50, 100),
        ];
        assert!(!is_within_tolerance(&groups, 0.1));
    }

    #[test]
    fn test_compute_fairness() {
        let groups = vec![
            GroupOutcome::new("a", 80, 100),
            GroupOutcome::new("b", 60, 100),
        ];
        let fi = compute_fairness(groups, 0.25);
        assert!((fi.demographic_parity_diff - 0.2).abs() < f64::EPSILON);
        assert!(fi.within_tolerance);
        assert_eq!(fi.group_outcomes.len(), 2);
    }

    #[test]
    fn test_confidence_trend_display() {
        assert_eq!(ConfidenceTrend::Improving.to_string(), "improving");
        assert_eq!(ConfidenceTrend::Stable.to_string(), "stable");
        assert_eq!(ConfidenceTrend::Declining.to_string(), "declining");
        assert_eq!(
            ConfidenceTrend::InsufficientData.to_string(),
            "insufficient-data"
        );
    }
}
