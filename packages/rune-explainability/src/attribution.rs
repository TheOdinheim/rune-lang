// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Feature attribution scoring.
//
// FeatureAttribution quantifies how much each input feature contributed
// to a decision. AttributionSet aggregates attributions with analysis.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── AttributionDirection ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionDirection {
    Positive,
    Negative,
    Neutral,
}

impl fmt::Display for AttributionDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Positive => f.write_str("positive"),
            Self::Negative => f.write_str("negative"),
            Self::Neutral => f.write_str("neutral"),
        }
    }
}

// ── FeatureAttribution ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FeatureAttribution {
    pub feature_name: String,
    pub importance_score: f64,
    pub direction: AttributionDirection,
    pub baseline_value: Option<f64>,
    pub actual_value: Option<f64>,
    pub contribution: f64,
}

impl FeatureAttribution {
    pub fn new(
        feature_name: impl Into<String>,
        importance_score: f64,
        direction: AttributionDirection,
        contribution: f64,
    ) -> Self {
        Self {
            feature_name: feature_name.into(),
            importance_score,
            direction,
            baseline_value: None,
            actual_value: None,
            contribution,
        }
    }

    pub fn with_values(mut self, baseline: f64, actual: f64) -> Self {
        self.baseline_value = Some(baseline);
        self.actual_value = Some(actual);
        self
    }
}

// ── AttributionMethod ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionMethod {
    Shapley,
    Gradient,
    Perturbation,
    RuleBased,
    Manual,
}

impl fmt::Display for AttributionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shapley => f.write_str("shapley"),
            Self::Gradient => f.write_str("gradient"),
            Self::Perturbation => f.write_str("perturbation"),
            Self::RuleBased => f.write_str("rule-based"),
            Self::Manual => f.write_str("manual"),
        }
    }
}

// ── AttributionSet ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttributionSet {
    pub attributions: Vec<FeatureAttribution>,
    pub decision_id: String,
    pub method: AttributionMethod,
}

impl AttributionSet {
    pub fn new(decision_id: impl Into<String>, method: AttributionMethod) -> Self {
        Self {
            attributions: Vec::new(),
            decision_id: decision_id.into(),
            method,
        }
    }

    pub fn add(&mut self, attribution: FeatureAttribution) {
        self.attributions.push(attribution);
    }

    pub fn top_k(&self, k: usize) -> Vec<&FeatureAttribution> {
        let mut sorted: Vec<&FeatureAttribution> = self.attributions.iter().collect();
        sorted.sort_by(|a, b| {
            b.importance_score
                .abs()
                .partial_cmp(&a.importance_score.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(k);
        sorted
    }

    pub fn positive_contributors(&self) -> Vec<&FeatureAttribution> {
        self.attributions
            .iter()
            .filter(|a| a.direction == AttributionDirection::Positive)
            .collect()
    }

    pub fn negative_contributors(&self) -> Vec<&FeatureAttribution> {
        self.attributions
            .iter()
            .filter(|a| a.direction == AttributionDirection::Negative)
            .collect()
    }

    pub fn total_attribution(&self) -> f64 {
        self.attributions.iter().map(|a| a.importance_score).sum()
    }

    pub fn is_well_distributed(&self) -> bool {
        self.attributions
            .iter()
            .all(|a| a.importance_score <= 0.5)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_set() -> AttributionSet {
        let mut set = AttributionSet::new("d1", AttributionMethod::Shapley);
        set.add(FeatureAttribution::new(
            "income",
            0.4,
            AttributionDirection::Positive,
            0.3,
        ));
        set.add(FeatureAttribution::new(
            "credit_score",
            0.35,
            AttributionDirection::Positive,
            0.25,
        ));
        set.add(FeatureAttribution::new(
            "debt_ratio",
            0.15,
            AttributionDirection::Negative,
            -0.1,
        ));
        set.add(FeatureAttribution::new(
            "employment",
            0.1,
            AttributionDirection::Neutral,
            0.0,
        ));
        set
    }

    #[test]
    fn test_attribution_direction_display() {
        assert_eq!(AttributionDirection::Positive.to_string(), "positive");
        assert_eq!(AttributionDirection::Negative.to_string(), "negative");
        assert_eq!(AttributionDirection::Neutral.to_string(), "neutral");
    }

    #[test]
    fn test_attribution_with_values() {
        let a = FeatureAttribution::new("f1", 0.5, AttributionDirection::Positive, 0.3)
            .with_values(100.0, 150.0);
        assert_eq!(a.baseline_value, Some(100.0));
        assert_eq!(a.actual_value, Some(150.0));
    }

    #[test]
    fn test_top_k_returns_highest() {
        let set = sample_set();
        let top = set.top_k(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].feature_name, "income");
        assert_eq!(top[1].feature_name, "credit_score");
    }

    #[test]
    fn test_positive_contributors() {
        let set = sample_set();
        let pos = set.positive_contributors();
        assert_eq!(pos.len(), 2);
    }

    #[test]
    fn test_negative_contributors() {
        let set = sample_set();
        let neg = set.negative_contributors();
        assert_eq!(neg.len(), 1);
        assert_eq!(neg[0].feature_name, "debt_ratio");
    }

    #[test]
    fn test_total_attribution() {
        let set = sample_set();
        assert!((set.total_attribution() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_is_well_distributed_true() {
        let set = sample_set();
        assert!(set.is_well_distributed());
    }

    #[test]
    fn test_is_well_distributed_false() {
        let mut set = AttributionSet::new("d1", AttributionMethod::Manual);
        set.add(FeatureAttribution::new(
            "dominant",
            0.8,
            AttributionDirection::Positive,
            0.8,
        ));
        set.add(FeatureAttribution::new(
            "minor",
            0.2,
            AttributionDirection::Positive,
            0.2,
        ));
        assert!(!set.is_well_distributed());
    }
}
