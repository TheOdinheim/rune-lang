// ═══════════════════════════════════════════════════════════════════════
// Confidence — scoring and calibration for model output confidence.
//
// ConfidenceCalculator combines weighted factors (model calibration,
// output entropy, consistency, source quality, etc.) into a single
// ConfidenceScore with a derived ConfidenceLevel.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── ConfidenceLevel ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    VeryLow = 0,
    Low = 1,
    Moderate = 2,
    High = 3,
    VeryHigh = 4,
}

impl ConfidenceLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.2 => Self::VeryLow,
            s if s < 0.4 => Self::Low,
            s if s < 0.6 => Self::Moderate,
            s if s < 0.8 => Self::High,
            _ => Self::VeryHigh,
        }
    }

    pub fn min_score(&self) -> f64 {
        match self {
            Self::VeryLow => 0.0,
            Self::Low => 0.2,
            Self::Moderate => 0.4,
            Self::High => 0.6,
            Self::VeryHigh => 0.8,
        }
    }
}

impl fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VeryLow => f.write_str("very-low"),
            Self::Low => f.write_str("low"),
            Self::Moderate => f.write_str("moderate"),
            Self::High => f.write_str("high"),
            Self::VeryHigh => f.write_str("very-high"),
        }
    }
}

// ── ConfidenceFactorType ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfidenceFactorType {
    ModelCalibration,
    OutputEntropy,
    ConsistencyScore,
    SourceQuality,
    ProvenanceCompleteness,
    GroundTruthAlignment,
    ExpertAgreement,
    TemporalStability,
    Custom(String),
}

impl fmt::Display for ConfidenceFactorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelCalibration => f.write_str("model-calibration"),
            Self::OutputEntropy => f.write_str("output-entropy"),
            Self::ConsistencyScore => f.write_str("consistency-score"),
            Self::SourceQuality => f.write_str("source-quality"),
            Self::ProvenanceCompleteness => f.write_str("provenance-completeness"),
            Self::GroundTruthAlignment => f.write_str("ground-truth-alignment"),
            Self::ExpertAgreement => f.write_str("expert-agreement"),
            Self::TemporalStability => f.write_str("temporal-stability"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── ConfidenceFactor ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConfidenceFactor {
    pub factor_type: ConfidenceFactorType,
    pub value: f64,
    pub weight: f64,
    pub detail: String,
}

// ── ConfidenceScore ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConfidenceScore {
    pub value: f64,
    pub level: ConfidenceLevel,
    pub factors: Vec<ConfidenceFactor>,
    pub computed_at: i64,
    pub methodology: String,
}

impl ConfidenceScore {
    pub fn new(value: f64) -> Self {
        let clamped = value.clamp(0.0, 1.0);
        Self {
            value: clamped,
            level: ConfidenceLevel::from_score(clamped),
            factors: Vec::new(),
            computed_at: 0,
            methodology: String::new(),
        }
    }

    pub fn is_reliable(&self) -> bool {
        self.level >= ConfidenceLevel::Moderate
    }

    pub fn is_low(&self) -> bool {
        self.level <= ConfidenceLevel::Low
    }
}

// ── ConfidenceCalculator ─────────────────────────────────────────────

pub struct ConfidenceCalculator {
    pub weights: HashMap<ConfidenceFactorType, f64>,
    pub min_factors: usize,
}

impl ConfidenceCalculator {
    pub fn new() -> Self {
        Self {
            weights: Self::default_weights(),
            min_factors: 1,
        }
    }

    pub fn with_weights(weights: HashMap<ConfidenceFactorType, f64>) -> Self {
        Self {
            weights,
            min_factors: 1,
        }
    }

    pub fn default_weights() -> HashMap<ConfidenceFactorType, f64> {
        let mut w = HashMap::new();
        w.insert(ConfidenceFactorType::ModelCalibration, 1.0);
        w.insert(ConfidenceFactorType::OutputEntropy, 1.0);
        w.insert(ConfidenceFactorType::ConsistencyScore, 1.0);
        w.insert(ConfidenceFactorType::SourceQuality, 1.0);
        w.insert(ConfidenceFactorType::ProvenanceCompleteness, 1.0);
        w.insert(ConfidenceFactorType::GroundTruthAlignment, 1.0);
        w.insert(ConfidenceFactorType::ExpertAgreement, 1.0);
        w.insert(ConfidenceFactorType::TemporalStability, 1.0);
        w
    }

    pub fn calculate(&self, factors: &[ConfidenceFactor]) -> ConfidenceScore {
        if factors.len() < self.min_factors || factors.is_empty() {
            return ConfidenceScore::new(0.0);
        }

        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;

        for factor in factors {
            let w = self
                .weights
                .get(&factor.factor_type)
                .copied()
                .unwrap_or(1.0)
                * factor.weight;
            weighted_sum += factor.value.clamp(0.0, 1.0) * w;
            weight_total += w;
        }

        let value = if weight_total > 0.0 {
            (weighted_sum / weight_total).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let mut score = ConfidenceScore::new(value);
        score.factors = factors.to_vec();
        score.methodology = "weighted-average".into();
        score
    }
}

impl Default for ConfidenceCalculator {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Statistical Confidence Scoring
// ═══════════════════════════════════════════════════════════════════════

/// Running statistics using Welford's online algorithm.
#[derive(Debug, Clone)]
pub struct RunningStats {
    pub count: u64,
    pub mean: f64,
    pub m2: f64,
    pub min: f64,
    pub max: f64,
}

impl RunningStats {
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    pub fn update(&mut self, value: f64) {
        self.count += 1;
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.m2 / (self.count - 1) as f64
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn min(&self) -> f64 {
        self.min
    }

    pub fn max(&self) -> f64 {
        self.max
    }

    /// Merge two RunningStats using parallel Welford's algorithm.
    pub fn merge(&mut self, other: &RunningStats) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 {
            *self = other.clone();
            return;
        }
        let combined_count = self.count + other.count;
        let delta = other.mean - self.mean;
        let combined_mean = (self.count as f64 * self.mean + other.count as f64 * other.mean)
            / combined_count as f64;
        let combined_m2 = self.m2
            + other.m2
            + delta * delta * self.count as f64 * other.count as f64 / combined_count as f64;

        self.count = combined_count;
        self.mean = combined_mean;
        self.m2 = combined_m2;
        if other.min < self.min {
            self.min = other.min;
        }
        if other.max > self.max {
            self.max = other.max;
        }
    }
}

impl Default for RunningStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Calibrated confidence scorer that adjusts raw confidence using historical data.
pub struct CalibratedScorer {
    pub stats: RunningStats,
    predictions: Vec<(f64, bool)>,
    pub min_samples: usize,
}

impl CalibratedScorer {
    pub fn new(min_samples: usize) -> Self {
        Self {
            stats: RunningStats::new(),
            predictions: Vec::new(),
            min_samples,
        }
    }

    pub fn record_prediction(&mut self, confidence: f64, was_correct: bool) {
        self.stats.update(confidence);
        self.predictions.push((confidence, was_correct));
    }

    pub fn calibrated_confidence(&self, raw_confidence: f64) -> f64 {
        if self.predictions.len() < self.min_samples {
            return raw_confidence;
        }
        // Find predictions in a window around raw_confidence and compute actual accuracy
        let window = 0.1;
        let nearby: Vec<&(f64, bool)> = self.predictions.iter()
            .filter(|(c, _)| (*c - raw_confidence).abs() <= window)
            .collect();
        if nearby.len() < 3 {
            return raw_confidence;
        }
        let correct = nearby.iter().filter(|(_, w)| *w).count();
        correct as f64 / nearby.len() as f64
    }

    /// Brier score: mean squared error between predicted confidence and outcome.
    pub fn brier_score(&self) -> f64 {
        if self.predictions.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.predictions.iter()
            .map(|(conf, correct)| {
                let actual = if *correct { 1.0 } else { 0.0 };
                (conf - actual).powi(2)
            })
            .sum();
        sum / self.predictions.len() as f64
    }

    /// Expected Calibration Error across bins.
    pub fn calibration_error(&self) -> f64 {
        if self.predictions.is_empty() {
            return 0.0;
        }
        let num_bins = 10;
        let mut bin_correct = vec![0usize; num_bins];
        let mut bin_total = vec![0usize; num_bins];
        let mut bin_conf_sum = vec![0.0f64; num_bins];

        for (conf, correct) in &self.predictions {
            let bin = ((*conf * num_bins as f64) as usize).min(num_bins - 1);
            bin_total[bin] += 1;
            bin_conf_sum[bin] += conf;
            if *correct {
                bin_correct[bin] += 1;
            }
        }

        let n = self.predictions.len() as f64;
        let mut ece = 0.0;
        for i in 0..num_bins {
            if bin_total[i] > 0 {
                let avg_conf = bin_conf_sum[i] / bin_total[i] as f64;
                let accuracy = bin_correct[i] as f64 / bin_total[i] as f64;
                ece += (bin_total[i] as f64 / n) * (avg_conf - accuracy).abs();
            }
        }
        ece
    }

    pub fn is_well_calibrated(&self) -> bool {
        self.calibration_error() < 0.05
    }
}

/// Compute confidence interval bounds.
pub fn confidence_interval(mean: f64, std_dev: f64, n: u64, confidence_level: f64) -> (f64, f64) {
    let z = z_score_for_level(confidence_level);
    let margin = z * std_dev / (n as f64).sqrt();
    (mean - margin, mean + margin)
}

/// Map common confidence levels to z-scores.
pub fn z_score_for_level(confidence_level: f64) -> f64 {
    if (confidence_level - 0.90).abs() < 0.001 {
        1.645
    } else if (confidence_level - 0.95).abs() < 0.001 {
        1.96
    } else if (confidence_level - 0.99).abs() < 0.001 {
        2.576
    } else {
        1.96 // default
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_score_clamps() {
        assert_eq!(ConfidenceScore::new(1.5).value, 1.0);
        assert_eq!(ConfidenceScore::new(-0.3).value, 0.0);
        assert_eq!(ConfidenceScore::new(0.5).value, 0.5);
    }

    #[test]
    fn test_confidence_score_derives_level() {
        assert_eq!(ConfidenceScore::new(0.1).level, ConfidenceLevel::VeryLow);
        assert_eq!(ConfidenceScore::new(0.3).level, ConfidenceLevel::Low);
        assert_eq!(ConfidenceScore::new(0.5).level, ConfidenceLevel::Moderate);
        assert_eq!(ConfidenceScore::new(0.7).level, ConfidenceLevel::High);
        assert_eq!(ConfidenceScore::new(0.9).level, ConfidenceLevel::VeryHigh);
    }

    #[test]
    fn test_confidence_level_from_score() {
        assert_eq!(ConfidenceLevel::from_score(0.0), ConfidenceLevel::VeryLow);
        assert_eq!(ConfidenceLevel::from_score(0.19), ConfidenceLevel::VeryLow);
        assert_eq!(ConfidenceLevel::from_score(0.2), ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::from_score(0.4), ConfidenceLevel::Moderate);
        assert_eq!(ConfidenceLevel::from_score(0.6), ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::from_score(0.8), ConfidenceLevel::VeryHigh);
        assert_eq!(ConfidenceLevel::from_score(1.0), ConfidenceLevel::VeryHigh);
    }

    #[test]
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::VeryLow < ConfidenceLevel::Low);
        assert!(ConfidenceLevel::Low < ConfidenceLevel::Moderate);
        assert!(ConfidenceLevel::Moderate < ConfidenceLevel::High);
        assert!(ConfidenceLevel::High < ConfidenceLevel::VeryHigh);
    }

    #[test]
    fn test_confidence_level_min_score() {
        assert_eq!(ConfidenceLevel::VeryLow.min_score(), 0.0);
        assert_eq!(ConfidenceLevel::Low.min_score(), 0.2);
        assert_eq!(ConfidenceLevel::Moderate.min_score(), 0.4);
        assert_eq!(ConfidenceLevel::High.min_score(), 0.6);
        assert_eq!(ConfidenceLevel::VeryHigh.min_score(), 0.8);
    }

    #[test]
    fn test_is_reliable() {
        assert!(ConfidenceScore::new(0.5).is_reliable());
        assert!(ConfidenceScore::new(0.9).is_reliable());
        assert!(!ConfidenceScore::new(0.3).is_reliable());
    }

    #[test]
    fn test_is_low() {
        assert!(ConfidenceScore::new(0.1).is_low());
        assert!(ConfidenceScore::new(0.3).is_low());
        assert!(!ConfidenceScore::new(0.5).is_low());
    }

    #[test]
    fn test_calculator_single_factor() {
        let calc = ConfidenceCalculator::new();
        let factors = vec![ConfidenceFactor {
            factor_type: ConfidenceFactorType::ModelCalibration,
            value: 0.8,
            weight: 1.0,
            detail: "well calibrated".into(),
        }];
        let score = calc.calculate(&factors);
        assert!((score.value - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_calculator_multiple_factors() {
        let calc = ConfidenceCalculator::new();
        let factors = vec![
            ConfidenceFactor {
                factor_type: ConfidenceFactorType::ModelCalibration,
                value: 0.8,
                weight: 1.0,
                detail: String::new(),
            },
            ConfidenceFactor {
                factor_type: ConfidenceFactorType::OutputEntropy,
                value: 0.6,
                weight: 1.0,
                detail: String::new(),
            },
        ];
        let score = calc.calculate(&factors);
        assert!((score.value - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_calculator_custom_weights() {
        let mut weights = HashMap::new();
        weights.insert(ConfidenceFactorType::ModelCalibration, 3.0);
        weights.insert(ConfidenceFactorType::OutputEntropy, 1.0);
        let calc = ConfidenceCalculator::with_weights(weights);
        let factors = vec![
            ConfidenceFactor {
                factor_type: ConfidenceFactorType::ModelCalibration,
                value: 1.0,
                weight: 1.0,
                detail: String::new(),
            },
            ConfidenceFactor {
                factor_type: ConfidenceFactorType::OutputEntropy,
                value: 0.0,
                weight: 1.0,
                detail: String::new(),
            },
        ];
        let score = calc.calculate(&factors);
        // (1.0*3 + 0.0*1) / (3+1) = 0.75
        assert!((score.value - 0.75).abs() < 1e-9);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_running_stats_single_value() {
        let mut s = RunningStats::new();
        s.update(5.0);
        assert_eq!(s.mean(), 5.0);
        assert_eq!(s.count(), 1);
        assert_eq!(s.min(), 5.0);
        assert_eq!(s.max(), 5.0);
    }

    #[test]
    fn test_running_stats_multiple_values() {
        let mut s = RunningStats::new();
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            s.update(v);
        }
        assert!((s.mean() - 5.0).abs() < 1e-9);
        // sample variance of [2,4,4,4,5,5,7,9]: mean=5, SS=32, var=32/7≈4.571
        assert!((s.variance() - 32.0 / 7.0).abs() < 1e-9);
    }

    #[test]
    fn test_running_stats_variance_hand_calculation() {
        let mut s = RunningStats::new();
        s.update(10.0);
        s.update(20.0);
        s.update(30.0);
        // mean = 20, sample variance = ((10-20)^2 + (20-20)^2 + (30-20)^2) / 2 = 100
        assert!((s.mean() - 20.0).abs() < 1e-9);
        assert!((s.variance() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_running_stats_min_max() {
        let mut s = RunningStats::new();
        for v in [5.0, 1.0, 8.0, 3.0] {
            s.update(v);
        }
        assert_eq!(s.min(), 1.0);
        assert_eq!(s.max(), 8.0);
    }

    #[test]
    fn test_running_stats_merge_mean() {
        let mut a = RunningStats::new();
        for v in [1.0, 2.0, 3.0] {
            a.update(v);
        }
        let mut b = RunningStats::new();
        for v in [4.0, 5.0, 6.0] {
            b.update(v);
        }
        a.merge(&b);
        assert_eq!(a.count(), 6);
        assert!((a.mean() - 3.5).abs() < 1e-9);
    }

    #[test]
    fn test_running_stats_merge_variance() {
        let mut a = RunningStats::new();
        for v in [1.0, 2.0, 3.0] {
            a.update(v);
        }
        let mut b = RunningStats::new();
        for v in [4.0, 5.0, 6.0] {
            b.update(v);
        }
        a.merge(&b);
        // Combined [1,2,3,4,5,6]: mean=3.5, sample_var = 3.5
        assert!((a.variance() - 3.5).abs() < 1e-9);
    }

    #[test]
    fn test_confidence_interval_symmetric() {
        let (lo, hi) = confidence_interval(50.0, 10.0, 100, 0.95);
        // margin = 1.96 * 10 / 10 = 1.96
        assert!((hi - lo - 2.0 * 1.96).abs() < 1e-9);
        assert!((50.0 - lo - 1.96).abs() < 1e-9);
    }

    #[test]
    fn test_confidence_interval_narrows_with_more_samples() {
        let (lo1, hi1) = confidence_interval(50.0, 10.0, 10, 0.95);
        let (lo2, hi2) = confidence_interval(50.0, 10.0, 100, 0.95);
        assert!((hi1 - lo1) > (hi2 - lo2));
    }

    #[test]
    fn test_z_score_for_level_95() {
        assert!((z_score_for_level(0.95) - 1.96).abs() < 1e-9);
    }

    #[test]
    fn test_calibrated_scorer_initial_returns_raw() {
        let scorer = CalibratedScorer::new(10);
        assert_eq!(scorer.calibrated_confidence(0.8), 0.8);
    }

    #[test]
    fn test_calibrated_scorer_after_training() {
        let mut scorer = CalibratedScorer::new(5);
        // Record many predictions around confidence=0.9 that are always correct
        for _ in 0..20 {
            scorer.record_prediction(0.9, true);
        }
        // Calibrated confidence for 0.9 should be 1.0 (always correct in that window)
        let cal = scorer.calibrated_confidence(0.9);
        assert!((cal - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_brier_score_perfect() {
        let mut scorer = CalibratedScorer::new(5);
        scorer.record_prediction(1.0, true);
        scorer.record_prediction(0.0, false);
        assert!((scorer.brier_score() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_brier_score_bad_predictions() {
        let mut scorer = CalibratedScorer::new(5);
        scorer.record_prediction(1.0, false);
        scorer.record_prediction(0.0, true);
        // (1-0)^2 + (0-1)^2 / 2 = 1.0
        assert!((scorer.brier_score() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_calibration_error_well_calibrated() {
        let mut scorer = CalibratedScorer::new(5);
        // Record predictions that match reality well
        for _ in 0..20 {
            scorer.record_prediction(0.9, true);
        }
        for _ in 0..20 {
            scorer.record_prediction(0.1, false);
        }
        assert!(scorer.calibration_error() < 0.15);
    }

    #[test]
    fn test_is_well_calibrated() {
        let mut scorer = CalibratedScorer::new(5);
        // All predictions perfectly correct
        for _ in 0..50 {
            scorer.record_prediction(1.0, true);
        }
        for _ in 0..50 {
            scorer.record_prediction(0.0, false);
        }
        assert!(scorer.is_well_calibrated());
    }

    #[test]
    fn test_confidence_factor_type_display() {
        assert_eq!(ConfidenceFactorType::ModelCalibration.to_string(), "model-calibration");
        assert_eq!(ConfidenceFactorType::OutputEntropy.to_string(), "output-entropy");
        assert_eq!(ConfidenceFactorType::ConsistencyScore.to_string(), "consistency-score");
        assert_eq!(ConfidenceFactorType::SourceQuality.to_string(), "source-quality");
        assert_eq!(ConfidenceFactorType::ProvenanceCompleteness.to_string(), "provenance-completeness");
        assert_eq!(ConfidenceFactorType::GroundTruthAlignment.to_string(), "ground-truth-alignment");
        assert_eq!(ConfidenceFactorType::ExpertAgreement.to_string(), "expert-agreement");
        assert_eq!(ConfidenceFactorType::TemporalStability.to_string(), "temporal-stability");
        assert_eq!(ConfidenceFactorType::Custom("x".into()).to_string(), "custom:x");
    }
}
