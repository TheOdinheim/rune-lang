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
