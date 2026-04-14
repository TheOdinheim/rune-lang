// ═══════════════════════════════════════════════════════════════════════
// Detection Scoring — Weighted Multi-Signal Threat Scoring (Layer 2)
//
// Combines scores from statistical anomaly detection, pattern matching,
// behavioral analysis, and alert correlation into a single weighted
// threat score. Configurable weights and threshold.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── DetectionWeights ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionWeights {
    pub statistical: f64,
    pub pattern: f64,
    pub behavioral: f64,
    pub correlation: f64,
}

impl Default for DetectionWeights {
    fn default() -> Self {
        Self {
            statistical: 0.25,
            pattern: 0.35,
            behavioral: 0.20,
            correlation: 0.20,
        }
    }
}

impl DetectionWeights {
    pub fn total(&self) -> f64 {
        self.statistical + self.pattern + self.behavioral + self.correlation
    }

    pub fn is_valid(&self) -> bool {
        let total = self.total();
        (total - 1.0).abs() < 0.01
            && self.statistical >= 0.0
            && self.pattern >= 0.0
            && self.behavioral >= 0.0
            && self.correlation >= 0.0
    }
}

// ── ScoreComponent ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScoreComponent {
    pub name: String,
    pub raw_score: f64,
    pub weight: f64,
    pub weighted_score: f64,
    pub detail: String,
}

// ── DetectionScore ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionScore {
    pub total: f64,
    pub components: Vec<ScoreComponent>,
    pub is_threat: bool,
    pub threat_threshold: f64,
    pub detail: String,
}

// ── DetectionScorer ──────────────────────────────────────────────────

pub struct DetectionScorer {
    pub weights: DetectionWeights,
    pub threat_threshold: f64,
}

impl Default for DetectionScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionScorer {
    pub fn new() -> Self {
        Self {
            weights: DetectionWeights::default(),
            threat_threshold: 0.5,
        }
    }

    pub fn with_weights(weights: DetectionWeights) -> Self {
        Self {
            weights,
            threat_threshold: 0.5,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threat_threshold = threshold;
        self
    }

    /// Score a detection event from individual signal scores (each 0.0–1.0).
    pub fn score(
        &self,
        statistical: f64,
        pattern: f64,
        behavioral: f64,
        correlation: f64,
    ) -> DetectionScore {
        let stat_clamped = statistical.clamp(0.0, 1.0);
        let pat_clamped = pattern.clamp(0.0, 1.0);
        let beh_clamped = behavioral.clamp(0.0, 1.0);
        let cor_clamped = correlation.clamp(0.0, 1.0);

        let components = vec![
            ScoreComponent {
                name: "statistical".into(),
                raw_score: stat_clamped,
                weight: self.weights.statistical,
                weighted_score: stat_clamped * self.weights.statistical,
                detail: format!("anomaly={stat_clamped:.3}"),
            },
            ScoreComponent {
                name: "pattern".into(),
                raw_score: pat_clamped,
                weight: self.weights.pattern,
                weighted_score: pat_clamped * self.weights.pattern,
                detail: format!("pattern={pat_clamped:.3}"),
            },
            ScoreComponent {
                name: "behavioral".into(),
                raw_score: beh_clamped,
                weight: self.weights.behavioral,
                weighted_score: beh_clamped * self.weights.behavioral,
                detail: format!("behavioral={beh_clamped:.3}"),
            },
            ScoreComponent {
                name: "correlation".into(),
                raw_score: cor_clamped,
                weight: self.weights.correlation,
                weighted_score: cor_clamped * self.weights.correlation,
                detail: format!("correlation={cor_clamped:.3}"),
            },
        ];

        let total: f64 = components.iter().map(|c| c.weighted_score).sum();
        let total = total.min(1.0);
        let is_threat = total >= self.threat_threshold;

        let detail = format!(
            "total={total:.3} (stat={:.3} pat={:.3} beh={:.3} cor={:.3})",
            components[0].weighted_score,
            components[1].weighted_score,
            components[2].weighted_score,
            components[3].weighted_score,
        );

        DetectionScore {
            total,
            components,
            is_threat,
            threat_threshold: self.threat_threshold,
            detail,
        }
    }
}

impl fmt::Debug for DetectionScorer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectionScorer")
            .field("weights", &self.weights)
            .field("threat_threshold", &self.threat_threshold)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_weights_sum_to_one() {
        let w = DetectionWeights::default();
        assert!(w.is_valid());
        assert!((w.total() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_scorer_all_zeros() {
        let s = DetectionScorer::new();
        let r = s.score(0.0, 0.0, 0.0, 0.0);
        assert_eq!(r.total, 0.0);
        assert!(!r.is_threat);
    }

    #[test]
    fn test_scorer_all_ones() {
        let s = DetectionScorer::new();
        let r = s.score(1.0, 1.0, 1.0, 1.0);
        assert!((r.total - 1.0).abs() < 0.001);
        assert!(r.is_threat);
    }

    #[test]
    fn test_scorer_pattern_weighted_highest() {
        let s = DetectionScorer::new();
        // Only pattern fires at 1.0
        let r = s.score(0.0, 1.0, 0.0, 0.0);
        assert!((r.total - 0.35).abs() < 0.001);
        assert!(!r.is_threat); // 0.35 < 0.5
    }

    #[test]
    fn test_scorer_threshold_boundary() {
        let s = DetectionScorer::new().with_threshold(0.5);
        // Just below threshold
        let r = s.score(0.5, 0.5, 0.0, 0.0);
        // 0.5*0.25 + 0.5*0.35 = 0.125+0.175 = 0.3
        assert!(!r.is_threat);
        // Above threshold
        let r = s.score(1.0, 1.0, 0.5, 0.0);
        // 0.25 + 0.35 + 0.1 = 0.7
        assert!(r.is_threat);
    }

    #[test]
    fn test_scorer_clamping() {
        let s = DetectionScorer::new();
        let r = s.score(5.0, -1.0, 2.0, 0.5);
        // Clamped to 1.0, 0.0, 1.0, 0.5
        assert!(r.total <= 1.0);
        assert!(r.components[0].raw_score == 1.0);
        assert!(r.components[1].raw_score == 0.0);
    }

    #[test]
    fn test_scorer_custom_weights() {
        let w = DetectionWeights {
            statistical: 0.5,
            pattern: 0.5,
            behavioral: 0.0,
            correlation: 0.0,
        };
        let s = DetectionScorer::with_weights(w);
        let r = s.score(1.0, 0.0, 1.0, 1.0);
        // Only statistical counts: 1.0 * 0.5 = 0.5
        assert!((r.total - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_scorer_components_present() {
        let s = DetectionScorer::new();
        let r = s.score(0.5, 0.8, 0.3, 0.1);
        assert_eq!(r.components.len(), 4);
        assert_eq!(r.components[0].name, "statistical");
        assert_eq!(r.components[1].name, "pattern");
        assert_eq!(r.components[2].name, "behavioral");
        assert_eq!(r.components[3].name, "correlation");
    }

    #[test]
    fn test_scorer_detail_string() {
        let s = DetectionScorer::new();
        let r = s.score(0.5, 0.8, 0.3, 0.1);
        assert!(r.detail.contains("total="));
        assert!(r.detail.contains("stat="));
    }
}
