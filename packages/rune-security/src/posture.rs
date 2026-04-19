// ═══════════════════════════════════════════════════════════════════════
// Security Posture — overall security assessment and grading
//
// Aggregates dimensional scores (access control, data protection, etc.)
// into a weighted overall score and letter grade.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── PostureGrade ──────────────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum PostureGrade {
    F = 0,
    D = 1,
    C = 2,
    B = 3,
    A = 4,
}

impl PostureGrade {
    pub fn from_score(score: f64) -> Self {
        if score >= 90.0 {
            Self::A
        } else if score >= 80.0 {
            Self::B
        } else if score >= 70.0 {
            Self::C
        } else if score >= 60.0 {
            Self::D
        } else {
            Self::F
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }
}

impl fmt::Display for PostureGrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── DimensionCategory ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DimensionCategory {
    AccessControl,
    DataProtection,
    ThreatManagement,
    IncidentResponse,
    Compliance,
    AiGovernance,
    OperationalResilience,
}

impl fmt::Display for DimensionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── PostureDimension ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PostureDimension {
    pub name: String,
    pub category: DimensionCategory,
    pub score: f64,
    pub weight: f64,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

// ── SecurityPosture ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityPosture {
    pub score: f64,
    pub grade: PostureGrade,
    pub dimensions: Vec<PostureDimension>,
    pub assessed_at: i64,
    pub assessor: String,
    pub recommendations: Vec<String>,
}

// ── PostureAssessor ───────────────────────────────────────────────────

pub struct PostureAssessor {
    pub dimension_weights: HashMap<DimensionCategory, f64>,
}

impl Default for PostureAssessor {
    fn default() -> Self {
        Self::new()
    }
}

impl PostureAssessor {
    pub fn new() -> Self {
        let mut w = HashMap::new();
        for cat in [
            DimensionCategory::AccessControl,
            DimensionCategory::DataProtection,
            DimensionCategory::ThreatManagement,
            DimensionCategory::IncidentResponse,
            DimensionCategory::Compliance,
            DimensionCategory::AiGovernance,
            DimensionCategory::OperationalResilience,
        ] {
            w.insert(cat, 1.0);
        }
        Self { dimension_weights: w }
    }

    pub fn with_weights(weights: HashMap<DimensionCategory, f64>) -> Self {
        Self { dimension_weights: weights }
    }

    pub fn assess(&self, dimensions: Vec<PostureDimension>) -> SecurityPosture {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        for d in &dimensions {
            let w = self
                .dimension_weights
                .get(&d.category)
                .copied()
                .unwrap_or(d.weight);
            weighted_sum += d.score * w;
            total_weight += w;
        }
        let score = if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        };
        let grade = PostureGrade::from_score(score);
        let recommendations = Self::generate_recommendations(&dimensions);

        SecurityPosture {
            score,
            grade,
            dimensions,
            assessed_at: 0,
            assessor: "system".into(),
            recommendations,
        }
    }

    pub fn generate_recommendations(dimensions: &[PostureDimension]) -> Vec<String> {
        let mut recs = Vec::new();
        for d in dimensions {
            if d.score < 70.0 {
                recs.push(format!(
                    "[{}] {}: score {:.1} — improve controls",
                    d.category, d.name, d.score
                ));
            }
        }
        recs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Multi-dimensional Posture Scoring with Trend Tracking
// ═══════════════════════════════════════════════════════════════════════

use crate::severity::SecuritySeverity;

/// A finding within a posture dimension.
#[derive(Debug, Clone)]
pub struct PostureFinding {
    pub id: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub remediated: bool,
}

/// A scored security dimension with findings.
#[derive(Debug, Clone)]
pub struct DimensionScore {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub findings: Vec<PostureFinding>,
}

/// A complete security posture score.
#[derive(Debug, Clone)]
pub struct SecurityPostureScore {
    pub overall: f64,
    pub dimensions: HashMap<String, DimensionScore>,
    pub assessed_at: i64,
    pub assessor: String,
}

/// Create the default set of 8 security dimensions, each starting at 100.
pub fn default_dimensions() -> HashMap<String, DimensionScore> {
    let names = [
        "access_control",
        "data_protection",
        "vulnerability_management",
        "incident_response",
        "monitoring",
        "compliance",
        "network_security",
        "application_security",
    ];
    let mut dims = HashMap::new();
    for name in names {
        dims.insert(
            name.into(),
            DimensionScore {
                name: name.into(),
                score: 100.0,
                weight: 1.0,
                findings: Vec::new(),
            },
        );
    }
    dims
}

/// Calculate the weighted average of all dimension scores.
pub fn calculate_overall(dimensions: &HashMap<String, DimensionScore>) -> f64 {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for dim in dimensions.values() {
        weighted_sum += dim.score * dim.weight;
        total_weight += dim.weight;
    }
    if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    }
}

/// Convert a numeric score to a letter grade.
pub fn posture_grade(score: f64) -> PostureGrade {
    PostureGrade::from_score(score)
}

/// Returns all unremediated findings with Critical severity.
pub fn critical_findings<'a>(
    dimensions: &'a HashMap<String, DimensionScore>,
) -> Vec<&'a PostureFinding> {
    dimensions
        .values()
        .flat_map(|d| d.findings.iter())
        .filter(|f| f.severity == SecuritySeverity::Critical && !f.remediated)
        .collect()
}

/// Direction of a posture trend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    InsufficientData,
}

/// Tracks posture scores over time.
#[derive(Debug, Clone, Default)]
pub struct PostureTrend {
    pub scores: Vec<(i64, f64)>,
}

impl PostureTrend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, score: f64, now: i64) {
        self.scores.push((now, score));
    }

    pub fn trend_direction(&self) -> TrendDirection {
        if self.scores.len() < 3 {
            return TrendDirection::InsufficientData;
        }
        let mid = self.scores.len() / 2;
        let first_avg: f64 =
            self.scores[..mid].iter().map(|(_, s)| s).sum::<f64>() / mid as f64;
        let second_avg: f64 =
            self.scores[mid..].iter().map(|(_, s)| s).sum::<f64>()
                / (self.scores.len() - mid) as f64;
        let delta = second_avg - first_avg;
        let threshold = 2.0; // 2-point threshold
        if delta > threshold {
            TrendDirection::Improving
        } else if delta < -threshold {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        }
    }

    pub fn average_score(&self) -> f64 {
        if self.scores.is_empty() {
            return 0.0;
        }
        self.scores.iter().map(|(_, s)| s).sum::<f64>() / self.scores.len() as f64
    }

    pub fn volatility(&self) -> f64 {
        if self.scores.len() < 2 {
            return 0.0;
        }
        let mean = self.average_score();
        let variance: f64 = self
            .scores
            .iter()
            .map(|(_, s)| (s - mean).powi(2))
            .sum::<f64>()
            / (self.scores.len() - 1) as f64;
        variance.sqrt()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn dim(name: &str, cat: DimensionCategory, score: f64) -> PostureDimension {
        PostureDimension {
            name: name.into(),
            category: cat,
            score,
            weight: 1.0,
            findings: vec![],
            recommendations: vec![],
        }
    }

    #[test]
    fn test_grade_from_score() {
        assert_eq!(PostureGrade::from_score(95.0), PostureGrade::A);
        assert_eq!(PostureGrade::from_score(90.0), PostureGrade::A);
        assert_eq!(PostureGrade::from_score(85.0), PostureGrade::B);
        assert_eq!(PostureGrade::from_score(80.0), PostureGrade::B);
        assert_eq!(PostureGrade::from_score(75.0), PostureGrade::C);
        assert_eq!(PostureGrade::from_score(65.0), PostureGrade::D);
        assert_eq!(PostureGrade::from_score(59.9), PostureGrade::F);
        assert_eq!(PostureGrade::from_score(0.0), PostureGrade::F);
    }

    #[test]
    fn test_grade_ordering() {
        assert!(PostureGrade::F < PostureGrade::D);
        assert!(PostureGrade::D < PostureGrade::C);
        assert!(PostureGrade::C < PostureGrade::B);
        assert!(PostureGrade::B < PostureGrade::A);
    }

    #[test]
    fn test_assessor_equal_weights() {
        let a = PostureAssessor::new();
        let posture = a.assess(vec![
            dim("ac", DimensionCategory::AccessControl, 80.0),
            dim("dp", DimensionCategory::DataProtection, 90.0),
            dim("tm", DimensionCategory::ThreatManagement, 70.0),
        ]);
        assert!((posture.score - 80.0).abs() < 0.01);
        assert_eq!(posture.grade, PostureGrade::B);
    }

    #[test]
    fn test_assessor_custom_weights() {
        let mut weights = HashMap::new();
        weights.insert(DimensionCategory::AccessControl, 2.0);
        weights.insert(DimensionCategory::DataProtection, 1.0);
        let a = PostureAssessor::with_weights(weights);
        let posture = a.assess(vec![
            dim("ac", DimensionCategory::AccessControl, 90.0),
            dim("dp", DimensionCategory::DataProtection, 60.0),
        ]);
        // (90*2 + 60*1) / 3 = 80.0
        assert!((posture.score - 80.0).abs() < 0.01);
    }

    #[test]
    fn test_generate_recommendations_for_low_scores() {
        let dims = vec![
            dim("ac", DimensionCategory::AccessControl, 50.0),
            dim("dp", DimensionCategory::DataProtection, 90.0),
            dim("tm", DimensionCategory::ThreatManagement, 65.0),
        ];
        let recs = PostureAssessor::generate_recommendations(&dims);
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn test_dimension_construction() {
        let d = dim("test", DimensionCategory::AiGovernance, 85.0);
        assert_eq!(d.category, DimensionCategory::AiGovernance);
    }

    #[test]
    fn test_dimension_category_display() {
        assert_eq!(
            DimensionCategory::AiGovernance.to_string(),
            "AiGovernance"
        );
    }

    #[test]
    fn test_assessor_auto_populates_recommendations() {
        let a = PostureAssessor::new();
        let posture = a.assess(vec![
            dim("ac", DimensionCategory::AccessControl, 50.0),
            dim("dp", DimensionCategory::DataProtection, 95.0),
        ]);
        assert_eq!(posture.recommendations.len(), 1);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_default_dimensions_creates_8() {
        let dims = default_dimensions();
        assert_eq!(dims.len(), 8);
        assert!(dims.contains_key("access_control"));
        assert!(dims.contains_key("application_security"));
    }

    #[test]
    fn test_calculate_overall_weighted_average() {
        let mut dims = HashMap::new();
        dims.insert("a".into(), DimensionScore {
            name: "a".into(),
            score: 80.0,
            weight: 2.0,
            findings: vec![],
        });
        dims.insert("b".into(), DimensionScore {
            name: "b".into(),
            score: 60.0,
            weight: 1.0,
            findings: vec![],
        });
        // (80*2 + 60*1) / 3 = 73.33...
        let overall = calculate_overall(&dims);
        assert!((overall - 220.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_posture_grade_a_for_90_plus() {
        assert_eq!(posture_grade(95.0), PostureGrade::A);
        assert_eq!(posture_grade(90.0), PostureGrade::A);
    }

    #[test]
    fn test_posture_grade_f_for_below_60() {
        assert_eq!(posture_grade(59.0), PostureGrade::F);
        assert_eq!(posture_grade(0.0), PostureGrade::F);
    }

    #[test]
    fn test_critical_findings_returns_unremediated_critical() {
        let mut dims = HashMap::new();
        dims.insert("a".into(), DimensionScore {
            name: "a".into(),
            score: 50.0,
            weight: 1.0,
            findings: vec![
                PostureFinding {
                    id: "f1".into(),
                    description: "critical issue".into(),
                    severity: SecuritySeverity::Critical,
                    remediated: false,
                },
                PostureFinding {
                    id: "f2".into(),
                    description: "remediated critical".into(),
                    severity: SecuritySeverity::Critical,
                    remediated: true,
                },
                PostureFinding {
                    id: "f3".into(),
                    description: "high issue".into(),
                    severity: SecuritySeverity::High,
                    remediated: false,
                },
            ],
        });
        let crit = critical_findings(&dims);
        assert_eq!(crit.len(), 1);
        assert_eq!(crit[0].id, "f1");
    }

    #[test]
    fn test_posture_trend_improving() {
        let mut trend = PostureTrend::new();
        trend.record(60.0, 1000);
        trend.record(65.0, 2000);
        trend.record(80.0, 3000);
        trend.record(85.0, 4000);
        trend.record(90.0, 5000);
        assert_eq!(trend.trend_direction(), TrendDirection::Improving);
    }

    #[test]
    fn test_posture_trend_degrading() {
        let mut trend = PostureTrend::new();
        trend.record(90.0, 1000);
        trend.record(85.0, 2000);
        trend.record(70.0, 3000);
        trend.record(60.0, 4000);
        trend.record(55.0, 5000);
        assert_eq!(trend.trend_direction(), TrendDirection::Degrading);
    }

    #[test]
    fn test_posture_trend_volatility() {
        let mut trend = PostureTrend::new();
        trend.record(80.0, 1000);
        trend.record(80.0, 2000);
        trend.record(80.0, 3000);
        assert!((trend.volatility()).abs() < 1e-9);

        let mut spread = PostureTrend::new();
        spread.record(60.0, 1000);
        spread.record(100.0, 2000);
        assert!(spread.volatility() > 0.0);
    }
}
