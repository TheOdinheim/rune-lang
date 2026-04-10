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
}
