// ═══════════════════════════════════════════════════════════════════════
// Explanation Quality Assessor — Trait for evaluating the quality of
// generated explanations along four dimensions from the explainability
// literature:
//
//   1. Faithfulness  — does the explanation accurately reflect the
//                      model's actual decision process?
//   2. Stability     — do similar inputs produce similar explanations?
//   3. Comprehensibility — can the target audience understand it?
//   4. Actionability — does the explanation suggest concrete next steps?
//
// StructuralFaithfulnessAssessor checks structural properties
// (non-empty factors, present summary) as a proxy for faithfulness.
// ReadabilityAssessor uses simple heuristics (word count, factor
// count) as proxies for comprehensibility and actionability.
//
// Full semantic assessment (e.g., comparing explanation to actual model
// internals) requires model-specific adapters and belongs in adapter
// crates.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::ExplainabilityError;
use crate::explanation_export::ExportableExplanation;

// ── OverallQualityClass ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OverallQualityClass {
    Excellent,
    Adequate,
    Poor,
    Unknown,
}

impl fmt::Display for OverallQualityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Excellent => write!(f, "excellent"),
            Self::Adequate => write!(f, "adequate"),
            Self::Poor => write!(f, "poor"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── QualityAssessment ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityAssessment {
    pub explanation_id: String,
    pub faithfulness_score: String,
    pub stability_score: String,
    pub comprehensibility_score: String,
    pub actionability_score: String,
    pub overall_quality_class: OverallQualityClass,
    pub limitations: Vec<String>,
    pub assessor_id: String,
    pub assessed_at: i64,
}

impl QualityAssessment {
    pub fn scores_as_f64(&self) -> (f64, f64, f64, f64) {
        (
            self.faithfulness_score.parse().unwrap_or(0.0),
            self.stability_score.parse().unwrap_or(0.0),
            self.comprehensibility_score.parse().unwrap_or(0.0),
            self.actionability_score.parse().unwrap_or(0.0),
        )
    }
}

// ── ExplanationQualityAssessor trait ───────────────────────────

pub trait ExplanationQualityAssessor {
    fn assess_quality(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<QualityAssessment, ExplainabilityError>;

    fn assessor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── StructuralFaithfulnessAssessor ─────────────────────────────

pub struct StructuralFaithfulnessAssessor {
    id: String,
}

impl StructuralFaithfulnessAssessor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ExplanationQualityAssessor for StructuralFaithfulnessAssessor {
    fn assess_quality(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<QualityAssessment, ExplainabilityError> {
        let mut limitations = Vec::new();

        // Faithfulness: does the explanation have factors that relate to the subject?
        let faithfulness = if explanation.factors.is_empty() {
            limitations.push("No contributing factors provided".to_string());
            0.0
        } else {
            let non_zero_contributions = explanation.factors.iter()
                .filter(|f| {
                    let val: f64 = f.contribution.parse().unwrap_or(0.0);
                    val.abs() > f64::EPSILON
                })
                .count();
            if non_zero_contributions == 0 {
                limitations.push("All factor contributions are zero".to_string());
                0.2
            } else {
                let ratio = non_zero_contributions as f64 / explanation.factors.len() as f64;
                0.4 + 0.6 * ratio
            }
        };

        // Stability: proxy — check if confidence score is present and reasonable
        let stability = if let Ok(conf) = explanation.confidence_score.parse::<f64>() {
            if conf >= 0.8 {
                1.0
            } else if conf >= 0.5 {
                0.7
            } else {
                0.4
            }
        } else {
            limitations.push("Confidence score not parseable".to_string());
            0.0
        };

        // Comprehensibility: proxy — summary length and factor count
        let word_count = explanation.summary.split_whitespace().count();
        let comprehensibility = if word_count == 0 {
            limitations.push("Empty summary".to_string());
            0.0
        } else if word_count <= 5 {
            0.5
        } else if word_count <= 50 {
            1.0
        } else {
            limitations.push("Summary may be too long for quick comprehension".to_string());
            0.6
        };

        // Actionability: proxy — are there factors with clear direction?
        let directed_factors = explanation.factors.iter()
            .filter(|f| f.direction != "neutral" && !f.direction.is_empty())
            .count();
        let actionability = if explanation.factors.is_empty() {
            0.0
        } else {
            directed_factors as f64 / explanation.factors.len() as f64
        };

        let avg = (faithfulness + stability + comprehensibility + actionability) / 4.0;
        let overall = if avg >= 0.8 {
            OverallQualityClass::Excellent
        } else if avg >= 0.5 {
            OverallQualityClass::Adequate
        } else {
            OverallQualityClass::Poor
        };

        Ok(QualityAssessment {
            explanation_id: explanation.explanation_id.clone(),
            faithfulness_score: format!("{faithfulness}"),
            stability_score: format!("{stability}"),
            comprehensibility_score: format!("{comprehensibility}"),
            actionability_score: format!("{actionability}"),
            overall_quality_class: overall,
            limitations,
            assessor_id: self.id.clone(),
            assessed_at: 0,
        })
    }

    fn assessor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── ReadabilityAssessor ────────────────────────────────────────

pub struct ReadabilityAssessor {
    id: String,
    max_factor_count: usize,
    max_summary_words: usize,
}

impl ReadabilityAssessor {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            max_factor_count: 10,
            max_summary_words: 100,
        }
    }

    pub fn with_max_factor_count(mut self, max: usize) -> Self {
        self.max_factor_count = max;
        self
    }

    pub fn with_max_summary_words(mut self, max: usize) -> Self {
        self.max_summary_words = max;
        self
    }
}

impl ExplanationQualityAssessor for ReadabilityAssessor {
    fn assess_quality(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<QualityAssessment, ExplainabilityError> {
        let mut limitations = Vec::new();

        // Faithfulness: not assessed by readability — return neutral
        let faithfulness = 0.5;

        // Stability: not assessed by readability — return neutral
        let stability = 0.5;

        // Comprehensibility: factor count and summary length
        let factor_count = explanation.factors.len();
        let comprehensibility = if factor_count == 0 {
            limitations.push("No factors to explain".to_string());
            0.0
        } else if factor_count <= self.max_factor_count {
            1.0
        } else {
            limitations.push(format!(
                "Too many factors ({factor_count}) for easy comprehension (max: {})",
                self.max_factor_count
            ));
            self.max_factor_count as f64 / factor_count as f64
        };

        let word_count = explanation.summary.split_whitespace().count();
        let summary_score = if word_count == 0 {
            limitations.push("Missing summary".to_string());
            0.0
        } else if word_count <= self.max_summary_words {
            1.0
        } else {
            limitations.push(format!(
                "Summary too long ({word_count} words, max: {})",
                self.max_summary_words
            ));
            self.max_summary_words as f64 / word_count as f64
        };

        let comprehensibility = (comprehensibility + summary_score) / 2.0;

        // Actionability: check for non-empty direction and contribution
        let actionable = explanation.factors.iter()
            .filter(|f| !f.direction.is_empty() && !f.contribution.is_empty())
            .count();
        let actionability = if explanation.factors.is_empty() {
            0.0
        } else {
            actionable as f64 / explanation.factors.len() as f64
        };

        let avg = (faithfulness + stability + comprehensibility + actionability) / 4.0;
        let overall = if avg >= 0.8 {
            OverallQualityClass::Excellent
        } else if avg >= 0.5 {
            OverallQualityClass::Adequate
        } else {
            OverallQualityClass::Poor
        };

        Ok(QualityAssessment {
            explanation_id: explanation.explanation_id.clone(),
            faithfulness_score: format!("{faithfulness}"),
            stability_score: format!("{stability}"),
            comprehensibility_score: format!("{comprehensibility}"),
            actionability_score: format!("{actionability}"),
            overall_quality_class: overall,
            limitations,
            assessor_id: self.id.clone(),
            assessed_at: 0,
        })
    }

    fn assessor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullExplanationQualityAssessor ─────────────────────────────

pub struct NullExplanationQualityAssessor {
    id: String,
}

impl NullExplanationQualityAssessor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ExplanationQualityAssessor for NullExplanationQualityAssessor {
    fn assess_quality(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<QualityAssessment, ExplainabilityError> {
        Ok(QualityAssessment {
            explanation_id: explanation.explanation_id.clone(),
            faithfulness_score: "0".to_string(),
            stability_score: "0".to_string(),
            comprehensibility_score: "0".to_string(),
            actionability_score: "0".to_string(),
            overall_quality_class: OverallQualityClass::Unknown,
            limitations: vec!["Null assessor — no assessment performed".to_string()],
            assessor_id: self.id.clone(),
            assessed_at: 0,
        })
    }

    fn assessor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explanation_export::ExportableFactor;
    use std::collections::HashMap;

    fn sample_explanation() -> ExportableExplanation {
        ExportableExplanation {
            explanation_id: "exp-1".to_string(),
            subject_id: "pred-1".to_string(),
            explanation_type: "feature-attribution".to_string(),
            summary: "Loan denied due to low income and high debt ratio".to_string(),
            factors: vec![
                ExportableFactor {
                    factor_name: "income".into(),
                    factor_value: "30000".into(),
                    contribution: "0.7".into(),
                    direction: "negative".into(),
                },
                ExportableFactor {
                    factor_name: "debt_ratio".into(),
                    factor_value: "0.6".into(),
                    contribution: "0.2".into(),
                    direction: "negative".into(),
                },
            ],
            confidence_score: "0.85".to_string(),
            generator_id: "lc-1".to_string(),
            generated_at: 1000,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_overall_quality_class_display() {
        assert_eq!(OverallQualityClass::Excellent.to_string(), "excellent");
        assert_eq!(OverallQualityClass::Adequate.to_string(), "adequate");
        assert_eq!(OverallQualityClass::Poor.to_string(), "poor");
        assert_eq!(OverallQualityClass::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_structural_faithfulness_good_explanation() {
        let assessor = StructuralFaithfulnessAssessor::new("sf-1");
        let exp = sample_explanation();
        let result = assessor.assess_quality(&exp).unwrap();
        assert_eq!(result.explanation_id, "exp-1");
        let (f, s, c, a) = result.scores_as_f64();
        assert!(f > 0.5, "faithfulness should be high: {f}");
        assert!(s > 0.5, "stability should be moderate: {s}");
        assert!(c > 0.5, "comprehensibility should be high: {c}");
        assert!(a > 0.5, "actionability should be high: {a}");
    }

    #[test]
    fn test_structural_faithfulness_empty_factors() {
        let assessor = StructuralFaithfulnessAssessor::new("sf-1");
        let mut exp = sample_explanation();
        exp.factors.clear();
        let result = assessor.assess_quality(&exp).unwrap();
        let (f, _, _, a) = result.scores_as_f64();
        assert!(f < 0.1, "faithfulness should be zero with no factors: {f}");
        assert!(a < 0.1, "actionability should be zero with no factors: {a}");
        assert!(!result.limitations.is_empty());
    }

    #[test]
    fn test_structural_faithfulness_empty_summary() {
        let assessor = StructuralFaithfulnessAssessor::new("sf-1");
        let mut exp = sample_explanation();
        exp.summary = String::new();
        let result = assessor.assess_quality(&exp).unwrap();
        let (_, _, c, _) = result.scores_as_f64();
        assert!(c < 0.1, "comprehensibility should be zero with empty summary: {c}");
    }

    #[test]
    fn test_readability_assessor_defaults() {
        let assessor = ReadabilityAssessor::new("ra-1");
        let exp = sample_explanation();
        let result = assessor.assess_quality(&exp).unwrap();
        assert_eq!(result.assessor_id, "ra-1");
        let (_, _, c, _) = result.scores_as_f64();
        assert!(c > 0.5, "comprehensibility should be adequate: {c}");
    }

    #[test]
    fn test_readability_assessor_too_many_factors() {
        let assessor = ReadabilityAssessor::new("ra-1").with_max_factor_count(1);
        let exp = sample_explanation();
        let result = assessor.assess_quality(&exp).unwrap();
        assert!(result.limitations.iter().any(|l| l.contains("Too many factors")));
    }

    #[test]
    fn test_readability_assessor_long_summary() {
        let assessor = ReadabilityAssessor::new("ra-1").with_max_summary_words(3);
        let exp = sample_explanation();
        let result = assessor.assess_quality(&exp).unwrap();
        assert!(result.limitations.iter().any(|l| l.contains("Summary too long")));
    }

    #[test]
    fn test_null_assessor() {
        let assessor = NullExplanationQualityAssessor::new("null-1");
        let exp = sample_explanation();
        let result = assessor.assess_quality(&exp).unwrap();
        assert_eq!(result.overall_quality_class, OverallQualityClass::Unknown);
        assert!(!assessor.is_active());
    }

    #[test]
    fn test_assessor_ids() {
        let sf = StructuralFaithfulnessAssessor::new("sf-1");
        assert_eq!(sf.assessor_id(), "sf-1");
        assert!(sf.is_active());

        let ra = ReadabilityAssessor::new("ra-1");
        assert_eq!(ra.assessor_id(), "ra-1");
        assert!(ra.is_active());
    }

    #[test]
    fn test_quality_assessment_scores_as_f64() {
        let qa = QualityAssessment {
            explanation_id: "e1".into(),
            faithfulness_score: "0.9".into(),
            stability_score: "0.8".into(),
            comprehensibility_score: "0.7".into(),
            actionability_score: "0.6".into(),
            overall_quality_class: OverallQualityClass::Adequate,
            limitations: Vec::new(),
            assessor_id: "a1".into(),
            assessed_at: 0,
        };
        let (f, s, c, a) = qa.scores_as_f64();
        assert!((f - 0.9).abs() < f64::EPSILON);
        assert!((s - 0.8).abs() < f64::EPSILON);
        assert!((c - 0.7).abs() < f64::EPSILON);
        assert!((a - 0.6).abs() < f64::EPSILON);
    }
}
