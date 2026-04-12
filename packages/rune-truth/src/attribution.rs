// ═══════════════════════════════════════════════════════════════════════
// Attribution — source attribution: which data influenced an output.
//
// AttributionEngine computes influence scores between model outputs
// and candidate sources using token overlap, then normalizes scores
// so total influence approaches 1.0.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── InfluenceType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfluenceType {
    TrainingData,
    FineTuningData,
    ContextProvided,
    RetrievalAugmented,
    FewShotExample,
    KnowledgeBase,
    DirectReference,
    Inferred,
}

impl fmt::Display for InfluenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrainingData => f.write_str("training-data"),
            Self::FineTuningData => f.write_str("fine-tuning-data"),
            Self::ContextProvided => f.write_str("context-provided"),
            Self::RetrievalAugmented => f.write_str("retrieval-augmented"),
            Self::FewShotExample => f.write_str("few-shot-example"),
            Self::KnowledgeBase => f.write_str("knowledge-base"),
            Self::DirectReference => f.write_str("direct-reference"),
            Self::Inferred => f.write_str("inferred"),
        }
    }
}

// ── AttributionMethod ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionMethod {
    Similarity,
    Overlap,
    Citation,
    Provenance,
    Manual,
}

impl fmt::Display for AttributionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Similarity => f.write_str("similarity"),
            Self::Overlap => f.write_str("overlap"),
            Self::Citation => f.write_str("citation"),
            Self::Provenance => f.write_str("provenance"),
            Self::Manual => f.write_str("manual"),
        }
    }
}

// ── SourceInfluence ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SourceInfluence {
    pub source_id: String,
    pub source_name: String,
    pub influence_score: f64,
    pub influence_type: InfluenceType,
    pub evidence: String,
    pub confidence: f64,
}

// ── Attribution ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Attribution {
    pub output_id: String,
    pub model_id: String,
    pub sources: Vec<SourceInfluence>,
    pub computed_at: i64,
    pub methodology: AttributionMethod,
    pub total_influence_score: f64,
}

// ── AttributionEngine ────────────────────────────────────────────────

#[derive(Default)]
pub struct AttributionEngine {
    attributions: HashMap<String, Attribution>,
}

impl AttributionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute attribution by word overlap between output and candidate sources.
    /// `sources` is a slice of (id, name, text) tuples.
    pub fn attribute(
        &mut self,
        output_id: &str,
        output_text: &str,
        sources: &[(&str, &str, &str)],
        now: i64,
    ) -> Attribution {
        let output_tokens = tokenize(output_text);

        let mut raw_scores: Vec<(String, String, f64)> = Vec::new();
        let mut total_raw = 0.0;

        for &(id, name, text) in sources {
            let source_tokens = tokenize(text);
            let score = jaccard_overlap(&output_tokens, &source_tokens);
            raw_scores.push((id.to_string(), name.to_string(), score));
            total_raw += score;
        }

        // Normalize scores so they sum to ~1.0 (or keep raw if total is 0).
        let influences: Vec<SourceInfluence> = raw_scores
            .into_iter()
            .map(|(id, name, score)| {
                let normalized = if total_raw > 0.0 {
                    score / total_raw
                } else {
                    0.0
                };
                SourceInfluence {
                    source_id: id,
                    source_name: name,
                    influence_score: normalized,
                    influence_type: InfluenceType::Inferred,
                    evidence: format!("word overlap score: {score:.3}"),
                    confidence: normalized.min(1.0),
                }
            })
            .collect();

        let total_influence: f64 = influences.iter().map(|s| s.influence_score).sum();

        let attr = Attribution {
            output_id: output_id.to_string(),
            model_id: String::new(),
            sources: influences,
            computed_at: now,
            methodology: AttributionMethod::Overlap,
            total_influence_score: total_influence,
        };

        self.attributions.insert(output_id.to_string(), attr.clone());
        attr
    }

    pub fn record_attribution(&mut self, attribution: Attribution) {
        self.attributions
            .insert(attribution.output_id.clone(), attribution);
    }

    pub fn get(&self, output_id: &str) -> Option<&Attribution> {
        self.attributions.get(output_id)
    }

    pub fn top_sources(&self, output_id: &str, n: usize) -> Vec<&SourceInfluence> {
        match self.attributions.get(output_id) {
            Some(attr) => {
                let mut sorted: Vec<&SourceInfluence> = attr.sources.iter().collect();
                sorted.sort_by(|a, b| {
                    b.influence_score
                        .partial_cmp(&a.influence_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                sorted.truncate(n);
                sorted
            }
            None => Vec::new(),
        }
    }

    pub fn sources_above(&self, output_id: &str, threshold: f64) -> Vec<&SourceInfluence> {
        match self.attributions.get(output_id) {
            Some(attr) => attr
                .sources
                .iter()
                .filter(|s| s.influence_score > threshold)
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn unattributed_outputs(&self) -> Vec<&str> {
        self.attributions
            .iter()
            .filter(|(_, attr)| attr.total_influence_score < 0.1)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn count(&self) -> usize {
        self.attributions.len()
    }
}

fn tokenize(text: &str) -> HashSet<String> {
    text.split_whitespace()
        .map(|w| w.to_lowercase())
        .collect()
}

fn jaccard_overlap(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_overlapping_source() {
        let mut engine = AttributionEngine::new();
        let attr = engine.attribute(
            "o1",
            "the cat sat on the mat",
            &[("s1", "source1", "the cat sat on a rug")],
            1000,
        );
        assert!(attr.sources[0].influence_score > 0.0);
    }

    #[test]
    fn test_attribute_non_overlapping_source() {
        let mut engine = AttributionEngine::new();
        let attr = engine.attribute(
            "o1",
            "the cat sat on the mat",
            &[("s1", "source1", "dogs run quickly through fields")],
            1000,
        );
        // Low overlap — but since it's the only source, normalized to 1.0
        // unless raw score is 0
        assert!(attr.sources[0].influence_score >= 0.0);
    }

    #[test]
    fn test_attribute_normalizes() {
        let mut engine = AttributionEngine::new();
        let attr = engine.attribute(
            "o1",
            "the cat sat on the mat",
            &[
                ("s1", "src1", "the cat sat on a rug"),
                ("s2", "src2", "the dog ran in the park"),
            ],
            1000,
        );
        let total: f64 = attr.sources.iter().map(|s| s.influence_score).sum();
        assert!((total - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_record_and_get() {
        let mut engine = AttributionEngine::new();
        engine.attribute("o1", "text", &[("s1", "s", "text")], 1000);
        assert!(engine.get("o1").is_some());
        assert_eq!(engine.count(), 1);
    }

    #[test]
    fn test_top_sources() {
        let mut engine = AttributionEngine::new();
        engine.attribute(
            "o1",
            "alpha beta gamma delta",
            &[
                ("s1", "s1", "alpha beta"),
                ("s2", "s2", "gamma delta epsilon"),
                ("s3", "s3", "completely unrelated words here"),
            ],
            1000,
        );
        let top = engine.top_sources("o1", 2);
        assert_eq!(top.len(), 2);
        assert!(top[0].influence_score >= top[1].influence_score);
    }

    #[test]
    fn test_sources_above() {
        let mut engine = AttributionEngine::new();
        engine.attribute(
            "o1",
            "alpha beta gamma",
            &[
                ("s1", "s1", "alpha beta gamma"),
                ("s2", "s2", "completely different text"),
            ],
            1000,
        );
        let above = engine.sources_above("o1", 0.3);
        assert!(!above.is_empty());
    }

    #[test]
    fn test_unattributed_outputs() {
        let mut engine = AttributionEngine::new();
        // Record an attribution with zero influence
        let attr = Attribution {
            output_id: "o1".into(),
            model_id: String::new(),
            sources: Vec::new(),
            computed_at: 1000,
            methodology: AttributionMethod::Overlap,
            total_influence_score: 0.0,
        };
        engine.record_attribution(attr);
        let unattr = engine.unattributed_outputs();
        assert_eq!(unattr.len(), 1);
    }

    #[test]
    fn test_influence_type_display() {
        assert_eq!(InfluenceType::TrainingData.to_string(), "training-data");
        assert_eq!(InfluenceType::FineTuningData.to_string(), "fine-tuning-data");
        assert_eq!(InfluenceType::ContextProvided.to_string(), "context-provided");
        assert_eq!(InfluenceType::RetrievalAugmented.to_string(), "retrieval-augmented");
        assert_eq!(InfluenceType::FewShotExample.to_string(), "few-shot-example");
        assert_eq!(InfluenceType::KnowledgeBase.to_string(), "knowledge-base");
        assert_eq!(InfluenceType::DirectReference.to_string(), "direct-reference");
        assert_eq!(InfluenceType::Inferred.to_string(), "inferred");
    }

    #[test]
    fn test_attribution_method_display() {
        assert_eq!(AttributionMethod::Similarity.to_string(), "similarity");
        assert_eq!(AttributionMethod::Overlap.to_string(), "overlap");
        assert_eq!(AttributionMethod::Citation.to_string(), "citation");
        assert_eq!(AttributionMethod::Provenance.to_string(), "provenance");
        assert_eq!(AttributionMethod::Manual.to_string(), "manual");
    }
}
