// ═══════════════════════════════════════════════════════════════════════
// Explanation Backend — pluggable storage for explanations, reasoning
// traces, feature attribution sets, counterfactual examples, and rule
// firing records.
//
// SubjectIdRef is a newtype wrapping a String — the subject of
// explanation may be a model prediction, a policy decision, a claim,
// or any other explainable artifact.  The backend is agnostic to the
// source domain; it accepts opaque reference identifiers.
//
// StoredExplanation.confidence_score is String for Eq derivation,
// following the pattern established across all RUNE backends.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::ExplainabilityError;

// ── SubjectIdRef ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectIdRef(pub String);

impl SubjectIdRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectIdRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for SubjectIdRef {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

// ── ExplanationType ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExplanationType {
    FeatureAttribution,
    RuleBased,
    Counterfactual,
    DecisionTrace,
    NaturalLanguage,
}

impl fmt::Display for ExplanationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureAttribution => write!(f, "feature-attribution"),
            Self::RuleBased => write!(f, "rule-based"),
            Self::Counterfactual => write!(f, "counterfactual"),
            Self::DecisionTrace => write!(f, "decision-trace"),
            Self::NaturalLanguage => write!(f, "natural-language"),
        }
    }
}

// ── StoredExplanation ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExplanation {
    pub explanation_id: String,
    pub subject_id_ref: SubjectIdRef,
    pub explanation_type: ExplanationType,
    pub confidence_score: String,
    pub generated_at: i64,
    pub explanation_body_bytes: Vec<u8>,
    pub generator_id: String,
}

// ── StoredReasoningTrace ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReasoningTrace {
    pub trace_id: String,
    pub decision_id: String,
    pub steps: Vec<StoredReasoningStep>,
    pub conclusion: Option<String>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReasoningStep {
    pub step_id: String,
    pub step_number: usize,
    pub step_type: String,
    pub description: String,
    pub inputs: HashMap<String, String>,
    pub outputs: HashMap<String, String>,
    pub executed_at: i64,
}

// ── StoredFeatureAttributionSet ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFeatureAttributionSet {
    pub attribution_set_id: String,
    pub prediction_id: String,
    pub method: String,
    pub attributions_json: String,
    pub computed_at: i64,
}

// ── StoredCounterfactualExample ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCounterfactualExample {
    pub example_id: String,
    pub prediction_id: String,
    pub resulting_outcome: String,
    pub distance_from_original: String,
    pub generated_at: i64,
    pub original_input_json: String,
    pub modified_input_json: String,
}

// ── StoredRuleFiringRecord ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuleFiringRecord {
    pub record_id: String,
    pub decision_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub matched: bool,
    pub priority: usize,
    pub fired_at: i64,
    pub inputs: HashMap<String, String>,
    pub outputs: HashMap<String, String>,
}

// ── ExplanationBackendInfo ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplanationBackendInfo {
    pub backend_name: String,
    pub explanation_count: usize,
    pub reasoning_trace_count: usize,
    pub feature_attribution_set_count: usize,
    pub counterfactual_count: usize,
    pub rule_firing_count: usize,
}

// ── ExplanationBackend trait ────────────────────────────────────

pub trait ExplanationBackend {
    // Explanations
    fn store_explanation(&mut self, explanation: StoredExplanation) -> Result<(), ExplainabilityError>;
    fn retrieve_explanation(&self, explanation_id: &str) -> Result<StoredExplanation, ExplainabilityError>;
    fn delete_explanation(&mut self, explanation_id: &str) -> Result<(), ExplainabilityError>;
    fn list_explanations_for_subject_id(&self, subject_id: &SubjectIdRef) -> Vec<&StoredExplanation>;
    fn explanation_count(&self) -> usize;

    // Reasoning traces
    fn store_reasoning_trace(&mut self, trace: StoredReasoningTrace) -> Result<(), ExplainabilityError>;
    fn retrieve_reasoning_trace(&self, trace_id: &str) -> Result<StoredReasoningTrace, ExplainabilityError>;
    fn list_reasoning_traces_for_decision(&self, decision_id: &str) -> Vec<&StoredReasoningTrace>;

    // Feature attribution sets
    fn store_feature_attribution_set(&mut self, set: StoredFeatureAttributionSet) -> Result<(), ExplainabilityError>;
    fn retrieve_feature_attribution_set(&self, set_id: &str) -> Result<StoredFeatureAttributionSet, ExplainabilityError>;
    fn list_feature_attribution_sets_for_prediction(&self, prediction_id: &str) -> Vec<&StoredFeatureAttributionSet>;

    // Counterfactual examples
    fn store_counterfactual_example(&mut self, example: StoredCounterfactualExample) -> Result<(), ExplainabilityError>;
    fn retrieve_counterfactual_example(&self, example_id: &str) -> Result<StoredCounterfactualExample, ExplainabilityError>;
    fn list_counterfactuals_for_prediction(&self, prediction_id: &str) -> Vec<&StoredCounterfactualExample>;

    // Rule firing records
    fn store_rule_firing_record(&mut self, record: StoredRuleFiringRecord) -> Result<(), ExplainabilityError>;
    fn retrieve_rule_firing_record(&self, record_id: &str) -> Result<StoredRuleFiringRecord, ExplainabilityError>;
    fn list_rule_firings_for_decision(&self, decision_id: &str) -> Vec<&StoredRuleFiringRecord>;

    // Management
    fn flush(&mut self);
    fn backend_info(&self) -> ExplanationBackendInfo;
}

// ── InMemoryExplanationBackend ──────────────────────────────────

pub struct InMemoryExplanationBackend {
    explanations: HashMap<String, StoredExplanation>,
    reasoning_traces: HashMap<String, StoredReasoningTrace>,
    attribution_sets: HashMap<String, StoredFeatureAttributionSet>,
    counterfactuals: HashMap<String, StoredCounterfactualExample>,
    rule_firings: HashMap<String, StoredRuleFiringRecord>,
}

impl InMemoryExplanationBackend {
    pub fn new() -> Self {
        Self {
            explanations: HashMap::new(),
            reasoning_traces: HashMap::new(),
            attribution_sets: HashMap::new(),
            counterfactuals: HashMap::new(),
            rule_firings: HashMap::new(),
        }
    }
}

impl Default for InMemoryExplanationBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ExplanationBackend for InMemoryExplanationBackend {
    fn store_explanation(&mut self, explanation: StoredExplanation) -> Result<(), ExplainabilityError> {
        self.explanations.insert(explanation.explanation_id.clone(), explanation);
        Ok(())
    }

    fn retrieve_explanation(&self, explanation_id: &str) -> Result<StoredExplanation, ExplainabilityError> {
        self.explanations.get(explanation_id).cloned()
            .ok_or_else(|| ExplainabilityError::DecisionNotFound(explanation_id.to_string()))
    }

    fn delete_explanation(&mut self, explanation_id: &str) -> Result<(), ExplainabilityError> {
        self.explanations.remove(explanation_id)
            .map(|_| ())
            .ok_or_else(|| ExplainabilityError::DecisionNotFound(explanation_id.to_string()))
    }

    fn list_explanations_for_subject_id(&self, subject_id: &SubjectIdRef) -> Vec<&StoredExplanation> {
        self.explanations.values()
            .filter(|e| e.subject_id_ref == *subject_id)
            .collect()
    }

    fn explanation_count(&self) -> usize {
        self.explanations.len()
    }

    fn store_reasoning_trace(&mut self, trace: StoredReasoningTrace) -> Result<(), ExplainabilityError> {
        self.reasoning_traces.insert(trace.trace_id.clone(), trace);
        Ok(())
    }

    fn retrieve_reasoning_trace(&self, trace_id: &str) -> Result<StoredReasoningTrace, ExplainabilityError> {
        self.reasoning_traces.get(trace_id).cloned()
            .ok_or_else(|| ExplainabilityError::DecisionNotFound(trace_id.to_string()))
    }

    fn list_reasoning_traces_for_decision(&self, decision_id: &str) -> Vec<&StoredReasoningTrace> {
        self.reasoning_traces.values()
            .filter(|t| t.decision_id == decision_id)
            .collect()
    }

    fn store_feature_attribution_set(&mut self, set: StoredFeatureAttributionSet) -> Result<(), ExplainabilityError> {
        self.attribution_sets.insert(set.attribution_set_id.clone(), set);
        Ok(())
    }

    fn retrieve_feature_attribution_set(&self, set_id: &str) -> Result<StoredFeatureAttributionSet, ExplainabilityError> {
        self.attribution_sets.get(set_id).cloned()
            .ok_or_else(|| ExplainabilityError::DecisionNotFound(set_id.to_string()))
    }

    fn list_feature_attribution_sets_for_prediction(&self, prediction_id: &str) -> Vec<&StoredFeatureAttributionSet> {
        self.attribution_sets.values()
            .filter(|s| s.prediction_id == prediction_id)
            .collect()
    }

    fn store_counterfactual_example(&mut self, example: StoredCounterfactualExample) -> Result<(), ExplainabilityError> {
        self.counterfactuals.insert(example.example_id.clone(), example);
        Ok(())
    }

    fn retrieve_counterfactual_example(&self, example_id: &str) -> Result<StoredCounterfactualExample, ExplainabilityError> {
        self.counterfactuals.get(example_id).cloned()
            .ok_or_else(|| ExplainabilityError::DecisionNotFound(example_id.to_string()))
    }

    fn list_counterfactuals_for_prediction(&self, prediction_id: &str) -> Vec<&StoredCounterfactualExample> {
        self.counterfactuals.values()
            .filter(|c| c.prediction_id == prediction_id)
            .collect()
    }

    fn store_rule_firing_record(&mut self, record: StoredRuleFiringRecord) -> Result<(), ExplainabilityError> {
        self.rule_firings.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_rule_firing_record(&self, record_id: &str) -> Result<StoredRuleFiringRecord, ExplainabilityError> {
        self.rule_firings.get(record_id).cloned()
            .ok_or_else(|| ExplainabilityError::DecisionNotFound(record_id.to_string()))
    }

    fn list_rule_firings_for_decision(&self, decision_id: &str) -> Vec<&StoredRuleFiringRecord> {
        self.rule_firings.values()
            .filter(|r| r.decision_id == decision_id)
            .collect()
    }

    fn flush(&mut self) {
        self.explanations.clear();
        self.reasoning_traces.clear();
        self.attribution_sets.clear();
        self.counterfactuals.clear();
        self.rule_firings.clear();
    }

    fn backend_info(&self) -> ExplanationBackendInfo {
        ExplanationBackendInfo {
            backend_name: "InMemoryExplanationBackend".to_string(),
            explanation_count: self.explanations.len(),
            reasoning_trace_count: self.reasoning_traces.len(),
            feature_attribution_set_count: self.attribution_sets.len(),
            counterfactual_count: self.counterfactuals.len(),
            rule_firing_count: self.rule_firings.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_explanation() -> StoredExplanation {
        StoredExplanation {
            explanation_id: "exp-1".to_string(),
            subject_id_ref: SubjectIdRef::new("prediction-42"),
            explanation_type: ExplanationType::FeatureAttribution,
            confidence_score: "0.85".to_string(),
            generated_at: 1000,
            explanation_body_bytes: b"{}".to_vec(),
            generator_id: "shap-explainer".to_string(),
        }
    }

    fn sample_trace() -> StoredReasoningTrace {
        StoredReasoningTrace {
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            steps: vec![StoredReasoningStep {
                step_id: "step-1".to_string(),
                step_number: 0,
                step_type: "Premise".to_string(),
                description: "User is authenticated".to_string(),
                inputs: HashMap::new(),
                outputs: HashMap::new(),
                executed_at: 1000,
            }],
            conclusion: Some("Access granted".to_string()),
            started_at: 1000,
            completed_at: Some(1050),
        }
    }

    #[test]
    fn test_store_and_retrieve_explanation() {
        let mut backend = InMemoryExplanationBackend::new();
        backend.store_explanation(sample_explanation()).unwrap();
        let retrieved = backend.retrieve_explanation("exp-1").unwrap();
        assert_eq!(retrieved.explanation_id, "exp-1");
        assert_eq!(retrieved.confidence_score, "0.85");
        assert_eq!(backend.explanation_count(), 1);
    }

    #[test]
    fn test_delete_explanation() {
        let mut backend = InMemoryExplanationBackend::new();
        backend.store_explanation(sample_explanation()).unwrap();
        backend.delete_explanation("exp-1").unwrap();
        assert_eq!(backend.explanation_count(), 0);
        assert!(backend.delete_explanation("exp-1").is_err());
    }

    #[test]
    fn test_list_explanations_for_subject() {
        let mut backend = InMemoryExplanationBackend::new();
        backend.store_explanation(sample_explanation()).unwrap();
        let mut exp2 = sample_explanation();
        exp2.explanation_id = "exp-2".to_string();
        backend.store_explanation(exp2).unwrap();
        let results = backend.list_explanations_for_subject_id(&SubjectIdRef::new("prediction-42"));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_reasoning_trace() {
        let mut backend = InMemoryExplanationBackend::new();
        backend.store_reasoning_trace(sample_trace()).unwrap();
        let retrieved = backend.retrieve_reasoning_trace("trace-1").unwrap();
        assert_eq!(retrieved.steps.len(), 1);
        assert_eq!(retrieved.conclusion.as_deref(), Some("Access granted"));
    }

    #[test]
    fn test_list_reasoning_traces_for_decision() {
        let mut backend = InMemoryExplanationBackend::new();
        backend.store_reasoning_trace(sample_trace()).unwrap();
        let results = backend.list_reasoning_traces_for_decision("decision-1");
        assert_eq!(results.len(), 1);
        assert!(backend.list_reasoning_traces_for_decision("other").is_empty());
    }

    #[test]
    fn test_store_and_retrieve_attribution_set() {
        let mut backend = InMemoryExplanationBackend::new();
        let set = StoredFeatureAttributionSet {
            attribution_set_id: "as-1".to_string(),
            prediction_id: "pred-1".to_string(),
            method: "shap".to_string(),
            attributions_json: "[]".to_string(),
            computed_at: 1000,
        };
        backend.store_feature_attribution_set(set).unwrap();
        let retrieved = backend.retrieve_feature_attribution_set("as-1").unwrap();
        assert_eq!(retrieved.method, "shap");
    }

    #[test]
    fn test_list_attribution_sets_for_prediction() {
        let mut backend = InMemoryExplanationBackend::new();
        let set = StoredFeatureAttributionSet {
            attribution_set_id: "as-1".to_string(),
            prediction_id: "pred-1".to_string(),
            method: "shap".to_string(),
            attributions_json: "[]".to_string(),
            computed_at: 1000,
        };
        backend.store_feature_attribution_set(set).unwrap();
        assert_eq!(backend.list_feature_attribution_sets_for_prediction("pred-1").len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_counterfactual() {
        let mut backend = InMemoryExplanationBackend::new();
        let cf = StoredCounterfactualExample {
            example_id: "cf-1".to_string(),
            prediction_id: "pred-1".to_string(),
            resulting_outcome: "approved".to_string(),
            distance_from_original: "0.15".to_string(),
            generated_at: 1000,
            original_input_json: "{}".to_string(),
            modified_input_json: "{}".to_string(),
        };
        backend.store_counterfactual_example(cf).unwrap();
        let retrieved = backend.retrieve_counterfactual_example("cf-1").unwrap();
        assert_eq!(retrieved.resulting_outcome, "approved");
    }

    #[test]
    fn test_list_counterfactuals_for_prediction() {
        let mut backend = InMemoryExplanationBackend::new();
        let cf = StoredCounterfactualExample {
            example_id: "cf-1".to_string(),
            prediction_id: "pred-1".to_string(),
            resulting_outcome: "approved".to_string(),
            distance_from_original: "0.15".to_string(),
            generated_at: 1000,
            original_input_json: "{}".to_string(),
            modified_input_json: "{}".to_string(),
        };
        backend.store_counterfactual_example(cf).unwrap();
        assert_eq!(backend.list_counterfactuals_for_prediction("pred-1").len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_rule_firing() {
        let mut backend = InMemoryExplanationBackend::new();
        let record = StoredRuleFiringRecord {
            record_id: "rf-1".to_string(),
            decision_id: "d-1".to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "deny-unauth".to_string(),
            matched: true,
            priority: 10,
            fired_at: 1000,
            inputs: HashMap::new(),
            outputs: HashMap::new(),
        };
        backend.store_rule_firing_record(record).unwrap();
        let retrieved = backend.retrieve_rule_firing_record("rf-1").unwrap();
        assert_eq!(retrieved.rule_name, "deny-unauth");
        assert!(retrieved.matched);
    }

    #[test]
    fn test_list_rule_firings_for_decision() {
        let mut backend = InMemoryExplanationBackend::new();
        let record = StoredRuleFiringRecord {
            record_id: "rf-1".to_string(),
            decision_id: "d-1".to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "deny-unauth".to_string(),
            matched: true,
            priority: 10,
            fired_at: 1000,
            inputs: HashMap::new(),
            outputs: HashMap::new(),
        };
        backend.store_rule_firing_record(record).unwrap();
        assert_eq!(backend.list_rule_firings_for_decision("d-1").len(), 1);
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryExplanationBackend::new();
        backend.store_explanation(sample_explanation()).unwrap();
        backend.store_reasoning_trace(sample_trace()).unwrap();
        backend.flush();
        assert_eq!(backend.explanation_count(), 0);
        assert!(backend.retrieve_reasoning_trace("trace-1").is_err());
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryExplanationBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_name, "InMemoryExplanationBackend");
        assert_eq!(info.explanation_count, 0);
    }

    #[test]
    fn test_subject_id_ref() {
        let ref1 = SubjectIdRef::new("pred-42");
        assert_eq!(ref1.as_str(), "pred-42");
        assert_eq!(ref1.to_string(), "pred-42");
        let ref2: SubjectIdRef = "pred-42".into();
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn test_explanation_type_display() {
        assert_eq!(ExplanationType::FeatureAttribution.to_string(), "feature-attribution");
        assert_eq!(ExplanationType::RuleBased.to_string(), "rule-based");
        assert_eq!(ExplanationType::Counterfactual.to_string(), "counterfactual");
        assert_eq!(ExplanationType::DecisionTrace.to_string(), "decision-trace");
        assert_eq!(ExplanationType::NaturalLanguage.to_string(), "natural-language");
    }
}
