// ═══════════════════════════════════════════════════════════════════════
// Counterfactual Example Generator — Trait for generating "what-if"
// scenarios that show how input changes would alter predictions.
//
// This module is named `counterfactual_example` to avoid collision with
// the L1 `counterfactual` module.  The trait is named
// `CounterfactualExampleGenerator` to avoid collision with the L1
// `CounterfactualGenerator` struct.
//
// ActionableChange.constrained surfaces whether a suggested change
// involves an immutable attribute (e.g. age, protected characteristics)
// — critical for fair lending and hiring contexts where certain
// features cannot ethically be recommended as actionable.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::ExplainabilityError;

// ── ChangeDirection ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChangeDirection {
    IncreaseRequired,
    DecreaseRequired,
    DiscreteChangeRequired,
}

impl fmt::Display for ChangeDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncreaseRequired => write!(f, "increase-required"),
            Self::DecreaseRequired => write!(f, "decrease-required"),
            Self::DiscreteChangeRequired => write!(f, "discrete-change-required"),
        }
    }
}

// ── ActionableChange ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionableChange {
    pub feature_name: String,
    pub original_value: String,
    pub suggested_value: String,
    pub change_direction: ChangeDirection,
    pub constrained: bool,
}

impl ActionableChange {
    pub fn new(
        feature_name: &str,
        original_value: &str,
        suggested_value: &str,
        change_direction: ChangeDirection,
        constrained: bool,
    ) -> Self {
        Self {
            feature_name: feature_name.to_string(),
            original_value: original_value.to_string(),
            suggested_value: suggested_value.to_string(),
            change_direction,
            constrained,
        }
    }
}

// ── CounterfactualExample ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterfactualExample {
    pub example_id: String,
    pub prediction_id: String,
    pub original_input_summary: HashMap<String, String>,
    pub modified_input_summary: HashMap<String, String>,
    pub resulting_outcome: String,
    pub distance_from_original: String,
    pub actionable_changes: Vec<ActionableChange>,
    pub generated_at: i64,
}

// ── CounterfactualExampleGenerator trait ────────────────────────

pub trait CounterfactualExampleGenerator {
    fn generate_counterfactuals(
        &self,
        prediction_id: &str,
        original_input: &HashMap<String, String>,
        desired_outcome: &str,
    ) -> Result<Vec<CounterfactualExample>, ExplainabilityError>;

    fn generator_id(&self) -> &str;
    fn supports_target_outcome(&self, outcome: &str) -> bool;
    fn is_active(&self) -> bool;
}

// ── NearestNeighborCounterfactualGenerator ─────────────────────

pub struct NearestNeighborCounterfactualGenerator {
    id: String,
    known_examples: Vec<(HashMap<String, String>, String)>,
    next_example_id: std::cell::Cell<usize>,
}

impl NearestNeighborCounterfactualGenerator {
    pub fn new(id: &str, known_examples: Vec<(HashMap<String, String>, String)>) -> Self {
        Self {
            id: id.to_string(),
            known_examples,
            next_example_id: std::cell::Cell::new(0),
        }
    }

    fn distance(a: &HashMap<String, String>, b: &HashMap<String, String>) -> f64 {
        let mut sum = 0.0;
        for (key, val_a) in a {
            if let Some(val_b) = b.get(key) {
                let na: f64 = val_a.parse().unwrap_or(0.0);
                let nb: f64 = val_b.parse().unwrap_or(0.0);
                sum += (na - nb).powi(2);
            } else {
                sum += 1.0;
            }
        }
        sum.sqrt()
    }

    fn compute_changes(
        original: &HashMap<String, String>,
        modified: &HashMap<String, String>,
    ) -> Vec<ActionableChange> {
        let mut changes = Vec::new();
        for (key, orig_val) in original {
            if let Some(mod_val) = modified.get(key)
                && orig_val != mod_val
            {
                let orig_num: Option<f64> = orig_val.parse().ok();
                let mod_num: Option<f64> = mod_val.parse().ok();
                let direction = match (orig_num, mod_num) {
                    (Some(o), Some(m)) if m > o => ChangeDirection::IncreaseRequired,
                    (Some(o), Some(m)) if m < o => ChangeDirection::DecreaseRequired,
                    _ => ChangeDirection::DiscreteChangeRequired,
                };
                changes.push(ActionableChange {
                    feature_name: key.clone(),
                    original_value: orig_val.clone(),
                    suggested_value: mod_val.clone(),
                    change_direction: direction,
                    constrained: false,
                });
            }
        }
        changes.sort_by(|a, b| a.feature_name.cmp(&b.feature_name));
        changes
    }
}

impl CounterfactualExampleGenerator for NearestNeighborCounterfactualGenerator {
    fn generate_counterfactuals(
        &self,
        prediction_id: &str,
        original_input: &HashMap<String, String>,
        desired_outcome: &str,
    ) -> Result<Vec<CounterfactualExample>, ExplainabilityError> {
        let matching: Vec<_> = self.known_examples.iter()
            .filter(|(_, outcome)| outcome == desired_outcome)
            .collect();

        if matching.is_empty() {
            return Ok(Vec::new());
        }

        let mut scored: Vec<_> = matching.iter()
            .map(|(features, outcome)| {
                let dist = Self::distance(original_input, features);
                (features, outcome, dist)
            })
            .collect();
        scored.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());

        let mut results = Vec::new();
        for (features, outcome, dist) in scored.into_iter().take(3) {
            let eid = self.next_example_id.get();
            self.next_example_id.set(eid + 1);
            let changes = Self::compute_changes(original_input, features);
            results.push(CounterfactualExample {
                example_id: format!("nn-{eid}"),
                prediction_id: prediction_id.to_string(),
                original_input_summary: original_input.clone(),
                modified_input_summary: features.clone(),
                resulting_outcome: outcome.clone(),
                distance_from_original: format!("{dist}"),
                actionable_changes: changes,
                generated_at: 0,
            });
        }
        Ok(results)
    }

    fn generator_id(&self) -> &str { &self.id }
    fn supports_target_outcome(&self, outcome: &str) -> bool {
        self.known_examples.iter().any(|(_, o)| o == outcome)
    }
    fn is_active(&self) -> bool { true }
}

// ── FeaturePerturbationCounterfactualGenerator ─────────────────

pub struct FeaturePerturbationCounterfactualGenerator {
    id: String,
    perturbation_delta: String,
    next_example_id: std::cell::Cell<usize>,
}

impl FeaturePerturbationCounterfactualGenerator {
    pub fn new(id: &str, perturbation_delta: &str) -> Self {
        Self {
            id: id.to_string(),
            perturbation_delta: perturbation_delta.to_string(),
            next_example_id: std::cell::Cell::new(0),
        }
    }
}

impl CounterfactualExampleGenerator for FeaturePerturbationCounterfactualGenerator {
    fn generate_counterfactuals(
        &self,
        prediction_id: &str,
        original_input: &HashMap<String, String>,
        desired_outcome: &str,
    ) -> Result<Vec<CounterfactualExample>, ExplainabilityError> {
        let delta: f64 = self.perturbation_delta.parse().unwrap_or(1.0);
        let mut results = Vec::new();

        for (feature, value_str) in original_input {
            let value: f64 = match value_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let perturbed = value + delta;
            let mut modified = original_input.clone();
            modified.insert(feature.clone(), format!("{perturbed}"));

            let direction = if delta > 0.0 {
                ChangeDirection::IncreaseRequired
            } else {
                ChangeDirection::DecreaseRequired
            };

            let eid = self.next_example_id.get();
            self.next_example_id.set(eid + 1);

            let dist = delta.abs();
            results.push(CounterfactualExample {
                example_id: format!("fp-{eid}"),
                prediction_id: prediction_id.to_string(),
                original_input_summary: original_input.clone(),
                modified_input_summary: modified,
                resulting_outcome: desired_outcome.to_string(),
                distance_from_original: format!("{dist}"),
                actionable_changes: vec![ActionableChange {
                    feature_name: feature.clone(),
                    original_value: value_str.clone(),
                    suggested_value: format!("{perturbed}"),
                    change_direction: direction,
                    constrained: false,
                }],
                generated_at: 0,
            });
        }

        results.sort_by(|a, b| {
            a.actionable_changes.first().map(|c| &c.feature_name)
                .cmp(&b.actionable_changes.first().map(|c| &c.feature_name))
        });
        Ok(results)
    }

    fn generator_id(&self) -> &str { &self.id }
    fn supports_target_outcome(&self, _outcome: &str) -> bool { true }
    fn is_active(&self) -> bool { true }
}

// ── NullCounterfactualGenerator ────────────────────────────────

pub struct NullCounterfactualExampleGenerator {
    id: String,
}

impl NullCounterfactualExampleGenerator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl CounterfactualExampleGenerator for NullCounterfactualExampleGenerator {
    fn generate_counterfactuals(
        &self,
        _prediction_id: &str,
        _original_input: &HashMap<String, String>,
        _desired_outcome: &str,
    ) -> Result<Vec<CounterfactualExample>, ExplainabilityError> {
        Ok(Vec::new())
    }

    fn generator_id(&self) -> &str { &self.id }
    fn supports_target_outcome(&self, _outcome: &str) -> bool { false }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_direction_display() {
        assert_eq!(ChangeDirection::IncreaseRequired.to_string(), "increase-required");
        assert_eq!(ChangeDirection::DecreaseRequired.to_string(), "decrease-required");
        assert_eq!(ChangeDirection::DiscreteChangeRequired.to_string(), "discrete-change-required");
    }

    #[test]
    fn test_actionable_change_constrained() {
        let change = ActionableChange::new("age", "25", "35", ChangeDirection::IncreaseRequired, true);
        assert!(change.constrained);
        assert_eq!(change.feature_name, "age");
    }

    #[test]
    fn test_nearest_neighbor_generator() {
        let examples = vec![
            (HashMap::from([("income".into(), "80000".into()), ("age".into(), "40".into())]), "approved".to_string()),
            (HashMap::from([("income".into(), "90000".into()), ("age".into(), "35".into())]), "approved".to_string()),
        ];
        let generator = NearestNeighborCounterfactualGenerator::new("nn-1", examples);

        let input = HashMap::from([("income".into(), "50000".into()), ("age".into(), "30".into())]);
        let results = generator.generate_counterfactuals("pred-1", &input, "approved").unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].prediction_id, "pred-1");
        assert!(!results[0].actionable_changes.is_empty());
    }

    #[test]
    fn test_nearest_neighbor_no_match() {
        let examples = vec![
            (HashMap::from([("income".into(), "80000".into())]), "approved".to_string()),
        ];
        let generator = NearestNeighborCounterfactualGenerator::new("nn-1", examples);
        let input = HashMap::from([("income".into(), "50000".into())]);
        let results = generator.generate_counterfactuals("pred-1", &input, "denied").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_nearest_neighbor_supports_outcome() {
        let examples = vec![
            (HashMap::new(), "approved".to_string()),
        ];
        let generator = NearestNeighborCounterfactualGenerator::new("nn-1", examples);
        assert!(generator.supports_target_outcome("approved"));
        assert!(!generator.supports_target_outcome("denied"));
    }

    #[test]
    fn test_feature_perturbation_generator() {
        let generator = FeaturePerturbationCounterfactualGenerator::new("fp-1", "10.0");
        let input = HashMap::from([
            ("income".into(), "50000".into()),
            ("score".into(), "700".into()),
        ]);
        let results = generator.generate_counterfactuals("pred-1", &input, "approved").unwrap();
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.actionable_changes.len(), 1);
            assert_eq!(r.actionable_changes[0].change_direction, ChangeDirection::IncreaseRequired);
        }
    }

    #[test]
    fn test_feature_perturbation_skips_non_numeric() {
        let generator = FeaturePerturbationCounterfactualGenerator::new("fp-1", "5.0");
        let input = HashMap::from([
            ("category".into(), "A".into()),
            ("score".into(), "100".into()),
        ]);
        let results = generator.generate_counterfactuals("pred-1", &input, "approved").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actionable_changes[0].feature_name, "score");
    }

    #[test]
    fn test_null_counterfactual_generator() {
        let generator = NullCounterfactualExampleGenerator::new("null-1");
        let results = generator.generate_counterfactuals("pred-1", &HashMap::new(), "any").unwrap();
        assert!(results.is_empty());
        assert!(!generator.is_active());
        assert!(!generator.supports_target_outcome("any"));
    }

    #[test]
    fn test_generator_ids() {
        let nn = NearestNeighborCounterfactualGenerator::new("nn-1", Vec::new());
        assert_eq!(nn.generator_id(), "nn-1");
        assert!(nn.is_active());

        let fp = FeaturePerturbationCounterfactualGenerator::new("fp-1", "1.0");
        assert_eq!(fp.generator_id(), "fp-1");
        assert!(fp.is_active());
    }
}
