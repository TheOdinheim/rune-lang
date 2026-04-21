// ═══════════════════════════════════════════════════════════════════════
// Feature Attribution Explainer — Trait for computing per-feature
// attributions for statistical and ML model predictions.
//
// SHAP, LIME, and integrated gradients are the dominant industry
// techniques.  This trait defines the contract without implementing
// them — actual SHAP or LIME computation requires substantial
// dependencies (optimization solvers, sampling infrastructure) that
// belong in adapter crates.
//
// ExplainerAttributionMethod is distinct from the L2 AttributionMethod
// in attribution.rs.  L2's enum is for scoring/analysis; L3's enum
// names specific ML explainability techniques.
//
// FeatureAttributionRecord is distinct from the L2 FeatureAttribution
// in attribution.rs.  FeatureAttributionRecord uses String values
// for Eq derivation, matching the pattern across all RUNE backends.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::ExplainabilityError;

// ── ExplainerAttributionMethod ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExplainerAttributionMethod {
    Shap,
    Lime,
    IntegratedGradients,
    GradCam,
    PermutationImportance,
    LinearCoefficients,
    TreeSplit,
    Custom { method_name: String },
}

impl fmt::Display for ExplainerAttributionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shap => write!(f, "SHAP"),
            Self::Lime => write!(f, "LIME"),
            Self::IntegratedGradients => write!(f, "integrated-gradients"),
            Self::GradCam => write!(f, "Grad-CAM"),
            Self::PermutationImportance => write!(f, "permutation-importance"),
            Self::LinearCoefficients => write!(f, "linear-coefficients"),
            Self::TreeSplit => write!(f, "tree-split"),
            Self::Custom { method_name } => write!(f, "custom({method_name})"),
        }
    }
}

// ── AttributionValueDirection ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributionValueDirection {
    Positive,
    Negative,
    Neutral,
}

impl fmt::Display for AttributionValueDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Positive => write!(f, "positive"),
            Self::Negative => write!(f, "negative"),
            Self::Neutral => write!(f, "neutral"),
        }
    }
}

// ── FeatureAttributionRecord ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureAttributionRecord {
    pub feature_name: String,
    pub attribution_value: String,
    pub confidence: String,
    pub direction: AttributionValueDirection,
}

impl FeatureAttributionRecord {
    pub fn new(feature_name: &str, attribution_value: &str, confidence: &str, direction: AttributionValueDirection) -> Self {
        Self {
            feature_name: feature_name.to_string(),
            attribution_value: attribution_value.to_string(),
            confidence: confidence.to_string(),
            direction,
        }
    }
}

// ── FeatureAttributionSet ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainerFeatureAttributionSet {
    pub attribution_set_id: String,
    pub prediction_id: String,
    pub method: ExplainerAttributionMethod,
    pub attributions: Vec<FeatureAttributionRecord>,
    pub baseline: Option<HashMap<String, String>>,
    pub computed_at: i64,
}

// ── FeatureAttributionExplainer trait ───────────────────────────

pub trait FeatureAttributionExplainer {
    fn compute_attributions(
        &self,
        prediction_id: &str,
        input_features: &HashMap<String, String>,
        model_output: &str,
    ) -> Result<ExplainerFeatureAttributionSet, ExplainabilityError>;

    fn supported_attribution_methods(&self) -> Vec<ExplainerAttributionMethod>;
    fn attribution_method_used(&self) -> ExplainerAttributionMethod;
    fn explainer_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── LinearCoefficientExplainer ──────────────────────────────────

pub struct LinearCoefficientExplainer {
    id: String,
    coefficients: HashMap<String, f64>,
    next_set_id: std::cell::Cell<usize>,
}

impl LinearCoefficientExplainer {
    pub fn new(id: &str, coefficients: HashMap<String, f64>) -> Self {
        Self {
            id: id.to_string(),
            coefficients,
            next_set_id: std::cell::Cell::new(0),
        }
    }
}

impl FeatureAttributionExplainer for LinearCoefficientExplainer {
    fn compute_attributions(
        &self,
        prediction_id: &str,
        input_features: &HashMap<String, String>,
        _model_output: &str,
    ) -> Result<ExplainerFeatureAttributionSet, ExplainabilityError> {
        let set_id = {
            let id = self.next_set_id.get();
            self.next_set_id.set(id + 1);
            format!("lc-{id}")
        };
        let mut attributions = Vec::new();
        for (feature, value_str) in input_features {
            let value: f64 = value_str.parse().unwrap_or(0.0);
            let coeff = self.coefficients.get(feature).copied().unwrap_or(0.0);
            let attribution = coeff * value;
            let direction = if attribution > 0.0 {
                AttributionValueDirection::Positive
            } else if attribution < 0.0 {
                AttributionValueDirection::Negative
            } else {
                AttributionValueDirection::Neutral
            };
            attributions.push(FeatureAttributionRecord {
                feature_name: feature.clone(),
                attribution_value: format!("{attribution}"),
                confidence: "1.0".to_string(),
                direction,
            });
        }
        attributions.sort_by(|a, b| {
            let va: f64 = a.attribution_value.parse().unwrap_or(0.0);
            let vb: f64 = b.attribution_value.parse().unwrap_or(0.0);
            vb.abs().partial_cmp(&va.abs()).unwrap()
        });
        Ok(ExplainerFeatureAttributionSet {
            attribution_set_id: set_id,
            prediction_id: prediction_id.to_string(),
            method: ExplainerAttributionMethod::LinearCoefficients,
            attributions,
            baseline: None,
            computed_at: 0,
        })
    }

    fn supported_attribution_methods(&self) -> Vec<ExplainerAttributionMethod> {
        vec![ExplainerAttributionMethod::LinearCoefficients]
    }

    fn attribution_method_used(&self) -> ExplainerAttributionMethod {
        ExplainerAttributionMethod::LinearCoefficients
    }

    fn explainer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── PermutationImportanceExplainer ──────────────────────────────

pub struct PermutationImportanceExplainer {
    id: String,
    baseline_output: String,
    next_set_id: std::cell::Cell<usize>,
}

impl PermutationImportanceExplainer {
    pub fn new(id: &str, baseline_output: &str) -> Self {
        Self {
            id: id.to_string(),
            baseline_output: baseline_output.to_string(),
            next_set_id: std::cell::Cell::new(0),
        }
    }
}

impl FeatureAttributionExplainer for PermutationImportanceExplainer {
    fn compute_attributions(
        &self,
        prediction_id: &str,
        input_features: &HashMap<String, String>,
        model_output: &str,
    ) -> Result<ExplainerFeatureAttributionSet, ExplainabilityError> {
        let set_id = {
            let id = self.next_set_id.get();
            self.next_set_id.set(id + 1);
            format!("pi-{id}")
        };
        let output_val: f64 = model_output.parse().unwrap_or(0.0);
        let baseline_val: f64 = self.baseline_output.parse().unwrap_or(0.0);
        let diff = output_val - baseline_val;
        let feature_count = input_features.len().max(1) as f64;
        let per_feature = diff / feature_count;

        let mut attributions: Vec<FeatureAttributionRecord> = input_features.keys().map(|feature| {
            let direction = if per_feature > 0.0 {
                AttributionValueDirection::Positive
            } else if per_feature < 0.0 {
                AttributionValueDirection::Negative
            } else {
                AttributionValueDirection::Neutral
            };
            FeatureAttributionRecord {
                feature_name: feature.clone(),
                attribution_value: format!("{per_feature}"),
                confidence: "0.5".to_string(),
                direction,
            }
        }).collect();
        attributions.sort_by(|a, b| a.feature_name.cmp(&b.feature_name));

        Ok(ExplainerFeatureAttributionSet {
            attribution_set_id: set_id,
            prediction_id: prediction_id.to_string(),
            method: ExplainerAttributionMethod::PermutationImportance,
            attributions,
            baseline: Some(HashMap::from([("baseline_output".to_string(), self.baseline_output.clone())])),
            computed_at: 0,
        })
    }

    fn supported_attribution_methods(&self) -> Vec<ExplainerAttributionMethod> {
        vec![ExplainerAttributionMethod::PermutationImportance]
    }

    fn attribution_method_used(&self) -> ExplainerAttributionMethod {
        ExplainerAttributionMethod::PermutationImportance
    }

    fn explainer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullFeatureAttributionExplainer ─────────────────────────────

pub struct NullFeatureAttributionExplainer {
    id: String,
}

impl NullFeatureAttributionExplainer {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl FeatureAttributionExplainer for NullFeatureAttributionExplainer {
    fn compute_attributions(
        &self,
        prediction_id: &str,
        _input_features: &HashMap<String, String>,
        _model_output: &str,
    ) -> Result<ExplainerFeatureAttributionSet, ExplainabilityError> {
        Ok(ExplainerFeatureAttributionSet {
            attribution_set_id: "null-0".to_string(),
            prediction_id: prediction_id.to_string(),
            method: ExplainerAttributionMethod::LinearCoefficients,
            attributions: Vec::new(),
            baseline: None,
            computed_at: 0,
        })
    }

    fn supported_attribution_methods(&self) -> Vec<ExplainerAttributionMethod> {
        vec![]
    }

    fn attribution_method_used(&self) -> ExplainerAttributionMethod {
        ExplainerAttributionMethod::LinearCoefficients
    }

    fn explainer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explainer_attribution_method_display() {
        assert_eq!(ExplainerAttributionMethod::Shap.to_string(), "SHAP");
        assert_eq!(ExplainerAttributionMethod::Lime.to_string(), "LIME");
        assert_eq!(ExplainerAttributionMethod::IntegratedGradients.to_string(), "integrated-gradients");
        assert_eq!(ExplainerAttributionMethod::GradCam.to_string(), "Grad-CAM");
        assert_eq!(ExplainerAttributionMethod::PermutationImportance.to_string(), "permutation-importance");
        assert_eq!(ExplainerAttributionMethod::LinearCoefficients.to_string(), "linear-coefficients");
        assert_eq!(ExplainerAttributionMethod::TreeSplit.to_string(), "tree-split");
        assert_eq!(ExplainerAttributionMethod::Custom { method_name: "my-method".into() }.to_string(), "custom(my-method)");
    }

    #[test]
    fn test_attribution_value_direction_display() {
        assert_eq!(AttributionValueDirection::Positive.to_string(), "positive");
        assert_eq!(AttributionValueDirection::Negative.to_string(), "negative");
        assert_eq!(AttributionValueDirection::Neutral.to_string(), "neutral");
    }

    #[test]
    fn test_linear_coefficient_explainer() {
        let coefficients = HashMap::from([
            ("income".to_string(), 0.5),
            ("age".to_string(), -0.2),
        ]);
        let explainer = LinearCoefficientExplainer::new("lc-1", coefficients);
        let features = HashMap::from([
            ("income".to_string(), "50000".to_string()),
            ("age".to_string(), "30".to_string()),
        ]);
        let result = explainer.compute_attributions("pred-1", &features, "0.8").unwrap();
        assert_eq!(result.prediction_id, "pred-1");
        assert_eq!(result.method, ExplainerAttributionMethod::LinearCoefficients);
        assert_eq!(result.attributions.len(), 2);
        // Income: 0.5 * 50000 = 25000 (positive)
        let income_attr = result.attributions.iter().find(|a| a.feature_name == "income").unwrap();
        assert_eq!(income_attr.direction, AttributionValueDirection::Positive);
        // Age: -0.2 * 30 = -6 (negative)
        let age_attr = result.attributions.iter().find(|a| a.feature_name == "age").unwrap();
        assert_eq!(age_attr.direction, AttributionValueDirection::Negative);
    }

    #[test]
    fn test_linear_coefficient_sorted_by_magnitude() {
        let coefficients = HashMap::from([
            ("a".to_string(), 0.1),
            ("b".to_string(), 10.0),
        ]);
        let explainer = LinearCoefficientExplainer::new("lc-1", coefficients);
        let features = HashMap::from([
            ("a".to_string(), "1.0".to_string()),
            ("b".to_string(), "1.0".to_string()),
        ]);
        let result = explainer.compute_attributions("p1", &features, "0").unwrap();
        assert_eq!(result.attributions[0].feature_name, "b");
    }

    #[test]
    fn test_permutation_importance_explainer() {
        let explainer = PermutationImportanceExplainer::new("pi-1", "0.5");
        let features = HashMap::from([
            ("income".to_string(), "50000".to_string()),
            ("age".to_string(), "30".to_string()),
        ]);
        let result = explainer.compute_attributions("pred-1", &features, "0.8").unwrap();
        assert_eq!(result.method, ExplainerAttributionMethod::PermutationImportance);
        assert_eq!(result.attributions.len(), 2);
        assert!(result.baseline.is_some());
    }

    #[test]
    fn test_null_explainer() {
        let explainer = NullFeatureAttributionExplainer::new("null-1");
        let features = HashMap::new();
        let result = explainer.compute_attributions("pred-1", &features, "0").unwrap();
        assert!(result.attributions.is_empty());
        assert!(!explainer.is_active());
        assert!(explainer.supported_attribution_methods().is_empty());
    }

    #[test]
    fn test_explainer_ids() {
        let lc = LinearCoefficientExplainer::new("lc-1", HashMap::new());
        assert_eq!(lc.explainer_id(), "lc-1");
        assert!(lc.is_active());
        assert_eq!(lc.supported_attribution_methods(), vec![ExplainerAttributionMethod::LinearCoefficients]);

        let pi = PermutationImportanceExplainer::new("pi-1", "0");
        assert_eq!(pi.explainer_id(), "pi-1");
        assert_eq!(pi.attribution_method_used(), ExplainerAttributionMethod::PermutationImportance);
    }

    #[test]
    fn test_feature_attribution_record_new() {
        let record = FeatureAttributionRecord::new("income", "25000.0", "0.95", AttributionValueDirection::Positive);
        assert_eq!(record.feature_name, "income");
        assert_eq!(record.attribution_value, "25000.0");
        assert_eq!(record.confidence, "0.95");
    }
}
