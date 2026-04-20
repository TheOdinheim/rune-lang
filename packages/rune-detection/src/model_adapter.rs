// ═══════════════════════════════════════════════════════════════════════
// Model Adapter — Detection model invocation trait.
//
// Layer 3 defines the contract for plugging detection models into
// the sensing pipeline. Models have inference-time semantics distinct
// from storage — they load, predict, and unload. RUNE provides the
// shaped hole; the customer provides the model implementation.
//
// This does NOT add ML framework integration (ONNX, TensorFlow,
// PyTorch) — those belong in downstream adapter crates. The trait
// defines the shape of model invocation, not the implementation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::DetectionError;

// ── PredictionResult ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PredictionResult {
    pub score: f64,
    pub confidence: f64,
    pub explanation: String,
    pub metadata: HashMap<String, String>,
}

impl PredictionResult {
    pub fn new(score: f64, confidence: f64, explanation: &str) -> Self {
        Self {
            score,
            confidence,
            explanation: explanation.to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn is_anomalous(&self, threshold: f64) -> bool {
        self.score > threshold
    }
}

// ── ModelInfo ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub model_id: String,
    pub architecture: String,
    pub input_shape: Vec<usize>,
    pub output_shape: Vec<usize>,
    pub attestation_hash: String,
    pub loaded_at: i64,
}

// ── DetectionModelAdapter trait ──────────────────────────────────

pub trait DetectionModelAdapter {
    fn load_model(&mut self, model_id: &str, data: &[u8]) -> Result<(), DetectionError>;
    fn predict(&self, features: &[f64]) -> Result<PredictionResult, DetectionError>;
    fn batch_predict(&self, batch: &[Vec<f64>]) -> Result<Vec<PredictionResult>, DetectionError>;
    fn model_info(&self) -> Option<&ModelInfo>;
    fn is_loaded(&self) -> bool;
    fn unload(&mut self);
}

// ── NullDetectionModel ──────────────────────────────────────────

/// Always returns zero score. Used for testing the trait interface.
pub struct NullDetectionModel {
    info: Option<ModelInfo>,
}

impl NullDetectionModel {
    pub fn new() -> Self {
        Self { info: None }
    }
}

impl Default for NullDetectionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionModelAdapter for NullDetectionModel {
    fn load_model(&mut self, model_id: &str, data: &[u8]) -> Result<(), DetectionError> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        self.info = Some(ModelInfo {
            model_id: model_id.to_string(),
            architecture: "null".to_string(),
            input_shape: vec![0],
            output_shape: vec![1],
            attestation_hash: hash,
            loaded_at: 0,
        });
        Ok(())
    }

    fn predict(&self, _features: &[f64]) -> Result<PredictionResult, DetectionError> {
        if !self.is_loaded() {
            return Err(DetectionError::InvalidOperation("model not loaded".into()));
        }
        Ok(PredictionResult::new(0.0, 1.0, "null model: always zero"))
    }

    fn batch_predict(&self, batch: &[Vec<f64>]) -> Result<Vec<PredictionResult>, DetectionError> {
        batch.iter().map(|f| self.predict(f)).collect()
    }

    fn model_info(&self) -> Option<&ModelInfo> {
        self.info.as_ref()
    }

    fn is_loaded(&self) -> bool {
        self.info.is_some()
    }

    fn unload(&mut self) {
        self.info = None;
    }
}

// ── RulesOnlyModel ──────────────────────────────────────────────

/// Deterministic baseline that applies a threshold rule and returns
/// a binary score (0.0 or 1.0).
pub struct RulesOnlyModel {
    threshold: f64,
    feature_index: usize,
    info: Option<ModelInfo>,
}

impl RulesOnlyModel {
    pub fn new(threshold: f64, feature_index: usize) -> Self {
        Self {
            threshold,
            feature_index,
            info: None,
        }
    }
}

impl DetectionModelAdapter for RulesOnlyModel {
    fn load_model(&mut self, model_id: &str, data: &[u8]) -> Result<(), DetectionError> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        self.info = Some(ModelInfo {
            model_id: model_id.to_string(),
            architecture: "rules-only".to_string(),
            input_shape: vec![self.feature_index + 1],
            output_shape: vec![1],
            attestation_hash: hash,
            loaded_at: 0,
        });
        Ok(())
    }

    fn predict(&self, features: &[f64]) -> Result<PredictionResult, DetectionError> {
        if !self.is_loaded() {
            return Err(DetectionError::InvalidOperation("model not loaded".into()));
        }
        if self.feature_index >= features.len() {
            return Err(DetectionError::InvalidSignal(format!(
                "feature index {} out of bounds (len={})",
                self.feature_index,
                features.len()
            )));
        }
        let value = features[self.feature_index];
        let score = if value > self.threshold { 1.0 } else { 0.0 };
        let confidence = if score > 0.0 {
            ((value - self.threshold) / self.threshold).min(1.0)
        } else {
            1.0
        };
        Ok(PredictionResult::new(
            score,
            confidence,
            &format!("threshold rule: feature[{}]={value:.3} vs {:.3}", self.feature_index, self.threshold),
        ))
    }

    fn batch_predict(&self, batch: &[Vec<f64>]) -> Result<Vec<PredictionResult>, DetectionError> {
        batch.iter().map(|f| self.predict(f)).collect()
    }

    fn model_info(&self) -> Option<&ModelInfo> {
        self.info.as_ref()
    }

    fn is_loaded(&self) -> bool {
        self.info.is_some()
    }

    fn unload(&mut self) {
        self.info = None;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_model_not_loaded() {
        let model = NullDetectionModel::new();
        assert!(!model.is_loaded());
        assert!(model.predict(&[1.0]).is_err());
    }

    #[test]
    fn test_null_model_load_and_predict() {
        let mut model = NullDetectionModel::new();
        model.load_model("test", b"model-bytes").unwrap();
        assert!(model.is_loaded());
        let r = model.predict(&[1.0, 2.0, 3.0]).unwrap();
        assert_eq!(r.score, 0.0);
        assert_eq!(r.confidence, 1.0);
    }

    #[test]
    fn test_null_model_attestation_hash() {
        let mut model = NullDetectionModel::new();
        model.load_model("test", b"bytes").unwrap();
        let info = model.model_info().unwrap();
        assert!(!info.attestation_hash.is_empty());
        assert_eq!(info.architecture, "null");
    }

    #[test]
    fn test_null_model_batch_predict() {
        let mut model = NullDetectionModel::new();
        model.load_model("test", b"data").unwrap();
        let results = model.batch_predict(&[vec![1.0], vec![2.0]]).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].score, 0.0);
    }

    #[test]
    fn test_null_model_unload() {
        let mut model = NullDetectionModel::new();
        model.load_model("test", b"data").unwrap();
        model.unload();
        assert!(!model.is_loaded());
        assert!(model.predict(&[1.0]).is_err());
    }

    #[test]
    fn test_rules_only_model_above_threshold() {
        let mut model = RulesOnlyModel::new(5.0, 0);
        model.load_model("rules", b"rule-data").unwrap();
        let r = model.predict(&[10.0]).unwrap();
        assert_eq!(r.score, 1.0);
        assert!(r.is_anomalous(0.5));
    }

    #[test]
    fn test_rules_only_model_below_threshold() {
        let mut model = RulesOnlyModel::new(5.0, 0);
        model.load_model("rules", b"rule-data").unwrap();
        let r = model.predict(&[3.0]).unwrap();
        assert_eq!(r.score, 0.0);
        assert!(!r.is_anomalous(0.5));
    }

    #[test]
    fn test_rules_only_model_feature_index() {
        let mut model = RulesOnlyModel::new(5.0, 2);
        model.load_model("rules", b"data").unwrap();
        let r = model.predict(&[1.0, 2.0, 10.0]).unwrap();
        assert_eq!(r.score, 1.0);
    }

    #[test]
    fn test_rules_only_model_out_of_bounds() {
        let mut model = RulesOnlyModel::new(5.0, 5);
        model.load_model("rules", b"data").unwrap();
        assert!(model.predict(&[1.0]).is_err());
    }

    #[test]
    fn test_prediction_result_metadata() {
        let r = PredictionResult::new(0.8, 0.9, "test");
        assert!(r.is_anomalous(0.5));
        assert!(!r.is_anomalous(0.9));
    }
}
