// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — AI governance metrics. Computes aggregate statistics
// over model records, dataset records, evaluation results, deployment
// records, fairness assessments, and drift detection results. All
// numeric values stored as String for Eq compatibility.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::bias_fairness::{FairnessAssessment, FairnessStatus};
use crate::deployment::DeploymentRecord;
use crate::drift::{DriftDetectionResult, DriftStatus};
use crate::evaluation::EvaluationResult;
use crate::model_registry::ModelRecord;
use crate::training_data::DatasetRecord;

// ── AiMetricSnapshot ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiMetricSnapshot {
    pub snapshot_id: String,
    pub computed_at: i64,
    pub total_models: String,
    pub total_datasets: String,
    pub evaluation_pass_rate: String,
    pub deployment_count: String,
    pub fairness_compliance_rate: String,
    pub drift_detection_rate: String,
    pub metadata: HashMap<String, String>,
}

// ── AiMetrics ───────────────────────────────────────────────────────

pub struct AiMetrics;

impl AiMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn compute_model_count_by_status(
        &self,
        records: &[ModelRecord],
    ) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in records {
            *counts.entry(r.status.to_string()).or_default() += 1;
        }
        counts
    }

    pub fn compute_dataset_count_by_quality(
        &self,
        records: &[DatasetRecord],
    ) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in records {
            *counts.entry(r.quality_status.to_string()).or_default() += 1;
        }
        counts
    }

    pub fn compute_evaluation_pass_rate(
        &self,
        results: &[EvaluationResult],
    ) -> String {
        if results.is_empty() {
            return "0.00".to_string();
        }
        let passed = results.iter().filter(|r| r.passed).count();
        let rate = passed as f64 / results.len() as f64;
        format!("{rate:.2}")
    }

    pub fn compute_deployment_count_by_environment(
        &self,
        records: &[DeploymentRecord],
    ) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in records {
            *counts.entry(r.environment.to_string()).or_default() += 1;
        }
        counts
    }

    pub fn compute_fairness_compliance_rate(
        &self,
        assessments: &[FairnessAssessment],
    ) -> String {
        if assessments.is_empty() {
            return "0.00".to_string();
        }
        let fair = assessments
            .iter()
            .filter(|a| a.overall_status == FairnessStatus::Fair)
            .count();
        let rate = fair as f64 / assessments.len() as f64;
        format!("{rate:.2}")
    }

    pub fn compute_drift_detection_rate(
        &self,
        results: &[DriftDetectionResult],
    ) -> String {
        if results.is_empty() {
            return "0.00".to_string();
        }
        let drifted = results
            .iter()
            .filter(|r| !matches!(r.overall_status, DriftStatus::NoDrift | DriftStatus::NotAssessed))
            .count();
        let rate = drifted as f64 / results.len() as f64;
        format!("{rate:.2}")
    }

    pub fn compute_model_age_distribution(
        &self,
        records: &[ModelRecord],
        current_timestamp: i64,
    ) -> HashMap<String, usize> {
        let mut buckets: HashMap<String, usize> = HashMap::new();
        for r in records {
            let age_ms = current_timestamp - r.created_at;
            let age_days = age_ms / 86_400_000;
            let bucket = if age_days < 30 {
                "0-30d"
            } else if age_days < 90 {
                "30-90d"
            } else if age_days < 180 {
                "90-180d"
            } else {
                "180d+"
            };
            *buckets.entry(bucket.to_string()).or_default() += 1;
        }
        buckets
    }
}

impl Default for AiMetrics {
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
    use crate::deployment::DeploymentEnvironment;
    use crate::model_registry::{ModelArchitecture, ModelStatus, ModelTaskType};
    use crate::training_data::{DataQualityStatus, DatasetFormat, DatasetSource};

    fn make_model(id: &str, status: ModelStatus, created_at: i64) -> ModelRecord {
        let mut r = ModelRecord::new(
            id, "name", "1.0",
            ModelArchitecture::Transformer,
            ModelTaskType::Classification,
            "pytorch", "alice", created_at,
        );
        r.status = status;
        r
    }

    fn make_dataset(id: &str, quality: DataQualityStatus) -> DatasetRecord {
        let mut r = DatasetRecord::new(
            id, "ds", "1.0",
            DatasetSource::Internal { team: "ml".into() },
            DatasetFormat::Csv,
            1000, "alice",
        );
        r.quality_status = quality;
        r
    }

    fn make_eval_result(id: &str, passed: bool) -> EvaluationResult {
        EvaluationResult::new(id, "m1", "1.0", "ec-1", "0.9", passed, 2000, "eval")
    }

    fn make_deployment(id: &str, env: DeploymentEnvironment) -> DeploymentRecord {
        DeploymentRecord::new(id, "req-1", "m1", "1.0", env, 1000, "deployer")
    }

    fn make_fairness(id: &str, status: FairnessStatus) -> FairnessAssessment {
        FairnessAssessment::new(id, "fp-1", "m1", "1.0", status, 2000, "engine")
    }

    fn make_drift(id: &str, status: DriftStatus) -> DriftDetectionResult {
        DriftDetectionResult::new(id, "dp-1", "m1", "1.0", status, 2000, 1000, 2000)
    }

    #[test]
    fn test_model_count_by_status() {
        let metrics = AiMetrics::new();
        let records = vec![
            make_model("m1", ModelStatus::Draft, 1000),
            make_model("m2", ModelStatus::Draft, 2000),
            make_model("m3", ModelStatus::Deployed, 3000),
        ];
        let counts = metrics.compute_model_count_by_status(&records);
        assert_eq!(counts.get("Draft"), Some(&2));
        assert_eq!(counts.get("Deployed"), Some(&1));
    }

    #[test]
    fn test_model_count_by_status_empty() {
        let metrics = AiMetrics::new();
        let counts = metrics.compute_model_count_by_status(&[]);
        assert!(counts.is_empty());
    }

    #[test]
    fn test_dataset_count_by_quality() {
        let metrics = AiMetrics::new();
        let records = vec![
            make_dataset("ds1", DataQualityStatus::Validated),
            make_dataset("ds2", DataQualityStatus::Validated),
            make_dataset("ds3", DataQualityStatus::Unknown),
        ];
        let counts = metrics.compute_dataset_count_by_quality(&records);
        assert_eq!(counts.get("Validated"), Some(&2));
        assert_eq!(counts.get("Unknown"), Some(&1));
    }

    #[test]
    fn test_dataset_count_by_quality_empty() {
        let metrics = AiMetrics::new();
        let counts = metrics.compute_dataset_count_by_quality(&[]);
        assert!(counts.is_empty());
    }

    #[test]
    fn test_evaluation_pass_rate_all_pass() {
        let metrics = AiMetrics::new();
        let results = vec![
            make_eval_result("r1", true),
            make_eval_result("r2", true),
        ];
        assert_eq!(metrics.compute_evaluation_pass_rate(&results), "1.00");
    }

    #[test]
    fn test_evaluation_pass_rate_half() {
        let metrics = AiMetrics::new();
        let results = vec![
            make_eval_result("r1", true),
            make_eval_result("r2", false),
        ];
        assert_eq!(metrics.compute_evaluation_pass_rate(&results), "0.50");
    }

    #[test]
    fn test_evaluation_pass_rate_empty() {
        let metrics = AiMetrics::new();
        assert_eq!(metrics.compute_evaluation_pass_rate(&[]), "0.00");
    }

    #[test]
    fn test_deployment_count_by_environment() {
        let metrics = AiMetrics::new();
        let records = vec![
            make_deployment("d1", DeploymentEnvironment::Production),
            make_deployment("d2", DeploymentEnvironment::Production),
            make_deployment("d3", DeploymentEnvironment::Staging),
        ];
        let counts = metrics.compute_deployment_count_by_environment(&records);
        assert_eq!(counts.get("Production"), Some(&2));
        assert_eq!(counts.get("Staging"), Some(&1));
    }

    #[test]
    fn test_deployment_count_by_environment_empty() {
        let metrics = AiMetrics::new();
        let counts = metrics.compute_deployment_count_by_environment(&[]);
        assert!(counts.is_empty());
    }

    #[test]
    fn test_fairness_compliance_rate_all_fair() {
        let metrics = AiMetrics::new();
        let assessments = vec![
            make_fairness("fa1", FairnessStatus::Fair),
            make_fairness("fa2", FairnessStatus::Fair),
        ];
        assert_eq!(metrics.compute_fairness_compliance_rate(&assessments), "1.00");
    }

    #[test]
    fn test_fairness_compliance_rate_mixed() {
        let metrics = AiMetrics::new();
        let assessments = vec![
            make_fairness("fa1", FairnessStatus::Fair),
            make_fairness("fa2", FairnessStatus::Unfair { violations: vec!["v1".into()] }),
        ];
        assert_eq!(metrics.compute_fairness_compliance_rate(&assessments), "0.50");
    }

    #[test]
    fn test_fairness_compliance_rate_empty() {
        let metrics = AiMetrics::new();
        assert_eq!(metrics.compute_fairness_compliance_rate(&[]), "0.00");
    }

    #[test]
    fn test_drift_detection_rate_no_drift() {
        let metrics = AiMetrics::new();
        let results = vec![
            make_drift("dd1", DriftStatus::NoDrift),
            make_drift("dd2", DriftStatus::NoDrift),
        ];
        assert_eq!(metrics.compute_drift_detection_rate(&results), "0.00");
    }

    #[test]
    fn test_drift_detection_rate_with_drift() {
        let metrics = AiMetrics::new();
        let results = vec![
            make_drift("dd1", DriftStatus::NoDrift),
            make_drift("dd2", DriftStatus::MinorDrift { details: "shift".into() }),
        ];
        assert_eq!(metrics.compute_drift_detection_rate(&results), "0.50");
    }

    #[test]
    fn test_drift_detection_rate_empty() {
        let metrics = AiMetrics::new();
        assert_eq!(metrics.compute_drift_detection_rate(&[]), "0.00");
    }

    #[test]
    fn test_model_age_distribution() {
        let metrics = AiMetrics::new();
        let now = 100 * 86_400_000; // 100 days in ms
        let records = vec![
            make_model("m1", ModelStatus::Draft, now - 10 * 86_400_000),  // 10 days old → 0-30d
            make_model("m2", ModelStatus::Draft, now - 50 * 86_400_000),  // 50 days old → 30-90d
            make_model("m3", ModelStatus::Draft, now - 100 * 86_400_000), // 100 days old → 90-180d
            make_model("m4", ModelStatus::Draft, now - 200 * 86_400_000), // 200 days old → 180d+
        ];
        let dist = metrics.compute_model_age_distribution(&records, now);
        assert_eq!(dist.get("0-30d"), Some(&1));
        assert_eq!(dist.get("30-90d"), Some(&1));
        assert_eq!(dist.get("90-180d"), Some(&1));
        assert_eq!(dist.get("180d+"), Some(&1));
    }

    #[test]
    fn test_model_age_distribution_empty() {
        let metrics = AiMetrics::new();
        let dist = metrics.compute_model_age_distribution(&[], 1000);
        assert!(dist.is_empty());
    }

    #[test]
    fn test_metrics_default() {
        let _m = AiMetrics;
    }
}
