// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Data governance metrics. Computes quality pass rates,
// classification coverage, lineage completeness, access denial rates,
// schema compatibility rates, freshness compliance rates, and
// staleness distribution. All numeric values as String for Eq.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::access::DataAccessDecision;
use crate::freshness::{FreshnessAssessment, FreshnessStatus};
use crate::classification::DataClassification;
use crate::lineage::{LineageChain, LineageChainStatus};
use crate::quality_engine::QualityRuleEvaluation;
use crate::schema::SchemaCompatibility;

// ── DataMetricSnapshot ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMetricSnapshot {
    pub snapshot_id: String,
    pub computed_at: i64,
    pub quality_pass_rate: String,
    pub classification_coverage: String,
    pub lineage_completeness: String,
    pub access_denial_rate: String,
    pub schema_compatibility_rate: String,
    pub freshness_compliance_rate: String,
    pub total_datasets: String,
    pub total_rules: String,
    pub metadata: HashMap<String, String>,
}

// ── DataMetrics ──────────────────────────────────────────────────────

pub struct DataMetrics;

impl DataMetrics {
    pub fn new() -> Self {
        Self
    }

    pub fn compute_quality_pass_rate(&self, evaluations: &[QualityRuleEvaluation]) -> String {
        if evaluations.is_empty() {
            return "1.00".to_string();
        }
        let passed = evaluations.iter().filter(|e| e.passed).count();
        let ratio = passed as f64 / evaluations.len() as f64;
        format!("{ratio:.2}")
    }

    pub fn compute_classification_coverage(
        &self,
        dataset_refs: &[String],
        classifications: &[DataClassification],
    ) -> String {
        if dataset_refs.is_empty() {
            return "1.00".to_string();
        }
        let classified: Vec<&str> = classifications
            .iter()
            .map(|c| c.dataset_ref.as_str())
            .collect();
        let covered = dataset_refs
            .iter()
            .filter(|d| classified.contains(&d.as_str()))
            .count();
        let ratio = covered as f64 / dataset_refs.len() as f64;
        format!("{ratio:.2}")
    }

    pub fn compute_lineage_completeness(&self, chains: &[LineageChain]) -> String {
        if chains.is_empty() {
            return "1.00".to_string();
        }
        let complete = chains
            .iter()
            .filter(|c| c.chain_status == LineageChainStatus::Complete)
            .count();
        let ratio = complete as f64 / chains.len() as f64;
        format!("{ratio:.2}")
    }

    pub fn compute_access_denial_rate(&self, decisions: &[DataAccessDecision]) -> String {
        if decisions.is_empty() {
            return "0.00".to_string();
        }
        let denied = decisions
            .iter()
            .filter(|d| matches!(d, DataAccessDecision::Denied { .. }))
            .count();
        let ratio = denied as f64 / decisions.len() as f64;
        format!("{ratio:.2}")
    }

    pub fn compute_schema_compatibility_rate(
        &self,
        compatibilities: &[SchemaCompatibility],
    ) -> String {
        if compatibilities.is_empty() {
            return "1.00".to_string();
        }
        let compatible = compatibilities
            .iter()
            .filter(|c| !matches!(c, SchemaCompatibility::Breaking { .. }))
            .count();
        let ratio = compatible as f64 / compatibilities.len() as f64;
        format!("{ratio:.2}")
    }

    pub fn compute_freshness_compliance_rate(
        &self,
        assessments: &[FreshnessAssessment],
    ) -> String {
        if assessments.is_empty() {
            return "1.00".to_string();
        }
        let fresh = assessments
            .iter()
            .filter(|a| matches!(a.freshness_status, FreshnessStatus::Fresh { .. }))
            .count();
        let ratio = fresh as f64 / assessments.len() as f64;
        format!("{ratio:.2}")
    }

    pub fn compute_staleness_distribution(
        &self,
        assessments: &[FreshnessAssessment],
    ) -> HashMap<String, String> {
        let mut dist = HashMap::new();
        for a in assessments {
            let key = match &a.freshness_status {
                FreshnessStatus::Fresh { .. } => "Fresh",
                FreshnessStatus::Stale { .. } => "Stale",
                FreshnessStatus::Unknown { .. } => "Unknown",
                FreshnessStatus::NotApplicable => "NotApplicable",
            };
            let count = dist
                .entry(key.to_string())
                .or_insert_with(|| "0".to_string());
            let val: usize = count.parse().unwrap_or(0);
            *count = (val + 1).to_string();
        }
        dist
    }
}

impl Default for DataMetrics {
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
    use crate::classification::{ClassificationMethod, DataSensitivity};

    fn make_eval(passed: bool) -> QualityRuleEvaluation {
        QualityRuleEvaluation {
            rule_id: "qr-1".into(),
            rule_name: "test".into(),
            dimension: "Completeness".into(),
            passed,
            measured_value: None,
            violation_details: None,
            severity: "Critical".into(),
            evaluated_at: 1000,
        }
    }

    fn make_freshness_assessment(fresh: bool) -> FreshnessAssessment {
        FreshnessAssessment {
            assessment_id: "fa-1".into(),
            policy_id: "fp-1".into(),
            dataset_ref: "ds-1".into(),
            last_updated_at: 1000,
            assessed_at: 2000,
            freshness_status: if fresh {
                FreshnessStatus::Fresh { hours_since_update: "1".into() }
            } else {
                FreshnessStatus::Stale { hours_since_update: "48".into(), threshold_hours: "24".into() }
            },
            sla_met: fresh,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_quality_pass_rate_all_pass() {
        let metrics = DataMetrics::new();
        let evals = vec![make_eval(true), make_eval(true)];
        assert_eq!(metrics.compute_quality_pass_rate(&evals), "1.00");
    }

    #[test]
    fn test_quality_pass_rate_half() {
        let metrics = DataMetrics::new();
        let evals = vec![make_eval(true), make_eval(false)];
        assert_eq!(metrics.compute_quality_pass_rate(&evals), "0.50");
    }

    #[test]
    fn test_quality_pass_rate_empty() {
        let metrics = DataMetrics::new();
        assert_eq!(metrics.compute_quality_pass_rate(&[]), "1.00");
    }

    #[test]
    fn test_classification_coverage_all() {
        let metrics = DataMetrics::new();
        let refs = vec!["ds-1".to_string()];
        let cls = vec![DataClassification {
            classification_id: "c".into(),
            dataset_ref: "ds-1".into(),
            sensitivity_level: DataSensitivity::Public,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Manual { classified_by: "a".into() },
            classified_at: 1000,
            review_due_at: None,
            metadata: HashMap::new(),
        }];
        assert_eq!(metrics.compute_classification_coverage(&refs, &cls), "1.00");
    }

    #[test]
    fn test_classification_coverage_none() {
        let metrics = DataMetrics::new();
        let refs = vec!["ds-1".to_string(), "ds-2".to_string()];
        assert_eq!(metrics.compute_classification_coverage(&refs, &[]), "0.00");
    }

    #[test]
    fn test_lineage_completeness_all_complete() {
        let metrics = DataMetrics::new();
        let chains = vec![LineageChain {
            chain_id: "lc-1".into(),
            dataset_ref: "ds-1".into(),
            records: Vec::new(),
            chain_status: LineageChainStatus::Complete,
            verified_at: None,
            metadata: HashMap::new(),
        }];
        assert_eq!(metrics.compute_lineage_completeness(&chains), "1.00");
    }

    #[test]
    fn test_lineage_completeness_half() {
        let metrics = DataMetrics::new();
        let chains = vec![
            LineageChain {
                chain_id: "lc-1".into(), dataset_ref: "ds-1".into(), records: Vec::new(),
                chain_status: LineageChainStatus::Complete, verified_at: None, metadata: HashMap::new(),
            },
            LineageChain {
                chain_id: "lc-2".into(), dataset_ref: "ds-2".into(), records: Vec::new(),
                chain_status: LineageChainStatus::Broken { gap_description: "broken".into() },
                verified_at: None, metadata: HashMap::new(),
            },
        ];
        assert_eq!(metrics.compute_lineage_completeness(&chains), "0.50");
    }

    #[test]
    fn test_access_denial_rate_no_denials() {
        let metrics = DataMetrics::new();
        let decisions = vec![
            DataAccessDecision::Granted { reason: "ok".into() },
        ];
        assert_eq!(metrics.compute_access_denial_rate(&decisions), "0.00");
    }

    #[test]
    fn test_access_denial_rate_all_denied() {
        let metrics = DataMetrics::new();
        let decisions = vec![
            DataAccessDecision::Denied { reason: "no".into() },
            DataAccessDecision::Denied { reason: "no".into() },
        ];
        assert_eq!(metrics.compute_access_denial_rate(&decisions), "1.00");
    }

    #[test]
    fn test_schema_compatibility_rate_all_compatible() {
        let metrics = DataMetrics::new();
        let compats = vec![SchemaCompatibility::FullyCompatible];
        assert_eq!(metrics.compute_schema_compatibility_rate(&compats), "1.00");
    }

    #[test]
    fn test_schema_compatibility_rate_with_breaking() {
        let metrics = DataMetrics::new();
        let compats = vec![
            SchemaCompatibility::FullyCompatible,
            SchemaCompatibility::Breaking { breaking_changes: Vec::new() },
        ];
        assert_eq!(metrics.compute_schema_compatibility_rate(&compats), "0.50");
    }

    #[test]
    fn test_freshness_compliance_all_fresh() {
        let metrics = DataMetrics::new();
        let assessments = vec![make_freshness_assessment(true)];
        assert_eq!(metrics.compute_freshness_compliance_rate(&assessments), "1.00");
    }

    #[test]
    fn test_freshness_compliance_half() {
        let metrics = DataMetrics::new();
        let assessments = vec![
            make_freshness_assessment(true),
            make_freshness_assessment(false),
        ];
        assert_eq!(metrics.compute_freshness_compliance_rate(&assessments), "0.50");
    }

    #[test]
    fn test_staleness_distribution() {
        let metrics = DataMetrics::new();
        let assessments = vec![
            make_freshness_assessment(true),
            make_freshness_assessment(true),
            make_freshness_assessment(false),
        ];
        let dist = metrics.compute_staleness_distribution(&assessments);
        assert_eq!(dist.get("Fresh"), Some(&"2".to_string()));
        assert_eq!(dist.get("Stale"), Some(&"1".to_string()));
    }

    #[test]
    fn test_snapshot_construction() {
        let snapshot = DataMetricSnapshot {
            snapshot_id: "snap-1".into(),
            computed_at: 5000,
            quality_pass_rate: "0.95".into(),
            classification_coverage: "0.80".into(),
            lineage_completeness: "1.00".into(),
            access_denial_rate: "0.10".into(),
            schema_compatibility_rate: "0.90".into(),
            freshness_compliance_rate: "0.75".into(),
            total_datasets: "50".into(),
            total_rules: "120".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(snapshot.snapshot_id, "snap-1");
        assert_eq!(snapshot.quality_pass_rate, "0.95");
    }

    #[test]
    fn test_metrics_default() {
        let _m = DataMetrics;
    }
}
