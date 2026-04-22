// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Data governance metrics collector trait. Named
// data_governance_metrics.rs to avoid collision with L2 data_metrics.rs.
// Computes quality pass rate, classification coverage, lineage
// completeness, schema compatibility rate, catalog completeness rate,
// freshness SLA met rate, and lists datasets by quality rule count.
// Reference implementations: InMemoryDataGovernanceMetricsCollector,
// NullDataGovernanceMetricsCollector.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::{
    StoredCatalogEntry, StoredClassification, StoredFreshnessAssessment, StoredLineageRecord,
    StoredQualityRule, StoredSchemaRecord,
};
use crate::catalog::CatalogEntryStatus;

// ── DataGovernanceMetricSnapshot ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGovernanceMetricSnapshot {
    pub snapshot_id: String,
    pub computed_at: i64,
    pub quality_pass_rate: String,
    pub classification_coverage: String,
    pub lineage_completeness: String,
    pub schema_compatibility_rate: String,
    pub catalog_completeness_rate: String,
    pub freshness_sla_met_rate: String,
    pub total_rules: String,
    pub total_datasets: String,
    pub metadata: HashMap<String, String>,
}

// ── DataGovernanceMetricsCollector trait ──────────────────────────

pub trait DataGovernanceMetricsCollector {
    fn compute_quality_pass_rate(&self, rules: &[StoredQualityRule]) -> String;
    fn compute_classification_coverage(&self, classifications: &[StoredClassification], total_datasets: usize) -> String;
    fn compute_lineage_completeness(&self, records: &[StoredLineageRecord]) -> String;
    fn compute_schema_compatibility_rate(&self, schemas: &[StoredSchemaRecord]) -> String;
    fn compute_catalog_completeness_rate(&self, entries: &[StoredCatalogEntry]) -> String;
    fn compute_freshness_sla_met_rate(&self, assessments: &[StoredFreshnessAssessment]) -> String;
    fn list_datasets_by_rule_count(
        &self,
        rules: &[StoredQualityRule],
        limit: usize,
    ) -> Vec<(String, String)>;
    fn collector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryDataGovernanceMetricsCollector ────────────────────────

pub struct InMemoryDataGovernanceMetricsCollector {
    collector_id: String,
    active: bool,
}

impl InMemoryDataGovernanceMetricsCollector {
    pub fn new(collector_id: impl Into<String>) -> Self {
        Self {
            collector_id: collector_id.into(),
            active: true,
        }
    }
}

impl DataGovernanceMetricsCollector for InMemoryDataGovernanceMetricsCollector {
    fn compute_quality_pass_rate(&self, rules: &[StoredQualityRule]) -> String {
        if rules.is_empty() {
            return "0.0000".to_string();
        }
        let with_pass_rate = rules
            .iter()
            .filter(|r| r.pass_rate.is_some())
            .count();
        if with_pass_rate == 0 {
            return "0.0000".to_string();
        }
        let total: f64 = rules
            .iter()
            .filter_map(|r| r.pass_rate.as_ref())
            .filter_map(|pr| pr.parse::<f64>().ok())
            .sum();
        format!("{:.4}", total / with_pass_rate as f64)
    }

    fn compute_classification_coverage(&self, classifications: &[StoredClassification], total_datasets: usize) -> String {
        if total_datasets == 0 {
            return "0.0000".to_string();
        }
        let classified_datasets: usize = classifications
            .iter()
            .map(|c| c.dataset_ref.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        format!("{:.4}", classified_datasets as f64 / total_datasets as f64)
    }

    fn compute_lineage_completeness(&self, records: &[StoredLineageRecord]) -> String {
        if records.is_empty() {
            return "0.0000".to_string();
        }
        let with_predecessors = records
            .iter()
            .filter(|r| !r.predecessor_refs.is_empty() || !r.successor_refs.is_empty())
            .count();
        format!("{:.4}", with_predecessors as f64 / records.len() as f64)
    }

    fn compute_schema_compatibility_rate(&self, schemas: &[StoredSchemaRecord]) -> String {
        if schemas.is_empty() {
            return "0.0000".to_string();
        }
        let compatible = schemas
            .iter()
            .filter(|s| s.compatibility_with_previous.is_some())
            .count();
        format!("{:.4}", compatible as f64 / schemas.len() as f64)
    }

    fn compute_catalog_completeness_rate(&self, entries: &[StoredCatalogEntry]) -> String {
        if entries.is_empty() {
            return "0.0000".to_string();
        }
        let active = entries
            .iter()
            .filter(|e| matches!(e.status, CatalogEntryStatus::Active))
            .count();
        format!("{:.4}", active as f64 / entries.len() as f64)
    }

    fn compute_freshness_sla_met_rate(&self, assessments: &[StoredFreshnessAssessment]) -> String {
        if assessments.is_empty() {
            return "0.0000".to_string();
        }
        let met = assessments
            .iter()
            .filter(|a| a.sla_met)
            .count();
        format!("{:.4}", met as f64 / assessments.len() as f64)
    }

    fn list_datasets_by_rule_count(
        &self,
        rules: &[StoredQualityRule],
        limit: usize,
    ) -> Vec<(String, String)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for rule in rules {
            *counts.entry(rule.target_dataset_ref.as_str()).or_default() += 1;
        }
        let mut entries: Vec<(String, String)> = counts
            .into_iter()
            .map(|(ds, count)| (ds.to_string(), count.to_string()))
            .collect();
        entries.sort_by(|a, b| {
            let a_count = a.1.parse::<usize>().unwrap_or(0);
            let b_count = b.1.parse::<usize>().unwrap_or(0);
            b_count.cmp(&a_count)
        });
        entries.truncate(limit);
        entries
    }

    fn collector_id(&self) -> &str {
        &self.collector_id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullDataGovernanceMetricsCollector ────────────────────────────

pub struct NullDataGovernanceMetricsCollector;

impl DataGovernanceMetricsCollector for NullDataGovernanceMetricsCollector {
    fn compute_quality_pass_rate(&self, _rules: &[StoredQualityRule]) -> String {
        "0.0000".to_string()
    }

    fn compute_classification_coverage(&self, _classifications: &[StoredClassification], _total_datasets: usize) -> String {
        "0.0000".to_string()
    }

    fn compute_lineage_completeness(&self, _records: &[StoredLineageRecord]) -> String {
        "0.0000".to_string()
    }

    fn compute_schema_compatibility_rate(&self, _schemas: &[StoredSchemaRecord]) -> String {
        "0.0000".to_string()
    }

    fn compute_catalog_completeness_rate(&self, _entries: &[StoredCatalogEntry]) -> String {
        "0.0000".to_string()
    }

    fn compute_freshness_sla_met_rate(&self, _assessments: &[StoredFreshnessAssessment]) -> String {
        "1.0000".to_string()
    }

    fn list_datasets_by_rule_count(
        &self,
        _rules: &[StoredQualityRule],
        _limit: usize,
    ) -> Vec<(String, String)> {
        Vec::new()
    }

    fn collector_id(&self) -> &str {
        "null-data-governance-metrics"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        StoredCatalogEntry, StoredClassification, StoredFreshnessAssessment,
        StoredLineageRecord, StoredQualityRule, StoredSchemaRecord,
    };
    use crate::catalog::CatalogEntryStatus;
    use crate::classification::DataSensitivity;
    use crate::quality::DataQualityDimension;

    fn make_stored_rule(id: &str, dataset: &str, pass_rate: Option<&str>) -> StoredQualityRule {
        StoredQualityRule {
            rule_id: id.into(),
            rule_name: format!("rule_{id}"),
            dimension: DataQualityDimension::Completeness,
            target_dataset_ref: dataset.into(),
            target_field: None,
            severity: "Critical".into(),
            enabled: true,
            created_at: 1000,
            metadata: HashMap::new(),
            stored_at: 2000,
            evaluations_run: "1".into(),
            last_evaluated_at: Some(2000),
            pass_rate: pass_rate.map(String::from),
        }
    }

    fn make_stored_classification(id: &str, dataset: &str) -> StoredClassification {
        StoredClassification {
            classification_id: id.into(),
            dataset_ref: dataset.into(),
            sensitivity_level: DataSensitivity::Confidential,
            classified_at: 1000,
            review_due_at: None,
            metadata: HashMap::new(),
            stored_at: 2000,
            review_count: "0".into(),
            last_reviewed_at: None,
        }
    }

    fn make_stored_lineage(id: &str, has_links: bool) -> StoredLineageRecord {
        StoredLineageRecord {
            record_id: id.into(),
            dataset_ref: "ds-1".into(),
            stage: "Source".into(),
            predecessor_refs: if has_links { vec!["prev".into()] } else { Vec::new() },
            successor_refs: Vec::new(),
            recorded_at: 1000,
            recorded_by: "agent".into(),
            metadata: HashMap::new(),
            stored_at: 2000,
            lineage_hash: "abc123".into(),
        }
    }

    fn make_stored_schema(id: &str, compat: Option<&str>) -> StoredSchemaRecord {
        StoredSchemaRecord {
            schema_id: id.into(),
            dataset_ref: "ds-1".into(),
            version: "1.0.0".into(),
            format: "JsonSchema".into(),
            field_count: "5".into(),
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
            stored_at: 2000,
            schema_hash: "def456".into(),
            compatibility_with_previous: compat.map(String::from),
        }
    }

    fn make_stored_catalog(id: &str, status: CatalogEntryStatus) -> StoredCatalogEntry {
        StoredCatalogEntry {
            entry_id: id.into(),
            dataset_ref: format!("ds-{id}"),
            dataset_name: "Test".into(),
            owner_id: "owner".into(),
            steward_id: None,
            domain: None,
            status,
            registered_at: 1000,
            metadata: HashMap::new(),
            stored_at: 2000,
            completeness_score: "0.80".into(),
        }
    }

    fn make_stored_freshness(id: &str, sla_met: bool) -> StoredFreshnessAssessment {
        StoredFreshnessAssessment {
            assessment_id: id.into(),
            policy_id: "fp-1".into(),
            dataset_ref: "ds-1".into(),
            last_updated_at: 1000,
            assessed_at: 2000,
            freshness_status: "Fresh".into(),
            sla_met,
            stored_at: 3000,
        }
    }

    #[test]
    fn test_quality_pass_rate() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let rules = vec![
            make_stored_rule("qr-1", "ds-1", Some("0.9500")),
            make_stored_rule("qr-2", "ds-1", Some("0.8500")),
        ];
        let rate = collector.compute_quality_pass_rate(&rules);
        assert_eq!(rate, "0.9000");
    }

    #[test]
    fn test_quality_pass_rate_empty() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.compute_quality_pass_rate(&[]), "0.0000");
    }

    #[test]
    fn test_quality_pass_rate_no_evaluations() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let rules = vec![make_stored_rule("qr-1", "ds-1", None)];
        assert_eq!(collector.compute_quality_pass_rate(&rules), "0.0000");
    }

    #[test]
    fn test_classification_coverage() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let classifications = vec![
            make_stored_classification("cls-1", "ds-1"),
            make_stored_classification("cls-2", "ds-2"),
        ];
        let rate = collector.compute_classification_coverage(&classifications, 4);
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_classification_coverage_zero_datasets() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.compute_classification_coverage(&[], 0), "0.0000");
    }

    #[test]
    fn test_lineage_completeness() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let records = vec![
            make_stored_lineage("lr-1", true),
            make_stored_lineage("lr-2", false),
        ];
        let rate = collector.compute_lineage_completeness(&records);
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_schema_compatibility_rate() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let schemas = vec![
            make_stored_schema("sch-1", Some("FullyCompatible")),
            make_stored_schema("sch-2", None),
            make_stored_schema("sch-3", Some("BackwardCompatible")),
        ];
        let rate = collector.compute_schema_compatibility_rate(&schemas);
        assert_eq!(rate, "0.6667");
    }

    #[test]
    fn test_catalog_completeness_rate() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let entries = vec![
            make_stored_catalog("ce-1", CatalogEntryStatus::Active),
            make_stored_catalog("ce-2", CatalogEntryStatus::Deprecated { reason: "old".into() }),
            make_stored_catalog("ce-3", CatalogEntryStatus::Active),
        ];
        let rate = collector.compute_catalog_completeness_rate(&entries);
        assert_eq!(rate, "0.6667");
    }

    #[test]
    fn test_freshness_sla_met_rate() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let assessments = vec![
            make_stored_freshness("fa-1", true),
            make_stored_freshness("fa-2", false),
            make_stored_freshness("fa-3", true),
        ];
        let rate = collector.compute_freshness_sla_met_rate(&assessments);
        assert_eq!(rate, "0.6667");
    }

    #[test]
    fn test_list_datasets_by_rule_count() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        let rules = vec![
            make_stored_rule("qr-1", "ds-users", None),
            make_stored_rule("qr-2", "ds-users", None),
            make_stored_rule("qr-3", "ds-orders", None),
            make_stored_rule("qr-4", "ds-users", None),
            make_stored_rule("qr-5", "ds-products", None),
        ];
        let top = collector.list_datasets_by_rule_count(&rules, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "ds-users");
        assert_eq!(top[0].1, "3");
    }

    #[test]
    fn test_collector_identity() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.collector_id(), "mc-1");
        assert!(collector.is_active());
    }

    #[test]
    fn test_null_collector() {
        let collector = NullDataGovernanceMetricsCollector;
        assert_eq!(collector.compute_quality_pass_rate(&[]), "0.0000");
        assert_eq!(collector.compute_freshness_sla_met_rate(&[]), "1.0000");
        assert!(!collector.is_active());
        assert_eq!(collector.collector_id(), "null-data-governance-metrics");
    }

    #[test]
    fn test_snapshot_equality() {
        let s1 = DataGovernanceMetricSnapshot {
            snapshot_id: "snap-1".into(),
            computed_at: 5000,
            quality_pass_rate: "0.9000".into(),
            classification_coverage: "0.7500".into(),
            lineage_completeness: "0.8000".into(),
            schema_compatibility_rate: "0.9500".into(),
            catalog_completeness_rate: "0.6000".into(),
            freshness_sla_met_rate: "0.8500".into(),
            total_rules: "20".into(),
            total_datasets: "10".into(),
            metadata: Default::default(),
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_empty_inputs_default_rates() {
        let collector = InMemoryDataGovernanceMetricsCollector::new("mc-1");
        assert_eq!(collector.compute_lineage_completeness(&[]), "0.0000");
        assert_eq!(collector.compute_schema_compatibility_rate(&[]), "0.0000");
        assert_eq!(collector.compute_catalog_completeness_rate(&[]), "0.0000");
        assert_eq!(collector.compute_freshness_sla_met_rate(&[]), "0.0000");
    }
}
