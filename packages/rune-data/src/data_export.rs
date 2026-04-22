// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Data governance exporter trait. Defines the export contract
// for quality reports, classification reports, lineage reports, schema
// reports, catalog inventories, and freshness reports. Five
// implementations: JsonDataExporter, DataQualityReportExporter,
// DataLineageExporter, DataCatalogExporter, GdprDataMappingExporter.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{
    StoredCatalogEntry, StoredClassification, StoredLineageRecord, StoredQualityRule,
    StoredSchemaRecord,
};
use crate::error::DataError;

// ── DataGovernanceExporter trait ──────────────────────────────────────

pub trait DataGovernanceExporter {
    fn export_quality_report(&self, rules: &[StoredQualityRule]) -> Result<String, DataError>;
    fn export_classification_report(&self, classifications: &[StoredClassification]) -> Result<String, DataError>;
    fn export_lineage_report(&self, records: &[StoredLineageRecord]) -> Result<String, DataError>;
    fn export_schema_report(&self, schemas: &[StoredSchemaRecord]) -> Result<String, DataError>;
    fn export_catalog_inventory(&self, entries: &[StoredCatalogEntry]) -> Result<String, DataError>;
    fn export_freshness_report(&self, assessments: &[crate::backend::StoredFreshnessAssessment]) -> Result<String, DataError>;
    fn export_batch(
        &self,
        rules: &[StoredQualityRule],
        classifications: &[StoredClassification],
        records: &[StoredLineageRecord],
    ) -> Result<String, DataError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonDataExporter ─────────────────────────────────────────────────

pub struct JsonDataExporter;

impl DataGovernanceExporter for JsonDataExporter {
    fn export_quality_report(&self, rules: &[StoredQualityRule]) -> Result<String, DataError> {
        let entries: Vec<serde_json::Value> = rules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "dimension": format!("{}", r.dimension),
                    "dataset_ref": r.target_dataset_ref,
                    "severity": r.severity,
                    "evaluations_run": r.evaluations_run,
                    "pass_rate": r.pass_rate,
                    "stored_at": r.stored_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "quality_report",
            "rule_count": rules.len(),
            "rules": entries,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_classification_report(&self, classifications: &[StoredClassification]) -> Result<String, DataError> {
        let entries: Vec<serde_json::Value> = classifications
            .iter()
            .map(|c| {
                serde_json::json!({
                    "classification_id": c.classification_id,
                    "dataset_ref": c.dataset_ref,
                    "sensitivity_level": format!("{}", c.sensitivity_level),
                    "review_count": c.review_count,
                    "stored_at": c.stored_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "classification_report",
            "classification_count": classifications.len(),
            "classifications": entries,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_lineage_report(&self, records: &[StoredLineageRecord]) -> Result<String, DataError> {
        let entries: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "record_id": r.record_id,
                    "dataset_ref": r.dataset_ref,
                    "stage": r.stage,
                    "lineage_hash": r.lineage_hash,
                    "predecessor_refs": r.predecessor_refs,
                    "stored_at": r.stored_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "lineage_report",
            "record_count": records.len(),
            "records": entries,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_schema_report(&self, schemas: &[StoredSchemaRecord]) -> Result<String, DataError> {
        let entries: Vec<serde_json::Value> = schemas
            .iter()
            .map(|s| {
                serde_json::json!({
                    "schema_id": s.schema_id,
                    "dataset_ref": s.dataset_ref,
                    "version": s.version,
                    "format": s.format,
                    "field_count": s.field_count,
                    "schema_hash": s.schema_hash,
                    "stored_at": s.stored_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "schema_report",
            "schema_count": schemas.len(),
            "schemas": entries,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_catalog_inventory(&self, entries: &[StoredCatalogEntry]) -> Result<String, DataError> {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "entry_id": e.entry_id,
                    "dataset_ref": e.dataset_ref,
                    "dataset_name": e.dataset_name,
                    "owner_id": e.owner_id,
                    "status": format!("{}", e.status),
                    "completeness_score": e.completeness_score,
                    "stored_at": e.stored_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "catalog_inventory",
            "entry_count": entries.len(),
            "entries": items,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_freshness_report(&self, assessments: &[crate::backend::StoredFreshnessAssessment]) -> Result<String, DataError> {
        let items: Vec<serde_json::Value> = assessments
            .iter()
            .map(|a| {
                serde_json::json!({
                    "assessment_id": a.assessment_id,
                    "dataset_ref": a.dataset_ref,
                    "freshness_status": a.freshness_status,
                    "sla_met": a.sla_met,
                    "assessed_at": a.assessed_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "freshness_report",
            "assessment_count": assessments.len(),
            "assessments": items,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_batch(
        &self,
        rules: &[StoredQualityRule],
        classifications: &[StoredClassification],
        records: &[StoredLineageRecord],
    ) -> Result<String, DataError> {
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "data_governance_batch",
            "quality_rule_count": rules.len(),
            "classification_count": classifications.len(),
            "lineage_record_count": records.len(),
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn format_name(&self) -> &str { "JSON" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── DataQualityReportExporter ────────────────────────────────────────

pub struct DataQualityReportExporter;

impl DataGovernanceExporter for DataQualityReportExporter {
    fn export_quality_report(&self, rules: &[StoredQualityRule]) -> Result<String, DataError> {
        let mut sections = Vec::new();
        for r in rules {
            let pass_rate = r.pass_rate.as_deref().unwrap_or("N/A");
            sections.push(serde_json::json!({
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "dimension": format!("{}", r.dimension),
                "severity": r.severity,
                "evaluations_run": r.evaluations_run,
                "pass_rate": pass_rate,
                "sla_status": if pass_rate == "N/A" { "no_data" } else { "tracked" },
            }));
        }
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "data_quality_assessment",
            "rules": sections,
            "total_rules": rules.len(),
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_classification_report(&self, c: &[StoredClassification]) -> Result<String, DataError> { JsonDataExporter.export_classification_report(c) }
    fn export_lineage_report(&self, r: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_lineage_report(r) }
    fn export_schema_report(&self, s: &[StoredSchemaRecord]) -> Result<String, DataError> { JsonDataExporter.export_schema_report(s) }
    fn export_catalog_inventory(&self, e: &[StoredCatalogEntry]) -> Result<String, DataError> { JsonDataExporter.export_catalog_inventory(e) }
    fn export_freshness_report(&self, a: &[crate::backend::StoredFreshnessAssessment]) -> Result<String, DataError> { JsonDataExporter.export_freshness_report(a) }
    fn export_batch(&self, r: &[StoredQualityRule], c: &[StoredClassification], l: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_batch(r, c, l) }
    fn format_name(&self) -> &str { "DataQualityReport" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── DataLineageExporter ──────────────────────────────────────────────

pub struct DataLineageExporter;

impl DataGovernanceExporter for DataLineageExporter {
    fn export_lineage_report(&self, records: &[StoredLineageRecord]) -> Result<String, DataError> {
        let chains: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "record_id": r.record_id,
                    "dataset_ref": r.dataset_ref,
                    "stage": r.stage,
                    "predecessor_refs": r.predecessor_refs,
                    "successor_refs": r.successor_refs,
                    "lineage_hash": r.lineage_hash,
                    "recorded_at": r.recorded_at,
                    "recorded_by": r.recorded_by,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "lineage_documentation",
            "record_count": records.len(),
            "lineage_records": chains,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_quality_report(&self, r: &[StoredQualityRule]) -> Result<String, DataError> { JsonDataExporter.export_quality_report(r) }
    fn export_classification_report(&self, c: &[StoredClassification]) -> Result<String, DataError> { JsonDataExporter.export_classification_report(c) }
    fn export_schema_report(&self, s: &[StoredSchemaRecord]) -> Result<String, DataError> { JsonDataExporter.export_schema_report(s) }
    fn export_catalog_inventory(&self, e: &[StoredCatalogEntry]) -> Result<String, DataError> { JsonDataExporter.export_catalog_inventory(e) }
    fn export_freshness_report(&self, a: &[crate::backend::StoredFreshnessAssessment]) -> Result<String, DataError> { JsonDataExporter.export_freshness_report(a) }
    fn export_batch(&self, r: &[StoredQualityRule], c: &[StoredClassification], l: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_batch(r, c, l) }
    fn format_name(&self) -> &str { "DataLineage" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── DataCatalogExporter ──────────────────────────────────────────────

pub struct DataCatalogExporter;

impl DataGovernanceExporter for DataCatalogExporter {
    fn export_catalog_inventory(&self, entries: &[StoredCatalogEntry]) -> Result<String, DataError> {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "entry_id": e.entry_id,
                    "dataset_ref": e.dataset_ref,
                    "dataset_name": e.dataset_name,
                    "owner_id": e.owner_id,
                    "steward_id": e.steward_id,
                    "domain": e.domain,
                    "status": format!("{}", e.status),
                    "completeness_score": e.completeness_score,
                    "governance_coverage": if e.completeness_score == "1.00" { "full" } else { "partial" },
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "catalog_inventory_governance",
            "entry_count": entries.len(),
            "entries": items,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_quality_report(&self, r: &[StoredQualityRule]) -> Result<String, DataError> { JsonDataExporter.export_quality_report(r) }
    fn export_classification_report(&self, c: &[StoredClassification]) -> Result<String, DataError> { JsonDataExporter.export_classification_report(c) }
    fn export_lineage_report(&self, l: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_lineage_report(l) }
    fn export_schema_report(&self, s: &[StoredSchemaRecord]) -> Result<String, DataError> { JsonDataExporter.export_schema_report(s) }
    fn export_freshness_report(&self, a: &[crate::backend::StoredFreshnessAssessment]) -> Result<String, DataError> { JsonDataExporter.export_freshness_report(a) }
    fn export_batch(&self, r: &[StoredQualityRule], c: &[StoredClassification], l: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_batch(r, c, l) }
    fn format_name(&self) -> &str { "DataCatalog" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── GdprDataMappingExporter ──────────────────────────────────────────

pub struct GdprDataMappingExporter;

impl DataGovernanceExporter for GdprDataMappingExporter {
    fn export_classification_report(&self, classifications: &[StoredClassification]) -> Result<String, DataError> {
        let pii_datasets: Vec<serde_json::Value> = classifications
            .iter()
            .filter(|c| {
                let s = format!("{}", c.sensitivity_level);
                s == "Confidential" || s == "Restricted"
            })
            .map(|c| {
                serde_json::json!({
                    "dataset_ref": c.dataset_ref,
                    "sensitivity_level": format!("{}", c.sensitivity_level),
                    "classification_id": c.classification_id,
                    "gdpr_article_30_processing_activity": {
                        "data_category": format!("{}", c.sensitivity_level),
                        "privacy_policy_ref": c.metadata.get("privacy_policy_ref").cloned().unwrap_or_default(),
                        "retention_policy_ref": c.metadata.get("retention_policy_ref").cloned().unwrap_or_default(),
                        "cross_border_transfer": c.metadata.get("cross_border_transfer").cloned().unwrap_or_default(),
                    },
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "gdpr_article_30_data_mapping",
            "gdpr_reference": "Regulation (EU) 2016/679 Article 30",
            "dataset_count": pii_datasets.len(),
            "processing_activities": pii_datasets,
        }))
        .map_err(|e| DataError::InvalidOperation(e.to_string()))
    }

    fn export_quality_report(&self, r: &[StoredQualityRule]) -> Result<String, DataError> { JsonDataExporter.export_quality_report(r) }
    fn export_lineage_report(&self, l: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_lineage_report(l) }
    fn export_schema_report(&self, s: &[StoredSchemaRecord]) -> Result<String, DataError> { JsonDataExporter.export_schema_report(s) }
    fn export_catalog_inventory(&self, e: &[StoredCatalogEntry]) -> Result<String, DataError> { JsonDataExporter.export_catalog_inventory(e) }
    fn export_freshness_report(&self, a: &[crate::backend::StoredFreshnessAssessment]) -> Result<String, DataError> { JsonDataExporter.export_freshness_report(a) }
    fn export_batch(&self, r: &[StoredQualityRule], c: &[StoredClassification], l: &[StoredLineageRecord]) -> Result<String, DataError> { JsonDataExporter.export_batch(r, c, l) }
    fn format_name(&self) -> &str { "GdprDataMapping" }
    fn content_type(&self) -> &str { "application/json" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::StoredFreshnessAssessment;
    use crate::catalog::CatalogEntryStatus;
    use crate::classification::DataSensitivity;
    use crate::quality::DataQualityDimension;
    use std::collections::HashMap;

    fn make_stored_rule(id: &str) -> StoredQualityRule {
        StoredQualityRule {
            rule_id: id.into(),
            rule_name: format!("rule_{id}"),
            dimension: DataQualityDimension::Completeness,
            target_dataset_ref: "ds-1".into(),
            target_field: None,
            severity: "Critical".into(),
            enabled: true,
            created_at: 1000,
            metadata: HashMap::new(),
            stored_at: 2000,
            evaluations_run: "5".into(),
            last_evaluated_at: Some(3000),
            pass_rate: Some("0.95".into()),
        }
    }

    fn make_stored_classification(id: &str, sensitivity: DataSensitivity) -> StoredClassification {
        StoredClassification {
            classification_id: id.into(),
            dataset_ref: "ds-1".into(),
            sensitivity_level: sensitivity,
            classified_at: 1000,
            review_due_at: None,
            metadata: HashMap::new(),
            stored_at: 2000,
            review_count: "0".into(),
            last_reviewed_at: None,
        }
    }

    fn make_stored_lineage(id: &str) -> StoredLineageRecord {
        StoredLineageRecord {
            record_id: id.into(),
            dataset_ref: "ds-1".into(),
            stage: "Source".into(),
            predecessor_refs: Vec::new(),
            successor_refs: Vec::new(),
            recorded_at: 1000,
            recorded_by: "agent".into(),
            metadata: HashMap::new(),
            stored_at: 2000,
            lineage_hash: "abc123".into(),
        }
    }

    fn make_stored_schema(id: &str) -> StoredSchemaRecord {
        StoredSchemaRecord {
            schema_id: id.into(),
            dataset_ref: "ds-1".into(),
            version: "1.0.0".into(),
            format: "JsonSchema".into(),
            field_count: "3".into(),
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
            stored_at: 2000,
            schema_hash: "def456".into(),
            compatibility_with_previous: None,
        }
    }

    fn make_stored_catalog(id: &str) -> StoredCatalogEntry {
        StoredCatalogEntry {
            entry_id: id.into(),
            dataset_ref: "ds-1".into(),
            dataset_name: "Test".into(),
            owner_id: "owner".into(),
            steward_id: Some("steward".into()),
            domain: Some("analytics".into()),
            status: CatalogEntryStatus::Active,
            registered_at: 1000,
            metadata: HashMap::new(),
            stored_at: 2000,
            completeness_score: "1.00".into(),
        }
    }

    #[test]
    fn test_json_exporter_quality() {
        let exporter = JsonDataExporter;
        let rules = vec![make_stored_rule("qr-1")];
        let output = exporter.export_quality_report(&rules).unwrap();
        assert!(output.contains("quality_report"));
        assert!(output.contains("qr-1"));
    }

    #[test]
    fn test_json_exporter_classification() {
        let exporter = JsonDataExporter;
        let cls = vec![make_stored_classification("cls-1", DataSensitivity::Restricted)];
        let output = exporter.export_classification_report(&cls).unwrap();
        assert!(output.contains("classification_report"));
    }

    #[test]
    fn test_json_exporter_lineage() {
        let exporter = JsonDataExporter;
        let records = vec![make_stored_lineage("lr-1")];
        let output = exporter.export_lineage_report(&records).unwrap();
        assert!(output.contains("lineage_report"));
    }

    #[test]
    fn test_json_exporter_schema() {
        let exporter = JsonDataExporter;
        let schemas = vec![make_stored_schema("sch-1")];
        let output = exporter.export_schema_report(&schemas).unwrap();
        assert!(output.contains("schema_report"));
    }

    #[test]
    fn test_json_exporter_catalog() {
        let exporter = JsonDataExporter;
        let entries = vec![make_stored_catalog("ce-1")];
        let output = exporter.export_catalog_inventory(&entries).unwrap();
        assert!(output.contains("catalog_inventory"));
    }

    #[test]
    fn test_json_exporter_freshness() {
        let exporter = JsonDataExporter;
        let assessments = vec![StoredFreshnessAssessment {
            assessment_id: "fa-1".into(),
            policy_id: "fp-1".into(),
            dataset_ref: "ds-1".into(),
            last_updated_at: 1000,
            assessed_at: 2000,
            freshness_status: "Fresh".into(),
            sla_met: true,
            stored_at: 3000,
        }];
        let output = exporter.export_freshness_report(&assessments).unwrap();
        assert!(output.contains("freshness_report"));
    }

    #[test]
    fn test_json_exporter_batch() {
        let exporter = JsonDataExporter;
        let output = exporter.export_batch(
            &[make_stored_rule("qr-1")],
            &[make_stored_classification("cls-1", DataSensitivity::Public)],
            &[make_stored_lineage("lr-1")],
        ).unwrap();
        assert!(output.contains("data_governance_batch"));
    }

    #[test]
    fn test_quality_report_exporter() {
        let exporter = DataQualityReportExporter;
        let rules = vec![make_stored_rule("qr-1")];
        let output = exporter.export_quality_report(&rules).unwrap();
        assert!(output.contains("data_quality_assessment"));
        assert_eq!(exporter.format_name(), "DataQualityReport");
    }

    #[test]
    fn test_lineage_exporter() {
        let exporter = DataLineageExporter;
        let records = vec![make_stored_lineage("lr-1")];
        let output = exporter.export_lineage_report(&records).unwrap();
        assert!(output.contains("lineage_documentation"));
        assert_eq!(exporter.format_name(), "DataLineage");
    }

    #[test]
    fn test_catalog_exporter() {
        let exporter = DataCatalogExporter;
        let entries = vec![make_stored_catalog("ce-1")];
        let output = exporter.export_catalog_inventory(&entries).unwrap();
        assert!(output.contains("catalog_inventory_governance"));
        assert_eq!(exporter.format_name(), "DataCatalog");
    }

    #[test]
    fn test_gdpr_data_mapping_exporter() {
        let exporter = GdprDataMappingExporter;
        let cls = vec![
            make_stored_classification("cls-1", DataSensitivity::Restricted),
            make_stored_classification("cls-2", DataSensitivity::Public),
        ];
        let output = exporter.export_classification_report(&cls).unwrap();
        assert!(output.contains("gdpr_article_30"));
        // Only Restricted should be in the output, not Public
        assert!(output.contains("cls-1"));
        assert_eq!(exporter.format_name(), "GdprDataMapping");
    }

    #[test]
    fn test_format_names_and_content_types() {
        assert_eq!(JsonDataExporter.format_name(), "JSON");
        assert_eq!(JsonDataExporter.content_type(), "application/json");
        assert_eq!(DataQualityReportExporter.content_type(), "application/json");
        assert_eq!(DataLineageExporter.content_type(), "application/json");
        assert_eq!(DataCatalogExporter.content_type(), "application/json");
        assert_eq!(GdprDataMappingExporter.content_type(), "application/json");
    }
}
