// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Data governance backend trait. Defines the pluggable storage
// contract for quality rules, classifications, lineage records, access
// policies, schema records, catalog entries, freshness policies and
// assessments. Reference implementation: InMemoryDataGovernanceBackend.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::access::DataAccessPolicy;
use crate::catalog::{CatalogEntry, CatalogEntryStatus, CatalogGovernancePolicy};
use crate::classification::{DataClassification, DataSensitivity};
use crate::data_hash::{hash_lineage_record, hash_schema_record};
use crate::error::DataError;
use crate::freshness::{FreshnessAlert, FreshnessAssessment, FreshnessPolicy};
use crate::lineage::{LineageChain, LineageRecord};
use crate::quality::{DataQualityDimension, DataQualityPolicy, DataQualityResult, DataQualityRule};
use crate::schema::SchemaRecord;

// ── Stored wrapper types ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredQualityRule {
    pub rule_id: String,
    pub rule_name: String,
    pub dimension: DataQualityDimension,
    pub target_dataset_ref: String,
    pub target_field: Option<String>,
    pub severity: String,
    pub enabled: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub evaluations_run: String,
    pub last_evaluated_at: Option<i64>,
    pub pass_rate: Option<String>,
}

impl StoredQualityRule {
    pub fn from_rule(rule: &DataQualityRule, stored_at: i64) -> Self {
        Self {
            rule_id: rule.rule_id.clone(),
            rule_name: rule.rule_name.clone(),
            dimension: rule.dimension.clone(),
            target_dataset_ref: rule.target_dataset_ref.clone(),
            target_field: rule.target_field.clone(),
            severity: rule.severity.to_string(),
            enabled: rule.enabled,
            created_at: rule.created_at,
            metadata: rule.metadata.clone(),
            stored_at,
            evaluations_run: "0".to_string(),
            last_evaluated_at: None,
            pass_rate: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredClassification {
    pub classification_id: String,
    pub dataset_ref: String,
    pub sensitivity_level: DataSensitivity,
    pub classified_at: i64,
    pub review_due_at: Option<i64>,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub review_count: String,
    pub last_reviewed_at: Option<i64>,
}

impl StoredClassification {
    pub fn from_classification(cls: &DataClassification, stored_at: i64) -> Self {
        Self {
            classification_id: cls.classification_id.clone(),
            dataset_ref: cls.dataset_ref.clone(),
            sensitivity_level: cls.sensitivity_level.clone(),
            classified_at: cls.classified_at,
            review_due_at: cls.review_due_at,
            metadata: cls.metadata.clone(),
            stored_at,
            review_count: "0".to_string(),
            last_reviewed_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLineageRecord {
    pub record_id: String,
    pub dataset_ref: String,
    pub stage: String,
    pub predecessor_refs: Vec<String>,
    pub successor_refs: Vec<String>,
    pub recorded_at: i64,
    pub recorded_by: String,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub lineage_hash: String,
}

impl StoredLineageRecord {
    pub fn from_record(record: &LineageRecord, stored_at: i64) -> Self {
        let lineage_hash = hash_lineage_record(record);
        Self {
            record_id: record.record_id.clone(),
            dataset_ref: record.dataset_ref.clone(),
            stage: record.stage.to_string(),
            predecessor_refs: record.predecessor_refs.clone(),
            successor_refs: record.successor_refs.clone(),
            recorded_at: record.recorded_at,
            recorded_by: record.recorded_by.clone(),
            metadata: record.metadata.clone(),
            stored_at,
            lineage_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSchemaRecord {
    pub schema_id: String,
    pub dataset_ref: String,
    pub version: String,
    pub format: String,
    pub field_count: String,
    pub registered_at: i64,
    pub registered_by: String,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub schema_hash: String,
    pub compatibility_with_previous: Option<String>,
}

impl StoredSchemaRecord {
    pub fn from_record(record: &SchemaRecord, stored_at: i64) -> Self {
        let schema_hash = hash_schema_record(record);
        Self {
            schema_id: record.schema_id.clone(),
            dataset_ref: record.dataset_ref.clone(),
            version: record.version.clone(),
            format: record.format.to_string(),
            field_count: record.fields.len().to_string(),
            registered_at: record.registered_at,
            registered_by: record.registered_by.clone(),
            metadata: record.metadata.clone(),
            stored_at,
            schema_hash,
            compatibility_with_previous: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCatalogEntry {
    pub entry_id: String,
    pub dataset_ref: String,
    pub dataset_name: String,
    pub owner_id: String,
    pub steward_id: Option<String>,
    pub domain: Option<String>,
    pub status: CatalogEntryStatus,
    pub registered_at: i64,
    pub metadata: HashMap<String, String>,
    pub stored_at: i64,
    pub completeness_score: String,
}

impl StoredCatalogEntry {
    pub fn from_entry(entry: &CatalogEntry, policy: Option<&CatalogGovernancePolicy>, stored_at: i64) -> Self {
        let completeness_score = Self::compute_completeness(entry, policy);
        Self {
            entry_id: entry.entry_id.clone(),
            dataset_ref: entry.dataset_ref.clone(),
            dataset_name: entry.dataset_name.clone(),
            owner_id: entry.owner_id.clone(),
            steward_id: entry.steward_id.clone(),
            domain: entry.domain.clone(),
            status: entry.status.clone(),
            registered_at: entry.registered_at,
            metadata: entry.metadata.clone(),
            stored_at,
            completeness_score,
        }
    }

    fn compute_completeness(entry: &CatalogEntry, policy: Option<&CatalogGovernancePolicy>) -> String {
        let policy = match policy {
            Some(p) => p,
            None => return "1.00".to_string(),
        };
        let mut total = 0u32;
        let mut met = 0u32;
        if policy.require_description {
            total += 1;
            if !entry.description.is_empty() {
                met += 1;
            }
        }
        if policy.require_owner {
            total += 1;
            if !entry.owner_id.is_empty() {
                met += 1;
            }
        }
        if policy.require_steward {
            total += 1;
            if entry.steward_id.is_some() {
                met += 1;
            }
        }
        if policy.require_schema {
            total += 1;
            if entry.schema_ref.is_some() {
                met += 1;
            }
        }
        if policy.require_classification {
            total += 1;
            if entry.classification_ref.is_some() {
                met += 1;
            }
        }
        if policy.require_quality_policy {
            total += 1;
            if entry.quality_policy_ref.is_some() {
                met += 1;
            }
        }
        if policy.require_freshness_policy {
            total += 1;
            if entry.freshness_policy_ref.is_some() {
                met += 1;
            }
        }
        if let Some(min_tags) = policy.minimum_tag_count {
            total += 1;
            if entry.tags.len() >= min_tags {
                met += 1;
            }
        }
        if total == 0 {
            return "1.00".to_string();
        }
        let ratio = met as f64 / total as f64;
        format!("{ratio:.2}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFreshnessAssessment {
    pub assessment_id: String,
    pub policy_id: String,
    pub dataset_ref: String,
    pub last_updated_at: i64,
    pub assessed_at: i64,
    pub freshness_status: String,
    pub sla_met: bool,
    pub stored_at: i64,
}

impl StoredFreshnessAssessment {
    pub fn from_assessment(a: &FreshnessAssessment, stored_at: i64) -> Self {
        Self {
            assessment_id: a.assessment_id.clone(),
            policy_id: a.policy_id.clone(),
            dataset_ref: a.dataset_ref.clone(),
            last_updated_at: a.last_updated_at,
            assessed_at: a.assessed_at,
            freshness_status: a.freshness_status.to_string(),
            sla_met: a.sla_met,
            stored_at,
        }
    }
}

// ── DataBackendInfo ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataBackendInfo {
    pub backend_id: String,
    pub backend_type: String,
    pub rule_count: String,
    pub classification_count: String,
    pub lineage_record_count: String,
    pub schema_count: String,
    pub catalog_entry_count: String,
    pub freshness_policy_count: String,
}

// ── DataGovernanceBackend trait ───────────────────────────────────────

pub trait DataGovernanceBackend {
    fn store_quality_rule(&mut self, rule: &DataQualityRule, stored_at: i64) -> Result<StoredQualityRule, DataError>;
    fn retrieve_quality_rule(&self, rule_id: &str) -> Result<StoredQualityRule, DataError>;
    fn list_rules_by_dataset(&self, dataset_ref: &str) -> Vec<StoredQualityRule>;
    fn list_rules_by_dimension(&self, dimension: &str) -> Vec<StoredQualityRule>;
    fn rule_count(&self) -> usize;

    fn store_quality_result(&mut self, result: &DataQualityResult, stored_at: i64) -> Result<(), DataError>;
    fn list_results_by_rule(&self, rule_id: &str) -> Vec<DataQualityResult>;

    fn store_quality_policy(&mut self, policy: &DataQualityPolicy, stored_at: i64) -> Result<(), DataError>;
    fn retrieve_quality_policy(&self, policy_id: &str) -> Result<DataQualityPolicy, DataError>;

    fn store_classification(&mut self, cls: &DataClassification, stored_at: i64) -> Result<StoredClassification, DataError>;
    fn retrieve_classification(&self, classification_id: &str) -> Result<StoredClassification, DataError>;
    fn list_classifications_by_sensitivity(&self, sensitivity: &DataSensitivity) -> Vec<StoredClassification>;
    fn classification_count(&self) -> usize;

    fn store_lineage_record(&mut self, record: &LineageRecord, stored_at: i64) -> Result<StoredLineageRecord, DataError>;
    fn retrieve_lineage_record(&self, record_id: &str) -> Result<StoredLineageRecord, DataError>;
    fn list_lineage_by_dataset(&self, dataset_ref: &str) -> Vec<StoredLineageRecord>;

    fn store_lineage_chain(&mut self, chain: &LineageChain, stored_at: i64) -> Result<(), DataError>;
    fn retrieve_lineage_chain(&self, chain_id: &str) -> Result<LineageChain, DataError>;

    fn store_access_policy(&mut self, policy: &DataAccessPolicy, stored_at: i64) -> Result<(), DataError>;
    fn retrieve_access_policy(&self, policy_id: &str) -> Result<DataAccessPolicy, DataError>;
    fn list_access_policies_by_dataset(&self, dataset_ref: &str) -> Vec<DataAccessPolicy>;

    fn store_schema_record(&mut self, record: &SchemaRecord, stored_at: i64) -> Result<StoredSchemaRecord, DataError>;
    fn retrieve_schema_record(&self, schema_id: &str) -> Result<StoredSchemaRecord, DataError>;
    fn list_schemas_by_dataset(&self, dataset_ref: &str) -> Vec<StoredSchemaRecord>;

    fn store_catalog_entry(&mut self, entry: &CatalogEntry, policy: Option<&CatalogGovernancePolicy>, stored_at: i64) -> Result<StoredCatalogEntry, DataError>;
    fn retrieve_catalog_entry(&self, entry_id: &str) -> Result<StoredCatalogEntry, DataError>;
    fn list_catalog_entries_by_status(&self, status: &str) -> Vec<StoredCatalogEntry>;
    fn list_catalog_entries_by_domain(&self, domain: &str) -> Vec<StoredCatalogEntry>;
    fn catalog_entry_count(&self) -> usize;

    fn store_freshness_policy(&mut self, policy: &FreshnessPolicy, stored_at: i64) -> Result<(), DataError>;
    fn retrieve_freshness_policy(&self, policy_id: &str) -> Result<FreshnessPolicy, DataError>;

    fn store_freshness_assessment(&mut self, assessment: &FreshnessAssessment, stored_at: i64) -> Result<StoredFreshnessAssessment, DataError>;
    fn list_assessments_by_dataset(&self, dataset_ref: &str) -> Vec<StoredFreshnessAssessment>;

    fn store_freshness_alert(&mut self, alert: &FreshnessAlert, stored_at: i64) -> Result<(), DataError>;
    fn list_alerts_by_dataset(&self, dataset_ref: &str) -> Vec<FreshnessAlert>;

    fn flush(&mut self) -> Result<(), DataError>;
    fn backend_info(&self) -> DataBackendInfo;
}

// ── InMemoryDataGovernanceBackend ────────────────────────────────────

pub struct InMemoryDataGovernanceBackend {
    backend_id: String,
    rules: HashMap<String, StoredQualityRule>,
    results: HashMap<String, Vec<DataQualityResult>>,
    policies: HashMap<String, DataQualityPolicy>,
    classifications: HashMap<String, StoredClassification>,
    lineage_records: HashMap<String, StoredLineageRecord>,
    lineage_chains: HashMap<String, LineageChain>,
    access_policies: HashMap<String, DataAccessPolicy>,
    schemas: HashMap<String, StoredSchemaRecord>,
    catalog_entries: HashMap<String, StoredCatalogEntry>,
    freshness_policies: HashMap<String, FreshnessPolicy>,
    freshness_assessments: HashMap<String, Vec<StoredFreshnessAssessment>>,
    freshness_alerts: HashMap<String, Vec<FreshnessAlert>>,
}

impl InMemoryDataGovernanceBackend {
    pub fn new(backend_id: impl Into<String>) -> Self {
        Self {
            backend_id: backend_id.into(),
            rules: HashMap::new(),
            results: HashMap::new(),
            policies: HashMap::new(),
            classifications: HashMap::new(),
            lineage_records: HashMap::new(),
            lineage_chains: HashMap::new(),
            access_policies: HashMap::new(),
            schemas: HashMap::new(),
            catalog_entries: HashMap::new(),
            freshness_policies: HashMap::new(),
            freshness_assessments: HashMap::new(),
            freshness_alerts: HashMap::new(),
        }
    }
}

impl DataGovernanceBackend for InMemoryDataGovernanceBackend {
    fn store_quality_rule(&mut self, rule: &DataQualityRule, stored_at: i64) -> Result<StoredQualityRule, DataError> {
        let stored = StoredQualityRule::from_rule(rule, stored_at);
        self.rules.insert(rule.rule_id.clone(), stored.clone());
        Ok(stored)
    }

    fn retrieve_quality_rule(&self, rule_id: &str) -> Result<StoredQualityRule, DataError> {
        self.rules.get(rule_id).cloned().ok_or_else(|| DataError::RuleNotFound(rule_id.to_string()))
    }

    fn list_rules_by_dataset(&self, dataset_ref: &str) -> Vec<StoredQualityRule> {
        self.rules.values().filter(|r| r.target_dataset_ref == dataset_ref).cloned().collect()
    }

    fn list_rules_by_dimension(&self, dimension: &str) -> Vec<StoredQualityRule> {
        self.rules.values().filter(|r| r.dimension.to_string() == dimension).cloned().collect()
    }

    fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn store_quality_result(&mut self, result: &DataQualityResult, _stored_at: i64) -> Result<(), DataError> {
        self.results.entry(result.rule_id.clone()).or_default().push(result.clone());
        if let Some(rule) = self.rules.get_mut(&result.rule_id) {
            let count: usize = rule.evaluations_run.parse().unwrap_or(0);
            rule.evaluations_run = (count + 1).to_string();
            rule.last_evaluated_at = Some(result.evaluated_at);
        }
        Ok(())
    }

    fn list_results_by_rule(&self, rule_id: &str) -> Vec<DataQualityResult> {
        self.results.get(rule_id).cloned().unwrap_or_default()
    }

    fn store_quality_policy(&mut self, policy: &DataQualityPolicy, _stored_at: i64) -> Result<(), DataError> {
        self.policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_quality_policy(&self, policy_id: &str) -> Result<DataQualityPolicy, DataError> {
        self.policies.get(policy_id).cloned().ok_or_else(|| DataError::RuleNotFound(policy_id.to_string()))
    }

    fn store_classification(&mut self, cls: &DataClassification, stored_at: i64) -> Result<StoredClassification, DataError> {
        let stored = StoredClassification::from_classification(cls, stored_at);
        self.classifications.insert(cls.classification_id.clone(), stored.clone());
        Ok(stored)
    }

    fn retrieve_classification(&self, classification_id: &str) -> Result<StoredClassification, DataError> {
        self.classifications.get(classification_id).cloned().ok_or_else(|| DataError::ClassificationNotFound(classification_id.to_string()))
    }

    fn list_classifications_by_sensitivity(&self, sensitivity: &DataSensitivity) -> Vec<StoredClassification> {
        self.classifications.values().filter(|c| &c.sensitivity_level == sensitivity).cloned().collect()
    }

    fn classification_count(&self) -> usize {
        self.classifications.len()
    }

    fn store_lineage_record(&mut self, record: &LineageRecord, stored_at: i64) -> Result<StoredLineageRecord, DataError> {
        let stored = StoredLineageRecord::from_record(record, stored_at);
        self.lineage_records.insert(record.record_id.clone(), stored.clone());
        Ok(stored)
    }

    fn retrieve_lineage_record(&self, record_id: &str) -> Result<StoredLineageRecord, DataError> {
        self.lineage_records.get(record_id).cloned().ok_or_else(|| DataError::LineageNotFound(record_id.to_string()))
    }

    fn list_lineage_by_dataset(&self, dataset_ref: &str) -> Vec<StoredLineageRecord> {
        self.lineage_records.values().filter(|r| r.dataset_ref == dataset_ref).cloned().collect()
    }

    fn store_lineage_chain(&mut self, chain: &LineageChain, _stored_at: i64) -> Result<(), DataError> {
        self.lineage_chains.insert(chain.chain_id.clone(), chain.clone());
        Ok(())
    }

    fn retrieve_lineage_chain(&self, chain_id: &str) -> Result<LineageChain, DataError> {
        self.lineage_chains.get(chain_id).cloned().ok_or_else(|| DataError::LineageNotFound(chain_id.to_string()))
    }

    fn store_access_policy(&mut self, policy: &DataAccessPolicy, _stored_at: i64) -> Result<(), DataError> {
        self.access_policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_access_policy(&self, policy_id: &str) -> Result<DataAccessPolicy, DataError> {
        self.access_policies.get(policy_id).cloned().ok_or_else(|| DataError::DatasetNotFound(policy_id.to_string()))
    }

    fn list_access_policies_by_dataset(&self, dataset_ref: &str) -> Vec<DataAccessPolicy> {
        self.access_policies.values().filter(|p| p.dataset_ref == dataset_ref).cloned().collect()
    }

    fn store_schema_record(&mut self, record: &SchemaRecord, stored_at: i64) -> Result<StoredSchemaRecord, DataError> {
        let stored = StoredSchemaRecord::from_record(record, stored_at);
        self.schemas.insert(record.schema_id.clone(), stored.clone());
        Ok(stored)
    }

    fn retrieve_schema_record(&self, schema_id: &str) -> Result<StoredSchemaRecord, DataError> {
        self.schemas.get(schema_id).cloned().ok_or_else(|| DataError::SchemaNotFound(schema_id.to_string()))
    }

    fn list_schemas_by_dataset(&self, dataset_ref: &str) -> Vec<StoredSchemaRecord> {
        self.schemas.values().filter(|s| s.dataset_ref == dataset_ref).cloned().collect()
    }

    fn store_catalog_entry(&mut self, entry: &CatalogEntry, policy: Option<&CatalogGovernancePolicy>, stored_at: i64) -> Result<StoredCatalogEntry, DataError> {
        let stored = StoredCatalogEntry::from_entry(entry, policy, stored_at);
        self.catalog_entries.insert(entry.entry_id.clone(), stored.clone());
        Ok(stored)
    }

    fn retrieve_catalog_entry(&self, entry_id: &str) -> Result<StoredCatalogEntry, DataError> {
        self.catalog_entries.get(entry_id).cloned().ok_or_else(|| DataError::CatalogEntryNotFound(entry_id.to_string()))
    }

    fn list_catalog_entries_by_status(&self, status: &str) -> Vec<StoredCatalogEntry> {
        self.catalog_entries.values().filter(|e| e.status.to_string() == status).cloned().collect()
    }

    fn list_catalog_entries_by_domain(&self, domain: &str) -> Vec<StoredCatalogEntry> {
        self.catalog_entries.values().filter(|e| e.domain.as_deref() == Some(domain)).cloned().collect()
    }

    fn catalog_entry_count(&self) -> usize {
        self.catalog_entries.len()
    }

    fn store_freshness_policy(&mut self, policy: &FreshnessPolicy, _stored_at: i64) -> Result<(), DataError> {
        self.freshness_policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn retrieve_freshness_policy(&self, policy_id: &str) -> Result<FreshnessPolicy, DataError> {
        self.freshness_policies.get(policy_id).cloned().ok_or_else(|| DataError::DatasetNotFound(policy_id.to_string()))
    }

    fn store_freshness_assessment(&mut self, assessment: &FreshnessAssessment, stored_at: i64) -> Result<StoredFreshnessAssessment, DataError> {
        let stored = StoredFreshnessAssessment::from_assessment(assessment, stored_at);
        self.freshness_assessments.entry(assessment.dataset_ref.clone()).or_default().push(stored.clone());
        Ok(stored)
    }

    fn list_assessments_by_dataset(&self, dataset_ref: &str) -> Vec<StoredFreshnessAssessment> {
        self.freshness_assessments.get(dataset_ref).cloned().unwrap_or_default()
    }

    fn store_freshness_alert(&mut self, alert: &FreshnessAlert, _stored_at: i64) -> Result<(), DataError> {
        self.freshness_alerts.entry(alert.dataset_ref.clone()).or_default().push(alert.clone());
        Ok(())
    }

    fn list_alerts_by_dataset(&self, dataset_ref: &str) -> Vec<FreshnessAlert> {
        self.freshness_alerts.get(dataset_ref).cloned().unwrap_or_default()
    }

    fn flush(&mut self) -> Result<(), DataError> {
        self.rules.clear();
        self.results.clear();
        self.policies.clear();
        self.classifications.clear();
        self.lineage_records.clear();
        self.lineage_chains.clear();
        self.access_policies.clear();
        self.schemas.clear();
        self.catalog_entries.clear();
        self.freshness_policies.clear();
        self.freshness_assessments.clear();
        self.freshness_alerts.clear();
        Ok(())
    }

    fn backend_info(&self) -> DataBackendInfo {
        DataBackendInfo {
            backend_id: self.backend_id.clone(),
            backend_type: "InMemory".to_string(),
            rule_count: self.rules.len().to_string(),
            classification_count: self.classifications.len().to_string(),
            lineage_record_count: self.lineage_records.len().to_string(),
            schema_count: self.schemas.len().to_string(),
            catalog_entry_count: self.catalog_entries.len().to_string(),
            freshness_policy_count: self.freshness_policies.len().to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::ClassificationMethod;
    use crate::freshness::{FreshnessStatus, UpdateFrequency};
    use crate::lineage::LineageStage;
    use crate::quality::{QualityExpectation, QualitySeverity};
    use crate::schema::{SchemaField, SchemaFormat};

    fn make_rule(id: &str, dataset: &str) -> DataQualityRule {
        DataQualityRule {
            rule_id: id.into(),
            rule_name: format!("rule_{id}"),
            dimension: DataQualityDimension::Completeness,
            target_dataset_ref: dataset.into(),
            target_field: None,
            expectation: QualityExpectation::NotNull,
            severity: QualitySeverity::Critical,
            enabled: true,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn make_classification(id: &str, dataset: &str, sensitivity: DataSensitivity) -> DataClassification {
        DataClassification {
            classification_id: id.into(),
            dataset_ref: dataset.into(),
            sensitivity_level: sensitivity,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Manual { classified_by: "admin".into() },
            classified_at: 1000,
            review_due_at: None,
            metadata: HashMap::new(),
        }
    }

    fn make_lineage_record(id: &str, dataset: &str) -> LineageRecord {
        LineageRecord {
            record_id: id.into(),
            dataset_ref: dataset.into(),
            stage: LineageStage::Source { origin: "s3".into() },
            predecessor_refs: Vec::new(),
            successor_refs: Vec::new(),
            transformation_metadata: HashMap::new(),
            attestation_ref: None,
            recorded_at: 1000,
            recorded_by: "agent".into(),
            metadata: HashMap::new(),
        }
    }

    fn make_schema_record(id: &str, dataset: &str) -> SchemaRecord {
        SchemaRecord {
            schema_id: id.into(),
            dataset_ref: dataset.into(),
            version: "1.0.0".into(),
            fields: vec![SchemaField {
                field_name: "id".into(),
                field_type: "string".into(),
                nullable: false,
                description: None,
                sensitivity_label: None,
                constraints: Vec::new(),
            }],
            format: SchemaFormat::JsonSchema,
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
        }
    }

    fn make_catalog_entry(id: &str, dataset: &str) -> CatalogEntry {
        CatalogEntry {
            entry_id: id.into(),
            dataset_ref: dataset.into(),
            dataset_name: "Test Dataset".into(),
            description: "A test dataset".into(),
            owner_id: "owner-1".into(),
            steward_id: Some("steward-1".into()),
            domain: Some("analytics".into()),
            tags: vec!["test".into()],
            schema_ref: None,
            classification_ref: None,
            quality_policy_ref: None,
            freshness_policy_ref: None,
            registered_at: 1000,
            last_updated_at: None,
            status: CatalogEntryStatus::Active,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_rule() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let rule = make_rule("qr-1", "ds-users");
        let stored = backend.store_quality_rule(&rule, 2000).unwrap();
        assert_eq!(stored.rule_id, "qr-1");
        assert_eq!(stored.evaluations_run, "0");
        assert_eq!(stored.stored_at, 2000);
        let retrieved = backend.retrieve_quality_rule("qr-1").unwrap();
        assert_eq!(retrieved, stored);
    }

    #[test]
    fn test_list_rules_by_dataset() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_quality_rule(&make_rule("qr-1", "ds-users"), 2000).unwrap();
        backend.store_quality_rule(&make_rule("qr-2", "ds-orders"), 2000).unwrap();
        backend.store_quality_rule(&make_rule("qr-3", "ds-users"), 2000).unwrap();
        assert_eq!(backend.list_rules_by_dataset("ds-users").len(), 2);
        assert_eq!(backend.list_rules_by_dataset("ds-orders").len(), 1);
    }

    #[test]
    fn test_list_rules_by_dimension() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_quality_rule(&make_rule("qr-1", "ds-1"), 2000).unwrap();
        let by_dim = backend.list_rules_by_dimension("Completeness");
        assert_eq!(by_dim.len(), 1);
    }

    #[test]
    fn test_store_quality_result_updates_rule() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_quality_rule(&make_rule("qr-1", "ds-1"), 2000).unwrap();
        let result = DataQualityResult {
            result_id: "res-1".into(),
            rule_id: "qr-1".into(),
            dataset_ref: "ds-1".into(),
            passed: true,
            measured_value: Some("ok".into()),
            violation_count: "0".into(),
            violation_sample: Vec::new(),
            evaluated_at: 3000,
            evaluated_by: "engine".into(),
            metadata: HashMap::new(),
        };
        backend.store_quality_result(&result, 3000).unwrap();
        let rule = backend.retrieve_quality_rule("qr-1").unwrap();
        assert_eq!(rule.evaluations_run, "1");
        assert_eq!(rule.last_evaluated_at, Some(3000));
        let results = backend.list_results_by_rule("qr-1");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_classification() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let cls = make_classification("cls-1", "ds-users", DataSensitivity::Confidential);
        let stored = backend.store_classification(&cls, 2000).unwrap();
        assert_eq!(stored.classification_id, "cls-1");
        assert_eq!(stored.review_count, "0");
        let retrieved = backend.retrieve_classification("cls-1").unwrap();
        assert_eq!(retrieved, stored);
    }

    #[test]
    fn test_list_classifications_by_sensitivity() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_classification(&make_classification("cls-1", "ds-1", DataSensitivity::Restricted), 2000).unwrap();
        backend.store_classification(&make_classification("cls-2", "ds-2", DataSensitivity::Public), 2000).unwrap();
        assert_eq!(backend.list_classifications_by_sensitivity(&DataSensitivity::Restricted).len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_lineage_record() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let record = make_lineage_record("lr-1", "ds-orders");
        let stored = backend.store_lineage_record(&record, 2000).unwrap();
        assert_eq!(stored.record_id, "lr-1");
        assert_eq!(stored.lineage_hash.len(), 64);
        let retrieved = backend.retrieve_lineage_record("lr-1").unwrap();
        assert_eq!(retrieved, stored);
    }

    #[test]
    fn test_list_lineage_by_dataset() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_lineage_record(&make_lineage_record("lr-1", "ds-orders"), 2000).unwrap();
        backend.store_lineage_record(&make_lineage_record("lr-2", "ds-users"), 2000).unwrap();
        assert_eq!(backend.list_lineage_by_dataset("ds-orders").len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_schema_record() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let schema = make_schema_record("sch-1", "ds-users");
        let stored = backend.store_schema_record(&schema, 2000).unwrap();
        assert_eq!(stored.schema_id, "sch-1");
        assert_eq!(stored.schema_hash.len(), 64);
        let retrieved = backend.retrieve_schema_record("sch-1").unwrap();
        assert_eq!(retrieved, stored);
    }

    #[test]
    fn test_store_and_retrieve_catalog_entry() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let entry = make_catalog_entry("ce-1", "ds-users");
        let stored = backend.store_catalog_entry(&entry, None, 2000).unwrap();
        assert_eq!(stored.entry_id, "ce-1");
        assert_eq!(stored.completeness_score, "1.00");
        let retrieved = backend.retrieve_catalog_entry("ce-1").unwrap();
        assert_eq!(retrieved, stored);
    }

    #[test]
    fn test_catalog_completeness_with_policy() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let entry = make_catalog_entry("ce-1", "ds-users");
        let policy = CatalogGovernancePolicy {
            policy_id: "cgp-1".into(),
            require_description: true,
            require_owner: true,
            require_steward: true,
            require_schema: true,
            require_classification: true,
            require_quality_policy: true,
            require_freshness_policy: true,
            minimum_tag_count: Some(1),
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let stored = backend.store_catalog_entry(&entry, Some(&policy), 2000).unwrap();
        // entry has description, owner, steward, tags>=1 (4 met), but no schema_ref, classification_ref, quality_policy_ref, freshness_policy_ref (4 not met)
        assert_eq!(stored.completeness_score, "0.50");
    }

    #[test]
    fn test_list_catalog_by_status_and_domain() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_catalog_entry(&make_catalog_entry("ce-1", "ds-1"), None, 2000).unwrap();
        assert_eq!(backend.list_catalog_entries_by_status("Active").len(), 1);
        assert_eq!(backend.list_catalog_entries_by_domain("analytics").len(), 1);
        assert_eq!(backend.list_catalog_entries_by_domain("finance").len(), 0);
    }

    #[test]
    fn test_store_freshness_assessment() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let assessment = FreshnessAssessment {
            assessment_id: "fa-1".into(),
            policy_id: "fp-1".into(),
            dataset_ref: "ds-orders".into(),
            last_updated_at: 1000,
            assessed_at: 2000,
            freshness_status: FreshnessStatus::Fresh { hours_since_update: "1.00".into() },
            sla_met: true,
            metadata: HashMap::new(),
        };
        let stored = backend.store_freshness_assessment(&assessment, 3000).unwrap();
        assert_eq!(stored.assessment_id, "fa-1");
        assert!(stored.sla_met);
        let list = backend.list_assessments_by_dataset("ds-orders");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_store_freshness_alert() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let alert = FreshnessAlert {
            alert_id: "fal-1".into(),
            assessment_id: "fa-1".into(),
            dataset_ref: "ds-orders".into(),
            severity: QualitySeverity::Warning,
            message: "stale".into(),
            alerted_at: 2000,
            acknowledged_by: None,
            acknowledged_at: None,
            metadata: HashMap::new(),
        };
        backend.store_freshness_alert(&alert, 3000).unwrap();
        let list = backend.list_alerts_by_dataset("ds-orders");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_store_freshness_policy() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let policy = FreshnessPolicy {
            policy_id: "fp-1".into(),
            dataset_ref: "ds-orders".into(),
            expected_update_frequency: UpdateFrequency::Hourly,
            staleness_threshold_hours: "4".into(),
            alerting_severity: QualitySeverity::Warning,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        backend.store_freshness_policy(&policy, 2000).unwrap();
        let retrieved = backend.retrieve_freshness_policy("fp-1").unwrap();
        assert_eq!(retrieved.policy_id, "fp-1");
    }

    #[test]
    fn test_flush_clears_all() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_quality_rule(&make_rule("qr-1", "ds-1"), 2000).unwrap();
        backend.store_classification(&make_classification("cls-1", "ds-1", DataSensitivity::Public), 2000).unwrap();
        backend.flush().unwrap();
        assert_eq!(backend.rule_count(), 0);
        assert_eq!(backend.classification_count(), 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_quality_rule(&make_rule("qr-1", "ds-1"), 2000).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.backend_id, "test-backend");
        assert_eq!(info.backend_type, "InMemory");
        assert_eq!(info.rule_count, "1");
    }

    #[test]
    fn test_store_and_retrieve_quality_policy() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let policy = DataQualityPolicy {
            policy_id: "qp-1".into(),
            dataset_ref: "ds-1".into(),
            rules: vec!["qr-1".into()],
            minimum_pass_rate: "0.95".into(),
            block_on_failure: true,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        backend.store_quality_policy(&policy, 2000).unwrap();
        let retrieved = backend.retrieve_quality_policy("qp-1").unwrap();
        assert_eq!(retrieved.policy_id, "qp-1");
    }

    #[test]
    fn test_store_and_retrieve_access_policy() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let policy = DataAccessPolicy {
            policy_id: "dap-1".into(),
            dataset_ref: "ds-users".into(),
            allowed_roles: vec!["analyst".into()],
            denied_roles: Vec::new(),
            allowed_operations: vec![crate::access::DataOperation::Read],
            require_purpose_declaration: false,
            require_audit: false,
            max_sensitivity_level: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        backend.store_access_policy(&policy, 2000).unwrap();
        let retrieved = backend.retrieve_access_policy("dap-1").unwrap();
        assert_eq!(retrieved.policy_id, "dap-1");
        let by_dataset = backend.list_access_policies_by_dataset("ds-users");
        assert_eq!(by_dataset.len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_lineage_chain() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        let chain = LineageChain {
            chain_id: "lc-1".into(),
            dataset_ref: "ds-1".into(),
            records: vec!["lr-1".into(), "lr-2".into()],
            chain_status: crate::lineage::LineageChainStatus::Complete,
            verified_at: None,
            metadata: HashMap::new(),
        };
        backend.store_lineage_chain(&chain, 2000).unwrap();
        let retrieved = backend.retrieve_lineage_chain("lc-1").unwrap();
        assert_eq!(retrieved.chain_id, "lc-1");
        assert_eq!(retrieved.records.len(), 2);
    }

    #[test]
    fn test_retrieve_nonexistent_returns_error() {
        let backend = InMemoryDataGovernanceBackend::new("test-backend");
        assert!(backend.retrieve_quality_rule("nope").is_err());
        assert!(backend.retrieve_classification("nope").is_err());
        assert!(backend.retrieve_lineage_record("nope").is_err());
        assert!(backend.retrieve_schema_record("nope").is_err());
        assert!(backend.retrieve_catalog_entry("nope").is_err());
    }

    #[test]
    fn test_list_schemas_by_dataset() {
        let mut backend = InMemoryDataGovernanceBackend::new("test-backend");
        backend.store_schema_record(&make_schema_record("sch-1", "ds-users"), 2000).unwrap();
        backend.store_schema_record(&make_schema_record("sch-2", "ds-orders"), 2000).unwrap();
        assert_eq!(backend.list_schemas_by_dataset("ds-users").len(), 1);
    }
}
