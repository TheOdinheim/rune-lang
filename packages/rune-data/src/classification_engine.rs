// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Data classification engine. Infers sensitivity levels
// from data categories, classifies datasets, checks review due dates,
// and evaluates classification policy compliance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::catalog::CatalogEntry;
use crate::classification::{
    ClassificationMethod, ClassificationPolicy, DataCategory, DataCategoryType,
    DataClassification, DataSensitivity,
};

// ── ClassificationReviewResult ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationReviewResult {
    pub classification_id: String,
    pub is_due: bool,
    pub days_overdue: Option<String>,
    pub checked_at: i64,
}

// ── ClassificationComplianceResult ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationComplianceResult {
    pub classification_id: String,
    pub compliant: bool,
    pub missing_requirements: Vec<String>,
    pub checked_at: i64,
}

// ── ClassificationEngine ─────────────────────────────────────────────

pub struct ClassificationEngine;

impl ClassificationEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn classify_dataset(
        &self,
        dataset_ref: &str,
        categories: Vec<DataCategory>,
        method: ClassificationMethod,
        timestamp: i64,
    ) -> DataClassification {
        let category_types: Vec<&DataCategoryType> =
            categories.iter().map(|c| &c.category_type).collect();
        let sensitivity = Self::infer_sensitivity_from_categories(&category_types);
        let classification_id = format!("cls-{dataset_ref}-{timestamp}");
        DataClassification {
            classification_id,
            dataset_ref: dataset_ref.to_string(),
            sensitivity_level: sensitivity,
            data_categories: categories,
            classification_method: method,
            classified_at: timestamp,
            review_due_at: None,
            metadata: HashMap::new(),
        }
    }

    pub fn infer_sensitivity_from_categories(
        categories: &[&DataCategoryType],
    ) -> DataSensitivity {
        if categories.is_empty() {
            return DataSensitivity::Public;
        }
        let mut highest = DataSensitivity::Public;
        for cat in categories {
            let level = match cat {
                DataCategoryType::ProtectedHealthInformation
                | DataCategoryType::PaymentCardData
                | DataCategoryType::ChildrenData
                | DataCategoryType::BiometricData
                | DataCategoryType::GovernmentClassified => DataSensitivity::Restricted,
                DataCategoryType::PersonallyIdentifiable
                | DataCategoryType::FinanciallyScoped
                | DataCategoryType::IntellectualProperty => DataSensitivity::Confidential,
                DataCategoryType::Custom { .. } => DataSensitivity::Internal,
            };
            if level > highest {
                highest = level;
            }
        }
        highest
    }

    pub fn check_classification_review_due(
        &self,
        classification: &DataClassification,
        current_timestamp: i64,
    ) -> ClassificationReviewResult {
        let (is_due, days_overdue) = match classification.review_due_at {
            Some(due_at) if current_timestamp >= due_at => {
                let overdue_ms = current_timestamp - due_at;
                let overdue_days = overdue_ms / (24 * 3600 * 1000);
                (true, Some(overdue_days.to_string()))
            }
            Some(_) => (false, None),
            None => (false, None),
        };
        ClassificationReviewResult {
            classification_id: classification.classification_id.clone(),
            is_due,
            days_overdue,
            checked_at: current_timestamp,
        }
    }

    pub fn evaluate_policy_compliance(
        &self,
        classification: &DataClassification,
        policy: &ClassificationPolicy,
        catalog_entry: Option<&CatalogEntry>,
        checked_at: i64,
    ) -> ClassificationComplianceResult {
        let mut missing = Vec::new();

        if policy.require_classification_before_processing {
            // Classification exists — this requirement is met
        }

        if policy.require_periodic_review && classification.review_due_at.is_none() {
            missing.push("Periodic review required but no review_due_at set".to_string());
        }

        if let Some(entry) = catalog_entry
            && entry.classification_ref.is_none()
        {
            missing.push("Catalog entry missing classification_ref".into());
        }

        let compliant = missing.is_empty();
        ClassificationComplianceResult {
            classification_id: classification.classification_id.clone(),
            compliant,
            missing_requirements: missing,
            checked_at,
        }
    }
}

impl Default for ClassificationEngine {
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
    use crate::catalog::CatalogEntryStatus;

    fn make_category(cat_type: DataCategoryType) -> DataCategory {
        DataCategory {
            category_id: "cat-test".into(),
            category_type: cat_type,
            handling_requirements: Vec::new(),
            regulatory_refs: Vec::new(),
        }
    }

    #[test]
    fn test_pii_infers_confidential() {
        let cats = vec![&DataCategoryType::PersonallyIdentifiable];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Confidential);
    }

    #[test]
    fn test_phi_infers_restricted() {
        let cats = vec![&DataCategoryType::ProtectedHealthInformation];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Restricted);
    }

    #[test]
    fn test_pci_infers_restricted() {
        let cats = vec![&DataCategoryType::PaymentCardData];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Restricted);
    }

    #[test]
    fn test_mixed_categories_takes_highest() {
        let cats = vec![
            &DataCategoryType::PersonallyIdentifiable, // Confidential
            &DataCategoryType::ProtectedHealthInformation, // Restricted
        ];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Restricted);
    }

    #[test]
    fn test_empty_categories_public() {
        let cats: Vec<&DataCategoryType> = Vec::new();
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Public);
    }

    #[test]
    fn test_custom_category_internal() {
        let cat = DataCategoryType::Custom { name: "telemetry".into() };
        let cats = vec![&cat];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Internal);
    }

    #[test]
    fn test_classify_dataset() {
        let engine = ClassificationEngine::new();
        let categories = vec![make_category(DataCategoryType::PersonallyIdentifiable)];
        let cls = engine.classify_dataset(
            "ds-users",
            categories,
            ClassificationMethod::Manual { classified_by: "alice".into() },
            1000,
        );
        assert_eq!(cls.sensitivity_level, DataSensitivity::Confidential);
        assert_eq!(cls.dataset_ref, "ds-users");
        assert_eq!(cls.data_categories.len(), 1);
    }

    #[test]
    fn test_review_due_overdue() {
        let engine = ClassificationEngine::new();
        let cls = DataClassification {
            classification_id: "cls-1".into(),
            dataset_ref: "ds-1".into(),
            sensitivity_level: DataSensitivity::Confidential,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Manual { classified_by: "alice".into() },
            classified_at: 1000,
            review_due_at: Some(5000),
            metadata: HashMap::new(),
        };
        let result = engine.check_classification_review_due(&cls, 10000);
        assert!(result.is_due);
        assert!(result.days_overdue.is_some());
    }

    #[test]
    fn test_review_not_due() {
        let engine = ClassificationEngine::new();
        let cls = DataClassification {
            classification_id: "cls-2".into(),
            dataset_ref: "ds-2".into(),
            sensitivity_level: DataSensitivity::Public,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Automated { classifier_ref: "auto".into() },
            classified_at: 1000,
            review_due_at: Some(50000),
            metadata: HashMap::new(),
        };
        let result = engine.check_classification_review_due(&cls, 10000);
        assert!(!result.is_due);
        assert!(result.days_overdue.is_none());
    }

    #[test]
    fn test_review_no_due_date() {
        let engine = ClassificationEngine::new();
        let cls = DataClassification {
            classification_id: "cls-3".into(),
            dataset_ref: "ds-3".into(),
            sensitivity_level: DataSensitivity::Public,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Automated { classifier_ref: "auto".into() },
            classified_at: 1000,
            review_due_at: None,
            metadata: HashMap::new(),
        };
        let result = engine.check_classification_review_due(&cls, 10000);
        assert!(!result.is_due);
    }

    #[test]
    fn test_policy_compliance_all_met() {
        let engine = ClassificationEngine::new();
        let cls = DataClassification {
            classification_id: "cls-c".into(),
            dataset_ref: "ds-c".into(),
            sensitivity_level: DataSensitivity::Confidential,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Manual { classified_by: "alice".into() },
            classified_at: 1000,
            review_due_at: Some(5000),
            metadata: HashMap::new(),
        };
        let policy = ClassificationPolicy {
            policy_id: "cp-1".into(),
            require_classification_before_processing: true,
            require_periodic_review: true,
            review_interval_days: Some("90".into()),
            auto_classify_on_ingestion: false,
            escalation_target: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let result = engine.evaluate_policy_compliance(&cls, &policy, None, 2000);
        assert!(result.compliant);
        assert!(result.missing_requirements.is_empty());
    }

    #[test]
    fn test_policy_compliance_missing_review_date() {
        let engine = ClassificationEngine::new();
        let cls = DataClassification {
            classification_id: "cls-d".into(),
            dataset_ref: "ds-d".into(),
            sensitivity_level: DataSensitivity::Internal,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Manual { classified_by: "bob".into() },
            classified_at: 1000,
            review_due_at: None,
            metadata: HashMap::new(),
        };
        let policy = ClassificationPolicy {
            policy_id: "cp-2".into(),
            require_classification_before_processing: true,
            require_periodic_review: true,
            review_interval_days: Some("90".into()),
            auto_classify_on_ingestion: false,
            escalation_target: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let result = engine.evaluate_policy_compliance(&cls, &policy, None, 2000);
        assert!(!result.compliant);
        assert!(!result.missing_requirements.is_empty());
    }

    #[test]
    fn test_policy_compliance_missing_catalog_classification_ref() {
        let engine = ClassificationEngine::new();
        let cls = DataClassification {
            classification_id: "cls-e".into(),
            dataset_ref: "ds-e".into(),
            sensitivity_level: DataSensitivity::Public,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Manual { classified_by: "carol".into() },
            classified_at: 1000,
            review_due_at: Some(5000),
            metadata: HashMap::new(),
        };
        let policy = ClassificationPolicy {
            policy_id: "cp-3".into(),
            require_classification_before_processing: true,
            require_periodic_review: true,
            review_interval_days: None,
            auto_classify_on_ingestion: false,
            escalation_target: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let entry = CatalogEntry {
            entry_id: "ce-1".into(),
            dataset_ref: "ds-e".into(),
            dataset_name: "Test".into(),
            description: "test".into(),
            owner_id: "owner".into(),
            steward_id: None,
            domain: None,
            tags: Vec::new(),
            schema_ref: None,
            classification_ref: None, // missing!
            quality_policy_ref: None,
            freshness_policy_ref: None,
            registered_at: 1000,
            last_updated_at: None,
            status: CatalogEntryStatus::Active,
            metadata: HashMap::new(),
        };
        let result = engine.evaluate_policy_compliance(&cls, &policy, Some(&entry), 2000);
        assert!(!result.compliant);
        assert!(result.missing_requirements.iter().any(|r| r.contains("classification_ref")));
    }

    #[test]
    fn test_children_data_restricted() {
        let cats = vec![&DataCategoryType::ChildrenData];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Restricted);
    }

    #[test]
    fn test_biometric_data_restricted() {
        let cats = vec![&DataCategoryType::BiometricData];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Restricted);
    }

    #[test]
    fn test_ip_confidential() {
        let cats = vec![&DataCategoryType::IntellectualProperty];
        let sensitivity = ClassificationEngine::infer_sensitivity_from_categories(&cats);
        assert_eq!(sensitivity, DataSensitivity::Confidential);
    }
}
