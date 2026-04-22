// ═══════════════════════════════════════════════════════════════════════
// Data classification and sensitivity types — sensitivity levels with
// Ord derivation for threshold-based access control, data categories
// for PII/PHI/PCI/financial/IP classification, classification methods
// (manual, automated, inherited), and classification policies.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── DataSensitivity ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
    Custom { name: String },
}

impl DataSensitivity {
    fn ordinal(&self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Confidential => 2,
            Self::Restricted => 3,
            Self::Custom { .. } => 4,
        }
    }
}

impl Ord for DataSensitivity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal().cmp(&other.ordinal())
    }
}

impl PartialOrd for DataSensitivity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for DataSensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("Public"),
            Self::Internal => f.write_str("Internal"),
            Self::Confidential => f.write_str("Confidential"),
            Self::Restricted => f.write_str("Restricted"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DataCategoryType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataCategoryType {
    PersonallyIdentifiable,
    ProtectedHealthInformation,
    PaymentCardData,
    FinanciallyScoped,
    IntellectualProperty,
    GovernmentClassified,
    BiometricData,
    ChildrenData,
    Custom { name: String },
}

impl fmt::Display for DataCategoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PersonallyIdentifiable => f.write_str("PersonallyIdentifiable"),
            Self::ProtectedHealthInformation => f.write_str("ProtectedHealthInformation"),
            Self::PaymentCardData => f.write_str("PaymentCardData"),
            Self::FinanciallyScoped => f.write_str("FinanciallyScoped"),
            Self::IntellectualProperty => f.write_str("IntellectualProperty"),
            Self::GovernmentClassified => f.write_str("GovernmentClassified"),
            Self::BiometricData => f.write_str("BiometricData"),
            Self::ChildrenData => f.write_str("ChildrenData"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DataCategory ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataCategory {
    pub category_id: String,
    pub category_type: DataCategoryType,
    pub handling_requirements: Vec<String>,
    pub regulatory_refs: Vec<String>,
}

// ── ClassificationMethod ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationMethod {
    Manual { classified_by: String },
    Automated { classifier_ref: String },
    Inherited { source_dataset_ref: String },
    Custom { name: String },
}

impl fmt::Display for ClassificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manual { classified_by } => write!(f, "Manual(by={classified_by})"),
            Self::Automated { classifier_ref } => write!(f, "Automated(ref={classifier_ref})"),
            Self::Inherited { source_dataset_ref } => write!(f, "Inherited(source={source_dataset_ref})"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DataClassification ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataClassification {
    pub classification_id: String,
    pub dataset_ref: String,
    pub sensitivity_level: DataSensitivity,
    pub data_categories: Vec<DataCategory>,
    pub classification_method: ClassificationMethod,
    pub classified_at: i64,
    pub review_due_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── ClassificationPolicy ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClassificationPolicy {
    pub policy_id: String,
    pub require_classification_before_processing: bool,
    pub require_periodic_review: bool,
    pub review_interval_days: Option<String>,
    pub auto_classify_on_ingestion: bool,
    pub escalation_target: Option<String>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_sensitivity_display() {
        let levels = vec![
            DataSensitivity::Public,
            DataSensitivity::Internal,
            DataSensitivity::Confidential,
            DataSensitivity::Restricted,
            DataSensitivity::Custom { name: "TopSecret".into() },
        ];
        for l in &levels {
            assert!(!l.to_string().is_empty());
        }
        assert_eq!(levels.len(), 5);
    }

    #[test]
    fn test_data_sensitivity_ord() {
        assert!(DataSensitivity::Public < DataSensitivity::Internal);
        assert!(DataSensitivity::Internal < DataSensitivity::Confidential);
        assert!(DataSensitivity::Confidential < DataSensitivity::Restricted);
        assert!(DataSensitivity::Restricted < DataSensitivity::Custom { name: "X".into() });
    }

    #[test]
    fn test_data_category_type_display() {
        let types = vec![
            DataCategoryType::PersonallyIdentifiable,
            DataCategoryType::ProtectedHealthInformation,
            DataCategoryType::PaymentCardData,
            DataCategoryType::FinanciallyScoped,
            DataCategoryType::IntellectualProperty,
            DataCategoryType::GovernmentClassified,
            DataCategoryType::BiometricData,
            DataCategoryType::ChildrenData,
            DataCategoryType::Custom { name: "Telemetry".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 9);
    }

    #[test]
    fn test_data_category_construction() {
        let cat = DataCategory {
            category_id: "cat-1".into(),
            category_type: DataCategoryType::PersonallyIdentifiable,
            handling_requirements: vec!["encrypt_at_rest".into(), "mask_in_logs".into()],
            regulatory_refs: vec!["GDPR".into(), "CCPA".into()],
        };
        assert_eq!(cat.handling_requirements.len(), 2);
        assert_eq!(cat.regulatory_refs.len(), 2);
    }

    #[test]
    fn test_classification_method_display() {
        let methods = vec![
            ClassificationMethod::Manual { classified_by: "alice".into() },
            ClassificationMethod::Automated { classifier_ref: "clf-1".into() },
            ClassificationMethod::Inherited { source_dataset_ref: "ds-parent".into() },
            ClassificationMethod::Custom { name: "hybrid".into() },
        ];
        for m in &methods {
            assert!(!m.to_string().is_empty());
        }
        assert_eq!(methods.len(), 4);
    }

    #[test]
    fn test_data_classification_construction() {
        let cls = DataClassification {
            classification_id: "cls-1".into(),
            dataset_ref: "ds-users".into(),
            sensitivity_level: DataSensitivity::Restricted,
            data_categories: vec![DataCategory {
                category_id: "cat-1".into(),
                category_type: DataCategoryType::PersonallyIdentifiable,
                handling_requirements: vec!["encrypt".into()],
                regulatory_refs: vec!["GDPR".into()],
            }],
            classification_method: ClassificationMethod::Manual { classified_by: "alice".into() },
            classified_at: 1000,
            review_due_at: Some(2000),
            metadata: HashMap::new(),
        };
        assert_eq!(cls.sensitivity_level, DataSensitivity::Restricted);
        assert_eq!(cls.data_categories.len(), 1);
        assert_eq!(cls.review_due_at, Some(2000));
    }

    #[test]
    fn test_classification_policy_construction() {
        let policy = ClassificationPolicy {
            policy_id: "cp-1".into(),
            require_classification_before_processing: true,
            require_periodic_review: true,
            review_interval_days: Some("90".into()),
            auto_classify_on_ingestion: false,
            escalation_target: Some("data-governance-team".into()),
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert!(policy.require_classification_before_processing);
        assert!(policy.require_periodic_review);
        assert_eq!(policy.review_interval_days, Some("90".into()));
    }

    #[test]
    fn test_sensitivity_equality() {
        assert_eq!(DataSensitivity::Confidential, DataSensitivity::Confidential);
        assert_ne!(DataSensitivity::Public, DataSensitivity::Internal);
    }

    #[test]
    fn test_classification_no_review_due() {
        let cls = DataClassification {
            classification_id: "cls-2".into(),
            dataset_ref: "ds-public".into(),
            sensitivity_level: DataSensitivity::Public,
            data_categories: Vec::new(),
            classification_method: ClassificationMethod::Automated { classifier_ref: "auto-1".into() },
            classified_at: 5000,
            review_due_at: None,
            metadata: HashMap::new(),
        };
        assert!(cls.review_due_at.is_none());
        assert!(cls.data_categories.is_empty());
    }

    #[test]
    fn test_data_category_pci() {
        let cat = DataCategory {
            category_id: "cat-pci".into(),
            category_type: DataCategoryType::PaymentCardData,
            handling_requirements: vec!["tokenize".into(), "pci_zone_only".into()],
            regulatory_refs: vec!["PCI_DSS".into()],
        };
        assert_eq!(cat.category_type, DataCategoryType::PaymentCardData);
        assert!(cat.regulatory_refs.contains(&"PCI_DSS".to_string()));
    }
}
