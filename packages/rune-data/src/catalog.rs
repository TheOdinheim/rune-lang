// ═══════════════════════════════════════════════════════════════════════
// Data catalog governance types — catalog entries with ownership,
// stewardship, domain tagging, and status tracking, plus governance
// policies requiring documentation, classification, quality, and
// freshness policy linkage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── CatalogEntryStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogEntryStatus {
    Active,
    Deprecated { reason: String },
    Archived,
    PendingReview,
    Draft,
}

impl fmt::Display for CatalogEntryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("Active"),
            Self::Deprecated { reason } => write!(f, "Deprecated: {reason}"),
            Self::Archived => f.write_str("Archived"),
            Self::PendingReview => f.write_str("PendingReview"),
            Self::Draft => f.write_str("Draft"),
        }
    }
}

// ── CatalogEntry ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub entry_id: String,
    pub dataset_ref: String,
    pub dataset_name: String,
    pub description: String,
    pub owner_id: String,
    pub steward_id: Option<String>,
    pub domain: Option<String>,
    pub tags: Vec<String>,
    pub schema_ref: Option<String>,
    pub classification_ref: Option<String>,
    pub quality_policy_ref: Option<String>,
    pub freshness_policy_ref: Option<String>,
    pub registered_at: i64,
    pub last_updated_at: Option<i64>,
    pub status: CatalogEntryStatus,
    pub metadata: HashMap<String, String>,
}

// ── CatalogGovernancePolicy ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CatalogGovernancePolicy {
    pub policy_id: String,
    pub require_description: bool,
    pub require_owner: bool,
    pub require_steward: bool,
    pub require_schema: bool,
    pub require_classification: bool,
    pub require_quality_policy: bool,
    pub require_freshness_policy: bool,
    pub minimum_tag_count: Option<usize>,
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
    fn test_catalog_entry_status_display() {
        let statuses = vec![
            CatalogEntryStatus::Active,
            CatalogEntryStatus::Deprecated { reason: "replaced by v2".into() },
            CatalogEntryStatus::Archived,
            CatalogEntryStatus::PendingReview,
            CatalogEntryStatus::Draft,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_catalog_entry_full_construction() {
        let entry = CatalogEntry {
            entry_id: "ce-1".into(),
            dataset_ref: "ds-users".into(),
            dataset_name: "User Profiles".into(),
            description: "Core user profile data".into(),
            owner_id: "team-platform".into(),
            steward_id: Some("alice".into()),
            domain: Some("identity".into()),
            tags: vec!["pii".into(), "core".into(), "production".into()],
            schema_ref: Some("sch-1".into()),
            classification_ref: Some("cls-1".into()),
            quality_policy_ref: Some("qp-1".into()),
            freshness_policy_ref: Some("fp-1".into()),
            registered_at: 1000,
            last_updated_at: Some(2000),
            status: CatalogEntryStatus::Active,
            metadata: HashMap::new(),
        };
        assert_eq!(entry.tags.len(), 3);
        assert_eq!(entry.steward_id, Some("alice".into()));
        assert_eq!(entry.domain, Some("identity".into()));
        assert_eq!(entry.status, CatalogEntryStatus::Active);
    }

    #[test]
    fn test_catalog_entry_minimal() {
        let entry = CatalogEntry {
            entry_id: "ce-2".into(),
            dataset_ref: "ds-logs".into(),
            dataset_name: "Application Logs".into(),
            description: "App log stream".into(),
            owner_id: "team-infra".into(),
            steward_id: None,
            domain: None,
            tags: Vec::new(),
            schema_ref: None,
            classification_ref: None,
            quality_policy_ref: None,
            freshness_policy_ref: None,
            registered_at: 3000,
            last_updated_at: None,
            status: CatalogEntryStatus::Draft,
            metadata: HashMap::new(),
        };
        assert!(entry.steward_id.is_none());
        assert!(entry.tags.is_empty());
        assert!(entry.schema_ref.is_none());
        assert!(entry.last_updated_at.is_none());
    }

    #[test]
    fn test_catalog_entry_deprecated() {
        let entry = CatalogEntry {
            entry_id: "ce-3".into(),
            dataset_ref: "ds-old-orders".into(),
            dataset_name: "Legacy Orders".into(),
            description: "Deprecated order data".into(),
            owner_id: "team-commerce".into(),
            steward_id: None,
            domain: Some("commerce".into()),
            tags: vec!["legacy".into()],
            schema_ref: None,
            classification_ref: None,
            quality_policy_ref: None,
            freshness_policy_ref: None,
            registered_at: 500,
            last_updated_at: Some(1500),
            status: CatalogEntryStatus::Deprecated { reason: "migrated to v2".into() },
            metadata: HashMap::new(),
        };
        if let CatalogEntryStatus::Deprecated { reason } = &entry.status {
            assert!(reason.contains("v2"));
        }
    }

    #[test]
    fn test_catalog_governance_policy_strict() {
        let policy = CatalogGovernancePolicy {
            policy_id: "cgp-1".into(),
            require_description: true,
            require_owner: true,
            require_steward: true,
            require_schema: true,
            require_classification: true,
            require_quality_policy: true,
            require_freshness_policy: true,
            minimum_tag_count: Some(2),
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert!(policy.require_steward);
        assert!(policy.require_freshness_policy);
        assert_eq!(policy.minimum_tag_count, Some(2));
    }

    #[test]
    fn test_catalog_governance_policy_relaxed() {
        let policy = CatalogGovernancePolicy {
            policy_id: "cgp-2".into(),
            require_description: true,
            require_owner: true,
            require_steward: false,
            require_schema: false,
            require_classification: false,
            require_quality_policy: false,
            require_freshness_policy: false,
            minimum_tag_count: None,
            created_at: 2000,
            metadata: HashMap::new(),
        };
        assert!(!policy.require_steward);
        assert!(policy.minimum_tag_count.is_none());
    }

    #[test]
    fn test_catalog_entry_with_metadata() {
        let mut meta = HashMap::new();
        meta.insert("data_product".into(), "customer_360".into());
        let entry = CatalogEntry {
            entry_id: "ce-4".into(),
            dataset_ref: "ds-customer-360".into(),
            dataset_name: "Customer 360".into(),
            description: "Unified customer view".into(),
            owner_id: "team-data".into(),
            steward_id: Some("bob".into()),
            domain: Some("analytics".into()),
            tags: vec!["data-product".into()],
            schema_ref: None,
            classification_ref: None,
            quality_policy_ref: None,
            freshness_policy_ref: None,
            registered_at: 4000,
            last_updated_at: None,
            status: CatalogEntryStatus::PendingReview,
            metadata: meta,
        };
        assert_eq!(entry.metadata.get("data_product"), Some(&"customer_360".to_string()));
    }
}
