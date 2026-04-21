// ═══════════════════════════════════════════════════════════════════════
// Training Data — Training data governance types for dataset
// registration, lineage, license compliance, and data quality policy.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── DatasetSource ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatasetSource {
    Public { url: String },
    Licensed { license_id: String },
    Internal { team: String },
    Synthetic { generator: String },
    Custom { name: String },
}

impl fmt::Display for DatasetSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public { url } => write!(f, "Public({url})"),
            Self::Licensed { license_id } => write!(f, "Licensed({license_id})"),
            Self::Internal { team } => write!(f, "Internal({team})"),
            Self::Synthetic { generator } => write!(f, "Synthetic({generator})"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DatasetFormat ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatasetFormat {
    Csv,
    Parquet,
    JsonLines,
    Tfrecord,
    ImageFolder,
    AudioFolder,
    Custom { name: String },
}

impl fmt::Display for DatasetFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Csv => f.write_str("CSV"),
            Self::Parquet => f.write_str("Parquet"),
            Self::JsonLines => f.write_str("JsonLines"),
            Self::Tfrecord => f.write_str("TFRecord"),
            Self::ImageFolder => f.write_str("ImageFolder"),
            Self::AudioFolder => f.write_str("AudioFolder"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── DataQualityStatus ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataQualityStatus {
    Unknown,
    Pending,
    Validated,
    QualityIssuesFound { issue_count: String },
    Rejected { reason: String },
}

impl fmt::Display for DataQualityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("Unknown"),
            Self::Pending => f.write_str("Pending"),
            Self::Validated => f.write_str("Validated"),
            Self::QualityIssuesFound { issue_count } => {
                write!(f, "QualityIssuesFound(count={issue_count})")
            }
            Self::Rejected { reason } => write!(f, "Rejected: {reason}"),
        }
    }
}

// ── DatasetRecord ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetRecord {
    pub dataset_id: String,
    pub dataset_name: String,
    pub version: String,
    pub source: DatasetSource,
    pub format: DatasetFormat,
    pub record_count: Option<String>,
    pub size_bytes: Option<String>,
    pub created_at: i64,
    pub created_by: String,
    pub license: Option<String>,
    pub lineage_refs: Vec<String>,
    pub quality_status: DataQualityStatus,
    pub sensitivity_label: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl DatasetRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dataset_id: impl Into<String>,
        dataset_name: impl Into<String>,
        version: impl Into<String>,
        source: DatasetSource,
        format: DatasetFormat,
        created_at: i64,
        created_by: impl Into<String>,
    ) -> Self {
        Self {
            dataset_id: dataset_id.into(),
            dataset_name: dataset_name.into(),
            version: version.into(),
            source,
            format,
            record_count: None,
            size_bytes: None,
            created_at,
            created_by: created_by.into(),
            license: None,
            lineage_refs: Vec::new(),
            quality_status: DataQualityStatus::Unknown,
            sensitivity_label: None,
            metadata: HashMap::new(),
        }
    }
}

// ── DataGovernancePolicy ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGovernancePolicy {
    pub policy_id: String,
    pub require_license_review: bool,
    pub require_quality_validation: bool,
    pub require_lineage_documentation: bool,
    pub prohibited_sources: Vec<String>,
    pub max_staleness_days: Option<String>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl DataGovernancePolicy {
    pub fn new(policy_id: impl Into<String>, created_at: i64) -> Self {
        Self {
            policy_id: policy_id.into(),
            require_license_review: false,
            require_quality_validation: false,
            require_lineage_documentation: false,
            prohibited_sources: Vec::new(),
            max_staleness_days: None,
            created_at,
            metadata: HashMap::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_source_display() {
        let sources = vec![
            DatasetSource::Public { url: "https://example.com".into() },
            DatasetSource::Licensed { license_id: "MIT".into() },
            DatasetSource::Internal { team: "ml-team".into() },
            DatasetSource::Synthetic { generator: "gan-v2".into() },
            DatasetSource::Custom { name: "custom-src".into() },
        ];
        for s in &sources {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(sources.len(), 5);
    }

    #[test]
    fn test_dataset_format_display() {
        let formats = vec![
            DatasetFormat::Csv,
            DatasetFormat::Parquet,
            DatasetFormat::JsonLines,
            DatasetFormat::Tfrecord,
            DatasetFormat::ImageFolder,
            DatasetFormat::AudioFolder,
            DatasetFormat::Custom { name: "hdf5".into() },
        ];
        for f in &formats {
            assert!(!f.to_string().is_empty());
        }
        assert_eq!(formats.len(), 7);
    }

    #[test]
    fn test_data_quality_status_display() {
        let statuses = vec![
            DataQualityStatus::Unknown,
            DataQualityStatus::Pending,
            DataQualityStatus::Validated,
            DataQualityStatus::QualityIssuesFound { issue_count: "3".into() },
            DataQualityStatus::Rejected { reason: "corrupt records".into() },
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_dataset_record_construction() {
        let mut record = DatasetRecord::new(
            "ds-1", "ImageNet-2024", "1.0",
            DatasetSource::Public { url: "https://imagenet.org".into() },
            DatasetFormat::ImageFolder,
            1000, "alice",
        );
        assert_eq!(record.dataset_id, "ds-1");
        assert_eq!(record.quality_status, DataQualityStatus::Unknown);
        assert!(record.record_count.is_none());

        record.record_count = Some("1000000".into());
        record.size_bytes = Some("5368709120".into());
        record.license = Some("CC-BY-4.0".into());
        record.lineage_refs.push("parent-ds-1".into());
        record.sensitivity_label = Some("pii-free".into());
        record.metadata.insert("split".into(), "train".into());
        assert_eq!(record.lineage_refs.len(), 1);
    }

    #[test]
    fn test_data_governance_policy_construction() {
        let mut policy = DataGovernancePolicy::new("dgp-1", 1000);
        assert!(!policy.require_license_review);
        policy.require_license_review = true;
        policy.require_quality_validation = true;
        policy.require_lineage_documentation = true;
        policy.prohibited_sources.push("scraped-web".into());
        policy.max_staleness_days = Some("365".into());
        assert!(policy.require_license_review);
        assert_eq!(policy.prohibited_sources.len(), 1);
    }

    #[test]
    fn test_dataset_record_quality_status_update() {
        let mut record = DatasetRecord::new(
            "ds-2", "COCO", "2.0",
            DatasetSource::Public { url: "https://cocodataset.org".into() },
            DatasetFormat::ImageFolder,
            2000, "bob",
        );
        assert_eq!(record.quality_status, DataQualityStatus::Unknown);
        record.quality_status = DataQualityStatus::Validated;
        assert_eq!(record.quality_status, DataQualityStatus::Validated);
    }

    #[test]
    fn test_dataset_record_multiple_lineage_refs() {
        let mut record = DatasetRecord::new(
            "ds-3", "derived", "1.0",
            DatasetSource::Internal { team: "data-eng".into() },
            DatasetFormat::Parquet,
            3000, "carol",
        );
        record.lineage_refs.push("ds-1".into());
        record.lineage_refs.push("ds-2".into());
        assert_eq!(record.lineage_refs.len(), 2);
    }

    #[test]
    fn test_governance_policy_metadata() {
        let mut policy = DataGovernancePolicy::new("dgp-2", 5000);
        policy.metadata.insert("regulation".into(), "GDPR".into());
        assert_eq!(policy.metadata["regulation"], "GDPR");
    }
}
