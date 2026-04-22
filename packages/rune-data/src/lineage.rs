// ═══════════════════════════════════════════════════════════════════════
// Data lineage and transformation tracking types — lineage records
// tracking source→transform→sink stages, lineage chains with
// completeness status, and lineage policies requiring documentation,
// transformation metadata, and provenance attestation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── LineageStage ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageStage {
    Source { origin: String },
    Transform { operation: String, input_refs: Vec<String> },
    Sink { destination: String },
    Custom { name: String },
}

impl fmt::Display for LineageStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source { origin } => write!(f, "Source({origin})"),
            Self::Transform { operation, .. } => write!(f, "Transform({operation})"),
            Self::Sink { destination } => write!(f, "Sink({destination})"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── LineageChainStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageChainStatus {
    Complete,
    Partial { missing_stages: Vec<String> },
    Broken { gap_description: String },
    Unknown,
}

impl fmt::Display for LineageChainStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => f.write_str("Complete"),
            Self::Partial { missing_stages } => {
                write!(f, "Partial(missing={})", missing_stages.join(", "))
            }
            Self::Broken { gap_description } => write!(f, "Broken({gap_description})"),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

// ── LineageRecord ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LineageRecord {
    pub record_id: String,
    pub dataset_ref: String,
    pub stage: LineageStage,
    pub predecessor_refs: Vec<String>,
    pub successor_refs: Vec<String>,
    pub transformation_metadata: HashMap<String, String>,
    pub attestation_ref: Option<String>,
    pub recorded_at: i64,
    pub recorded_by: String,
    pub metadata: HashMap<String, String>,
}

// ── LineageChain ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LineageChain {
    pub chain_id: String,
    pub dataset_ref: String,
    pub records: Vec<String>,
    pub chain_status: LineageChainStatus,
    pub verified_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── LineagePolicy ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LineagePolicy {
    pub policy_id: String,
    pub require_source_documentation: bool,
    pub require_transformation_metadata: bool,
    pub require_attestation: bool,
    pub max_chain_depth: Option<String>,
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
    fn test_lineage_stage_display() {
        let stages = vec![
            LineageStage::Source { origin: "s3://bucket/raw".into() },
            LineageStage::Transform { operation: "deduplicate".into(), input_refs: vec!["lr-1".into()] },
            LineageStage::Sink { destination: "warehouse.table".into() },
            LineageStage::Custom { name: "audit_copy".into() },
        ];
        for s in &stages {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(stages.len(), 4);
    }

    #[test]
    fn test_lineage_chain_status_display() {
        let statuses = vec![
            LineageChainStatus::Complete,
            LineageChainStatus::Partial { missing_stages: vec!["transform-2".into()] },
            LineageChainStatus::Broken { gap_description: "missing sink".into() },
            LineageChainStatus::Unknown,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_lineage_record_construction() {
        let mut transform_meta = HashMap::new();
        transform_meta.insert("sql_hash".into(), "abc123".into());
        let record = LineageRecord {
            record_id: "lr-1".into(),
            dataset_ref: "ds-orders".into(),
            stage: LineageStage::Transform {
                operation: "aggregate".into(),
                input_refs: vec!["lr-0".into()],
            },
            predecessor_refs: vec!["lr-0".into()],
            successor_refs: vec!["lr-2".into()],
            transformation_metadata: transform_meta,
            attestation_ref: Some("att-1".into()),
            recorded_at: 1000,
            recorded_by: "airflow-dag".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(record.record_id, "lr-1");
        assert_eq!(record.predecessor_refs.len(), 1);
        assert_eq!(record.successor_refs.len(), 1);
        assert!(record.attestation_ref.is_some());
    }

    #[test]
    fn test_lineage_record_source_stage() {
        let record = LineageRecord {
            record_id: "lr-0".into(),
            dataset_ref: "ds-raw".into(),
            stage: LineageStage::Source { origin: "kafka://topic".into() },
            predecessor_refs: Vec::new(),
            successor_refs: vec!["lr-1".into()],
            transformation_metadata: HashMap::new(),
            attestation_ref: None,
            recorded_at: 500,
            recorded_by: "ingestion-service".into(),
            metadata: HashMap::new(),
        };
        assert!(record.predecessor_refs.is_empty());
        assert!(record.attestation_ref.is_none());
    }

    #[test]
    fn test_lineage_chain_construction() {
        let chain = LineageChain {
            chain_id: "lc-1".into(),
            dataset_ref: "ds-orders".into(),
            records: vec!["lr-0".into(), "lr-1".into(), "lr-2".into()],
            chain_status: LineageChainStatus::Complete,
            verified_at: Some(2000),
            metadata: HashMap::new(),
        };
        assert_eq!(chain.records.len(), 3);
        assert_eq!(chain.chain_status, LineageChainStatus::Complete);
        assert_eq!(chain.verified_at, Some(2000));
    }

    #[test]
    fn test_lineage_chain_broken() {
        let chain = LineageChain {
            chain_id: "lc-2".into(),
            dataset_ref: "ds-broken".into(),
            records: vec!["lr-0".into()],
            chain_status: LineageChainStatus::Broken { gap_description: "no sink recorded".into() },
            verified_at: None,
            metadata: HashMap::new(),
        };
        assert!(chain.verified_at.is_none());
        if let LineageChainStatus::Broken { gap_description } = &chain.chain_status {
            assert!(gap_description.contains("sink"));
        }
    }

    #[test]
    fn test_lineage_policy_construction() {
        let policy = LineagePolicy {
            policy_id: "lp-1".into(),
            require_source_documentation: true,
            require_transformation_metadata: true,
            require_attestation: false,
            max_chain_depth: Some("10".into()),
            created_at: 1000,
            metadata: HashMap::new(),
        };
        assert!(policy.require_source_documentation);
        assert!(policy.require_transformation_metadata);
        assert!(!policy.require_attestation);
        assert_eq!(policy.max_chain_depth, Some("10".into()));
    }

    #[test]
    fn test_lineage_policy_no_depth_limit() {
        let policy = LineagePolicy {
            policy_id: "lp-2".into(),
            require_source_documentation: false,
            require_transformation_metadata: false,
            require_attestation: true,
            max_chain_depth: None,
            created_at: 2000,
            metadata: HashMap::new(),
        };
        assert!(policy.max_chain_depth.is_none());
        assert!(policy.require_attestation);
    }

    #[test]
    fn test_lineage_record_with_metadata() {
        let mut meta = HashMap::new();
        meta.insert("pipeline".into(), "daily_etl".into());
        let record = LineageRecord {
            record_id: "lr-meta".into(),
            dataset_ref: "ds-x".into(),
            stage: LineageStage::Sink { destination: "bigquery.table".into() },
            predecessor_refs: vec!["lr-prev".into()],
            successor_refs: Vec::new(),
            transformation_metadata: HashMap::new(),
            attestation_ref: None,
            recorded_at: 3000,
            recorded_by: "dbt".into(),
            metadata: meta.clone(),
        };
        assert_eq!(record.metadata.get("pipeline"), Some(&"daily_etl".to_string()));
    }

    #[test]
    fn test_lineage_stage_transform_with_multiple_inputs() {
        let stage = LineageStage::Transform {
            operation: "join".into(),
            input_refs: vec!["lr-a".into(), "lr-b".into(), "lr-c".into()],
        };
        assert!(stage.to_string().contains("join"));
        if let LineageStage::Transform { input_refs, .. } = &stage {
            assert_eq!(input_refs.len(), 3);
        }
    }

    #[test]
    fn test_lineage_chain_partial() {
        let chain = LineageChain {
            chain_id: "lc-partial".into(),
            dataset_ref: "ds-partial".into(),
            records: vec!["lr-0".into(), "lr-2".into()],
            chain_status: LineageChainStatus::Partial {
                missing_stages: vec!["transform-1".into()],
            },
            verified_at: None,
            metadata: HashMap::new(),
        };
        if let LineageChainStatus::Partial { missing_stages } = &chain.chain_status {
            assert_eq!(missing_stages.len(), 1);
        }
    }
}
