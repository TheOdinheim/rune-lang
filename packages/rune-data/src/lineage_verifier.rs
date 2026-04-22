// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Lineage chain verification. Verifies lineage chain
// integrity and completeness, detects gaps in predecessor/successor
// references, checks record compliance against lineage policies,
// and computes chain depth.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::lineage::{LineageChain, LineageChainStatus, LineagePolicy, LineageRecord};

// ── LineageGapType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageGapType {
    MissingPredecessor,
    MissingSuccessor,
    BrokenReference { reference_id: String },
    DepthLimitExceeded { current_depth: String, max_depth: String },
}

impl fmt::Display for LineageGapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPredecessor => f.write_str("MissingPredecessor"),
            Self::MissingSuccessor => f.write_str("MissingSuccessor"),
            Self::BrokenReference { reference_id } => {
                write!(f, "BrokenReference({reference_id})")
            }
            Self::DepthLimitExceeded { current_depth, max_depth } => {
                write!(f, "DepthLimitExceeded(current={current_depth}, max={max_depth})")
            }
        }
    }
}

// ── LineageGap ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageGap {
    pub gap_id: String,
    pub before_record_id: Option<String>,
    pub after_record_id: Option<String>,
    pub gap_type: LineageGapType,
}

// ── LineageVerificationResult ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageVerificationResult {
    pub chain_id: String,
    pub verified_status: LineageChainStatus,
    pub gaps: Vec<LineageGap>,
    pub depth: String,
    pub verified_at: i64,
}

// ── RecordComplianceResult ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordComplianceResult {
    pub record_id: String,
    pub compliant: bool,
    pub missing_requirements: Vec<String>,
    pub checked_at: i64,
}

// ── LineageVerifier ──────────────────────────────────────────────────

pub struct LineageVerifier;

impl LineageVerifier {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_chain(
        &self,
        chain: &LineageChain,
        records: &HashMap<String, LineageRecord>,
        verified_at: i64,
    ) -> LineageVerificationResult {
        let gaps = self.detect_chain_gaps(&chain.records, records);
        let depth = self.compute_chain_depth(chain);

        let verified_status = if gaps.is_empty() {
            LineageChainStatus::Complete
        } else {
            let has_broken = gaps.iter().any(|g| matches!(g.gap_type, LineageGapType::BrokenReference { .. }));
            if has_broken {
                let desc = gaps.iter()
                    .filter_map(|g| {
                        if let LineageGapType::BrokenReference { reference_id } = &g.gap_type {
                            Some(reference_id.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                LineageChainStatus::Broken { gap_description: format!("Broken references: {desc}") }
            } else {
                let missing = gaps.iter()
                    .map(|g| g.gap_type.to_string())
                    .collect();
                LineageChainStatus::Partial { missing_stages: missing }
            }
        };

        LineageVerificationResult {
            chain_id: chain.chain_id.clone(),
            verified_status,
            gaps,
            depth,
            verified_at,
        }
    }

    pub fn check_record_completeness(
        &self,
        record: &LineageRecord,
        policy: &LineagePolicy,
        checked_at: i64,
    ) -> RecordComplianceResult {
        let mut missing = Vec::new();

        if policy.require_source_documentation
            && record.metadata.is_empty()
            && record.transformation_metadata.is_empty()
        {
            missing.push("Source documentation required but no metadata provided".to_string());
        }

        if policy.require_transformation_metadata && record.transformation_metadata.is_empty() {
            missing.push("Transformation metadata required but empty".to_string());
        }

        if policy.require_attestation && record.attestation_ref.is_none() {
            missing.push("Attestation required but attestation_ref is None".to_string());
        }

        let compliant = missing.is_empty();
        RecordComplianceResult {
            record_id: record.record_id.clone(),
            compliant,
            missing_requirements: missing,
            checked_at,
        }
    }

    pub fn detect_chain_gaps(
        &self,
        record_ids: &[String],
        records: &HashMap<String, LineageRecord>,
    ) -> Vec<LineageGap> {
        let mut gaps = Vec::new();
        let mut gap_counter = 0;

        for (i, record_id) in record_ids.iter().enumerate() {
            let record = match records.get(record_id) {
                Some(r) => r,
                None => {
                    gaps.push(LineageGap {
                        gap_id: format!("gap-{gap_counter}"),
                        before_record_id: if i > 0 { Some(record_ids[i - 1].clone()) } else { None },
                        after_record_id: if i + 1 < record_ids.len() { Some(record_ids[i + 1].clone()) } else { None },
                        gap_type: LineageGapType::BrokenReference { reference_id: record_id.clone() },
                    });
                    gap_counter += 1;
                    continue;
                }
            };

            // Check predecessor references exist
            for pred_ref in &record.predecessor_refs {
                if !records.contains_key(pred_ref) && record_ids.first().is_none_or(|first| first != record_id) {
                    gaps.push(LineageGap {
                        gap_id: format!("gap-{gap_counter}"),
                        before_record_id: Some(pred_ref.clone()),
                        after_record_id: Some(record_id.clone()),
                        gap_type: LineageGapType::MissingPredecessor,
                    });
                    gap_counter += 1;
                }
            }
        }

        gaps
    }

    pub fn compute_chain_depth(&self, chain: &LineageChain) -> String {
        chain.records.len().to_string()
    }
}

impl Default for LineageVerifier {
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
    use crate::lineage::LineageStage;

    fn make_record(id: &str, stage: LineageStage, preds: Vec<String>) -> LineageRecord {
        LineageRecord {
            record_id: id.into(),
            dataset_ref: "ds-test".into(),
            stage,
            predecessor_refs: preds,
            successor_refs: Vec::new(),
            transformation_metadata: HashMap::new(),
            attestation_ref: None,
            recorded_at: 1000,
            recorded_by: "agent".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_complete_chain_verification() {
        let verifier = LineageVerifier::new();
        let lr0 = make_record("lr-0", LineageStage::Source { origin: "s3".into() }, vec![]);
        let lr1 = make_record("lr-1", LineageStage::Transform { operation: "agg".into(), input_refs: vec!["lr-0".into()] }, vec!["lr-0".into()]);
        let lr2 = make_record("lr-2", LineageStage::Sink { destination: "bq".into() }, vec!["lr-1".into()]);
        let mut records = HashMap::new();
        records.insert("lr-0".into(), lr0);
        records.insert("lr-1".into(), lr1);
        records.insert("lr-2".into(), lr2);
        let chain = LineageChain {
            chain_id: "lc-1".into(),
            dataset_ref: "ds-test".into(),
            records: vec!["lr-0".into(), "lr-1".into(), "lr-2".into()],
            chain_status: LineageChainStatus::Unknown,
            verified_at: None,
            metadata: HashMap::new(),
        };
        let result = verifier.verify_chain(&chain, &records, 2000);
        assert_eq!(result.verified_status, LineageChainStatus::Complete);
        assert!(result.gaps.is_empty());
        assert_eq!(result.depth, "3");
    }

    #[test]
    fn test_chain_with_missing_record() {
        let verifier = LineageVerifier::new();
        let lr0 = make_record("lr-0", LineageStage::Source { origin: "s3".into() }, vec![]);
        let mut records = HashMap::new();
        records.insert("lr-0".into(), lr0);
        // lr-1 is missing from records
        let chain = LineageChain {
            chain_id: "lc-2".into(),
            dataset_ref: "ds-test".into(),
            records: vec!["lr-0".into(), "lr-1".into()],
            chain_status: LineageChainStatus::Unknown,
            verified_at: None,
            metadata: HashMap::new(),
        };
        let result = verifier.verify_chain(&chain, &records, 2000);
        assert!(!result.gaps.is_empty());
        assert!(matches!(result.verified_status, LineageChainStatus::Broken { .. }));
    }

    #[test]
    fn test_chain_with_broken_predecessor() {
        let verifier = LineageVerifier::new();
        let lr0 = make_record("lr-0", LineageStage::Source { origin: "s3".into() }, vec![]);
        let lr1 = make_record("lr-1", LineageStage::Transform {
            operation: "join".into(), input_refs: vec!["lr-0".into()]
        }, vec!["lr-missing".into()]); // references non-existent predecessor
        let mut records = HashMap::new();
        records.insert("lr-0".into(), lr0);
        records.insert("lr-1".into(), lr1);
        let chain = LineageChain {
            chain_id: "lc-3".into(),
            dataset_ref: "ds-test".into(),
            records: vec!["lr-0".into(), "lr-1".into()],
            chain_status: LineageChainStatus::Unknown,
            verified_at: None,
            metadata: HashMap::new(),
        };
        let result = verifier.verify_chain(&chain, &records, 2000);
        assert!(!result.gaps.is_empty());
        let has_missing_pred = result.gaps.iter().any(|g| g.gap_type == LineageGapType::MissingPredecessor);
        assert!(has_missing_pred);
    }

    #[test]
    fn test_depth_computation() {
        let verifier = LineageVerifier::new();
        let chain = LineageChain {
            chain_id: "lc-d".into(),
            dataset_ref: "ds-test".into(),
            records: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            chain_status: LineageChainStatus::Unknown,
            verified_at: None,
            metadata: HashMap::new(),
        };
        assert_eq!(verifier.compute_chain_depth(&chain), "4");
    }

    #[test]
    fn test_record_missing_source_documentation() {
        let verifier = LineageVerifier::new();
        let record = make_record("lr-no-docs", LineageStage::Source { origin: "raw".into() }, vec![]);
        let policy = LineagePolicy {
            policy_id: "lp-1".into(),
            require_source_documentation: true,
            require_transformation_metadata: false,
            require_attestation: false,
            max_chain_depth: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let result = verifier.check_record_completeness(&record, &policy, 2000);
        assert!(!result.compliant);
        assert!(result.missing_requirements.iter().any(|r| r.contains("documentation")));
    }

    #[test]
    fn test_record_missing_attestation() {
        let verifier = LineageVerifier::new();
        let record = make_record("lr-no-att", LineageStage::Source { origin: "raw".into() }, vec![]);
        let policy = LineagePolicy {
            policy_id: "lp-2".into(),
            require_source_documentation: false,
            require_transformation_metadata: false,
            require_attestation: true,
            max_chain_depth: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let result = verifier.check_record_completeness(&record, &policy, 2000);
        assert!(!result.compliant);
        assert!(result.missing_requirements.iter().any(|r| r.contains("attestation")));
    }

    #[test]
    fn test_record_compliant() {
        let verifier = LineageVerifier::new();
        let mut record = make_record("lr-good", LineageStage::Transform {
            operation: "filter".into(), input_refs: vec!["lr-0".into()]
        }, vec!["lr-0".into()]);
        record.transformation_metadata.insert("sql".into(), "SELECT *".into());
        record.metadata.insert("docs".into(), "documented".into());
        record.attestation_ref = Some("att-1".into());
        let policy = LineagePolicy {
            policy_id: "lp-3".into(),
            require_source_documentation: true,
            require_transformation_metadata: true,
            require_attestation: true,
            max_chain_depth: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let result = verifier.check_record_completeness(&record, &policy, 2000);
        assert!(result.compliant);
    }

    #[test]
    fn test_empty_chain() {
        let verifier = LineageVerifier::new();
        let chain = LineageChain {
            chain_id: "lc-empty".into(),
            dataset_ref: "ds-test".into(),
            records: Vec::new(),
            chain_status: LineageChainStatus::Unknown,
            verified_at: None,
            metadata: HashMap::new(),
        };
        let result = verifier.verify_chain(&chain, &HashMap::new(), 2000);
        assert_eq!(result.verified_status, LineageChainStatus::Complete);
        assert_eq!(result.depth, "0");
    }

    #[test]
    fn test_gap_type_display() {
        let types = vec![
            LineageGapType::MissingPredecessor,
            LineageGapType::MissingSuccessor,
            LineageGapType::BrokenReference { reference_id: "lr-x".into() },
            LineageGapType::DepthLimitExceeded { current_depth: "15".into(), max_depth: "10".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_verifier_default() {
        let _v = LineageVerifier;
    }

    #[test]
    fn test_record_missing_transformation_metadata() {
        let verifier = LineageVerifier::new();
        let record = make_record("lr-no-tm", LineageStage::Transform {
            operation: "transform".into(), input_refs: Vec::new()
        }, vec![]);
        let policy = LineagePolicy {
            policy_id: "lp-4".into(),
            require_source_documentation: false,
            require_transformation_metadata: true,
            require_attestation: false,
            max_chain_depth: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        let result = verifier.check_record_completeness(&record, &policy, 2000);
        assert!(!result.compliant);
        assert!(result.missing_requirements.iter().any(|r| r.contains("Transformation metadata")));
    }
}
