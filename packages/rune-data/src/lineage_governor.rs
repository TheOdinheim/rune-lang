// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Lineage governor trait. Governs data lineage at the
// integration boundary. Reference implementations:
// InMemoryLineageGovernor, NullLineageGovernor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::lineage::{LineageChain, LineageChainStatus, LineagePolicy, LineageRecord};
use crate::lineage_verifier::LineageVerifier;

// ── LineageGovernanceDecision ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageGovernanceDecision {
    Compliant { chain_depth: String, policy_ref: String },
    NonCompliant { gaps: Vec<String>, policy_ref: String },
    ChainBroken { gap_description: String },
    InsufficientData { reason: String },
}

impl fmt::Display for LineageGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compliant { chain_depth, policy_ref } => {
                write!(f, "Compliant(depth={chain_depth}, policy={policy_ref})")
            }
            Self::NonCompliant { gaps, policy_ref } => {
                write!(f, "NonCompliant(gaps={}, policy={policy_ref})", gaps.len())
            }
            Self::ChainBroken { gap_description } => {
                write!(f, "ChainBroken({gap_description})")
            }
            Self::InsufficientData { reason } => {
                write!(f, "InsufficientData({reason})")
            }
        }
    }
}

// ── LineageGovernanceResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageGovernanceResult {
    pub dataset_ref: String,
    pub decision: LineageGovernanceDecision,
    pub evaluated_at: i64,
}

// ── LineageGovernor trait ────────────────────────────────────────────

pub trait LineageGovernor {
    fn evaluate_lineage_compliance(
        &self,
        dataset_ref: &str,
        evaluated_at: i64,
    ) -> LineageGovernanceResult;

    fn register_lineage_policy(&mut self, policy: LineagePolicy);
    fn remove_lineage_policy(&mut self, policy_id: &str);
    fn list_lineage_policies(&self) -> Vec<&LineagePolicy>;

    fn verify_lineage_chain(
        &self,
        chain_id: &str,
        verified_at: i64,
    ) -> LineageGovernanceResult;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryLineageGovernor ──────────────────────────────────────────

pub struct InMemoryLineageGovernor {
    id: String,
    active: bool,
    verifier: LineageVerifier,
    policies: HashMap<String, LineagePolicy>,
    chains: HashMap<String, LineageChain>,
    records: HashMap<String, LineageRecord>,
}

impl InMemoryLineageGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            verifier: LineageVerifier::new(),
            policies: HashMap::new(),
            chains: HashMap::new(),
            records: HashMap::new(),
        }
    }

    pub fn add_chain(&mut self, chain: LineageChain) {
        self.chains.insert(chain.chain_id.clone(), chain);
    }

    pub fn add_record(&mut self, record: LineageRecord) {
        self.records.insert(record.record_id.clone(), record);
    }
}

impl LineageGovernor for InMemoryLineageGovernor {
    fn evaluate_lineage_compliance(
        &self,
        dataset_ref: &str,
        evaluated_at: i64,
    ) -> LineageGovernanceResult {
        let dataset_chains: Vec<&LineageChain> = self.chains.values()
            .filter(|c| c.dataset_ref == dataset_ref)
            .collect();

        if dataset_chains.is_empty() {
            return LineageGovernanceResult {
                dataset_ref: dataset_ref.to_string(),
                decision: LineageGovernanceDecision::InsufficientData {
                    reason: format!("No lineage chains found for dataset {dataset_ref}"),
                },
                evaluated_at,
            };
        }

        let policy = self.policies.values().next();
        let policy_ref = policy.map_or("none".to_string(), |p| p.policy_id.clone());

        for chain in &dataset_chains {
            let result = self.verifier.verify_chain(chain, &self.records, evaluated_at);
            match &result.verified_status {
                LineageChainStatus::Complete => {}
                LineageChainStatus::Broken { gap_description } => {
                    return LineageGovernanceResult {
                        dataset_ref: dataset_ref.to_string(),
                        decision: LineageGovernanceDecision::ChainBroken {
                            gap_description: gap_description.clone(),
                        },
                        evaluated_at,
                    };
                }
                LineageChainStatus::Partial { missing_stages } => {
                    return LineageGovernanceResult {
                        dataset_ref: dataset_ref.to_string(),
                        decision: LineageGovernanceDecision::NonCompliant {
                            gaps: missing_stages.clone(),
                            policy_ref,
                        },
                        evaluated_at,
                    };
                }
                LineageChainStatus::Unknown => {
                    return LineageGovernanceResult {
                        dataset_ref: dataset_ref.to_string(),
                        decision: LineageGovernanceDecision::InsufficientData {
                            reason: "Chain status unknown".to_string(),
                        },
                        evaluated_at,
                    };
                }
            }
        }

        let max_depth = dataset_chains.iter()
            .map(|c| self.verifier.compute_chain_depth(c))
            .max()
            .unwrap_or_else(|| "0".to_string());

        LineageGovernanceResult {
            dataset_ref: dataset_ref.to_string(),
            decision: LineageGovernanceDecision::Compliant {
                chain_depth: max_depth,
                policy_ref,
            },
            evaluated_at,
        }
    }

    fn register_lineage_policy(&mut self, policy: LineagePolicy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    fn remove_lineage_policy(&mut self, policy_id: &str) {
        self.policies.remove(policy_id);
    }

    fn list_lineage_policies(&self) -> Vec<&LineagePolicy> {
        self.policies.values().collect()
    }

    fn verify_lineage_chain(
        &self,
        chain_id: &str,
        verified_at: i64,
    ) -> LineageGovernanceResult {
        let chain = match self.chains.get(chain_id) {
            Some(c) => c,
            None => {
                return LineageGovernanceResult {
                    dataset_ref: "unknown".to_string(),
                    decision: LineageGovernanceDecision::InsufficientData {
                        reason: format!("Chain {chain_id} not found"),
                    },
                    evaluated_at: verified_at,
                };
            }
        };

        let result = self.verifier.verify_chain(chain, &self.records, verified_at);
        let policy_ref = self.policies.values().next()
            .map_or("none".to_string(), |p| p.policy_id.clone());

        let decision = match &result.verified_status {
            LineageChainStatus::Complete => LineageGovernanceDecision::Compliant {
                chain_depth: result.depth,
                policy_ref,
            },
            LineageChainStatus::Broken { gap_description } => LineageGovernanceDecision::ChainBroken {
                gap_description: gap_description.clone(),
            },
            LineageChainStatus::Partial { missing_stages } => LineageGovernanceDecision::NonCompliant {
                gaps: missing_stages.clone(),
                policy_ref,
            },
            LineageChainStatus::Unknown => LineageGovernanceDecision::InsufficientData {
                reason: "Chain status unknown".to_string(),
            },
        };

        LineageGovernanceResult {
            dataset_ref: chain.dataset_ref.clone(),
            decision,
            evaluated_at: verified_at,
        }
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullLineageGovernor ──────────────────────────────────────────────

pub struct NullLineageGovernor;

impl LineageGovernor for NullLineageGovernor {
    fn evaluate_lineage_compliance(&self, dataset_ref: &str, evaluated_at: i64) -> LineageGovernanceResult {
        LineageGovernanceResult {
            dataset_ref: dataset_ref.to_string(),
            decision: LineageGovernanceDecision::Compliant {
                chain_depth: "0".to_string(),
                policy_ref: "null".to_string(),
            },
            evaluated_at,
        }
    }

    fn register_lineage_policy(&mut self, _policy: LineagePolicy) {}
    fn remove_lineage_policy(&mut self, _policy_id: &str) {}
    fn list_lineage_policies(&self) -> Vec<&LineagePolicy> { Vec::new() }
    fn verify_lineage_chain(&self, _chain_id: &str, evaluated_at: i64) -> LineageGovernanceResult {
        LineageGovernanceResult {
            dataset_ref: "unknown".to_string(),
            decision: LineageGovernanceDecision::Compliant {
                chain_depth: "0".to_string(),
                policy_ref: "null".to_string(),
            },
            evaluated_at,
        }
    }
    fn governor_id(&self) -> &str { "null-lineage-governor" }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lineage::LineageStage;

    fn make_record(id: &str, dataset: &str, stage: LineageStage) -> LineageRecord {
        LineageRecord {
            record_id: id.into(),
            dataset_ref: dataset.into(),
            stage,
            predecessor_refs: Vec::new(),
            successor_refs: Vec::new(),
            transformation_metadata: HashMap::new(),
            attestation_ref: None,
            recorded_at: 1000,
            recorded_by: "agent".into(),
            metadata: HashMap::new(),
        }
    }

    fn make_chain(id: &str, dataset: &str, record_ids: Vec<&str>) -> LineageChain {
        LineageChain {
            chain_id: id.into(),
            dataset_ref: dataset.into(),
            records: record_ids.into_iter().map(String::from).collect(),
            chain_status: LineageChainStatus::Unknown,
            verified_at: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_compliant_lineage() {
        let mut gov = InMemoryLineageGovernor::new("lg-1");
        let lr0 = make_record("lr-0", "ds-1", LineageStage::Source { origin: "s3".into() });
        let lr1 = make_record("lr-1", "ds-1", LineageStage::Sink { destination: "bq".into() });
        gov.add_record(lr0);
        gov.add_record(lr1);
        gov.add_chain(make_chain("lc-1", "ds-1", vec!["lr-0", "lr-1"]));
        let result = gov.evaluate_lineage_compliance("ds-1", 2000);
        assert!(matches!(result.decision, LineageGovernanceDecision::Compliant { .. }));
    }

    #[test]
    fn test_broken_chain() {
        let mut gov = InMemoryLineageGovernor::new("lg-1");
        let lr0 = make_record("lr-0", "ds-1", LineageStage::Source { origin: "s3".into() });
        gov.add_record(lr0);
        // lr-missing is in chain but not in records
        gov.add_chain(make_chain("lc-1", "ds-1", vec!["lr-0", "lr-missing"]));
        let result = gov.evaluate_lineage_compliance("ds-1", 2000);
        assert!(matches!(result.decision, LineageGovernanceDecision::ChainBroken { .. }));
    }

    #[test]
    fn test_insufficient_data() {
        let gov = InMemoryLineageGovernor::new("lg-1");
        let result = gov.evaluate_lineage_compliance("ds-missing", 2000);
        assert!(matches!(result.decision, LineageGovernanceDecision::InsufficientData { .. }));
    }

    #[test]
    fn test_verify_chain_not_found() {
        let gov = InMemoryLineageGovernor::new("lg-1");
        let result = gov.verify_lineage_chain("lc-missing", 2000);
        assert!(matches!(result.decision, LineageGovernanceDecision::InsufficientData { .. }));
    }

    #[test]
    fn test_verify_chain_complete() {
        let mut gov = InMemoryLineageGovernor::new("lg-1");
        let lr0 = make_record("lr-0", "ds-1", LineageStage::Source { origin: "s3".into() });
        gov.add_record(lr0);
        gov.add_chain(make_chain("lc-1", "ds-1", vec!["lr-0"]));
        let result = gov.verify_lineage_chain("lc-1", 2000);
        assert!(matches!(result.decision, LineageGovernanceDecision::Compliant { .. }));
    }

    #[test]
    fn test_register_and_remove_policy() {
        let mut gov = InMemoryLineageGovernor::new("lg-1");
        let policy = LineagePolicy {
            policy_id: "lp-1".into(),
            require_source_documentation: true,
            require_transformation_metadata: false,
            require_attestation: false,
            max_chain_depth: None,
            created_at: 1000,
            metadata: HashMap::new(),
        };
        gov.register_lineage_policy(policy);
        assert_eq!(gov.list_lineage_policies().len(), 1);
        gov.remove_lineage_policy("lp-1");
        assert_eq!(gov.list_lineage_policies().len(), 0);
    }

    #[test]
    fn test_governor_id_and_active() {
        let gov = InMemoryLineageGovernor::new("lg-1");
        assert_eq!(gov.governor_id(), "lg-1");
        assert!(gov.is_active());
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullLineageGovernor;
        let result = gov.evaluate_lineage_compliance("ds-1", 2000);
        assert!(matches!(result.decision, LineageGovernanceDecision::Compliant { .. }));
        assert_eq!(gov.governor_id(), "null-lineage-governor");
        assert!(!gov.is_active());
        gov.register_lineage_policy(LineagePolicy {
            policy_id: "x".into(), require_source_documentation: false,
            require_transformation_metadata: false, require_attestation: false,
            max_chain_depth: None, created_at: 0, metadata: HashMap::new(),
        });
        gov.remove_lineage_policy("x");
        assert!(gov.list_lineage_policies().is_empty());
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            LineageGovernanceDecision::Compliant { chain_depth: "3".into(), policy_ref: "lp-1".into() },
            LineageGovernanceDecision::NonCompliant { gaps: vec!["gap".into()], policy_ref: "lp-1".into() },
            LineageGovernanceDecision::ChainBroken { gap_description: "broken".into() },
            LineageGovernanceDecision::InsufficientData { reason: "no data".into() },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }
}
