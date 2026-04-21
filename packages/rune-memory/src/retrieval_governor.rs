// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — RetrievalGovernor trait for RAG retrieval governance at
// the integration boundary. Evaluates retrieval requests, manages
// collection policies, and enforces sensitivity ceilings.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MemoryError;
use crate::memory::MemorySensitivity;
use crate::retrieval::{RetrievalGovernancePolicy, RetrievalRequest};

// ── RetrievalGovernanceDecision ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalGovernanceDecision {
    Permit {
        max_results: usize,
        policy_ref: String,
    },
    Deny {
        reason: String,
        policy_ref: String,
    },
    FilterResults {
        allowed_count: usize,
        filtered_count: usize,
        reason: String,
    },
    RequireProvenance {
        collection_id: String,
    },
}

impl fmt::Display for RetrievalGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permit { max_results, policy_ref } => {
                write!(f, "Permit(max={max_results}, policy={policy_ref})")
            }
            Self::Deny { reason, policy_ref } => {
                write!(f, "Deny(policy={policy_ref}): {reason}")
            }
            Self::FilterResults {
                allowed_count,
                filtered_count,
                reason,
            } => write!(
                f,
                "FilterResults({allowed_count}/{filtered_count}): {reason}"
            ),
            Self::RequireProvenance { collection_id } => {
                write!(f, "RequireProvenance({collection_id})")
            }
        }
    }
}

// ── RetrievalGovernanceResult ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalGovernanceResult {
    pub request_id: String,
    pub decision: RetrievalGovernanceDecision,
    pub sensitivity_ceiling: Option<MemorySensitivity>,
    pub evaluated_at: i64,
}

// ── RetrievalGovernor trait ───────────────────────────────────────

pub trait RetrievalGovernor {
    fn evaluate_retrieval_request(
        &self,
        request: &RetrievalRequest,
        agent_context: &HashMap<String, String>,
    ) -> Result<RetrievalGovernanceResult, MemoryError>;

    fn register_collection_policy(
        &mut self,
        collection_id: &str,
        policy: RetrievalGovernancePolicy,
    ) -> Result<(), MemoryError>;

    fn remove_collection_policy(&mut self, collection_id: &str) -> Result<(), MemoryError>;

    fn list_collection_policies(&self) -> Vec<(String, RetrievalGovernancePolicy)>;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryRetrievalGovernor ─────────────────────────────────────

pub struct InMemoryRetrievalGovernor {
    id: String,
    active: bool,
    collection_policies: HashMap<String, RetrievalGovernancePolicy>,
}

impl InMemoryRetrievalGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            collection_policies: HashMap::new(),
        }
    }
}

impl RetrievalGovernor for InMemoryRetrievalGovernor {
    fn evaluate_retrieval_request(
        &self,
        request: &RetrievalRequest,
        _agent_context: &HashMap<String, String>,
    ) -> Result<RetrievalGovernanceResult, MemoryError> {
        // Find applicable policy for this collection
        let policy = self.collection_policies.get(&request.collection_id);

        let (decision, ceiling) = match policy {
            Some(p) => {
                if !p.is_collection_allowed(&request.collection_id) {
                    (
                        RetrievalGovernanceDecision::Deny {
                            reason: format!(
                                "collection '{}' denied by policy '{}'",
                                request.collection_id, p.policy_id
                            ),
                            policy_ref: p.policy_id.clone(),
                        },
                        p.sensitivity_ceiling.clone(),
                    )
                } else if p.require_provenance {
                    (
                        RetrievalGovernanceDecision::RequireProvenance {
                            collection_id: request.collection_id.clone(),
                        },
                        p.sensitivity_ceiling.clone(),
                    )
                } else {
                    let max = p
                        .max_results_per_query
                        .map(|m| m.min(request.max_results))
                        .unwrap_or(request.max_results);
                    (
                        RetrievalGovernanceDecision::Permit {
                            max_results: max,
                            policy_ref: p.policy_id.clone(),
                        },
                        p.sensitivity_ceiling.clone(),
                    )
                }
            }
            None => {
                // No policy — permit with default limits
                (
                    RetrievalGovernanceDecision::Permit {
                        max_results: request.max_results,
                        policy_ref: "default".into(),
                    },
                    None,
                )
            }
        };

        Ok(RetrievalGovernanceResult {
            request_id: request.request_id.clone(),
            decision,
            sensitivity_ceiling: ceiling,
            evaluated_at: request.requested_at,
        })
    }

    fn register_collection_policy(
        &mut self,
        collection_id: &str,
        policy: RetrievalGovernancePolicy,
    ) -> Result<(), MemoryError> {
        self.collection_policies
            .insert(collection_id.into(), policy);
        Ok(())
    }

    fn remove_collection_policy(&mut self, collection_id: &str) -> Result<(), MemoryError> {
        self.collection_policies.remove(collection_id);
        Ok(())
    }

    fn list_collection_policies(&self) -> Vec<(String, RetrievalGovernancePolicy)> {
        self.collection_policies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── DenyAllRetrievalGovernor ──────────────────────────────────────

pub struct DenyAllRetrievalGovernor {
    id: String,
}

impl DenyAllRetrievalGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl RetrievalGovernor for DenyAllRetrievalGovernor {
    fn evaluate_retrieval_request(
        &self,
        request: &RetrievalRequest,
        _agent_context: &HashMap<String, String>,
    ) -> Result<RetrievalGovernanceResult, MemoryError> {
        Ok(RetrievalGovernanceResult {
            request_id: request.request_id.clone(),
            decision: RetrievalGovernanceDecision::Deny {
                reason: "all retrievals denied by policy".into(),
                policy_ref: "deny-all".into(),
            },
            sensitivity_ceiling: None,
            evaluated_at: request.requested_at,
        })
    }

    fn register_collection_policy(
        &mut self,
        _collection_id: &str,
        _policy: RetrievalGovernancePolicy,
    ) -> Result<(), MemoryError> {
        Err(MemoryError::InvalidOperation(
            "deny-all governor does not accept policies".into(),
        ))
    }

    fn remove_collection_policy(&mut self, _collection_id: &str) -> Result<(), MemoryError> {
        Ok(())
    }

    fn list_collection_policies(&self) -> Vec<(String, RetrievalGovernancePolicy)> {
        Vec::new()
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullRetrievalGovernor ─────────────────────────────────────────

pub struct NullRetrievalGovernor;

impl RetrievalGovernor for NullRetrievalGovernor {
    fn evaluate_retrieval_request(
        &self,
        request: &RetrievalRequest,
        _agent_context: &HashMap<String, String>,
    ) -> Result<RetrievalGovernanceResult, MemoryError> {
        Ok(RetrievalGovernanceResult {
            request_id: request.request_id.clone(),
            decision: RetrievalGovernanceDecision::Permit {
                max_results: request.max_results,
                policy_ref: "null".into(),
            },
            sensitivity_ceiling: None,
            evaluated_at: request.requested_at,
        })
    }

    fn register_collection_policy(
        &mut self,
        _collection_id: &str,
        _policy: RetrievalGovernancePolicy,
    ) -> Result<(), MemoryError> {
        Ok(())
    }

    fn remove_collection_policy(&mut self, _collection_id: &str) -> Result<(), MemoryError> {
        Ok(())
    }

    fn list_collection_policies(&self) -> Vec<(String, RetrievalGovernancePolicy)> {
        Vec::new()
    }

    fn governor_id(&self) -> &str {
        "null-retrieval-governor"
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

    fn make_request(collection: &str) -> RetrievalRequest {
        RetrievalRequest::new("rr-1", "agent-1", collection, "query", 10, 2000)
    }

    fn make_policy(id: &str) -> RetrievalGovernancePolicy {
        RetrievalGovernancePolicy::new(id, "agent-*", 1000)
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            RetrievalGovernanceDecision::Permit { max_results: 10, policy_ref: "p".into() },
            RetrievalGovernanceDecision::Deny { reason: "no".into(), policy_ref: "p".into() },
            RetrievalGovernanceDecision::FilterResults { allowed_count: 5, filtered_count: 3, reason: "filter".into() },
            RetrievalGovernanceDecision::RequireProvenance { collection_id: "docs".into() },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }

    #[test]
    fn test_in_memory_no_policy_permits() {
        let gov = InMemoryRetrievalGovernor::new("rg-1");
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        assert!(matches!(
            result.decision,
            RetrievalGovernanceDecision::Permit { .. }
        ));
    }

    #[test]
    fn test_in_memory_with_policy_permits() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        let mut policy = make_policy("rgp-1");
        policy.add_allowed_collection("docs");
        gov.register_collection_policy("docs", policy).unwrap();
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        assert!(matches!(
            result.decision,
            RetrievalGovernanceDecision::Permit { .. }
        ));
    }

    #[test]
    fn test_in_memory_denied_collection() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        let mut policy = make_policy("rgp-1");
        policy.add_denied_collection("private");
        gov.register_collection_policy("private", policy).unwrap();
        let result = gov
            .evaluate_retrieval_request(&make_request("private"), &HashMap::new())
            .unwrap();
        assert!(matches!(
            result.decision,
            RetrievalGovernanceDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_in_memory_require_provenance() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        let policy = make_policy("rgp-1").with_require_provenance(true);
        gov.register_collection_policy("docs", policy).unwrap();
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        assert!(matches!(
            result.decision,
            RetrievalGovernanceDecision::RequireProvenance { .. }
        ));
    }

    #[test]
    fn test_in_memory_max_results_capped() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        let policy = make_policy("rgp-1").with_max_results(3);
        gov.register_collection_policy("docs", policy).unwrap();
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        match result.decision {
            RetrievalGovernanceDecision::Permit { max_results, .. } => assert_eq!(max_results, 3),
            _ => panic!("expected Permit"),
        }
    }

    #[test]
    fn test_in_memory_sensitivity_ceiling() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        let policy = make_policy("rgp-1")
            .with_sensitivity_ceiling(MemorySensitivity::Internal);
        gov.register_collection_policy("docs", policy).unwrap();
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        assert_eq!(
            result.sensitivity_ceiling,
            Some(MemorySensitivity::Internal)
        );
    }

    #[test]
    fn test_remove_collection_policy() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        gov.register_collection_policy("docs", make_policy("rgp-1"))
            .unwrap();
        gov.remove_collection_policy("docs").unwrap();
        assert!(gov.list_collection_policies().is_empty());
    }

    #[test]
    fn test_list_collection_policies() {
        let mut gov = InMemoryRetrievalGovernor::new("rg-1");
        gov.register_collection_policy("a", make_policy("p1")).unwrap();
        gov.register_collection_policy("b", make_policy("p2")).unwrap();
        assert_eq!(gov.list_collection_policies().len(), 2);
    }

    #[test]
    fn test_deny_all_governor() {
        let mut gov = DenyAllRetrievalGovernor::new("deny-all");
        assert!(gov.is_active());
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        assert!(matches!(
            result.decision,
            RetrievalGovernanceDecision::Deny { .. }
        ));
        assert!(gov.register_collection_policy("x", make_policy("p")).is_err());
        assert!(gov.list_collection_policies().is_empty());
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullRetrievalGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-retrieval-governor");
        let result = gov
            .evaluate_retrieval_request(&make_request("docs"), &HashMap::new())
            .unwrap();
        assert!(matches!(
            result.decision,
            RetrievalGovernanceDecision::Permit { .. }
        ));
        gov.register_collection_policy("x", make_policy("p")).unwrap();
    }

    #[test]
    fn test_governor_id() {
        let gov = InMemoryRetrievalGovernor::new("my-gov");
        assert_eq!(gov.governor_id(), "my-gov");
    }
}
