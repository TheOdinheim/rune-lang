// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Memory access evaluator. Evaluates MemoryAccessRequest
// instances against scope isolation and sensitivity clearance, and
// RetrievalRequest instances against RetrievalGovernancePolicy.
// ═══════════════════════════════════════════════════════════════════════

use crate::memory::{
    MemoryAccessDecision, MemoryAccessRequest, MemoryEntry, MemorySensitivity,
};
use crate::retrieval::{RetrievalDecision, RetrievalGovernancePolicy, RetrievalRequest};

// ── SensitivityClearance ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitivityClearance {
    Cleared,
    InsufficientClearance {
        required: MemorySensitivity,
        actual: MemorySensitivity,
    },
}

impl std::fmt::Display for SensitivityClearance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cleared => write!(f, "Cleared"),
            Self::InsufficientClearance { required, actual } => {
                write!(
                    f,
                    "InsufficientClearance(required={required}, actual={actual})"
                )
            }
        }
    }
}

// ── MemoryAccessEvaluator ─────────────────────────────────────────

pub struct MemoryAccessEvaluator;

impl MemoryAccessEvaluator {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a memory access request. If the request references an
    /// entry, check sensitivity clearance against the requester's
    /// clearance level.
    pub fn evaluate_access(
        &self,
        request: &MemoryAccessRequest,
        entry: Option<&MemoryEntry>,
        requester_clearance: &MemorySensitivity,
    ) -> MemoryAccessDecision {
        // Check sensitivity clearance against entry if provided
        if let Some(entry) = entry {
            let clearance = self.check_sensitivity_clearance(
                requester_clearance,
                &entry.sensitivity_level,
            );
            match clearance {
                SensitivityClearance::Cleared => MemoryAccessDecision::Granted {
                    reason: format!(
                        "requester '{}' has sufficient clearance for scope '{}'",
                        request.requester_id, request.scope_id
                    ),
                },
                SensitivityClearance::InsufficientClearance { required, actual } => {
                    MemoryAccessDecision::Denied {
                        reason: format!(
                            "requester '{}' has clearance {} but entry requires {}",
                            request.requester_id, actual, required
                        ),
                    }
                }
            }
        } else {
            // No specific entry — grant access at scope level
            MemoryAccessDecision::Granted {
                reason: format!(
                    "scope-level {} access granted to '{}'",
                    request.access_type, request.requester_id
                ),
            }
        }
    }

    /// Evaluate a retrieval request against a governance policy.
    pub fn evaluate_retrieval(
        &self,
        request: &RetrievalRequest,
        policy: &RetrievalGovernancePolicy,
    ) -> RetrievalDecision {
        // Check collection access
        if !policy.is_collection_allowed(&request.collection_id) {
            return RetrievalDecision::Denied {
                reason: format!(
                    "collection '{}' is not permitted by policy '{}'",
                    request.collection_id, policy.policy_id
                ),
            };
        }

        // Check provenance requirement
        if policy.require_provenance {
            return RetrievalDecision::RequiresProvenance {
                collection_id: request.collection_id.clone(),
            };
        }

        // Apply max results limit
        let max_results = policy
            .max_results_per_query
            .map(|max| max.min(request.max_results))
            .unwrap_or(request.max_results);

        RetrievalDecision::Permitted {
            collection_id: request.collection_id.clone(),
            max_results,
        }
    }

    /// Check whether a requester's clearance level is sufficient for
    /// an entry's sensitivity level. Clearance must be >= sensitivity.
    pub fn check_sensitivity_clearance(
        &self,
        requester_clearance: &MemorySensitivity,
        entry_sensitivity: &MemorySensitivity,
    ) -> SensitivityClearance {
        if requester_clearance >= entry_sensitivity {
            SensitivityClearance::Cleared
        } else {
            SensitivityClearance::InsufficientClearance {
                required: entry_sensitivity.clone(),
                actual: requester_clearance.clone(),
            }
        }
    }
}

impl Default for MemoryAccessEvaluator {
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
    use crate::memory::{MemoryAccessType, MemoryContentType};

    fn make_entry(sensitivity: MemorySensitivity) -> MemoryEntry {
        MemoryEntry::new(
            "e1", "scope-1", "content",
            MemoryContentType::ConversationTurn,
            sensitivity, "agent-1", 1000,
        )
    }

    fn make_request() -> MemoryAccessRequest {
        MemoryAccessRequest::new("r1", "agent-1", "scope-1", MemoryAccessType::Read, 2000)
    }

    fn make_retrieval_request(collection: &str) -> RetrievalRequest {
        RetrievalRequest::new("rr-1", "agent-1", collection, "query text", 10, 2000)
    }

    #[test]
    fn test_evaluate_access_granted() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_request();
        let entry = make_entry(MemorySensitivity::Internal);
        let decision = evaluator.evaluate_access(
            &request,
            Some(&entry),
            &MemorySensitivity::Sensitive,
        );
        assert!(matches!(decision, MemoryAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_evaluate_access_denied_insufficient_clearance() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_request();
        let entry = make_entry(MemorySensitivity::Restricted);
        let decision = evaluator.evaluate_access(
            &request,
            Some(&entry),
            &MemorySensitivity::Internal,
        );
        assert!(matches!(decision, MemoryAccessDecision::Denied { .. }));
    }

    #[test]
    fn test_evaluate_access_no_entry() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_request();
        let decision = evaluator.evaluate_access(
            &request,
            None,
            &MemorySensitivity::Public,
        );
        assert!(matches!(decision, MemoryAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_evaluate_access_exact_clearance() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_request();
        let entry = make_entry(MemorySensitivity::Sensitive);
        let decision = evaluator.evaluate_access(
            &request,
            Some(&entry),
            &MemorySensitivity::Sensitive,
        );
        assert!(matches!(decision, MemoryAccessDecision::Granted { .. }));
    }

    #[test]
    fn test_evaluate_retrieval_permitted() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_retrieval_request("docs");
        let mut policy = RetrievalGovernancePolicy::new("rgp-1", "agent-*", 1000);
        policy.add_allowed_collection("docs");
        let decision = evaluator.evaluate_retrieval(&request, &policy);
        assert!(matches!(decision, RetrievalDecision::Permitted { .. }));
    }

    #[test]
    fn test_evaluate_retrieval_denied_collection() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_retrieval_request("private");
        let mut policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000);
        policy.add_denied_collection("private");
        let decision = evaluator.evaluate_retrieval(&request, &policy);
        assert!(matches!(decision, RetrievalDecision::Denied { .. }));
    }

    #[test]
    fn test_evaluate_retrieval_requires_provenance() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_retrieval_request("docs");
        let policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000)
            .with_require_provenance(true);
        let decision = evaluator.evaluate_retrieval(&request, &policy);
        assert!(matches!(
            decision,
            RetrievalDecision::RequiresProvenance { .. }
        ));
    }

    #[test]
    fn test_evaluate_retrieval_max_results_capped() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_retrieval_request("docs");
        let policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000)
            .with_max_results(5);
        let decision = evaluator.evaluate_retrieval(&request, &policy);
        match decision {
            RetrievalDecision::Permitted { max_results, .. } => assert_eq!(max_results, 5),
            _ => panic!("expected Permitted"),
        }
    }

    #[test]
    fn test_evaluate_retrieval_max_results_request_lower() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_retrieval_request("docs");
        let policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000)
            .with_max_results(50);
        let decision = evaluator.evaluate_retrieval(&request, &policy);
        match decision {
            RetrievalDecision::Permitted { max_results, .. } => assert_eq!(max_results, 10),
            _ => panic!("expected Permitted"),
        }
    }

    #[test]
    fn test_check_sensitivity_clearance_cleared() {
        let evaluator = MemoryAccessEvaluator::new();
        let result = evaluator.check_sensitivity_clearance(
            &MemorySensitivity::Restricted,
            &MemorySensitivity::Sensitive,
        );
        assert_eq!(result, SensitivityClearance::Cleared);
    }

    #[test]
    fn test_check_sensitivity_clearance_insufficient() {
        let evaluator = MemoryAccessEvaluator::new();
        let result = evaluator.check_sensitivity_clearance(
            &MemorySensitivity::Public,
            &MemorySensitivity::Sensitive,
        );
        assert!(matches!(
            result,
            SensitivityClearance::InsufficientClearance { .. }
        ));
    }

    #[test]
    fn test_sensitivity_clearance_display() {
        let c1 = SensitivityClearance::Cleared;
        assert_eq!(c1.to_string(), "Cleared");
        let c2 = SensitivityClearance::InsufficientClearance {
            required: MemorySensitivity::Restricted,
            actual: MemorySensitivity::Public,
        };
        assert!(c2.to_string().contains("Restricted"));
    }

    #[test]
    fn test_evaluator_default() {
        let _evaluator = MemoryAccessEvaluator;
    }

    #[test]
    fn test_evaluate_retrieval_empty_allowed_permits() {
        let evaluator = MemoryAccessEvaluator::new();
        let request = make_retrieval_request("anything");
        let policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000);
        let decision = evaluator.evaluate_retrieval(&request, &policy);
        assert!(matches!(decision, RetrievalDecision::Permitted { .. }));
    }

    #[test]
    fn test_check_sensitivity_clearance_equal() {
        let evaluator = MemoryAccessEvaluator::new();
        let result = evaluator.check_sensitivity_clearance(
            &MemorySensitivity::Internal,
            &MemorySensitivity::Internal,
        );
        assert_eq!(result, SensitivityClearance::Cleared);
    }
}
