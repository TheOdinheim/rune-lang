// ═══════════════════════════════════════════════════════════════════════
// Retrieval — RAG retrieval governance types: policies, requests,
// decisions, and results for governing which agents can retrieve
// from which vector store collections under what conditions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::memory::MemorySensitivity;

// ── RetrievalDecision ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetrievalDecision {
    Permitted {
        collection_id: String,
        max_results: usize,
    },
    Denied {
        reason: String,
    },
    FilteredResults {
        original_count: usize,
        filtered_count: usize,
        reason: String,
    },
    RequiresProvenance {
        collection_id: String,
    },
}

impl fmt::Display for RetrievalDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permitted {
                collection_id,
                max_results,
            } => write!(f, "Permitted({collection_id}, max={max_results})"),
            Self::Denied { reason } => write!(f, "Denied({reason})"),
            Self::FilteredResults {
                original_count,
                filtered_count,
                reason,
            } => write!(
                f,
                "FilteredResults({original_count}→{filtered_count}, {reason})"
            ),
            Self::RequiresProvenance { collection_id } => {
                write!(f, "RequiresProvenance({collection_id})")
            }
        }
    }
}

// ── RetrievalGovernancePolicy ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalGovernancePolicy {
    pub policy_id: String,
    pub agent_id_pattern: String,
    pub allowed_collections: Vec<String>,
    pub denied_collections: Vec<String>,
    pub max_results_per_query: Option<usize>,
    pub require_provenance: bool,
    pub sensitivity_ceiling: Option<MemorySensitivity>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl RetrievalGovernancePolicy {
    pub fn new(
        policy_id: impl Into<String>,
        agent_id_pattern: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            agent_id_pattern: agent_id_pattern.into(),
            allowed_collections: Vec::new(),
            denied_collections: Vec::new(),
            max_results_per_query: None,
            require_provenance: false,
            sensitivity_ceiling: None,
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn add_allowed_collection(&mut self, collection: impl Into<String>) {
        self.allowed_collections.push(collection.into());
    }

    pub fn add_denied_collection(&mut self, collection: impl Into<String>) {
        self.denied_collections.push(collection.into());
    }

    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results_per_query = Some(max);
        self
    }

    pub fn with_require_provenance(mut self, required: bool) -> Self {
        self.require_provenance = required;
        self
    }

    pub fn with_sensitivity_ceiling(mut self, ceiling: MemorySensitivity) -> Self {
        self.sensitivity_ceiling = Some(ceiling);
        self
    }

    pub fn is_collection_allowed(&self, collection_id: &str) -> bool {
        if self.denied_collections.iter().any(|c| c == collection_id) {
            return false;
        }
        if self.allowed_collections.is_empty() {
            return true;
        }
        self.allowed_collections.iter().any(|c| c == collection_id)
    }
}

// ── RetrievalRequest ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalRequest {
    pub request_id: String,
    pub agent_id: String,
    pub collection_id: String,
    pub query_text: String,
    pub max_results: usize,
    pub requested_at: i64,
    pub context: HashMap<String, String>,
}

impl RetrievalRequest {
    pub fn new(
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
        collection_id: impl Into<String>,
        query_text: impl Into<String>,
        max_results: usize,
        requested_at: i64,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            agent_id: agent_id.into(),
            collection_id: collection_id.into(),
            query_text: query_text.into(),
            max_results,
            requested_at,
            context: HashMap::new(),
        }
    }
}

// ── RetrievalResult ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalResult {
    pub result_id: String,
    pub request_id: String,
    pub collection_id: String,
    pub result_count: usize,
    pub provenance_refs: Vec<String>,
    pub sensitivity_level: MemorySensitivity,
    pub retrieved_at: i64,
    pub metadata: HashMap<String, String>,
}

impl RetrievalResult {
    pub fn new(
        result_id: impl Into<String>,
        request_id: impl Into<String>,
        collection_id: impl Into<String>,
        result_count: usize,
        sensitivity_level: MemorySensitivity,
        retrieved_at: i64,
    ) -> Self {
        Self {
            result_id: result_id.into(),
            request_id: request_id.into(),
            collection_id: collection_id.into(),
            result_count,
            provenance_refs: Vec::new(),
            sensitivity_level,
            retrieved_at,
            metadata: HashMap::new(),
        }
    }

    pub fn add_provenance_ref(&mut self, provenance_ref: impl Into<String>) {
        self.provenance_refs.push(provenance_ref.into());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retrieval_decision_display() {
        let decisions = vec![
            RetrievalDecision::Permitted {
                collection_id: "docs".into(),
                max_results: 10,
            },
            RetrievalDecision::Denied {
                reason: "not authorized".into(),
            },
            RetrievalDecision::FilteredResults {
                original_count: 20,
                filtered_count: 5,
                reason: "sensitivity filter".into(),
            },
            RetrievalDecision::RequiresProvenance {
                collection_id: "external".into(),
            },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 4);
    }

    #[test]
    fn test_retrieval_governance_policy_construction() {
        let policy = RetrievalGovernancePolicy::new("rgp-1", "agent-*", 1000);
        assert_eq!(policy.policy_id, "rgp-1");
        assert_eq!(policy.agent_id_pattern, "agent-*");
        assert!(!policy.require_provenance);
        assert!(policy.allowed_collections.is_empty());
    }

    #[test]
    fn test_retrieval_policy_allowed_denied_collections() {
        let mut policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000);
        policy.add_allowed_collection("docs");
        policy.add_allowed_collection("kb");
        policy.add_denied_collection("private");
        assert!(policy.is_collection_allowed("docs"));
        assert!(policy.is_collection_allowed("kb"));
        assert!(!policy.is_collection_allowed("private"));
        assert!(!policy.is_collection_allowed("unknown"));
    }

    #[test]
    fn test_retrieval_policy_empty_allowed_permits_all() {
        let policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000);
        assert!(policy.is_collection_allowed("anything"));
    }

    #[test]
    fn test_retrieval_policy_denied_overrides_allowed() {
        let mut policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000);
        policy.add_allowed_collection("docs");
        policy.add_denied_collection("docs");
        assert!(!policy.is_collection_allowed("docs"));
    }

    #[test]
    fn test_retrieval_policy_builders() {
        let policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000)
            .with_max_results(50)
            .with_require_provenance(true)
            .with_sensitivity_ceiling(MemorySensitivity::Internal);
        assert_eq!(policy.max_results_per_query, Some(50));
        assert!(policy.require_provenance);
        assert_eq!(
            policy.sensitivity_ceiling,
            Some(MemorySensitivity::Internal)
        );
    }

    #[test]
    fn test_retrieval_request_construction() {
        let req = RetrievalRequest::new(
            "rr-1",
            "agent-1",
            "docs",
            "what is governance?",
            10,
            1000,
        );
        assert_eq!(req.request_id, "rr-1");
        assert_eq!(req.agent_id, "agent-1");
        assert_eq!(req.collection_id, "docs");
        assert_eq!(req.query_text, "what is governance?");
        assert_eq!(req.max_results, 10);
    }

    #[test]
    fn test_retrieval_result_construction() {
        let result = RetrievalResult::new(
            "res-1",
            "rr-1",
            "docs",
            5,
            MemorySensitivity::Public,
            2000,
        );
        assert_eq!(result.result_id, "res-1");
        assert_eq!(result.request_id, "rr-1");
        assert_eq!(result.result_count, 5);
        assert!(result.provenance_refs.is_empty());
    }

    #[test]
    fn test_retrieval_result_provenance() {
        let mut result = RetrievalResult::new(
            "res-1",
            "rr-1",
            "docs",
            3,
            MemorySensitivity::Internal,
            2000,
        );
        result.add_provenance_ref("attest-1");
        result.add_provenance_ref("attest-2");
        assert_eq!(result.provenance_refs.len(), 2);
    }

    #[test]
    fn test_retrieval_result_eq() {
        let r1 = RetrievalResult::new(
            "res-1",
            "rr-1",
            "docs",
            5,
            MemorySensitivity::Public,
            2000,
        );
        assert_eq!(r1, r1.clone());
    }

    #[test]
    fn test_retrieval_request_context() {
        let mut req = RetrievalRequest::new("rr-1", "agent-1", "docs", "query", 10, 1000);
        req.context.insert("session".into(), "abc".into());
        assert_eq!(req.context.get("session"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_retrieval_result_metadata() {
        let mut result = RetrievalResult::new(
            "res-1", "rr-1", "docs", 5, MemorySensitivity::Public, 2000,
        );
        result.metadata.insert("latency_ms".into(), "42".into());
        assert_eq!(result.metadata.len(), 1);
    }

    #[test]
    fn test_retrieval_policy_metadata() {
        let mut policy = RetrievalGovernancePolicy::new("rgp-1", "*", 1000);
        policy.metadata.insert("version".into(), "1".into());
        assert_eq!(policy.metadata.len(), 1);
    }
}
