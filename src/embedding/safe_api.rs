// ═══════════════════════════════════════════════════════════════════════
// Safe Rust Embedding API
//
// A safe, ergonomic Rust wrapper around the RUNE runtime pipeline.
// No raw pointers or unsafe code — external Rust users get a clean API.
//
// Pillar: Security Baked In — fail-closed by default. Errors produce Deny.
// ═══════════════════════════════════════════════════════════════════════

use crate::runtime::audit::AuditRecord;
use crate::runtime::evaluator::{PolicyDecision, PolicyRequest};
use crate::runtime::pipeline::{PipelineConfig, RuntimePipeline};

// ── Safe request / decision types ──────────────────────────────────

/// A policy evaluation request (safe Rust counterpart to RunePolicyRequest).
#[derive(Debug, Clone)]
pub struct EmbeddingRequest {
    pub subject_id: i64,
    pub action: i64,
    pub resource_id: i64,
    pub risk_score: i64,
    pub context: Option<serde_json::Value>,
}

impl EmbeddingRequest {
    pub fn new(subject_id: i64, action: i64, resource_id: i64, risk_score: i64) -> Self {
        Self {
            subject_id,
            action,
            resource_id,
            risk_score,
            context: None,
        }
    }

    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }
}

/// A policy evaluation decision (safe Rust counterpart to RunePolicyDecision).
#[derive(Debug, Clone)]
pub struct EmbeddingDecision {
    pub outcome: PolicyDecision,
    pub matched_rule: String,
    pub evaluation_duration: std::time::Duration,
    pub error: Option<String>,
    pub audit_record_id: u64,
}

// ── RuneEngine ─────────────────────────────────────────────────────

/// Safe Rust wrapper around a loaded RUNE policy module.
///
/// Thread safety: a RuneEngine is NOT thread-safe. Each thread should
/// create its own engine instance.
pub struct RuneEngine {
    pipeline: RuntimePipeline,
}

impl RuneEngine {
    /// Load and compile a RUNE policy module from source code.
    pub fn from_source(
        source: &str,
        signing_key: &[u8],
        module_name: &str,
    ) -> Result<Self, String> {
        let config = PipelineConfig {
            signing_key: signing_key.to_vec(),
            module_name: module_name.to_string(),
            attestation_checker: None,
        };

        let pipeline = RuntimePipeline::from_source(source, config)
            .map_err(|e| e.to_string())?;

        Ok(Self { pipeline })
    }

    /// Load a RUNE policy module from pre-compiled WASM bytes.
    pub fn from_wasm(
        wasm_bytes: &[u8],
        signing_key: &[u8],
        module_name: &str,
    ) -> Result<Self, String> {
        let policy_module = crate::runtime::evaluator::PolicyModule::from_bytes(wasm_bytes)
            .map_err(|e| e.to_string())?;

        let evaluator = crate::runtime::evaluator::AuditedPolicyEvaluator::new(
            &policy_module,
            signing_key.to_vec(),
            module_name,
        )
        .map_err(|e| e.to_string())?;

        let pipeline = RuntimePipeline::from_evaluator(evaluator);
        Ok(Self { pipeline })
    }

    /// Evaluate a policy request.
    ///
    /// FAIL-CLOSED: any runtime error produces a Deny decision with
    /// the error message populated. This method never returns an
    /// implicit Permit due to an internal failure.
    pub fn evaluate(&mut self, request: &EmbeddingRequest) -> EmbeddingDecision {
        let policy_request = PolicyRequest::new(
            request.subject_id,
            request.action,
            request.resource_id,
            request.risk_score,
        );

        match self.pipeline.evaluate(&policy_request) {
            Ok(result) => {
                let audit_id = self.pipeline.audit_trail().len() as u64;
                EmbeddingDecision {
                    outcome: result.decision,
                    matched_rule: "evaluate".to_string(),
                    evaluation_duration: result.evaluation_duration,
                    error: None,
                    audit_record_id: audit_id,
                }
            }
            Err(err) => {
                // FAIL-CLOSED: error → Deny.
                EmbeddingDecision {
                    outcome: PolicyDecision::Deny,
                    matched_rule: String::new(),
                    evaluation_duration: std::time::Duration::ZERO,
                    error: Some(err.to_string()),
                    audit_record_id: 0,
                }
            }
        }
    }

    /// Get the number of audit records.
    pub fn audit_trail_len(&self) -> usize {
        self.pipeline.audit_trail().len()
    }

    /// Export all audit records for independent verification.
    pub fn export_audit_log(&self) -> Vec<AuditRecord> {
        self.pipeline.export_audit_log()
    }
}

impl std::fmt::Debug for RuneEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuneEngine")
            .field("audit_trail_len", &self.audit_trail_len())
            .finish()
    }
}
