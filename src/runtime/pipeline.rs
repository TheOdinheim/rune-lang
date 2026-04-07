// ═══════════════════════════════════════════════════════════════════════
// Runtime Pipeline — End-to-End Integration
//
// Full pipeline from .rune source to audited policy decisions:
//   source → compile → load → (attest) → evaluate → audit trail
//
// RuntimePipeline is the public API surface that host applications use.
// It wraps compilation, module loading, attestation, evaluation, and
// audit trail into a single cohesive interface.
//
// Pillar: Security Baked In — the pipeline enforces audit recording for
// every evaluation. There is no way to evaluate without an audit trail.
//
// Pillar: Zero Trust Throughout — optional attestation verification
// ensures only trusted models are invoked.
// ═══════════════════════════════════════════════════════════════════════

use crate::compiler::compile_source;
use crate::runtime::attestation::{
    AttestationChecker, AttestationError, AttestationVerdict, ModelAttestation,
};
use crate::runtime::audit::{AuditRecord, AuditTrail};
use crate::runtime::evaluator::{
    AuditedPolicyEvaluator, PolicyModule, PolicyRequest, PolicyResult, RuntimeError, Value,
};

// ── Pipeline configuration ───────────────────────────────────────────

/// Configuration for the runtime pipeline.
pub struct PipelineConfig {
    /// Signing key for the cryptographic audit trail.
    pub signing_key: Vec<u8>,
    /// Human-readable name for the module (used in audit records).
    pub module_name: String,
    /// Optional attestation checker for model trust chain verification.
    pub attestation_checker: Option<AttestationChecker>,
}

// ── RuntimePipeline ──────────────────────────────────────────────────

/// End-to-end runtime pipeline: compile → load → attest → evaluate → audit.
///
/// This is the primary API surface for host applications. It wraps the
/// full lifecycle of a RUNE policy module in a single struct.
pub struct RuntimePipeline {
    evaluator: AuditedPolicyEvaluator,
}

impl RuntimePipeline {
    /// Build a pipeline from RUNE source code.
    ///
    /// Compiles the source through the full compiler pipeline (lex → parse
    /// → type check → IR → codegen → WASM), loads the resulting module,
    /// and wraps it in an audited evaluator with optional attestation.
    pub fn from_source(source: &str, config: PipelineConfig) -> Result<Self, RuntimeError> {
        let wasm_bytes = compile_source(source, 0).map_err(|errors| {
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            RuntimeError::CompilationFailed(msgs.join("; "))
        })?;

        let module = PolicyModule::from_bytes(&wasm_bytes)?;

        let evaluator = AuditedPolicyEvaluator::new(
            &module,
            config.signing_key,
            &config.module_name,
        )?;

        let evaluator = match config.attestation_checker {
            Some(checker) => evaluator.with_attestation(checker),
            None => evaluator,
        };

        Ok(Self { evaluator })
    }

    /// Evaluate the standard `evaluate(subject_id, action, resource_id, risk_score)`
    /// entry point. The decision is automatically recorded in the audit trail.
    pub fn evaluate(&mut self, request: &PolicyRequest) -> Result<PolicyResult, RuntimeError> {
        self.evaluator.evaluate(request)
    }

    /// Evaluate an individual exported rule by name.
    /// The decision is automatically recorded in the audit trail.
    pub fn evaluate_rule(
        &mut self,
        rule_name: &str,
        args: &[Value],
    ) -> Result<PolicyResult, RuntimeError> {
        self.evaluator.evaluate_rule(rule_name, args)
    }

    /// Verify a model's attestation and record the result in the audit trail.
    pub fn verify_model(
        &mut self,
        attestation: &ModelAttestation,
    ) -> Result<AttestationVerdict, AttestationError> {
        self.evaluator.verify_model(attestation)
    }

    /// Access the cryptographic audit trail.
    pub fn audit_trail(&self) -> &AuditTrail {
        self.evaluator.audit_trail()
    }

    /// Export all audit records for independent verification.
    pub fn export_audit_log(&self) -> Vec<AuditRecord> {
        self.evaluator.export_audit_log()
    }
}

impl std::fmt::Debug for RuntimePipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimePipeline")
            .field("audit_trail_len", &self.audit_trail().len())
            .finish()
    }
}

// ── Legacy convenience functions ─────────────────────────────────────

/// Compile RUNE source code and load it as a reusable PolicyModule.
pub fn compile_and_load(source: &str) -> Result<PolicyModule, RuntimeError> {
    let wasm_bytes = compile_source(source, 0).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        RuntimeError::CompilationFailed(msgs.join("; "))
    })?;
    PolicyModule::from_bytes(&wasm_bytes)
}

/// Compile RUNE source code and evaluate a policy request in one step.
///
/// This is a convenience function for testing and one-shot evaluation.
/// For repeated evaluations, use `compile_and_load` to get a reusable
/// PolicyModule, or use `RuntimePipeline` for full audit trail support.
pub fn compile_and_evaluate(
    source: &str,
    request: &PolicyRequest,
) -> Result<PolicyResult, RuntimeError> {
    let module = compile_and_load(source)?;
    let evaluator = module.evaluator()?;
    evaluator.evaluate(request)
}
