// ═══════════════════════════════════════════════════════════════════════
// rune-rs — Rust integration for the RUNE governance-first policy engine
//
// Ergonomic Rust API wrapping the RUNE embedding layer. This is the crate
// that Rust developers add to their Cargo.toml for policy evaluation.
//
// Pillar: Security Baked In — fail-closed by default. Errors produce Deny.
// Pillar: Assumed Breach — every evaluation is audit-recorded.
// ═══════════════════════════════════════════════════════════════════════

use rune_lang::embedding::safe_api::{EmbeddingDecision, EmbeddingRequest, RuneEngine};
use rune_lang::runtime::audit::{AuditEventType, AuditRecord};
use rune_lang::runtime::evaluator::PolicyDecision;

// ── Error type ───────────────────────────────────────────────────────

/// Error type for RUNE policy operations.
#[derive(Debug, Clone)]
pub struct RuneError {
    pub message: String,
}

impl std::fmt::Display for RuneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RuneError: {}", self.message)
    }
}

impl std::error::Error for RuneError {}

impl From<String> for RuneError {
    fn from(message: String) -> Self {
        Self { message }
    }
}

// ── Outcome enum ─────────────────────────────────────────────────────

/// A governance policy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Permit,
    Deny,
    Escalate,
    Quarantine,
}

impl Outcome {
    pub fn is_permit(&self) -> bool {
        matches!(self, Outcome::Permit)
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Outcome::Deny)
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Permit => write!(f, "Permit"),
            Outcome::Deny => write!(f, "Deny"),
            Outcome::Escalate => write!(f, "Escalate"),
            Outcome::Quarantine => write!(f, "Quarantine"),
        }
    }
}

impl From<PolicyDecision> for Outcome {
    fn from(d: PolicyDecision) -> Self {
        match d {
            PolicyDecision::Permit => Outcome::Permit,
            PolicyDecision::Deny => Outcome::Deny,
            PolicyDecision::Escalate => Outcome::Escalate,
            PolicyDecision::Quarantine => Outcome::Quarantine,
        }
    }
}

// ── Request ──────────────────────────────────────────────────────────

/// A policy evaluation request with builder pattern support.
///
/// # Examples
/// ```ignore
/// let req = Request::new().subject(1).action(2).resource(3).risk(85);
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Request {
    pub subject_id: i64,
    pub action: i64,
    pub resource_id: i64,
    pub risk_score: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            subject_id: 0,
            action: 0,
            resource_id: 0,
            risk_score: 0,
            context: None,
        }
    }
}

impl Request {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subject(mut self, id: i64) -> Self {
        self.subject_id = id;
        self
    }

    pub fn action(mut self, action: i64) -> Self {
        self.action = action;
        self
    }

    pub fn resource(mut self, id: i64) -> Self {
        self.resource_id = id;
        self
    }

    pub fn risk(mut self, score: i64) -> Self {
        self.risk_score = score;
        self
    }

    pub fn context(mut self, ctx: serde_json::Value) -> Self {
        self.context = Some(ctx);
        self
    }
}

// ── Decision ─────────────────────────────────────────────────────────

/// The result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    pub matched_rule: String,
    pub evaluation_time: std::time::Duration,
    pub error: Option<String>,
    pub audit_id: u64,
}

// ── AuditEntry ───────────────────────────────────────────────────────

/// A simplified audit trail entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: u64,
    pub event_type: String,
    pub policy_module: String,
    pub function_name: String,
    pub decision: Option<Outcome>,
    pub timestamp: std::time::SystemTime,
}

impl From<&AuditRecord> for AuditEntry {
    fn from(r: &AuditRecord) -> Self {
        Self {
            id: r.record_id,
            event_type: r.event_type.to_string(),
            policy_module: r.policy_module.clone(),
            function_name: r.function_name.clone(),
            decision: r.decision.map(Outcome::from),
            timestamp: r.timestamp,
        }
    }
}

// ── PolicyEngine ─────────────────────────────────────────────────────

/// The default signing key used when none is provided.
/// In production deployments, callers should use `from_source_with_key`.
const DEFAULT_SIGNING_KEY: &[u8] = b"rune-rs-default-key";

/// A RUNE policy engine for evaluating governance policies.
///
/// Wraps the RUNE embedding API with an ergonomic Rust interface.
/// Thread safety: each thread should create its own `PolicyEngine`.
pub struct PolicyEngine {
    engine: RuneEngine,
    audit_cache: Vec<AuditEntry>,
}

impl PolicyEngine {
    /// Load a policy engine from RUNE source code with the default signing key.
    pub fn from_source(source: &str) -> Result<Self, RuneError> {
        Self::from_source_with_key(source, DEFAULT_SIGNING_KEY)
    }

    /// Load a policy engine from RUNE source code with a custom signing key.
    pub fn from_source_with_key(source: &str, signing_key: &[u8]) -> Result<Self, RuneError> {
        let engine = RuneEngine::from_source(source, signing_key, "rune-rs")
            .map_err(RuneError::from)?;
        Ok(Self {
            engine,
            audit_cache: Vec::new(),
        })
    }

    /// Load a policy engine from pre-compiled WASM bytes.
    pub fn from_wasm(wasm_bytes: &[u8]) -> Result<Self, RuneError> {
        let engine = RuneEngine::from_wasm(wasm_bytes, DEFAULT_SIGNING_KEY, "rune-rs")
            .map_err(RuneError::from)?;
        Ok(Self {
            engine,
            audit_cache: Vec::new(),
        })
    }

    /// Evaluate a policy request. Always returns a Decision (fail-closed).
    pub fn evaluate(&mut self, request: &Request) -> Decision {
        let embed_req = EmbeddingRequest::new(
            request.subject_id,
            request.action,
            request.resource_id,
            request.risk_score,
        );

        let embed_dec = self.engine.evaluate(&embed_req);
        self.refresh_audit_cache();

        Decision {
            outcome: Outcome::from(embed_dec.outcome),
            matched_rule: embed_dec.matched_rule,
            evaluation_time: embed_dec.evaluation_duration,
            error: embed_dec.error,
            audit_id: embed_dec.audit_record_id,
        }
    }

    /// Evaluate a policy request from a JSON string.
    ///
    /// The JSON must contain fields: subject_id, action, resource_id, risk_score.
    /// Returns Err if the JSON is malformed.
    pub fn evaluate_json(&mut self, json: &str) -> Result<Decision, RuneError> {
        let request: Request = serde_json::from_str(json)
            .map_err(|e| RuneError { message: format!("invalid JSON request: {e}") })?;
        Ok(self.evaluate(&request))
    }

    /// Returns all audit entries.
    pub fn audit_trail(&self) -> &[AuditEntry] {
        &self.audit_cache
    }

    /// Returns the number of audit entries.
    pub fn audit_count(&self) -> usize {
        self.engine.audit_trail_len()
    }

    fn refresh_audit_cache(&mut self) {
        let records = self.engine.export_audit_log();
        self.audit_cache = records.iter().map(AuditEntry::from).collect();
    }
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("audit_count", &self.audit_count())
            .finish()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn permit_source() -> &'static str {
        "policy access { rule allow(subject: Int, action: Int, resource: Int, risk: Int) { permit } }"
    }

    fn deny_source() -> &'static str {
        "policy access { rule block(subject: Int, action: Int, resource: Int, risk: Int) { deny } }"
    }

    fn escalate_source() -> &'static str {
        "policy access { rule esc(subject: Int, action: Int, resource: Int, risk: Int) { escalate } }"
    }

    fn quarantine_source() -> &'static str {
        "policy access { rule quar(subject: Int, action: Int, resource: Int, risk: Int) { quarantine } }"
    }

    fn risk_source() -> &'static str {
        r#"
        policy risk_based {
            rule check_risk(subject: Int, action: Int, resource: Int, risk: Int) {
                if risk > 50 { deny } else { permit }
            }
        }
        "#
    }

    #[test]
    fn test_from_source_valid() {
        let engine = PolicyEngine::from_source(permit_source());
        assert!(engine.is_ok());
    }

    #[test]
    fn test_from_source_invalid() {
        let engine = PolicyEngine::from_source("this is not valid rune code {{{");
        assert!(engine.is_err());
    }

    #[test]
    fn test_evaluate_permit() {
        let mut engine = PolicyEngine::from_source(permit_source()).unwrap();
        let decision = engine.evaluate(&Request::default());
        assert_eq!(decision.outcome, Outcome::Permit);
        assert!(decision.outcome.is_permit());
        assert!(!decision.outcome.is_deny());
    }

    #[test]
    fn test_evaluate_deny() {
        let mut engine = PolicyEngine::from_source(deny_source()).unwrap();
        let decision = engine.evaluate(&Request::default());
        assert_eq!(decision.outcome, Outcome::Deny);
        assert!(decision.outcome.is_deny());
        assert!(!decision.outcome.is_permit());
    }

    #[test]
    fn test_evaluate_escalate() {
        let mut engine = PolicyEngine::from_source(escalate_source()).unwrap();
        let decision = engine.evaluate(&Request::default());
        assert_eq!(decision.outcome, Outcome::Escalate);
    }

    #[test]
    fn test_evaluate_quarantine() {
        let mut engine = PolicyEngine::from_source(quarantine_source()).unwrap();
        let decision = engine.evaluate(&Request::default());
        assert_eq!(decision.outcome, Outcome::Quarantine);
    }

    #[test]
    fn test_risk_based_policy() {
        let mut engine = PolicyEngine::from_source(risk_source()).unwrap();

        let low_risk = Request::new().risk(30);
        assert_eq!(engine.evaluate(&low_risk).outcome, Outcome::Permit);

        let high_risk = Request::new().risk(80);
        assert_eq!(engine.evaluate(&high_risk).outcome, Outcome::Deny);
    }

    #[test]
    fn test_request_builder() {
        let req = Request::new().subject(1).action(2).resource(3).risk(85);
        assert_eq!(req.subject_id, 1);
        assert_eq!(req.action, 2);
        assert_eq!(req.resource_id, 3);
        assert_eq!(req.risk_score, 85);
        assert!(req.context.is_none());
    }

    #[test]
    fn test_request_default() {
        let req = Request::default();
        assert_eq!(req.subject_id, 0);
        assert_eq!(req.action, 0);
        assert_eq!(req.resource_id, 0);
        assert_eq!(req.risk_score, 0);
        assert!(req.context.is_none());
    }

    #[test]
    fn test_outcome_display() {
        assert_eq!(Outcome::Permit.to_string(), "Permit");
        assert_eq!(Outcome::Deny.to_string(), "Deny");
        assert_eq!(Outcome::Escalate.to_string(), "Escalate");
        assert_eq!(Outcome::Quarantine.to_string(), "Quarantine");
    }

    #[test]
    fn test_outcome_helpers() {
        assert!(Outcome::Permit.is_permit());
        assert!(!Outcome::Permit.is_deny());
        assert!(Outcome::Deny.is_deny());
        assert!(!Outcome::Deny.is_permit());
        assert!(!Outcome::Escalate.is_permit());
        assert!(!Outcome::Escalate.is_deny());
    }

    #[test]
    fn test_audit_trail_grows() {
        let mut engine = PolicyEngine::from_source(permit_source()).unwrap();
        assert_eq!(engine.audit_count(), 0);

        engine.evaluate(&Request::default());
        let count_after_one = engine.audit_count();
        assert!(count_after_one > 0);

        engine.evaluate(&Request::default());
        assert!(engine.audit_count() > count_after_one);
    }

    #[test]
    fn test_audit_entries_have_types() {
        let mut engine = PolicyEngine::from_source(permit_source()).unwrap();
        engine.evaluate(&Request::default());

        let trail = engine.audit_trail();
        assert!(!trail.is_empty());
        // Audit entries should have event type strings
        for entry in trail {
            assert!(!entry.event_type.is_empty());
        }
    }

    #[test]
    fn test_evaluate_json_valid() {
        let mut engine = PolicyEngine::from_source(risk_source()).unwrap();
        let json = r#"{"subject_id": 1, "action": 2, "resource_id": 3, "risk_score": 30}"#;
        let decision = engine.evaluate_json(json).unwrap();
        assert_eq!(decision.outcome, Outcome::Permit);
    }

    #[test]
    fn test_evaluate_json_invalid() {
        let mut engine = PolicyEngine::from_source(permit_source()).unwrap();
        let result = engine.evaluate_json("not json at all");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("invalid JSON"));
    }

    #[test]
    fn test_rune_error_display() {
        let err = RuneError { message: "test error".into() };
        assert_eq!(err.to_string(), "RuneError: test error");
    }
}
