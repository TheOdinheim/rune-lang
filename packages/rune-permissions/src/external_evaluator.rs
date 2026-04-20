// ═══════════════════════════════════════════════════════════════════════
// External Policy Evaluator — Integration point for external engines.
//
// Layer 3 defines the contract for delegating policy evaluation to
// external authorization services (OPA, Cedar, AuthZed, etc.).
// No HTTP clients or SDK integrations — those belong in adapter crates.
//
// NullExternalEvaluator returns Indeterminate (not Deny) so that
// external evaluator unavailability does not silently become denial
// without going through the decision engine's fallback logic.
// ═══════════════════════════════════════════════════════════════════════

use crate::decision_engine::AuthorizationRequest;
use crate::error::PermissionError;

// ── ExternalEvaluatorType ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalEvaluatorType {
    Opa,
    Cedar,
    AuthZed,
    Custom,
}

impl std::fmt::Display for ExternalEvaluatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opa => write!(f, "OPA"),
            Self::Cedar => write!(f, "Cedar"),
            Self::AuthZed => write!(f, "AuthZed"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

// ── ExternalEvaluationResult ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalEvaluationResult {
    pub decision: String,
    pub evaluator_id: String,
    pub evaluation_latency_us: String,
    pub external_decision_id: String,
}

// ── ExternalPolicyEvaluator trait ────────────────────────────

pub trait ExternalPolicyEvaluator {
    fn evaluate_external(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<ExternalEvaluationResult, PermissionError>;

    fn evaluator_id(&self) -> &str;
    fn evaluator_type(&self) -> ExternalEvaluatorType;
    fn supported_policy_formats(&self) -> Vec<String>;
    fn is_active(&self) -> bool;
}

// ── NullExternalEvaluator ────────────────────────────────────

pub struct NullExternalEvaluator {
    id: String,
}

impl NullExternalEvaluator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ExternalPolicyEvaluator for NullExternalEvaluator {
    fn evaluate_external(
        &self,
        _request: &AuthorizationRequest,
    ) -> Result<ExternalEvaluationResult, PermissionError> {
        Ok(ExternalEvaluationResult {
            decision: "indeterminate".to_string(),
            evaluator_id: self.id.clone(),
            evaluation_latency_us: "0".to_string(),
            external_decision_id: "null".to_string(),
        })
    }

    fn evaluator_id(&self) -> &str {
        &self.id
    }

    fn evaluator_type(&self) -> ExternalEvaluatorType {
        ExternalEvaluatorType::Custom
    }

    fn supported_policy_formats(&self) -> Vec<String> {
        vec![]
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ── RecordingExternalEvaluator ───────────────────────────────

pub struct RecordingExternalEvaluator {
    id: String,
    inner: Box<dyn ExternalPolicyEvaluator>,
    recorded: std::cell::RefCell<Vec<RecordedCall>>,
}

#[derive(Debug, Clone)]
pub struct RecordedCall {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub result_decision: String,
}

impl RecordingExternalEvaluator {
    pub fn new(id: &str, inner: Box<dyn ExternalPolicyEvaluator>) -> Self {
        Self {
            id: id.to_string(),
            inner,
            recorded: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub fn recorded_calls(&self) -> Vec<RecordedCall> {
        self.recorded.borrow().clone()
    }

    pub fn call_count(&self) -> usize {
        self.recorded.borrow().len()
    }
}

impl ExternalPolicyEvaluator for RecordingExternalEvaluator {
    fn evaluate_external(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<ExternalEvaluationResult, PermissionError> {
        let result = self.inner.evaluate_external(request)?;
        self.recorded.borrow_mut().push(RecordedCall {
            subject: request.subject.as_str().to_string(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            result_decision: result.decision.clone(),
        });
        Ok(result)
    }

    fn evaluator_id(&self) -> &str {
        &self.id
    }

    fn evaluator_type(&self) -> ExternalEvaluatorType {
        self.inner.evaluator_type()
    }

    fn supported_policy_formats(&self) -> Vec<String> {
        self.inner.supported_policy_formats()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::IdentityRef;

    #[test]
    fn test_null_evaluator_returns_indeterminate() {
        let evaluator = NullExternalEvaluator::new("null-1");
        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "docs");
        let result = evaluator.evaluate_external(&req).unwrap();
        assert_eq!(result.decision, "indeterminate");
        assert_eq!(result.evaluator_id, "null-1");
        assert!(!evaluator.is_active());
    }

    #[test]
    fn test_null_evaluator_metadata() {
        let evaluator = NullExternalEvaluator::new("null-1");
        assert_eq!(evaluator.evaluator_id(), "null-1");
        assert_eq!(evaluator.evaluator_type(), ExternalEvaluatorType::Custom);
        assert!(evaluator.supported_policy_formats().is_empty());
    }

    #[test]
    fn test_recording_evaluator() {
        let inner = Box::new(NullExternalEvaluator::new("inner"));
        let recorder = RecordingExternalEvaluator::new("rec-1", inner);

        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "docs");
        recorder.evaluate_external(&req).unwrap();
        recorder.evaluate_external(&req).unwrap();

        assert_eq!(recorder.call_count(), 2);
        let calls = recorder.recorded_calls();
        assert_eq!(calls[0].subject, "alice");
        assert_eq!(calls[0].action, "read");
        assert_eq!(calls[0].result_decision, "indeterminate");
    }

    #[test]
    fn test_evaluator_type_display() {
        assert_eq!(ExternalEvaluatorType::Opa.to_string(), "OPA");
        assert_eq!(ExternalEvaluatorType::Cedar.to_string(), "Cedar");
        assert_eq!(ExternalEvaluatorType::AuthZed.to_string(), "AuthZed");
        assert_eq!(ExternalEvaluatorType::Custom.to_string(), "Custom");
    }

    #[test]
    fn test_external_evaluation_result_fields() {
        let result = ExternalEvaluationResult {
            decision: "permit".to_string(),
            evaluator_id: "opa-1".to_string(),
            evaluation_latency_us: "1500".to_string(),
            external_decision_id: "dec-abc123".to_string(),
        };
        assert_eq!(result.evaluation_latency_us, "1500");
        assert_eq!(result.external_decision_id, "dec-abc123");
    }
}
