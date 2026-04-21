// ═══════════════════════════════════════════════════════════════════════
// External Evaluator Integration — Layer 3 trait boundary for
// submitting policy packages to external evaluation engines.
//
// Does NOT implement actual OPA/Cedar/XACML evaluator calls — those
// belong in adapter crates. Ships InMemoryExternalEvaluatorIntegration
// (local echo-loop for testing) and NullExternalEvaluatorIntegration.
//
// rune-permissions' ExternalPolicyEvaluator decides; this trait
// packages and submits. The scope boundary: rune-policy-ext prepares
// packages for evaluation, rune-permissions performs the decision.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::PolicyExtError;

// ── EvaluatorType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluatorType {
    OpaRego,
    Cedar,
    XacmlPdp,
    InternalRune,
    Custom { name: String },
}

impl fmt::Display for EvaluatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpaRego => f.write_str("opa-rego"),
            Self::Cedar => f.write_str("cedar"),
            Self::XacmlPdp => f.write_str("xacml-pdp"),
            Self::InternalRune => f.write_str("internal-rune"),
            Self::Custom { name } => write!(f, "custom({name})"),
        }
    }
}

// ── EvaluationPayload ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationPayload {
    pub payload_id: String,
    pub target_evaluator: EvaluatorType,
    pub serialized_package: Vec<u8>,
    pub evaluation_config: HashMap<String, String>,
}

// ── EvaluationHandle ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvaluationHandle(pub String);

impl fmt::Display for EvaluationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── EvaluationResult ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationResult {
    pub result_id: String,
    pub handle_ref: String,
    pub decision_outcome: String,
    pub evaluation_duration_microseconds: String,
    pub evaluator_metadata: HashMap<String, String>,
    pub completed_at: String,
}

// ── ExternalEvaluatorIntegration trait ────────────────────────────

pub trait ExternalEvaluatorIntegration {
    fn prepare_package_for_evaluation(
        &self,
        package_bytes: &[u8],
        evaluator_type: &EvaluatorType,
    ) -> Result<EvaluationPayload, PolicyExtError>;

    fn submit_for_evaluation(
        &mut self,
        payload: &EvaluationPayload,
    ) -> Result<EvaluationHandle, PolicyExtError>;

    fn fetch_evaluation_result(
        &self,
        handle: &EvaluationHandle,
    ) -> Result<EvaluationResult, PolicyExtError>;

    fn cancel_evaluation(
        &mut self,
        handle: &EvaluationHandle,
    ) -> Result<(), PolicyExtError>;

    fn supported_evaluator_types(&self) -> Vec<EvaluatorType>;
    fn integration_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryExternalEvaluatorIntegration ──────────────────────────

pub struct InMemoryExternalEvaluatorIntegration {
    id: String,
    pending: HashMap<String, EvaluationPayload>,
    results: HashMap<String, EvaluationResult>,
    next_handle: usize,
}

impl InMemoryExternalEvaluatorIntegration {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            pending: HashMap::new(),
            results: HashMap::new(),
            next_handle: 0,
        }
    }
}

impl ExternalEvaluatorIntegration for InMemoryExternalEvaluatorIntegration {
    fn prepare_package_for_evaluation(
        &self,
        package_bytes: &[u8],
        evaluator_type: &EvaluatorType,
    ) -> Result<EvaluationPayload, PolicyExtError> {
        Ok(EvaluationPayload {
            payload_id: format!("payload-{}", self.next_handle),
            target_evaluator: evaluator_type.clone(),
            serialized_package: package_bytes.to_vec(),
            evaluation_config: HashMap::new(),
        })
    }

    fn submit_for_evaluation(
        &mut self,
        payload: &EvaluationPayload,
    ) -> Result<EvaluationHandle, PolicyExtError> {
        let handle_id = format!("eval-{}", self.next_handle);
        self.next_handle += 1;
        self.pending.insert(handle_id.clone(), payload.clone());

        // Echo-loop: immediately produce a result
        let result = EvaluationResult {
            result_id: format!("result-{handle_id}"),
            handle_ref: handle_id.clone(),
            decision_outcome: "Permit".to_string(),
            evaluation_duration_microseconds: "100".to_string(),
            evaluator_metadata: {
                let mut m = HashMap::new();
                m.insert(
                    "evaluator".to_string(),
                    payload.target_evaluator.to_string(),
                );
                m
            },
            completed_at: "2026-04-20T00:00:00Z".to_string(),
        };
        self.results.insert(handle_id.clone(), result);

        Ok(EvaluationHandle(handle_id))
    }

    fn fetch_evaluation_result(
        &self,
        handle: &EvaluationHandle,
    ) -> Result<EvaluationResult, PolicyExtError> {
        self.results
            .get(&handle.0)
            .cloned()
            .ok_or_else(|| {
                PolicyExtError::InvalidOperation(format!("no result for handle {}", handle.0))
            })
    }

    fn cancel_evaluation(
        &mut self,
        handle: &EvaluationHandle,
    ) -> Result<(), PolicyExtError> {
        self.pending.remove(&handle.0);
        self.results.remove(&handle.0);
        Ok(())
    }

    fn supported_evaluator_types(&self) -> Vec<EvaluatorType> {
        vec![
            EvaluatorType::OpaRego,
            EvaluatorType::Cedar,
            EvaluatorType::XacmlPdp,
            EvaluatorType::InternalRune,
        ]
    }

    fn integration_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullExternalEvaluatorIntegration ──────────────────────────────

pub struct NullExternalEvaluatorIntegration {
    id: String,
}

impl NullExternalEvaluatorIntegration {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ExternalEvaluatorIntegration for NullExternalEvaluatorIntegration {
    fn prepare_package_for_evaluation(
        &self,
        _package_bytes: &[u8],
        _evaluator_type: &EvaluatorType,
    ) -> Result<EvaluationPayload, PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "null evaluator integration".to_string(),
        ))
    }

    fn submit_for_evaluation(
        &mut self,
        _payload: &EvaluationPayload,
    ) -> Result<EvaluationHandle, PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "null evaluator integration".to_string(),
        ))
    }

    fn fetch_evaluation_result(
        &self,
        _handle: &EvaluationHandle,
    ) -> Result<EvaluationResult, PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "null evaluator integration".to_string(),
        ))
    }

    fn cancel_evaluation(
        &mut self,
        _handle: &EvaluationHandle,
    ) -> Result<(), PolicyExtError> {
        Ok(())
    }

    fn supported_evaluator_types(&self) -> Vec<EvaluatorType> { Vec::new() }
    fn integration_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluator_type_display() {
        assert_eq!(EvaluatorType::OpaRego.to_string(), "opa-rego");
        assert_eq!(EvaluatorType::Cedar.to_string(), "cedar");
        assert_eq!(EvaluatorType::XacmlPdp.to_string(), "xacml-pdp");
        assert_eq!(EvaluatorType::InternalRune.to_string(), "internal-rune");
        assert_eq!(
            EvaluatorType::Custom {
                name: "my-engine".into()
            }
            .to_string(),
            "custom(my-engine)"
        );
    }

    #[test]
    fn test_evaluation_handle_display() {
        let handle = EvaluationHandle("eval-42".to_string());
        assert_eq!(handle.to_string(), "eval-42");
    }

    #[test]
    fn test_prepare_and_submit() {
        let mut integration = InMemoryExternalEvaluatorIntegration::new("int-1");
        let payload = integration
            .prepare_package_for_evaluation(b"policy data", &EvaluatorType::OpaRego)
            .unwrap();
        assert_eq!(payload.target_evaluator, EvaluatorType::OpaRego);

        let handle = integration.submit_for_evaluation(&payload).unwrap();
        let result = integration.fetch_evaluation_result(&handle).unwrap();
        assert_eq!(result.decision_outcome, "Permit");
        assert_eq!(result.handle_ref, handle.0);
    }

    #[test]
    fn test_cancel_evaluation() {
        let mut integration = InMemoryExternalEvaluatorIntegration::new("int-1");
        let payload = integration
            .prepare_package_for_evaluation(b"data", &EvaluatorType::Cedar)
            .unwrap();
        let handle = integration.submit_for_evaluation(&payload).unwrap();
        integration.cancel_evaluation(&handle).unwrap();
        assert!(integration.fetch_evaluation_result(&handle).is_err());
    }

    #[test]
    fn test_supported_types() {
        let integration = InMemoryExternalEvaluatorIntegration::new("int-1");
        let types = integration.supported_evaluator_types();
        assert_eq!(types.len(), 4);
        assert!(types.contains(&EvaluatorType::OpaRego));
        assert!(types.contains(&EvaluatorType::Cedar));
    }

    #[test]
    fn test_integration_id() {
        let integration = InMemoryExternalEvaluatorIntegration::new("my-int");
        assert_eq!(integration.integration_id(), "my-int");
        assert!(integration.is_active());
    }

    #[test]
    fn test_null_integration() {
        let mut integration = NullExternalEvaluatorIntegration::new("null-1");
        assert!(!integration.is_active());
        assert!(integration.supported_evaluator_types().is_empty());
        assert!(integration
            .prepare_package_for_evaluation(b"x", &EvaluatorType::OpaRego)
            .is_err());
        assert!(integration
            .submit_for_evaluation(&EvaluationPayload {
                payload_id: "p".into(),
                target_evaluator: EvaluatorType::OpaRego,
                serialized_package: vec![],
                evaluation_config: HashMap::new(),
            })
            .is_err());
    }

    #[test]
    fn test_fetch_nonexistent() {
        let integration = InMemoryExternalEvaluatorIntegration::new("int-1");
        assert!(integration
            .fetch_evaluation_result(&EvaluationHandle("nonexistent".into()))
            .is_err());
    }
}
