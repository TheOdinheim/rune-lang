// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — SafetyCaseBuilder trait for constructing structured safety
// arguments (GSN, CAE, AMLAS, NIST AI RMF). Does NOT render notation —
// visualization belongs in adapter crates.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SafetyError;

// ── SafetyClaimType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyClaimType {
    TopLevel,
    SubClaim,
    Assumption,
    Justification,
    Context,
}

impl fmt::Display for SafetyClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TopLevel => f.write_str("TopLevel"),
            Self::SubClaim => f.write_str("SubClaim"),
            Self::Assumption => f.write_str("Assumption"),
            Self::Justification => f.write_str("Justification"),
            Self::Context => f.write_str("Context"),
        }
    }
}

// ── SafetyClaimStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyClaimStatus {
    Unsupported,
    PartiallySupported,
    FullySupported,
    Challenged,
}

impl fmt::Display for SafetyClaimStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Unsupported"),
            Self::PartiallySupported => f.write_str("PartiallySupported"),
            Self::FullySupported => f.write_str("FullySupported"),
            Self::Challenged => f.write_str("Challenged"),
        }
    }
}

// ── SafetyClaim ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyClaim {
    pub claim_id: String,
    pub case_id: String,
    pub claim_text: String,
    pub claim_type: SafetyClaimType,
    pub parent_claim_id: Option<String>,
    pub supporting_evidence_refs: Vec<String>,
    pub supporting_argument_refs: Vec<String>,
    pub status: SafetyClaimStatus,
}

// ── SafetyArgumentType ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyArgumentType {
    DirectEvidence,
    InferentialLink,
    Decomposition,
    Concretion,
}

impl fmt::Display for SafetyArgumentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectEvidence => f.write_str("DirectEvidence"),
            Self::InferentialLink => f.write_str("InferentialLink"),
            Self::Decomposition => f.write_str("Decomposition"),
            Self::Concretion => f.write_str("Concretion"),
        }
    }
}

// ── SafetyArgument ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyArgument {
    pub argument_id: String,
    pub case_id: String,
    pub argument_text: String,
    pub from_claim_id: String,
    pub to_claim_ids: Vec<String>,
    pub argument_type: SafetyArgumentType,
}

// ── CompletenessAssessment ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessAssessment {
    pub assessment_id: String,
    pub case_id: String,
    pub overall_complete: bool,
    pub unsupported_claims: Vec<String>,
    pub uncovered_hazards: Vec<String>,
    pub assessment_notes: String,
}

// ── SafetyCaseBuilder trait ─────────────────────────────────────────

pub trait SafetyCaseBuilder {
    fn create_case(
        &mut self,
        case_id: &str,
        system_id: &str,
        top_level_claim: &str,
    ) -> Result<(), SafetyError>;

    fn add_claim(&mut self, claim: SafetyClaim) -> Result<(), SafetyError>;

    fn add_argument(&mut self, argument: SafetyArgument) -> Result<(), SafetyError>;

    fn add_evidence_ref(
        &mut self,
        claim_id: &str,
        evidence_ref: &str,
    ) -> Result<(), SafetyError>;

    fn assess_completeness(&self, case_id: &str) -> Result<CompletenessAssessment, SafetyError>;

    fn finalize_case(&mut self, case_id: &str) -> Result<(), SafetyError>;

    fn builder_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemorySafetyCaseBuilder ───────────────────────────────────────

struct CaseState {
    #[allow(dead_code)]
    system_id: String,
    #[allow(dead_code)]
    top_level_claim: String,
    claims: Vec<SafetyClaim>,
    arguments: Vec<SafetyArgument>,
    finalized: bool,
}

pub struct InMemorySafetyCaseBuilder {
    id: String,
    cases: HashMap<String, CaseState>,
}

impl InMemorySafetyCaseBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            cases: HashMap::new(),
        }
    }
}

impl SafetyCaseBuilder for InMemorySafetyCaseBuilder {
    fn create_case(
        &mut self,
        case_id: &str,
        system_id: &str,
        top_level_claim: &str,
    ) -> Result<(), SafetyError> {
        if self.cases.contains_key(case_id) {
            return Err(SafetyError::SafetyCaseAlreadyExists(case_id.to_string()));
        }
        self.cases.insert(
            case_id.to_string(),
            CaseState {
                system_id: system_id.to_string(),
                top_level_claim: top_level_claim.to_string(),
                claims: Vec::new(),
                arguments: Vec::new(),
                finalized: false,
            },
        );
        Ok(())
    }

    fn add_claim(&mut self, claim: SafetyClaim) -> Result<(), SafetyError> {
        let state = self
            .cases
            .get_mut(&claim.case_id)
            .ok_or_else(|| SafetyError::SafetyCaseNotFound(claim.case_id.clone()))?;
        if state.finalized {
            return Err(SafetyError::InvalidOperation(
                "cannot add claim to finalized case".into(),
            ));
        }
        state.claims.push(claim);
        Ok(())
    }

    fn add_argument(&mut self, argument: SafetyArgument) -> Result<(), SafetyError> {
        let state = self
            .cases
            .get_mut(&argument.case_id)
            .ok_or_else(|| SafetyError::SafetyCaseNotFound(argument.case_id.clone()))?;
        if state.finalized {
            return Err(SafetyError::InvalidOperation(
                "cannot add argument to finalized case".into(),
            ));
        }
        state.arguments.push(argument);
        Ok(())
    }

    fn add_evidence_ref(
        &mut self,
        claim_id: &str,
        evidence_ref: &str,
    ) -> Result<(), SafetyError> {
        for state in self.cases.values_mut() {
            if state.finalized {
                continue;
            }
            for claim in &mut state.claims {
                if claim.claim_id == claim_id {
                    claim
                        .supporting_evidence_refs
                        .push(evidence_ref.to_string());
                    return Ok(());
                }
            }
        }
        Err(SafetyError::InvalidOperation(format!(
            "claim not found: {claim_id}"
        )))
    }

    fn assess_completeness(&self, case_id: &str) -> Result<CompletenessAssessment, SafetyError> {
        let state = self
            .cases
            .get(case_id)
            .ok_or_else(|| SafetyError::SafetyCaseNotFound(case_id.to_string()))?;
        let unsupported: Vec<String> = state
            .claims
            .iter()
            .filter(|c| c.status == SafetyClaimStatus::Unsupported)
            .map(|c| c.claim_id.clone())
            .collect();
        let overall_complete = unsupported.is_empty() && !state.claims.is_empty();
        Ok(CompletenessAssessment {
            assessment_id: format!("assess-{case_id}"),
            case_id: case_id.to_string(),
            overall_complete,
            unsupported_claims: unsupported,
            uncovered_hazards: Vec::new(),
            assessment_notes: if overall_complete {
                "all claims supported".into()
            } else {
                "unsupported claims remain".into()
            },
        })
    }

    fn finalize_case(&mut self, case_id: &str) -> Result<(), SafetyError> {
        let state = self
            .cases
            .get_mut(case_id)
            .ok_or_else(|| SafetyError::SafetyCaseNotFound(case_id.to_string()))?;
        state.finalized = true;
        Ok(())
    }

    fn builder_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullSafetyCaseBuilder ───────────────────────────────────────────

pub struct NullSafetyCaseBuilder;

impl SafetyCaseBuilder for NullSafetyCaseBuilder {
    fn create_case(&mut self, _: &str, _: &str, _: &str) -> Result<(), SafetyError> {
        Ok(())
    }
    fn add_claim(&mut self, _: SafetyClaim) -> Result<(), SafetyError> {
        Ok(())
    }
    fn add_argument(&mut self, _: SafetyArgument) -> Result<(), SafetyError> {
        Ok(())
    }
    fn add_evidence_ref(&mut self, _: &str, _: &str) -> Result<(), SafetyError> {
        Ok(())
    }
    fn assess_completeness(&self, case_id: &str) -> Result<CompletenessAssessment, SafetyError> {
        Ok(CompletenessAssessment {
            assessment_id: format!("null-{case_id}"),
            case_id: case_id.to_string(),
            overall_complete: false,
            unsupported_claims: Vec::new(),
            uncovered_hazards: Vec::new(),
            assessment_notes: "null builder".into(),
        })
    }
    fn finalize_case(&mut self, _: &str) -> Result<(), SafetyError> {
        Ok(())
    }
    fn builder_id(&self) -> &str {
        "null-safety-case-builder"
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

    fn sample_claim(case_id: &str, claim_id: &str, status: SafetyClaimStatus) -> SafetyClaim {
        SafetyClaim {
            claim_id: claim_id.into(),
            case_id: case_id.into(),
            claim_text: "System is safe".into(),
            claim_type: SafetyClaimType::TopLevel,
            parent_claim_id: None,
            supporting_evidence_refs: Vec::new(),
            supporting_argument_refs: Vec::new(),
            status,
        }
    }

    fn sample_argument(case_id: &str) -> SafetyArgument {
        SafetyArgument {
            argument_id: "arg-1".into(),
            case_id: case_id.into(),
            argument_text: "Decomposition into sub-goals".into(),
            from_claim_id: "cl-1".into(),
            to_claim_ids: vec!["cl-2".into()],
            argument_type: SafetyArgumentType::Decomposition,
        }
    }

    #[test]
    fn test_create_case() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "System is safe").unwrap();
        assert!(builder.create_case("case-1", "sys-1", "dup").is_err());
    }

    #[test]
    fn test_add_claim() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "safe").unwrap();
        builder
            .add_claim(sample_claim("case-1", "cl-1", SafetyClaimStatus::FullySupported))
            .unwrap();
    }

    #[test]
    fn test_add_claim_to_missing_case() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        assert!(builder
            .add_claim(sample_claim("missing", "cl-1", SafetyClaimStatus::Unsupported))
            .is_err());
    }

    #[test]
    fn test_add_argument() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "safe").unwrap();
        builder.add_argument(sample_argument("case-1")).unwrap();
    }

    #[test]
    fn test_add_evidence_ref() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "safe").unwrap();
        builder
            .add_claim(sample_claim("case-1", "cl-1", SafetyClaimStatus::Unsupported))
            .unwrap();
        builder.add_evidence_ref("cl-1", "ev-001").unwrap();
        assert!(builder.add_evidence_ref("missing-cl", "ev-001").is_err());
    }

    #[test]
    fn test_assess_completeness_complete() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "safe").unwrap();
        builder
            .add_claim(sample_claim("case-1", "cl-1", SafetyClaimStatus::FullySupported))
            .unwrap();
        let assess = builder.assess_completeness("case-1").unwrap();
        assert!(assess.overall_complete);
        assert!(assess.unsupported_claims.is_empty());
    }

    #[test]
    fn test_assess_completeness_incomplete() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "safe").unwrap();
        builder
            .add_claim(sample_claim("case-1", "cl-1", SafetyClaimStatus::Unsupported))
            .unwrap();
        let assess = builder.assess_completeness("case-1").unwrap();
        assert!(!assess.overall_complete);
        assert_eq!(assess.unsupported_claims, vec!["cl-1"]);
    }

    #[test]
    fn test_finalize_prevents_modification() {
        let mut builder = InMemorySafetyCaseBuilder::new("b1");
        builder.create_case("case-1", "sys-1", "safe").unwrap();
        builder.finalize_case("case-1").unwrap();
        assert!(builder
            .add_claim(sample_claim("case-1", "cl-1", SafetyClaimStatus::Unsupported))
            .is_err());
        assert!(builder.add_argument(sample_argument("case-1")).is_err());
    }

    #[test]
    fn test_null_builder() {
        let mut builder = NullSafetyCaseBuilder;
        assert!(!builder.is_active());
        builder.create_case("c", "s", "t").unwrap();
        let assess = builder.assess_completeness("c").unwrap();
        assert!(!assess.overall_complete);
    }

    #[test]
    fn test_enum_display() {
        assert!(!SafetyClaimType::TopLevel.to_string().is_empty());
        assert!(!SafetyClaimType::Assumption.to_string().is_empty());
        assert!(!SafetyClaimStatus::Unsupported.to_string().is_empty());
        assert!(!SafetyClaimStatus::FullySupported.to_string().is_empty());
        assert!(!SafetyArgumentType::DirectEvidence.to_string().is_empty());
        assert!(!SafetyArgumentType::Concretion.to_string().is_empty());
    }

    #[test]
    fn test_builder_id() {
        let builder = InMemorySafetyCaseBuilder::new("my-builder");
        assert_eq!(builder.builder_id(), "my-builder");
        assert!(builder.is_active());
    }
}
