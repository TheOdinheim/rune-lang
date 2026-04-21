// ═══════════════════════════════════════════════════════════════════════
// Claim Consistency Checker — Internal consistency verification for
// individual claims.
//
// Internal consistency is tractable where truth is not. A claim that
// says "X is both red and not red at the same time" can be rejected
// without knowing whether X is actually red. The checker examines a
// single claim's internal structure, not its relationship to other
// claims (that is ContradictionDetector's job).
//
// NotCheckable is a first-class outcome because many claim types
// (natural language assertions, subjective statements) are not
// mechanically checkable, and a checker that returns Inconsistent
// for every uncheckable claim is worse than one that honestly
// reports NotCheckable.
//
// Named ClaimConsistencyChecker to avoid collision with the existing
// ConsistencyChecker struct in consistency.rs.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::StoredClaim;
use crate::error::TruthError;

// ── ClaimConsistencyResult ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimConsistencyResult {
    Consistent,
    Inconsistent { reason: String, conflicting_subclaims: Vec<String> },
    NotCheckable { reason: String },
}

impl ClaimConsistencyResult {
    pub fn is_consistent(&self) -> bool {
        matches!(self, Self::Consistent)
    }

    pub fn is_inconsistent(&self) -> bool {
        matches!(self, Self::Inconsistent { .. })
    }
}

impl fmt::Display for ClaimConsistencyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consistent => f.write_str("Consistent"),
            Self::Inconsistent { reason, .. } => write!(f, "Inconsistent({reason})"),
            Self::NotCheckable { reason } => write!(f, "NotCheckable({reason})"),
        }
    }
}

// ── ClaimConsistencyChecker trait ──────────────────────────────────

pub trait ClaimConsistencyChecker {
    fn check_consistency(
        &self,
        claim: &StoredClaim,
    ) -> Result<ClaimConsistencyResult, TruthError>;

    fn checker_id(&self) -> &str;
    fn supported_claim_types(&self) -> Vec<String>;
    fn is_active(&self) -> bool;
}

// ── StructuralConsistencyChecker ───────────────────────────────────

pub struct StructuralConsistencyChecker {
    id: String,
}

impl StructuralConsistencyChecker {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ClaimConsistencyChecker for StructuralConsistencyChecker {
    fn check_consistency(
        &self,
        claim: &StoredClaim,
    ) -> Result<ClaimConsistencyResult, TruthError> {
        // Validate that the claim body parses as valid JSON and fields are present
        let body = std::str::from_utf8(&claim.claim_body_bytes)
            .map_err(|_| TruthError::ConsistencyCheckFailed("claim body is not valid UTF-8".into()))?;

        if body.trim().is_empty() {
            return Ok(ClaimConsistencyResult::Inconsistent {
                reason: "empty claim body".to_string(),
                conflicting_subclaims: Vec::new(),
            });
        }

        // Try JSON parse for structured claims
        if (body.starts_with('{') || body.starts_with('['))
            && serde_json::from_str::<serde_json::Value>(body).is_err()
        {
            return Ok(ClaimConsistencyResult::Inconsistent {
                reason: "claim body appears to be JSON but fails to parse".to_string(),
                conflicting_subclaims: Vec::new(),
            });
        }

        // Check for contradictory markers in the body
        let lower = body.to_lowercase();
        if (lower.contains("true") && lower.contains("false"))
            || (lower.contains("yes") && lower.contains("no "))
        {
            return Ok(ClaimConsistencyResult::Inconsistent {
                reason: "claim body contains contradictory boolean assertions".to_string(),
                conflicting_subclaims: vec!["true/false conflict".to_string()],
            });
        }

        Ok(ClaimConsistencyResult::Consistent)
    }

    fn checker_id(&self) -> &str { &self.id }
    fn supported_claim_types(&self) -> Vec<String> {
        vec!["factual-accuracy".to_string(), "completeness".to_string(), "consistency".to_string()]
    }
    fn is_active(&self) -> bool { true }
}

// ── TemporalConsistencyChecker ─────────────────────────────────────

pub struct TemporalClaimConsistencyChecker {
    id: String,
}

impl TemporalClaimConsistencyChecker {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ClaimConsistencyChecker for TemporalClaimConsistencyChecker {
    fn check_consistency(
        &self,
        claim: &StoredClaim,
    ) -> Result<ClaimConsistencyResult, TruthError> {
        let body = std::str::from_utf8(&claim.claim_body_bytes)
            .map_err(|_| TruthError::ConsistencyCheckFailed("claim body is not valid UTF-8".into()))?;

        // Look for timestamp pairs in the body and verify ordering
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
            let start = value.get("start_time").and_then(|v| v.as_i64());
            let end = value.get("end_time").and_then(|v| v.as_i64());

            if let (Some(s), Some(e)) = (start, end)
                && e < s
            {
                return Ok(ClaimConsistencyResult::Inconsistent {
                    reason: format!("end_time ({e}) precedes start_time ({s})"),
                    conflicting_subclaims: vec!["start_time".to_string(), "end_time".to_string()],
                });
            }

            let cause_at = value.get("cause_at").and_then(|v| v.as_i64());
            let effect_at = value.get("effect_at").and_then(|v| v.as_i64());

            if let (Some(c), Some(ef)) = (cause_at, effect_at)
                && ef < c
            {
                return Ok(ClaimConsistencyResult::Inconsistent {
                    reason: format!("effect_at ({ef}) precedes cause_at ({c})"),
                    conflicting_subclaims: vec!["cause_at".to_string(), "effect_at".to_string()],
                });
            }

            return Ok(ClaimConsistencyResult::Consistent);
        }

        Ok(ClaimConsistencyResult::NotCheckable {
            reason: "claim body is not structured JSON with temporal fields".to_string(),
        })
    }

    fn checker_id(&self) -> &str { &self.id }
    fn supported_claim_types(&self) -> Vec<String> {
        vec!["temporal".to_string(), "causal".to_string()]
    }
    fn is_active(&self) -> bool { true }
}

// ── NullConsistencyChecker ─────────────────────────────────────────

pub struct NullClaimConsistencyChecker {
    id: String,
}

impl NullClaimConsistencyChecker {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ClaimConsistencyChecker for NullClaimConsistencyChecker {
    fn check_consistency(
        &self,
        _claim: &StoredClaim,
    ) -> Result<ClaimConsistencyResult, TruthError> {
        Ok(ClaimConsistencyResult::NotCheckable {
            reason: "null checker always returns NotCheckable".to_string(),
        })
    }

    fn checker_id(&self) -> &str { &self.id }
    fn supported_claim_types(&self) -> Vec<String> { vec![] }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SubjectOfClaimRef;

    fn make_claim(body: &[u8]) -> StoredClaim {
        StoredClaim {
            claim_id: "test-claim".to_string(),
            subject_of_claim_ref: SubjectOfClaimRef::new("subject-1"),
            claim_type: "factual-accuracy".to_string(),
            claim_body_bytes: body.to_vec(),
            claimant: "alice".to_string(),
            asserted_at: 1000,
            confidence_score: "0.90".to_string(),
            evidence_attestation_refs: vec![],
            retracted_at: None,
        }
    }

    #[test]
    fn test_structural_consistent_plain_text() {
        let checker = StructuralConsistencyChecker::new("sc-1");
        let claim = make_claim(b"This is a simple claim");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_consistent());
    }

    #[test]
    fn test_structural_consistent_json() {
        let checker = StructuralConsistencyChecker::new("sc-1");
        let claim = make_claim(b"{\"status\": \"active\"}");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_consistent());
    }

    #[test]
    fn test_structural_inconsistent_empty_body() {
        let checker = StructuralConsistencyChecker::new("sc-1");
        let claim = make_claim(b"");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_inconsistent());
    }

    #[test]
    fn test_structural_inconsistent_bad_json() {
        let checker = StructuralConsistencyChecker::new("sc-1");
        let claim = make_claim(b"{invalid json");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_inconsistent());
    }

    #[test]
    fn test_structural_inconsistent_contradictory_booleans() {
        let checker = StructuralConsistencyChecker::new("sc-1");
        let claim = make_claim(b"The value is both true and false");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_inconsistent());
    }

    #[test]
    fn test_temporal_consistent() {
        let checker = TemporalClaimConsistencyChecker::new("tc-1");
        let claim = make_claim(b"{\"start_time\": 1000, \"end_time\": 2000}");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_consistent());
    }

    #[test]
    fn test_temporal_inconsistent_reversed_times() {
        let checker = TemporalClaimConsistencyChecker::new("tc-1");
        let claim = make_claim(b"{\"start_time\": 3000, \"end_time\": 1000}");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_inconsistent());
    }

    #[test]
    fn test_temporal_inconsistent_cause_after_effect() {
        let checker = TemporalClaimConsistencyChecker::new("tc-1");
        let claim = make_claim(b"{\"cause_at\": 5000, \"effect_at\": 1000}");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(result.is_inconsistent());
    }

    #[test]
    fn test_temporal_not_checkable_plain_text() {
        let checker = TemporalClaimConsistencyChecker::new("tc-1");
        let claim = make_claim(b"just some text, no temporal fields");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(matches!(result, ClaimConsistencyResult::NotCheckable { .. }));
    }

    #[test]
    fn test_null_checker_always_not_checkable() {
        let checker = NullClaimConsistencyChecker::new("null-1");
        let claim = make_claim(b"anything");
        let result = checker.check_consistency(&claim).unwrap();
        assert!(matches!(result, ClaimConsistencyResult::NotCheckable { .. }));
        assert!(!checker.is_active());
    }

    #[test]
    fn test_checker_metadata() {
        let checker = StructuralConsistencyChecker::new("sc-1");
        assert_eq!(checker.checker_id(), "sc-1");
        assert!(checker.is_active());
        assert!(!checker.supported_claim_types().is_empty());
    }

    #[test]
    fn test_claim_consistency_result_display() {
        assert_eq!(ClaimConsistencyResult::Consistent.to_string(), "Consistent");
        assert!(ClaimConsistencyResult::Inconsistent { reason: "bad".into(), conflicting_subclaims: vec![] }.to_string().contains("bad"));
        assert!(ClaimConsistencyResult::NotCheckable { reason: "nope".into() }.to_string().contains("nope"));
    }
}
