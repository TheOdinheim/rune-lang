// ═══════════════════════════════════════════════════════════════════════
// Relational Contradiction Detector — Pairwise contradiction detection
// between claims.
//
// Where claim consistency is internal, contradiction detection is
// relational: given two claims, are they mutually exclusive?
//
// LikelyContradiction is distinct from DirectContradiction because
// many apparent contradictions are actually disagreements about
// definitions or scope. A detector that cannot distinguish "definitely
// contradictory" from "possibly contradictory" forces every
// disagreement into the same bucket.
//
// Named RelationalContradictionDetector to avoid collision with the
// existing ContradictionDetector struct in contradiction.rs.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::StoredClaim;
use crate::error::TruthError;

// ── ContradictionResult ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContradictionResult {
    NoContradiction,
    DirectContradiction { explanation: String },
    LikelyContradiction { explanation: String, similarity_score: String },
    NotComparable { reason: String },
}

impl ContradictionResult {
    pub fn is_contradiction(&self) -> bool {
        matches!(self, Self::DirectContradiction { .. } | Self::LikelyContradiction { .. })
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, Self::DirectContradiction { .. })
    }
}

impl fmt::Display for ContradictionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoContradiction => f.write_str("NoContradiction"),
            Self::DirectContradiction { explanation } => write!(f, "DirectContradiction({explanation})"),
            Self::LikelyContradiction { explanation, similarity_score } => {
                write!(f, "LikelyContradiction({explanation}, score={similarity_score})")
            }
            Self::NotComparable { reason } => write!(f, "NotComparable({reason})"),
        }
    }
}

// ── RelationalContradictionDetector trait ───────────────────────────

pub trait RelationalContradictionDetector {
    fn detect_contradiction(
        &self,
        claim_a: &StoredClaim,
        claim_b: &StoredClaim,
    ) -> Result<ContradictionResult, TruthError>;

    fn supported_claim_types(&self) -> Vec<String>;
    fn detector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── NegationContradictionDetector ──────────────────────────────────

pub struct NegationContradictionDetector {
    id: String,
}

impl NegationContradictionDetector {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

const NEGATION_MARKERS: &[&str] = &[
    "not", "no", "never", "false", "incorrect", "wrong", "isn't", "doesn't",
    "won't", "cannot", "neither", "nor", "none", "denied", "rejected",
];

impl RelationalContradictionDetector for NegationContradictionDetector {
    fn detect_contradiction(
        &self,
        claim_a: &StoredClaim,
        claim_b: &StoredClaim,
    ) -> Result<ContradictionResult, TruthError> {
        if claim_a.subject_of_claim_ref != claim_b.subject_of_claim_ref {
            return Ok(ContradictionResult::NotComparable {
                reason: "claims are about different subjects".to_string(),
            });
        }

        let body_a = String::from_utf8_lossy(&claim_a.claim_body_bytes).to_lowercase();
        let body_b = String::from_utf8_lossy(&claim_b.claim_body_bytes).to_lowercase();

        let neg_a = NEGATION_MARKERS.iter().any(|m| body_a.contains(m));
        let neg_b = NEGATION_MARKERS.iter().any(|m| body_b.contains(m));

        if neg_a != neg_b {
            // One has negation, the other doesn't — check content overlap
            let words_a: Vec<&str> = body_a.split_whitespace().collect();
            let words_b: Vec<&str> = body_b.split_whitespace().collect();
            let shared = words_a.iter().filter(|w| words_b.contains(w)).count();
            let total = words_a.len().max(words_b.len()).max(1);
            let overlap = shared as f64 / total as f64;

            if overlap > 0.4 {
                return Ok(ContradictionResult::DirectContradiction {
                    explanation: "negation pattern detected with high content overlap".to_string(),
                });
            } else if overlap > 0.2 {
                return Ok(ContradictionResult::LikelyContradiction {
                    explanation: "negation pattern detected with moderate overlap".to_string(),
                    similarity_score: format!("{overlap:.3}"),
                });
            }
        }

        Ok(ContradictionResult::NoContradiction)
    }

    fn supported_claim_types(&self) -> Vec<String> {
        vec!["factual-accuracy".to_string(), "completeness".to_string()]
    }
    fn detector_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── TemporalContradictionDetector ──────────────────────────────────

pub struct TemporalContradictionDetector {
    id: String,
}

impl TemporalContradictionDetector {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl RelationalContradictionDetector for TemporalContradictionDetector {
    fn detect_contradiction(
        &self,
        claim_a: &StoredClaim,
        claim_b: &StoredClaim,
    ) -> Result<ContradictionResult, TruthError> {
        if claim_a.subject_of_claim_ref != claim_b.subject_of_claim_ref {
            return Ok(ContradictionResult::NotComparable {
                reason: "claims are about different subjects".to_string(),
            });
        }

        let body_a = std::str::from_utf8(&claim_a.claim_body_bytes).unwrap_or("");
        let body_b = std::str::from_utf8(&claim_b.claim_body_bytes).unwrap_or("");

        let val_a = serde_json::from_str::<serde_json::Value>(body_a).ok();
        let val_b = serde_json::from_str::<serde_json::Value>(body_b).ok();

        if let (Some(va), Some(vb)) = (val_a, val_b) {
            let ts_a = va.get("timestamp").and_then(|v| v.as_i64());
            let ts_b = vb.get("timestamp").and_then(|v| v.as_i64());

            let order_a = va.get("ordering").and_then(|v| v.as_str()).map(String::from);
            let order_b = vb.get("ordering").and_then(|v| v.as_str()).map(String::from);

            // If both claim a specific ordering that is reversed
            if let (Some(oa), Some(ob)) = (&order_a, &order_b)
                && (oa == "before" && ob == "after" || oa == "after" && ob == "before")
                && let (Some(ta), Some(tb)) = (ts_a, ts_b)
                && ((oa == "before" && ta > tb) || (oa == "after" && ta < tb))
            {
                return Ok(ContradictionResult::DirectContradiction {
                    explanation: format!("temporal ordering conflict: claim A says '{oa}' at {ta}, claim B says '{ob}' at {tb}"),
                });
            }

            // If both provide timestamps for the same event but they differ significantly
            if let (Some(ta), Some(tb)) = (ts_a, ts_b) {
                let diff = (ta - tb).unsigned_abs();
                if diff > 86400 {
                    return Ok(ContradictionResult::LikelyContradiction {
                        explanation: format!("timestamps differ by {diff} seconds for same subject"),
                        similarity_score: "0.000".to_string(),
                    });
                }
            }

            return Ok(ContradictionResult::NoContradiction);
        }

        Ok(ContradictionResult::NotComparable {
            reason: "one or both claim bodies are not structured JSON with temporal fields".to_string(),
        })
    }

    fn supported_claim_types(&self) -> Vec<String> {
        vec!["temporal".to_string(), "causal".to_string()]
    }
    fn detector_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── ValueContradictionDetector ─────────────────────────────────────

pub struct ValueContradictionDetector {
    id: String,
    tolerance: f64,
}

impl ValueContradictionDetector {
    pub fn new(id: &str, tolerance: f64) -> Self {
        Self { id: id.to_string(), tolerance }
    }
}

impl RelationalContradictionDetector for ValueContradictionDetector {
    fn detect_contradiction(
        &self,
        claim_a: &StoredClaim,
        claim_b: &StoredClaim,
    ) -> Result<ContradictionResult, TruthError> {
        if claim_a.subject_of_claim_ref != claim_b.subject_of_claim_ref {
            return Ok(ContradictionResult::NotComparable {
                reason: "claims are about different subjects".to_string(),
            });
        }

        let body_a = std::str::from_utf8(&claim_a.claim_body_bytes).unwrap_or("");
        let body_b = std::str::from_utf8(&claim_b.claim_body_bytes).unwrap_or("");

        let val_a = serde_json::from_str::<serde_json::Value>(body_a).ok();
        let val_b = serde_json::from_str::<serde_json::Value>(body_b).ok();

        if let (Some(va), Some(vb)) = (val_a, val_b) {
            let num_a = va.get("value").and_then(|v| v.as_f64());
            let num_b = vb.get("value").and_then(|v| v.as_f64());

            if let (Some(na), Some(nb)) = (num_a, num_b) {
                let max_abs = na.abs().max(nb.abs()).max(1.0);
                let relative_diff = (na - nb).abs() / max_abs;

                if relative_diff > self.tolerance {
                    return Ok(ContradictionResult::DirectContradiction {
                        explanation: format!("numerical values differ by {:.1}% (tolerance: {:.1}%)", relative_diff * 100.0, self.tolerance * 100.0),
                    });
                }
            }

            return Ok(ContradictionResult::NoContradiction);
        }

        Ok(ContradictionResult::NotComparable {
            reason: "one or both claim bodies are not structured JSON with value fields".to_string(),
        })
    }

    fn supported_claim_types(&self) -> Vec<String> {
        vec!["numeric".to_string(), "measurement".to_string()]
    }
    fn detector_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullContradictionDetector ──────────────────────────────────────

pub struct NullRelationalContradictionDetector {
    id: String,
}

impl NullRelationalContradictionDetector {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl RelationalContradictionDetector for NullRelationalContradictionDetector {
    fn detect_contradiction(
        &self,
        _claim_a: &StoredClaim,
        _claim_b: &StoredClaim,
    ) -> Result<ContradictionResult, TruthError> {
        Ok(ContradictionResult::NotComparable {
            reason: "null detector always returns NotComparable".to_string(),
        })
    }

    fn supported_claim_types(&self) -> Vec<String> { vec![] }
    fn detector_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SubjectOfClaimRef;

    fn make_claim(id: &str, subject: &str, body: &[u8]) -> StoredClaim {
        StoredClaim {
            claim_id: id.to_string(),
            subject_of_claim_ref: SubjectOfClaimRef::new(subject),
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
    fn test_negation_direct_contradiction() {
        let detector = NegationContradictionDetector::new("nd-1");
        let a = make_claim("c1", "server-1", b"The server is running and operational");
        let b = make_claim("c2", "server-1", b"The server is not running and operational");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(result.is_contradiction());
    }

    #[test]
    fn test_negation_no_contradiction_different_subjects() {
        let detector = NegationContradictionDetector::new("nd-1");
        let a = make_claim("c1", "server-1", b"The server is running");
        let b = make_claim("c2", "server-2", b"The server is not running");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(matches!(result, ContradictionResult::NotComparable { .. }));
    }

    #[test]
    fn test_negation_no_contradiction_agreement() {
        let detector = NegationContradictionDetector::new("nd-1");
        let a = make_claim("c1", "s", b"The service is healthy");
        let b = make_claim("c2", "s", b"The service is healthy and responsive");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(!result.is_contradiction());
    }

    #[test]
    fn test_temporal_direct_contradiction() {
        let detector = TemporalContradictionDetector::new("td-1");
        let a = make_claim("c1", "event-1", b"{\"timestamp\": 1000, \"ordering\": \"before\"}");
        let b = make_claim("c2", "event-1", b"{\"timestamp\": 500, \"ordering\": \"after\"}");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(result.is_direct());
    }

    #[test]
    fn test_temporal_likely_contradiction_large_diff() {
        let detector = TemporalContradictionDetector::new("td-1");
        let a = make_claim("c1", "event-1", b"{\"timestamp\": 1000}");
        let b = make_claim("c2", "event-1", b"{\"timestamp\": 200000}");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(result.is_contradiction());
    }

    #[test]
    fn test_temporal_not_comparable_plain_text() {
        let detector = TemporalContradictionDetector::new("td-1");
        let a = make_claim("c1", "s", b"some text");
        let b = make_claim("c2", "s", b"other text");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(matches!(result, ContradictionResult::NotComparable { .. }));
    }

    #[test]
    fn test_value_contradiction_beyond_tolerance() {
        let detector = ValueContradictionDetector::new("vd-1", 0.10);
        let a = make_claim("c1", "metric", b"{\"value\": 100.0}");
        let b = make_claim("c2", "metric", b"{\"value\": 200.0}");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(result.is_direct());
    }

    #[test]
    fn test_value_no_contradiction_within_tolerance() {
        let detector = ValueContradictionDetector::new("vd-1", 0.10);
        let a = make_claim("c1", "metric", b"{\"value\": 100.0}");
        let b = make_claim("c2", "metric", b"{\"value\": 105.0}");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(!result.is_contradiction());
    }

    #[test]
    fn test_null_detector_always_not_comparable() {
        let detector = NullRelationalContradictionDetector::new("null-1");
        let a = make_claim("c1", "s", b"a");
        let b = make_claim("c2", "s", b"b");
        let result = detector.detect_contradiction(&a, &b).unwrap();
        assert!(matches!(result, ContradictionResult::NotComparable { .. }));
        assert!(!detector.is_active());
    }

    #[test]
    fn test_contradiction_result_display() {
        assert_eq!(ContradictionResult::NoContradiction.to_string(), "NoContradiction");
        assert!(ContradictionResult::DirectContradiction { explanation: "x".into() }.to_string().contains("x"));
        assert!(ContradictionResult::LikelyContradiction { explanation: "y".into(), similarity_score: "0.5".into() }.to_string().contains("y"));
        assert!(ContradictionResult::NotComparable { reason: "z".into() }.to_string().contains("z"));
    }

    #[test]
    fn test_detector_metadata() {
        let d = NegationContradictionDetector::new("nd-1");
        assert_eq!(d.detector_id(), "nd-1");
        assert!(d.is_active());
        assert!(!d.supported_claim_types().is_empty());
    }
}
