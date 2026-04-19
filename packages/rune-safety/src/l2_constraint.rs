// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Safety constraint verification.
//
// Structured verification of safety constraints with evidence,
// formal checking, and priority-based reporting.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── L2ConstraintType ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum L2ConstraintType {
    Invariant { condition: String },
    PreCondition { condition: String },
    PostCondition { condition: String },
    ResourceBound { resource: String, max_value: f64 },
    TemporalBound { max_duration_ms: i64 },
}

impl fmt::Display for L2ConstraintType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Invariant { .. } => "Invariant",
            Self::PreCondition { .. } => "PreCondition",
            Self::PostCondition { .. } => "PostCondition",
            Self::ResourceBound { .. } => "ResourceBound",
            Self::TemporalBound { .. } => "TemporalBound",
        };
        f.write_str(s)
    }
}

// ── L2ConstraintPriority ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2ConstraintPriority {
    Safety,
    Security,
    Performance,
    Quality,
}

impl fmt::Display for L2ConstraintPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Safety => "Safety",
            Self::Security => "Security",
            Self::Performance => "Performance",
            Self::Quality => "Quality",
        };
        f.write_str(s)
    }
}

// ── L2SafetyConstraint ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2SafetyConstraint {
    pub id: String,
    pub name: String,
    pub description: String,
    pub constraint_type: L2ConstraintType,
    pub priority: L2ConstraintPriority,
    pub verified: bool,
    pub last_verified_at: Option<i64>,
    pub evidence: Vec<String>,
}

impl L2SafetyConstraint {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        constraint_type: L2ConstraintType,
        priority: L2ConstraintPriority,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            constraint_type,
            priority,
            verified: false,
            last_verified_at: None,
            evidence: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }
}

// ── L2ConstraintVerification ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2ConstraintVerification {
    pub constraint_id: String,
    pub verified: bool,
    pub detail: String,
    pub verified_at: i64,
}

// ── L2ConstraintVerificationReport ────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2ConstraintVerificationReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub verifications: Vec<L2ConstraintVerification>,
    pub overall_safe: bool,
}

// ── L2ConstraintVerifier ──────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2ConstraintVerifier {
    constraints: Vec<L2SafetyConstraint>,
}

impl L2ConstraintVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_constraint(&mut self, constraint: L2SafetyConstraint) {
        self.constraints.push(constraint);
    }

    pub fn verify_invariant(
        &self,
        constraint_id: &str,
        condition_met: bool,
        now: i64,
    ) -> L2ConstraintVerification {
        let detail = if condition_met {
            "Invariant condition satisfied".to_string()
        } else {
            "Invariant condition violated".to_string()
        };
        L2ConstraintVerification {
            constraint_id: constraint_id.to_string(),
            verified: condition_met,
            detail,
            verified_at: now,
        }
    }

    pub fn verify_resource_bound(
        &self,
        constraint_id: &str,
        current_value: f64,
        now: i64,
    ) -> L2ConstraintVerification {
        let constraint = self.constraints.iter().find(|c| c.id == constraint_id);
        let (verified, detail) = if let Some(c) = constraint {
            if let L2ConstraintType::ResourceBound { max_value, resource } = &c.constraint_type {
                if current_value <= *max_value {
                    (true, format!("{resource} within bound: {current_value} <= {max_value}"))
                } else {
                    (false, format!("{resource} exceeds bound: {current_value} > {max_value}"))
                }
            } else {
                (false, "Not a ResourceBound constraint".to_string())
            }
        } else {
            (false, format!("Constraint {constraint_id} not found"))
        };

        L2ConstraintVerification {
            constraint_id: constraint_id.to_string(),
            verified,
            detail,
            verified_at: now,
        }
    }

    pub fn verify_temporal_bound(
        &self,
        constraint_id: &str,
        elapsed_ms: i64,
        now: i64,
    ) -> L2ConstraintVerification {
        let constraint = self.constraints.iter().find(|c| c.id == constraint_id);
        let (verified, detail) = if let Some(c) = constraint {
            if let L2ConstraintType::TemporalBound { max_duration_ms } = &c.constraint_type {
                if elapsed_ms <= *max_duration_ms {
                    (true, format!("Within time bound: {elapsed_ms}ms <= {max_duration_ms}ms"))
                } else {
                    (false, format!("Exceeded time bound: {elapsed_ms}ms > {max_duration_ms}ms"))
                }
            } else {
                (false, "Not a TemporalBound constraint".to_string())
            }
        } else {
            (false, format!("Constraint {constraint_id} not found"))
        };

        L2ConstraintVerification {
            constraint_id: constraint_id.to_string(),
            verified,
            detail,
            verified_at: now,
        }
    }

    pub fn verify_all(
        &self,
        conditions: &HashMap<String, bool>,
        now: i64,
    ) -> L2ConstraintVerificationReport {
        let mut verifications = Vec::new();

        for c in &self.constraints {
            let verified = conditions.get(&c.id).copied().unwrap_or(false);
            let detail = if verified {
                format!("Constraint {} passed", c.name)
            } else {
                format!("Constraint {} failed", c.name)
            };
            verifications.push(L2ConstraintVerification {
                constraint_id: c.id.clone(),
                verified,
                detail,
                verified_at: now,
            });
        }

        let total = verifications.len();
        let passed = verifications.iter().filter(|v| v.verified).count();
        let failed = total - passed;

        // overall_safe is true only if ALL Safety-priority constraints pass
        let overall_safe = self
            .constraints
            .iter()
            .filter(|c| c.priority == L2ConstraintPriority::Safety)
            .all(|c| conditions.get(&c.id).copied().unwrap_or(false));

        L2ConstraintVerificationReport {
            total,
            passed,
            failed,
            verifications,
            overall_safe,
        }
    }

    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_invariant_passes_when_true() {
        let verifier = L2ConstraintVerifier::new();
        let result = verifier.verify_invariant("inv-1", true, 1000);
        assert!(result.verified);
    }

    #[test]
    fn test_verify_invariant_fails_when_false() {
        let verifier = L2ConstraintVerifier::new();
        let result = verifier.verify_invariant("inv-1", false, 1000);
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_resource_bound_passes_under_limit() {
        let mut verifier = L2ConstraintVerifier::new();
        verifier.add_constraint(L2SafetyConstraint::new(
            "rb-1", "Memory limit",
            L2ConstraintType::ResourceBound { resource: "memory_mb".into(), max_value: 1024.0 },
            L2ConstraintPriority::Safety,
        ));
        let result = verifier.verify_resource_bound("rb-1", 512.0, 1000);
        assert!(result.verified);
    }

    #[test]
    fn test_verify_resource_bound_fails_over_limit() {
        let mut verifier = L2ConstraintVerifier::new();
        verifier.add_constraint(L2SafetyConstraint::new(
            "rb-1", "Memory limit",
            L2ConstraintType::ResourceBound { resource: "memory_mb".into(), max_value: 1024.0 },
            L2ConstraintPriority::Safety,
        ));
        let result = verifier.verify_resource_bound("rb-1", 2048.0, 1000);
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_temporal_bound_passes_within_time() {
        let mut verifier = L2ConstraintVerifier::new();
        verifier.add_constraint(L2SafetyConstraint::new(
            "tb-1", "Response time",
            L2ConstraintType::TemporalBound { max_duration_ms: 1000 },
            L2ConstraintPriority::Performance,
        ));
        let result = verifier.verify_temporal_bound("tb-1", 500, 1000);
        assert!(result.verified);
    }

    #[test]
    fn test_verify_all_reports_overall_safe_correctly() {
        let mut verifier = L2ConstraintVerifier::new();
        verifier.add_constraint(L2SafetyConstraint::new(
            "s-1", "Safety constraint",
            L2ConstraintType::Invariant { condition: "safe".into() },
            L2ConstraintPriority::Safety,
        ));
        verifier.add_constraint(L2SafetyConstraint::new(
            "q-1", "Quality constraint",
            L2ConstraintType::Invariant { condition: "quality".into() },
            L2ConstraintPriority::Quality,
        ));

        // Safety passes, quality fails → overall_safe = true
        let mut conditions = HashMap::new();
        conditions.insert("s-1".to_string(), true);
        conditions.insert("q-1".to_string(), false);
        let report = verifier.verify_all(&conditions, 1000);
        assert!(report.overall_safe);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);

        // Safety fails → overall_safe = false
        conditions.insert("s-1".to_string(), false);
        let report = verifier.verify_all(&conditions, 1000);
        assert!(!report.overall_safe);
    }

    #[test]
    fn test_verification_report_counts() {
        let mut verifier = L2ConstraintVerifier::new();
        verifier.add_constraint(L2SafetyConstraint::new(
            "c-1", "A", L2ConstraintType::Invariant { condition: "a".into() },
            L2ConstraintPriority::Safety,
        ));
        verifier.add_constraint(L2SafetyConstraint::new(
            "c-2", "B", L2ConstraintType::Invariant { condition: "b".into() },
            L2ConstraintPriority::Security,
        ));
        verifier.add_constraint(L2SafetyConstraint::new(
            "c-3", "C", L2ConstraintType::Invariant { condition: "c".into() },
            L2ConstraintPriority::Quality,
        ));
        let mut conditions = HashMap::new();
        conditions.insert("c-1".to_string(), true);
        conditions.insert("c-2".to_string(), true);
        conditions.insert("c-3".to_string(), false);
        let report = verifier.verify_all(&conditions, 1000);
        assert_eq!(report.total, 3);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 1);
    }
}
