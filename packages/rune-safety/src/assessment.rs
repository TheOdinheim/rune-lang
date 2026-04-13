// ═══════════════════════════════════════════════════════════════════════
// Assessment — Overall safety assessment combining all signals:
// constraints, safety cases, hazards, monitors, and boundaries.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::boundary::{BoundaryCheckResult, BoundaryStatus, SafetyBoundarySet};
use crate::constraint::{ConstraintEvaluation, ConstraintSeverity, ConstraintStore};
use crate::hazard::{HazardRegistry, HazardStatus, RiskLevel};
use crate::integrity::SafetyClassification;
use crate::monitor::SafetyMonitorEngine;
use crate::safety_case::{SafetyCaseId, SafetyCaseStore};

// ── SafetyLevel ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyLevel {
    Safe,
    ConditionalSafe { conditions: Vec<String> },
    Degraded { reason: String },
    Unsafe { reason: String },
    Unknown,
}

impl fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safe => write!(f, "Safe"),
            Self::ConditionalSafe { conditions } => {
                write!(f, "ConditionalSafe({})", conditions.join(", "))
            }
            Self::Degraded { reason } => write!(f, "Degraded: {reason}"),
            Self::Unsafe { reason } => write!(f, "Unsafe: {reason}"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── HazardSummary ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HazardSummary {
    pub total: usize,
    pub intolerable: usize,
    pub undesirable: usize,
    pub tolerable: usize,
    pub negligible: usize,
    pub unmitigated: usize,
}

// ── MonitorSummary ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSummary {
    pub total: usize,
    pub active: usize,
    pub triggered: usize,
    pub disabled: usize,
    pub total_violations: u64,
}

// ── SafetyAssessment ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafetyAssessment {
    pub system_name: String,
    pub classification: SafetyClassification,
    pub constraint_results: Vec<ConstraintEvaluation>,
    pub safety_case_completeness: Option<f64>,
    pub hazard_summary: HazardSummary,
    pub monitor_summary: MonitorSummary,
    pub boundary_status: Vec<BoundaryCheckResult>,
    pub overall_safety: SafetyLevel,
    pub assessed_at: i64,
    pub assessed_by: String,
    pub recommendations: Vec<String>,
}

// ── SafetyAssessor ────────────────────────────────────────────────────

pub struct SafetyAssessor;

impl SafetyAssessor {
    pub fn new() -> Self {
        Self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assess(
        &self,
        system_name: &str,
        classification: &SafetyClassification,
        constraint_store: &ConstraintStore,
        safety_case_store: &SafetyCaseStore,
        safety_case_id: Option<&SafetyCaseId>,
        hazard_registry: &HazardRegistry,
        monitor_engine: &SafetyMonitorEngine,
        boundary_set: &SafetyBoundarySet,
        context: &HashMap<String, String>,
        now: i64,
    ) -> SafetyAssessment {
        // a. Evaluate all constraints
        let constraint_results = constraint_store.evaluate_all(context, now);

        // b. Check safety case completeness (None means no case specified = skip check)
        let safety_case_completeness = safety_case_id
            .and_then(|id| safety_case_store.completeness(id));

        // c. Summarize hazards
        let hazard_summary = {
            let matrix = hazard_registry.risk_matrix();
            let total = matrix.len();
            let intolerable = matrix.iter().filter(|e| e.3 == RiskLevel::Intolerable).count();
            let undesirable = matrix.iter().filter(|e| e.3 == RiskLevel::Undesirable).count();
            let tolerable = matrix.iter().filter(|e| e.3 == RiskLevel::Tolerable).count();
            let negligible = matrix.iter().filter(|e| e.3 == RiskLevel::Negligible).count();
            let unmitigated = hazard_registry.unmitigated_hazards().len();
            HazardSummary {
                total,
                intolerable,
                undesirable,
                tolerable,
                negligible,
                unmitigated,
            }
        };

        // d. Summarize monitor status
        let monitor_summary = {
            let triggered = monitor_engine.triggered_monitors();
            let active = monitor_engine.active_monitors();
            let total = monitor_engine.count();
            let total_violations: u64 = triggered
                .iter()
                .map(|m| m.violation_count)
                .sum();
            let disabled = total - triggered.len() - active.len();
            MonitorSummary {
                total,
                active: active.len(),
                triggered: triggered.len(),
                disabled,
                total_violations,
            }
        };

        // e. Check boundaries
        let values: HashMap<String, f64> = context
            .iter()
            .filter_map(|(k, v)| v.parse::<f64>().ok().map(|f| (k.clone(), f)))
            .collect();
        let boundary_status = boundary_set.check_all(&values);

        // f. Determine overall safety level
        let mut recommendations = Vec::new();
        let overall_safety;

        // Check for Critical+ constraint violations
        let critical_violations: Vec<&ConstraintEvaluation> = constraint_results
            .iter()
            .filter(|r| !r.satisfied)
            .collect();

        let has_critical_violation = critical_violations.iter().any(|r| {
            constraint_store
                .get(&r.constraint_id)
                .map(|c| c.severity >= ConstraintSeverity::Critical)
                .unwrap_or(false)
        });

        let any_boundary_breached = boundary_status
            .iter()
            .any(|b| matches!(b.status, BoundaryStatus::Breached { .. }));

        let any_monitor_triggered = monitor_summary.triggered > 0;

        let intolerable_unmitigated = hazard_registry
            .intolerable_hazards()
            .iter()
            .any(|h| matches!(h.status, HazardStatus::Identified | HazardStatus::Analyzed));

        if has_critical_violation {
            overall_safety = SafetyLevel::Unsafe {
                reason: "Critical safety constraint violated".into(),
            };
            recommendations.push("Investigate and resolve critical constraint violations immediately".into());
        } else if any_boundary_breached {
            overall_safety = SafetyLevel::Unsafe {
                reason: "Safety boundary breached".into(),
            };
            recommendations.push("Return to safe operating envelope immediately".into());
        } else if intolerable_unmitigated {
            overall_safety = SafetyLevel::Unsafe {
                reason: "Intolerable hazard without mitigation".into(),
            };
            recommendations.push("Implement mitigations for intolerable hazards before operation".into());
        } else if any_monitor_triggered {
            overall_safety = SafetyLevel::Degraded {
                reason: format!("{} safety monitor(s) triggered", monitor_summary.triggered),
            };
            recommendations.push("Investigate triggered safety monitors".into());
        } else if safety_case_completeness.is_some_and(|c| c < 0.5) {
            let pct = safety_case_completeness.unwrap();
            overall_safety = SafetyLevel::ConditionalSafe {
                conditions: vec![format!(
                    "Safety case only {:.0}% complete — complete safety argumentation before full deployment",
                    pct * 100.0
                )],
            };
            recommendations.push("Complete safety case documentation".into());
        } else if !critical_violations.is_empty() {
            overall_safety = SafetyLevel::ConditionalSafe {
                conditions: vec!["Non-critical constraint violations present".into()],
            };
            recommendations.push("Resolve remaining constraint violations".into());
        } else {
            overall_safety = SafetyLevel::Safe;
        }

        if hazard_summary.unmitigated > 0 && !intolerable_unmitigated {
            recommendations.push(format!(
                "{} hazards remain unmitigated",
                hazard_summary.unmitigated
            ));
        }

        SafetyAssessment {
            system_name: system_name.into(),
            classification: classification.clone(),
            constraint_results,
            safety_case_completeness,
            hazard_summary,
            monitor_summary,
            boundary_status,
            overall_safety,
            assessed_at: now,
            assessed_by: "SafetyAssessor".into(),
            recommendations,
        }
    }
}

impl Default for SafetyAssessor {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::*;
    use crate::constraint::*;
    use crate::hazard::*;
    use crate::integrity::*;
    use crate::monitor::*;
    use crate::safety_case::*;

    fn empty_assessment_inputs() -> (
        SafetyClassification,
        ConstraintStore,
        SafetyCaseStore,
        HazardRegistry,
        SafetyMonitorEngine,
        SafetyBoundarySet,
    ) {
        (
            SafetyClassification::new().with_sil(SafetyIntegrityLevel::Sil2),
            ConstraintStore::new(),
            SafetyCaseStore::new(),
            HazardRegistry::new(),
            SafetyMonitorEngine::new(),
            SafetyBoundarySet::new(),
        )
    }

    #[test]
    fn test_assess_all_safe() {
        let (classification, mut cs, scs, hr, me, bs) = empty_assessment_inputs();
        cs.add(SafetyConstraint::new(
            "c1",
            "ok",
            ConstraintType::Invariant,
            SafetyCondition::FieldPresent { field: "status".into() },
            ConstraintSeverity::Critical,
        ))
        .unwrap();

        let ctx = HashMap::from([("status".into(), "ok".into())]);
        let assessor = SafetyAssessor::new();
        let result = assessor.assess("sys", &classification, &cs, &scs, None, &hr, &me, &bs, &ctx, 1000);
        assert_eq!(result.overall_safety, SafetyLevel::Safe);
    }

    #[test]
    fn test_assess_critical_violation_unsafe() {
        let (classification, mut cs, scs, hr, me, bs) = empty_assessment_inputs();
        cs.add(SafetyConstraint::new(
            "c1",
            "must have status",
            ConstraintType::Invariant,
            SafetyCondition::FieldPresent { field: "status".into() },
            ConstraintSeverity::Critical,
        ))
        .unwrap();

        let ctx: HashMap<String, String> = HashMap::new(); // missing "status"
        let assessor = SafetyAssessor::new();
        let result = assessor.assess("sys", &classification, &cs, &scs, None, &hr, &me, &bs, &ctx, 1000);
        assert!(matches!(result.overall_safety, SafetyLevel::Unsafe { .. }));
    }

    #[test]
    fn test_assess_triggered_monitor_degraded() {
        let (classification, mut cs, scs, hr, mut me, bs) = empty_assessment_inputs();
        cs.add(SafetyConstraint::new(
            "c1",
            "confidence",
            ConstraintType::Invariant,
            SafetyCondition::ValueAbove { field: "confidence".into(), threshold: 0.5 },
            ConstraintSeverity::Warning,
        ))
        .unwrap();

        let monitor = SafetyMonitor::new("m1", "conf monitor", MonitorResponse::LogOnly)
            .with_constraint(ConstraintId::new("c1"));
        me.register(monitor).unwrap();

        // Trigger the monitor
        let bad_ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        me.check(&SafetyMonitorId::new("m1"), &cs, &bad_ctx, 999).unwrap();

        let assessor = SafetyAssessor::new();
        let result = assessor.assess("sys", &classification, &cs, &scs, None, &hr, &me, &bs, &bad_ctx, 1000);
        assert!(matches!(result.overall_safety, SafetyLevel::Degraded { .. }));
    }

    #[test]
    fn test_assess_breached_boundary_unsafe() {
        let (classification, cs, scs, hr, me, mut bs) = empty_assessment_inputs();
        bs.add(
            SafetyBoundary::new("b1", "temp", BoundaryType::OperatingEnvelope)
                .with_limit(OperatingLimit::new("temperature", "°C").with_range(0.0, 100.0)),
        );

        let ctx = HashMap::from([("temperature".into(), "150".into())]);
        let assessor = SafetyAssessor::new();
        let result = assessor.assess("sys", &classification, &cs, &scs, None, &hr, &me, &bs, &ctx, 1000);
        assert!(matches!(result.overall_safety, SafetyLevel::Unsafe { .. }));
    }

    #[test]
    fn test_assess_intolerable_unmitigated_unsafe() {
        let (classification, cs, scs, mut hr, me, bs) = empty_assessment_inputs();
        hr.register(Hazard::new(
            "h1",
            "Critical AI failure",
            HazardType::AiSpecific,
            ConstraintSeverity::Critical,
            HazardLikelihood::Probable,
        ))
        .unwrap();

        let ctx = HashMap::new();
        let assessor = SafetyAssessor::new();
        let result = assessor.assess("sys", &classification, &cs, &scs, None, &hr, &me, &bs, &ctx, 1000);
        assert!(matches!(result.overall_safety, SafetyLevel::Unsafe { .. }));
    }

    #[test]
    fn test_assess_low_completeness_conditional() {
        let (classification, cs, mut scs, hr, me, bs) = empty_assessment_inputs();
        let top = SafetyGoal::new("g1", "Safe").with_status(GoalStatus::Undeveloped);
        scs.add(SafetyCase::new("sc1", "Case", "sys", top)).unwrap();

        let ctx = HashMap::new();
        let assessor = SafetyAssessor::new();
        let result = assessor.assess(
            "sys",
            &classification,
            &cs,
            &scs,
            Some(&SafetyCaseId::new("sc1")),
            &hr,
            &me,
            &bs,
            &ctx,
            1000,
        );
        assert!(matches!(result.overall_safety, SafetyLevel::ConditionalSafe { .. }));
    }

    #[test]
    fn test_assess_generates_recommendations() {
        let (classification, cs, scs, mut hr, me, bs) = empty_assessment_inputs();
        hr.register(Hazard::new(
            "h1",
            "Minor issue",
            HazardType::DesignFlaw,
            ConstraintSeverity::Warning,
            HazardLikelihood::Remote,
        ))
        .unwrap();

        let ctx = HashMap::new();
        let assessor = SafetyAssessor::new();
        let result = assessor.assess("sys", &classification, &cs, &scs, None, &hr, &me, &bs, &ctx, 1000);
        assert!(!result.recommendations.is_empty());
    }

    #[test]
    fn test_safety_level_display() {
        let levels = vec![
            SafetyLevel::Safe,
            SafetyLevel::ConditionalSafe { conditions: vec!["c".into()] },
            SafetyLevel::Degraded { reason: "r".into() },
            SafetyLevel::Unsafe { reason: "r".into() },
            SafetyLevel::Unknown,
        ];
        for l in &levels {
            assert!(!l.to_string().is_empty());
        }
        assert_eq!(levels.len(), 5);
    }

    #[test]
    fn test_hazard_summary_construction() {
        let hs = HazardSummary {
            total: 10,
            intolerable: 1,
            undesirable: 2,
            tolerable: 3,
            negligible: 4,
            unmitigated: 2,
        };
        assert_eq!(hs.total, 10);
        assert_eq!(hs.unmitigated, 2);
    }

    #[test]
    fn test_monitor_summary_construction() {
        let ms = MonitorSummary {
            total: 5,
            active: 3,
            triggered: 1,
            disabled: 1,
            total_violations: 7,
        };
        assert_eq!(ms.total, 5);
        assert_eq!(ms.total_violations, 7);
    }
}
