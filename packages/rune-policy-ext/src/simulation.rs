// ═══════════════════════════════════════════════════════════════════════
// Simulation — Simulate policy changes against test cases to predict
// impact before deployment.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::composition::evaluate_rule_expression;
use crate::policy::*;

// ── SimulationRisk ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimulationRisk {
    Safe,
    Moderate,
    High,
}

impl fmt::Display for SimulationRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Safe => "Safe",
            Self::Moderate => "Moderate",
            Self::High => "High",
        };
        f.write_str(s)
    }
}

// ── SimulationTestCase ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimulationTestCase {
    pub id: String,
    pub description: String,
    pub context: HashMap<String, String>,
    pub expected_action: Option<PolicyAction>,
}

// ── SimulationResult ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub test_case_id: String,
    pub current_action: Option<PolicyAction>,
    pub proposed_action: Option<PolicyAction>,
    pub changed: bool,
    pub change_description: String,
}

// ── SimulationImpact ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimulationImpact {
    pub total_test_cases: usize,
    pub unchanged: usize,
    pub changed: usize,
    pub change_rate: f64,
    pub newly_denied: usize,
    pub newly_permitted: usize,
    pub severity_changes: Vec<String>,
    pub summary: String,
    pub risk_assessment: SimulationRisk,
}

// ── SimulationRun ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimulationRun {
    pub id: String,
    pub description: String,
    pub current_policy: ManagedPolicyId,
    pub proposed_policy: ManagedPolicy,
    pub test_cases: Vec<SimulationTestCase>,
    pub results: Vec<SimulationResult>,
    pub impact: SimulationImpact,
    pub run_at: i64,
}

// ── PolicySimulator ─────────────────────────────────────────────────

pub struct PolicySimulator;

impl PolicySimulator {
    pub fn new() -> Self {
        Self
    }

    pub fn simulate(
        &self,
        current: &ManagedPolicy,
        proposed: &ManagedPolicy,
        test_cases: Vec<SimulationTestCase>,
        now: i64,
    ) -> SimulationRun {
        let mut results = Vec::new();
        let mut newly_denied = 0;
        let mut newly_permitted = 0;
        let mut changed_count = 0;

        for tc in &test_cases {
            let current_action = evaluate_policy(current, &tc.context);
            let proposed_action = evaluate_policy(proposed, &tc.context);

            let changed = current_action != proposed_action;
            if changed {
                changed_count += 1;
                if proposed_action.as_ref() == Some(&PolicyAction::Deny)
                    && current_action.as_ref() != Some(&PolicyAction::Deny)
                {
                    newly_denied += 1;
                }
                if current_action.as_ref() == Some(&PolicyAction::Deny)
                    && proposed_action.as_ref() != Some(&PolicyAction::Deny)
                {
                    newly_permitted += 1;
                }
            }

            let change_description = if changed {
                format!(
                    "{} → {}",
                    current_action
                        .as_ref()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into()),
                    proposed_action
                        .as_ref()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into()),
                )
            } else {
                "unchanged".into()
            };

            results.push(SimulationResult {
                test_case_id: tc.id.clone(),
                current_action,
                proposed_action,
                changed,
                change_description,
            });
        }

        let total = test_cases.len();
        let change_rate = if total > 0 {
            changed_count as f64 / total as f64
        } else {
            0.0
        };

        let risk_assessment = if change_rate > 0.20 || newly_permitted > total / 5 {
            SimulationRisk::High
        } else if change_rate > 0.05 || newly_permitted > 0 {
            SimulationRisk::Moderate
        } else {
            SimulationRisk::Safe
        };

        let summary = format!(
            "{}/{} changed ({:.0}%), {} newly denied, {} newly permitted — {}",
            changed_count,
            total,
            change_rate * 100.0,
            newly_denied,
            newly_permitted,
            risk_assessment,
        );

        let impact = SimulationImpact {
            total_test_cases: total,
            unchanged: total - changed_count,
            changed: changed_count,
            change_rate,
            newly_denied,
            newly_permitted,
            severity_changes: Vec::new(),
            summary: summary.clone(),
            risk_assessment,
        };

        SimulationRun {
            id: format!("sim-{now}"),
            description: format!("Simulation of {} → proposed", current.id),
            current_policy: current.id.clone(),
            proposed_policy: proposed.clone(),
            test_cases,
            results,
            impact,
            run_at: now,
        }
    }

    pub fn generate_test_cases(
        &self,
        policy: &ManagedPolicy,
        count: usize,
    ) -> Vec<SimulationTestCase> {
        let mut fields = Vec::new();
        for rule in &policy.rules {
            collect_expression_fields(&rule.condition, &mut fields);
        }
        fields.sort();
        fields.dedup();

        let mut cases = Vec::new();
        let boundary_values: Vec<(&str, Vec<&str>)> = vec![
            ("severity", vec!["Info", "Low", "Medium", "High", "Critical", "Emergency"]),
            ("classification", vec!["Public", "Internal", "Confidential", "Restricted"]),
            ("env", vec!["dev", "staging", "prod"]),
            ("role", vec!["user", "admin", "service"]),
        ];

        let mut idx = 0;
        'outer: for field in &fields {
            let values = boundary_values
                .iter()
                .find(|(f, _)| *f == field.as_str())
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| vec!["value-a", "value-b"]);

            for val in &values {
                if idx >= count {
                    break 'outer;
                }
                let mut ctx = HashMap::new();
                ctx.insert(field.clone(), val.to_string());
                cases.push(SimulationTestCase {
                    id: format!("tc-{idx}"),
                    description: format!("{field}={val}"),
                    context: ctx,
                    expected_action: None,
                });
                idx += 1;
            }
        }

        cases
    }

    pub fn impact_summary(&self, run: &SimulationRun) -> String {
        run.impact.summary.clone()
    }
}

impl Default for PolicySimulator {
    fn default() -> Self {
        Self::new()
    }
}

fn evaluate_policy(
    policy: &ManagedPolicy,
    context: &HashMap<String, String>,
) -> Option<PolicyAction> {
    let mut best: Option<(u32, &PolicyAction)> = None;
    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }
        if evaluate_rule_expression(&rule.condition, context) {
            match best {
                None => best = Some((rule.priority, &rule.action)),
                Some((prio, _)) if rule.priority > prio => {
                    best = Some((rule.priority, &rule.action));
                }
                _ => {}
            }
        }
    }
    best.map(|(_, a)| a.clone())
}

fn collect_expression_fields(expr: &RuleExpression, fields: &mut Vec<String>) {
    match expr {
        RuleExpression::Equals { field, .. }
        | RuleExpression::NotEquals { field, .. }
        | RuleExpression::Contains { field, .. }
        | RuleExpression::GreaterThan { field, .. }
        | RuleExpression::LessThan { field, .. }
        | RuleExpression::InList { field, .. } => {
            fields.push(field.clone());
        }
        RuleExpression::SeverityAtLeast(_) => fields.push("severity".into()),
        RuleExpression::ClassificationAtLeast(_) => fields.push("classification".into()),
        RuleExpression::And(exprs) | RuleExpression::Or(exprs) => {
            for e in exprs {
                collect_expression_fields(e, fields);
            }
        }
        RuleExpression::Not(e) => collect_expression_fields(e, fields),
        _ => {}
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn current_policy() -> ManagedPolicy {
        ManagedPolicy::new("p1", "Current", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new("r1", "Allow all", RuleExpression::Always, PolicyAction::Allow))
    }

    fn proposed_deny_policy() -> ManagedPolicy {
        ManagedPolicy::new("p1-proposed", "Proposed", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new("r1", "Deny all", RuleExpression::Always, PolicyAction::Deny))
    }

    fn test_cases() -> Vec<SimulationTestCase> {
        vec![
            SimulationTestCase {
                id: "tc-1".into(),
                description: "normal request".into(),
                context: HashMap::new(),
                expected_action: None,
            },
            SimulationTestCase {
                id: "tc-2".into(),
                description: "admin request".into(),
                context: [("role".into(), "admin".into())].into(),
                expected_action: None,
            },
        ]
    }

    #[test]
    fn test_simulate_identical_policies() {
        let sim = PolicySimulator::new();
        let current = current_policy();
        let proposed = current_policy();
        let run = sim.simulate(&current, &proposed, test_cases(), 1000);
        assert_eq!(run.impact.changed, 0);
        assert_eq!(run.impact.change_rate, 0.0);
    }

    #[test]
    fn test_simulate_different_policies() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &proposed_deny_policy(), test_cases(), 1000);
        assert!(run.impact.changed > 0);
    }

    #[test]
    fn test_simulate_newly_denied() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &proposed_deny_policy(), test_cases(), 1000);
        assert!(run.impact.newly_denied > 0);
    }

    #[test]
    fn test_simulate_newly_permitted() {
        let sim = PolicySimulator::new();
        let deny = proposed_deny_policy();
        let allow = current_policy();
        let run = sim.simulate(&deny, &allow, test_cases(), 1000);
        assert!(run.impact.newly_permitted > 0);
    }

    #[test]
    fn test_risk_safe() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &current_policy(), test_cases(), 1000);
        assert_eq!(run.impact.risk_assessment, SimulationRisk::Safe);
    }

    #[test]
    fn test_risk_high() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &proposed_deny_policy(), test_cases(), 1000);
        assert_eq!(run.impact.risk_assessment, SimulationRisk::High);
    }

    #[test]
    fn test_impact_summary() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &proposed_deny_policy(), test_cases(), 1000);
        let summary = sim.impact_summary(&run);
        assert!(summary.contains("changed"));
    }

    #[test]
    fn test_generate_test_cases() {
        let policy = ManagedPolicy::new("p1", "Test", PolicyDomain::AccessControl, "team", 1000)
            .with_rule(PolicyRule::new(
                "r1",
                "Check severity",
                RuleExpression::SeverityAtLeast("High".into()),
                PolicyAction::Deny,
            ));
        let sim = PolicySimulator::new();
        let cases = sim.generate_test_cases(&policy, 10);
        assert!(!cases.is_empty());
        assert!(cases.iter().any(|tc| tc.context.contains_key("severity")));
    }

    #[test]
    fn test_result_changed_flag() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &proposed_deny_policy(), test_cases(), 1000);
        assert!(run.results.iter().all(|r| r.changed));
    }

    #[test]
    fn test_empty_test_cases() {
        let sim = PolicySimulator::new();
        let run = sim.simulate(&current_policy(), &proposed_deny_policy(), Vec::new(), 1000);
        assert_eq!(run.impact.total_test_cases, 0);
        assert_eq!(run.impact.change_rate, 0.0);
    }
}
