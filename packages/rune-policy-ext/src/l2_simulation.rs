// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Policy simulation and impact analysis.
//
// Dry-run simulation against test cases, projected impact computation,
// and simulation result storage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::l2_conflict::{PolicyEffect, PolicyRecord};

// ── SimulationTestCase ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2SimulationTestCase {
    pub id: String,
    pub description: String,
    pub input: HashMap<String, String>,
    pub expected_outcome: PolicyEffect,
}

// ── SimulationResult ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2SimulationResult {
    pub test_case_id: String,
    pub actual_outcome: PolicyEffect,
    pub matches_expected: bool,
    pub evaluation_time_us: i64,
    pub factors: Vec<String>,
}

// ── PolicySimulation ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2PolicySimulation {
    pub simulation_id: String,
    pub policy_id: String,
    pub test_cases: Vec<L2SimulationTestCase>,
    pub results: Vec<L2SimulationResult>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
}

/// Evaluates a policy against a test case by simple resource/condition matching.
fn evaluate_policy_against_case(
    policy: &PolicyRecord,
    test_case: &L2SimulationTestCase,
) -> PolicyEffect {
    // Check if any of the policy's conditions match the test case input
    let matches = if policy.conditions.is_empty() {
        true // no conditions = matches everything
    } else {
        policy.conditions.iter().any(|cond| {
            // condition format: "key=value"
            if let Some((key, value)) = cond.split_once('=') {
                test_case.input.get(key).map_or(false, |v| v == value)
            } else {
                test_case.input.contains_key(cond)
            }
        })
    };

    if matches {
        policy.effect.clone()
    } else {
        // Default: if conditions don't match, the opposite effect
        match &policy.effect {
            PolicyEffect::Permit => PolicyEffect::Deny,
            PolicyEffect::Deny => PolicyEffect::Permit,
        }
    }
}

pub fn run_simulation(
    policy: &PolicyRecord,
    test_cases: &[L2SimulationTestCase],
) -> L2PolicySimulation {
    let simulation_id = format!("sim-{}", policy.id);
    let started_at = 0i64;

    let results: Vec<L2SimulationResult> = test_cases
        .iter()
        .map(|tc| {
            let actual_outcome = evaluate_policy_against_case(policy, tc);
            let matches_expected = actual_outcome == tc.expected_outcome;
            let mut factors = Vec::new();
            if !policy.conditions.is_empty() {
                factors.push(format!("conditions: {}", policy.conditions.len()));
            }
            factors.push(format!("effect: {}", policy.effect));

            L2SimulationResult {
                test_case_id: tc.id.clone(),
                actual_outcome,
                matches_expected,
                evaluation_time_us: 1, // simulated
                factors,
            }
        })
        .collect();

    L2PolicySimulation {
        simulation_id,
        policy_id: policy.id.clone(),
        test_cases: test_cases.to_vec(),
        results,
        started_at,
        completed_at: Some(started_at + 1),
    }
}

// ── ImpactRisk ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImpactRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ImpactRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── PolicyImpactAnalysis ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyImpactAnalysis {
    pub policy_id: String,
    pub affected_resources: Vec<String>,
    pub affected_subjects: Vec<String>,
    pub current_permits: usize,
    pub current_denies: usize,
    pub projected_permits: usize,
    pub projected_denies: usize,
    pub net_change_permits: i64,
    pub net_change_denies: i64,
    pub risk_assessment: ImpactRisk,
}

pub fn analyze_impact(
    current_policy: Option<&PolicyRecord>,
    new_policy: &PolicyRecord,
    affected_count: usize,
) -> PolicyImpactAnalysis {
    let (current_permits, current_denies) = match current_policy {
        Some(p) => match p.effect {
            PolicyEffect::Permit => (affected_count, 0),
            PolicyEffect::Deny => (0, affected_count),
        },
        None => (0, 0),
    };

    let (projected_permits, projected_denies) = match new_policy.effect {
        PolicyEffect::Permit => (affected_count, 0),
        PolicyEffect::Deny => (0, affected_count),
    };

    let net_change_permits = projected_permits as i64 - current_permits as i64;
    let net_change_denies = projected_denies as i64 - current_denies as i64;

    let risk_assessment = if affected_count >= 1000 {
        ImpactRisk::Critical
    } else if affected_count >= 100 {
        ImpactRisk::High
    } else if affected_count >= 10 {
        ImpactRisk::Medium
    } else {
        ImpactRisk::Low
    };

    PolicyImpactAnalysis {
        policy_id: new_policy.id.clone(),
        affected_resources: new_policy.resources.clone(),
        affected_subjects: Vec::new(),
        current_permits,
        current_denies,
        projected_permits,
        projected_denies,
        net_change_permits,
        net_change_denies,
        risk_assessment,
    }
}

// ── SimulationStore ────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2SimulationStore {
    simulations: HashMap<String, L2PolicySimulation>,
}

impl L2SimulationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&mut self, simulation: L2PolicySimulation) {
        self.simulations
            .insert(simulation.simulation_id.clone(), simulation);
    }

    pub fn get(&self, simulation_id: &str) -> Option<&L2PolicySimulation> {
        self.simulations.get(simulation_id)
    }

    pub fn pass_rate(&self, simulation_id: &str) -> Option<f64> {
        let sim = self.simulations.get(simulation_id)?;
        if sim.results.is_empty() {
            return Some(0.0);
        }
        let passed = sim.results.iter().filter(|r| r.matches_expected).count();
        Some(passed as f64 / sim.results.len() as f64)
    }

    pub fn simulations_for_policy(&self, policy_id: &str) -> Vec<&L2PolicySimulation> {
        self.simulations
            .values()
            .filter(|s| s.policy_id == policy_id)
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> PolicyRecord {
        PolicyRecord {
            id: "p1".into(),
            name: "Test Policy".into(),
            effect: PolicyEffect::Deny,
            resources: vec!["db:users".into()],
            priority: 10,
            conditions: Vec::new(),
            valid_from: None,
            valid_until: None,
        }
    }

    fn test_cases() -> Vec<L2SimulationTestCase> {
        vec![
            L2SimulationTestCase {
                id: "tc1".into(),
                description: "deny case".into(),
                input: HashMap::new(),
                expected_outcome: PolicyEffect::Deny,
            },
            L2SimulationTestCase {
                id: "tc2".into(),
                description: "permit case".into(),
                input: HashMap::new(),
                expected_outcome: PolicyEffect::Permit,
            },
        ]
    }

    #[test]
    fn test_run_simulation_evaluates_all_test_cases() {
        let policy = test_policy();
        let cases = test_cases();
        let sim = run_simulation(&policy, &cases);
        assert_eq!(sim.results.len(), 2);
    }

    #[test]
    fn test_run_simulation_matches_expected_correct_for_matching() {
        let policy = test_policy(); // Deny effect, no conditions
        let cases = vec![L2SimulationTestCase {
            id: "tc1".into(),
            description: "should deny".into(),
            input: HashMap::new(),
            expected_outcome: PolicyEffect::Deny,
        }];
        let sim = run_simulation(&policy, &cases);
        assert!(sim.results[0].matches_expected);
    }

    #[test]
    fn test_run_simulation_matches_expected_false_for_mismatch() {
        let policy = test_policy(); // Deny effect, no conditions
        let cases = vec![L2SimulationTestCase {
            id: "tc1".into(),
            description: "expects permit".into(),
            input: HashMap::new(),
            expected_outcome: PolicyEffect::Permit,
        }];
        let sim = run_simulation(&policy, &cases);
        assert!(!sim.results[0].matches_expected);
    }

    #[test]
    fn test_simulation_store_pass_rate_calculates_correctly() {
        let policy = test_policy();
        let cases = vec![
            L2SimulationTestCase {
                id: "tc1".into(),
                description: "match".into(),
                input: HashMap::new(),
                expected_outcome: PolicyEffect::Deny,
            },
            L2SimulationTestCase {
                id: "tc2".into(),
                description: "mismatch".into(),
                input: HashMap::new(),
                expected_outcome: PolicyEffect::Permit,
            },
        ];
        let sim = run_simulation(&policy, &cases);
        let mut store = L2SimulationStore::new();
        let sim_id = sim.simulation_id.clone();
        store.store(sim);
        let rate = store.pass_rate(&sim_id).unwrap();
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_simulation_store_simulations_for_policy_returns_correct() {
        let policy = test_policy();
        let sim = run_simulation(&policy, &[]);
        let mut store = L2SimulationStore::new();
        store.store(sim);
        let results = store.simulations_for_policy("p1");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_analyze_impact_computes_net_changes() {
        let current = PolicyRecord::new("p1", "Old", PolicyEffect::Permit)
            .with_resource("db:users");
        let new = PolicyRecord::new("p1", "New", PolicyEffect::Deny)
            .with_resource("db:users");
        let impact = analyze_impact(Some(&current), &new, 50);
        assert_eq!(impact.current_permits, 50);
        assert_eq!(impact.current_denies, 0);
        assert_eq!(impact.projected_permits, 0);
        assert_eq!(impact.projected_denies, 50);
        assert_eq!(impact.net_change_permits, -50);
        assert_eq!(impact.net_change_denies, 50);
    }

    #[test]
    fn test_analyze_impact_risk_assessment_based_on_affected_count() {
        let new = PolicyRecord::new("p1", "New", PolicyEffect::Deny);
        let low = analyze_impact(None, &new, 5);
        assert_eq!(low.risk_assessment, ImpactRisk::Low);
        let medium = analyze_impact(None, &new, 50);
        assert_eq!(medium.risk_assessment, ImpactRisk::Medium);
        let high = analyze_impact(None, &new, 500);
        assert_eq!(high.risk_assessment, ImpactRisk::High);
        let critical = analyze_impact(None, &new, 1000);
        assert_eq!(critical.risk_assessment, ImpactRisk::Critical);
    }
}
