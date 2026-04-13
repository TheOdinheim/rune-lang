// ═══════════════════════════════════════════════════════════════════════
// Counterfactual — "what would need to change" analysis.
//
// CounterfactualGenerator examines a decision's factors and generates
// counterfactuals: hypothetical changes that would flip the outcome.
// Each counterfactual has a difficulty rating and feasibility assessment.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::decision::{Decision, DecisionOutcome, FactorDirection};

// ── ChangeDifficulty ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChangeDifficulty {
    Easy = 0,
    Moderate = 1,
    Hard = 2,
    Impossible = 3,
}

impl fmt::Display for ChangeDifficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Easy => f.write_str("easy"),
            Self::Moderate => f.write_str("moderate"),
            Self::Hard => f.write_str("hard"),
            Self::Impossible => f.write_str("impossible"),
        }
    }
}

// ── RequiredChange ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequiredChange {
    pub factor_name: String,
    pub current_value: String,
    pub required_value: String,
    pub difficulty: ChangeDifficulty,
    pub explanation: String,
}

impl RequiredChange {
    pub fn new(
        factor_name: impl Into<String>,
        current_value: impl Into<String>,
        required_value: impl Into<String>,
        difficulty: ChangeDifficulty,
    ) -> Self {
        Self {
            factor_name: factor_name.into(),
            current_value: current_value.into(),
            required_value: required_value.into(),
            difficulty,
            explanation: String::new(),
        }
    }

    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = explanation.into();
        self
    }
}

// ── CounterfactualFeasibility ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterfactualFeasibility {
    Feasible,
    DifficultButPossible,
    Infeasible,
}

impl fmt::Display for CounterfactualFeasibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Feasible => f.write_str("feasible"),
            Self::DifficultButPossible => f.write_str("difficult-but-possible"),
            Self::Infeasible => f.write_str("infeasible"),
        }
    }
}

// ── Counterfactual ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Counterfactual {
    pub decision_id: String,
    pub original_outcome: String,
    pub target_outcome: String,
    pub required_changes: Vec<RequiredChange>,
    pub feasibility: CounterfactualFeasibility,
    pub overall_difficulty: ChangeDifficulty,
    pub narrative: String,
    pub generated_at: i64,
}

impl Counterfactual {
    pub fn min_changes(&self) -> usize {
        self.required_changes.len()
    }

    pub fn easiest_change(&self) -> Option<&RequiredChange> {
        self.required_changes.iter().min_by_key(|c| c.difficulty.clone())
    }

    pub fn hardest_change(&self) -> Option<&RequiredChange> {
        self.required_changes.iter().max_by_key(|c| c.difficulty.clone())
    }
}

// ── CounterfactualGenerator ─────────────────────────────────────────

pub struct CounterfactualGenerator;

impl CounterfactualGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(
        &self,
        decision: &Decision,
        target_outcome: &str,
        now: i64,
    ) -> Counterfactual {
        let original_outcome = decision.outcome.to_string();
        let is_flip = is_outcome_flip(&decision.outcome, target_outcome);

        let mut required_changes: Vec<RequiredChange> = if is_flip {
            // For a flip (e.g., denied → approved), opposing factors need to change
            decision
                .factors
                .iter()
                .filter(|f| f.direction == FactorDirection::Opposing)
                .map(|f| {
                    let difficulty = difficulty_from_weight(f.weight);
                    RequiredChange::new(
                        &f.name,
                        &f.value,
                        format!("{} (flipped)", f.value),
                        difficulty,
                    )
                    .with_explanation(format!(
                        "Change {} from {} to supporting",
                        f.name, f.direction
                    ))
                })
                .collect()
        } else {
            // Non-flip: all non-supporting factors need adjustment
            decision
                .factors
                .iter()
                .filter(|f| f.direction != FactorDirection::Supporting)
                .map(|f| {
                    let difficulty = difficulty_from_weight(f.weight);
                    RequiredChange::new(
                        &f.name,
                        &f.value,
                        format!("{} (adjusted)", f.value),
                        difficulty,
                    )
                    .with_explanation(format!("Adjust {} to support {}", f.name, target_outcome))
                })
                .collect()
        };

        // If no changes needed (all factors already support), produce a single
        // "no change required" entry
        if required_changes.is_empty() && !decision.factors.is_empty() {
            required_changes.push(
                RequiredChange::new(
                    "outcome-override",
                    &original_outcome,
                    target_outcome,
                    ChangeDifficulty::Easy,
                )
                .with_explanation("All factors already support this outcome"),
            );
        }

        let overall_difficulty = required_changes
            .iter()
            .map(|c| c.difficulty.clone())
            .max()
            .unwrap_or(ChangeDifficulty::Easy);

        let feasibility = match &overall_difficulty {
            ChangeDifficulty::Easy | ChangeDifficulty::Moderate => {
                CounterfactualFeasibility::Feasible
            }
            ChangeDifficulty::Hard => CounterfactualFeasibility::DifficultButPossible,
            ChangeDifficulty::Impossible => CounterfactualFeasibility::Infeasible,
        };

        let narrative = format!(
            "To change outcome from {} to {}, {} change(s) required ({})",
            original_outcome,
            target_outcome,
            required_changes.len(),
            feasibility
        );

        Counterfactual {
            decision_id: decision.id.0.clone(),
            original_outcome,
            target_outcome: target_outcome.into(),
            required_changes,
            feasibility,
            overall_difficulty,
            narrative,
            generated_at: now,
        }
    }
}

impl Default for CounterfactualGenerator {
    fn default() -> Self {
        Self::new()
    }
}

fn is_outcome_flip(current: &DecisionOutcome, target: &str) -> bool {
    matches!(
        (current, target),
        (DecisionOutcome::Denied, "approved")
            | (DecisionOutcome::Approved, "denied")
            | (DecisionOutcome::Escalated, "approved")
            | (DecisionOutcome::Deferred, "approved")
    )
}

fn difficulty_from_weight(weight: f64) -> ChangeDifficulty {
    match weight {
        w if w < 0.3 => ChangeDifficulty::Easy,
        w if w < 0.6 => ChangeDifficulty::Moderate,
        w if w < 0.9 => ChangeDifficulty::Hard,
        _ => ChangeDifficulty::Impossible,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::*;

    fn ctx() -> DecisionContext {
        DecisionContext::new("alice", "db", "read", 1000)
    }

    fn denied_decision() -> Decision {
        Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "policy",
            FactorType::SecurityPolicy,
            FactorDirection::Opposing,
            0.7,
            "deny-rule",
        ))
        .with_factor(DecisionFactor::new(
            "trust",
            FactorType::TrustLevel,
            FactorDirection::Supporting,
            0.3,
            "high",
        ))
    }

    #[test]
    fn test_generate_flip() {
        let cfgen = CounterfactualGenerator::new();
        let cf = cfgen.generate(&denied_decision(), "approved", 2000);
        assert_eq!(cf.original_outcome, "denied");
        assert_eq!(cf.target_outcome, "approved");
        // Only the opposing factor needs to change
        assert_eq!(cf.required_changes.len(), 1);
        assert_eq!(cf.required_changes[0].factor_name, "policy");
    }

    #[test]
    fn test_difficulty_from_weight() {
        let cfgen = CounterfactualGenerator::new();
        let d = Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "low-weight",
            FactorType::SecurityPolicy,
            FactorDirection::Opposing,
            0.2,
            "deny",
        ));
        let cf = cfgen.generate(&d, "approved", 2000);
        assert_eq!(cf.required_changes[0].difficulty, ChangeDifficulty::Easy);
    }

    #[test]
    fn test_high_weight_is_hard() {
        let cfgen = CounterfactualGenerator::new();
        let cf = cfgen.generate(&denied_decision(), "approved", 2000);
        assert_eq!(cf.required_changes[0].difficulty, ChangeDifficulty::Hard);
    }

    #[test]
    fn test_feasibility_from_difficulty() {
        let cfgen = CounterfactualGenerator::new();
        let cf = cfgen.generate(&denied_decision(), "approved", 2000);
        assert_eq!(cf.feasibility, CounterfactualFeasibility::DifficultButPossible);
    }

    #[test]
    fn test_overall_difficulty_is_max() {
        let cfgen = CounterfactualGenerator::new();
        let d = Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "f1",
            FactorType::SecurityPolicy,
            FactorDirection::Opposing,
            0.2,
            "deny",
        ))
        .with_factor(DecisionFactor::new(
            "f2",
            FactorType::RiskScore,
            FactorDirection::Opposing,
            0.8,
            "high-risk",
        ));
        let cf = cfgen.generate(&d, "approved", 2000);
        assert_eq!(cf.overall_difficulty, ChangeDifficulty::Hard);
    }

    #[test]
    fn test_min_changes() {
        let cfgen = CounterfactualGenerator::new();
        let cf = cfgen.generate(&denied_decision(), "approved", 2000);
        assert_eq!(cf.min_changes(), 1);
    }

    #[test]
    fn test_easiest_and_hardest() {
        let cfgen = CounterfactualGenerator::new();
        let d = Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "easy-one",
            FactorType::SecurityPolicy,
            FactorDirection::Opposing,
            0.1,
            "deny",
        ))
        .with_factor(DecisionFactor::new(
            "hard-one",
            FactorType::RiskScore,
            FactorDirection::Opposing,
            0.8,
            "high-risk",
        ));
        let cf = cfgen.generate(&d, "approved", 2000);
        assert_eq!(cf.easiest_change().unwrap().factor_name, "easy-one");
        assert_eq!(cf.hardest_change().unwrap().factor_name, "hard-one");
    }

    #[test]
    fn test_narrative_populated() {
        let cfgen = CounterfactualGenerator::new();
        let cf = cfgen.generate(&denied_decision(), "approved", 2000);
        assert!(cf.narrative.contains("denied"));
        assert!(cf.narrative.contains("approved"));
    }

    #[test]
    fn test_change_difficulty_display() {
        assert_eq!(ChangeDifficulty::Easy.to_string(), "easy");
        assert_eq!(ChangeDifficulty::Moderate.to_string(), "moderate");
        assert_eq!(ChangeDifficulty::Hard.to_string(), "hard");
        assert_eq!(ChangeDifficulty::Impossible.to_string(), "impossible");
    }

    #[test]
    fn test_feasibility_display() {
        assert_eq!(CounterfactualFeasibility::Feasible.to_string(), "feasible");
        assert_eq!(
            CounterfactualFeasibility::DifficultButPossible.to_string(),
            "difficult-but-possible"
        );
        assert_eq!(CounterfactualFeasibility::Infeasible.to_string(), "infeasible");
    }

    #[test]
    fn test_all_supporting_no_flip_needed() {
        let cfgen = CounterfactualGenerator::new();
        let d = Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "trust",
            FactorType::TrustLevel,
            FactorDirection::Supporting,
            0.8,
            "high",
        ));
        let cf = cfgen.generate(&d, "denied", 2000);
        // No opposing factors, but needs to flip → targeting non-supporting
        // The supporting factor won't be in required_changes for a flip
        // (direction != Opposing), so we get a fallback
        assert!(!cf.required_changes.is_empty());
    }
}
