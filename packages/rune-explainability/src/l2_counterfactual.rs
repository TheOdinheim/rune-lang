// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Enhanced counterfactual analysis.
//
// Extends Layer 1 counterfactuals with typed feature changes,
// quantitative distance metrics, counterfactual sets, and immutable
// feature constraints.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── ChangeType ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ChangeType {
    Increase { amount: f64 },
    Decrease { amount: f64 },
    SetTo(String),
    Remove,
    Add(String),
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Increase { amount } => write!(f, "increase by {amount:.2}"),
            Self::Decrease { amount } => write!(f, "decrease by {amount:.2}"),
            Self::SetTo(v) => write!(f, "set to {v}"),
            Self::Remove => f.write_str("remove"),
            Self::Add(v) => write!(f, "add {v}"),
        }
    }
}

// ── FeatureChange ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FeatureChange {
    pub feature_name: String,
    pub original_value: String,
    pub required_value: String,
    pub change_type: ChangeType,
}

impl FeatureChange {
    pub fn new(
        feature_name: impl Into<String>,
        original_value: impl Into<String>,
        required_value: impl Into<String>,
        change_type: ChangeType,
    ) -> Self {
        Self {
            feature_name: feature_name.into(),
            original_value: original_value.into(),
            required_value: required_value.into(),
            change_type,
        }
    }
}

// ── CounterfactualFeasibility ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum L2CounterfactualFeasibility {
    Easy = 0,
    Moderate = 1,
    Difficult = 2,
    Infeasible = 3,
}

impl fmt::Display for L2CounterfactualFeasibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Easy => f.write_str("easy"),
            Self::Moderate => f.write_str("moderate"),
            Self::Difficult => f.write_str("difficult"),
            Self::Infeasible => f.write_str("infeasible"),
        }
    }
}

// ── L2Counterfactual ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2Counterfactual {
    pub id: String,
    pub original_outcome: String,
    pub alternative_outcome: String,
    pub changes_required: Vec<FeatureChange>,
    pub feasibility: L2CounterfactualFeasibility,
    pub distance: f64,
}

// ── CounterfactualGenerator ──────────────────────────────────────────

pub struct L2CounterfactualGenerator {
    pub max_changes: usize,
    pub immutable_features: Vec<String>,
}

impl L2CounterfactualGenerator {
    pub fn new(max_changes: usize) -> Self {
        Self {
            max_changes,
            immutable_features: Vec::new(),
        }
    }

    pub fn add_immutable(&mut self, feature: &str) {
        self.immutable_features.push(feature.into());
    }

    pub fn generate(
        &self,
        decision_id: &str,
        original_outcome: &str,
        alternative_outcome: &str,
        changes: Vec<FeatureChange>,
    ) -> L2Counterfactual {
        let has_immutable = changes
            .iter()
            .any(|c| self.immutable_features.contains(&c.feature_name));
        let too_many = changes.len() > self.max_changes;

        let feasibility = if has_immutable {
            L2CounterfactualFeasibility::Infeasible
        } else if too_many {
            L2CounterfactualFeasibility::Difficult
        } else if changes.len() <= 1 {
            L2CounterfactualFeasibility::Easy
        } else {
            L2CounterfactualFeasibility::Moderate
        };

        let distance = Self::distance(&changes);

        L2Counterfactual {
            id: decision_id.into(),
            original_outcome: original_outcome.into(),
            alternative_outcome: alternative_outcome.into(),
            changes_required: changes,
            feasibility,
            distance,
        }
    }

    pub fn distance(changes: &[FeatureChange]) -> f64 {
        let mut dist = 0.0;
        for change in changes {
            match &change.change_type {
                ChangeType::Increase { amount } => dist += amount.abs(),
                ChangeType::Decrease { amount } => dist += amount.abs(),
                ChangeType::SetTo(_) | ChangeType::Remove | ChangeType::Add(_) => dist += 1.0,
            }
        }
        dist
    }
}

// ── CounterfactualSet ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CounterfactualSet {
    pub decision_id: String,
    pub counterfactuals: Vec<L2Counterfactual>,
}

impl CounterfactualSet {
    pub fn new(decision_id: impl Into<String>) -> Self {
        Self {
            decision_id: decision_id.into(),
            counterfactuals: Vec::new(),
        }
    }

    pub fn add(&mut self, cf: L2Counterfactual) {
        self.counterfactuals.push(cf);
    }

    pub fn most_actionable(&self) -> Option<&L2Counterfactual> {
        self.counterfactuals
            .iter()
            .filter(|cf| cf.feasibility != L2CounterfactualFeasibility::Infeasible)
            .min_by(|a, b| {
                a.feasibility
                    .cmp(&b.feasibility)
                    .then(a.distance.partial_cmp(&b.distance).unwrap_or(std::cmp::Ordering::Equal))
            })
    }

    pub fn by_feasibility(
        &self,
        feasibility: &L2CounterfactualFeasibility,
    ) -> Vec<&L2Counterfactual> {
        self.counterfactuals
            .iter()
            .filter(|cf| cf.feasibility == *feasibility)
            .collect()
    }

    pub fn min_changes_required(&self) -> usize {
        self.counterfactuals
            .iter()
            .map(|cf| cf.changes_required.len())
            .min()
            .unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterfactual_construction() {
        let cf = L2Counterfactual {
            id: "d1".into(),
            original_outcome: "denied".into(),
            alternative_outcome: "approved".into(),
            changes_required: vec![FeatureChange::new(
                "income",
                "50000",
                "75000",
                ChangeType::Increase { amount: 25000.0 },
            )],
            feasibility: L2CounterfactualFeasibility::Moderate,
            distance: 25000.0,
        };
        assert_eq!(cf.changes_required.len(), 1);
    }

    #[test]
    fn test_generator_feasibility_easy() {
        let generator = L2CounterfactualGenerator::new(3);
        let cf = generator.generate(
            "d1",
            "denied",
            "approved",
            vec![FeatureChange::new(
                "score",
                "0.4",
                "0.8",
                ChangeType::Increase { amount: 0.4 },
            )],
        );
        assert_eq!(cf.feasibility, L2CounterfactualFeasibility::Easy);
    }

    #[test]
    fn test_generator_immutable_infeasible() {
        let mut generator = L2CounterfactualGenerator::new(3);
        generator.add_immutable("age");
        let cf = generator.generate(
            "d1",
            "denied",
            "approved",
            vec![FeatureChange::new(
                "age",
                "25",
                "30",
                ChangeType::Increase { amount: 5.0 },
            )],
        );
        assert_eq!(cf.feasibility, L2CounterfactualFeasibility::Infeasible);
    }

    #[test]
    fn test_distance_calculation() {
        let changes = vec![
            FeatureChange::new("a", "1", "2", ChangeType::Increase { amount: 10.0 }),
            FeatureChange::new("b", "x", "y", ChangeType::SetTo("y".into())),
        ];
        let dist = L2CounterfactualGenerator::distance(&changes);
        assert!((dist - 11.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_counterfactual_set_most_actionable() {
        let generator = L2CounterfactualGenerator::new(5);
        let mut set = CounterfactualSet::new("d1");
        set.add(generator.generate(
            "d1",
            "denied",
            "approved",
            vec![
                FeatureChange::new("a", "1", "2", ChangeType::Increase { amount: 100.0 }),
                FeatureChange::new("b", "1", "2", ChangeType::Increase { amount: 100.0 }),
            ],
        ));
        set.add(generator.generate(
            "d1",
            "denied",
            "approved",
            vec![FeatureChange::new(
                "c",
                "1",
                "2",
                ChangeType::Increase { amount: 5.0 },
            )],
        ));
        let best = set.most_actionable().unwrap();
        assert_eq!(best.changes_required.len(), 1); // fewer changes, lower distance
    }

    #[test]
    fn test_counterfactual_set_by_feasibility() {
        let generator = L2CounterfactualGenerator::new(5);
        let mut set = CounterfactualSet::new("d1");
        set.add(generator.generate(
            "d1",
            "denied",
            "approved",
            vec![FeatureChange::new(
                "a",
                "1",
                "2",
                ChangeType::Increase { amount: 1.0 },
            )],
        ));
        let easy = set.by_feasibility(&L2CounterfactualFeasibility::Easy);
        assert_eq!(easy.len(), 1);
        let hard = set.by_feasibility(&L2CounterfactualFeasibility::Difficult);
        assert!(hard.is_empty());
    }

    #[test]
    fn test_counterfactual_set_min_changes() {
        let generator = L2CounterfactualGenerator::new(5);
        let mut set = CounterfactualSet::new("d1");
        set.add(generator.generate(
            "d1",
            "denied",
            "approved",
            vec![
                FeatureChange::new("a", "1", "2", ChangeType::Increase { amount: 1.0 }),
                FeatureChange::new("b", "1", "2", ChangeType::Increase { amount: 1.0 }),
                FeatureChange::new("c", "1", "2", ChangeType::Increase { amount: 1.0 }),
            ],
        ));
        set.add(generator.generate(
            "d1",
            "denied",
            "approved",
            vec![FeatureChange::new(
                "x",
                "1",
                "2",
                ChangeType::Increase { amount: 1.0 },
            )],
        ));
        assert_eq!(set.min_changes_required(), 1);
    }
}
