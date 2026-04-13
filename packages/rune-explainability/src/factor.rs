// ═══════════════════════════════════════════════════════════════════════
// Factor — factor attribution analysis.
//
// FactorAnalyzer normalizes factor weights, ranks by importance,
// identifies the decisive factor, and compares factor profiles
// across decisions to find divergent factors.
// ═══════════════════════════════════════════════════════════════════════

use crate::decision::{Decision, DecisionFactor, FactorDirection};

// ── AnalyzedFactor ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnalyzedFactor {
    pub name: String,
    pub raw_weight: f64,
    pub normalized_weight: f64,
    pub direction: FactorDirection,
    pub rank: usize,
    pub is_decisive: bool,
}

// ── FactorAnalysis ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FactorAnalysis {
    pub decision_id: String,
    pub factors: Vec<AnalyzedFactor>,
    pub decisive_factor: Option<String>,
    pub supporting_weight: f64,
    pub opposing_weight: f64,
    pub analyzed_at: i64,
}

impl FactorAnalysis {
    pub fn factor_by_name(&self, name: &str) -> Option<&AnalyzedFactor> {
        self.factors.iter().find(|f| f.name == name)
    }

    pub fn top_factors(&self, n: usize) -> Vec<&AnalyzedFactor> {
        self.factors.iter().take(n).collect()
    }
}

// ── DivergentFactor ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DivergentFactor {
    pub name: String,
    pub weight_a: f64,
    pub weight_b: f64,
    pub direction_a: FactorDirection,
    pub direction_b: FactorDirection,
    pub divergence: f64,
}

// ── FactorComparison ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FactorComparison {
    pub decision_a: String,
    pub decision_b: String,
    pub common_factors: usize,
    pub divergent_factors: Vec<DivergentFactor>,
    pub similarity: f64,
}

// ── FactorAnalyzer ──────────────────────────────────────────────────

pub struct FactorAnalyzer;

impl FactorAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, decision: &Decision, now: i64) -> FactorAnalysis {
        let total_weight: f64 = decision.factors.iter().map(|f| f.weight.abs()).sum();
        let norm = if total_weight > 0.0 { total_weight } else { 1.0 };

        let mut analyzed: Vec<AnalyzedFactor> = decision
            .factors
            .iter()
            .map(|f| AnalyzedFactor {
                name: f.name.clone(),
                raw_weight: f.weight,
                normalized_weight: f.weight.abs() / norm,
                direction: f.direction.clone(),
                rank: 0,
                is_decisive: false,
            })
            .collect();

        // Sort by normalized weight descending
        analyzed.sort_by(|a, b| {
            b.normalized_weight
                .partial_cmp(&a.normalized_weight)
                .unwrap()
        });

        // Assign ranks (1-based)
        for (i, f) in analyzed.iter_mut().enumerate() {
            f.rank = i + 1;
        }

        // Mark decisive
        if let Some(first) = analyzed.first_mut() {
            first.is_decisive = true;
        }

        let decisive_factor = analyzed.first().map(|f| f.name.clone());

        let supporting_weight: f64 = analyzed
            .iter()
            .filter(|f| f.direction == FactorDirection::Supporting)
            .map(|f| f.normalized_weight)
            .sum();

        let opposing_weight: f64 = analyzed
            .iter()
            .filter(|f| f.direction == FactorDirection::Opposing)
            .map(|f| f.normalized_weight)
            .sum();

        FactorAnalysis {
            decision_id: decision.id.0.clone(),
            factors: analyzed,
            decisive_factor,
            supporting_weight,
            opposing_weight,
            analyzed_at: now,
        }
    }

    pub fn compare(&self, a: &Decision, b: &Decision) -> FactorComparison {
        let factors_a = factor_map(&a.factors);
        let factors_b = factor_map(&b.factors);

        let all_names: std::collections::HashSet<&str> = factors_a
            .keys()
            .chain(factors_b.keys())
            .copied()
            .collect();

        let mut common = 0usize;
        let mut divergent = Vec::new();

        for name in &all_names {
            match (factors_a.get(name), factors_b.get(name)) {
                (Some(fa), Some(fb)) => {
                    common += 1;
                    let div = (fa.weight - fb.weight).abs();
                    if div > 0.1 || fa.direction != fb.direction {
                        divergent.push(DivergentFactor {
                            name: name.to_string(),
                            weight_a: fa.weight,
                            weight_b: fb.weight,
                            direction_a: fa.direction.clone(),
                            direction_b: fb.direction.clone(),
                            divergence: div,
                        });
                    }
                }
                (Some(fa), None) => {
                    divergent.push(DivergentFactor {
                        name: name.to_string(),
                        weight_a: fa.weight,
                        weight_b: 0.0,
                        direction_a: fa.direction.clone(),
                        direction_b: FactorDirection::Neutral,
                        divergence: fa.weight,
                    });
                }
                (None, Some(fb)) => {
                    divergent.push(DivergentFactor {
                        name: name.to_string(),
                        weight_a: 0.0,
                        weight_b: fb.weight,
                        direction_a: FactorDirection::Neutral,
                        direction_b: fb.direction.clone(),
                        divergence: fb.weight,
                    });
                }
                (None, None) => {}
            }
        }

        let similarity = if all_names.is_empty() {
            1.0
        } else {
            1.0 - (divergent.len() as f64 / all_names.len() as f64)
        };

        FactorComparison {
            decision_a: a.id.0.clone(),
            decision_b: b.id.0.clone(),
            common_factors: common,
            divergent_factors: divergent,
            similarity,
        }
    }
}

impl Default for FactorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn factor_map(factors: &[DecisionFactor]) -> std::collections::HashMap<&str, &DecisionFactor> {
    factors.iter().map(|f| (f.name.as_str(), f)).collect()
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

    fn two_factor_decision(id: &str) -> Decision {
        Decision::new(
            DecisionId::new(id),
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
            "deny",
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
    fn test_analyze_normalized_weights() {
        let analyzer = FactorAnalyzer::new();
        let analysis = analyzer.analyze(&two_factor_decision("d1"), 2000);
        let total: f64 = analysis.factors.iter().map(|f| f.normalized_weight).sum();
        assert!((total - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_analyze_ranks() {
        let analyzer = FactorAnalyzer::new();
        let analysis = analyzer.analyze(&two_factor_decision("d1"), 2000);
        assert_eq!(analysis.factors[0].rank, 1);
        assert_eq!(analysis.factors[1].rank, 2);
    }

    #[test]
    fn test_analyze_decisive_factor() {
        let analyzer = FactorAnalyzer::new();
        let analysis = analyzer.analyze(&two_factor_decision("d1"), 2000);
        assert_eq!(analysis.decisive_factor.as_deref(), Some("policy"));
        assert!(analysis.factors[0].is_decisive);
        assert!(!analysis.factors[1].is_decisive);
    }

    #[test]
    fn test_analyze_supporting_opposing_weights() {
        let analyzer = FactorAnalyzer::new();
        let analysis = analyzer.analyze(&two_factor_decision("d1"), 2000);
        assert!((analysis.supporting_weight - 0.3).abs() < 1e-9);
        assert!((analysis.opposing_weight - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_analyze_empty_factors() {
        let analyzer = FactorAnalyzer::new();
        let d = Decision::new(
            DecisionId::new("d-empty"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            ctx(),
            "engine",
            1000,
        );
        let analysis = analyzer.analyze(&d, 2000);
        assert!(analysis.factors.is_empty());
        assert!(analysis.decisive_factor.is_none());
    }

    #[test]
    fn test_factor_by_name() {
        let analyzer = FactorAnalyzer::new();
        let analysis = analyzer.analyze(&two_factor_decision("d1"), 2000);
        assert!(analysis.factor_by_name("policy").is_some());
        assert!(analysis.factor_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_top_factors() {
        let analyzer = FactorAnalyzer::new();
        let analysis = analyzer.analyze(&two_factor_decision("d1"), 2000);
        assert_eq!(analysis.top_factors(1).len(), 1);
        assert_eq!(analysis.top_factors(5).len(), 2);
    }

    #[test]
    fn test_compare_identical() {
        let analyzer = FactorAnalyzer::new();
        let d1 = two_factor_decision("d1");
        let d2 = two_factor_decision("d2");
        let cmp = analyzer.compare(&d1, &d2);
        assert_eq!(cmp.common_factors, 2);
        assert!(cmp.divergent_factors.is_empty());
        assert!((cmp.similarity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_compare_divergent() {
        let analyzer = FactorAnalyzer::new();
        let d1 = two_factor_decision("d1");
        let d2 = Decision::new(
            DecisionId::new("d2"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "policy",
            FactorType::SecurityPolicy,
            FactorDirection::Supporting,
            0.9,
            "allow",
        ))
        .with_factor(DecisionFactor::new(
            "trust",
            FactorType::TrustLevel,
            FactorDirection::Supporting,
            0.3,
            "high",
        ));
        let cmp = analyzer.compare(&d1, &d2);
        assert_eq!(cmp.common_factors, 2);
        assert!(!cmp.divergent_factors.is_empty());
        assert!(cmp.similarity < 1.0);
    }

    #[test]
    fn test_compare_disjoint_factors() {
        let analyzer = FactorAnalyzer::new();
        let d1 = Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "alpha",
            FactorType::RiskScore,
            FactorDirection::Opposing,
            0.5,
            "high",
        ));
        let d2 = Decision::new(
            DecisionId::new("d2"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            ctx(),
            "engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "beta",
            FactorType::TrustLevel,
            FactorDirection::Supporting,
            0.5,
            "high",
        ));
        let cmp = analyzer.compare(&d1, &d2);
        assert_eq!(cmp.common_factors, 0);
        assert_eq!(cmp.divergent_factors.len(), 2);
        assert!((cmp.similarity - 0.0).abs() < 1e-9);
    }
}
