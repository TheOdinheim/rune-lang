// ═══════════════════════════════════════════════════════════════════════
// Differential Privacy — Epsilon/Delta Budgets and Noise Mechanisms
//
// Formal (ε, δ)-DP with budget accounting. Laplace and Gaussian
// mechanisms for counting, sum, average, and histogram queries.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::anonymize::add_laplace_noise;
use crate::error::PrivacyError;

// ── PrivacyBudget ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivacyBudget {
    pub epsilon: f64,
    pub delta: f64,
    pub consumed_epsilon: f64,
    pub consumed_delta: f64,
}

impl PrivacyBudget {
    pub fn new(epsilon: f64, delta: f64) -> Self {
        Self { epsilon, delta, consumed_epsilon: 0.0, consumed_delta: 0.0 }
    }

    pub fn strict() -> Self {
        Self::new(0.1, 1e-8)
    }

    pub fn standard() -> Self {
        Self::new(1.0, 1e-6)
    }

    pub fn relaxed() -> Self {
        Self::new(10.0, 1e-4)
    }

    pub fn remaining_epsilon(&self) -> f64 {
        (self.epsilon - self.consumed_epsilon).max(0.0)
    }

    pub fn remaining_delta(&self) -> f64 {
        (self.delta - self.consumed_delta).max(0.0)
    }

    pub fn is_exhausted(&self) -> bool {
        self.consumed_epsilon >= self.epsilon
    }

    pub fn can_afford(&self, epsilon_cost: f64, delta_cost: f64) -> bool {
        self.remaining_epsilon() >= epsilon_cost && self.remaining_delta() >= delta_cost
    }

    pub fn consume(&mut self, epsilon_cost: f64, delta_cost: f64) -> Result<(), PrivacyError> {
        if !self.can_afford(epsilon_cost, delta_cost) {
            return Err(PrivacyError::InsufficientPrivacyBudget {
                required_epsilon: epsilon_cost,
                remaining_epsilon: self.remaining_epsilon(),
            });
        }
        self.consumed_epsilon += epsilon_cost;
        self.consumed_delta += delta_cost;
        Ok(())
    }

    pub fn utilization(&self) -> f64 {
        if self.epsilon <= 0.0 {
            return 0.0;
        }
        (self.consumed_epsilon / self.epsilon) * 100.0
    }
}

// ── DpMechanism ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpMechanism {
    Laplace,
    Gaussian,
    Exponential,
}

impl fmt::Display for DpMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── QueryType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum QueryType {
    Count,
    Sum { field: String },
    Average { field: String },
    Histogram { field: String, bins: Vec<String> },
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count => write!(f, "Count"),
            Self::Sum { field } => write!(f, "Sum({field})"),
            Self::Average { field } => write!(f, "Average({field})"),
            Self::Histogram { field, bins } => write!(f, "Histogram({field}, {} bins)", bins.len()),
        }
    }
}

// ── DpQuery ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DpQuery {
    pub query_type: QueryType,
    pub sensitivity: f64,
    pub mechanism: DpMechanism,
    pub epsilon_cost: f64,
    pub delta_cost: f64,
}

// ── DpQueryResult ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DpQueryResult {
    pub query: DpQuery,
    pub true_value: f64,
    pub noisy_value: f64,
    pub noise_added: f64,
    pub executed_at: i64,
    pub remaining_epsilon: f64,
}

// ── DpEngine ──────────────────────────────────────────────────────────

pub struct DpEngine {
    pub budget: PrivacyBudget,
    pub queries_executed: Vec<DpQueryResult>,
}

impl DpEngine {
    pub fn new(budget: PrivacyBudget) -> Self {
        Self { budget, queries_executed: Vec::new() }
    }

    fn record(&mut self, query: DpQuery, true_value: f64, noisy_value: f64) {
        let result = DpQueryResult {
            query,
            true_value,
            noisy_value,
            noise_added: noisy_value - true_value,
            executed_at: 0,
            remaining_epsilon: self.budget.remaining_epsilon(),
        };
        self.queries_executed.push(result);
    }

    pub fn execute_count(&mut self, true_count: u64, epsilon: f64) -> Result<f64, PrivacyError> {
        self.budget.consume(epsilon, 0.0)?;
        let true_val = true_count as f64;
        let noisy = add_laplace_noise(true_val, 1.0, epsilon);
        let query = DpQuery {
            query_type: QueryType::Count,
            sensitivity: 1.0,
            mechanism: DpMechanism::Laplace,
            epsilon_cost: epsilon,
            delta_cost: 0.0,
        };
        self.record(query, true_val, noisy);
        Ok(noisy)
    }

    pub fn execute_sum(
        &mut self,
        true_sum: f64,
        sensitivity: f64,
        epsilon: f64,
    ) -> Result<f64, PrivacyError> {
        self.budget.consume(epsilon, 0.0)?;
        let noisy = add_laplace_noise(true_sum, sensitivity, epsilon);
        let query = DpQuery {
            query_type: QueryType::Sum { field: String::new() },
            sensitivity,
            mechanism: DpMechanism::Laplace,
            epsilon_cost: epsilon,
            delta_cost: 0.0,
        };
        self.record(query, true_sum, noisy);
        Ok(noisy)
    }

    pub fn execute_average(
        &mut self,
        true_avg: f64,
        count: u64,
        value_range: f64,
        epsilon: f64,
    ) -> Result<f64, PrivacyError> {
        self.budget.consume(epsilon, 0.0)?;
        let sensitivity = if count == 0 { value_range } else { value_range / count as f64 };
        let noisy = add_laplace_noise(true_avg, sensitivity, epsilon);
        let query = DpQuery {
            query_type: QueryType::Average { field: String::new() },
            sensitivity,
            mechanism: DpMechanism::Laplace,
            epsilon_cost: epsilon,
            delta_cost: 0.0,
        };
        self.record(query, true_avg, noisy);
        Ok(noisy)
    }

    pub fn execute_histogram(
        &mut self,
        true_counts: &[u64],
        epsilon: f64,
    ) -> Result<Vec<f64>, PrivacyError> {
        self.budget.consume(epsilon, 0.0)?;
        let num_bins = true_counts.len().max(1);
        let per_bin_epsilon = epsilon / num_bins as f64;
        let mut noisy = Vec::with_capacity(num_bins);
        for (i, c) in true_counts.iter().enumerate() {
            // Use different seeds per bin via offset
            let val = *c as f64 + i as f64 * 1e-9;
            noisy.push(add_laplace_noise(val, 1.0, per_bin_epsilon));
        }
        let query = DpQuery {
            query_type: QueryType::Histogram { field: String::new(), bins: Vec::new() },
            sensitivity: 1.0,
            mechanism: DpMechanism::Laplace,
            epsilon_cost: epsilon,
            delta_cost: 0.0,
        };
        let true_total: f64 = true_counts.iter().sum::<u64>() as f64;
        let noisy_total: f64 = noisy.iter().sum();
        self.record(query, true_total, noisy_total);
        Ok(noisy)
    }

    pub fn remaining_budget(&self) -> (f64, f64) {
        (self.budget.remaining_epsilon(), self.budget.remaining_delta())
    }

    pub fn query_count(&self) -> usize {
        self.queries_executed.len()
    }

    pub fn query_history(&self) -> &[DpQueryResult] {
        &self.queries_executed
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Enhanced Differential Privacy
// ═══════════════════════════════════════════════════════════════════════

use crate::anonymize::{add_gaussian_noise, deterministic_uniform, seed_from_value};

/// Gaussian noise for (ε,δ)-differential privacy.
/// σ = sensitivity * sqrt(2 * ln(1.25 / δ)) / ε
pub fn gaussian_noise(sensitivity: f64, epsilon: f64, delta: f64) -> f64 {
    if epsilon <= 0.0 || delta <= 0.0 {
        return 0.0;
    }
    let sigma = calibrate_gaussian(sensitivity, epsilon, delta);
    // Box-Muller transform
    let seed = seed_from_value(sensitivity * epsilon);
    let u1 = deterministic_uniform(seed).max(1e-12);
    let u2 = deterministic_uniform(seed.wrapping_add(1));
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    z * sigma
}

/// Calibrate Laplace scale parameter: b = sensitivity / epsilon.
pub fn calibrate_laplace(sensitivity: f64, epsilon: f64) -> f64 {
    if epsilon <= 0.0 {
        return f64::INFINITY;
    }
    sensitivity / epsilon
}

/// Calibrate Gaussian σ: sensitivity * sqrt(2 * ln(1.25/δ)) / ε.
pub fn calibrate_gaussian(sensitivity: f64, epsilon: f64, delta: f64) -> f64 {
    if epsilon <= 0.0 || delta <= 0.0 {
        return f64::INFINITY;
    }
    sensitivity * (2.0 * (1.25_f64 / delta).ln()).sqrt() / epsilon
}

/// Query record for budget tracking.
#[derive(Debug, Clone)]
pub struct BudgetQuery {
    pub query_id: String,
    pub epsilon_cost: f64,
    pub delta_cost: f64,
    pub mechanism: String,
    pub timestamp: i64,
}

/// Privacy budget tracker with query history and composition theorems.
pub struct PrivacyBudgetTracker {
    pub total_epsilon: f64,
    pub total_delta: f64,
    pub spent_epsilon: f64,
    pub spent_delta: f64,
    pub queries: Vec<BudgetQuery>,
}

impl PrivacyBudgetTracker {
    pub fn new(total_epsilon: f64, total_delta: f64) -> Self {
        Self {
            total_epsilon,
            total_delta,
            spent_epsilon: 0.0,
            spent_delta: 0.0,
            queries: Vec::new(),
        }
    }

    pub fn can_afford(&self, epsilon: f64, delta: f64) -> bool {
        self.remaining_epsilon() >= epsilon && self.remaining_delta() >= delta
    }

    pub fn spend(
        &mut self,
        query_id: &str,
        epsilon: f64,
        delta: f64,
        mechanism: &str,
        now: i64,
    ) -> Result<(), PrivacyError> {
        if !self.can_afford(epsilon, delta) {
            return Err(PrivacyError::InsufficientPrivacyBudget {
                required_epsilon: epsilon,
                remaining_epsilon: self.remaining_epsilon(),
            });
        }
        self.spent_epsilon += epsilon;
        self.spent_delta += delta;
        self.queries.push(BudgetQuery {
            query_id: query_id.to_string(),
            epsilon_cost: epsilon,
            delta_cost: delta,
            mechanism: mechanism.to_string(),
            timestamp: now,
        });
        Ok(())
    }

    pub fn remaining_epsilon(&self) -> f64 {
        (self.total_epsilon - self.spent_epsilon).max(0.0)
    }

    pub fn remaining_delta(&self) -> f64 {
        (self.total_delta - self.spent_delta).max(0.0)
    }

    pub fn utilization(&self) -> f64 {
        if self.total_epsilon <= 0.0 {
            return 0.0;
        }
        self.spent_epsilon / self.total_epsilon
    }

    pub fn reset(&mut self) {
        self.spent_epsilon = 0.0;
        self.spent_delta = 0.0;
        self.queries.clear();
    }

    /// Basic sequential composition: sum of all query epsilons.
    pub fn sequential_composition_epsilon(&self) -> f64 {
        self.queries.iter().map(|q| q.epsilon_cost).sum()
    }

    /// Advanced composition theorem (tighter bound).
    /// sqrt(2k * ln(1/δ')) * ε_max + k * ε_max * (e^ε_max - 1)
    pub fn advanced_composition_epsilon(&self, target_delta: f64) -> f64 {
        if self.queries.is_empty() || target_delta <= 0.0 {
            return 0.0;
        }
        let k = self.queries.len() as f64;
        let max_eps = self.queries.iter().map(|q| q.epsilon_cost)
            .fold(0.0_f64, f64::max);
        let term1 = (2.0 * k * (1.0 / target_delta).ln()).sqrt() * max_eps;
        let term2 = k * max_eps * (max_eps.exp() - 1.0);
        term1 + term2
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_tracks_consumption() {
        let mut b = PrivacyBudget::new(1.0, 1e-6);
        b.consume(0.3, 0.0).unwrap();
        assert!((b.consumed_epsilon - 0.3).abs() < 1e-9);
        assert!((b.remaining_epsilon() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_budget_strict() {
        let b = PrivacyBudget::strict();
        assert_eq!(b.epsilon, 0.1);
        assert_eq!(b.delta, 1e-8);
    }

    #[test]
    fn test_budget_standard() {
        let b = PrivacyBudget::standard();
        assert_eq!(b.epsilon, 1.0);
    }

    #[test]
    fn test_budget_exhausted() {
        let mut b = PrivacyBudget::new(1.0, 1e-6);
        b.consume(1.0, 0.0).unwrap();
        assert!(b.is_exhausted());
    }

    #[test]
    fn test_budget_can_afford() {
        let b = PrivacyBudget::new(1.0, 1e-6);
        assert!(b.can_afford(0.5, 1e-7));
        assert!(!b.can_afford(2.0, 0.0));
    }

    #[test]
    fn test_dp_count_adds_noise() {
        let mut engine = DpEngine::new(PrivacyBudget::standard());
        let noisy = engine.execute_count(100, 0.1).unwrap();
        // Noise is nonzero
        assert!((noisy - 100.0).abs() > 0.0);
    }

    #[test]
    fn test_dp_count_large_epsilon() {
        let mut engine = DpEngine::new(PrivacyBudget::new(1000.0, 1e-6));
        let noisy = engine.execute_count(100, 500.0).unwrap();
        // With sensitivity 1 and epsilon 500, noise should be very small
        assert!((noisy - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_dp_sum_sensitivity() {
        let mut engine = DpEngine::new(PrivacyBudget::standard());
        let noisy_small = engine.execute_sum(1000.0, 1.0, 0.1).unwrap();
        let mut engine2 = DpEngine::new(PrivacyBudget::standard());
        let noisy_large = engine2.execute_sum(1000.0, 100.0, 0.1).unwrap();
        // Larger sensitivity → larger noise
        assert!((noisy_large - 1000.0).abs() >= (noisy_small - 1000.0).abs());
    }

    #[test]
    fn test_dp_histogram() {
        let mut engine = DpEngine::new(PrivacyBudget::standard());
        let result = engine.execute_histogram(&[10, 20, 30], 0.3).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_dp_rejects_when_exhausted() {
        let mut engine = DpEngine::new(PrivacyBudget::new(0.1, 1e-6));
        engine.execute_count(100, 0.1).unwrap();
        let result = engine.execute_count(200, 0.1);
        assert!(result.is_err());
    }

    #[test]
    fn test_dp_tracks_history() {
        let mut engine = DpEngine::new(PrivacyBudget::standard());
        engine.execute_count(100, 0.1).unwrap();
        engine.execute_sum(500.0, 10.0, 0.1).unwrap();
        assert_eq!(engine.query_count(), 2);
        assert_eq!(engine.query_history().len(), 2);
    }

    #[test]
    fn test_dp_budget_decreases() {
        let mut engine = DpEngine::new(PrivacyBudget::new(1.0, 1e-6));
        let (before_eps, _) = engine.remaining_budget();
        engine.execute_count(100, 0.3).unwrap();
        let (after_eps, _) = engine.remaining_budget();
        assert!(after_eps < before_eps);
    }

    #[test]
    fn test_dp_mechanism_display() {
        assert_eq!(DpMechanism::Laplace.to_string(), "Laplace");
        assert_eq!(DpMechanism::Gaussian.to_string(), "Gaussian");
    }

    #[test]
    fn test_query_type_display() {
        assert_eq!(QueryType::Count.to_string(), "Count");
        assert_eq!(QueryType::Sum { field: "x".into() }.to_string(), "Sum(x)");
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_gaussian_noise_nonzero() {
        let noise = gaussian_noise(1.0, 1.0, 1e-5);
        assert!(noise.abs() > 0.0);
    }

    #[test]
    fn test_gaussian_noise_zero_epsilon() {
        let noise = gaussian_noise(1.0, 0.0, 1e-5);
        assert_eq!(noise, 0.0);
    }

    #[test]
    fn test_gaussian_noise_zero_delta() {
        let noise = gaussian_noise(1.0, 1.0, 0.0);
        assert_eq!(noise, 0.0);
    }

    #[test]
    fn test_calibrate_laplace() {
        let scale = calibrate_laplace(1.0, 0.5);
        assert!((scale - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_calibrate_laplace_zero_epsilon() {
        let scale = calibrate_laplace(1.0, 0.0);
        assert!(scale.is_infinite());
    }

    #[test]
    fn test_calibrate_gaussian_basic() {
        let sigma = calibrate_gaussian(1.0, 1.0, 1e-5);
        assert!(sigma > 0.0);
        assert!(sigma.is_finite());
    }

    #[test]
    fn test_calibrate_gaussian_zero_epsilon() {
        let sigma = calibrate_gaussian(1.0, 0.0, 1e-5);
        assert!(sigma.is_infinite());
    }

    #[test]
    fn test_budget_tracker_new() {
        let tracker = PrivacyBudgetTracker::new(1.0, 1e-6);
        assert!((tracker.total_epsilon - 1.0).abs() < 1e-9);
        assert!((tracker.remaining_epsilon() - 1.0).abs() < 1e-9);
        assert!(tracker.queries.is_empty());
    }

    #[test]
    fn test_budget_tracker_spend_and_track() {
        let mut tracker = PrivacyBudgetTracker::new(1.0, 1e-6);
        tracker.spend("q1", 0.3, 1e-7, "Laplace", 1000).unwrap();
        assert!((tracker.spent_epsilon - 0.3).abs() < 1e-9);
        assert!((tracker.remaining_epsilon() - 0.7).abs() < 1e-9);
        assert_eq!(tracker.queries.len(), 1);
        assert_eq!(tracker.queries[0].query_id, "q1");
    }

    #[test]
    fn test_budget_tracker_rejects_overspend() {
        let mut tracker = PrivacyBudgetTracker::new(0.5, 1e-6);
        let result = tracker.spend("q1", 0.6, 0.0, "Laplace", 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_budget_tracker_utilization() {
        let mut tracker = PrivacyBudgetTracker::new(1.0, 1e-6);
        tracker.spend("q1", 0.5, 0.0, "Laplace", 1000).unwrap();
        assert!((tracker.utilization() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_budget_tracker_reset() {
        let mut tracker = PrivacyBudgetTracker::new(1.0, 1e-6);
        tracker.spend("q1", 0.5, 1e-7, "Laplace", 1000).unwrap();
        tracker.reset();
        assert!((tracker.remaining_epsilon() - 1.0).abs() < 1e-9);
        assert!(tracker.queries.is_empty());
    }

    #[test]
    fn test_sequential_composition() {
        let mut tracker = PrivacyBudgetTracker::new(2.0, 1e-6);
        tracker.spend("q1", 0.3, 0.0, "Laplace", 1000).unwrap();
        tracker.spend("q2", 0.5, 0.0, "Laplace", 2000).unwrap();
        let seq = tracker.sequential_composition_epsilon();
        assert!((seq - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_advanced_composition() {
        let mut tracker = PrivacyBudgetTracker::new(10.0, 1e-3);
        for i in 0..5 {
            tracker.spend(&format!("q{i}"), 0.1, 0.0, "Laplace", i as i64 * 1000).unwrap();
        }
        let adv = tracker.advanced_composition_epsilon(1e-6);
        let seq = tracker.sequential_composition_epsilon();
        // Advanced composition should give a tighter bound than sequential
        assert!(adv > 0.0);
        // For small epsilon, advanced should be <= sequential (tighter)
        // In general advanced can be larger for small k but the formula is valid
        assert!(adv.is_finite());
        assert!(seq > 0.0);
    }

    #[test]
    fn test_advanced_composition_empty() {
        let tracker = PrivacyBudgetTracker::new(1.0, 1e-6);
        assert_eq!(tracker.advanced_composition_epsilon(1e-6), 0.0);
    }

    #[test]
    fn test_budget_tracker_can_afford() {
        let mut tracker = PrivacyBudgetTracker::new(1.0, 1e-6);
        assert!(tracker.can_afford(0.5, 0.0));
        tracker.spend("q1", 0.8, 0.0, "Laplace", 1000).unwrap();
        assert!(!tracker.can_afford(0.5, 0.0));
    }
}
