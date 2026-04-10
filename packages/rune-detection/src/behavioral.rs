// ═══════════════════════════════════════════════════════════════════════
// Behavioral Analysis — baseline establishment and deviation detection
//
// Online mean/variance updates via Welford's algorithm. Per-profile,
// per-metric baselines. Deviation is reported as z-score against the
// established baseline once enough observations have accumulated.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── MetricBaseline ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricBaseline {
    pub name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub min_observed: f64,
    pub max_observed: f64,
    pub sample_count: u64,
    pub last_updated: i64,
    pub(crate) m2: f64,
}

impl MetricBaseline {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            mean: 0.0,
            std_dev: 0.0,
            min_observed: f64::INFINITY,
            max_observed: f64::NEG_INFINITY,
            sample_count: 0,
            last_updated: 0,
            m2: 0.0,
        }
    }

    fn update(&mut self, value: f64, timestamp: i64) {
        self.sample_count += 1;
        let count = self.sample_count as f64;
        let delta = value - self.mean;
        self.mean += delta / count;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.std_dev = (self.m2 / count).sqrt();
        if value < self.min_observed {
            self.min_observed = value;
        }
        if value > self.max_observed {
            self.max_observed = value;
        }
        self.last_updated = timestamp;
    }
}

// ── BehaviorProfile ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    pub id: String,
    pub metrics: HashMap<String, MetricBaseline>,
    pub observation_count: u64,
    pub first_observed: i64,
    pub last_observed: i64,
}

impl BehaviorProfile {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.into(),
            metrics: HashMap::new(),
            observation_count: 0,
            first_observed: 0,
            last_observed: 0,
        }
    }
}

// ── BehaviorStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorStatus {
    Normal,
    Deviation,
    Unknown,
}

impl fmt::Display for BehaviorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── BehaviorResult ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorResult {
    pub status: BehaviorStatus,
    pub profile_id: String,
    pub metric_name: String,
    pub value: f64,
    pub baseline_mean: f64,
    pub baseline_std_dev: f64,
    pub deviation_score: f64,
    pub detail: String,
}

// ── BehaviorAnalyzer ──────────────────────────────────────────────────

pub struct BehaviorAnalyzer {
    pub profiles: HashMap<String, BehaviorProfile>,
    pub deviation_threshold: f64,
    pub min_observations: u64,
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            deviation_threshold: 2.0,
            min_observations: 10,
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            profiles: HashMap::new(),
            deviation_threshold: threshold,
            min_observations: 10,
        }
    }

    pub fn observe(&mut self, profile_id: &str, metric_name: &str, value: f64, timestamp: i64) {
        let profile = self
            .profiles
            .entry(profile_id.into())
            .or_insert_with(|| BehaviorProfile::new(profile_id));
        if profile.observation_count == 0 {
            profile.first_observed = timestamp;
        }
        profile.observation_count += 1;
        profile.last_observed = timestamp;
        let baseline = profile
            .metrics
            .entry(metric_name.into())
            .or_insert_with(|| MetricBaseline::new(metric_name));
        baseline.update(value, timestamp);
    }

    pub fn analyze(&self, profile_id: &str, metric_name: &str, value: f64) -> BehaviorResult {
        let profile = match self.profiles.get(profile_id) {
            Some(p) => p,
            None => {
                return BehaviorResult {
                    status: BehaviorStatus::Unknown,
                    profile_id: profile_id.into(),
                    metric_name: metric_name.into(),
                    value,
                    baseline_mean: 0.0,
                    baseline_std_dev: 0.0,
                    deviation_score: 0.0,
                    detail: "no profile".into(),
                };
            }
        };
        if profile.observation_count < self.min_observations {
            return BehaviorResult {
                status: BehaviorStatus::Unknown,
                profile_id: profile_id.into(),
                metric_name: metric_name.into(),
                value,
                baseline_mean: 0.0,
                baseline_std_dev: 0.0,
                deviation_score: 0.0,
                detail: format!(
                    "insufficient observations ({}/{})",
                    profile.observation_count, self.min_observations
                ),
            };
        }
        let baseline = match profile.metrics.get(metric_name) {
            Some(b) => b,
            None => {
                return BehaviorResult {
                    status: BehaviorStatus::Unknown,
                    profile_id: profile_id.into(),
                    metric_name: metric_name.into(),
                    value,
                    baseline_mean: 0.0,
                    baseline_std_dev: 0.0,
                    deviation_score: 0.0,
                    detail: "metric not tracked".into(),
                };
            }
        };
        let sd = baseline.std_dev;
        if sd == 0.0 {
            let anomalous = (value - baseline.mean).abs() > 0.0;
            return BehaviorResult {
                status: if anomalous {
                    BehaviorStatus::Deviation
                } else {
                    BehaviorStatus::Normal
                },
                profile_id: profile_id.into(),
                metric_name: metric_name.into(),
                value,
                baseline_mean: baseline.mean,
                baseline_std_dev: 0.0,
                deviation_score: if anomalous { f64::INFINITY } else { 0.0 },
                detail: "zero variance baseline".into(),
            };
        }
        let z = (value - baseline.mean) / sd;
        let abs_z = z.abs();
        let status = if abs_z > self.deviation_threshold {
            BehaviorStatus::Deviation
        } else {
            BehaviorStatus::Normal
        };
        BehaviorResult {
            status,
            profile_id: profile_id.into(),
            metric_name: metric_name.into(),
            value,
            baseline_mean: baseline.mean,
            baseline_std_dev: sd,
            deviation_score: abs_z,
            detail: format!("z={z:.3}"),
        }
    }

    pub fn analyze_batch(
        &self,
        profile_id: &str,
        observations: &[(&str, f64)],
    ) -> Vec<BehaviorResult> {
        observations
            .iter()
            .map(|(name, v)| self.analyze(profile_id, name, *v))
            .collect()
    }

    pub fn get_profile(&self, id: &str) -> Option<&BehaviorProfile> {
        self.profiles.get(id)
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_baseline_stable(&self, profile_id: &str) -> bool {
        self.profiles
            .get(profile_id)
            .map(|p| p.observation_count >= self.min_observations)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observe_creates_profile() {
        let mut a = BehaviorAnalyzer::new();
        a.observe("user:alice", "req_rate", 1.0, 100);
        assert_eq!(a.profile_count(), 1);
        assert!(a.get_profile("user:alice").is_some());
    }

    #[test]
    fn test_observe_updates_baseline() {
        let mut a = BehaviorAnalyzer::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            a.observe("user:alice", "req_rate", v, 100);
        }
        let p = a.get_profile("user:alice").unwrap();
        let b = p.metrics.get("req_rate").unwrap();
        assert!((b.mean - 3.0).abs() < 0.001);
        assert!(b.std_dev > 0.0);
    }

    #[test]
    fn test_analyze_normal() {
        let mut a = BehaviorAnalyzer::new();
        for _ in 0..15 {
            a.observe("u", "m", 10.0, 100);
        }
        // Break zero-variance: add tiny noise
        for v in [10.1, 9.9, 10.05, 9.95] {
            a.observe("u", "m", v, 200);
        }
        let r = a.analyze("u", "m", 10.02);
        assert_eq!(r.status, BehaviorStatus::Normal);
    }

    #[test]
    fn test_analyze_deviation() {
        let mut a = BehaviorAnalyzer::new();
        for v in [
            10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1, 10.0, 10.0,
        ] {
            a.observe("u", "m", v, 100);
        }
        let r = a.analyze("u", "m", 100.0);
        assert_eq!(r.status, BehaviorStatus::Deviation);
        assert!(r.deviation_score > 2.0);
    }

    #[test]
    fn test_analyze_unknown_no_profile() {
        let a = BehaviorAnalyzer::new();
        let r = a.analyze("missing", "m", 1.0);
        assert_eq!(r.status, BehaviorStatus::Unknown);
    }

    #[test]
    fn test_analyze_unknown_insufficient_observations() {
        let mut a = BehaviorAnalyzer::new();
        a.observe("u", "m", 1.0, 100);
        a.observe("u", "m", 2.0, 100);
        let r = a.analyze("u", "m", 100.0);
        assert_eq!(r.status, BehaviorStatus::Unknown);
    }

    #[test]
    fn test_welford_algorithm_correct_mean_std() {
        let mut a = BehaviorAnalyzer::new();
        // Values [2,4,4,4,5,5,7,9] — population mean=5, population std=2
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            a.observe("u", "m", v, 0);
        }
        let b = a.get_profile("u").unwrap().metrics.get("m").unwrap();
        assert!((b.mean - 5.0).abs() < 0.001);
        assert!((b.std_dev - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_multiple_metrics_tracked() {
        let mut a = BehaviorAnalyzer::new();
        a.observe("u", "m1", 1.0, 0);
        a.observe("u", "m2", 100.0, 0);
        let p = a.get_profile("u").unwrap();
        assert_eq!(p.metrics.len(), 2);
    }

    #[test]
    fn test_is_baseline_stable() {
        let mut a = BehaviorAnalyzer::new();
        assert!(!a.is_baseline_stable("u"));
        for _ in 0..15 {
            a.observe("u", "m", 1.0, 0);
        }
        assert!(a.is_baseline_stable("u"));
    }
}
