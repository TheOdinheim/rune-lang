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

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: BehavioralBaseline
//
// Per-metric baselines with configurable sensitivity thresholds and
// normal range overrides. Uses the existing MetricBaseline (Welford's)
// for online statistics, adding anomaly classification per metric.
// ═══════════════════════════════════════════════════════════════════════

// ── NormalRange ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NormalRange {
    pub min: f64,
    pub max: f64,
}

impl NormalRange {
    pub fn contains(&self, value: f64) -> bool {
        value >= self.min && value <= self.max
    }
}

// ── MetricConfig ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricConfig {
    pub sensitivity: f64,
    pub normal_range: Option<NormalRange>,
}

impl Default for MetricConfig {
    fn default() -> Self {
        Self {
            sensitivity: 1.0,
            normal_range: None,
        }
    }
}

// ── MetricStats ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub count: u64,
    pub last_updated: i64,
}

// ── BehavioralBaseline ───────────────────────────────────────────────

pub struct BehavioralBaseline {
    metrics: HashMap<String, MetricBaseline>,
    configs: HashMap<String, MetricConfig>,
    pub default_sensitivity: f64,
    pub deviation_threshold: f64,
    pub min_observations: u64,
}

impl Default for BehavioralBaseline {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralBaseline {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            configs: HashMap::new(),
            default_sensitivity: 1.0,
            deviation_threshold: 2.0,
            min_observations: 10,
        }
    }

    pub fn with_sensitivity(sensitivity: f64) -> Self {
        Self {
            metrics: HashMap::new(),
            configs: HashMap::new(),
            default_sensitivity: sensitivity,
            deviation_threshold: 2.0,
            min_observations: 10,
        }
    }

    pub fn configure_metric(&mut self, name: &str, config: MetricConfig) {
        self.configs.insert(name.into(), config);
    }

    pub fn observe(&mut self, metric: &str, value: f64, timestamp: i64) {
        let baseline = self
            .metrics
            .entry(metric.into())
            .or_insert_with(|| MetricBaseline::new(metric));
        baseline.update(value, timestamp);
    }

    pub fn is_anomalous(&self, metric: &str, value: f64) -> bool {
        let baseline = match self.metrics.get(metric) {
            Some(b) => b,
            None => return false,
        };
        if baseline.sample_count < self.min_observations {
            return false;
        }
        let config = self.configs.get(metric);
        // Check normal range override first
        if let Some(cfg) = config {
            if let Some(ref range) = cfg.normal_range {
                return !range.contains(value);
            }
        }
        let sensitivity = config.map(|c| c.sensitivity).unwrap_or(self.default_sensitivity);
        let effective_threshold = self.deviation_threshold / sensitivity;
        let sd = baseline.std_dev;
        if sd == 0.0 {
            return (value - baseline.mean).abs() > 0.0;
        }
        let z = ((value - baseline.mean) / sd).abs();
        z > effective_threshold
    }

    pub fn anomalous_metrics(&self, observations: &[(&str, f64)]) -> Vec<String> {
        observations
            .iter()
            .filter(|(name, val)| self.is_anomalous(name, *val))
            .map(|(name, _)| (*name).to_string())
            .collect()
    }

    pub fn metric_stats(&self, name: &str) -> Option<MetricStats> {
        self.metrics.get(name).map(|b| MetricStats {
            mean: b.mean,
            std_dev: b.std_dev,
            min: b.min_observed,
            max: b.max_observed,
            count: b.sample_count,
            last_updated: b.last_updated,
        })
    }

    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }

    pub fn has_sufficient_data(&self, metric: &str) -> bool {
        self.metrics
            .get(metric)
            .map(|b| b.sample_count >= self.min_observations)
            .unwrap_or(false)
    }
}

impl fmt::Debug for BehavioralBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BehavioralBaseline")
            .field("metric_count", &self.metrics.len())
            .field("default_sensitivity", &self.default_sensitivity)
            .finish()
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

    // ── Layer 2: BehavioralBaseline tests ───────────────────────────────

    #[test]
    fn test_behavioral_baseline_observe_and_stats() {
        let mut b = BehavioralBaseline::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            b.observe("latency", v, 100);
        }
        let stats = b.metric_stats("latency").unwrap();
        assert!((stats.mean - 3.0).abs() < 0.001);
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 5.0);
    }

    #[test]
    fn test_behavioral_baseline_anomalous() {
        let mut b = BehavioralBaseline::new();
        b.min_observations = 5;
        for v in [10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1] {
            b.observe("req_rate", v, 100);
        }
        assert!(!b.is_anomalous("req_rate", 10.05));
        assert!(b.is_anomalous("req_rate", 100.0));
    }

    #[test]
    fn test_behavioral_baseline_insufficient_data() {
        let mut b = BehavioralBaseline::new();
        b.observe("m", 1.0, 0);
        b.observe("m", 2.0, 0);
        assert!(!b.is_anomalous("m", 100.0)); // insufficient data returns false
    }

    #[test]
    fn test_behavioral_baseline_normal_range_override() {
        let mut b = BehavioralBaseline::new();
        b.min_observations = 3;
        for v in [50.0, 51.0, 49.0, 50.5, 50.0] {
            b.observe("temp", v, 0);
        }
        b.configure_metric("temp", MetricConfig {
            sensitivity: 1.0,
            normal_range: Some(NormalRange { min: 0.0, max: 100.0 }),
        });
        assert!(!b.is_anomalous("temp", 99.0));
        assert!(b.is_anomalous("temp", 101.0));
    }

    #[test]
    fn test_behavioral_baseline_sensitivity() {
        let mut b = BehavioralBaseline::new();
        b.min_observations = 5;
        for v in [10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1] {
            b.observe("m", v, 0);
        }
        // Default sensitivity=1.0: deviation_threshold=2.0
        let val = 10.5; // moderate deviation
        let normal_result = b.is_anomalous("m", val);
        // Higher sensitivity=2.0: effective_threshold=1.0 — more sensitive
        b.configure_metric("m", MetricConfig {
            sensitivity: 2.0,
            normal_range: None,
        });
        let sensitive_result = b.is_anomalous("m", val);
        // Higher sensitivity should detect more anomalies
        assert!(sensitive_result || !normal_result);
    }

    #[test]
    fn test_behavioral_baseline_anomalous_metrics() {
        let mut b = BehavioralBaseline::new();
        b.min_observations = 5;
        for v in [10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1] {
            b.observe("m1", v, 0);
            b.observe("m2", v * 2.0, 0);
        }
        let anomalous = b.anomalous_metrics(&[("m1", 100.0), ("m2", 20.0)]);
        assert!(anomalous.contains(&"m1".to_string()));
    }

    #[test]
    fn test_behavioral_baseline_metric_count() {
        let mut b = BehavioralBaseline::new();
        b.observe("a", 1.0, 0);
        b.observe("b", 2.0, 0);
        b.observe("c", 3.0, 0);
        assert_eq!(b.metric_count(), 3);
    }

    #[test]
    fn test_behavioral_baseline_has_sufficient_data() {
        let mut b = BehavioralBaseline::new();
        b.min_observations = 5;
        assert!(!b.has_sufficient_data("m"));
        for i in 0..5 {
            b.observe("m", i as f64, 0);
        }
        assert!(b.has_sufficient_data("m"));
    }

    #[test]
    fn test_behavioral_baseline_unknown_metric() {
        let b = BehavioralBaseline::new();
        assert!(!b.is_anomalous("nonexistent", 42.0));
        assert!(b.metric_stats("nonexistent").is_none());
    }
}
