// ═══════════════════════════════════════════════════════════════════════
// Anomaly Detection — statistical outlier detection
//
// Z-score, IQR, and moving average methods. Maintains a ring-buffer
// history of observed values as the baseline.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── AnomalyMethod ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyMethod {
    ZScore,
    Iqr,
    MovingAverage,
    Combined,
}

impl fmt::Display for AnomalyMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AnomalyResult ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub anomalous: bool,
    pub score: f64,
    pub method: AnomalyMethod,
    pub value: f64,
    pub threshold: f64,
    pub baseline_mean: f64,
    pub baseline_std_dev: f64,
    pub detail: String,
}

impl AnomalyResult {
    fn normal(value: f64, method: AnomalyMethod, mean: f64, std_dev: f64, threshold: f64) -> Self {
        Self {
            anomalous: false,
            score: 0.0,
            method,
            value,
            threshold,
            baseline_mean: mean,
            baseline_std_dev: std_dev,
            detail: "within baseline".into(),
        }
    }
}

// ── AnomalyDetector ───────────────────────────────────────────────────

pub struct AnomalyDetector {
    pub history: Vec<f64>,
    pub window_size: usize,
    pub z_score_threshold: f64,
    pub iqr_multiplier: f64,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            window_size: 100,
            z_score_threshold: 3.0,
            iqr_multiplier: 1.5,
        }
    }

    pub fn with_config(window_size: usize, z_threshold: f64, iqr_multiplier: f64) -> Self {
        Self {
            history: Vec::new(),
            window_size,
            z_score_threshold: z_threshold,
            iqr_multiplier,
        }
    }

    pub fn observe(&mut self, value: f64) {
        self.history.push(value);
        if self.history.len() > self.window_size {
            self.history.remove(0);
        }
    }

    pub fn mean(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }
        self.history.iter().sum::<f64>() / self.history.len() as f64
    }

    pub fn std_dev(&self) -> f64 {
        if self.history.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self.history.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
            / self.history.len() as f64;
        variance.sqrt()
    }

    /// Returns the value at the given percentile (0.0–1.0) of history.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.history.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p = p.clamp(0.0, 1.0);
        let idx = (p * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx]
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    pub fn detect_zscore(&self, value: f64) -> AnomalyResult {
        let mean = self.mean();
        let sd = self.std_dev();
        if self.history.len() < 2 || sd == 0.0 {
            return AnomalyResult::normal(value, AnomalyMethod::ZScore, mean, sd, self.z_score_threshold);
        }
        let z = (value - mean) / sd;
        let abs_z = z.abs();
        let anomalous = abs_z > self.z_score_threshold;
        AnomalyResult {
            anomalous,
            score: abs_z,
            method: AnomalyMethod::ZScore,
            value,
            threshold: self.z_score_threshold,
            baseline_mean: mean,
            baseline_std_dev: sd,
            detail: format!("z-score={z:.3} (|z|={abs_z:.3})"),
        }
    }

    pub fn detect_iqr(&self, value: f64) -> AnomalyResult {
        let mean = self.mean();
        let sd = self.std_dev();
        if self.history.len() < 4 {
            return AnomalyResult::normal(value, AnomalyMethod::Iqr, mean, sd, self.iqr_multiplier);
        }
        let q1 = self.percentile(0.25);
        let q3 = self.percentile(0.75);
        let iqr = q3 - q1;
        let lower = q1 - self.iqr_multiplier * iqr;
        let upper = q3 + self.iqr_multiplier * iqr;
        let anomalous = value < lower || value > upper;
        let score = if iqr > 0.0 {
            if value < lower {
                (lower - value) / iqr
            } else if value > upper {
                (value - upper) / iqr
            } else {
                0.0
            }
        } else {
            0.0
        };
        AnomalyResult {
            anomalous,
            score,
            method: AnomalyMethod::Iqr,
            value,
            threshold: self.iqr_multiplier,
            baseline_mean: mean,
            baseline_std_dev: sd,
            detail: format!("Q1={q1:.3} Q3={q3:.3} fence=[{lower:.3}, {upper:.3}]"),
        }
    }

    pub fn detect_moving_average(
        &self,
        value: f64,
        short_window: usize,
        long_window: usize,
    ) -> AnomalyResult {
        let mean = self.mean();
        let sd = self.std_dev();
        if self.history.len() < long_window.max(short_window) {
            return AnomalyResult::normal(
                value,
                AnomalyMethod::MovingAverage,
                mean,
                sd,
                self.z_score_threshold,
            );
        }
        let short_slice = &self.history[self.history.len() - short_window..];
        let long_slice = &self.history[self.history.len() - long_window..];
        let short_ma: f64 = short_slice.iter().sum::<f64>() / short_window as f64;
        let long_ma: f64 = long_slice.iter().sum::<f64>() / long_window as f64;
        let deviation = if long_ma.abs() > f64::EPSILON {
            (value - short_ma).abs() / long_ma.abs()
        } else {
            (value - short_ma).abs()
        };
        let threshold = 0.5;
        let anomalous = deviation > threshold;
        AnomalyResult {
            anomalous,
            score: deviation,
            method: AnomalyMethod::MovingAverage,
            value,
            threshold,
            baseline_mean: mean,
            baseline_std_dev: sd,
            detail: format!("short_ma={short_ma:.3} long_ma={long_ma:.3} dev={deviation:.3}"),
        }
    }

    /// Runs all three methods and returns the most severe anomalous result
    /// (or a normal combined result if none triggered).
    pub fn detect(&self, value: f64) -> AnomalyResult {
        let z = self.detect_zscore(value);
        let iqr = self.detect_iqr(value);
        let short = 5usize.min(self.history.len().max(1));
        let long = 20usize.min(self.history.len().max(1));
        let ma = self.detect_moving_average(value, short, long);

        let results = [z, iqr, ma];
        let any_anomalous = results.iter().any(|r| r.anomalous);
        let most_severe = results
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
            .unwrap();

        AnomalyResult {
            anomalous: any_anomalous,
            score: most_severe.score,
            method: AnomalyMethod::Combined,
            value,
            threshold: most_severe.threshold,
            baseline_mean: most_severe.baseline_mean,
            baseline_std_dev: most_severe.baseline_std_dev,
            detail: format!("most severe: {} ({})", most_severe.method, most_severe.detail),
        }
    }
}

// ── StatisticalDetector (Layer 2) ─────────────────────────────────────
//
// Production-grade online statistical detector using Welford's algorithm
// for running mean/variance, with sliding window, z-score, IQR, and
// percentile detection. Unlike AnomalyDetector which recomputes from
// history on every query, StatisticalDetector maintains running stats
// incrementally.

pub struct StatisticalDetector {
    window: Vec<f64>,
    pub window_size: usize,
    running_mean: f64,
    running_m2: f64,
    count: u64,
    pub min_observations: usize,
    pub z_score_threshold: f64,
    pub iqr_multiplier: f64,
}

impl Default for StatisticalDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StatisticalDetector {
    pub fn new() -> Self {
        Self {
            window: Vec::new(),
            window_size: 1000,
            running_mean: 0.0,
            running_m2: 0.0,
            count: 0,
            min_observations: 30,
            z_score_threshold: 3.0,
            iqr_multiplier: 1.5,
        }
    }

    pub fn with_config(
        window_size: usize,
        min_observations: usize,
        z_score_threshold: f64,
        iqr_multiplier: f64,
    ) -> Self {
        Self {
            window: Vec::new(),
            window_size,
            running_mean: 0.0,
            running_m2: 0.0,
            count: 0,
            min_observations,
            z_score_threshold,
            iqr_multiplier,
        }
    }

    /// Observe a new value using Welford's online algorithm and sliding window.
    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.running_mean;
        self.running_mean += delta / self.count as f64;
        let delta2 = value - self.running_mean;
        self.running_m2 += delta * delta2;

        self.window.push(value);
        if self.window.len() > self.window_size {
            self.window.remove(0);
        }
    }

    pub fn mean(&self) -> f64 {
        self.running_mean
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.running_m2 / self.count as f64
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    pub fn has_sufficient_data(&self) -> bool {
        self.count >= self.min_observations as u64
    }

    pub fn z_score(&self, value: f64) -> f64 {
        let sd = self.std_dev();
        if sd == 0.0 {
            return 0.0;
        }
        (value - self.running_mean) / sd
    }

    pub fn percentile(&self, p: f64) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.window.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p = p.clamp(0.0, 1.0);
        let idx = (p * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx]
    }

    pub fn detect_zscore(&self, value: f64) -> AnomalyResult {
        let mean = self.running_mean;
        let sd = self.std_dev();
        if !self.has_sufficient_data() || sd == 0.0 {
            return AnomalyResult::normal(value, AnomalyMethod::ZScore, mean, sd, self.z_score_threshold);
        }
        let z = (value - mean) / sd;
        let abs_z = z.abs();
        let anomalous = abs_z > self.z_score_threshold;
        AnomalyResult {
            anomalous,
            score: abs_z,
            method: AnomalyMethod::ZScore,
            value,
            threshold: self.z_score_threshold,
            baseline_mean: mean,
            baseline_std_dev: sd,
            detail: format!("z-score={z:.3} (|z|={abs_z:.3})"),
        }
    }

    pub fn detect_iqr(&self, value: f64) -> AnomalyResult {
        let mean = self.running_mean;
        let sd = self.std_dev();
        if self.window.len() < 4 || !self.has_sufficient_data() {
            return AnomalyResult::normal(value, AnomalyMethod::Iqr, mean, sd, self.iqr_multiplier);
        }
        let q1 = self.percentile(0.25);
        let q3 = self.percentile(0.75);
        let iqr = q3 - q1;
        let lower = q1 - self.iqr_multiplier * iqr;
        let upper = q3 + self.iqr_multiplier * iqr;
        let anomalous = value < lower || value > upper;
        let score = if iqr > 0.0 {
            if value < lower {
                (lower - value) / iqr
            } else if value > upper {
                (value - upper) / iqr
            } else {
                0.0
            }
        } else {
            0.0
        };
        AnomalyResult {
            anomalous,
            score,
            method: AnomalyMethod::Iqr,
            value,
            threshold: self.iqr_multiplier,
            baseline_mean: mean,
            baseline_std_dev: sd,
            detail: format!("Q1={q1:.3} Q3={q3:.3} fence=[{lower:.3}, {upper:.3}]"),
        }
    }

    /// Combined detection: returns most severe result from z-score and IQR.
    pub fn detect(&self, value: f64) -> AnomalyResult {
        let z = self.detect_zscore(value);
        let iqr = self.detect_iqr(value);
        let any_anomalous = z.anomalous || iqr.anomalous;
        let most_severe = if z.score >= iqr.score { &z } else { &iqr };
        AnomalyResult {
            anomalous: any_anomalous,
            score: most_severe.score,
            method: AnomalyMethod::Combined,
            value,
            threshold: most_severe.threshold,
            baseline_mean: most_severe.baseline_mean,
            baseline_std_dev: most_severe.baseline_std_dev,
            detail: format!("most severe: {} ({})", most_severe.method, most_severe.detail),
        }
    }
}

impl fmt::Debug for StatisticalDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatisticalDetector")
            .field("count", &self.count)
            .field("mean", &self.running_mean)
            .field("std_dev", &self.std_dev())
            .field("window_len", &self.window.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(detector: &mut AnomalyDetector, values: &[f64]) {
        for v in values {
            detector.observe(*v);
        }
    }

    #[test]
    fn test_default_config() {
        let d = AnomalyDetector::new();
        assert_eq!(d.window_size, 100);
        assert_eq!(d.z_score_threshold, 3.0);
        assert_eq!(d.iqr_multiplier, 1.5);
    }

    #[test]
    fn test_observe_fills_history() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[1.0, 2.0, 3.0]);
        assert_eq!(d.history_len(), 3);
    }

    #[test]
    fn test_observe_respects_window() {
        let mut d = AnomalyDetector::with_config(3, 3.0, 1.5);
        feed(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert_eq!(d.history_len(), 3);
        assert_eq!(d.history, vec![3.0, 4.0, 5.0]);
    }

    #[test]
    fn test_detect_zscore_outlier() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1]);
        let r = d.detect_zscore(50.0);
        assert!(r.anomalous);
        assert!(r.score > 3.0);
    }

    #[test]
    fn test_detect_zscore_normal() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1]);
        let r = d.detect_zscore(10.05);
        assert!(!r.anomalous);
    }

    #[test]
    fn test_detect_zscore_stable_data_low_score() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[5.0; 20]);
        // No variance — detector returns normal.
        let r = d.detect_zscore(5.0);
        assert!(!r.anomalous);
    }

    #[test]
    fn test_detect_iqr_outlier_above() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
        let r = d.detect_iqr(100.0);
        assert!(r.anomalous);
    }

    #[test]
    fn test_detect_iqr_outlier_below() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 17.0]);
        let r = d.detect_iqr(-50.0);
        assert!(r.anomalous);
    }

    #[test]
    fn test_detect_iqr_normal() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
        let r = d.detect_iqr(4.5);
        assert!(!r.anomalous);
    }

    #[test]
    fn test_detect_moving_average_deviation() {
        let mut d = AnomalyDetector::new();
        feed(
            &mut d,
            &[
                10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0,
                10.0, 10.0, 10.0, 10.0, 10.0, 10.0,
            ],
        );
        let r = d.detect_moving_average(50.0, 5, 20);
        assert!(r.anomalous);
    }

    #[test]
    fn test_detect_combined_returns_worst() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.1]);
        let r = d.detect(100.0);
        assert!(r.anomalous);
        assert_eq!(r.method, AnomalyMethod::Combined);
    }

    #[test]
    fn test_mean_calculates_correctly() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert_eq!(d.mean(), 3.0);
    }

    #[test]
    fn test_std_dev_calculates_correctly() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        // population std dev = 2.0
        assert!((d.std_dev() - 2.0).abs() < 0.0001);
    }

    #[test]
    fn test_percentile() {
        let mut d = AnomalyDetector::new();
        feed(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]);
        assert_eq!(d.percentile(0.5), 5.0);
    }

    #[test]
    fn test_empty_history_non_anomalous() {
        let d = AnomalyDetector::new();
        let r = d.detect_zscore(100.0);
        assert!(!r.anomalous);
        let r = d.detect_iqr(100.0);
        assert!(!r.anomalous);
    }

    // ── Layer 2: StatisticalDetector tests ──────────────────────────────

    fn feed_stat(d: &mut StatisticalDetector, values: &[f64]) {
        for v in values {
            d.observe(*v);
        }
    }

    #[test]
    fn test_statistical_detector_default() {
        let d = StatisticalDetector::new();
        assert_eq!(d.window_size, 1000);
        assert_eq!(d.min_observations, 30);
        assert_eq!(d.z_score_threshold, 3.0);
        assert_eq!(d.count(), 0);
    }

    #[test]
    fn test_statistical_detector_welford_mean() {
        let mut d = StatisticalDetector::new();
        feed_stat(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert!((d.mean() - 3.0).abs() < 0.0001);
    }

    #[test]
    fn test_statistical_detector_welford_std_dev() {
        let mut d = StatisticalDetector::new();
        feed_stat(&mut d, &[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        // population std dev = 2.0
        assert!((d.std_dev() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_statistical_detector_insufficient_data() {
        let mut d = StatisticalDetector::new();
        feed_stat(&mut d, &[10.0, 10.1, 9.9]);
        assert!(!d.has_sufficient_data());
        let r = d.detect_zscore(100.0);
        assert!(!r.anomalous); // gated by min_observations
    }

    #[test]
    fn test_statistical_detector_zscore_outlier() {
        let mut d = StatisticalDetector::with_config(1000, 10, 3.0, 1.5);
        let values: Vec<f64> = (0..50).map(|i| 10.0 + (i as f64 * 0.01)).collect();
        feed_stat(&mut d, &values);
        let r = d.detect_zscore(100.0);
        assert!(r.anomalous);
        assert!(r.score > 3.0);
    }

    #[test]
    fn test_statistical_detector_zscore_normal() {
        let mut d = StatisticalDetector::with_config(1000, 10, 3.0, 1.5);
        let values: Vec<f64> = (0..50).map(|i| 10.0 + (i as f64 * 0.01)).collect();
        feed_stat(&mut d, &values);
        let r = d.detect_zscore(10.25);
        assert!(!r.anomalous);
    }

    #[test]
    fn test_statistical_detector_iqr_outlier() {
        let mut d = StatisticalDetector::with_config(1000, 5, 3.0, 1.5);
        feed_stat(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0,
                             1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0,
                             1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0,
                             1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let r = d.detect_iqr(100.0);
        assert!(r.anomalous);
    }

    #[test]
    fn test_statistical_detector_percentile() {
        let mut d = StatisticalDetector::new();
        feed_stat(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]);
        assert_eq!(d.percentile(0.5), 5.0);
    }

    #[test]
    fn test_statistical_detector_combined() {
        let mut d = StatisticalDetector::with_config(1000, 10, 3.0, 1.5);
        let values: Vec<f64> = (0..50).map(|i| 10.0 + (i as f64 * 0.01)).collect();
        feed_stat(&mut d, &values);
        let r = d.detect(100.0);
        assert!(r.anomalous);
        assert_eq!(r.method, AnomalyMethod::Combined);
    }

    #[test]
    fn test_statistical_detector_window_trimming() {
        let mut d = StatisticalDetector::with_config(5, 3, 3.0, 1.5);
        feed_stat(&mut d, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
        assert_eq!(d.window_len(), 5);
        assert_eq!(d.count(), 7);
    }

    #[test]
    fn test_statistical_detector_z_score_method() {
        let mut d = StatisticalDetector::with_config(1000, 5, 3.0, 1.5);
        feed_stat(&mut d, &[10.0, 10.0, 10.0, 10.0, 10.0, 10.1, 9.9, 10.0, 10.0, 10.0]);
        let z = d.z_score(10.0);
        assert!(z.abs() < 1.0);
    }
}
