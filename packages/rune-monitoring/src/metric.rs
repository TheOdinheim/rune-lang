// ═══════════════════════════════════════════════════════════════════════
// Metric — time-series metric registry with percentiles, rate, trend.
//
// MonitoringMetric is the monitoring-layer metric, distinct from
// rune-security's SecurityMetric so that monitoring can track arbitrary
// operational values (latency histograms, queue depths, etc.) without
// constraining them to the security vocabulary. MetricType is re-declared
// here as MonitoringMetricType to avoid cross-crate confusion.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::{MonitoringError, MonitoringResult};

// ── MonitoringMetricType ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MonitoringMetricType {
    Counter,
    Gauge,
    Histogram,
    Timer,
    Rate,
}

impl fmt::Display for MonitoringMetricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Counter => f.write_str("counter"),
            Self::Gauge => f.write_str("gauge"),
            Self::Histogram => f.write_str("histogram"),
            Self::Timer => f.write_str("timer"),
            Self::Rate => f.write_str("rate"),
        }
    }
}

// ── MetricId ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetricId(pub String);

impl MetricId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for MetricId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── MonitoringMetric ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MonitoringMetric {
    pub id: MetricId,
    pub name: String,
    pub metric_type: MonitoringMetricType,
    pub unit: String,
    pub description: String,
    pub tags: HashMap<String, String>,
}

impl MonitoringMetric {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        metric_type: MonitoringMetricType,
        unit: impl Into<String>,
    ) -> Self {
        Self {
            id: MetricId::new(id),
            name: name.into(),
            metric_type,
            unit: unit.into(),
            description: String::new(),
            tags: HashMap::new(),
        }
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn with_tag(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.tags.insert(k.into(), v.into());
        self
    }
}

// ── MetricSample ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct MetricSample {
    pub value: f64,
    pub timestamp: i64,
}

// ── MonitoringTrend ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringTrend {
    Improving,
    Stable,
    Degrading,
    InsufficientData,
}

impl fmt::Display for MonitoringTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Improving => f.write_str("improving"),
            Self::Stable => f.write_str("stable"),
            Self::Degrading => f.write_str("degrading"),
            Self::InsufficientData => f.write_str("insufficient-data"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricTrendResult {
    pub trend: MonitoringTrend,
    pub first_half_avg: Option<f64>,
    pub second_half_avg: Option<f64>,
    pub delta: Option<f64>,
}

// ── MetricRegistry ────────────────────────────────────────────────────

#[derive(Default)]
pub struct MetricRegistry {
    pub metrics: HashMap<String, MonitoringMetric>,
    pub samples: HashMap<String, Vec<MetricSample>>,
    /// Metrics whose *lower* value is better (latency, error rate).
    pub lower_is_better: Vec<String>,
}

impl MetricRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, metric: MonitoringMetric) {
        let id = metric.id.0.clone();
        let lower = matches!(
            metric.metric_type,
            MonitoringMetricType::Timer | MonitoringMetricType::Histogram
        );
        if lower && !self.lower_is_better.contains(&id) {
            self.lower_is_better.push(id.clone());
        }
        self.metrics.insert(id, metric);
    }

    pub fn mark_lower_is_better(&mut self, id: &str) {
        if !self.lower_is_better.iter().any(|s| s == id) {
            self.lower_is_better.push(id.to_string());
        }
    }

    pub fn record(
        &mut self,
        id: &str,
        value: f64,
        timestamp: i64,
    ) -> MonitoringResult<()> {
        if !self.metrics.contains_key(id) {
            return Err(MonitoringError::MetricNotFound { id: id.into() });
        }
        if value.is_nan() || value.is_infinite() {
            return Err(MonitoringError::InvalidMetricValue {
                reason: format!("non-finite: {value}"),
            });
        }
        self.samples.entry(id.into()).or_default().push(MetricSample {
            value,
            timestamp,
        });
        Ok(())
    }

    pub fn latest(&self, id: &str) -> Option<f64> {
        self.samples.get(id).and_then(|v| v.last()).map(|s| s.value)
    }

    fn values(&self, id: &str) -> Vec<f64> {
        self.samples
            .get(id)
            .map(|v| v.iter().map(|s| s.value).collect())
            .unwrap_or_default()
    }

    pub fn count(&self, id: &str) -> usize {
        self.samples.get(id).map(|v| v.len()).unwrap_or(0)
    }

    pub fn sum(&self, id: &str) -> f64 {
        self.values(id).iter().sum()
    }

    pub fn average(&self, id: &str) -> Option<f64> {
        let v = self.values(id);
        if v.is_empty() {
            None
        } else {
            Some(v.iter().sum::<f64>() / v.len() as f64)
        }
    }

    pub fn max(&self, id: &str) -> Option<f64> {
        self.values(id).into_iter().fold(None, |acc, x| {
            Some(match acc {
                None => x,
                Some(a) => a.max(x),
            })
        })
    }

    pub fn min(&self, id: &str) -> Option<f64> {
        self.values(id).into_iter().fold(None, |acc, x| {
            Some(match acc {
                None => x,
                Some(a) => a.min(x),
            })
        })
    }

    /// Linear-interpolated percentile (0.0..=1.0) over all recorded samples.
    pub fn percentile(&self, id: &str, p: f64) -> Option<f64> {
        let mut v = self.values(id);
        if v.is_empty() {
            return None;
        }
        if !(0.0..=1.0).contains(&p) {
            return None;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        if v.len() == 1 {
            return Some(v[0]);
        }
        let rank = p * (v.len() - 1) as f64;
        let lo = rank.floor() as usize;
        let hi = rank.ceil() as usize;
        if lo == hi {
            Some(v[lo])
        } else {
            let frac = rank - lo as f64;
            Some(v[lo] + frac * (v[hi] - v[lo]))
        }
    }

    /// Samples per second across the observed window. Requires ≥ 2 samples.
    pub fn rate(&self, id: &str) -> Option<f64> {
        let samples = self.samples.get(id)?;
        if samples.len() < 2 {
            return None;
        }
        let first = samples.first()?.timestamp;
        let last = samples.last()?.timestamp;
        if last == first {
            return None;
        }
        let elapsed_secs = (last - first) as f64;
        Some((samples.len() - 1) as f64 / elapsed_secs)
    }

    /// Compare first half of samples with the second half. Returns the
    /// trend plus the two averages so callers can present the delta.
    pub fn trend(&self, id: &str) -> MetricTrendResult {
        let values = self.values(id);
        if values.len() < 4 {
            return MetricTrendResult {
                trend: MonitoringTrend::InsufficientData,
                first_half_avg: None,
                second_half_avg: None,
                delta: None,
            };
        }
        let mid = values.len() / 2;
        let first_avg: f64 = values[..mid].iter().sum::<f64>() / mid as f64;
        let second_avg: f64 =
            values[mid..].iter().sum::<f64>() / (values.len() - mid) as f64;
        let delta = second_avg - first_avg;
        let threshold = first_avg.abs() * 0.05;
        let trend = if delta.abs() < threshold {
            MonitoringTrend::Stable
        } else {
            let lower_is_better = self.lower_is_better.iter().any(|s| s == id);
            let improving = if lower_is_better {
                delta < 0.0
            } else {
                delta > 0.0
            };
            if improving {
                MonitoringTrend::Improving
            } else {
                MonitoringTrend::Degrading
            }
        };
        MetricTrendResult {
            trend,
            first_half_avg: Some(first_avg),
            second_half_avg: Some(second_avg),
            delta: Some(delta),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(id: &str, t: MonitoringMetricType) -> MonitoringMetric {
        MonitoringMetric::new(id, id, t, "unit")
    }

    #[test]
    fn test_register_and_record() {
        let mut r = MetricRegistry::new();
        r.register(mk("q", MonitoringMetricType::Gauge));
        r.record("q", 10.0, 1).unwrap();
        assert_eq!(r.latest("q"), Some(10.0));
    }

    #[test]
    fn test_record_unknown_errors() {
        let mut r = MetricRegistry::new();
        let err = r.record("nope", 1.0, 1).unwrap_err();
        assert!(matches!(err, MonitoringError::MetricNotFound { .. }));
    }

    #[test]
    fn test_record_rejects_nan() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Gauge));
        let err = r.record("g", f64::NAN, 1).unwrap_err();
        assert!(matches!(err, MonitoringError::InvalidMetricValue { .. }));
    }

    #[test]
    fn test_count_sum_avg_max_min() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Gauge));
        for (i, v) in [1.0, 2.0, 3.0, 4.0, 5.0].iter().enumerate() {
            r.record("g", *v, i as i64).unwrap();
        }
        assert_eq!(r.count("g"), 5);
        assert_eq!(r.sum("g"), 15.0);
        assert_eq!(r.average("g"), Some(3.0));
        assert_eq!(r.max("g"), Some(5.0));
        assert_eq!(r.min("g"), Some(1.0));
    }

    #[test]
    fn test_percentiles() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Histogram));
        for v in 1..=100 {
            r.record("g", v as f64, v as i64).unwrap();
        }
        let p50 = r.percentile("g", 0.5).unwrap();
        let p95 = r.percentile("g", 0.95).unwrap();
        let p99 = r.percentile("g", 0.99).unwrap();
        assert!((p50 - 50.5).abs() < 0.01);
        assert!(p95 > 90.0);
        assert!(p99 > p95);
    }

    #[test]
    fn test_percentile_single_sample() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Histogram));
        r.record("g", 7.0, 1).unwrap();
        assert_eq!(r.percentile("g", 0.5), Some(7.0));
    }

    #[test]
    fn test_percentile_invalid_range() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Histogram));
        r.record("g", 1.0, 1).unwrap();
        assert_eq!(r.percentile("g", 1.5), None);
    }

    #[test]
    fn test_rate_requires_two_samples_with_gap() {
        let mut r = MetricRegistry::new();
        r.register(mk("c", MonitoringMetricType::Counter));
        assert_eq!(r.rate("c"), None);
        r.record("c", 1.0, 0).unwrap();
        assert_eq!(r.rate("c"), None);
        r.record("c", 1.0, 10).unwrap();
        r.record("c", 1.0, 20).unwrap();
        let rate = r.rate("c").unwrap();
        assert!((rate - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_trend_improving_gauge_higher_is_better() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Gauge));
        for v in [10.0, 11.0, 50.0, 55.0] {
            r.record("g", v, 1).unwrap();
        }
        assert_eq!(r.trend("g").trend, MonitoringTrend::Improving);
    }

    #[test]
    fn test_trend_improving_timer_lower_is_better() {
        let mut r = MetricRegistry::new();
        r.register(mk("t", MonitoringMetricType::Timer));
        for v in [100.0, 95.0, 20.0, 15.0] {
            r.record("t", v, 1).unwrap();
        }
        assert_eq!(r.trend("t").trend, MonitoringTrend::Improving);
    }

    #[test]
    fn test_trend_insufficient_data() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Gauge));
        r.record("g", 1.0, 1).unwrap();
        r.record("g", 2.0, 2).unwrap();
        assert_eq!(r.trend("g").trend, MonitoringTrend::InsufficientData);
    }

    #[test]
    fn test_trend_stable_under_threshold() {
        let mut r = MetricRegistry::new();
        r.register(mk("g", MonitoringMetricType::Gauge));
        for v in [100.0, 101.0, 100.5, 100.3] {
            r.record("g", v, 1).unwrap();
        }
        assert_eq!(r.trend("g").trend, MonitoringTrend::Stable);
    }

    #[test]
    fn test_metric_display_types() {
        assert_eq!(MonitoringMetricType::Counter.to_string(), "counter");
        assert_eq!(MonitoringMetricType::Gauge.to_string(), "gauge");
        assert_eq!(MonitoringMetricType::Timer.to_string(), "timer");
    }

    #[test]
    fn test_metric_builders() {
        let m = MonitoringMetric::new(
            "api_latency",
            "API Latency",
            MonitoringMetricType::Timer,
            "ms",
        )
        .with_description("p95 request latency")
        .with_tag("env", "prod");
        assert_eq!(m.description, "p95 request latency");
        assert_eq!(m.tags.get("env").map(String::as_str), Some("prod"));
    }
}
