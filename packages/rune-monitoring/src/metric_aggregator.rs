// ═══════════════════════════════════════════════════════════════════════
// Metric Aggregator — Reduces raw metric points into dashboard-ready
// aggregated windows and percentile summaries.
//
// Two reference implementations:
//   - InMemoryMetricAggregator: recomputes from stored points each time.
//   - StreamingMetricAggregator: incrementally updates aggregates as
//     new points arrive — the correct approach for high-cardinality
//     metric streams.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::backend::{MetricPoint, StoredMetricSeries};
use crate::error::MonitoringError;

// ── AggregationFunction ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AggregationFunction {
    Sum,
    Mean,
    Min,
    Max,
    Count,
    First,
    Last,
    P50,
    P75,
    P90,
    P95,
    P99,
}

impl fmt::Display for AggregationFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AggregatedMetricWindow ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedMetricWindow {
    pub series_id: String,
    pub window_start: i64,
    pub window_end: i64,
    pub aggregation_function: AggregationFunction,
    pub aggregated_value: String,
    pub point_count: usize,
}

// ── PercentileSummary ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercentileSummary {
    pub series_id: String,
    pub window_start: i64,
    pub window_end: i64,
    pub p50: String,
    pub p75: String,
    pub p90: String,
    pub p95: String,
    pub p99: String,
    pub sample_count: usize,
}

// ── MetricAggregator trait ───────────────────────────────────────

pub trait MetricAggregator {
    fn aggregate_window(
        &self,
        series: &StoredMetricSeries,
        window_start: i64,
        window_end: i64,
        function: &AggregationFunction,
    ) -> Result<AggregatedMetricWindow, MonitoringError>;

    fn downsample(
        &self,
        series: &StoredMetricSeries,
        target_interval: i64,
    ) -> Result<Vec<MetricPoint>, MonitoringError>;

    fn compute_percentiles(
        &self,
        series: &StoredMetricSeries,
        window_start: i64,
        window_end: i64,
    ) -> Result<PercentileSummary, MonitoringError>;

    fn aggregator_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── Helper: parse f64 values from points in a window ─────────────

fn points_in_window(series: &StoredMetricSeries, start: i64, end: i64) -> Vec<f64> {
    series.points.iter()
        .filter(|p| p.timestamp >= start && p.timestamp <= end)
        .filter_map(|p| p.value.parse::<f64>().ok())
        .collect()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = p / 100.0 * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;
    if upper >= sorted.len() {
        sorted[sorted.len() - 1]
    } else {
        sorted[lower] * (1.0 - frac) + sorted[upper] * frac
    }
}

fn apply_aggregation(values: &[f64], function: &AggregationFunction) -> f64 {
    match function {
        AggregationFunction::Sum => values.iter().sum(),
        AggregationFunction::Mean => {
            if values.is_empty() { 0.0 } else { values.iter().sum::<f64>() / values.len() as f64 }
        }
        AggregationFunction::Min => values.iter().copied().fold(f64::INFINITY, f64::min),
        AggregationFunction::Max => values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        AggregationFunction::Count => values.len() as f64,
        AggregationFunction::First => values.first().copied().unwrap_or(0.0),
        AggregationFunction::Last => values.last().copied().unwrap_or(0.0),
        AggregationFunction::P50 => {
            let mut s = values.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            percentile(&s, 50.0)
        }
        AggregationFunction::P75 => {
            let mut s = values.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            percentile(&s, 75.0)
        }
        AggregationFunction::P90 => {
            let mut s = values.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            percentile(&s, 90.0)
        }
        AggregationFunction::P95 => {
            let mut s = values.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            percentile(&s, 95.0)
        }
        AggregationFunction::P99 => {
            let mut s = values.to_vec();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            percentile(&s, 99.0)
        }
    }
}

// ── InMemoryMetricAggregator ─────────────────────────────────────

pub struct InMemoryMetricAggregator {
    id: String,
}

impl InMemoryMetricAggregator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl MetricAggregator for InMemoryMetricAggregator {
    fn aggregate_window(
        &self,
        series: &StoredMetricSeries,
        window_start: i64,
        window_end: i64,
        function: &AggregationFunction,
    ) -> Result<AggregatedMetricWindow, MonitoringError> {
        let values = points_in_window(series, window_start, window_end);
        if values.is_empty() {
            return Err(MonitoringError::InsufficientData {
                reason: format!("no points in window {window_start}..{window_end}"),
            });
        }
        let result = apply_aggregation(&values, function);
        Ok(AggregatedMetricWindow {
            series_id: series.series_id.clone(),
            window_start,
            window_end,
            aggregation_function: function.clone(),
            aggregated_value: format!("{result:.6}"),
            point_count: values.len(),
        })
    }

    fn downsample(
        &self,
        series: &StoredMetricSeries,
        target_interval: i64,
    ) -> Result<Vec<MetricPoint>, MonitoringError> {
        if series.points.is_empty() {
            return Ok(Vec::new());
        }
        let min_ts = series.points.iter().map(|p| p.timestamp).min().unwrap();
        let max_ts = series.points.iter().map(|p| p.timestamp).max().unwrap();
        let mut result = Vec::new();
        let mut bucket_start = min_ts;
        while bucket_start <= max_ts {
            let bucket_end = bucket_start + target_interval;
            let values = points_in_window(series, bucket_start, bucket_end - 1);
            if !values.is_empty() {
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                result.push(MetricPoint::new(bucket_start, &format!("{mean:.6}")));
            }
            bucket_start = bucket_end;
        }
        Ok(result)
    }

    fn compute_percentiles(
        &self,
        series: &StoredMetricSeries,
        window_start: i64,
        window_end: i64,
    ) -> Result<PercentileSummary, MonitoringError> {
        let mut values = points_in_window(series, window_start, window_end);
        if values.is_empty() {
            return Err(MonitoringError::InsufficientData {
                reason: "no points for percentile computation".to_string(),
            });
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Ok(PercentileSummary {
            series_id: series.series_id.clone(),
            window_start,
            window_end,
            p50: format!("{:.6}", percentile(&values, 50.0)),
            p75: format!("{:.6}", percentile(&values, 75.0)),
            p90: format!("{:.6}", percentile(&values, 90.0)),
            p95: format!("{:.6}", percentile(&values, 95.0)),
            p99: format!("{:.6}", percentile(&values, 99.0)),
            sample_count: values.len(),
        })
    }

    fn aggregator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── StreamingMetricAggregator ────────────────────────────────────
// Incrementally updates aggregates as new points arrive, rather
// than recomputing from scratch.

pub struct StreamingMetricAggregator {
    id: String,
    running: HashMap<String, StreamingState>,
}

struct StreamingState {
    count: usize,
    sum: f64,
    min: f64,
    max: f64,
    last: f64,
    first: f64,
}

impl StreamingState {
    fn new(value: f64) -> Self {
        Self {
            count: 1,
            sum: value,
            min: value,
            max: value,
            last: value,
            first: value,
        }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.min = f64::min(self.min, value);
        self.max = f64::max(self.max, value);
        self.last = value;
    }
}

impl StreamingMetricAggregator {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            running: HashMap::new(),
        }
    }

    pub fn ingest_point(&mut self, series_id: &str, value: f64) {
        if let Some(state) = self.running.get_mut(series_id) {
            state.update(value);
        } else {
            self.running.insert(series_id.to_string(), StreamingState::new(value));
        }
    }

    pub fn streaming_value(&self, series_id: &str, function: &AggregationFunction) -> Option<f64> {
        let state = self.running.get(series_id)?;
        Some(match function {
            AggregationFunction::Sum => state.sum,
            AggregationFunction::Mean => state.sum / state.count as f64,
            AggregationFunction::Min => state.min,
            AggregationFunction::Max => state.max,
            AggregationFunction::Count => state.count as f64,
            AggregationFunction::First => state.first,
            AggregationFunction::Last => state.last,
            _ => return None, // Percentiles require full data
        })
    }

    pub fn reset(&mut self, series_id: &str) {
        self.running.remove(series_id);
    }
}

impl MetricAggregator for StreamingMetricAggregator {
    fn aggregate_window(
        &self,
        series: &StoredMetricSeries,
        window_start: i64,
        window_end: i64,
        function: &AggregationFunction,
    ) -> Result<AggregatedMetricWindow, MonitoringError> {
        let values = points_in_window(series, window_start, window_end);
        if values.is_empty() {
            return Err(MonitoringError::InsufficientData {
                reason: format!("no points in window {window_start}..{window_end}"),
            });
        }
        let result = apply_aggregation(&values, function);
        Ok(AggregatedMetricWindow {
            series_id: series.series_id.clone(),
            window_start,
            window_end,
            aggregation_function: function.clone(),
            aggregated_value: format!("{result:.6}"),
            point_count: values.len(),
        })
    }

    fn downsample(
        &self,
        series: &StoredMetricSeries,
        target_interval: i64,
    ) -> Result<Vec<MetricPoint>, MonitoringError> {
        if series.points.is_empty() {
            return Ok(Vec::new());
        }
        let min_ts = series.points.iter().map(|p| p.timestamp).min().unwrap();
        let max_ts = series.points.iter().map(|p| p.timestamp).max().unwrap();
        let mut result = Vec::new();
        let mut bucket_start = min_ts;
        while bucket_start <= max_ts {
            let bucket_end = bucket_start + target_interval;
            let values = points_in_window(series, bucket_start, bucket_end - 1);
            if !values.is_empty() {
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                result.push(MetricPoint::new(bucket_start, &format!("{mean:.6}")));
            }
            bucket_start = bucket_end;
        }
        Ok(result)
    }

    fn compute_percentiles(
        &self,
        series: &StoredMetricSeries,
        window_start: i64,
        window_end: i64,
    ) -> Result<PercentileSummary, MonitoringError> {
        let mut values = points_in_window(series, window_start, window_end);
        if values.is_empty() {
            return Err(MonitoringError::InsufficientData {
                reason: "no points for percentile computation".to_string(),
            });
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Ok(PercentileSummary {
            series_id: series.series_id.clone(),
            window_start,
            window_end,
            p50: format!("{:.6}", percentile(&values, 50.0)),
            p75: format!("{:.6}", percentile(&values, 75.0)),
            p90: format!("{:.6}", percentile(&values, 90.0)),
            p95: format!("{:.6}", percentile(&values, 95.0)),
            p99: format!("{:.6}", percentile(&values, 99.0)),
            sample_count: values.len(),
        })
    }

    fn aggregator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MetricKind;

    fn sample_series() -> StoredMetricSeries {
        StoredMetricSeries {
            series_id: "s1".to_string(),
            metric_name: "latency_ms".to_string(),
            labels: HashMap::new(),
            points: vec![
                MetricPoint::new(100, "10.0"),
                MetricPoint::new(200, "20.0"),
                MetricPoint::new(300, "30.0"),
                MetricPoint::new(400, "40.0"),
                MetricPoint::new(500, "50.0"),
            ],
            unit: "ms".to_string(),
            metric_kind: MetricKind::Gauge,
        }
    }

    #[test]
    fn test_aggregate_sum() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let result = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Sum).unwrap();
        assert_eq!(result.aggregated_value, "150.000000");
        assert_eq!(result.point_count, 5);
    }

    #[test]
    fn test_aggregate_mean() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let result = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Mean).unwrap();
        assert_eq!(result.aggregated_value, "30.000000");
    }

    #[test]
    fn test_aggregate_min_max() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let min = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Min).unwrap();
        let max = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Max).unwrap();
        assert_eq!(min.aggregated_value, "10.000000");
        assert_eq!(max.aggregated_value, "50.000000");
    }

    #[test]
    fn test_aggregate_count() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let result = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Count).unwrap();
        assert_eq!(result.aggregated_value, "5.000000");
    }

    #[test]
    fn test_aggregate_first_last() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let first = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::First).unwrap();
        let last = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Last).unwrap();
        assert_eq!(first.aggregated_value, "10.000000");
        assert_eq!(last.aggregated_value, "50.000000");
    }

    #[test]
    fn test_aggregate_empty_window() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        assert!(agg.aggregate_window(&sample_series(), 600, 700, &AggregationFunction::Sum).is_err());
    }

    #[test]
    fn test_downsample() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let result = agg.downsample(&sample_series(), 200).unwrap();
        assert!(result.len() <= 3);
    }

    #[test]
    fn test_compute_percentiles() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        let result = agg.compute_percentiles(&sample_series(), 100, 500).unwrap();
        assert_eq!(result.sample_count, 5);
        // p50 of [10,20,30,40,50] = 30
        assert_eq!(result.p50, "30.000000");
    }

    #[test]
    fn test_streaming_aggregator_ingest() {
        let mut agg = StreamingMetricAggregator::new("stream-1");
        agg.ingest_point("s1", 10.0);
        agg.ingest_point("s1", 20.0);
        agg.ingest_point("s1", 30.0);
        assert_eq!(agg.streaming_value("s1", &AggregationFunction::Sum), Some(60.0));
        assert_eq!(agg.streaming_value("s1", &AggregationFunction::Mean), Some(20.0));
        assert_eq!(agg.streaming_value("s1", &AggregationFunction::Min), Some(10.0));
        assert_eq!(agg.streaming_value("s1", &AggregationFunction::Max), Some(30.0));
        assert_eq!(agg.streaming_value("s1", &AggregationFunction::Count), Some(3.0));
    }

    #[test]
    fn test_streaming_reset() {
        let mut agg = StreamingMetricAggregator::new("stream-1");
        agg.ingest_point("s1", 10.0);
        agg.reset("s1");
        assert_eq!(agg.streaming_value("s1", &AggregationFunction::Sum), None);
    }

    #[test]
    fn test_streaming_aggregate_window() {
        let agg = StreamingMetricAggregator::new("stream-1");
        let result = agg.aggregate_window(&sample_series(), 100, 500, &AggregationFunction::Mean).unwrap();
        assert_eq!(result.aggregated_value, "30.000000");
    }

    #[test]
    fn test_aggregator_metadata() {
        let agg = InMemoryMetricAggregator::new("agg-1");
        assert_eq!(agg.aggregator_id(), "agg-1");
        assert!(agg.is_active());
    }

    #[test]
    fn test_aggregation_function_display() {
        assert_eq!(AggregationFunction::Sum.to_string(), "Sum");
        assert_eq!(AggregationFunction::P99.to_string(), "P99");
    }
}
