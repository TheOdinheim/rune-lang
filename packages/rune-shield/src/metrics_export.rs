// ═══════════════════════════════════════════════════════════════════════
// Metrics Export — Shield metrics exporter trait and implementations.
//
// Layer 3 defines the contract for exporting shield operational
// metrics to observability platforms. Tracks per-rule hit counters,
// verdict latency histograms, action distribution gauges, and
// false-positive-rate gauges. RUNE produces the metric data —
// the customer ships it.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::ShieldError;

// ── Metric value types ──────────────────────────────────────────

/// Counter: monotonically increasing value. Stored as String for Eq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterMetric {
    pub name: String,
    pub value: String,
    pub labels: HashMap<String, String>,
}

/// Histogram: distribution of values. Bucket boundaries and counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramMetric {
    pub name: String,
    pub count: u64,
    pub sum: String,
    pub buckets: Vec<(String, u64)>,
    pub labels: HashMap<String, String>,
}

/// Gauge: point-in-time value. Stored as String for Eq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaugeMetric {
    pub name: String,
    pub value: String,
    pub labels: HashMap<String, String>,
}

// ── ShieldMetricsExporter trait ─────────────────────────────────

pub trait ShieldMetricsExporter {
    fn export_counters(&self) -> Result<Vec<u8>, ShieldError>;
    fn export_histograms(&self) -> Result<Vec<u8>, ShieldError>;
    fn export_gauges(&self) -> Result<Vec<u8>, ShieldError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── ShieldMetricsStore ──────────────────────────────────────────

/// Collects metrics for export.
#[derive(Debug, Clone, Default)]
pub struct ShieldMetricsStore {
    pub counters: Vec<CounterMetric>,
    pub histograms: Vec<HistogramMetric>,
    pub gauges: Vec<GaugeMetric>,
}

impl ShieldMetricsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_counter(&mut self, name: &str, value: f64, labels: HashMap<String, String>) {
        self.counters.push(CounterMetric {
            name: name.to_string(),
            value: format!("{value}"),
            labels,
        });
    }

    pub fn record_histogram(
        &mut self,
        name: &str,
        count: u64,
        sum: f64,
        buckets: Vec<(f64, u64)>,
        labels: HashMap<String, String>,
    ) {
        self.histograms.push(HistogramMetric {
            name: name.to_string(),
            count,
            sum: format!("{sum}"),
            buckets: buckets
                .into_iter()
                .map(|(bound, count)| (format!("{bound}"), count))
                .collect(),
            labels,
        });
    }

    pub fn record_gauge(&mut self, name: &str, value: f64, labels: HashMap<String, String>) {
        self.gauges.push(GaugeMetric {
            name: name.to_string(),
            value: format!("{value}"),
            labels,
        });
    }
}

// ── PrometheusMetricsExporter ───────────────────────────────────

/// Prometheus text exposition format.
pub struct PrometheusMetricsExporter {
    store: ShieldMetricsStore,
}

impl PrometheusMetricsExporter {
    pub fn new(store: ShieldMetricsStore) -> Self {
        Self { store }
    }

    fn format_labels(labels: &HashMap<String, String>) -> String {
        if labels.is_empty() {
            return String::new();
        }
        let mut pairs: Vec<String> = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect();
        pairs.sort();
        format!("{{{}}}", pairs.join(","))
    }
}

impl ShieldMetricsExporter for PrometheusMetricsExporter {
    fn export_counters(&self) -> Result<Vec<u8>, ShieldError> {
        let mut out = String::new();
        for c in &self.store.counters {
            let labels = Self::format_labels(&c.labels);
            out.push_str(&format!(
                "# TYPE {} counter\n{}{} {}\n",
                c.name, c.name, labels, c.value
            ));
        }
        Ok(out.into_bytes())
    }

    fn export_histograms(&self) -> Result<Vec<u8>, ShieldError> {
        let mut out = String::new();
        for h in &self.store.histograms {
            let labels = Self::format_labels(&h.labels);
            out.push_str(&format!("# TYPE {} histogram\n", h.name));
            for (bound, count) in &h.buckets {
                out.push_str(&format!(
                    "{}_bucket{{le=\"{bound}\"{comma}}} {count}\n",
                    h.name,
                    comma = if labels.is_empty() {
                        String::new()
                    } else {
                        format!(",{}", &labels[1..labels.len() - 1])
                    },
                ));
            }
            out.push_str(&format!("{}_count{} {}\n", h.name, labels, h.count));
            out.push_str(&format!("{}_sum{} {}\n", h.name, labels, h.sum));
        }
        Ok(out.into_bytes())
    }

    fn export_gauges(&self) -> Result<Vec<u8>, ShieldError> {
        let mut out = String::new();
        for g in &self.store.gauges {
            let labels = Self::format_labels(&g.labels);
            out.push_str(&format!(
                "# TYPE {} gauge\n{}{} {}\n",
                g.name, g.name, labels, g.value
            ));
        }
        Ok(out.into_bytes())
    }

    fn format_name(&self) -> &str {
        "prometheus"
    }

    fn content_type(&self) -> &str {
        "text/plain; version=0.0.4; charset=utf-8"
    }
}

// ── OtelMetricsExporter ─────────────────────────────────────────

/// OpenTelemetry metric data model (JSON).
pub struct OtelMetricsExporter {
    store: ShieldMetricsStore,
}

impl OtelMetricsExporter {
    pub fn new(store: ShieldMetricsStore) -> Self {
        Self { store }
    }
}

impl ShieldMetricsExporter for OtelMetricsExporter {
    fn export_counters(&self) -> Result<Vec<u8>, ShieldError> {
        let metrics: Vec<serde_json::Value> = self
            .store
            .counters
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "type": "sum",
                    "is_monotonic": true,
                    "data_points": [{
                        "value": c.value,
                        "attributes": c.labels,
                    }]
                })
            })
            .collect();
        serde_json::to_vec_pretty(&serde_json::json!({ "metrics": metrics }))
            .map_err(|e| ShieldError::InvalidConfiguration(format!("OTel counter export: {e}")))
    }

    fn export_histograms(&self) -> Result<Vec<u8>, ShieldError> {
        let metrics: Vec<serde_json::Value> = self
            .store
            .histograms
            .iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.name,
                    "type": "histogram",
                    "data_points": [{
                        "count": h.count,
                        "sum": h.sum,
                        "bucket_counts": h.buckets.iter().map(|(_, c)| c).collect::<Vec<_>>(),
                        "explicit_bounds": h.buckets.iter().map(|(b, _)| b).collect::<Vec<_>>(),
                        "attributes": h.labels,
                    }]
                })
            })
            .collect();
        serde_json::to_vec_pretty(&serde_json::json!({ "metrics": metrics }))
            .map_err(|e| ShieldError::InvalidConfiguration(format!("OTel histogram export: {e}")))
    }

    fn export_gauges(&self) -> Result<Vec<u8>, ShieldError> {
        let metrics: Vec<serde_json::Value> = self
            .store
            .gauges
            .iter()
            .map(|g| {
                serde_json::json!({
                    "name": g.name,
                    "type": "gauge",
                    "data_points": [{
                        "value": g.value,
                        "attributes": g.labels,
                    }]
                })
            })
            .collect();
        serde_json::to_vec_pretty(&serde_json::json!({ "metrics": metrics }))
            .map_err(|e| ShieldError::InvalidConfiguration(format!("OTel gauge export: {e}")))
    }

    fn format_name(&self) -> &str {
        "opentelemetry"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> ShieldMetricsStore {
        let mut store = ShieldMetricsStore::new();
        let mut labels = HashMap::new();
        labels.insert("rule_id".to_string(), "r1".to_string());
        store.record_counter("shield_rule_hits_total", 42.0, labels.clone());
        store.record_histogram(
            "shield_verdict_latency_seconds",
            100,
            5.5,
            vec![(0.01, 20), (0.05, 50), (0.1, 80), (0.5, 95), (1.0, 100)],
            labels.clone(),
        );
        store.record_gauge("shield_action_distribution", 0.75, labels.clone());
        store.record_gauge("shield_false_positive_rate", 0.03, HashMap::new());
        store
    }

    #[test]
    fn test_prometheus_counters() {
        let exporter = PrometheusMetricsExporter::new(make_store());
        let data = exporter.export_counters().unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("# TYPE shield_rule_hits_total counter"));
        assert!(text.contains("42"));
    }

    #[test]
    fn test_prometheus_histograms() {
        let exporter = PrometheusMetricsExporter::new(make_store());
        let data = exporter.export_histograms().unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("# TYPE shield_verdict_latency_seconds histogram"));
        assert!(text.contains("_bucket"));
        assert!(text.contains("_count"));
        assert!(text.contains("_sum"));
    }

    #[test]
    fn test_prometheus_gauges() {
        let exporter = PrometheusMetricsExporter::new(make_store());
        let data = exporter.export_gauges().unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("# TYPE shield_action_distribution gauge"));
        assert!(text.contains("0.75"));
    }

    #[test]
    fn test_prometheus_format_info() {
        let exporter = PrometheusMetricsExporter::new(ShieldMetricsStore::new());
        assert_eq!(exporter.format_name(), "prometheus");
        assert!(exporter.content_type().contains("text/plain"));
    }

    #[test]
    fn test_otel_counters() {
        let exporter = OtelMetricsExporter::new(make_store());
        let data = exporter.export_counters().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let metrics = parsed["metrics"].as_array().unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0]["type"], "sum");
        assert!(metrics[0]["is_monotonic"].as_bool().unwrap());
    }

    #[test]
    fn test_otel_histograms() {
        let exporter = OtelMetricsExporter::new(make_store());
        let data = exporter.export_histograms().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let metrics = parsed["metrics"].as_array().unwrap();
        assert_eq!(metrics[0]["type"], "histogram");
        let dp = &metrics[0]["data_points"][0];
        assert_eq!(dp["count"], 100);
    }

    #[test]
    fn test_otel_gauges() {
        let exporter = OtelMetricsExporter::new(make_store());
        let data = exporter.export_gauges().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let metrics = parsed["metrics"].as_array().unwrap();
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0]["type"], "gauge");
    }

    #[test]
    fn test_otel_format_info() {
        let exporter = OtelMetricsExporter::new(ShieldMetricsStore::new());
        assert_eq!(exporter.format_name(), "opentelemetry");
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_empty_store_exports() {
        let store = ShieldMetricsStore::new();
        let prom = PrometheusMetricsExporter::new(store.clone());
        assert!(prom.export_counters().unwrap().is_empty());
        assert!(prom.export_histograms().unwrap().is_empty());
        assert!(prom.export_gauges().unwrap().is_empty());
    }

    #[test]
    fn test_counter_metric_eq() {
        let c1 = CounterMetric {
            name: "x".into(),
            value: "1".into(),
            labels: HashMap::new(),
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }
}
