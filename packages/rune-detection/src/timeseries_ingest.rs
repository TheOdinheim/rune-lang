// ═══════════════════════════════════════════════════════════════════════
// Time-Series Ingestor — Trait for one-way metric ingestion.
//
// Layer 3 defines the contract for ingesting time-series metrics
// into the detection layer. This is one-way ingestion — retrieval
// protocols belong in downstream adapter crates. RUNE provides
// the shaped hole; the customer provides the transport.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::DetectionError;

// ── TimeSeriesPoint ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSeriesPoint {
    pub timestamp: i64,
    pub metric_name: String,
    pub value: String, // String for Eq derivation (no f64)
    pub labels: HashMap<String, String>,
}

impl TimeSeriesPoint {
    pub fn new(timestamp: i64, metric_name: &str, value: &str) -> Self {
        Self {
            timestamp,
            metric_name: metric_name.to_string(),
            value: value.to_string(),
            labels: HashMap::new(),
        }
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }
}

// ── TimeSeriesIngestor trait ───────────────────────────────────

pub trait TimeSeriesIngestor {
    fn ingest_metric(&mut self, point: &TimeSeriesPoint) -> Result<(), DetectionError>;
    fn ingest_batch(&mut self, points: &[TimeSeriesPoint]) -> Result<usize, DetectionError>;
    fn query_range(&self, metric_name: &str, start: i64, end: i64) -> Vec<&TimeSeriesPoint>;
    fn last_ingest_at(&self) -> Option<i64>;
    fn source_name(&self) -> &str;
    fn supported_metric_types(&self) -> Vec<&str>;
    fn is_active(&self) -> bool;
}

// ── InMemoryTimeSeriesIngestor ─────────────────────────────────

pub struct InMemoryTimeSeriesIngestor {
    name: String,
    points: Vec<TimeSeriesPoint>,
    last_ingest: Option<i64>,
    retention_seconds: i64,
    active: bool,
}

impl InMemoryTimeSeriesIngestor {
    pub fn new(name: &str, retention_seconds: i64) -> Self {
        Self {
            name: name.to_string(),
            points: Vec::new(),
            last_ingest: None,
            retention_seconds,
            active: true,
        }
    }

    pub fn point_count(&self) -> usize {
        self.points.len()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Remove points older than `now - retention_seconds`.
    pub fn purge_expired(&mut self, now: i64) -> usize {
        let cutoff = now - self.retention_seconds;
        let before = self.points.len();
        self.points.retain(|p| p.timestamp >= cutoff);
        before - self.points.len()
    }
}

impl TimeSeriesIngestor for InMemoryTimeSeriesIngestor {
    fn ingest_metric(&mut self, point: &TimeSeriesPoint) -> Result<(), DetectionError> {
        if !self.active {
            return Err(DetectionError::InvalidOperation("ingestor is inactive".into()));
        }
        self.last_ingest = Some(point.timestamp);
        self.points.push(point.clone());
        Ok(())
    }

    fn ingest_batch(&mut self, points: &[TimeSeriesPoint]) -> Result<usize, DetectionError> {
        if !self.active {
            return Err(DetectionError::InvalidOperation("ingestor is inactive".into()));
        }
        let mut count = 0;
        for p in points {
            self.last_ingest = Some(p.timestamp);
            self.points.push(p.clone());
            count += 1;
        }
        Ok(count)
    }

    fn query_range(&self, metric_name: &str, start: i64, end: i64) -> Vec<&TimeSeriesPoint> {
        self.points
            .iter()
            .filter(|p| p.metric_name == metric_name && p.timestamp >= start && p.timestamp <= end)
            .collect()
    }

    fn last_ingest_at(&self) -> Option<i64> {
        self.last_ingest
    }

    fn source_name(&self) -> &str {
        &self.name
    }

    fn supported_metric_types(&self) -> Vec<&str> {
        vec!["gauge", "counter", "histogram"]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(metric: &str, ts: i64, value: &str) -> TimeSeriesPoint {
        TimeSeriesPoint::new(ts, metric, value)
    }

    #[test]
    fn test_ingest_single_metric() {
        let mut ingestor = InMemoryTimeSeriesIngestor::new("test-src", 3600);
        ingestor.ingest_metric(&make_point("cpu", 1000, "0.75")).unwrap();
        assert_eq!(ingestor.point_count(), 1);
        assert_eq!(ingestor.last_ingest_at(), Some(1000));
    }

    #[test]
    fn test_ingest_batch() {
        let mut ingestor = InMemoryTimeSeriesIngestor::new("test-src", 3600);
        let points = vec![
            make_point("cpu", 1000, "0.75"),
            make_point("mem", 1001, "0.60"),
            make_point("cpu", 1002, "0.80"),
        ];
        let count = ingestor.ingest_batch(&points).unwrap();
        assert_eq!(count, 3);
        assert_eq!(ingestor.point_count(), 3);
    }

    #[test]
    fn test_query_range() {
        let mut ingestor = InMemoryTimeSeriesIngestor::new("test-src", 3600);
        ingestor.ingest_metric(&make_point("cpu", 1000, "0.75")).unwrap();
        ingestor.ingest_metric(&make_point("cpu", 2000, "0.80")).unwrap();
        ingestor.ingest_metric(&make_point("cpu", 3000, "0.85")).unwrap();
        ingestor.ingest_metric(&make_point("mem", 1500, "0.60")).unwrap();

        let results = ingestor.query_range("cpu", 1500, 2500);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "0.80");
    }

    #[test]
    fn test_query_range_all_cpu() {
        let mut ingestor = InMemoryTimeSeriesIngestor::new("test-src", 3600);
        ingestor.ingest_metric(&make_point("cpu", 1000, "0.75")).unwrap();
        ingestor.ingest_metric(&make_point("cpu", 2000, "0.80")).unwrap();
        let results = ingestor.query_range("cpu", 0, 5000);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_purge_expired() {
        let mut ingestor = InMemoryTimeSeriesIngestor::new("test-src", 1000);
        ingestor.ingest_metric(&make_point("cpu", 100, "0.5")).unwrap();
        ingestor.ingest_metric(&make_point("cpu", 500, "0.6")).unwrap();
        ingestor.ingest_metric(&make_point("cpu", 1500, "0.7")).unwrap();
        let purged = ingestor.purge_expired(1500);
        assert_eq!(purged, 1); // only ts=100 is older than 1500-1000=500
        assert_eq!(ingestor.point_count(), 2);
    }

    #[test]
    fn test_inactive_ingestor_rejects() {
        let mut ingestor = InMemoryTimeSeriesIngestor::new("test-src", 3600);
        ingestor.deactivate();
        assert!(ingestor.ingest_metric(&make_point("cpu", 1000, "0.75")).is_err());
        assert!(ingestor.ingest_batch(&[make_point("cpu", 1000, "0.75")]).is_err());
    }

    #[test]
    fn test_source_name_and_types() {
        let ingestor = InMemoryTimeSeriesIngestor::new("my-source", 3600);
        assert_eq!(ingestor.source_name(), "my-source");
        assert!(ingestor.supported_metric_types().contains(&"gauge"));
        assert!(ingestor.is_active());
    }

    #[test]
    fn test_point_with_labels() {
        let p = TimeSeriesPoint::new(1000, "cpu", "0.75")
            .with_label("host", "server-1")
            .with_label("region", "us-east");
        assert_eq!(p.labels.get("host").unwrap(), "server-1");
        assert_eq!(p.labels.get("region").unwrap(), "us-east");
    }

    #[test]
    fn test_point_eq() {
        let p1 = make_point("cpu", 1000, "0.75");
        let p2 = make_point("cpu", 1000, "0.75");
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_last_ingest_initially_none() {
        let ingestor = InMemoryTimeSeriesIngestor::new("test-src", 3600);
        assert!(ingestor.last_ingest_at().is_none());
    }
}
