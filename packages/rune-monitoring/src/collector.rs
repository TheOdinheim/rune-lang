// ═══════════════════════════════════════════════════════════════════════
// Collector — metric sources and the engine that gathers their samples.
//
// MetricSource is a thin trait-free description; CollectorEngine stores
// pending samples keyed by metric-id and drains them into a
// MetricRegistry on collect(). Sources push via `submit`, keeping the
// engine purely reactive (no I/O).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::{MonitoringError, MonitoringResult};
use crate::metric::MetricRegistry;

// ── MetricSourceType ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricSourceType {
    System,
    Application,
    Security,
    Custom,
}

impl fmt::Display for MetricSourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => f.write_str("system"),
            Self::Application => f.write_str("application"),
            Self::Security => f.write_str("security"),
            Self::Custom => f.write_str("custom"),
        }
    }
}

// ── MetricSource ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricSource {
    pub id: String,
    pub name: String,
    pub source_type: MetricSourceType,
    /// metric-id → (value, timestamp)
    pub pending: Vec<(String, f64, i64)>,
    pub enabled: bool,
}

impl MetricSource {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        source_type: MetricSourceType,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            source_type,
            pending: Vec::new(),
            enabled: true,
        }
    }

    pub fn submit(&mut self, metric_id: impl Into<String>, value: f64, timestamp: i64) {
        if !self.enabled {
            return;
        }
        self.pending.push((metric_id.into(), value, timestamp));
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

// ── CollectorEngine ───────────────────────────────────────────────────

#[derive(Default)]
pub struct CollectorEngine {
    pub sources: HashMap<String, MetricSource>,
    pub collected_total: u64,
    pub errors_total: u64,
}

impl CollectorEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_source(&mut self, source: MetricSource) {
        self.sources.insert(source.id.clone(), source);
    }

    pub fn submit(
        &mut self,
        source_id: &str,
        metric_id: impl Into<String>,
        value: f64,
        timestamp: i64,
    ) -> MonitoringResult<()> {
        let source = self
            .sources
            .get_mut(source_id)
            .ok_or_else(|| MonitoringError::CollectorNotFound { id: source_id.into() })?;
        source.submit(metric_id, value, timestamp);
        Ok(())
    }

    /// Drain every source's pending samples into `registry`. Unknown
    /// metric ids increment the error counter but do not abort the drain.
    pub fn collect(&mut self, registry: &mut MetricRegistry) -> usize {
        let mut drained = 0;
        for source in self.sources.values_mut() {
            if !source.enabled {
                continue;
            }
            let taken = std::mem::take(&mut source.pending);
            for (id, value, ts) in taken {
                match registry.record(&id, value, ts) {
                    Ok(()) => {
                        drained += 1;
                        self.collected_total += 1;
                    }
                    Err(_) => self.errors_total += 1,
                }
            }
        }
        drained
    }

    pub fn pending_total(&self) -> usize {
        self.sources.values().map(|s| s.pending_count()).sum()
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::{MonitoringMetric, MonitoringMetricType};

    fn registry() -> MetricRegistry {
        let mut r = MetricRegistry::new();
        r.register(MonitoringMetric::new(
            "lat",
            "Lat",
            MonitoringMetricType::Timer,
            "ms",
        ));
        r
    }

    #[test]
    fn test_source_submit_and_drain() {
        let mut eng = CollectorEngine::new();
        eng.add_source(MetricSource::new(
            "sys",
            "System",
            MetricSourceType::System,
        ));
        eng.submit("sys", "lat", 10.0, 1).unwrap();
        eng.submit("sys", "lat", 20.0, 2).unwrap();
        assert_eq!(eng.pending_total(), 2);
        let mut reg = registry();
        let drained = eng.collect(&mut reg);
        assert_eq!(drained, 2);
        assert_eq!(reg.count("lat"), 2);
        assert_eq!(eng.pending_total(), 0);
    }

    #[test]
    fn test_unknown_metric_counts_error() {
        let mut eng = CollectorEngine::new();
        eng.add_source(MetricSource::new(
            "sys",
            "System",
            MetricSourceType::System,
        ));
        eng.submit("sys", "missing", 1.0, 1).unwrap();
        let mut reg = registry();
        eng.collect(&mut reg);
        assert_eq!(eng.errors_total, 1);
        assert_eq!(eng.collected_total, 0);
    }

    #[test]
    fn test_unknown_source_errors() {
        let mut eng = CollectorEngine::new();
        let err = eng.submit("nope", "lat", 1.0, 1).unwrap_err();
        assert!(matches!(err, MonitoringError::CollectorNotFound { .. }));
    }

    #[test]
    fn test_disabled_source_not_drained() {
        let mut eng = CollectorEngine::new();
        let mut src = MetricSource::new("sys", "System", MetricSourceType::System);
        src.submit("lat", 1.0, 1);
        src.disable();
        eng.add_source(src);
        let mut reg = registry();
        let drained = eng.collect(&mut reg);
        assert_eq!(drained, 0);
    }

    #[test]
    fn test_multiple_sources() {
        let mut eng = CollectorEngine::new();
        eng.add_source(MetricSource::new(
            "a",
            "A",
            MetricSourceType::System,
        ));
        eng.add_source(MetricSource::new(
            "b",
            "B",
            MetricSourceType::Application,
        ));
        eng.submit("a", "lat", 1.0, 1).unwrap();
        eng.submit("b", "lat", 2.0, 2).unwrap();
        let mut reg = registry();
        eng.collect(&mut reg);
        assert_eq!(reg.count("lat"), 2);
        assert_eq!(eng.source_count(), 2);
    }

    #[test]
    fn test_source_type_display() {
        assert_eq!(MetricSourceType::System.to_string(), "system");
        assert_eq!(MetricSourceType::Application.to_string(), "application");
        assert_eq!(MetricSourceType::Security.to_string(), "security");
        assert_eq!(MetricSourceType::Custom.to_string(), "custom");
    }

    #[test]
    fn test_pending_count() {
        let mut src = MetricSource::new("a", "A", MetricSourceType::System);
        src.submit("lat", 1.0, 1);
        src.submit("lat", 2.0, 2);
        assert_eq!(src.pending_count(), 2);
    }

    #[test]
    fn test_collected_total_counter() {
        let mut eng = CollectorEngine::new();
        eng.add_source(MetricSource::new(
            "sys",
            "System",
            MetricSourceType::System,
        ));
        let mut reg = registry();
        for i in 0..5 {
            eng.submit("sys", "lat", i as f64, i).unwrap();
        }
        eng.collect(&mut reg);
        assert_eq!(eng.collected_total, 5);
    }
}
