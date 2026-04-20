// ═══════════════════════════════════════════════════════════════════════
// Batch — Batch export manager with backpressure signaling.
//
// Layer 3 defines the contract for batch export operations with
// backpressure signaling, so RUNE applications can implement flow
// control when their export target is overwhelmed.
// ═══════════════════════════════════════════════════════════════════════

use crate::event::UnifiedEvent;

// ── AcceptResult ──────────────────────────────────────────────────

#[derive(Debug)]
pub enum AcceptResult {
    /// Event queued successfully.
    Accepted,
    /// Batch is full — here are the events ready for export.
    BatchReady(Vec<UnifiedEvent>),
    /// Event dropped due to backpressure.
    Dropped,
}

// ── BatchExportConfig ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BatchExportConfig {
    pub max_batch_size: usize,
    pub max_pending_batches: usize,
    pub flush_interval_ms: i64,
}

impl Default for BatchExportConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            max_pending_batches: 10,
            flush_interval_ms: 5000,
        }
    }
}

// ── BatchExportStats ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BatchExportStats {
    pub batches_exported: u64,
    pub events_exported: u64,
    pub events_dropped: u64,
    pub pending_count: usize,
    pub backpressure_active: bool,
    pub drop_rate: String,
}

// ── BatchExportManager ────────────────────────────────────────────

pub struct BatchExportManager {
    config: BatchExportConfig,
    pending: Vec<UnifiedEvent>,
    batches_exported: u64,
    events_exported: u64,
    events_dropped: u64,
    last_flush_at: i64,
    backpressure_active: bool,
}

impl BatchExportManager {
    pub fn new(config: BatchExportConfig) -> Self {
        Self {
            config,
            pending: Vec::new(),
            batches_exported: 0,
            events_exported: 0,
            events_dropped: 0,
            last_flush_at: 0,
            backpressure_active: false,
        }
    }

    pub fn accept(&mut self, event: UnifiedEvent) -> AcceptResult {
        let max_pending = self.config.max_batch_size * self.config.max_pending_batches;
        if self.backpressure_active && self.pending.len() >= max_pending {
            self.events_dropped += 1;
            return AcceptResult::Dropped;
        }

        self.pending.push(event);

        // Under backpressure, don't auto-fire batches — the export target
        // is overwhelmed, so buffer up to max_pending then drop.
        // Callers can still use flush() to drain manually.
        if !self.backpressure_active && self.pending.len() >= self.config.max_batch_size {
            let batch: Vec<UnifiedEvent> = self.pending.drain(..).collect();
            let batch_len = batch.len() as u64;
            self.batches_exported += 1;
            self.events_exported += batch_len;
            AcceptResult::BatchReady(batch)
        } else {
            AcceptResult::Accepted
        }
    }

    pub fn flush(&mut self, now: i64) -> Option<Vec<UnifiedEvent>> {
        if self.pending.is_empty() {
            return None;
        }
        let elapsed = now - self.last_flush_at;
        if elapsed < self.config.flush_interval_ms {
            return None;
        }
        self.last_flush_at = now;
        let batch: Vec<UnifiedEvent> = self.pending.drain(..).collect();
        let batch_len = batch.len() as u64;
        self.batches_exported += 1;
        self.events_exported += batch_len;
        Some(batch)
    }

    pub fn signal_backpressure(&mut self, active: bool) {
        self.backpressure_active = active;
    }

    pub fn stats(&self) -> BatchExportStats {
        let total = self.events_exported + self.events_dropped;
        let drop_rate = if total > 0 {
            let rate = self.events_dropped as f64 / total as f64;
            format!("{:.4}", rate)
        } else {
            "0.0000".to_string()
        };
        BatchExportStats {
            batches_exported: self.batches_exported,
            events_exported: self.events_exported,
            events_dropped: self.events_dropped,
            pending_count: self.pending.len(),
            backpressure_active: self.backpressure_active,
            drop_rate,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use rune_security::SecuritySeverity;

    fn make_event(id: &str, ts: i64) -> UnifiedEvent {
        UnifiedEventBuilder::new(
            id,
            SourceCrate::RuneSecurity,
            EventCategory::ThreatDetection,
            "scan",
            ts,
        )
        .severity(SecuritySeverity::Medium)
        .build()
    }

    #[test]
    fn test_accept_returns_accepted_under_limit() {
        let config = BatchExportConfig {
            max_batch_size: 10,
            ..Default::default()
        };
        let mut mgr = BatchExportManager::new(config);
        let result = mgr.accept(make_event("e1", 100));
        assert!(matches!(result, AcceptResult::Accepted));
    }

    #[test]
    fn test_accept_returns_batch_ready_at_max() {
        let config = BatchExportConfig {
            max_batch_size: 2,
            ..Default::default()
        };
        let mut mgr = BatchExportManager::new(config);
        mgr.accept(make_event("e1", 100));
        let result = mgr.accept(make_event("e2", 200));
        match result {
            AcceptResult::BatchReady(batch) => assert_eq!(batch.len(), 2),
            _ => panic!("expected BatchReady"),
        }
    }

    #[test]
    fn test_accept_returns_dropped_under_backpressure() {
        // Under backpressure, BatchReady does NOT auto-fire — events buffer
        // up to max_pending, then get dropped.
        // max_pending = max_batch_size * max_pending_batches = 5 * 2 = 10
        let config = BatchExportConfig {
            max_batch_size: 5,
            max_pending_batches: 2,
            ..Default::default()
        };
        let mut mgr = BatchExportManager::new(config);
        mgr.signal_backpressure(true);

        // Fill to max_pending (10 events) — all should be Accepted
        for i in 0..10 {
            let result = mgr.accept(make_event(&format!("e{i}"), i as i64));
            assert!(matches!(result, AcceptResult::Accepted));
        }
        assert_eq!(mgr.stats().pending_count, 10);

        // 11th event exceeds max_pending — should be Dropped
        let result = mgr.accept(make_event("overflow", 9999));
        assert!(matches!(result, AcceptResult::Dropped));
        assert_eq!(mgr.stats().events_dropped, 1);
        assert_eq!(mgr.stats().pending_count, 10);
    }

    #[test]
    fn test_flush_returns_pending_events() {
        let config = BatchExportConfig {
            max_batch_size: 100,
            flush_interval_ms: 1000,
            ..Default::default()
        };
        let mut mgr = BatchExportManager::new(config);
        mgr.accept(make_event("e1", 100));
        mgr.accept(make_event("e2", 200));
        let flushed = mgr.flush(5000);
        assert!(flushed.is_some());
        assert_eq!(flushed.unwrap().len(), 2);
    }

    #[test]
    fn test_flush_returns_none_when_empty() {
        let config = BatchExportConfig::default();
        let mut mgr = BatchExportManager::new(config);
        assert!(mgr.flush(5000).is_none());
    }

    #[test]
    fn test_stats_tracks_exported_and_dropped() {
        let config = BatchExportConfig {
            max_batch_size: 2,
            max_pending_batches: 1,
            ..Default::default()
        };
        let mut mgr = BatchExportManager::new(config);
        mgr.accept(make_event("e1", 100));
        mgr.accept(make_event("e2", 200)); // BatchReady
        let stats = mgr.stats();
        assert_eq!(stats.batches_exported, 1);
        assert_eq!(stats.events_exported, 2);
        assert_eq!(stats.events_dropped, 0);
        assert!(!stats.backpressure_active);
    }

    #[test]
    fn test_signal_backpressure_toggles() {
        let config = BatchExportConfig::default();
        let mut mgr = BatchExportManager::new(config);
        assert!(!mgr.stats().backpressure_active);
        mgr.signal_backpressure(true);
        assert!(mgr.stats().backpressure_active);
        mgr.signal_backpressure(false);
        assert!(!mgr.stats().backpressure_active);
    }

    #[test]
    fn test_flush_respects_interval() {
        let config = BatchExportConfig {
            max_batch_size: 100,
            flush_interval_ms: 5000,
            ..Default::default()
        };
        let mut mgr = BatchExportManager::new(config);
        mgr.accept(make_event("e1", 100));
        // Too early to flush
        assert!(mgr.flush(3000).is_none());
        // After interval
        let flushed = mgr.flush(6000);
        assert!(flushed.is_some());
    }
}
