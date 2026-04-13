// ═══════════════════════════════════════════════════════════════════════
// Audit — Meta-audit events for rune-audit-ext's own operations.
//
// Tracks ingestion, queries, exports, retention actions, correlation
// runs, chain verification, and timeline generation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── AuditExtEventType ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditExtEventType {
    EventIngested { event_id: String, source: String },
    BatchIngested { count: usize },
    QueryExecuted { filter_count: usize, result_count: usize },
    Exported { format: String, event_count: usize },
    RetentionApplied { policy: String, removed: usize },
    CorrelationRun { chains_found: usize },
    ChainVerified { status: String },
    TimelineGenerated { entry_count: usize },
}

impl fmt::Display for AuditExtEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventIngested { event_id, source } => {
                write!(f, "event-ingested:{event_id} from {source}")
            }
            Self::BatchIngested { count } => write!(f, "batch-ingested:{count} events"),
            Self::QueryExecuted {
                filter_count,
                result_count,
            } => write!(f, "query-executed:{filter_count} filters, {result_count} results"),
            Self::Exported {
                format,
                event_count,
            } => write!(f, "exported:{format} ({event_count} events)"),
            Self::RetentionApplied { policy, removed } => {
                write!(f, "retention-applied:{policy} ({removed} removed)")
            }
            Self::CorrelationRun { chains_found } => {
                write!(f, "correlation-run:{chains_found} chains")
            }
            Self::ChainVerified { status } => write!(f, "chain-verified:{status}"),
            Self::TimelineGenerated { entry_count } => {
                write!(f, "timeline-generated:{entry_count} entries")
            }
        }
    }
}

impl AuditExtEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::EventIngested { .. } => "event-ingested",
            Self::BatchIngested { .. } => "batch-ingested",
            Self::QueryExecuted { .. } => "query-executed",
            Self::Exported { .. } => "exported",
            Self::RetentionApplied { .. } => "retention-applied",
            Self::CorrelationRun { .. } => "correlation-run",
            Self::ChainVerified { .. } => "chain-verified",
            Self::TimelineGenerated { .. } => "timeline-generated",
        }
    }
}

// ── AuditExtAuditEvent ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuditExtAuditEvent {
    pub event_type: AuditExtEventType,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
}

impl AuditExtAuditEvent {
    pub fn new(
        event_type: AuditExtEventType,
        actor: impl Into<String>,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
        }
    }
}

// ── AuditExtLog ─────────────────────────────────────────────────────

#[derive(Default)]
pub struct AuditExtLog {
    pub events: Vec<AuditExtAuditEvent>,
}

impl AuditExtLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: AuditExtAuditEvent) {
        self.events.push(event);
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&AuditExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.type_name() == type_name)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&AuditExtAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_retrieve() {
        let mut log = AuditExtLog::new();
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::EventIngested {
                event_id: "e1".into(),
                source: "rune-security".into(),
            },
            "system",
            1000,
            "ingested",
        ));
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_events_by_type() {
        let mut log = AuditExtLog::new();
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::EventIngested {
                event_id: "e1".into(),
                source: "rune-security".into(),
            },
            "system",
            1000,
            "ingested",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::QueryExecuted {
                filter_count: 2,
                result_count: 10,
            },
            "alice",
            2000,
            "queried",
        ));
        assert_eq!(log.events_by_type("event-ingested").len(), 1);
        assert_eq!(log.events_by_type("query-executed").len(), 1);
    }

    #[test]
    fn test_since_filter() {
        let mut log = AuditExtLog::new();
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::BatchIngested { count: 5 },
            "system",
            1000,
            "batch",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::Exported {
                format: "csv".into(),
                event_count: 100,
            },
            "system",
            2000,
            "exported",
        ));
        assert_eq!(log.since(1500).len(), 1);
    }

    #[test]
    fn test_all_event_type_displays() {
        let types = vec![
            AuditExtEventType::EventIngested { event_id: "e1".into(), source: "s".into() },
            AuditExtEventType::BatchIngested { count: 5 },
            AuditExtEventType::QueryExecuted { filter_count: 2, result_count: 10 },
            AuditExtEventType::Exported { format: "csv".into(), event_count: 100 },
            AuditExtEventType::RetentionApplied { policy: "p1".into(), removed: 50 },
            AuditExtEventType::CorrelationRun { chains_found: 3 },
            AuditExtEventType::ChainVerified { status: "valid".into() },
            AuditExtEventType::TimelineGenerated { entry_count: 20 },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
            assert!(!t.type_name().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_retention_and_correlation_events() {
        let mut log = AuditExtLog::new();
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::RetentionApplied { policy: "default".into(), removed: 10 },
            "system",
            1000,
            "retention",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::CorrelationRun { chains_found: 5 },
            "system",
            2000,
            "correlation",
        ));
        assert_eq!(log.events_by_type("retention-applied").len(), 1);
        assert_eq!(log.events_by_type("correlation-run").len(), 1);
    }
}
