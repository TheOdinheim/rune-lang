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
    ChainAuthenticated { event_count: usize, algorithm: String },
    StorageCompacted { before_count: usize, after_count: usize },
    IndexRebuilt { indexed_events: usize },
    EventEnriched { event_id: String, enrichments_applied: usize },
    ArchiveCompleted { archived_count: usize, policy: String },
    RetentionValidated { policy_count: usize, issues: usize },
    ExportValidated { format: String, event_count: usize, valid: bool },
    // Layer 3
    ExportFormatted { format: String, event_count: String },
    ExportBatchCompleted { batch_size: String, format: String },
    BackpressureActivated { pending: String },
    BackpressureDeactivated { pending: String },
    EventDropped { reason: String },
    SubscriberRegistered { subscriber_id: String },
    SubscriberRemoved { subscriber_id: String },
    EnrichmentApplied { enricher: String, events: String },
    L3QueryExecuted { filters: String, results: String },
    BackendFlushed { events: String },
    ChainIntegrityChecked { valid: bool, verified: String },
    StorageBackendChanged { backend_type: String },
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
            Self::ChainAuthenticated { event_count, algorithm } => {
                write!(f, "chain-authenticated:{event_count} events via {algorithm}")
            }
            Self::StorageCompacted { before_count, after_count } => {
                write!(f, "storage-compacted:{before_count}->{after_count}")
            }
            Self::IndexRebuilt { indexed_events } => {
                write!(f, "index-rebuilt:{indexed_events} events")
            }
            Self::EventEnriched { event_id, enrichments_applied } => {
                write!(f, "event-enriched:{event_id} ({enrichments_applied} enrichments)")
            }
            Self::ArchiveCompleted { archived_count, policy } => {
                write!(f, "archive-completed:{archived_count} events ({policy})")
            }
            Self::RetentionValidated { policy_count, issues } => {
                write!(f, "retention-validated:{policy_count} policies ({issues} issues)")
            }
            Self::ExportValidated { format, event_count, valid } => {
                write!(f, "export-validated:{format} ({event_count} events, valid={valid})")
            }
            // Layer 3
            Self::ExportFormatted { format, event_count } => {
                write!(f, "export-formatted:{format} ({event_count} events)")
            }
            Self::ExportBatchCompleted { batch_size, format } => {
                write!(f, "export-batch-completed:{batch_size} events ({format})")
            }
            Self::BackpressureActivated { pending } => {
                write!(f, "backpressure-activated:{pending} pending")
            }
            Self::BackpressureDeactivated { pending } => {
                write!(f, "backpressure-deactivated:{pending} pending")
            }
            Self::EventDropped { reason } => write!(f, "event-dropped:{reason}"),
            Self::SubscriberRegistered { subscriber_id } => {
                write!(f, "subscriber-registered:{subscriber_id}")
            }
            Self::SubscriberRemoved { subscriber_id } => {
                write!(f, "subscriber-removed:{subscriber_id}")
            }
            Self::EnrichmentApplied { enricher, events } => {
                write!(f, "enrichment-applied:{enricher} ({events} events)")
            }
            Self::L3QueryExecuted { filters, results } => {
                write!(f, "l3-query-executed:{filters} filters ({results} results)")
            }
            Self::BackendFlushed { events } => write!(f, "backend-flushed:{events} events"),
            Self::ChainIntegrityChecked { valid, verified } => {
                write!(f, "chain-integrity-checked:valid={valid} ({verified} verified)")
            }
            Self::StorageBackendChanged { backend_type } => {
                write!(f, "storage-backend-changed:{backend_type}")
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
            Self::ChainAuthenticated { .. } => "chain-authenticated",
            Self::StorageCompacted { .. } => "storage-compacted",
            Self::IndexRebuilt { .. } => "index-rebuilt",
            Self::EventEnriched { .. } => "event-enriched",
            Self::ArchiveCompleted { .. } => "archive-completed",
            Self::RetentionValidated { .. } => "retention-validated",
            Self::ExportValidated { .. } => "export-validated",
            // Layer 3
            Self::ExportFormatted { .. } => "export-formatted",
            Self::ExportBatchCompleted { .. } => "export-batch-completed",
            Self::BackpressureActivated { .. } => "backpressure-activated",
            Self::BackpressureDeactivated { .. } => "backpressure-deactivated",
            Self::EventDropped { .. } => "event-dropped",
            Self::SubscriberRegistered { .. } => "subscriber-registered",
            Self::SubscriberRemoved { .. } => "subscriber-removed",
            Self::EnrichmentApplied { .. } => "enrichment-applied",
            Self::L3QueryExecuted { .. } => "l3-query-executed",
            Self::BackendFlushed { .. } => "backend-flushed",
            Self::ChainIntegrityChecked { .. } => "chain-integrity-checked",
            Self::StorageBackendChanged { .. } => "storage-backend-changed",
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
            AuditExtEventType::ChainAuthenticated { event_count: 10, algorithm: "HMAC-SHA3-256".into() },
            AuditExtEventType::StorageCompacted { before_count: 100, after_count: 80 },
            AuditExtEventType::IndexRebuilt { indexed_events: 50 },
            AuditExtEventType::EventEnriched { event_id: "e2".into(), enrichments_applied: 3 },
            AuditExtEventType::ArchiveCompleted { archived_count: 25, policy: "p1".into() },
            AuditExtEventType::RetentionValidated { policy_count: 3, issues: 1 },
            AuditExtEventType::ExportValidated { format: "cef".into(), event_count: 50, valid: true },
            // Layer 3
            AuditExtEventType::ExportFormatted { format: "CEF".into(), event_count: "10".into() },
            AuditExtEventType::ExportBatchCompleted { batch_size: "100".into(), format: "JSON".into() },
            AuditExtEventType::BackpressureActivated { pending: "500".into() },
            AuditExtEventType::BackpressureDeactivated { pending: "50".into() },
            AuditExtEventType::EventDropped { reason: "backpressure".into() },
            AuditExtEventType::SubscriberRegistered { subscriber_id: "sub-1".into() },
            AuditExtEventType::SubscriberRemoved { subscriber_id: "sub-1".into() },
            AuditExtEventType::EnrichmentApplied { enricher: "SeverityMapper".into(), events: "5".into() },
            AuditExtEventType::L3QueryExecuted { filters: "3".into(), results: "42".into() },
            AuditExtEventType::BackendFlushed { events: "10".into() },
            AuditExtEventType::ChainIntegrityChecked { valid: true, verified: "100".into() },
            AuditExtEventType::StorageBackendChanged { backend_type: "InMemory".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
            assert!(!t.type_name().is_empty());
        }
        assert_eq!(types.len(), 27);
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

    #[test]
    fn test_new_layer2_event_types() {
        let mut log = AuditExtLog::new();
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::ChainAuthenticated { event_count: 10, algorithm: "HMAC-SHA3-256".into() },
            "system", 1000, "authenticated",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::StorageCompacted { before_count: 100, after_count: 80 },
            "system", 2000, "compacted",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::IndexRebuilt { indexed_events: 50 },
            "system", 3000, "rebuilt",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::EventEnriched { event_id: "e1".into(), enrichments_applied: 3 },
            "system", 4000, "enriched",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::ArchiveCompleted { archived_count: 25, policy: "p1".into() },
            "system", 5000, "archived",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::RetentionValidated { policy_count: 3, issues: 1 },
            "system", 6000, "validated",
        ));
        log.record(AuditExtAuditEvent::new(
            AuditExtEventType::ExportValidated { format: "cef".into(), event_count: 50, valid: true },
            "system", 7000, "export-validated",
        ));
        assert_eq!(log.count(), 7);
        assert_eq!(log.events_by_type("chain-authenticated").len(), 1);
        assert_eq!(log.events_by_type("storage-compacted").len(), 1);
        assert_eq!(log.events_by_type("index-rebuilt").len(), 1);
        assert_eq!(log.events_by_type("event-enriched").len(), 1);
        assert_eq!(log.events_by_type("archive-completed").len(), 1);
        assert_eq!(log.events_by_type("retention-validated").len(), 1);
        assert_eq!(log.events_by_type("export-validated").len(), 1);
    }
}
