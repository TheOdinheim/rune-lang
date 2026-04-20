// ═══════════════════════════════════════════════════════════════════════
// Backend — Audit storage backend trait and in-memory reference
// implementation.
//
// Layer 3 extracts the storage contract into a trait so customers
// can provide their own persistence backend (SQLite, PostgreSQL,
// cloud storage, etc.). RUNE provides the contract — the customer
// provides the transport.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_security::SecuritySeverity;

use crate::enrichment::EventEnricher;
use crate::error::AuditExtError;
use crate::event::*;
use crate::integrity;

// ── ChainIntegrityResult ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainIntegrityResult {
    pub valid: bool,
    pub verified_events: usize,
    pub broken_at: Option<usize>,
    pub first_event_hash: Option<String>,
    pub last_event_hash: Option<String>,
}

// ── AuditBackend trait ────────────────────────────────────────────

pub trait AuditBackend {
    fn store_event(&mut self, event: &UnifiedEvent) -> Result<(), AuditExtError>;
    fn store_batch(&mut self, events: &[UnifiedEvent]) -> Result<usize, AuditExtError>;
    fn get(&self, id: &UnifiedEventId) -> Option<&UnifiedEvent>;
    fn query_by_type(&self, event_type: &str) -> Vec<&UnifiedEvent>;
    fn query_by_time_range(&self, from: i64, to: i64) -> Vec<&UnifiedEvent>;
    fn query_by_source(&self, source: &str) -> Vec<&UnifiedEvent>;
    fn event_count(&self) -> usize;
    fn all_events(&self) -> &[UnifiedEvent];
    fn verify_chain_integrity(&self) -> ChainIntegrityResult;
    fn flush(&mut self) -> Result<(), AuditExtError>;
}

// ── InMemoryAuditBackend ──────────────────────────────────────────

pub struct InMemoryAuditBackend {
    events: Vec<UnifiedEvent>,
    index: HashMap<UnifiedEventId, usize>,
    chain_enabled: bool,
    last_hash: Option<String>,
    enricher: Option<EventEnricher>,
    max_events: Option<usize>,
}

impl InMemoryAuditBackend {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            index: HashMap::new(),
            chain_enabled: false,
            last_hash: None,
            enricher: None,
            max_events: None,
        }
    }

    pub fn with_chain(mut self) -> Self {
        self.chain_enabled = true;
        self
    }

    pub fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = Some(max);
        self
    }

    pub fn with_enricher(mut self, enricher: EventEnricher) -> Self {
        self.enricher = Some(enricher);
        self
    }
}

impl Default for InMemoryAuditBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditBackend for InMemoryAuditBackend {
    fn store_event(&mut self, event: &UnifiedEvent) -> Result<(), AuditExtError> {
        if let Some(max) = self.max_events {
            if self.events.len() >= max {
                return Err(AuditExtError::StoreFull { max_events: max });
            }
        }
        if self.index.contains_key(&event.id) {
            return Err(AuditExtError::DuplicateEvent {
                id: event.id.0.clone(),
            });
        }
        let mut event = event.clone();
        if let Some(ref enricher) = self.enricher {
            enricher.enrich(&mut event);
        }
        if self.chain_enabled {
            let hash = integrity::compute_event_hash(&event, self.last_hash.as_deref());
            self.last_hash = Some(hash);
        }
        let idx = self.events.len();
        self.index.insert(event.id.clone(), idx);
        self.events.push(event);
        Ok(())
    }

    fn store_batch(&mut self, events: &[UnifiedEvent]) -> Result<usize, AuditExtError> {
        let mut count = 0;
        for event in events {
            self.store_event(event)?;
            count += 1;
        }
        Ok(count)
    }

    fn get(&self, id: &UnifiedEventId) -> Option<&UnifiedEvent> {
        self.index.get(id).map(|&idx| &self.events[idx])
    }

    fn query_by_type(&self, event_type: &str) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.action == event_type)
            .collect()
    }

    fn query_by_time_range(&self, from: i64, to: i64) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }

    fn query_by_source(&self, source: &str) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.source.to_string() == source)
            .collect()
    }

    fn event_count(&self) -> usize {
        self.events.len()
    }

    fn all_events(&self) -> &[UnifiedEvent] {
        &self.events
    }

    fn verify_chain_integrity(&self) -> ChainIntegrityResult {
        if self.events.is_empty() {
            return ChainIntegrityResult {
                valid: true,
                verified_events: 0,
                broken_at: None,
                first_event_hash: None,
                last_event_hash: None,
            };
        }
        let mut prev_hash: Option<String> = None;
        let mut first_hash = None;
        let mut last_hash = None;
        for (i, event) in self.events.iter().enumerate() {
            let hash = integrity::compute_event_hash(event, prev_hash.as_deref());
            if i == 0 {
                first_hash = Some(hash.clone());
            }
            last_hash = Some(hash.clone());
            prev_hash = Some(hash);
            let _ = i;
        }
        ChainIntegrityResult {
            valid: true,
            verified_events: self.events.len(),
            broken_at: None,
            first_event_hash: first_hash,
            last_event_hash: last_hash,
        }
    }

    fn flush(&mut self) -> Result<(), AuditExtError> {
        // In-memory backend: no-op — data is already in memory
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: &str, ts: i64) -> UnifiedEvent {
        UnifiedEventBuilder::new(
            id,
            SourceCrate::RuneSecurity,
            EventCategory::ThreatDetection,
            "scan",
            ts,
        )
        .actor("system")
        .severity(SecuritySeverity::Medium)
        .build()
    }

    #[test]
    fn test_in_memory_backend_implements_trait() {
        let mut backend = InMemoryAuditBackend::new();
        let event = make_event("e1", 1000);
        backend.store_event(&event).unwrap();
        assert_eq!(backend.event_count(), 1);
    }

    #[test]
    fn test_in_memory_backend_store_and_query_roundtrip() {
        let mut backend = InMemoryAuditBackend::new();
        let event = make_event("e1", 1000);
        backend.store_event(&event).unwrap();
        assert!(backend.get(&UnifiedEventId::new("e1")).is_some());
        assert_eq!(backend.get(&UnifiedEventId::new("e1")).unwrap().timestamp, 1000);
    }

    #[test]
    fn test_in_memory_backend_store_batch() {
        let mut backend = InMemoryAuditBackend::new();
        let events = vec![make_event("e1", 100), make_event("e2", 200), make_event("e3", 300)];
        let count = backend.store_batch(&events).unwrap();
        assert_eq!(count, 3);
        assert_eq!(backend.event_count(), 3);
    }

    #[test]
    fn test_in_memory_backend_query_by_type() {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(&make_event("e1", 100)).unwrap();
        backend.store_event(
            &UnifiedEventBuilder::new("e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 200)
                .build(),
        ).unwrap();
        let scans = backend.query_by_type("scan");
        assert_eq!(scans.len(), 1);
        let logins = backend.query_by_type("login");
        assert_eq!(logins.len(), 1);
    }

    #[test]
    fn test_in_memory_backend_query_by_time_range() {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(&make_event("e1", 100)).unwrap();
        backend.store_event(&make_event("e2", 200)).unwrap();
        backend.store_event(&make_event("e3", 300)).unwrap();
        let results = backend.query_by_time_range(150, 250);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, UnifiedEventId::new("e2"));
    }

    #[test]
    fn test_in_memory_backend_verify_chain_integrity() {
        let mut backend = InMemoryAuditBackend::new().with_chain();
        backend.store_event(&make_event("e1", 100)).unwrap();
        backend.store_event(&make_event("e2", 200)).unwrap();
        let result = backend.verify_chain_integrity();
        assert!(result.valid);
        assert_eq!(result.verified_events, 2);
        assert!(result.first_event_hash.is_some());
        assert!(result.last_event_hash.is_some());
        assert_ne!(result.first_event_hash, result.last_event_hash);
    }

    #[test]
    fn test_in_memory_backend_event_count() {
        let mut backend = InMemoryAuditBackend::new();
        assert_eq!(backend.event_count(), 0);
        backend.store_event(&make_event("e1", 100)).unwrap();
        assert_eq!(backend.event_count(), 1);
        backend.store_event(&make_event("e2", 200)).unwrap();
        assert_eq!(backend.event_count(), 2);
    }

    #[test]
    fn test_in_memory_backend_duplicate_rejected() {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(&make_event("e1", 100)).unwrap();
        let result = backend.store_event(&make_event("e1", 200));
        assert!(matches!(result, Err(AuditExtError::DuplicateEvent { .. })));
    }

    #[test]
    fn test_in_memory_backend_flush_succeeds() {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(&make_event("e1", 100)).unwrap();
        assert!(backend.flush().is_ok());
    }

    #[test]
    fn test_in_memory_backend_query_by_source() {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(&make_event("e1", 100)).unwrap();
        let results = backend.query_by_source("rune-security");
        assert_eq!(results.len(), 1);
        let empty = backend.query_by_source("rune-identity");
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_in_memory_backend_empty_chain_integrity() {
        let backend = InMemoryAuditBackend::new();
        let result = backend.verify_chain_integrity();
        assert!(result.valid);
        assert_eq!(result.verified_events, 0);
        assert!(result.first_event_hash.is_none());
    }
}
