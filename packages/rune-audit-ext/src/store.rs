// ═══════════════════════════════════════════════════════════════════════
// Store — Unified audit store with ingestion, retrieval, and
// distribution queries. Ingestion helper free functions create
// UnifiedEvents from string parameters so callers do not need to
// depend on every source crate.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_security::SecuritySeverity;

use crate::enrichment::EventEnricher;
use crate::error::AuditExtError;
use crate::event::*;
use crate::integrity;

// ── EventIndex ─────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct EventIndex {
    pub by_source: HashMap<SourceCrate, Vec<usize>>,
    pub by_category: HashMap<EventCategory, Vec<usize>>,
    pub by_correlation: HashMap<String, Vec<usize>>,
    pub by_actor: HashMap<String, Vec<usize>>,
}

impl EventIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(events: &[UnifiedEvent]) -> Self {
        let mut idx = Self::new();
        for (i, event) in events.iter().enumerate() {
            idx.add(i, event);
        }
        idx
    }

    pub fn add(&mut self, position: usize, event: &UnifiedEvent) {
        self.by_source.entry(event.source).or_default().push(position);
        self.by_category.entry(event.category).or_default().push(position);
        if let Some(ref cid) = event.correlation_id {
            self.by_correlation.entry(cid.clone()).or_default().push(position);
        }
        if !event.actor.is_empty() {
            self.by_actor.entry(event.actor.clone()).or_default().push(position);
        }
    }

    pub fn clear(&mut self) {
        self.by_source.clear();
        self.by_category.clear();
        self.by_correlation.clear();
        self.by_actor.clear();
    }
}

// ── StorageStats ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_events: usize,
    pub unique_sources: usize,
    pub unique_categories: usize,
    pub unique_actors: usize,
    pub unique_correlations: usize,
    pub oldest_timestamp: Option<i64>,
    pub newest_timestamp: Option<i64>,
    pub memory_estimate_bytes: usize,
}

// ── AuditStore ──────────────────────────────────────────────────────

pub struct AuditStore {
    events: Vec<UnifiedEvent>,
    index: HashMap<UnifiedEventId, usize>,
    event_index: EventIndex,
    pub max_events: Option<usize>,
    pub chain_enabled: bool,
    pub last_hash: Option<String>,
    enricher: Option<EventEnricher>,
    archived: Vec<UnifiedEvent>,
}

impl AuditStore {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            index: HashMap::new(),
            event_index: EventIndex::new(),
            max_events: None,
            chain_enabled: false,
            last_hash: None,
            enricher: None,
            archived: Vec::new(),
        }
    }

    pub fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = Some(max);
        self
    }

    pub fn with_chain(mut self) -> Self {
        self.chain_enabled = true;
        self
    }

    pub fn with_enricher(mut self, enricher: EventEnricher) -> Self {
        self.enricher = Some(enricher);
        self
    }

    pub fn set_enricher(&mut self, enricher: EventEnricher) {
        self.enricher = Some(enricher);
    }

    pub fn ingest(&mut self, mut event: UnifiedEvent) -> Result<(), AuditExtError> {
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
        if let Some(ref enricher) = self.enricher {
            enricher.enrich(&mut event);
        }
        if self.chain_enabled {
            let hash = integrity::compute_event_hash(&event, self.last_hash.as_deref());
            self.last_hash = Some(hash);
        }
        let idx = self.events.len();
        self.index.insert(event.id.clone(), idx);
        self.event_index.add(idx, &event);
        self.events.push(event);
        Ok(())
    }

    pub fn ingest_batch(
        &mut self,
        events: Vec<UnifiedEvent>,
    ) -> Result<usize, AuditExtError> {
        let mut count = 0;
        for event in events {
            self.ingest(event)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn get(&self, id: &UnifiedEventId) -> Option<&UnifiedEvent> {
        self.index.get(id).map(|&idx| &self.events[idx])
    }

    pub fn latest(&self, n: usize) -> Vec<&UnifiedEvent> {
        let len = self.events.len();
        let start = len.saturating_sub(n);
        self.events[start..].iter().collect()
    }

    pub fn events_since(&self, timestamp: i64) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn events_between(&self, start: i64, end: i64) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    pub fn events_by_source(&self, source: SourceCrate) -> Vec<&UnifiedEvent> {
        if let Some(indices) = self.event_index.by_source.get(&source) {
            indices.iter().map(|&i| &self.events[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn events_by_category(&self, category: EventCategory) -> Vec<&UnifiedEvent> {
        if let Some(indices) = self.event_index.by_category.get(&category) {
            indices.iter().map(|&i| &self.events[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn events_by_severity(&self, severity: SecuritySeverity) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.severity >= severity)
            .collect()
    }

    pub fn events_by_actor(&self, actor: &str) -> Vec<&UnifiedEvent> {
        if let Some(indices) = self.event_index.by_actor.get(actor) {
            indices.iter().map(|&i| &self.events[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn events_by_subject(&self, subject: &str) -> Vec<&UnifiedEvent> {
        self.events
            .iter()
            .filter(|e| e.subject == subject)
            .collect()
    }

    pub fn events_by_correlation(&self, correlation_id: &str) -> Vec<&UnifiedEvent> {
        if let Some(indices) = self.event_index.by_correlation.get(correlation_id) {
            indices.iter().map(|&i| &self.events[i]).collect()
        } else {
            Vec::new()
        }
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }

    pub fn all_events(&self) -> &[UnifiedEvent] {
        &self.events
    }

    /// Remove events by predicate. Returns count removed.
    /// Critical+ events are never removed.
    pub fn remove_where<F>(&mut self, predicate: F) -> usize
    where
        F: Fn(&UnifiedEvent) -> bool,
    {
        let before = self.events.len();
        self.events.retain(|e| {
            if e.severity >= SecuritySeverity::Critical {
                return true; // never remove Critical+
            }
            !predicate(e)
        });
        // Rebuild indices
        self.index.clear();
        self.event_index.clear();
        for (idx, event) in self.events.iter().enumerate() {
            self.index.insert(event.id.clone(), idx);
            self.event_index.add(idx, event);
        }
        before - self.events.len()
    }

    // ── Distribution methods ────────────────────────────────────────

    pub fn distribution_by_source(&self) -> HashMap<SourceCrate, usize> {
        let mut map = HashMap::new();
        for e in &self.events {
            *map.entry(e.source).or_insert(0) += 1;
        }
        map
    }

    pub fn distribution_by_category(&self) -> HashMap<EventCategory, usize> {
        let mut map = HashMap::new();
        for e in &self.events {
            *map.entry(e.category).or_insert(0) += 1;
        }
        map
    }

    pub fn distribution_by_severity(&self) -> HashMap<SecuritySeverity, usize> {
        let mut map = HashMap::new();
        for e in &self.events {
            *map.entry(e.severity).or_insert(0) += 1;
        }
        map
    }

    pub fn events_per_second(&self) -> f64 {
        if self.events.len() < 2 {
            return 0.0;
        }
        let first = self.events.first().unwrap().timestamp;
        let last = self.events.last().unwrap().timestamp;
        let span = last - first;
        if span <= 0 {
            return 0.0;
        }
        self.events.len() as f64 / span as f64
    }

    // ── Storage abstraction (Layer 2) ──────────────────────────────

    pub fn storage_stats(&self) -> StorageStats {
        let oldest = self.events.first().map(|e| e.timestamp);
        let newest = self.events.last().map(|e| e.timestamp);
        StorageStats {
            total_events: self.events.len(),
            unique_sources: self.event_index.by_source.len(),
            unique_categories: self.event_index.by_category.len(),
            unique_actors: self.event_index.by_actor.len(),
            unique_correlations: self.event_index.by_correlation.len(),
            oldest_timestamp: oldest,
            newest_timestamp: newest,
            memory_estimate_bytes: self.memory_estimate(),
        }
    }

    pub fn memory_estimate(&self) -> usize {
        let base = std::mem::size_of::<Self>();
        let events_size = self.events.len() * 256;
        let id_index_size = self.index.len() * 64;
        let event_index_size = (self.event_index.by_source.len()
            + self.event_index.by_category.len()
            + self.event_index.by_actor.len()
            + self.event_index.by_correlation.len()) * 48;
        base + events_size + id_index_size + event_index_size
    }

    pub fn compact(&mut self) -> usize {
        let before = self.events.len();
        self.events.shrink_to_fit();
        self.index.shrink_to_fit();
        before
    }

    pub fn snapshot(&self) -> Vec<UnifiedEvent> {
        self.events.clone()
    }

    pub fn restore(&mut self, events: Vec<UnifiedEvent>) {
        self.events.clear();
        self.index.clear();
        self.event_index.clear();
        self.last_hash = None;
        for event in events {
            let _ = self.ingest(event);
        }
    }

    pub fn merge(&mut self, other: &AuditStore) -> usize {
        let mut merged = 0;
        for event in &other.events {
            if !self.index.contains_key(&event.id) {
                if self.ingest(event.clone()).is_ok() {
                    merged += 1;
                }
            }
        }
        merged
    }

    pub fn rebuild_index(&mut self) {
        self.index.clear();
        self.event_index.clear();
        for (idx, event) in self.events.iter().enumerate() {
            self.index.insert(event.id.clone(), idx);
            self.event_index.add(idx, event);
        }
    }

    pub fn event_index(&self) -> &EventIndex {
        &self.event_index
    }

    // ── Archive (Layer 2) ──────────────────────────────────────────

    pub fn archived_events(&self) -> &[UnifiedEvent] {
        &self.archived
    }

    pub fn archived_count(&self) -> usize {
        self.archived.len()
    }

    pub fn archive_where<F>(&mut self, predicate: F) -> usize
    where
        F: Fn(&UnifiedEvent) -> bool,
    {
        let mut to_archive = Vec::new();
        let mut to_keep = Vec::new();
        for event in self.events.drain(..) {
            if event.severity >= SecuritySeverity::Critical {
                to_keep.push(event);
            } else if predicate(&event) {
                to_archive.push(event);
            } else {
                to_keep.push(event);
            }
        }
        let archived_count = to_archive.len();
        self.archived.extend(to_archive);
        self.events = to_keep;
        self.rebuild_index();
        archived_count
    }
}

impl Default for AuditStore {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Ingestion helpers — free functions that create UnifiedEvents from
// string parameters. Callers use these instead of importing source
// crate types.
// ═══════════════════════════════════════════════════════════════════════

pub fn ingest_security_event(
    id: &str,
    action: &str,
    severity: SecuritySeverity,
    actor: &str,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneSecurity, EventCategory::ThreatDetection, action, timestamp)
        .severity(severity)
        .actor(actor)
        .detail(detail)
        .build()
}

pub fn ingest_identity_event(
    id: &str,
    action: &str,
    actor: &str,
    subject: &str,
    outcome: EventOutcome,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneIdentity, EventCategory::Authentication, action, timestamp)
        .actor(actor)
        .subject(subject)
        .outcome(outcome)
        .build()
}

pub fn ingest_permission_event(
    id: &str,
    action: &str,
    actor: &str,
    subject: &str,
    outcome: EventOutcome,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RunePermissions, EventCategory::Authorization, action, timestamp)
        .actor(actor)
        .subject(subject)
        .outcome(outcome)
        .build()
}

pub fn ingest_privacy_event(
    id: &str,
    action: &str,
    actor: &str,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RunePrivacy, EventCategory::Privacy, action, timestamp)
        .actor(actor)
        .detail(detail)
        .build()
}

pub fn ingest_detection_event(
    id: &str,
    action: &str,
    severity: SecuritySeverity,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneDetection, EventCategory::ThreatDetection, action, timestamp)
        .severity(severity)
        .detail(detail)
        .build()
}

pub fn ingest_shield_event(
    id: &str,
    action: &str,
    severity: SecuritySeverity,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneShield, EventCategory::ThreatResponse, action, timestamp)
        .severity(severity)
        .detail(detail)
        .build()
}

pub fn ingest_monitoring_event(
    id: &str,
    action: &str,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneMonitoring, EventCategory::Availability, action, timestamp)
        .detail(detail)
        .build()
}

pub fn ingest_provenance_event(
    id: &str,
    action: &str,
    subject: &str,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneProvenance, EventCategory::Integrity, action, timestamp)
        .subject(subject)
        .detail(detail)
        .build()
}

pub fn ingest_truth_event(
    id: &str,
    action: &str,
    subject: &str,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneTruth, EventCategory::Integrity, action, timestamp)
        .subject(subject)
        .detail(detail)
        .build()
}

pub fn ingest_document_event(
    id: &str,
    action: &str,
    subject: &str,
    detail: &str,
    timestamp: i64,
) -> UnifiedEvent {
    UnifiedEventBuilder::new(id, SourceCrate::RuneDocument, EventCategory::Compliance, action, timestamp)
        .subject(subject)
        .detail(detail)
        .build()
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
    fn test_ingest_and_get() {
        let mut store = AuditStore::new();
        let evt = make_event("e1", 1000);
        store.ingest(evt).unwrap();
        assert_eq!(store.count(), 1);
        assert!(store.get(&UnifiedEventId::new("e1")).is_some());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 1000)).unwrap();
        let result = store.ingest(make_event("e1", 2000));
        assert!(matches!(result, Err(AuditExtError::DuplicateEvent { .. })));
    }

    #[test]
    fn test_store_full() {
        let mut store = AuditStore::new().with_max_events(1);
        store.ingest(make_event("e1", 1000)).unwrap();
        let result = store.ingest(make_event("e2", 2000));
        assert!(matches!(result, Err(AuditExtError::StoreFull { .. })));
    }

    #[test]
    fn test_latest() {
        let mut store = AuditStore::new();
        for i in 0..5 {
            store
                .ingest(make_event(&format!("e{i}"), i * 100))
                .unwrap();
        }
        let latest = store.latest(2);
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].id, UnifiedEventId::new("e3"));
        assert_eq!(latest[1].id, UnifiedEventId::new("e4"));
    }

    #[test]
    fn test_events_since() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        store.ingest(make_event("e3", 300)).unwrap();
        assert_eq!(store.events_since(200).len(), 2);
    }

    #[test]
    fn test_events_between() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        store.ingest(make_event("e3", 300)).unwrap();
        assert_eq!(store.events_between(150, 250).len(), 1);
    }

    #[test]
    fn test_events_by_source() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new(
                    "e2",
                    SourceCrate::RuneIdentity,
                    EventCategory::Authentication,
                    "login",
                    200,
                )
                .build(),
            )
            .unwrap();
        assert_eq!(store.events_by_source(SourceCrate::RuneSecurity).len(), 1);
    }

    #[test]
    fn test_events_by_actor() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        assert_eq!(store.events_by_actor("system").len(), 1);
        assert_eq!(store.events_by_actor("nobody").len(), 0);
    }

    #[test]
    fn test_distribution_by_source() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        let dist = store.distribution_by_source();
        assert_eq!(dist[&SourceCrate::RuneSecurity], 2);
    }

    #[test]
    fn test_events_per_second() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 0)).unwrap();
        store.ingest(make_event("e2", 1)).unwrap();
        store.ingest(make_event("e3", 2)).unwrap();
        assert!((store.events_per_second() - 1.5).abs() < 0.01);
    }

    #[test]
    fn test_ingest_batch() {
        let mut store = AuditStore::new();
        let events = vec![make_event("e1", 100), make_event("e2", 200)];
        let count = store.ingest_batch(events).unwrap();
        assert_eq!(count, 2);
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn test_remove_where_preserves_critical() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap(); // Medium severity
        store
            .ingest(
                UnifiedEventBuilder::new(
                    "e2",
                    SourceCrate::RuneSecurity,
                    EventCategory::ThreatDetection,
                    "breach",
                    200,
                )
                .severity(SecuritySeverity::Critical)
                .build(),
            )
            .unwrap();
        let removed = store.remove_where(|_| true); // try to remove all
        assert_eq!(removed, 1); // only Medium removed
        assert_eq!(store.count(), 1); // Critical preserved
        assert!(store.get(&UnifiedEventId::new("e2")).is_some());
    }

    #[test]
    fn test_ingestion_helpers() {
        let mut store = AuditStore::new();
        store
            .ingest(ingest_security_event("s1", "scan", SecuritySeverity::High, "sys", "detail", 100))
            .unwrap();
        store
            .ingest(ingest_identity_event("i1", "login", "alice", "sess", EventOutcome::Success, 200))
            .unwrap();
        store
            .ingest(ingest_permission_event("p1", "check", "bob", "res", EventOutcome::Denied, 300))
            .unwrap();
        store
            .ingest(ingest_privacy_event("pr1", "consent", "carol", "granted", 400))
            .unwrap();
        store
            .ingest(ingest_detection_event("d1", "alert", SecuritySeverity::Medium, "anomaly", 500))
            .unwrap();
        store
            .ingest(ingest_shield_event("sh1", "block", SecuritySeverity::High, "blocked ip", 600))
            .unwrap();
        store
            .ingest(ingest_monitoring_event("m1", "health", "ok", 700))
            .unwrap();
        store
            .ingest(ingest_provenance_event("pv1", "verify", "artifact-1", "valid", 800))
            .unwrap();
        store
            .ingest(ingest_truth_event("t1", "assess", "output-1", "trusted", 900))
            .unwrap();
        store
            .ingest(ingest_document_event("dc1", "publish", "doc-1", "published", 1000))
            .unwrap();
        assert_eq!(store.count(), 10);
    }

    #[test]
    fn test_chain_enabled() {
        let mut store = AuditStore::new().with_chain();
        store.ingest(make_event("e1", 100)).unwrap();
        assert!(store.last_hash.is_some());
        let h1 = store.last_hash.clone();
        store.ingest(make_event("e2", 200)).unwrap();
        assert_ne!(store.last_hash, h1);
    }

    // ── EventIndex tests ───────────────────────────────────────────

    #[test]
    fn test_event_index_build() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        let idx = store.event_index();
        assert_eq!(idx.by_source.get(&SourceCrate::RuneSecurity).unwrap().len(), 2);
        assert_eq!(idx.by_actor.get("system").unwrap().len(), 2);
    }

    #[test]
    fn test_event_index_correlation() {
        let mut store = AuditStore::new();
        store.ingest(
            UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 100)
                .correlation_id("corr-1")
                .build(),
        ).unwrap();
        store.ingest(
            UnifiedEventBuilder::new("e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 200)
                .correlation_id("corr-1")
                .build(),
        ).unwrap();
        assert_eq!(store.event_index().by_correlation.get("corr-1").unwrap().len(), 2);
        assert_eq!(store.events_by_correlation("corr-1").len(), 2);
    }

    #[test]
    fn test_event_index_by_category() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(
            UnifiedEventBuilder::new("e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 200)
                .build(),
        ).unwrap();
        assert_eq!(store.events_by_category(EventCategory::ThreatDetection).len(), 1);
        assert_eq!(store.events_by_category(EventCategory::Authentication).len(), 1);
    }

    #[test]
    fn test_rebuild_index() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        store.rebuild_index();
        assert_eq!(store.events_by_source(SourceCrate::RuneSecurity).len(), 2);
        assert!(store.get(&UnifiedEventId::new("e1")).is_some());
    }

    // ── Storage stats tests ────────────────────────────────────────

    #[test]
    fn test_storage_stats() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        let stats = store.storage_stats();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.unique_sources, 1);
        assert_eq!(stats.oldest_timestamp, Some(100));
        assert_eq!(stats.newest_timestamp, Some(200));
        assert!(stats.memory_estimate_bytes > 0);
    }

    #[test]
    fn test_memory_estimate() {
        let mut store = AuditStore::new();
        let empty_estimate = store.memory_estimate();
        store.ingest(make_event("e1", 100)).unwrap();
        assert!(store.memory_estimate() > empty_estimate);
    }

    #[test]
    fn test_compact() {
        let mut store = AuditStore::new();
        for i in 0..10 {
            store.ingest(make_event(&format!("e{i}"), i * 100)).unwrap();
        }
        let before = store.compact();
        assert_eq!(before, 10);
        assert_eq!(store.count(), 10);
    }

    #[test]
    fn test_snapshot_and_restore() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap();
        store.ingest(make_event("e2", 200)).unwrap();
        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);

        let mut store2 = AuditStore::new();
        store2.restore(snap);
        assert_eq!(store2.count(), 2);
        assert!(store2.get(&UnifiedEventId::new("e1")).is_some());
    }

    #[test]
    fn test_merge() {
        let mut store1 = AuditStore::new();
        store1.ingest(make_event("e1", 100)).unwrap();
        store1.ingest(make_event("e2", 200)).unwrap();

        let mut store2 = AuditStore::new();
        store2.ingest(make_event("e2", 200)).unwrap(); // duplicate
        store2.ingest(make_event("e3", 300)).unwrap();

        let merged = store1.merge(&store2);
        assert_eq!(merged, 1); // only e3 merged
        assert_eq!(store1.count(), 3);
    }

    // ── Archive tests ──────────────────────────────────────────────

    #[test]
    fn test_archive_where() {
        let mut store = AuditStore::new();
        store.ingest(make_event("e1", 100)).unwrap(); // Medium
        store.ingest(make_event("e2", 200)).unwrap(); // Medium
        store.ingest(
            UnifiedEventBuilder::new("e3", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "breach", 300)
                .severity(SecuritySeverity::Critical)
                .build(),
        ).unwrap();

        let archived = store.archive_where(|e| e.timestamp < 250);
        assert_eq!(archived, 2);
        assert_eq!(store.count(), 1); // only Critical remains
        assert_eq!(store.archived_count(), 2);
        assert_eq!(store.archived_events().len(), 2);
    }

    #[test]
    fn test_archive_preserves_critical() {
        let mut store = AuditStore::new();
        store.ingest(
            UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "breach", 100)
                .severity(SecuritySeverity::Critical)
                .build(),
        ).unwrap();
        let archived = store.archive_where(|_| true);
        assert_eq!(archived, 0);
        assert_eq!(store.count(), 1);
    }
}
