// ═══════════════════════════════════════════════════════════════════════
// Correlation — Cross-crate event correlation engine.
//
// CorrelationEngine discovers causal chains across crate boundaries
// by following correlation_id and parent_event_id links.
// ═══════════════════════════════════════════════════════════════════════

use crate::event::*;
use crate::store::AuditStore;

// ── CorrelationChain ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelationChain {
    pub correlation_id: String,
    pub events: Vec<UnifiedEventId>,
    pub sources: Vec<SourceCrate>,
    pub start_time: i64,
    pub end_time: i64,
}

impl CorrelationChain {
    pub fn span(&self) -> i64 {
        self.end_time - self.start_time
    }

    pub fn is_cross_crate(&self) -> bool {
        if self.sources.len() < 2 {
            return false;
        }
        let first = self.sources[0];
        self.sources.iter().any(|s| *s != first)
    }
}

// ── CorrelationEngine ───────────────────────────────────────────────

pub struct CorrelationEngine;

impl CorrelationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Group events by correlation_id.
    pub fn correlate(&self, store: &AuditStore) -> Vec<CorrelationChain> {
        let mut map: std::collections::HashMap<String, Vec<&UnifiedEvent>> =
            std::collections::HashMap::new();
        for event in store.all_events() {
            if let Some(cid) = &event.correlation_id {
                map.entry(cid.clone()).or_default().push(event);
            }
        }
        let mut chains = Vec::new();
        for (cid, mut events) in map {
            events.sort_by_key(|e| e.timestamp);
            let start_time = events.first().unwrap().timestamp;
            let end_time = events.last().unwrap().timestamp;
            let event_ids: Vec<UnifiedEventId> = events.iter().map(|e| e.id.clone()).collect();
            let sources: Vec<SourceCrate> = events.iter().map(|e| e.source).collect();
            chains.push(CorrelationChain {
                correlation_id: cid,
                events: event_ids,
                sources,
                start_time,
                end_time,
            });
        }
        chains.sort_by_key(|c| c.start_time);
        chains
    }

    /// Follow parent_event_id links to build a causal chain from root to leaf.
    pub fn find_causal_chain(&self, store: &AuditStore, event_id: &UnifiedEventId) -> Vec<UnifiedEventId> {
        // Walk up to find root
        let mut chain = Vec::new();
        let mut current = event_id.clone();
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                break; // cycle protection
            }
            if let Some(event) = store.get(&current) {
                chain.push(current.clone());
                if let Some(parent) = &event.parent_event_id {
                    current = UnifiedEventId::new(parent);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        chain.reverse();
        chain
    }

    /// Find direct children of an event.
    pub fn find_children(&self, store: &AuditStore, parent_id: &UnifiedEventId) -> Vec<UnifiedEventId> {
        store
            .all_events()
            .iter()
            .filter(|e| e.parent_event_id.as_deref() == Some(&parent_id.0))
            .map(|e| e.id.clone())
            .collect()
    }

    /// Return all active correlation chains (those with events).
    pub fn active_correlations(&self, store: &AuditStore) -> Vec<String> {
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for event in store.all_events() {
            if let Some(cid) = &event.correlation_id {
                ids.insert(cid.clone());
            }
        }
        let mut result: Vec<String> = ids.into_iter().collect();
        result.sort();
        result
    }

    /// Return only chains that span multiple crates.
    pub fn cross_crate_chains(&self, store: &AuditStore) -> Vec<CorrelationChain> {
        self.correlate(store)
            .into_iter()
            .filter(|c| c.is_cross_crate())
            .collect()
    }

    /// Correlate events within a time window.
    pub fn correlate_by_time_window<'a>(
        &self,
        store: &'a AuditStore,
        center: i64,
        window_ms: i64,
    ) -> Vec<&'a UnifiedEvent> {
        let start = center - window_ms;
        let end = center + window_ms;
        store.events_between(start, end)
    }

    /// Correlate events by subject.
    pub fn correlate_by_subject<'a>(
        &self,
        store: &'a AuditStore,
        subject: &str,
    ) -> Vec<&'a UnifiedEvent> {
        store.events_by_subject(subject)
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rune_security::SecuritySeverity;

    fn make_correlated_store() -> AuditStore {
        let mut store = AuditStore::new();
        store
            .ingest(
                UnifiedEventBuilder::new("e1", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 100)
                    .actor("alice")
                    .correlation_id("corr-1")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e2", SourceCrate::RunePermissions, EventCategory::Authorization, "check", 200)
                    .actor("alice")
                    .correlation_id("corr-1")
                    .parent_event_id("e1")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e3", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 300)
                    .correlation_id("corr-1")
                    .parent_event_id("e2")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e4", SourceCrate::RuneMonitoring, EventCategory::Availability, "health", 400)
                    .correlation_id("corr-2")
                    .build(),
            )
            .unwrap();
        store
    }

    #[test]
    fn test_correlate_groups_by_id() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let chains = engine.correlate(&store);
        assert_eq!(chains.len(), 2);
    }

    #[test]
    fn test_correlation_chain_span() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let chains = engine.correlate(&store);
        let corr1 = chains.iter().find(|c| c.correlation_id == "corr-1").unwrap();
        assert_eq!(corr1.span(), 200); // 300 - 100
        assert_eq!(corr1.events.len(), 3);
    }

    #[test]
    fn test_cross_crate_detection() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let chains = engine.correlate(&store);
        let corr1 = chains.iter().find(|c| c.correlation_id == "corr-1").unwrap();
        assert!(corr1.is_cross_crate());
        let corr2 = chains.iter().find(|c| c.correlation_id == "corr-2").unwrap();
        assert!(!corr2.is_cross_crate());
    }

    #[test]
    fn test_find_causal_chain() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let chain = engine.find_causal_chain(&store, &UnifiedEventId::new("e3"));
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], UnifiedEventId::new("e1"));
        assert_eq!(chain[2], UnifiedEventId::new("e3"));
    }

    #[test]
    fn test_find_children() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let children = engine.find_children(&store, &UnifiedEventId::new("e1"));
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], UnifiedEventId::new("e2"));
    }

    #[test]
    fn test_active_correlations() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let active = engine.active_correlations(&store);
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"corr-1".to_string()));
        assert!(active.contains(&"corr-2".to_string()));
    }

    #[test]
    fn test_cross_crate_chains() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let cross = engine.cross_crate_chains(&store);
        assert_eq!(cross.len(), 1);
        assert_eq!(cross[0].correlation_id, "corr-1");
    }

    #[test]
    fn test_correlate_by_time_window() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let events = engine.correlate_by_time_window(&store, 200, 50);
        assert_eq!(events.len(), 1); // only e2 at t=200
    }

    #[test]
    fn test_correlate_by_subject() {
        let mut store = AuditStore::new();
        store
            .ingest(
                UnifiedEventBuilder::new("e1", SourceCrate::RuneTruth, EventCategory::Integrity, "verify", 100)
                    .subject("artifact-1")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e2", SourceCrate::RuneProvenance, EventCategory::Integrity, "check", 200)
                    .subject("artifact-1")
                    .build(),
            )
            .unwrap();
        let engine = CorrelationEngine::new();
        let events = engine.correlate_by_subject(&store, "artifact-1");
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_causal_chain_from_root() {
        let store = make_correlated_store();
        let engine = CorrelationEngine::new();
        let chain = engine.find_causal_chain(&store, &UnifiedEventId::new("e1"));
        assert_eq!(chain.len(), 1); // root has no parents
    }
}
