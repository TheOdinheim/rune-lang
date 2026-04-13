// ═══════════════════════════════════════════════════════════════════════
// Query — Composable query engine with And/Or/Not combinators.
//
// AuditQuery builds filters fluently; QueryEngine evaluates them
// against an AuditStore. QueryResult supports pagination.
// ═══════════════════════════════════════════════════════════════════════

use rune_security::SecuritySeverity;

use crate::event::*;
use crate::store::AuditStore;

// ── QueryFilter ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum QueryFilter {
    Source(SourceCrate),
    Category(EventCategory),
    SeverityAtLeast(SecuritySeverity),
    Outcome(EventOutcome),
    Actor(String),
    Subject(String),
    ActionContains(String),
    DetailContains(String),
    TimeBefore(i64),
    TimeAfter(i64),
    HasCorrelation,
    HasTag(String),
    And(Vec<QueryFilter>),
    Or(Vec<QueryFilter>),
    Not(Box<QueryFilter>),
}

impl QueryFilter {
    pub fn matches(&self, event: &UnifiedEvent) -> bool {
        match self {
            Self::Source(s) => event.source == *s,
            Self::Category(c) => event.category == *c,
            Self::SeverityAtLeast(s) => event.severity >= *s,
            Self::Outcome(o) => event.outcome == *o,
            Self::Actor(a) => event.actor == *a,
            Self::Subject(s) => event.subject == *s,
            Self::ActionContains(s) => event.action.contains(s.as_str()),
            Self::DetailContains(s) => event.detail.contains(s.as_str()),
            Self::TimeBefore(t) => event.timestamp < *t,
            Self::TimeAfter(t) => event.timestamp > *t,
            Self::HasCorrelation => event.correlation_id.is_some(),
            Self::HasTag(tag) => event.tags.contains(tag),
            Self::And(filters) => filters.iter().all(|f| f.matches(event)),
            Self::Or(filters) => filters.iter().any(|f| f.matches(event)),
            Self::Not(filter) => !filter.matches(event),
        }
    }
}

// ── QuerySort ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum QuerySort {
    TimestampAsc,
    TimestampDesc,
    SeverityAsc,
    SeverityDesc,
}

// ── QueryResult ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct QueryResult<'a> {
    pub events: Vec<&'a UnifiedEvent>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

// ── AuditQuery ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuditQuery {
    pub filters: Vec<QueryFilter>,
    pub sort: QuerySort,
    pub offset: usize,
    pub limit: usize,
}

impl AuditQuery {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            sort: QuerySort::TimestampAsc,
            offset: 0,
            limit: 100,
        }
    }

    pub fn filter(mut self, f: QueryFilter) -> Self {
        self.filters.push(f);
        self
    }

    pub fn sort(mut self, sort: QuerySort) -> Self {
        self.sort = sort;
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self::new()
    }
}

// ── QueryEngine ─────────────────────────────────────────────────────

pub struct QueryEngine;

impl QueryEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn execute<'a>(&self, store: &'a AuditStore, query: &AuditQuery) -> QueryResult<'a> {
        let combined = if query.filters.is_empty() {
            None
        } else {
            Some(QueryFilter::And(query.filters.clone()))
        };

        let mut matched: Vec<&UnifiedEvent> = store
            .all_events()
            .iter()
            .filter(|e| combined.as_ref().map_or(true, |f| f.matches(e)))
            .collect();

        // Sort
        match query.sort {
            QuerySort::TimestampAsc => matched.sort_by_key(|e| e.timestamp),
            QuerySort::TimestampDesc => matched.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
            QuerySort::SeverityAsc => matched.sort_by_key(|e| e.severity),
            QuerySort::SeverityDesc => matched.sort_by(|a, b| b.severity.cmp(&a.severity)),
        }

        let total = matched.len();
        let events: Vec<&UnifiedEvent> = matched
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();

        QueryResult {
            events,
            total,
            offset: query.offset,
            limit: query.limit,
        }
    }

    pub fn count(&self, store: &AuditStore, query: &AuditQuery) -> usize {
        let combined = if query.filters.is_empty() {
            None
        } else {
            Some(QueryFilter::And(query.filters.clone()))
        };

        store
            .all_events()
            .iter()
            .filter(|e| combined.as_ref().map_or(true, |f| f.matches(e)))
            .count()
    }
}

impl Default for QueryEngine {
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

    fn populated_store() -> AuditStore {
        let mut store = AuditStore::new();
        store
            .ingest(
                UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 100)
                    .severity(SecuritySeverity::High)
                    .actor("system")
                    .subject("host-1")
                    .tag("security")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 200)
                    .severity(SecuritySeverity::Info)
                    .actor("alice")
                    .outcome(EventOutcome::Success)
                    .correlation_id("corr-1")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e3", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "alert", 300)
                    .severity(SecuritySeverity::Critical)
                    .actor("system")
                    .detail("breach detected")
                    .build(),
            )
            .unwrap();
        store
    }

    #[test]
    fn test_query_no_filters() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let result = engine.execute(&store, &AuditQuery::new());
        assert_eq!(result.total, 3);
        assert_eq!(result.events.len(), 3);
    }

    #[test]
    fn test_query_by_source() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::Source(SourceCrate::RuneSecurity));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 2);
    }

    #[test]
    fn test_query_severity_at_least() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::SeverityAtLeast(SecuritySeverity::High));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 2); // High + Critical
    }

    #[test]
    fn test_query_and_combinator() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::And(vec![
            QueryFilter::Source(SourceCrate::RuneSecurity),
            QueryFilter::SeverityAtLeast(SecuritySeverity::Critical),
        ]));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 1);
    }

    #[test]
    fn test_query_or_combinator() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::Or(vec![
            QueryFilter::Actor("alice".into()),
            QueryFilter::SeverityAtLeast(SecuritySeverity::Critical),
        ]));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 2); // alice + Critical
    }

    #[test]
    fn test_query_not_combinator() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::Not(Box::new(QueryFilter::Actor(
            "system".into(),
        ))));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 1); // only alice
    }

    #[test]
    fn test_query_sort_severity_desc() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().sort(QuerySort::SeverityDesc);
        let result = engine.execute(&store, &query);
        assert_eq!(result.events[0].severity, SecuritySeverity::Critical);
    }

    #[test]
    fn test_query_pagination() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().limit(1).offset(1);
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 3);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.offset, 1);
        assert_eq!(result.events[0].id, UnifiedEventId::new("e2"));
    }

    #[test]
    fn test_query_count() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::Actor("system".into()));
        assert_eq!(engine.count(&store, &query), 2);
    }

    #[test]
    fn test_query_detail_contains() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::DetailContains("breach".into()));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 1);
    }

    #[test]
    fn test_query_has_correlation() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::HasCorrelation);
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 1); // only e2 has correlation_id
    }

    #[test]
    fn test_query_has_tag() {
        let store = populated_store();
        let engine = QueryEngine::new();
        let query = AuditQuery::new().filter(QueryFilter::HasTag("security".into()));
        let result = engine.execute(&store, &query);
        assert_eq!(result.total, 1);
    }
}
