// ═══════════════════════════════════════════════════════════════════════
// L3 Query — Structured query interface for audit backends.
//
// Layer 3 defines a structured query interface for audit events so
// customers can build audit dashboards, compliance reports, and
// forensic tools against any AuditBackend implementation.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::AuditBackend;
use crate::event::UnifiedEvent;

// ── SortField ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Timestamp,
    EventType,
    Source,
    Severity,
}

// ── SortOrder ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

// ── QueryFilter ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum L3QueryFilter {
    EventType(String),
    TimeRange { from: i64, to: i64 },
    Source(String),
    SeverityAtLeast(String),
    ContainsText(String),
    HasMetadata { key: String, value: Option<String> },
}

// ── AuditQuery ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L3AuditQuery {
    pub filters: Vec<L3QueryFilter>,
    pub sort_by: Option<SortField>,
    pub sort_order: SortOrder,
    pub limit: Option<usize>,
    pub offset: usize,
}

// ── AuditQueryBuilder ─────────────────────────────────────────────

pub struct AuditQueryBuilder {
    filters: Vec<L3QueryFilter>,
    sort_by: Option<SortField>,
    sort_order: SortOrder,
    limit: Option<usize>,
    offset: usize,
}

impl AuditQueryBuilder {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
            sort_by: None,
            sort_order: SortOrder::Ascending,
            limit: None,
            offset: 0,
        }
    }

    pub fn event_type(mut self, t: &str) -> Self {
        self.filters.push(L3QueryFilter::EventType(t.to_string()));
        self
    }

    pub fn time_range(mut self, from: i64, to: i64) -> Self {
        self.filters.push(L3QueryFilter::TimeRange { from, to });
        self
    }

    pub fn source(mut self, s: &str) -> Self {
        self.filters.push(L3QueryFilter::Source(s.to_string()));
        self
    }

    pub fn severity_at_least(mut self, s: &str) -> Self {
        self.filters
            .push(L3QueryFilter::SeverityAtLeast(s.to_string()));
        self
    }

    pub fn contains_text(mut self, text: &str) -> Self {
        self.filters
            .push(L3QueryFilter::ContainsText(text.to_string()));
        self
    }

    pub fn has_metadata(mut self, key: &str, value: Option<&str>) -> Self {
        self.filters.push(L3QueryFilter::HasMetadata {
            key: key.to_string(),
            value: value.map(|v| v.to_string()),
        });
        self
    }

    pub fn sort_by(mut self, field: SortField, order: SortOrder) -> Self {
        self.sort_by = Some(field);
        self.sort_order = order;
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn offset(mut self, n: usize) -> Self {
        self.offset = n;
        self
    }

    pub fn build(self) -> L3AuditQuery {
        L3AuditQuery {
            filters: self.filters,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            limit: self.limit,
            offset: self.offset,
        }
    }
}

impl Default for AuditQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── QueryResult ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct L3QueryResult {
    pub events: Vec<UnifiedEvent>,
    pub total_matching: usize,
    pub returned: usize,
    pub query_time_ms: i64,
}

// ── Query execution ───────────────────────────────────────────────

fn matches_filter(event: &UnifiedEvent, filter: &L3QueryFilter) -> bool {
    match filter {
        L3QueryFilter::EventType(t) => event.action == *t,
        L3QueryFilter::TimeRange { from, to } => event.timestamp >= *from && event.timestamp <= *to,
        L3QueryFilter::Source(s) => event.source.to_string() == *s,
        L3QueryFilter::SeverityAtLeast(s) => {
            let sev_str = event.severity.to_string();
            // Compare by severity ordering: Emergency > Critical > High > Medium > Low > Info
            let sev_order = |sv: &str| -> u8 {
                match sv {
                    "Info" => 0,
                    "Low" => 1,
                    "Medium" => 2,
                    "High" => 3,
                    "Critical" => 4,
                    "Emergency" => 5,
                    _ => 0,
                }
            };
            sev_order(&sev_str) >= sev_order(s)
        }
        L3QueryFilter::ContainsText(text) => {
            event.action.contains(text.as_str())
                || event.detail.contains(text.as_str())
                || event.actor.contains(text.as_str())
                || event.subject.contains(text.as_str())
        }
        L3QueryFilter::HasMetadata { key, value } => {
            match value {
                Some(v) => event.metadata.get(key).map_or(false, |mv| mv == v),
                None => event.metadata.contains_key(key),
            }
        }
    }
}

pub fn execute_query(backend: &dyn AuditBackend, query: &L3AuditQuery) -> L3QueryResult {
    let all_events = backend.all_events();

    let mut matched: Vec<UnifiedEvent> = all_events
        .iter()
        .filter(|e| query.filters.iter().all(|f| matches_filter(e, f)))
        .cloned()
        .collect();

    // Sort
    if let Some(ref field) = query.sort_by {
        match field {
            SortField::Timestamp => {
                match query.sort_order {
                    SortOrder::Ascending => matched.sort_by_key(|e| e.timestamp),
                    SortOrder::Descending => matched.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
                }
            }
            SortField::EventType => {
                match query.sort_order {
                    SortOrder::Ascending => matched.sort_by(|a, b| a.action.cmp(&b.action)),
                    SortOrder::Descending => matched.sort_by(|a, b| b.action.cmp(&a.action)),
                }
            }
            SortField::Source => {
                match query.sort_order {
                    SortOrder::Ascending => matched.sort_by(|a, b| a.source.to_string().cmp(&b.source.to_string())),
                    SortOrder::Descending => matched.sort_by(|a, b| b.source.to_string().cmp(&a.source.to_string())),
                }
            }
            SortField::Severity => {
                match query.sort_order {
                    SortOrder::Ascending => matched.sort_by_key(|e| e.severity),
                    SortOrder::Descending => matched.sort_by(|a, b| b.severity.cmp(&a.severity)),
                }
            }
        }
    }

    let total_matching = matched.len();

    let paged: Vec<UnifiedEvent> = matched
        .into_iter()
        .skip(query.offset)
        .take(query.limit.unwrap_or(usize::MAX))
        .collect();
    let returned = paged.len();

    L3QueryResult {
        events: paged,
        total_matching,
        returned,
        query_time_ms: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryAuditBackend;
    use crate::event::*;
    use rune_security::SecuritySeverity;

    fn populated_backend() -> InMemoryAuditBackend {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(
            &UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 100)
                .severity(SecuritySeverity::High)
                .actor("system")
                .detail("port scan detected")
                .build(),
        ).unwrap();
        backend.store_event(
            &UnifiedEventBuilder::new("e2", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 200)
                .severity(SecuritySeverity::Info)
                .actor("alice")
                .build(),
        ).unwrap();
        backend.store_event(
            &UnifiedEventBuilder::new("e3", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "alert", 300)
                .severity(SecuritySeverity::Critical)
                .actor("system")
                .detail("breach detected")
                .build(),
        ).unwrap();
        backend
    }

    #[test]
    fn test_query_builder_fluent_api() {
        let query = AuditQueryBuilder::new()
            .event_type("scan")
            .source("rune-security")
            .limit(10)
            .offset(0)
            .build();
        assert_eq!(query.filters.len(), 2);
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, 0);
    }

    #[test]
    fn test_query_builder_multiple_filters() {
        let query = AuditQueryBuilder::new()
            .event_type("scan")
            .time_range(0, 500)
            .severity_at_least("High")
            .build();
        assert_eq!(query.filters.len(), 3);
    }

    #[test]
    fn test_execute_query_event_type_filter() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new().event_type("scan").build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 1);
        assert_eq!(result.returned, 1);
        assert_eq!(result.events[0].id, UnifiedEventId::new("e1"));
    }

    #[test]
    fn test_execute_query_time_range_filter() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new().time_range(150, 250).build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 1);
        assert_eq!(result.events[0].id, UnifiedEventId::new("e2"));
    }

    #[test]
    fn test_execute_query_limit_and_offset() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new().limit(1).offset(1).build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 3);
        assert_eq!(result.returned, 1);
    }

    #[test]
    fn test_execute_query_sort_timestamp_ascending() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new()
            .sort_by(SortField::Timestamp, SortOrder::Ascending)
            .build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.events[0].timestamp, 100);
        assert_eq!(result.events[2].timestamp, 300);
    }

    #[test]
    fn test_execute_query_sort_timestamp_descending() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new()
            .sort_by(SortField::Timestamp, SortOrder::Descending)
            .build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.events[0].timestamp, 300);
        assert_eq!(result.events[2].timestamp, 100);
    }

    #[test]
    fn test_execute_query_contains_text() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new().contains_text("breach").build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 1);
    }

    #[test]
    fn test_query_result_reports_totals() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new().limit(2).build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 3);
        assert_eq!(result.returned, 2);
    }

    #[test]
    fn test_execute_query_source_filter() {
        let backend = populated_backend();
        let query = AuditQueryBuilder::new().source("rune-security").build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 2);
    }

    #[test]
    fn test_execute_query_has_metadata() {
        let mut backend = InMemoryAuditBackend::new();
        backend.store_event(
            &UnifiedEventBuilder::new("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 100)
                .meta("env", "prod")
                .build(),
        ).unwrap();
        backend.store_event(
            &UnifiedEventBuilder::new("e2", SourceCrate::RuneSecurity, EventCategory::ThreatDetection, "scan", 200)
                .build(),
        ).unwrap();
        let query = AuditQueryBuilder::new()
            .has_metadata("env", Some("prod"))
            .build();
        let result = execute_query(&backend, &query);
        assert_eq!(result.total_matching, 1);
    }
}
