// ═══════════════════════════════════════════════════════════════════════
// Timeline — Event timeline construction and bucketing.
//
// TimelineBuilder constructs timelines from the store, correlation
// chains, or subject filters. Bucketize produces histograms.
// ═══════════════════════════════════════════════════════════════════════

use crate::event::*;
use crate::store::AuditStore;

// ── TimelineEntry ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub event_id: UnifiedEventId,
    pub timestamp: i64,
    pub source: SourceCrate,
    pub action: String,
    pub summary: String,
}

// ── Timeline ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Timeline {
    pub entries: Vec<TimelineEntry>,
    pub start_time: i64,
    pub end_time: i64,
}

impl Timeline {
    pub fn new(entries: Vec<TimelineEntry>) -> Self {
        let start_time = entries.first().map_or(0, |e| e.timestamp);
        let end_time = entries.last().map_or(0, |e| e.timestamp);
        Self {
            entries,
            start_time,
            end_time,
        }
    }

    pub fn span(&self) -> i64 {
        self.end_time - self.start_time
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── TimelineBuilder ─────────────────────────────────────────────────

pub struct TimelineBuilder;

impl TimelineBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build timeline from all events in the store.
    pub fn from_store(&self, store: &AuditStore) -> Timeline {
        let entries: Vec<TimelineEntry> = store
            .all_events()
            .iter()
            .map(|e| event_to_entry(e))
            .collect();
        Timeline::new(entries)
    }

    /// Build timeline from events with a given correlation_id.
    pub fn from_correlation(&self, store: &AuditStore, correlation_id: &str) -> Timeline {
        let entries: Vec<TimelineEntry> = store
            .events_by_correlation(correlation_id)
            .into_iter()
            .map(|e| event_to_entry(e))
            .collect();
        Timeline::new(entries)
    }

    /// Build timeline from events with a given subject.
    pub fn from_subject(&self, store: &AuditStore, subject: &str) -> Timeline {
        let entries: Vec<TimelineEntry> = store
            .events_by_subject(subject)
            .into_iter()
            .map(|e| event_to_entry(e))
            .collect();
        Timeline::new(entries)
    }
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn event_to_entry(e: &UnifiedEvent) -> TimelineEntry {
    TimelineEntry {
        event_id: e.id.clone(),
        timestamp: e.timestamp,
        source: e.source,
        action: e.action.clone(),
        summary: if e.detail.is_empty() {
            format!("[{}] {}", e.source, e.action)
        } else {
            format!("[{}] {} — {}", e.source, e.action, e.detail)
        },
    }
}

/// Bucket events into time intervals, producing a histogram.
/// Returns Vec<(bucket_start, count)>.
pub fn bucketize(timeline: &Timeline, bucket_size: i64) -> Vec<(i64, usize)> {
    if timeline.is_empty() || bucket_size <= 0 {
        return Vec::new();
    }

    let start = timeline.start_time;
    let end = timeline.end_time;
    let num_buckets = ((end - start) / bucket_size + 1) as usize;
    let mut buckets = vec![0usize; num_buckets];

    for entry in &timeline.entries {
        let idx = ((entry.timestamp - start) / bucket_size) as usize;
        if idx < buckets.len() {
            buckets[idx] += 1;
        }
    }

    buckets
        .into_iter()
        .enumerate()
        .map(|(i, count)| (start + i as i64 * bucket_size, count))
        .collect()
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
                UnifiedEventBuilder::new("e1", SourceCrate::RuneIdentity, EventCategory::Authentication, "login", 100)
                    .actor("alice")
                    .subject("session-1")
                    .correlation_id("corr-1")
                    .detail("login success")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e2", SourceCrate::RunePermissions, EventCategory::Authorization, "check", 200)
                    .actor("alice")
                    .subject("session-1")
                    .correlation_id("corr-1")
                    .build(),
            )
            .unwrap();
        store
            .ingest(
                UnifiedEventBuilder::new("e3", SourceCrate::RuneMonitoring, EventCategory::Availability, "health", 300)
                    .detail("healthy")
                    .build(),
            )
            .unwrap();
        store
    }

    #[test]
    fn test_from_store() {
        let store = populated_store();
        let tb = TimelineBuilder::new();
        let tl = tb.from_store(&store);
        assert_eq!(tl.len(), 3);
        assert_eq!(tl.start_time, 100);
        assert_eq!(tl.end_time, 300);
        assert_eq!(tl.span(), 200);
    }

    #[test]
    fn test_from_correlation() {
        let store = populated_store();
        let tb = TimelineBuilder::new();
        let tl = tb.from_correlation(&store, "corr-1");
        assert_eq!(tl.len(), 2);
    }

    #[test]
    fn test_from_subject() {
        let store = populated_store();
        let tb = TimelineBuilder::new();
        let tl = tb.from_subject(&store, "session-1");
        assert_eq!(tl.len(), 2);
    }

    #[test]
    fn test_empty_timeline() {
        let store = AuditStore::new();
        let tb = TimelineBuilder::new();
        let tl = tb.from_store(&store);
        assert!(tl.is_empty());
        assert_eq!(tl.span(), 0);
    }

    #[test]
    fn test_timeline_entry_summary() {
        let store = populated_store();
        let tb = TimelineBuilder::new();
        let tl = tb.from_store(&store);
        assert!(tl.entries[0].summary.contains("login"));
        assert!(tl.entries[0].summary.contains("rune-identity"));
    }

    #[test]
    fn test_bucketize() {
        let store = populated_store();
        let tb = TimelineBuilder::new();
        let tl = tb.from_store(&store);
        let buckets = bucketize(&tl, 100);
        assert_eq!(buckets.len(), 3); // 100, 200, 300
        assert_eq!(buckets[0].1, 1); // e1
        assert_eq!(buckets[1].1, 1); // e2
        assert_eq!(buckets[2].1, 1); // e3
    }

    #[test]
    fn test_bucketize_single_bucket() {
        let store = populated_store();
        let tb = TimelineBuilder::new();
        let tl = tb.from_store(&store);
        let buckets = bucketize(&tl, 1000);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].1, 3); // all in one bucket
    }

    #[test]
    fn test_bucketize_empty() {
        let tl = Timeline::new(Vec::new());
        let buckets = bucketize(&tl, 100);
        assert!(buckets.is_empty());
    }

    #[test]
    fn test_timeline_entry_empty_detail() {
        let mut store = AuditStore::new();
        store
            .ingest(
                UnifiedEventBuilder::new("x", SourceCrate::RuneLang, EventCategory::Lifecycle, "init", 0)
                    .build(),
            )
            .unwrap();
        let tb = TimelineBuilder::new();
        let tl = tb.from_store(&store);
        assert!(tl.entries[0].summary.contains("[rune-lang] init"));
        assert!(!tl.entries[0].summary.contains("—")); // no detail separator
    }
}
