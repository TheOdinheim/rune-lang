// ═══════════════════════════════════════════════════════════════════════
// Pipeline — Audit event enrichment pipeline.
//
// Layer 3 defines a pipeline for enriching audit events before
// export — adding context, normalizing fields, computing derived
// values — so customers get a clean, consistent event stream.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_security::SecuritySeverity;

use crate::event::UnifiedEvent;

// ── AuditEnricher trait ───────────────────────────────────────────

pub trait AuditEnricher {
    fn enrich(&self, event: &mut UnifiedEvent);
    fn enricher_name(&self) -> &str;
}

// ── TimestampNormalizer ───────────────────────────────────────────

pub struct TimestampNormalizer {
    offset_hours: i32,
}

impl TimestampNormalizer {
    pub fn new(timezone_offset_hours: i32) -> Self {
        Self {
            offset_hours: timezone_offset_hours,
        }
    }
}

impl AuditEnricher for TimestampNormalizer {
    fn enrich(&self, event: &mut UnifiedEvent) {
        let offset_seconds = self.offset_hours as i64 * 3600;
        event.timestamp += offset_seconds;
    }

    fn enricher_name(&self) -> &str {
        "TimestampNormalizer"
    }
}

// ── SourceTagger ──────────────────────────────────────────────────

pub struct SourceTagger {
    tags: HashMap<String, String>,
}

impl SourceTagger {
    pub fn new(tags: HashMap<String, String>) -> Self {
        Self { tags }
    }
}

impl AuditEnricher for SourceTagger {
    fn enrich(&self, event: &mut UnifiedEvent) {
        for (key, value) in &self.tags {
            event.metadata.insert(key.clone(), value.clone());
        }
    }

    fn enricher_name(&self) -> &str {
        "SourceTagger"
    }
}

// ── SeverityMapper ────────────────────────────────────────────────

pub struct SeverityMapper;

impl SeverityMapper {
    pub fn new() -> Self {
        Self
    }

    pub fn severity_to_numeric(sev: SecuritySeverity) -> u8 {
        match sev {
            SecuritySeverity::Info => 1,
            SecuritySeverity::Low => 3,
            SecuritySeverity::Medium => 5,
            SecuritySeverity::High => 7,
            SecuritySeverity::Critical => 9,
            SecuritySeverity::Emergency => 10,
        }
    }
}

impl Default for SeverityMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditEnricher for SeverityMapper {
    fn enrich(&self, event: &mut UnifiedEvent) {
        let numeric = Self::severity_to_numeric(event.severity);
        event
            .metadata
            .insert("severity_numeric".to_string(), numeric.to_string());
    }

    fn enricher_name(&self) -> &str {
        "SeverityMapper"
    }
}

// ── EnrichmentPipeline ────────────────────────────────────────────

pub struct EnrichmentPipeline {
    enrichers: Vec<Box<dyn AuditEnricher>>,
}

impl EnrichmentPipeline {
    pub fn new() -> Self {
        Self {
            enrichers: Vec::new(),
        }
    }

    pub fn add_enricher(&mut self, enricher: Box<dyn AuditEnricher>) {
        self.enrichers.push(enricher);
    }

    pub fn enrich(&self, event: &mut UnifiedEvent) {
        for enricher in &self.enrichers {
            enricher.enrich(event);
        }
    }

    pub fn enrich_batch(&self, events: &mut [UnifiedEvent]) {
        for event in events.iter_mut() {
            self.enrich(event);
        }
    }

    pub fn enricher_count(&self) -> usize {
        self.enrichers.len()
    }
}

impl Default for EnrichmentPipeline {
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
    use crate::event::*;

    fn make_event(id: &str, ts: i64) -> UnifiedEvent {
        UnifiedEventBuilder::new(
            id,
            SourceCrate::RuneSecurity,
            EventCategory::ThreatDetection,
            "scan",
            ts,
        )
        .severity(SecuritySeverity::High)
        .build()
    }

    #[test]
    fn test_timestamp_normalizer_adjusts() {
        let normalizer = TimestampNormalizer::new(2);
        let mut event = make_event("e1", 1000);
        normalizer.enrich(&mut event);
        assert_eq!(event.timestamp, 1000 + 2 * 3600);
    }

    #[test]
    fn test_timestamp_normalizer_negative_offset() {
        let normalizer = TimestampNormalizer::new(-5);
        let mut event = make_event("e1", 100000);
        normalizer.enrich(&mut event);
        assert_eq!(event.timestamp, 100000 - 5 * 3600);
    }

    #[test]
    fn test_source_tagger_adds_tags() {
        let mut tags = HashMap::new();
        tags.insert("environment".to_string(), "production".to_string());
        tags.insert("region".to_string(), "us-east-1".to_string());
        let tagger = SourceTagger::new(tags);
        let mut event = make_event("e1", 1000);
        tagger.enrich(&mut event);
        assert_eq!(event.metadata.get("environment").unwrap(), "production");
        assert_eq!(event.metadata.get("region").unwrap(), "us-east-1");
    }

    #[test]
    fn test_severity_mapper_normalizes() {
        let mapper = SeverityMapper::new();
        let mut event = make_event("e1", 1000);
        mapper.enrich(&mut event);
        assert_eq!(event.metadata.get("severity_numeric").unwrap(), "7");
    }

    #[test]
    fn test_severity_mapper_all_levels() {
        assert_eq!(SeverityMapper::severity_to_numeric(SecuritySeverity::Info), 1);
        assert_eq!(SeverityMapper::severity_to_numeric(SecuritySeverity::Low), 3);
        assert_eq!(SeverityMapper::severity_to_numeric(SecuritySeverity::Medium), 5);
        assert_eq!(SeverityMapper::severity_to_numeric(SecuritySeverity::High), 7);
        assert_eq!(SeverityMapper::severity_to_numeric(SecuritySeverity::Critical), 9);
        assert_eq!(SeverityMapper::severity_to_numeric(SecuritySeverity::Emergency), 10);
    }

    #[test]
    fn test_pipeline_applies_in_order() {
        let mut pipeline = EnrichmentPipeline::new();
        let mut tags = HashMap::new();
        tags.insert("env".to_string(), "test".to_string());
        pipeline.add_enricher(Box::new(SourceTagger::new(tags)));
        pipeline.add_enricher(Box::new(SeverityMapper::new()));
        let mut event = make_event("e1", 1000);
        pipeline.enrich(&mut event);
        assert_eq!(event.metadata.get("env").unwrap(), "test");
        assert_eq!(event.metadata.get("severity_numeric").unwrap(), "7");
    }

    #[test]
    fn test_pipeline_enrich_batch() {
        let mut pipeline = EnrichmentPipeline::new();
        pipeline.add_enricher(Box::new(SeverityMapper::new()));
        let mut events = vec![make_event("e1", 100), make_event("e2", 200)];
        pipeline.enrich_batch(&mut events);
        assert!(events[0].metadata.contains_key("severity_numeric"));
        assert!(events[1].metadata.contains_key("severity_numeric"));
    }

    #[test]
    fn test_pipeline_enricher_count() {
        let mut pipeline = EnrichmentPipeline::new();
        assert_eq!(pipeline.enricher_count(), 0);
        pipeline.add_enricher(Box::new(SeverityMapper::new()));
        assert_eq!(pipeline.enricher_count(), 1);
        pipeline.add_enricher(Box::new(TimestampNormalizer::new(0)));
        assert_eq!(pipeline.enricher_count(), 2);
    }

    #[test]
    fn test_enricher_names() {
        let ts = TimestampNormalizer::new(0);
        assert_eq!(ts.enricher_name(), "TimestampNormalizer");
        let sm = SeverityMapper::new();
        assert_eq!(sm.enricher_name(), "SeverityMapper");
        let st = SourceTagger::new(HashMap::new());
        assert_eq!(st.enricher_name(), "SourceTagger");
    }
}
