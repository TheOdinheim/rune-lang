// ═══════════════════════════════════════════════════════════════════════
// Enrichment — Cross-crate event enrichment with condition-based rules.
//
// EventEnricher applies enrichment rules to events during ingestion.
// Rules match events by condition and apply transformations such as
// adding tags, setting correlation IDs, escalating severity, or
// adding metadata details.
// ═══════════════════════════════════════════════════════════════════════

use rune_security::SecuritySeverity;

use crate::event::*;

// ── EnrichmentCondition ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EnrichmentCondition {
    SourceIs(SourceCrate),
    CategoryIs(EventCategory),
    SeverityAtLeast(SecuritySeverity),
    TagExists(String),
    Always,
}

impl EnrichmentCondition {
    pub fn matches(&self, event: &UnifiedEvent) -> bool {
        match self {
            Self::SourceIs(s) => event.source == *s,
            Self::CategoryIs(c) => event.category == *c,
            Self::SeverityAtLeast(s) => event.severity >= *s,
            Self::TagExists(tag) => event.tags.contains(tag),
            Self::Always => true,
        }
    }
}

// ── Enrichment ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Enrichment {
    AddTag(String),
    SetCorrelationId(String),
    EscalateSeverity(SecuritySeverity),
    AddDetail(String),
}

impl Enrichment {
    pub fn apply(&self, event: &mut UnifiedEvent) {
        match self {
            Self::AddTag(tag) => {
                if !event.tags.contains(tag) {
                    event.tags.push(tag.clone());
                }
            }
            Self::SetCorrelationId(cid) => {
                if event.correlation_id.is_none() {
                    event.correlation_id = Some(cid.clone());
                }
            }
            Self::EscalateSeverity(sev) => {
                if event.severity < *sev {
                    event.severity = *sev;
                }
            }
            Self::AddDetail(extra) => {
                if event.detail.is_empty() {
                    event.detail = extra.clone();
                } else {
                    event.detail = format!("{}; {}", event.detail, extra);
                }
            }
        }
    }
}

// ── EnrichmentRule ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EnrichmentRule {
    pub name: String,
    pub condition: EnrichmentCondition,
    pub enrichments: Vec<Enrichment>,
}

impl EnrichmentRule {
    pub fn new(
        name: impl Into<String>,
        condition: EnrichmentCondition,
        enrichments: Vec<Enrichment>,
    ) -> Self {
        Self {
            name: name.into(),
            condition,
            enrichments,
        }
    }

    pub fn apply(&self, event: &mut UnifiedEvent) -> usize {
        if self.condition.matches(event) {
            for enrichment in &self.enrichments {
                enrichment.apply(event);
            }
            self.enrichments.len()
        } else {
            0
        }
    }
}

// ── EventEnricher ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EventEnricher {
    rules: Vec<EnrichmentRule>,
}

impl EventEnricher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: EnrichmentRule) {
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[EnrichmentRule] {
        &self.rules
    }

    pub fn enrich(&self, event: &mut UnifiedEvent) -> usize {
        let mut total = 0;
        for rule in &self.rules {
            total += rule.apply(event);
        }
        total
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: &str, source: SourceCrate, category: EventCategory) -> UnifiedEvent {
        UnifiedEventBuilder::new(id, source, category, "action", 1000)
            .severity(SecuritySeverity::Medium)
            .actor("system")
            .detail("original detail")
            .build()
    }

    #[test]
    fn test_condition_source_is() {
        let cond = EnrichmentCondition::SourceIs(SourceCrate::RuneSecurity);
        let evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert!(cond.matches(&evt));
        let evt2 = make_event("e2", SourceCrate::RuneIdentity, EventCategory::Authentication);
        assert!(!cond.matches(&evt2));
    }

    #[test]
    fn test_condition_category_is() {
        let cond = EnrichmentCondition::CategoryIs(EventCategory::ThreatDetection);
        let evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert!(cond.matches(&evt));
    }

    #[test]
    fn test_condition_severity_at_least() {
        let cond = EnrichmentCondition::SeverityAtLeast(SecuritySeverity::High);
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert!(!cond.matches(&evt)); // Medium < High
        evt.severity = SecuritySeverity::High;
        assert!(cond.matches(&evt));
    }

    #[test]
    fn test_condition_tag_exists() {
        let cond = EnrichmentCondition::TagExists("security".into());
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert!(!cond.matches(&evt));
        evt.tags.push("security".into());
        assert!(cond.matches(&evt));
    }

    #[test]
    fn test_condition_always() {
        let cond = EnrichmentCondition::Always;
        let evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert!(cond.matches(&evt));
    }

    #[test]
    fn test_enrichment_add_tag() {
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        Enrichment::AddTag("tagged".into()).apply(&mut evt);
        assert!(evt.tags.contains(&"tagged".to_string()));
        // No duplicate
        Enrichment::AddTag("tagged".into()).apply(&mut evt);
        assert_eq!(evt.tags.iter().filter(|t| *t == "tagged").count(), 1);
    }

    #[test]
    fn test_enrichment_set_correlation_id() {
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert!(evt.correlation_id.is_none());
        Enrichment::SetCorrelationId("corr-1".into()).apply(&mut evt);
        assert_eq!(evt.correlation_id, Some("corr-1".into()));
        // Does not overwrite existing
        Enrichment::SetCorrelationId("corr-2".into()).apply(&mut evt);
        assert_eq!(evt.correlation_id, Some("corr-1".into()));
    }

    #[test]
    fn test_enrichment_escalate_severity() {
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        assert_eq!(evt.severity, SecuritySeverity::Medium);
        Enrichment::EscalateSeverity(SecuritySeverity::High).apply(&mut evt);
        assert_eq!(evt.severity, SecuritySeverity::High);
        // Does not downgrade
        Enrichment::EscalateSeverity(SecuritySeverity::Low).apply(&mut evt);
        assert_eq!(evt.severity, SecuritySeverity::High);
    }

    #[test]
    fn test_enrichment_add_detail() {
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        Enrichment::AddDetail("extra info".into()).apply(&mut evt);
        assert!(evt.detail.contains("extra info"));
        assert!(evt.detail.contains("original detail"));
    }

    #[test]
    fn test_enrichment_rule_applies() {
        let rule = EnrichmentRule::new(
            "tag-security",
            EnrichmentCondition::SourceIs(SourceCrate::RuneSecurity),
            vec![Enrichment::AddTag("auto-security".into())],
        );
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        let applied = rule.apply(&mut evt);
        assert_eq!(applied, 1);
        assert!(evt.tags.contains(&"auto-security".to_string()));
    }

    #[test]
    fn test_enrichment_rule_skips_non_match() {
        let rule = EnrichmentRule::new(
            "tag-security",
            EnrichmentCondition::SourceIs(SourceCrate::RuneSecurity),
            vec![Enrichment::AddTag("auto-security".into())],
        );
        let mut evt = make_event("e1", SourceCrate::RuneIdentity, EventCategory::Authentication);
        let applied = rule.apply(&mut evt);
        assert_eq!(applied, 0);
        assert!(evt.tags.is_empty());
    }

    #[test]
    fn test_event_enricher_multiple_rules() {
        let mut enricher = EventEnricher::new();
        enricher.add_rule(EnrichmentRule::new(
            "tag-all",
            EnrichmentCondition::Always,
            vec![Enrichment::AddTag("audited".into())],
        ));
        enricher.add_rule(EnrichmentRule::new(
            "escalate-threats",
            EnrichmentCondition::CategoryIs(EventCategory::ThreatDetection),
            vec![Enrichment::EscalateSeverity(SecuritySeverity::High)],
        ));
        let mut evt = make_event("e1", SourceCrate::RuneSecurity, EventCategory::ThreatDetection);
        let total = enricher.enrich(&mut evt);
        assert_eq!(total, 2);
        assert!(evt.tags.contains(&"audited".to_string()));
        assert_eq!(evt.severity, SecuritySeverity::High);
    }

    #[test]
    fn test_enricher_rules_accessor() {
        let mut enricher = EventEnricher::new();
        enricher.add_rule(EnrichmentRule::new(
            "r1",
            EnrichmentCondition::Always,
            vec![Enrichment::AddTag("x".into())],
        ));
        assert_eq!(enricher.rules().len(), 1);
        assert_eq!(enricher.rules()[0].name, "r1");
    }
}
