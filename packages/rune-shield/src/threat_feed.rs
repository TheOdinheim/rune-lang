// ═══════════════════════════════════════════════════════════════════════
// Threat Feed — Threat intelligence feed source trait.
//
// Layer 3 defines the interface for threat intelligence feeds so
// customers can plug in STIX/TAXII, MISP, or proprietary feeds.
// RUNE provides the shaped hole — the customer provides the
// transport and feed implementation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::ShieldError;

// ── IndicatorType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    Ip,
    Domain,
    Url,
    FileHash,
    PromptPattern,
    ToolUseSignature,
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ThreatIndicator ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub severity: String,
    pub source: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub description: String,
}

impl ThreatIndicator {
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

// ── ThreatFeedSource trait ───────────────────────────────────────

pub trait ThreatFeedSource {
    fn fetch_indicators(&self) -> Vec<&ThreatIndicator>;
    fn refresh(&mut self) -> Result<usize, ShieldError>;
    fn indicator_count(&self) -> usize;
    fn source_name(&self) -> &str;
    fn last_refreshed(&self) -> Option<i64>;
    fn supported_indicator_types(&self) -> Vec<IndicatorType>;
    fn is_active(&self) -> bool;
}

// ── InMemoryThreatFeed ───────────────────────────────────────────

pub struct InMemoryThreatFeed {
    name: String,
    indicators: Vec<ThreatIndicator>,
    last_refreshed_at: Option<i64>,
    active: bool,
}

impl InMemoryThreatFeed {
    pub fn new(name: &str, indicators: Vec<ThreatIndicator>) -> Self {
        Self {
            name: name.to_string(),
            indicators,
            last_refreshed_at: None,
            active: true,
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.indicators.push(indicator);
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Remove expired indicators, returning count removed.
    pub fn purge_expired(&mut self, now: i64) -> usize {
        let before = self.indicators.len();
        self.indicators.retain(|i| !i.is_expired(now));
        before - self.indicators.len()
    }

    /// Active (non-expired) indicators only.
    pub fn active_indicators(&self, now: i64) -> Vec<&ThreatIndicator> {
        self.indicators.iter().filter(|i| !i.is_expired(now)).collect()
    }
}

impl ThreatFeedSource for InMemoryThreatFeed {
    fn fetch_indicators(&self) -> Vec<&ThreatIndicator> {
        self.indicators.iter().collect()
    }

    fn refresh(&mut self) -> Result<usize, ShieldError> {
        self.last_refreshed_at = Some(0); // Placeholder — in-memory has nothing to refresh
        Ok(self.indicators.len())
    }

    fn indicator_count(&self) -> usize {
        self.indicators.len()
    }

    fn source_name(&self) -> &str {
        &self.name
    }

    fn last_refreshed(&self) -> Option<i64> {
        self.last_refreshed_at
    }

    fn supported_indicator_types(&self) -> Vec<IndicatorType> {
        vec![
            IndicatorType::Ip,
            IndicatorType::Domain,
            IndicatorType::Url,
            IndicatorType::FileHash,
            IndicatorType::PromptPattern,
            IndicatorType::ToolUseSignature,
        ]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_indicator(id: &str, itype: IndicatorType, expires: Option<i64>) -> ThreatIndicator {
        ThreatIndicator {
            id: id.to_string(),
            indicator_type: itype,
            value: format!("value-{id}"),
            severity: "High".to_string(),
            source: "test-feed".to_string(),
            created_at: 100,
            expires_at: expires,
            description: "test indicator".to_string(),
        }
    }

    #[test]
    fn test_fetch_indicators() {
        let feed = InMemoryThreatFeed::new("test", vec![
            make_indicator("i1", IndicatorType::Ip, None),
            make_indicator("i2", IndicatorType::Domain, None),
        ]);
        assert_eq!(feed.fetch_indicators().len(), 2);
    }

    #[test]
    fn test_indicator_count() {
        let feed = InMemoryThreatFeed::new("test", vec![
            make_indicator("i1", IndicatorType::Ip, None),
        ]);
        assert_eq!(feed.indicator_count(), 1);
    }

    #[test]
    fn test_source_name() {
        let feed = InMemoryThreatFeed::new("my-feed", vec![]);
        assert_eq!(feed.source_name(), "my-feed");
    }

    #[test]
    fn test_refresh() {
        let mut feed = InMemoryThreatFeed::new("test", vec![
            make_indicator("i1", IndicatorType::Ip, None),
        ]);
        assert!(feed.last_refreshed().is_none());
        let count = feed.refresh().unwrap();
        assert_eq!(count, 1);
        assert!(feed.last_refreshed().is_some());
    }

    #[test]
    fn test_is_active() {
        let mut feed = InMemoryThreatFeed::new("test", vec![]);
        assert!(feed.is_active());
        feed.deactivate();
        assert!(!feed.is_active());
    }

    #[test]
    fn test_supported_indicator_types() {
        let feed = InMemoryThreatFeed::new("test", vec![]);
        let types = feed.supported_indicator_types();
        assert!(types.contains(&IndicatorType::Ip));
        assert!(types.contains(&IndicatorType::PromptPattern));
    }

    #[test]
    fn test_ttl_expired_filtering() {
        let mut feed = InMemoryThreatFeed::new("test", vec![
            make_indicator("i1", IndicatorType::Ip, Some(500)),
            make_indicator("i2", IndicatorType::Domain, Some(1000)),
            make_indicator("i3", IndicatorType::Url, None),
        ]);
        let active = feed.active_indicators(600);
        assert_eq!(active.len(), 2); // i2 and i3
        let purged = feed.purge_expired(600);
        assert_eq!(purged, 1);
        assert_eq!(feed.indicator_count(), 2);
    }

    #[test]
    fn test_indicator_is_expired() {
        let i = make_indicator("i1", IndicatorType::Ip, Some(500));
        assert!(!i.is_expired(400));
        assert!(i.is_expired(500));
        assert!(i.is_expired(600));
    }

    #[test]
    fn test_add_indicator() {
        let mut feed = InMemoryThreatFeed::new("test", vec![]);
        feed.add_indicator(make_indicator("i1", IndicatorType::FileHash, None));
        assert_eq!(feed.indicator_count(), 1);
    }
}
