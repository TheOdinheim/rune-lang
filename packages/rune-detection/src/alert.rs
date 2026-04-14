// ═══════════════════════════════════════════════════════════════════════
// Alert Generation — structured detection output
//
// Alerts are the sensing layer's output: structured notifications that
// something needs attention. Deduplicated within a time window. Tracked
// through lifecycle (New → Acknowledged → Resolved | FalsePositive).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::{SecuritySeverity, ThreatCategory};
use serde::{Deserialize, Serialize};

use crate::error::DetectionError;

// ── AlertId ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlertId(pub String);

impl AlertId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AlertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── AlertSource ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AlertSource {
    AnomalyDetector { method: String, score: f64 },
    PatternScanner { category: String, confidence: f64 },
    BehaviorAnalyzer { profile: String, metric: String, deviation: f64 },
    IoC { indicator_type: String, indicator: String },
    Rule { rule_id: String },
    Pipeline { pipeline_id: String },
    External { source: String },
}

impl fmt::Display for AlertSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnomalyDetector { method, score } => {
                write!(f, "AnomalyDetector({method}, {score:.3})")
            }
            Self::PatternScanner { category, confidence } => {
                write!(f, "PatternScanner({category}, {confidence:.3})")
            }
            Self::BehaviorAnalyzer { profile, metric, deviation } => {
                write!(f, "BehaviorAnalyzer({profile}, {metric}, {deviation:.3})")
            }
            Self::IoC { indicator_type, indicator } => {
                write!(f, "IoC({indicator_type}, {indicator})")
            }
            Self::Rule { rule_id } => write!(f, "Rule({rule_id})"),
            Self::Pipeline { pipeline_id } => write!(f, "Pipeline({pipeline_id})"),
            Self::External { source } => write!(f, "External({source})"),
        }
    }
}

// ── AlertStatus ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    Acknowledged,
    Investigating,
    Resolved,
    FalsePositive,
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Alert ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Alert {
    pub id: AlertId,
    pub title: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub category: ThreatCategory,
    pub source: AlertSource,
    pub status: AlertStatus,
    pub created_at: i64,
    pub acknowledged_at: Option<i64>,
    pub resolved_at: Option<i64>,
    pub assignee: Option<String>,
    pub evidence: Vec<String>,
    pub related_alerts: Vec<AlertId>,
    pub false_positive: bool,
    pub metadata: HashMap<String, String>,
}

// ── AlertManager ──────────────────────────────────────────────────────

pub struct AlertManager {
    pub alerts: HashMap<AlertId, Alert>,
    pub dedup_window_ms: i64,
    pub max_alerts: usize,
    pub alert_counter: u64,
    order: Vec<AlertId>,
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertManager {
    pub fn new() -> Self {
        Self::with_config(300_000, 10_000)
    }

    pub fn with_config(dedup_window_ms: i64, max_alerts: usize) -> Self {
        Self {
            alerts: HashMap::new(),
            dedup_window_ms,
            max_alerts,
            alert_counter: 0,
            order: Vec::new(),
        }
    }

    pub fn raise(
        &mut self,
        title: &str,
        description: &str,
        severity: SecuritySeverity,
        category: ThreatCategory,
        source: AlertSource,
        now: i64,
    ) -> AlertId {
        // Dedup: look for a matching recent alert
        for id in self.order.iter().rev() {
            if let Some(a) = self.alerts.get_mut(id) {
                if a.title == title
                    && a.category == category
                    && a.severity == severity
                    && (now - a.created_at) <= self.dedup_window_ms
                {
                    a.evidence.push(description.into());
                    return a.id.clone();
                }
            }
        }
        self.alert_counter += 1;
        let id = AlertId::new(format!("alert-{}", self.alert_counter));
        let alert = Alert {
            id: id.clone(),
            title: title.into(),
            description: description.into(),
            severity,
            category,
            source,
            status: AlertStatus::New,
            created_at: now,
            acknowledged_at: None,
            resolved_at: None,
            assignee: None,
            evidence: vec![description.into()],
            related_alerts: Vec::new(),
            false_positive: false,
            metadata: HashMap::new(),
        };
        self.alerts.insert(id.clone(), alert);
        self.order.push(id.clone());
        // Enforce max_alerts: drop oldest
        while self.alerts.len() > self.max_alerts {
            if let Some(old) = self.order.first().cloned() {
                self.order.remove(0);
                self.alerts.remove(&old);
            } else {
                break;
            }
        }
        id
    }

    pub fn acknowledge(&mut self, id: &AlertId, by: &str, now: i64) -> Result<(), DetectionError> {
        let a = self
            .alerts
            .get_mut(id)
            .ok_or_else(|| DetectionError::AlertNotFound(id.0.clone()))?;
        if a.status == AlertStatus::Resolved || a.status == AlertStatus::FalsePositive {
            return Err(DetectionError::AlertAlreadyResolved(id.0.clone()));
        }
        a.status = AlertStatus::Acknowledged;
        a.acknowledged_at = Some(now);
        a.assignee = Some(by.into());
        Ok(())
    }

    pub fn resolve(&mut self, id: &AlertId, by: &str, now: i64) -> Result<(), DetectionError> {
        let a = self
            .alerts
            .get_mut(id)
            .ok_or_else(|| DetectionError::AlertNotFound(id.0.clone()))?;
        if a.status == AlertStatus::Resolved || a.status == AlertStatus::FalsePositive {
            return Err(DetectionError::AlertAlreadyResolved(id.0.clone()));
        }
        a.status = AlertStatus::Resolved;
        a.resolved_at = Some(now);
        a.assignee = Some(by.into());
        Ok(())
    }

    pub fn mark_false_positive(&mut self, id: &AlertId, by: &str) -> Result<(), DetectionError> {
        let a = self
            .alerts
            .get_mut(id)
            .ok_or_else(|| DetectionError::AlertNotFound(id.0.clone()))?;
        a.status = AlertStatus::FalsePositive;
        a.false_positive = true;
        a.assignee = Some(by.into());
        Ok(())
    }

    pub fn get(&self, id: &AlertId) -> Option<&Alert> {
        self.alerts.get(id)
    }

    pub fn active_alerts(&self) -> Vec<&Alert> {
        self.alerts
            .values()
            .filter(|a| matches!(a.status, AlertStatus::New | AlertStatus::Acknowledged))
            .collect()
    }

    pub fn alerts_by_severity(&self, severity: SecuritySeverity) -> Vec<&Alert> {
        self.alerts.values().filter(|a| a.severity == severity).collect()
    }

    pub fn alerts_by_category(&self, category: &ThreatCategory) -> Vec<&Alert> {
        self.alerts.values().filter(|a| &a.category == category).collect()
    }

    pub fn critical_alerts(&self) -> Vec<&Alert> {
        self.alerts
            .values()
            .filter(|a| a.severity >= SecuritySeverity::Critical)
            .collect()
    }

    pub fn recent_alerts(&self, since: i64) -> Vec<&Alert> {
        self.alerts.values().filter(|a| a.created_at >= since).collect()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn false_positive_rate(&self) -> f64 {
        let resolved_or_fp: Vec<_> = self
            .alerts
            .values()
            .filter(|a| matches!(a.status, AlertStatus::Resolved | AlertStatus::FalsePositive))
            .collect();
        if resolved_or_fp.is_empty() {
            return 0.0;
        }
        let fp = resolved_or_fp.iter().filter(|a| a.false_positive).count();
        fp as f64 / resolved_or_fp.len() as f64
    }

    pub fn severity_distribution(&self) -> HashMap<SecuritySeverity, usize> {
        let mut map = HashMap::new();
        for a in self.alerts.values() {
            *map.entry(a.severity).or_insert(0) += 1;
        }
        map
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Alert Correlation
//
// Time-windowed correlation of alerts by source, category, target,
// count, and rapid succession. CorrelationRules define conditions;
// AlertCorrelator evaluates them against a set of alerts.
// ═══════════════════════════════════════════════════════════════════════

// ── CorrelationCondition ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CorrelationCondition {
    SameSource,
    SameCategory,
    SameTarget { target_key: String },
    CountExceeds { threshold: usize },
    RapidSuccession { max_interval_ms: i64 },
    Custom { key: String, value: String },
}

// ── CorrelationRule ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub conditions: Vec<CorrelationCondition>,
    pub window_ms: i64,
    pub min_alerts: usize,
}

// ── CorrelatedAlert ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelatedAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub alert_ids: Vec<AlertId>,
    pub correlation_time: i64,
    pub detail: String,
}

// ── AlertCorrelator ──────────────────────────────────────────────────

#[derive(Default)]
pub struct AlertCorrelator {
    rules: Vec<CorrelationRule>,
}

impl AlertCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn correlate(&self, alerts: &[&Alert], now: i64) -> Vec<CorrelatedAlert> {
        let mut results = Vec::new();

        for rule in &self.rules {
            // Filter alerts within the time window
            let cutoff = now - rule.window_ms;
            let windowed: Vec<&Alert> = alerts
                .iter()
                .filter(|a| a.created_at >= cutoff)
                .copied()
                .collect();

            if windowed.len() < rule.min_alerts {
                continue;
            }

            // Check all conditions
            let mut passes = true;
            for cond in &rule.conditions {
                match cond {
                    CorrelationCondition::SameSource => {
                        if windowed.len() >= 2 {
                            let first_src = source_key(&windowed[0].source);
                            passes = passes && windowed.iter().all(|a| source_key(&a.source) == first_src);
                        }
                    }
                    CorrelationCondition::SameCategory => {
                        if windowed.len() >= 2 {
                            let first_cat = &windowed[0].category;
                            passes = passes && windowed.iter().all(|a| &a.category == first_cat);
                        }
                    }
                    CorrelationCondition::SameTarget { target_key } => {
                        if windowed.len() >= 2 {
                            let first_val = windowed[0].metadata.get(target_key);
                            passes = passes && windowed.iter().all(|a| a.metadata.get(target_key) == first_val && first_val.is_some());
                        }
                    }
                    CorrelationCondition::CountExceeds { threshold } => {
                        passes = passes && windowed.len() > *threshold;
                    }
                    CorrelationCondition::RapidSuccession { max_interval_ms } => {
                        if windowed.len() >= 2 {
                            let mut timestamps: Vec<i64> = windowed.iter().map(|a| a.created_at).collect();
                            timestamps.sort();
                            let rapid = timestamps.windows(2).any(|w| (w[1] - w[0]) <= *max_interval_ms);
                            passes = passes && rapid;
                        }
                    }
                    CorrelationCondition::Custom { key, value } => {
                        passes = passes && windowed.iter().any(|a| a.metadata.get(key).map(|v| v == value).unwrap_or(false));
                    }
                }
            }

            if passes {
                let ids: Vec<AlertId> = windowed.iter().map(|a| a.id.clone()).collect();
                let detail = format!(
                    "rule '{}' correlated {} alerts within {}ms",
                    rule.name, ids.len(), rule.window_ms
                );
                results.push(CorrelatedAlert {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    alert_ids: ids,
                    correlation_time: now,
                    detail,
                });
            }
        }

        results
    }
}

fn source_key(source: &AlertSource) -> String {
    match source {
        AlertSource::AnomalyDetector { .. } => "anomaly".into(),
        AlertSource::PatternScanner { .. } => "pattern".into(),
        AlertSource::BehaviorAnalyzer { .. } => "behavior".into(),
        AlertSource::IoC { indicator_type, .. } => format!("ioc:{indicator_type}"),
        AlertSource::Rule { rule_id } => format!("rule:{rule_id}"),
        AlertSource::Pipeline { pipeline_id } => format!("pipeline:{pipeline_id}"),
        AlertSource::External { source } => format!("external:{source}"),
    }
}

impl fmt::Debug for AlertCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertCorrelator")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raise_one(mgr: &mut AlertManager, title: &str, now: i64) -> AlertId {
        mgr.raise(
            title,
            "test",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            AlertSource::External { source: "test".into() },
            now,
        )
    }

    #[test]
    fn test_raise_creates_alert() {
        let mut m = AlertManager::new();
        let id = raise_one(&mut m, "t1", 1000);
        assert!(m.get(&id).is_some());
        assert_eq!(m.alert_count(), 1);
    }

    #[test]
    fn test_dedup_within_window() {
        let mut m = AlertManager::new();
        let id1 = raise_one(&mut m, "t1", 1000);
        let id2 = raise_one(&mut m, "t1", 1500);
        assert_eq!(id1, id2);
        assert_eq!(m.alert_count(), 1);
        assert_eq!(m.get(&id1).unwrap().evidence.len(), 2);
    }

    #[test]
    fn test_no_dedup_outside_window() {
        let mut m = AlertManager::with_config(100, 1000);
        let id1 = raise_one(&mut m, "t1", 1000);
        let id2 = raise_one(&mut m, "t1", 2000);
        assert_ne!(id1, id2);
        assert_eq!(m.alert_count(), 2);
    }

    #[test]
    fn test_acknowledge_updates_status() {
        let mut m = AlertManager::new();
        let id = raise_one(&mut m, "t1", 1000);
        m.acknowledge(&id, "alice", 1100).unwrap();
        let a = m.get(&id).unwrap();
        assert_eq!(a.status, AlertStatus::Acknowledged);
        assert_eq!(a.acknowledged_at, Some(1100));
    }

    #[test]
    fn test_resolve_updates_status() {
        let mut m = AlertManager::new();
        let id = raise_one(&mut m, "t1", 1000);
        m.resolve(&id, "alice", 1200).unwrap();
        let a = m.get(&id).unwrap();
        assert_eq!(a.status, AlertStatus::Resolved);
    }

    #[test]
    fn test_mark_false_positive() {
        let mut m = AlertManager::new();
        let id = raise_one(&mut m, "t1", 1000);
        m.mark_false_positive(&id, "alice").unwrap();
        let a = m.get(&id).unwrap();
        assert!(a.false_positive);
        assert_eq!(a.status, AlertStatus::FalsePositive);
    }

    #[test]
    fn test_active_alerts_filter() {
        let mut m = AlertManager::new();
        let id1 = raise_one(&mut m, "t1", 1000);
        let id2 = raise_one(&mut m, "t2", 2000);
        m.resolve(&id2, "a", 2100).unwrap();
        let active = m.active_alerts();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id1);
    }

    #[test]
    fn test_alerts_by_severity() {
        let mut m = AlertManager::new();
        m.raise(
            "t1",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            AlertSource::External { source: "s".into() },
            1000,
        );
        m.raise(
            "t2",
            "d",
            SecuritySeverity::Low,
            ThreatCategory::Spoofing,
            AlertSource::External { source: "s".into() },
            2000,
        );
        assert_eq!(m.alerts_by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_critical_alerts() {
        let mut m = AlertManager::new();
        m.raise(
            "t1",
            "d",
            SecuritySeverity::Critical,
            ThreatCategory::Spoofing,
            AlertSource::External { source: "s".into() },
            1000,
        );
        m.raise(
            "t2",
            "d",
            SecuritySeverity::Low,
            ThreatCategory::Spoofing,
            AlertSource::External { source: "s".into() },
            2000,
        );
        assert_eq!(m.critical_alerts().len(), 1);
    }

    #[test]
    fn test_false_positive_rate() {
        let mut m = AlertManager::new();
        let id1 = raise_one(&mut m, "t1", 1000);
        let id2 = raise_one(&mut m, "t2", 2000);
        m.resolve(&id1, "a", 1100).unwrap();
        m.mark_false_positive(&id2, "a").unwrap();
        // 1 fp out of 2 resolved/fp
        assert!((m.false_positive_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_severity_distribution() {
        let mut m = AlertManager::new();
        m.raise(
            "t1",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            AlertSource::External { source: "s".into() },
            1000,
        );
        m.raise(
            "t2",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Tampering,
            AlertSource::External { source: "s".into() },
            2000,
        );
        let dist = m.severity_distribution();
        assert_eq!(dist.get(&SecuritySeverity::High), Some(&2));
    }

    #[test]
    fn test_alert_id_sequential() {
        let mut m = AlertManager::new();
        let id1 = raise_one(&mut m, "t1", 1000);
        let id2 = raise_one(&mut m, "t2", 2000);
        assert_eq!(id1.as_str(), "alert-1");
        assert_eq!(id2.as_str(), "alert-2");
    }

    // ── Layer 2: AlertCorrelator tests ──────────────────────────────────

    fn make_alert(id: &str, source: AlertSource, category: ThreatCategory, ts: i64) -> Alert {
        Alert {
            id: AlertId(id.into()),
            title: format!("alert {id}"),
            description: "test".into(),
            severity: SecuritySeverity::High,
            category,
            source,
            status: AlertStatus::New,
            created_at: ts,
            acknowledged_at: None,
            resolved_at: None,
            assignee: None,
            evidence: Vec::new(),
            related_alerts: Vec::new(),
            false_positive: false,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_correlator_same_source() {
        let c = {
            let mut c = AlertCorrelator::new();
            c.add_rule(CorrelationRule {
                id: "r1".into(),
                name: "same-source".into(),
                conditions: vec![CorrelationCondition::SameSource],
                window_ms: 5000,
                min_alerts: 2,
            });
            c
        };
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 1000);
        let a2 = make_alert("2", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Tampering, 2000);
        let results = c.correlate(&[&a1, &a2], 3000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].alert_ids.len(), 2);
    }

    #[test]
    fn test_correlator_same_category() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "same-cat".into(),
            conditions: vec![CorrelationCondition::SameCategory],
            window_ms: 5000,
            min_alerts: 2,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::PromptInjection, 1000);
        let a2 = make_alert("2", AlertSource::AnomalyDetector { method: "zscore".into(), score: 4.5 }, ThreatCategory::PromptInjection, 2000);
        let results = c.correlate(&[&a1, &a2], 3000);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_correlator_different_category_no_match() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "same-cat".into(),
            conditions: vec![CorrelationCondition::SameCategory],
            window_ms: 5000,
            min_alerts: 2,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::PromptInjection, 1000);
        let a2 = make_alert("2", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 2000);
        let results = c.correlate(&[&a1, &a2], 3000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_correlator_count_exceeds() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "count".into(),
            conditions: vec![CorrelationCondition::CountExceeds { threshold: 2 }],
            window_ms: 5000,
            min_alerts: 2,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 1000);
        let a2 = make_alert("2", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 2000);
        let a3 = make_alert("3", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 3000);
        let results = c.correlate(&[&a1, &a2, &a3], 4000);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_correlator_rapid_succession() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "rapid".into(),
            conditions: vec![CorrelationCondition::RapidSuccession { max_interval_ms: 100 }],
            window_ms: 5000,
            min_alerts: 2,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 1000);
        let a2 = make_alert("2", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 1050);
        let results = c.correlate(&[&a1, &a2], 2000);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_correlator_outside_window() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "same-source".into(),
            conditions: vec![CorrelationCondition::SameSource],
            window_ms: 100,
            min_alerts: 2,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 100);
        let a2 = make_alert("2", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 5000);
        let results = c.correlate(&[&a1, &a2], 5100);
        // a1 is outside the window (5100-100=5000, a1 at 100 < 5000)
        assert!(results.is_empty());
    }

    #[test]
    fn test_correlator_min_alerts_not_met() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "high-count".into(),
            conditions: vec![CorrelationCondition::CountExceeds { threshold: 0 }],
            window_ms: 5000,
            min_alerts: 5,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 1000);
        let results = c.correlate(&[&a1], 2000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_correlator_multiple_rules() {
        let mut c = AlertCorrelator::new();
        c.add_rule(CorrelationRule {
            id: "r1".into(),
            name: "same-source".into(),
            conditions: vec![CorrelationCondition::SameSource],
            window_ms: 5000,
            min_alerts: 2,
        });
        c.add_rule(CorrelationRule {
            id: "r2".into(),
            name: "same-cat".into(),
            conditions: vec![CorrelationCondition::SameCategory],
            window_ms: 5000,
            min_alerts: 2,
        });
        let a1 = make_alert("1", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 1000);
        let a2 = make_alert("2", AlertSource::PatternScanner { category: "test".into(), confidence: 0.8 }, ThreatCategory::Spoofing, 2000);
        let results = c.correlate(&[&a1, &a2], 3000);
        assert_eq!(results.len(), 2); // both rules match
    }
}
