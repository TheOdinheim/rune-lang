// ═══════════════════════════════════════════════════════════════════════
// Policy — monitoring policy: targets, alert channels, interval tiers.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::SecuritySeverity;

// ── AlertChannel ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertChannel {
    Log,
    Webhook { url: String },
    Email { address: String },
    Slack { channel: String },
    PagerDuty { integration_key: String },
    Custom { name: String },
}

impl fmt::Display for AlertChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log => f.write_str("log"),
            Self::Webhook { url } => write!(f, "webhook:{url}"),
            Self::Email { address } => write!(f, "email:{address}"),
            Self::Slack { channel } => write!(f, "slack:{channel}"),
            Self::PagerDuty { .. } => f.write_str("pagerduty"),
            Self::Custom { name } => write!(f, "custom:{name}"),
        }
    }
}

// ── MonitoringTarget ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitoringTarget {
    Service(String),
    Component(String),
    Metric(String),
    HealthCheck(String),
    AllServices,
}

impl fmt::Display for MonitoringTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(s) => write!(f, "service:{s}"),
            Self::Component(s) => write!(f, "component:{s}"),
            Self::Metric(s) => write!(f, "metric:{s}"),
            Self::HealthCheck(s) => write!(f, "health:{s}"),
            Self::AllServices => f.write_str("all-services"),
        }
    }
}

// ── MonitoringPolicy ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MonitoringPolicy {
    pub id: String,
    pub name: String,
    pub target: MonitoringTarget,
    pub health_check_interval_ms: u64,
    pub metric_collection_interval_ms: u64,
    pub threshold_evaluation_interval_ms: u64,
    pub min_alert_severity: SecuritySeverity,
    pub channels: Vec<AlertChannel>,
    pub enabled: bool,
    pub description: String,
}

impl MonitoringPolicy {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        target: MonitoringTarget,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            target,
            health_check_interval_ms: 30_000,
            metric_collection_interval_ms: 15_000,
            threshold_evaluation_interval_ms: 15_000,
            min_alert_severity: SecuritySeverity::Medium,
            channels: vec![AlertChannel::Log],
            enabled: true,
            description: String::new(),
        }
    }

    pub fn with_channel(mut self, c: AlertChannel) -> Self {
        self.channels.push(c);
        self
    }

    pub fn with_min_severity(mut self, s: SecuritySeverity) -> Self {
        self.min_alert_severity = s;
        self
    }

    pub fn with_health_interval(mut self, ms: u64) -> Self {
        self.health_check_interval_ms = ms;
        self
    }

    pub fn with_metric_interval(mut self, ms: u64) -> Self {
        self.metric_collection_interval_ms = ms;
        self
    }

    pub fn with_threshold_interval(mut self, ms: u64) -> Self {
        self.threshold_evaluation_interval_ms = ms;
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn should_notify(&self, severity: SecuritySeverity) -> bool {
        self.enabled && severity >= self.min_alert_severity
    }
}

// ── MonitoringPolicySet ───────────────────────────────────────────────

#[derive(Default)]
pub struct MonitoringPolicySet {
    pub policies: HashMap<String, MonitoringPolicy>,
}

impl MonitoringPolicySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, p: MonitoringPolicy) {
        self.policies.insert(p.id.clone(), p);
    }

    pub fn get(&self, id: &str) -> Option<&MonitoringPolicy> {
        self.policies.get(id)
    }

    pub fn for_target(&self, target: &MonitoringTarget) -> Vec<&MonitoringPolicy> {
        self.policies
            .values()
            .filter(|p| p.enabled && (&p.target == target || p.target == MonitoringTarget::AllServices))
            .collect()
    }

    pub fn enabled_count(&self) -> usize {
        self.policies.values().filter(|p| p.enabled).count()
    }
}

// ── Templates ─────────────────────────────────────────────────────────

pub fn default_production() -> MonitoringPolicy {
    MonitoringPolicy::new(
        "default_production",
        "Default Production Policy",
        MonitoringTarget::AllServices,
    )
    .with_health_interval(30_000)
    .with_metric_interval(15_000)
    .with_threshold_interval(15_000)
    .with_min_severity(SecuritySeverity::Medium)
}

pub fn high_availability() -> MonitoringPolicy {
    MonitoringPolicy::new(
        "high_availability",
        "High Availability Policy",
        MonitoringTarget::AllServices,
    )
    .with_health_interval(5_000)
    .with_metric_interval(5_000)
    .with_threshold_interval(5_000)
    .with_min_severity(SecuritySeverity::Low)
    .with_channel(AlertChannel::PagerDuty {
        integration_key: "replace-me".into(),
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_has_log_channel() {
        let p = MonitoringPolicy::new("a", "A", MonitoringTarget::AllServices);
        assert_eq!(p.channels.len(), 1);
        assert!(matches!(p.channels[0], AlertChannel::Log));
    }

    #[test]
    fn test_should_notify_respects_severity_floor() {
        let p = MonitoringPolicy::new("a", "A", MonitoringTarget::AllServices)
            .with_min_severity(SecuritySeverity::High);
        assert!(!p.should_notify(SecuritySeverity::Low));
        assert!(!p.should_notify(SecuritySeverity::Medium));
        assert!(p.should_notify(SecuritySeverity::High));
        assert!(p.should_notify(SecuritySeverity::Critical));
    }

    #[test]
    fn test_disabled_policy_never_notifies() {
        let p = MonitoringPolicy::new("a", "A", MonitoringTarget::AllServices)
            .with_min_severity(SecuritySeverity::Info)
            .disable();
        assert!(!p.should_notify(SecuritySeverity::Emergency));
    }

    #[test]
    fn test_add_and_for_target() {
        let mut set = MonitoringPolicySet::new();
        set.add(MonitoringPolicy::new(
            "a",
            "A",
            MonitoringTarget::Service("api".into()),
        ));
        set.add(MonitoringPolicy::new(
            "b",
            "B",
            MonitoringTarget::AllServices,
        ));
        let matches = set.for_target(&MonitoringTarget::Service("api".into()));
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_for_target_excludes_disabled() {
        let mut set = MonitoringPolicySet::new();
        set.add(
            MonitoringPolicy::new("a", "A", MonitoringTarget::AllServices).disable(),
        );
        let matches = set.for_target(&MonitoringTarget::Service("api".into()));
        assert!(matches.is_empty());
    }

    #[test]
    fn test_enabled_count() {
        let mut set = MonitoringPolicySet::new();
        set.add(MonitoringPolicy::new("a", "A", MonitoringTarget::AllServices));
        set.add(
            MonitoringPolicy::new("b", "B", MonitoringTarget::AllServices).disable(),
        );
        assert_eq!(set.enabled_count(), 1);
    }

    #[test]
    fn test_templates() {
        let p = default_production();
        assert_eq!(p.id, "default_production");
        assert_eq!(p.min_alert_severity, SecuritySeverity::Medium);

        let h = high_availability();
        assert_eq!(h.health_check_interval_ms, 5_000);
        assert_eq!(h.min_alert_severity, SecuritySeverity::Low);
        assert!(h
            .channels
            .iter()
            .any(|c| matches!(c, AlertChannel::PagerDuty { .. })));
    }

    #[test]
    fn test_alert_channel_display() {
        assert_eq!(AlertChannel::Log.to_string(), "log");
        assert_eq!(
            AlertChannel::Webhook { url: "https://x".into() }.to_string(),
            "webhook:https://x"
        );
    }

    #[test]
    fn test_target_display() {
        assert_eq!(
            MonitoringTarget::Service("api".into()).to_string(),
            "service:api"
        );
        assert_eq!(MonitoringTarget::AllServices.to_string(), "all-services");
    }

    #[test]
    fn test_builder_interval_overrides() {
        let p = MonitoringPolicy::new("a", "A", MonitoringTarget::AllServices)
            .with_health_interval(1_000)
            .with_metric_interval(2_000)
            .with_threshold_interval(3_000);
        assert_eq!(p.health_check_interval_ms, 1_000);
        assert_eq!(p.metric_collection_interval_ms, 2_000);
        assert_eq!(p.threshold_evaluation_interval_ms, 3_000);
    }
}
