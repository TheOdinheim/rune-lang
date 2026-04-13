// ═══════════════════════════════════════════════════════════════════════
// Failsafe — Fail-safe behavior definitions: what happens when things
// go wrong.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SafetyError;

// ── FailsafeId ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FailsafeId(pub String);

impl FailsafeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for FailsafeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── FailsafeTrigger ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FailsafeTrigger {
    ConstraintViolation { constraint_id: String },
    MonitorTriggered { monitor_id: String },
    ComponentFailure { component: String },
    ThresholdExceeded { metric: String, threshold: f64 },
    ManualActivation,
    CascadeFrom { failsafe_id: String },
    Custom(String),
}

impl fmt::Display for FailsafeTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConstraintViolation { constraint_id } => {
                write!(f, "ConstraintViolation({constraint_id})")
            }
            Self::MonitorTriggered { monitor_id } => {
                write!(f, "MonitorTriggered({monitor_id})")
            }
            Self::ComponentFailure { component } => {
                write!(f, "ComponentFailure({component})")
            }
            Self::ThresholdExceeded { metric, threshold } => {
                write!(f, "ThresholdExceeded({metric} > {threshold})")
            }
            Self::ManualActivation => write!(f, "ManualActivation"),
            Self::CascadeFrom { failsafe_id } => {
                write!(f, "CascadeFrom({failsafe_id})")
            }
            Self::Custom(desc) => write!(f, "Custom({desc})"),
        }
    }
}

// ── FailsafeAction ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailsafeAction {
    SwitchToSafeMode { mode: String },
    DisableComponent { component: String },
    RateLimitTo { max_per_minute: u64 },
    RejectAllRequests { message: String },
    FallbackToDefault { default_response: String },
    NotifyOperator { channel: String, message: String },
    LogAndContinue { message: String },
    GracefulShutdown { timeout_ms: u64 },
}

impl fmt::Display for FailsafeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SwitchToSafeMode { mode } => write!(f, "SwitchToSafeMode({mode})"),
            Self::DisableComponent { component } => {
                write!(f, "DisableComponent({component})")
            }
            Self::RateLimitTo { max_per_minute } => {
                write!(f, "RateLimitTo({max_per_minute}/min)")
            }
            Self::RejectAllRequests { message } => {
                write!(f, "RejectAllRequests({message})")
            }
            Self::FallbackToDefault { default_response } => {
                write!(f, "FallbackToDefault({default_response})")
            }
            Self::NotifyOperator { channel, message } => {
                write!(f, "NotifyOperator({channel}: {message})")
            }
            Self::LogAndContinue { message } => write!(f, "LogAndContinue({message})"),
            Self::GracefulShutdown { timeout_ms } => {
                write!(f, "GracefulShutdown({timeout_ms}ms)")
            }
        }
    }
}

// ── RecoveryProcedure ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProcedure {
    pub description: String,
    pub steps: Vec<String>,
    pub auto_recovery: bool,
    pub recovery_timeout_ms: Option<u64>,
    pub requires_human_approval: bool,
}

impl RecoveryProcedure {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            steps: Vec::new(),
            auto_recovery: false,
            recovery_timeout_ms: None,
            requires_human_approval: true,
        }
    }

    pub fn with_step(mut self, step: impl Into<String>) -> Self {
        self.steps.push(step.into());
        self
    }

    pub fn with_auto_recovery(mut self, timeout_ms: u64) -> Self {
        self.auto_recovery = true;
        self.recovery_timeout_ms = Some(timeout_ms);
        self.requires_human_approval = false;
        self
    }
}

// ── FailsafeBehavior ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailsafeBehavior {
    pub id: FailsafeId,
    pub name: String,
    pub description: String,
    pub trigger: FailsafeTrigger,
    pub actions: Vec<FailsafeAction>,
    pub priority: u32,
    pub recovery: Option<RecoveryProcedure>,
    pub tested: bool,
    pub last_tested: Option<i64>,
    pub test_interval_days: Option<u64>,
    pub enabled: bool,
}

impl FailsafeBehavior {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        trigger: FailsafeTrigger,
    ) -> Self {
        Self {
            id: FailsafeId::new(id),
            name: name.into(),
            description: String::new(),
            trigger,
            actions: Vec::new(),
            priority: 0,
            recovery: None,
            tested: false,
            last_tested: None,
            test_interval_days: None,
            enabled: true,
        }
    }

    pub fn with_action(mut self, action: FailsafeAction) -> Self {
        self.actions.push(action);
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_recovery(mut self, recovery: RecoveryProcedure) -> Self {
        self.recovery = Some(recovery);
        self
    }

    pub fn with_tested(mut self, at: i64, interval_days: u64) -> Self {
        self.tested = true;
        self.last_tested = Some(at);
        self.test_interval_days = Some(interval_days);
        self
    }
}

// ── FailsafeRegistry ──────────────────────────────────────────────────

pub struct FailsafeRegistry {
    failsafes: HashMap<FailsafeId, FailsafeBehavior>,
}

impl FailsafeRegistry {
    pub fn new() -> Self {
        Self {
            failsafes: HashMap::new(),
        }
    }

    pub fn register(&mut self, behavior: FailsafeBehavior) -> Result<(), SafetyError> {
        if self.failsafes.contains_key(&behavior.id) {
            return Err(SafetyError::FailsafeAlreadyExists(behavior.id.0.clone()));
        }
        self.failsafes.insert(behavior.id.clone(), behavior);
        Ok(())
    }

    pub fn get(&self, id: &FailsafeId) -> Option<&FailsafeBehavior> {
        self.failsafes.get(id)
    }

    /// Returns fail-safes matching the trigger, sorted by priority (highest first).
    pub fn trigger(&self, trigger: &FailsafeTrigger) -> Vec<&FailsafeBehavior> {
        let mut matching: Vec<&FailsafeBehavior> = self
            .failsafes
            .values()
            .filter(|fs| fs.enabled && &fs.trigger == trigger)
            .collect();
        matching.sort_by(|a, b| b.priority.cmp(&a.priority));
        matching
    }

    pub fn untested(&self) -> Vec<&FailsafeBehavior> {
        self.failsafes.values().filter(|fs| !fs.tested).collect()
    }

    pub fn overdue_testing(&self, now: i64) -> Vec<&FailsafeBehavior> {
        self.failsafes
            .values()
            .filter(|fs| {
                if let (Some(last), Some(interval)) = (fs.last_tested, fs.test_interval_days) {
                    let due_at = last + (interval as i64 * 86400);
                    now > due_at
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn by_priority(&self) -> Vec<&FailsafeBehavior> {
        let mut all: Vec<&FailsafeBehavior> = self.failsafes.values().collect();
        all.sort_by(|a, b| b.priority.cmp(&a.priority));
        all
    }

    pub fn enabled_count(&self) -> usize {
        self.failsafes.values().filter(|fs| fs.enabled).count()
    }

    pub fn count(&self) -> usize {
        self.failsafes.len()
    }
}

impl Default for FailsafeRegistry {
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

    fn sample_failsafe(id: &str, trigger: FailsafeTrigger, priority: u32) -> FailsafeBehavior {
        FailsafeBehavior::new(id, format!("Failsafe {id}"), trigger)
            .with_action(FailsafeAction::RejectAllRequests {
                message: "Safety shutdown".into(),
            })
            .with_priority(priority)
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = FailsafeRegistry::new();
        reg.register(sample_failsafe(
            "fs1",
            FailsafeTrigger::ManualActivation,
            10,
        ))
        .unwrap();
        assert!(reg.get(&FailsafeId::new("fs1")).is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_trigger_returns_sorted_by_priority() {
        let mut reg = FailsafeRegistry::new();
        let trig = FailsafeTrigger::ConstraintViolation {
            constraint_id: "c1".into(),
        };
        reg.register(sample_failsafe("fs1", trig.clone(), 5)).unwrap();
        reg.register(sample_failsafe("fs2", trig.clone(), 10)).unwrap();
        let matched = reg.trigger(&trig);
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].id.0, "fs2"); // higher priority first
        assert_eq!(matched[1].id.0, "fs1");
    }

    #[test]
    fn test_trigger_constraint_violation() {
        let mut reg = FailsafeRegistry::new();
        let trig = FailsafeTrigger::ConstraintViolation {
            constraint_id: "c1".into(),
        };
        reg.register(sample_failsafe("fs1", trig.clone(), 5)).unwrap();
        assert_eq!(reg.trigger(&trig).len(), 1);
    }

    #[test]
    fn test_trigger_monitor_triggered() {
        let mut reg = FailsafeRegistry::new();
        let trig = FailsafeTrigger::MonitorTriggered {
            monitor_id: "m1".into(),
        };
        reg.register(sample_failsafe("fs1", trig.clone(), 5)).unwrap();
        assert_eq!(reg.trigger(&trig).len(), 1);
    }

    #[test]
    fn test_trigger_no_match() {
        let reg = FailsafeRegistry::new();
        assert!(reg.trigger(&FailsafeTrigger::ManualActivation).is_empty());
    }

    #[test]
    fn test_untested() {
        let mut reg = FailsafeRegistry::new();
        reg.register(sample_failsafe("fs1", FailsafeTrigger::ManualActivation, 5))
            .unwrap();
        assert_eq!(reg.untested().len(), 1);
    }

    #[test]
    fn test_overdue_testing() {
        let mut reg = FailsafeRegistry::new();
        let fs = sample_failsafe("fs1", FailsafeTrigger::ManualActivation, 5)
            .with_tested(1000, 30); // tested at 1000, interval 30 days
        reg.register(fs).unwrap();
        // 30 days = 2592000 seconds. At now=1000+2592001, overdue.
        assert_eq!(reg.overdue_testing(2593001).len(), 1);
        assert_eq!(reg.overdue_testing(1500).len(), 0); // not overdue
    }

    #[test]
    fn test_by_priority() {
        let mut reg = FailsafeRegistry::new();
        reg.register(sample_failsafe("fs1", FailsafeTrigger::ManualActivation, 1))
            .unwrap();
        reg.register(sample_failsafe(
            "fs2",
            FailsafeTrigger::Custom("x".into()),
            10,
        ))
        .unwrap();
        let sorted = reg.by_priority();
        assert_eq!(sorted[0].priority, 10);
        assert_eq!(sorted[1].priority, 1);
    }

    #[test]
    fn test_failsafe_trigger_display() {
        let triggers = vec![
            FailsafeTrigger::ConstraintViolation { constraint_id: "c".into() },
            FailsafeTrigger::MonitorTriggered { monitor_id: "m".into() },
            FailsafeTrigger::ComponentFailure { component: "comp".into() },
            FailsafeTrigger::ThresholdExceeded { metric: "cpu".into(), threshold: 0.9 },
            FailsafeTrigger::ManualActivation,
            FailsafeTrigger::CascadeFrom { failsafe_id: "fs".into() },
            FailsafeTrigger::Custom("custom".into()),
        ];
        for t in &triggers {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(triggers.len(), 7);
    }

    #[test]
    fn test_failsafe_action_display() {
        let actions = vec![
            FailsafeAction::SwitchToSafeMode { mode: "degraded".into() },
            FailsafeAction::DisableComponent { component: "ai".into() },
            FailsafeAction::RateLimitTo { max_per_minute: 10 },
            FailsafeAction::RejectAllRequests { message: "down".into() },
            FailsafeAction::FallbackToDefault { default_response: "safe".into() },
            FailsafeAction::NotifyOperator { channel: "slack".into(), message: "alert".into() },
            FailsafeAction::LogAndContinue { message: "logged".into() },
            FailsafeAction::GracefulShutdown { timeout_ms: 5000 },
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(actions.len(), 8);
    }

    #[test]
    fn test_recovery_procedure() {
        let rp = RecoveryProcedure::new("Restart service")
            .with_step("Stop processing")
            .with_step("Clear queue")
            .with_step("Restart")
            .with_auto_recovery(30000);
        assert_eq!(rp.steps.len(), 3);
        assert!(rp.auto_recovery);
        assert!(!rp.requires_human_approval);
        assert_eq!(rp.recovery_timeout_ms, Some(30000));
    }
}
