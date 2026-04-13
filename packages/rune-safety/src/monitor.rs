// ═══════════════════════════════════════════════════════════════════════
// Monitor — Runtime safety monitors that watch for unsafe conditions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_security::SecuritySeverity;
use serde::{Deserialize, Serialize};

use crate::constraint::{ConstraintEvaluation, ConstraintId, ConstraintStore, evaluate_safety_condition};
use crate::error::SafetyError;

// ── SafetyMonitorId ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafetyMonitorId(pub String);

impl SafetyMonitorId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for SafetyMonitorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── MonitorResponse ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorResponse {
    LogOnly,
    Alert { severity: SecuritySeverity },
    Degrade { to_mode: String },
    Failsafe { failsafe_id: String },
    Shutdown { reason: String },
    Custom { action: String },
}

impl fmt::Display for MonitorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogOnly => write!(f, "LogOnly"),
            Self::Alert { severity } => write!(f, "Alert({severity})"),
            Self::Degrade { to_mode } => write!(f, "Degrade(to: {to_mode})"),
            Self::Failsafe { failsafe_id } => write!(f, "Failsafe({failsafe_id})"),
            Self::Shutdown { reason } => write!(f, "Shutdown({reason})"),
            Self::Custom { action } => write!(f, "Custom({action})"),
        }
    }
}

// ── MonitorStatus ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorStatus {
    Active,
    Triggered { since: i64, violation: String },
    Suspended { reason: String },
    Disabled,
}

impl fmt::Display for MonitorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Triggered { violation, .. } => write!(f, "Triggered: {violation}"),
            Self::Suspended { reason } => write!(f, "Suspended: {reason}"),
            Self::Disabled => write!(f, "Disabled"),
        }
    }
}

// ── SafetyMonitor ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyMonitor {
    pub id: SafetyMonitorId,
    pub name: String,
    pub description: String,
    pub monitored_constraints: Vec<ConstraintId>,
    pub check_interval_ms: i64,
    pub response: MonitorResponse,
    pub status: MonitorStatus,
    pub last_check: Option<i64>,
    pub violation_count: u64,
    pub consecutive_violations: u32,
    pub max_consecutive_before_action: u32,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

impl SafetyMonitor {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        response: MonitorResponse,
    ) -> Self {
        Self {
            id: SafetyMonitorId::new(id),
            name: name.into(),
            description: String::new(),
            monitored_constraints: Vec::new(),
            check_interval_ms: 1000,
            response,
            status: MonitorStatus::Active,
            last_check: None,
            violation_count: 0,
            consecutive_violations: 0,
            max_consecutive_before_action: 1,
            enabled: true,
            metadata: HashMap::new(),
        }
    }

    pub fn with_constraint(mut self, id: ConstraintId) -> Self {
        self.monitored_constraints.push(id);
        self
    }

    pub fn with_max_consecutive(mut self, n: u32) -> Self {
        self.max_consecutive_before_action = n;
        self
    }
}

// ── MonitorCheckResult ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MonitorCheckResult {
    pub monitor_id: SafetyMonitorId,
    pub checked_at: i64,
    pub all_satisfied: bool,
    pub violations: Vec<ConstraintEvaluation>,
    pub response_taken: Option<MonitorResponse>,
}

// ── SafetyMonitorEngine ───────────────────────────────────────────────

pub struct SafetyMonitorEngine {
    monitors: HashMap<SafetyMonitorId, SafetyMonitor>,
}

impl SafetyMonitorEngine {
    pub fn new() -> Self {
        Self {
            monitors: HashMap::new(),
        }
    }

    pub fn register(&mut self, monitor: SafetyMonitor) -> Result<(), SafetyError> {
        if self.monitors.contains_key(&monitor.id) {
            return Err(SafetyError::MonitorAlreadyExists(monitor.id.0.clone()));
        }
        self.monitors.insert(monitor.id.clone(), monitor);
        Ok(())
    }

    pub fn get(&self, id: &SafetyMonitorId) -> Option<&SafetyMonitor> {
        self.monitors.get(id)
    }

    pub fn check(
        &mut self,
        monitor_id: &SafetyMonitorId,
        constraint_store: &ConstraintStore,
        context: &HashMap<String, String>,
        now: i64,
    ) -> Result<MonitorCheckResult, SafetyError> {
        let monitor = self
            .monitors
            .get_mut(monitor_id)
            .ok_or_else(|| SafetyError::MonitorNotFound(monitor_id.0.clone()))?;

        if !monitor.enabled {
            return Ok(MonitorCheckResult {
                monitor_id: monitor.id.clone(),
                checked_at: now,
                all_satisfied: true,
                violations: Vec::new(),
                response_taken: None,
            });
        }

        let mut violations = Vec::new();

        for cid in &monitor.monitored_constraints {
            if let Some(constraint) = constraint_store.get(cid) {
                if constraint.active {
                    let satisfied = evaluate_safety_condition(&constraint.condition, context);
                    if !satisfied {
                        violations.push(ConstraintEvaluation {
                            constraint_id: cid.clone(),
                            satisfied: false,
                            detail: format!("Constraint '{}' violated", constraint.name),
                            evaluated_at: now,
                            context_snapshot: context.clone(),
                        });
                    }
                }
            }
        }

        let all_satisfied = violations.is_empty();
        monitor.last_check = Some(now);

        let response_taken = if !all_satisfied {
            monitor.violation_count += 1;
            monitor.consecutive_violations += 1;

            if monitor.consecutive_violations >= monitor.max_consecutive_before_action {
                let violation_desc = violations
                    .first()
                    .map(|v| v.detail.clone())
                    .unwrap_or_default();
                monitor.status = MonitorStatus::Triggered {
                    since: now,
                    violation: violation_desc,
                };
                Some(monitor.response.clone())
            } else {
                None
            }
        } else {
            monitor.consecutive_violations = 0;
            None
        };

        Ok(MonitorCheckResult {
            monitor_id: monitor.id.clone(),
            checked_at: now,
            all_satisfied,
            violations,
            response_taken,
        })
    }

    pub fn check_all(
        &mut self,
        constraint_store: &ConstraintStore,
        context: &HashMap<String, String>,
        now: i64,
    ) -> Vec<MonitorCheckResult> {
        let ids: Vec<SafetyMonitorId> = self
            .monitors
            .values()
            .filter(|m| m.enabled)
            .map(|m| m.id.clone())
            .collect();
        ids.iter()
            .filter_map(|id| self.check(id, constraint_store, context, now).ok())
            .collect()
    }

    pub fn triggered_monitors(&self) -> Vec<&SafetyMonitor> {
        self.monitors
            .values()
            .filter(|m| matches!(m.status, MonitorStatus::Triggered { .. }))
            .collect()
    }

    pub fn active_monitors(&self) -> Vec<&SafetyMonitor> {
        self.monitors
            .values()
            .filter(|m| matches!(m.status, MonitorStatus::Active) && m.enabled)
            .collect()
    }

    pub fn reset(&mut self, id: &SafetyMonitorId) -> Result<(), SafetyError> {
        let monitor = self
            .monitors
            .get_mut(id)
            .ok_or_else(|| SafetyError::MonitorNotFound(id.0.clone()))?;
        monitor.status = MonitorStatus::Active;
        monitor.consecutive_violations = 0;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.monitors.len()
    }
}

impl Default for SafetyMonitorEngine {
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
    use crate::constraint::*;

    fn setup_store_and_monitor() -> (ConstraintStore, SafetyMonitor) {
        let mut store = ConstraintStore::new();
        store
            .add(SafetyConstraint::new(
                "c1",
                "Min confidence",
                ConstraintType::Invariant,
                SafetyCondition::ValueAbove {
                    field: "confidence".into(),
                    threshold: 0.5,
                },
                ConstraintSeverity::Critical,
            ))
            .unwrap();

        let monitor = SafetyMonitor::new(
            "m1",
            "Confidence monitor",
            MonitorResponse::Alert {
                severity: SecuritySeverity::High,
            },
        )
        .with_constraint(ConstraintId::new("c1"));

        (store, monitor)
    }

    #[test]
    fn test_register_and_get() {
        let mut engine = SafetyMonitorEngine::new();
        let (_, monitor) = setup_store_and_monitor();
        engine.register(monitor).unwrap();
        assert!(engine.get(&SafetyMonitorId::new("m1")).is_some());
        assert_eq!(engine.count(), 1);
    }

    #[test]
    fn test_check_all_satisfied() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.8".into())]);
        let result = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 1000).unwrap();
        assert!(result.all_satisfied);
        assert!(result.violations.is_empty());
        assert!(result.response_taken.is_none());
    }

    #[test]
    fn test_check_violated() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        let result = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 1000).unwrap();
        assert!(!result.all_satisfied);
        assert_eq!(result.violations.len(), 1);
        // Default max_consecutive_before_action is 1, so response should fire
        assert!(result.response_taken.is_some());
    }

    #[test]
    fn test_consecutive_violations_triggers_response() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        // Require 3 consecutive violations
        engine.register(monitor.with_max_consecutive(3)).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.3".into())]);

        let r1 = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 1000).unwrap();
        assert!(r1.response_taken.is_none()); // 1st violation, need 3

        let r2 = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 2000).unwrap();
        assert!(r2.response_taken.is_none()); // 2nd violation

        let r3 = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 3000).unwrap();
        assert!(r3.response_taken.is_some()); // 3rd violation → triggers
    }

    #[test]
    fn test_satisfaction_resets_consecutive_count() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor.with_max_consecutive(3)).unwrap();

        let bad_ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        let good_ctx = HashMap::from([("confidence".into(), "0.8".into())]);

        engine.check(&SafetyMonitorId::new("m1"), &store, &bad_ctx, 1000).unwrap();
        engine.check(&SafetyMonitorId::new("m1"), &store, &bad_ctx, 2000).unwrap();
        // Now reset with a good check
        engine.check(&SafetyMonitorId::new("m1"), &store, &good_ctx, 3000).unwrap();
        // Two more bad — should NOT trigger (only 2 consecutive, need 3)
        engine.check(&SafetyMonitorId::new("m1"), &store, &bad_ctx, 4000).unwrap();
        let r = engine.check(&SafetyMonitorId::new("m1"), &store, &bad_ctx, 5000).unwrap();
        assert!(r.response_taken.is_none());
    }

    #[test]
    fn test_check_all() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.8".into())]);
        let results = engine.check_all(&store, &ctx, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].all_satisfied);
    }

    #[test]
    fn test_triggered_monitors() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 1000).unwrap();
        assert_eq!(engine.triggered_monitors().len(), 1);
        assert_eq!(engine.active_monitors().len(), 0);
    }

    #[test]
    fn test_active_monitors() {
        let (_, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor).unwrap();
        assert_eq!(engine.active_monitors().len(), 1);
    }

    #[test]
    fn test_reset_monitor() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 1000).unwrap();
        assert_eq!(engine.triggered_monitors().len(), 1);

        engine.reset(&SafetyMonitorId::new("m1")).unwrap();
        assert_eq!(engine.triggered_monitors().len(), 0);
        assert_eq!(engine.active_monitors().len(), 1);
    }

    #[test]
    fn test_monitor_response_display() {
        let responses = vec![
            MonitorResponse::LogOnly,
            MonitorResponse::Alert { severity: SecuritySeverity::High },
            MonitorResponse::Degrade { to_mode: "safe".into() },
            MonitorResponse::Failsafe { failsafe_id: "fs-1".into() },
            MonitorResponse::Shutdown { reason: "critical".into() },
            MonitorResponse::Custom { action: "notify".into() },
        ];
        for r in &responses {
            assert!(!r.to_string().is_empty());
        }
        assert_eq!(responses.len(), 6);
    }

    #[test]
    fn test_monitor_status_display() {
        let statuses = vec![
            MonitorStatus::Active,
            MonitorStatus::Triggered { since: 1000, violation: "v".into() },
            MonitorStatus::Suspended { reason: "maintenance".into() },
            MonitorStatus::Disabled,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_max_consecutive_before_action() {
        let (store, monitor) = setup_store_and_monitor();
        let mut engine = SafetyMonitorEngine::new();
        engine.register(monitor.with_max_consecutive(2)).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        let r1 = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 1000).unwrap();
        assert!(r1.response_taken.is_none());
        let r2 = engine.check(&SafetyMonitorId::new("m1"), &store, &ctx, 2000).unwrap();
        assert!(r2.response_taken.is_some());
    }
}
