// ═══════════════════════════════════════════════════════════════════════
// Uptime — per-component up/down state with availability and MTBF.
//
// UptimeTracker stores a sequence of ComponentStatus transitions for each
// component. Availability is computed as (total up time / observed time).
// MTBF = total up time / number of down transitions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── ComponentStatus ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentStatus {
    Up,
    Down,
    Maintenance,
    Unknown,
}

impl fmt::Display for ComponentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Up => f.write_str("up"),
            Self::Down => f.write_str("down"),
            Self::Maintenance => f.write_str("maintenance"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ── StatusChange ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StatusChange {
    pub component: String,
    pub from: ComponentStatus,
    pub to: ComponentStatus,
    pub at: i64,
    pub reason: String,
}

// ── ComponentUptime ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComponentUptime {
    pub component: String,
    pub current: ComponentStatus,
    pub since: i64,
    pub changes: Vec<StatusChange>,
    /// Cumulative seconds spent in Up state (finalized transitions only).
    pub total_up_seconds: i64,
    /// Cumulative seconds spent in Down state (finalized transitions only).
    pub total_down_seconds: i64,
    pub observation_start: i64,
    pub down_transitions: u64,
}

impl ComponentUptime {
    pub fn new(component: impl Into<String>, initial: ComponentStatus, at: i64) -> Self {
        Self {
            component: component.into(),
            current: initial,
            since: at,
            changes: Vec::new(),
            total_up_seconds: 0,
            total_down_seconds: 0,
            observation_start: at,
            down_transitions: 0,
        }
    }

    pub fn transition(&mut self, to: ComponentStatus, at: i64, reason: impl Into<String>) {
        if to == self.current {
            return;
        }
        let elapsed = (at - self.since).max(0);
        match self.current {
            ComponentStatus::Up => self.total_up_seconds += elapsed,
            ComponentStatus::Down => self.total_down_seconds += elapsed,
            _ => {}
        }
        let change = StatusChange {
            component: self.component.clone(),
            from: self.current,
            to,
            at,
            reason: reason.into(),
        };
        self.changes.push(change);
        if to == ComponentStatus::Down && self.current == ComponentStatus::Up {
            self.down_transitions += 1;
        }
        self.current = to;
        self.since = at;
    }

    /// Availability as a fraction 0.0..=1.0 over the observed window.
    pub fn availability(&self, now: i64) -> f64 {
        let mut up = self.total_up_seconds;
        let mut down = self.total_down_seconds;
        let in_flight = (now - self.since).max(0);
        match self.current {
            ComponentStatus::Up => up += in_flight,
            ComponentStatus::Down => down += in_flight,
            _ => {}
        }
        let total = up + down;
        if total == 0 {
            return 1.0;
        }
        up as f64 / total as f64
    }

    /// Availability as a 0..=100 percent.
    pub fn availability_percent(&self, now: i64) -> f64 {
        self.availability(now) * 100.0
    }

    /// Mean time between failures in seconds (None if no failures yet).
    pub fn mtbf_seconds(&self, now: i64) -> Option<f64> {
        if self.down_transitions == 0 {
            return None;
        }
        let mut up = self.total_up_seconds;
        if self.current == ComponentStatus::Up {
            up += (now - self.since).max(0);
        }
        Some(up as f64 / self.down_transitions as f64)
    }
}

// ── UptimeTracker ─────────────────────────────────────────────────────

#[derive(Default)]
pub struct UptimeTracker {
    pub components: HashMap<String, ComponentUptime>,
}

impl UptimeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: impl Into<String>, at: i64) {
        let name = name.into();
        self.components
            .insert(name.clone(), ComponentUptime::new(name, ComponentStatus::Up, at));
    }

    pub fn record(
        &mut self,
        component: &str,
        to: ComponentStatus,
        at: i64,
        reason: impl Into<String>,
    ) {
        if !self.components.contains_key(component) {
            self.components
                .insert(component.into(), ComponentUptime::new(component, to, at));
            return;
        }
        self.components
            .get_mut(component)
            .unwrap()
            .transition(to, at, reason);
    }

    pub fn get(&self, component: &str) -> Option<&ComponentUptime> {
        self.components.get(component)
    }

    pub fn availability(&self, component: &str, now: i64) -> Option<f64> {
        self.components.get(component).map(|c| c.availability(now))
    }

    /// Overall availability as the arithmetic mean across components.
    pub fn overall_availability(&self, now: i64) -> f64 {
        if self.components.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.components.values().map(|c| c.availability(now)).sum();
        sum / self.components.len() as f64
    }

    pub fn up_count(&self) -> usize {
        self.components
            .values()
            .filter(|c| c.current == ComponentStatus::Up)
            .count()
    }

    pub fn down_count(&self) -> usize {
        self.components
            .values()
            .filter(|c| c.current == ComponentStatus::Down)
            .count()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_starts_up() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        assert_eq!(t.get("api").unwrap().current, ComponentStatus::Up);
    }

    #[test]
    fn test_transition_accumulates_up_time() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        t.record("api", ComponentStatus::Down, 100, "crash");
        t.record("api", ComponentStatus::Up, 110, "restart");
        let c = t.get("api").unwrap();
        assert_eq!(c.total_up_seconds, 100);
        assert_eq!(c.total_down_seconds, 10);
    }

    #[test]
    fn test_availability_after_outage() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        t.record("api", ComponentStatus::Down, 90, "crash");
        t.record("api", ComponentStatus::Up, 100, "restart");
        let avail = t.availability("api", 100).unwrap();
        // 90 up / (90 + 10) down = 0.9
        assert!((avail - 0.9).abs() < 1e-9);
    }

    #[test]
    fn test_availability_percent_100_when_never_down() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        let c = t.get("api").unwrap();
        assert!((c.availability_percent(10000) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_mtbf_none_without_failures() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        let c = t.get("api").unwrap();
        assert_eq!(c.mtbf_seconds(1000), None);
    }

    #[test]
    fn test_mtbf_after_failures() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        t.record("api", ComponentStatus::Down, 100, "1");
        t.record("api", ComponentStatus::Up, 110, "fix");
        t.record("api", ComponentStatus::Down, 210, "2");
        t.record("api", ComponentStatus::Up, 220, "fix");
        let c = t.get("api").unwrap();
        // up = 100 + 100 = 200 seconds, 2 down transitions → mtbf 100
        let mtbf = c.mtbf_seconds(220).unwrap();
        assert!((mtbf - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_maintenance_not_counted() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        t.record("api", ComponentStatus::Maintenance, 100, "deploy");
        t.record("api", ComponentStatus::Up, 110, "done");
        let c = t.get("api").unwrap();
        assert_eq!(c.total_up_seconds, 100);
        assert_eq!(c.total_down_seconds, 0);
    }

    #[test]
    fn test_no_op_same_status() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        t.record("api", ComponentStatus::Up, 100, "same");
        let c = t.get("api").unwrap();
        assert!(c.changes.is_empty());
    }

    #[test]
    fn test_overall_availability_arithmetic_mean() {
        let mut t = UptimeTracker::new();
        t.register("a", 0);
        t.register("b", 0);
        t.record("a", ComponentStatus::Down, 50, "crash");
        let avail = t.overall_availability(100);
        // a: 50 up / (50+50) = 0.5; b: 100% (no transitions recorded)
        assert!((avail - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_up_and_down_counts() {
        let mut t = UptimeTracker::new();
        t.register("a", 0);
        t.register("b", 0);
        t.record("a", ComponentStatus::Down, 10, "x");
        assert_eq!(t.up_count(), 1);
        assert_eq!(t.down_count(), 1);
    }

    #[test]
    fn test_status_display() {
        assert_eq!(ComponentStatus::Up.to_string(), "up");
        assert_eq!(ComponentStatus::Down.to_string(), "down");
        assert_eq!(ComponentStatus::Maintenance.to_string(), "maintenance");
    }

    #[test]
    fn test_change_history_preserved() {
        let mut t = UptimeTracker::new();
        t.register("api", 0);
        t.record("api", ComponentStatus::Down, 10, "crash-1");
        t.record("api", ComponentStatus::Up, 20, "restart");
        let c = t.get("api").unwrap();
        assert_eq!(c.changes.len(), 2);
        assert_eq!(c.changes[0].reason, "crash-1");
    }
}
