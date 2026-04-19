// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Temporal policy scheduling.
//
// Time-bounded policy activation with recurrence patterns,
// activation windows, and overlap detection.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── PolicyRecurrence ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyRecurrence {
    Daily { start_hour: u8, end_hour: u8 },
    Weekly { days: Vec<u8> },
    Monthly { day_of_month: u8 },
    None,
}

impl fmt::Display for PolicyRecurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Daily { start_hour, end_hour } => {
                write!(f, "daily:{start_hour}-{end_hour}")
            }
            Self::Weekly { days } => {
                let day_strs: Vec<String> = days.iter().map(|d| d.to_string()).collect();
                write!(f, "weekly:{}", day_strs.join(","))
            }
            Self::Monthly { day_of_month } => write!(f, "monthly:{day_of_month}"),
            Self::None => f.write_str("none"),
        }
    }
}

// ── TemporalPolicy ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TemporalPolicy {
    pub policy_id: String,
    pub effective_from: i64,
    pub effective_until: Option<i64>,
    pub recurrence: Option<PolicyRecurrence>,
    pub timezone_offset_hours: i32,
}

impl TemporalPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        effective_from: i64,
        effective_until: Option<i64>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            effective_from,
            effective_until,
            recurrence: None,
            timezone_offset_hours: 0,
        }
    }

    pub fn with_recurrence(mut self, recurrence: PolicyRecurrence) -> Self {
        self.recurrence = Some(recurrence);
        self
    }

    pub fn is_active(&self, now: i64) -> bool {
        if now < self.effective_from {
            return false;
        }
        if let Some(until) = self.effective_until {
            if now >= until {
                return false;
            }
        }

        // Check recurrence
        if let Some(ref recurrence) = self.recurrence {
            match recurrence {
                PolicyRecurrence::Daily { start_hour, end_hour } => {
                    let offset_seconds = self.timezone_offset_hours as i64 * 3600;
                    let local_time = now + offset_seconds;
                    let seconds_in_day = local_time.rem_euclid(86400);
                    let hour = (seconds_in_day / 3600) as u8;
                    hour >= *start_hour && hour < *end_hour
                }
                PolicyRecurrence::Weekly { days } => {
                    let offset_seconds = self.timezone_offset_hours as i64 * 3600;
                    let local_time = now + offset_seconds;
                    // Unix epoch (1970-01-01) was a Thursday (day 4)
                    let day_of_week = ((local_time / 86400).rem_euclid(7) + 4) % 7;
                    days.contains(&(day_of_week as u8))
                }
                PolicyRecurrence::Monthly { day_of_month } => {
                    let offset_seconds = self.timezone_offset_hours as i64 * 3600;
                    let local_time = now + offset_seconds;
                    // Approximate: use day within 30-day month
                    let day = ((local_time / 86400).rem_euclid(30) + 1) as u8;
                    day == *day_of_month
                }
                PolicyRecurrence::None => true,
            }
        } else {
            true
        }
    }
}

// ── TemporalPolicyScheduler ────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TemporalPolicyScheduler {
    policies: Vec<TemporalPolicy>,
}

impl TemporalPolicyScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn schedule(&mut self, policy: TemporalPolicy) {
        self.policies.push(policy);
    }

    pub fn active_policies(&self, now: i64) -> Vec<&TemporalPolicy> {
        self.policies.iter().filter(|p| p.is_active(now)).collect()
    }

    pub fn upcoming_activations(&self, now: i64, window_ms: i64) -> Vec<&TemporalPolicy> {
        self.policies
            .iter()
            .filter(|p| p.effective_from > now && p.effective_from <= now + window_ms)
            .collect()
    }

    pub fn expired_policies(&self, now: i64) -> Vec<&TemporalPolicy> {
        self.policies
            .iter()
            .filter(|p| p.effective_until.is_some_and(|until| until <= now))
            .collect()
    }

    pub fn overlapping_policies(&self, policy_id: &str) -> Vec<(&TemporalPolicy, &TemporalPolicy)> {
        let target = self.policies.iter().find(|p| p.policy_id == policy_id);
        let target = match target {
            Some(t) => t,
            None => return Vec::new(),
        };

        let mut overlaps = Vec::new();
        for other in &self.policies {
            if other.policy_id == policy_id {
                continue;
            }
            if windows_overlap(target, other) {
                overlaps.push((target, other));
            }
        }
        overlaps
    }
}

fn windows_overlap(a: &TemporalPolicy, b: &TemporalPolicy) -> bool {
    let a_end = a.effective_until.unwrap_or(i64::MAX);
    let b_end = b.effective_until.unwrap_or(i64::MAX);
    a.effective_from < b_end && b.effective_from < a_end
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temporal_policy_is_active_true_within_window() {
        let policy = TemporalPolicy::new("p1", 1000, Some(5000));
        assert!(policy.is_active(2000));
        assert!(policy.is_active(4999));
    }

    #[test]
    fn test_temporal_policy_is_active_false_before_effective_from() {
        let policy = TemporalPolicy::new("p1", 1000, Some(5000));
        assert!(!policy.is_active(500));
    }

    #[test]
    fn test_temporal_policy_is_active_false_after_effective_until() {
        let policy = TemporalPolicy::new("p1", 1000, Some(5000));
        assert!(!policy.is_active(5000));
        assert!(!policy.is_active(6000));
    }

    #[test]
    fn test_scheduler_active_policies_filters_correctly() {
        let mut scheduler = TemporalPolicyScheduler::new();
        scheduler.schedule(TemporalPolicy::new("p1", 1000, Some(5000)));
        scheduler.schedule(TemporalPolicy::new("p2", 3000, Some(7000)));
        scheduler.schedule(TemporalPolicy::new("p3", 6000, Some(9000)));

        let active = scheduler.active_policies(4000);
        assert_eq!(active.len(), 2);
        let ids: Vec<&str> = active.iter().map(|p| p.policy_id.as_str()).collect();
        assert!(ids.contains(&"p1"));
        assert!(ids.contains(&"p2"));
    }

    #[test]
    fn test_scheduler_upcoming_activations_within_window() {
        let mut scheduler = TemporalPolicyScheduler::new();
        scheduler.schedule(TemporalPolicy::new("p1", 1000, Some(5000)));
        scheduler.schedule(TemporalPolicy::new("p2", 2000, Some(6000)));
        scheduler.schedule(TemporalPolicy::new("p3", 10000, Some(15000)));

        let upcoming = scheduler.upcoming_activations(500, 2000);
        assert_eq!(upcoming.len(), 2);
    }

    #[test]
    fn test_scheduler_expired_policies_returns_past() {
        let mut scheduler = TemporalPolicyScheduler::new();
        scheduler.schedule(TemporalPolicy::new("p1", 1000, Some(3000)));
        scheduler.schedule(TemporalPolicy::new("p2", 1000, Some(5000)));
        scheduler.schedule(TemporalPolicy::new("p3", 1000, None)); // no expiry

        let expired = scheduler.expired_policies(4000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].policy_id, "p1");
    }

    #[test]
    fn test_scheduler_overlapping_policies_detects_overlap() {
        let mut scheduler = TemporalPolicyScheduler::new();
        scheduler.schedule(TemporalPolicy::new("p1", 1000, Some(5000)));
        scheduler.schedule(TemporalPolicy::new("p2", 3000, Some(7000)));
        scheduler.schedule(TemporalPolicy::new("p3", 8000, Some(10000)));

        let overlaps = scheduler.overlapping_policies("p1");
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0].1.policy_id, "p2");
    }
}
