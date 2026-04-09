// ═══════════════════════════════════════════════════════════════════════
// Secret Rotation — Versioned Key Rotation with Policies
//
// RotationPolicy defines rotation intervals and grace periods.
// Rotation creates a new version, marks the old as Rotated,
// and respects version retention limits.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use serde::{Deserialize, Serialize};

use crate::secret::{SecretId, SecretType, SecretState};

// ── RotationPolicy ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub rotation_interval_days: u32,
    pub grace_period_days: u32,
    pub max_versions: usize,
    pub auto_rotate: bool,
    pub notify_before_days: u32,
}

impl RotationPolicy {
    /// Aggressive: 30-day rotation, 3-day grace, 3 versions
    pub fn aggressive() -> Self {
        Self {
            rotation_interval_days: 30,
            grace_period_days: 3,
            max_versions: 3,
            auto_rotate: true,
            notify_before_days: 7,
        }
    }

    /// Standard: 90-day rotation, 7-day grace, 5 versions
    pub fn standard() -> Self {
        Self {
            rotation_interval_days: 90,
            grace_period_days: 7,
            max_versions: 5,
            auto_rotate: true,
            notify_before_days: 14,
        }
    }

    /// Relaxed: 365-day rotation, 30-day grace, 10 versions
    pub fn relaxed() -> Self {
        Self {
            rotation_interval_days: 365,
            grace_period_days: 30,
            max_versions: 10,
            auto_rotate: false,
            notify_before_days: 30,
        }
    }

    /// Token policy: frequent rotation (7 days), short grace
    pub fn token() -> Self {
        Self {
            rotation_interval_days: 7,
            grace_period_days: 1,
            max_versions: 2,
            auto_rotate: true,
            notify_before_days: 2,
        }
    }

    /// Get a recommended policy based on secret type.
    pub fn for_secret_type(secret_type: &SecretType) -> Self {
        match secret_type {
            SecretType::Token => Self::token(),
            SecretType::ApiKey | SecretType::Password | SecretType::OAuthSecret => Self::standard(),
            SecretType::Certificate | SecretType::PrivateKey => Self::relaxed(),
            SecretType::SymmetricKey => Self::aggressive(),
            SecretType::SeedPhrase => Self::relaxed(),
            SecretType::ConnectionString | SecretType::Webhook => Self::standard(),
            SecretType::Custom(_) => Self::standard(),
        }
    }
}

impl fmt::Display for RotationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rotate every {}d, {}d grace, keep {} versions",
            self.rotation_interval_days, self.grace_period_days, self.max_versions
        )
    }
}

// ── RotationResult ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RotationResult {
    pub id: SecretId,
    pub old_version: u32,
    pub new_version: u32,
    pub old_state: SecretState,
    pub rotated_at: i64,
}

// ── RotationStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationStatus {
    Current,
    DueSoon { days_until_due: u32 },
    Overdue { days_overdue: u32 },
    NeverRotated,
}

impl RotationStatus {
    pub fn is_overdue(&self) -> bool {
        matches!(self, Self::Overdue { .. })
    }

    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::DueSoon { .. } | Self::Overdue { .. })
    }
}

impl fmt::Display for RotationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::DueSoon { days_until_due } => write!(f, "due in {days_until_due} days"),
            Self::Overdue { days_overdue } => write!(f, "overdue by {days_overdue} days"),
            Self::NeverRotated => write!(f, "never rotated"),
        }
    }
}

/// Check rotation status given creation/update time and policy.
pub fn check_rotation_status(
    last_rotated_at: i64,
    now: i64,
    policy: &RotationPolicy,
) -> RotationStatus {
    if last_rotated_at == 0 {
        return RotationStatus::NeverRotated;
    }

    let interval_secs = policy.rotation_interval_days as i64 * 86400;
    let notify_secs = policy.notify_before_days as i64 * 86400;
    let elapsed = now - last_rotated_at;
    let next_rotation = last_rotated_at + interval_secs;

    if elapsed >= interval_secs {
        let overdue_days = ((elapsed - interval_secs) / 86400) as u32;
        RotationStatus::Overdue { days_overdue: overdue_days }
    } else if now >= next_rotation - notify_secs {
        let days_left = ((next_rotation - now) / 86400) as u32;
        RotationStatus::DueSoon { days_until_due: days_left }
    } else {
        RotationStatus::Current
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86400;

    #[test]
    fn test_aggressive_policy() {
        let p = RotationPolicy::aggressive();
        assert_eq!(p.rotation_interval_days, 30);
        assert_eq!(p.grace_period_days, 3);
        assert_eq!(p.max_versions, 3);
        assert!(p.auto_rotate);
    }

    #[test]
    fn test_standard_policy() {
        let p = RotationPolicy::standard();
        assert_eq!(p.rotation_interval_days, 90);
        assert_eq!(p.max_versions, 5);
    }

    #[test]
    fn test_relaxed_policy() {
        let p = RotationPolicy::relaxed();
        assert_eq!(p.rotation_interval_days, 365);
        assert!(!p.auto_rotate);
    }

    #[test]
    fn test_token_policy() {
        let p = RotationPolicy::token();
        assert_eq!(p.rotation_interval_days, 7);
        assert_eq!(p.max_versions, 2);
    }

    #[test]
    fn test_for_secret_type() {
        let p = RotationPolicy::for_secret_type(&SecretType::Token);
        assert_eq!(p.rotation_interval_days, 7);
        let p = RotationPolicy::for_secret_type(&SecretType::Certificate);
        assert_eq!(p.rotation_interval_days, 365);
        let p = RotationPolicy::for_secret_type(&SecretType::SymmetricKey);
        assert_eq!(p.rotation_interval_days, 30);
    }

    #[test]
    fn test_policy_display() {
        let p = RotationPolicy::standard();
        let s = p.to_string();
        assert!(s.contains("90d"));
        assert!(s.contains("7d grace"));
        assert!(s.contains("5 versions"));
    }

    #[test]
    fn test_rotation_status_current() {
        let status = check_rotation_status(1000, 1000 + 10 * DAY, &RotationPolicy::standard());
        assert_eq!(status, RotationStatus::Current);
        assert!(!status.is_overdue());
        assert!(!status.needs_attention());
    }

    #[test]
    fn test_rotation_status_due_soon() {
        // Standard: 90 days interval, notify 14 days before
        let status = check_rotation_status(1000, 1000 + 80 * DAY, &RotationPolicy::standard());
        assert!(matches!(status, RotationStatus::DueSoon { .. }));
        assert!(status.needs_attention());
        assert!(!status.is_overdue());
    }

    #[test]
    fn test_rotation_status_overdue() {
        let status = check_rotation_status(1000, 1000 + 100 * DAY, &RotationPolicy::standard());
        assert!(matches!(status, RotationStatus::Overdue { days_overdue: 10 }));
        assert!(status.is_overdue());
        assert!(status.needs_attention());
    }

    #[test]
    fn test_rotation_status_never_rotated() {
        let status = check_rotation_status(0, 5000, &RotationPolicy::standard());
        assert_eq!(status, RotationStatus::NeverRotated);
    }

    #[test]
    fn test_rotation_status_display() {
        assert_eq!(RotationStatus::Current.to_string(), "current");
        assert_eq!(RotationStatus::NeverRotated.to_string(), "never rotated");
        assert!(RotationStatus::Overdue { days_overdue: 5 }.to_string().contains("5"));
    }

    #[test]
    fn test_rotation_result_fields() {
        let r = RotationResult {
            id: SecretId::new("k1"),
            old_version: 1,
            new_version: 2,
            old_state: SecretState::Rotated,
            rotated_at: 12345,
        };
        assert_eq!(r.old_version, 1);
        assert_eq!(r.new_version, 2);
    }
}
