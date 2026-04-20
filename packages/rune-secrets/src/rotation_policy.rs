// ═══════════════════════════════════════════════════════════════════════
// Rotation Policy Engine — Policy-driven secret rotation.
//
// Layer 3 adds a policy-driven rotation engine with pluggable
// rotation strategies. Layer 2 added basic rotation tracking —
// Layer 3 adds strategy-based decision making and compliance
// awareness.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::secret::SecretEntry;

// ── RotationUrgency ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RotationUrgency {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RotationUrgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── RotationStrategy trait ───────────────────────────────────────

pub trait RotationStrategy {
    fn should_rotate(&self, secret: &SecretEntry, now: i64) -> bool;
    fn rotation_urgency(&self, secret: &SecretEntry, now: i64) -> RotationUrgency;
    fn strategy_name(&self) -> &str;
}

// ── TimeBasedRotation ────────────────────────────────────────────

pub struct TimeBasedRotation {
    interval_ms: i64,
}

impl TimeBasedRotation {
    pub fn new(interval_ms: i64) -> Self {
        Self { interval_ms }
    }
}

impl RotationStrategy for TimeBasedRotation {
    fn should_rotate(&self, secret: &SecretEntry, now: i64) -> bool {
        let age = now - secret.metadata.created_at;
        age >= self.interval_ms
    }

    fn rotation_urgency(&self, secret: &SecretEntry, now: i64) -> RotationUrgency {
        let age = now - secret.metadata.created_at;
        if age < self.interval_ms / 2 {
            RotationUrgency::None
        } else if age < self.interval_ms {
            RotationUrgency::Low
        } else if age < self.interval_ms * 2 {
            RotationUrgency::Medium
        } else if age < self.interval_ms * 4 {
            RotationUrgency::High
        } else {
            RotationUrgency::Critical
        }
    }

    fn strategy_name(&self) -> &str {
        "time-based"
    }
}

// ── AccessCountRotation ──────────────────────────────────────────

pub struct AccessCountRotation {
    max_accesses: u64,
}

impl AccessCountRotation {
    pub fn new(max_accesses: u64) -> Self {
        Self { max_accesses }
    }
}

impl RotationStrategy for AccessCountRotation {
    fn should_rotate(&self, secret: &SecretEntry, _now: i64) -> bool {
        secret.metadata.usage_count >= self.max_accesses
    }

    fn rotation_urgency(&self, secret: &SecretEntry, _now: i64) -> RotationUrgency {
        if secret.metadata.usage_count < self.max_accesses / 2 {
            RotationUrgency::None
        } else if secret.metadata.usage_count < self.max_accesses {
            RotationUrgency::Low
        } else {
            RotationUrgency::High
        }
    }

    fn strategy_name(&self) -> &str {
        "access-count"
    }
}

// ── ComplianceRotation ───────────────────────────────────────────

pub struct ComplianceRotation {
    framework: String,
    requirement: String,
    interval_days: u32,
}

impl ComplianceRotation {
    pub fn new(framework: &str, requirement: &str) -> Self {
        // Built-in knowledge of compliance framework requirements
        let interval_days = match framework {
            "NIST" => 90,  // NIST 800-57: 90-day rotation for symmetric keys
            "CJIS" => 90,  // CJIS: 90-day rotation for passwords
            "PCI-DSS" => 90, // PCI-DSS: periodic key rotation
            "HIPAA" => 180,  // HIPAA: reasonable rotation period
            _ => 90,        // Default to 90 days
        };
        Self {
            framework: framework.to_string(),
            requirement: requirement.to_string(),
            interval_days,
        }
    }

    pub fn interval_days(&self) -> u32 {
        self.interval_days
    }
}

impl RotationStrategy for ComplianceRotation {
    fn should_rotate(&self, secret: &SecretEntry, now: i64) -> bool {
        let interval_ms = self.interval_days as i64 * 86400 * 1000;
        let age = now - secret.metadata.created_at;
        age >= interval_ms
    }

    fn rotation_urgency(&self, secret: &SecretEntry, now: i64) -> RotationUrgency {
        let interval_ms = self.interval_days as i64 * 86400 * 1000;
        let age = now - secret.metadata.created_at;
        if age < interval_ms / 2 {
            RotationUrgency::None
        } else if age < interval_ms {
            RotationUrgency::Medium
        } else {
            RotationUrgency::Critical
        }
    }

    fn strategy_name(&self) -> &str {
        "compliance"
    }
}

// ── RotationRecommendation ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RotationRecommendation {
    pub secret_id: String,
    pub urgency: RotationUrgency,
    pub strategy_name: String,
    pub reason: String,
}

// ── RotationRecord ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RotationRecord {
    pub secret_id: String,
    pub rotated_at: i64,
    pub strategy_name: String,
    pub urgency: RotationUrgency,
    pub initiated_by: String,
}

// ── ComplianceRotationStatus ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceRotationStatus {
    pub framework: String,
    pub compliant: bool,
    pub overdue_rotations: Vec<String>,
    pub next_rotation_due: Option<i64>,
}

// ── RotationPolicyEngine ─────────────────────────────────────────

pub struct RotationPolicyEngine {
    strategies: Vec<Box<dyn RotationStrategy>>,
    rotation_history: Vec<RotationRecord>,
}

impl RotationPolicyEngine {
    pub fn new() -> Self {
        Self {
            strategies: Vec::new(),
            rotation_history: Vec::new(),
        }
    }

    pub fn add_strategy(&mut self, strategy: Box<dyn RotationStrategy>) {
        self.strategies.push(strategy);
    }

    pub fn check_all(
        &self,
        secrets: &[&SecretEntry],
        now: i64,
    ) -> Vec<RotationRecommendation> {
        let mut recommendations = Vec::new();
        for secret in secrets {
            for strategy in &self.strategies {
                if strategy.should_rotate(secret, now) {
                    let urgency = strategy.rotation_urgency(secret, now);
                    recommendations.push(RotationRecommendation {
                        secret_id: secret.id.as_str().to_string(),
                        urgency,
                        strategy_name: strategy.strategy_name().to_string(),
                        reason: format!(
                            "{} recommends rotation for {}",
                            strategy.strategy_name(),
                            secret.id.as_str()
                        ),
                    });
                }
            }
        }
        recommendations
    }

    pub fn record_rotation(&mut self, record: RotationRecord) {
        self.rotation_history.push(record);
    }

    pub fn rotation_history_for(&self, secret_id: &str) -> Vec<&RotationRecord> {
        self.rotation_history
            .iter()
            .filter(|r| r.secret_id == secret_id)
            .collect()
    }

    pub fn compliance_status(&self, framework: &str) -> ComplianceRotationStatus {
        let overdue: Vec<String> = self
            .rotation_history
            .iter()
            .filter(|r| r.strategy_name == "compliance" && r.urgency >= RotationUrgency::High)
            .map(|r| r.secret_id.clone())
            .collect();

        let next_due = self
            .rotation_history
            .iter()
            .filter(|r| r.strategy_name == "compliance")
            .map(|r| {
                let interval_days: i64 = match framework {
                    "NIST" => 90,
                    "CJIS" => 90,
                    _ => 90,
                };
                r.rotated_at + interval_days * 86400 * 1000
            })
            .min();

        ComplianceRotationStatus {
            framework: framework.to_string(),
            compliant: overdue.is_empty(),
            overdue_rotations: overdue,
            next_rotation_due: next_due,
        }
    }

    pub fn strategy_count(&self) -> usize {
        self.strategies.len()
    }
}

impl Default for RotationPolicyEngine {
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
    use crate::secret::*;
    use rune_permissions::ClassificationLevel;

    fn make_secret(id: &str, created_at: i64, usage_count: u64) -> SecretEntry {
        let mut meta = SecretMetadata::new(
            SecretType::ApiKey,
            ClassificationLevel::Internal,
            "admin",
        )
        .with_timestamps(created_at, created_at);
        meta.usage_count = usage_count;
        SecretEntry::new(SecretId::new(id), SecretValue::from_str("value"), meta)
    }

    #[test]
    fn test_time_based_should_rotate_after_interval() {
        let strategy = TimeBasedRotation::new(1000);
        let secret = make_secret("s1", 0, 0);
        assert!(strategy.should_rotate(&secret, 1000));
        assert!(strategy.should_rotate(&secret, 2000));
    }

    #[test]
    fn test_time_based_should_not_rotate_before_interval() {
        let strategy = TimeBasedRotation::new(1000);
        let secret = make_secret("s1", 0, 0);
        assert!(!strategy.should_rotate(&secret, 500));
    }

    #[test]
    fn test_access_count_should_rotate_after_max() {
        let strategy = AccessCountRotation::new(100);
        let secret = make_secret("s1", 0, 100);
        assert!(strategy.should_rotate(&secret, 0));
    }

    #[test]
    fn test_access_count_should_not_rotate_below_max() {
        let strategy = AccessCountRotation::new(100);
        let secret = make_secret("s1", 0, 50);
        assert!(!strategy.should_rotate(&secret, 0));
    }

    #[test]
    fn test_compliance_rotation_nist_90_day() {
        let strategy = ComplianceRotation::new("NIST", "800-57");
        assert_eq!(strategy.interval_days(), 90);
        let secret = make_secret("s1", 0, 0);
        let ninety_days_ms = 90 * 86400 * 1000;
        assert!(!strategy.should_rotate(&secret, ninety_days_ms - 1));
        assert!(strategy.should_rotate(&secret, ninety_days_ms));
    }

    #[test]
    fn test_engine_check_all_returns_recommendations() {
        let mut engine = RotationPolicyEngine::new();
        engine.add_strategy(Box::new(TimeBasedRotation::new(1000)));
        let s1 = make_secret("s1", 0, 0);
        let s2 = make_secret("s2", 500, 0);
        let recommendations = engine.check_all(&[&s1, &s2], 1500);
        // s1 age=1500 >= 1000 → should rotate
        // s2 age=1000 >= 1000 → should rotate
        assert_eq!(recommendations.len(), 2);
    }

    #[test]
    fn test_engine_record_rotation() {
        let mut engine = RotationPolicyEngine::new();
        engine.record_rotation(RotationRecord {
            secret_id: "s1".to_string(),
            rotated_at: 1000,
            strategy_name: "time-based".to_string(),
            urgency: RotationUrgency::Medium,
            initiated_by: "admin".to_string(),
        });
        let history = engine.rotation_history_for("s1");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].rotated_at, 1000);
    }

    #[test]
    fn test_engine_compliance_status() {
        let mut engine = RotationPolicyEngine::new();
        engine.record_rotation(RotationRecord {
            secret_id: "s1".to_string(),
            rotated_at: 1000,
            strategy_name: "compliance".to_string(),
            urgency: RotationUrgency::Low,
            initiated_by: "admin".to_string(),
        });
        let status = engine.compliance_status("NIST");
        assert_eq!(status.framework, "NIST");
        assert!(status.compliant);
    }

    #[test]
    fn test_rotation_urgency_ordering() {
        assert!(RotationUrgency::None < RotationUrgency::Low);
        assert!(RotationUrgency::Low < RotationUrgency::Medium);
        assert!(RotationUrgency::Medium < RotationUrgency::High);
        assert!(RotationUrgency::High < RotationUrgency::Critical);
    }

    #[test]
    fn test_engine_strategy_count() {
        let mut engine = RotationPolicyEngine::new();
        assert_eq!(engine.strategy_count(), 0);
        engine.add_strategy(Box::new(TimeBasedRotation::new(1000)));
        assert_eq!(engine.strategy_count(), 1);
    }
}
