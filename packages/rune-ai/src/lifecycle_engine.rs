// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Lifecycle state machine enforcement. Validates and
// executes ModelStatus transitions, checks deprecation status,
// generates deprecation notices, and checks deployment age limits.
// ═══════════════════════════════════════════════════════════════════════

use crate::deployment::DeploymentRecord;
use crate::error::AiError;
use crate::lifecycle::{DeprecationNotice, DeprecationSeverity, ModelLifecyclePolicy, ModelLifecycleTransition};
use crate::model_registry::{ModelRecord, ModelStatus};

// ── DeprecationCheckResult ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeprecationCheckResult {
    pub model_id: String,
    pub is_deprecated: bool,
    pub days_until_sunset: Option<String>,
    pub should_notify: bool,
    pub checked_at: i64,
}

// ── DeploymentAgeCheckResult ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentAgeCheckResult {
    pub deployment_id: String,
    pub within_limit: bool,
    pub current_age_days: String,
    pub max_age_days: Option<String>,
    pub checked_at: i64,
}

// ── LifecycleEngine ─────────────────────────────────────────────────

pub struct LifecycleEngine;

impl LifecycleEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn execute_transition(
        &self,
        record: &ModelRecord,
        to_status: ModelStatus,
        actor: &str,
        reason: &str,
        timestamp: i64,
    ) -> Result<ModelLifecycleTransition, AiError> {
        if !record.status.is_valid_transition(&to_status) {
            return Err(AiError::InvalidTransition {
                model_id: record.model_id.clone(),
                from: record.status.to_string(),
                to: to_status.to_string(),
            });
        }
        Ok(ModelLifecycleTransition::new(
            format!("mlt-{timestamp}"),
            &record.model_id,
            record.status.clone(),
            to_status,
            timestamp,
            actor,
            reason,
        ))
    }

    pub fn check_deprecation_status(
        &self,
        policy: &ModelLifecyclePolicy,
        current_timestamp: i64,
    ) -> DeprecationCheckResult {
        let (is_deprecated, days_until_sunset) = if let Some(sunset) = policy.sunset_date {
            if current_timestamp >= sunset {
                (true, Some("0".to_string()))
            } else {
                let remaining_ms = sunset - current_timestamp;
                let remaining_days = remaining_ms / 86_400_000;
                (false, Some(remaining_days.to_string()))
            }
        } else {
            (false, None)
        };

        let should_notify = if let (Some(notice_days_str), Some(sunset)) =
            (&policy.deprecation_notice_days, policy.sunset_date)
        {
            if let Ok(notice_days) = notice_days_str.parse::<i64>() {
                let notice_ms = notice_days * 86_400_000;
                let notice_start = sunset - notice_ms;
                current_timestamp >= notice_start
            } else {
                false
            }
        } else {
            is_deprecated
        };

        DeprecationCheckResult {
            model_id: policy.model_id.clone(),
            is_deprecated,
            days_until_sunset,
            should_notify,
            checked_at: current_timestamp,
        }
    }

    pub fn generate_deprecation_notice(
        &self,
        policy: &ModelLifecyclePolicy,
        model_version: &str,
        timestamp: i64,
    ) -> Option<DeprecationNotice> {
        let check = self.check_deprecation_status(policy, timestamp);
        if !check.should_notify {
            return None;
        }

        let severity = if check.is_deprecated {
            DeprecationSeverity::Immediate
        } else {
            match &check.days_until_sunset {
                Some(days) => match days.parse::<i64>() {
                    Ok(d) if d <= 7 => DeprecationSeverity::Mandatory,
                    Ok(d) if d <= 30 => DeprecationSeverity::Warning,
                    _ => DeprecationSeverity::Advisory,
                },
                None => DeprecationSeverity::Advisory,
            }
        };

        let mut notice = DeprecationNotice::new(
            format!("dn-{timestamp}"),
            &policy.model_id,
            model_version,
            timestamp,
            format!("Model scheduled for retirement per policy {}", policy.policy_id),
            severity,
        );
        notice.sunset_date = policy.sunset_date;
        notice.replacement_model_ref = policy.replacement_model_id.clone();
        Some(notice)
    }

    pub fn check_deployment_age(
        &self,
        deployment: &DeploymentRecord,
        policy: &ModelLifecyclePolicy,
        current_timestamp: i64,
    ) -> DeploymentAgeCheckResult {
        let age_ms = current_timestamp - deployment.deployed_at;
        let age_days = age_ms / 86_400_000;

        let (within_limit, max_age_days) = if let Some(ref max_age_str) =
            policy.max_deployment_age_days
        {
            match max_age_str.parse::<i64>() {
                Ok(max_days) => (age_days <= max_days, Some(max_age_str.clone())),
                Err(_) => (true, Some(max_age_str.clone())),
            }
        } else {
            (true, None)
        };

        DeploymentAgeCheckResult {
            deployment_id: deployment.deployment_id.clone(),
            within_limit,
            current_age_days: age_days.to_string(),
            max_age_days,
            checked_at: current_timestamp,
        }
    }
}

impl Default for LifecycleEngine {
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
    use crate::deployment::DeploymentEnvironment;
    use crate::lifecycle::RetirementAction;
    use crate::model_registry::{ModelArchitecture, ModelTaskType};

    fn make_model(status: ModelStatus) -> ModelRecord {
        let mut record = ModelRecord::new(
            "model-1", "GPT", "1.0.0",
            ModelArchitecture::Transformer,
            ModelTaskType::Classification,
            "pytorch", "alice", 1000,
        );
        record.status = status;
        record
    }

    fn make_policy() -> ModelLifecyclePolicy {
        let mut policy = ModelLifecyclePolicy::new(
            "mlp-1", "model-1", RetirementAction::Archive, 1000,
        );
        policy.sunset_date = Some(100_000);
        policy.deprecation_notice_days = Some("30".into());
        policy.max_deployment_age_days = Some("365".into());
        policy
    }

    fn make_deployment(deployed_at: i64) -> DeploymentRecord {
        DeploymentRecord::new(
            "dep-1", "req-1", "model-1", "1.0.0",
            DeploymentEnvironment::Production,
            deployed_at, "deployer",
        )
    }

    #[test]
    fn test_valid_transition_draft_to_registered() {
        let engine = LifecycleEngine::new();
        let model = make_model(ModelStatus::Draft);
        let result = engine.execute_transition(
            &model, ModelStatus::Registered, "admin", "initial registration", 2000,
        );
        assert!(result.is_ok());
        let transition = result.unwrap();
        assert_eq!(transition.from_status, ModelStatus::Draft);
        assert_eq!(transition.to_status, ModelStatus::Registered);
    }

    #[test]
    fn test_invalid_transition_draft_to_deployed() {
        let engine = LifecycleEngine::new();
        let model = make_model(ModelStatus::Draft);
        let result = engine.execute_transition(
            &model, ModelStatus::Deployed, "admin", "skip everything", 2000,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AiError::InvalidTransition { .. }));
    }

    #[test]
    fn test_suspension_transition() {
        let engine = LifecycleEngine::new();
        let model = make_model(ModelStatus::Deployed);
        let result = engine.execute_transition(
            &model, ModelStatus::Suspended, "admin", "emergency", 2000,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_reactivation_transition() {
        let engine = LifecycleEngine::new();
        let model = make_model(ModelStatus::Suspended);
        let result = engine.execute_transition(
            &model, ModelStatus::Registered, "admin", "reactivation", 2000,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_deprecation_not_yet_deprecated() {
        let engine = LifecycleEngine::new();
        let policy = make_policy();
        // Well before sunset
        let check = engine.check_deprecation_status(&policy, 50_000);
        assert!(!check.is_deprecated);
        assert!(check.days_until_sunset.is_some());
    }

    #[test]
    fn test_deprecation_past_sunset() {
        let engine = LifecycleEngine::new();
        let policy = make_policy();
        let check = engine.check_deprecation_status(&policy, 200_000);
        assert!(check.is_deprecated);
        assert_eq!(check.days_until_sunset, Some("0".to_string()));
        assert!(check.should_notify);
    }

    #[test]
    fn test_deprecation_notice_in_window() {
        let engine = LifecycleEngine::new();
        let mut policy = make_policy();
        // sunset_date = 100_000, notice_days = 30 → notice_start = 100_000 - 30 * 86_400_000
        // That's far in the past, so any timestamp should trigger
        policy.sunset_date = Some(100_000_000_000);
        policy.deprecation_notice_days = Some("30".into());
        // 30 days = 30 * 86_400_000 = 2_592_000_000
        // notice_start = 100_000_000_000 - 2_592_000_000 = 97_408_000_000
        let check = engine.check_deprecation_status(&policy, 98_000_000_000);
        assert!(check.should_notify);
        assert!(!check.is_deprecated);
    }

    #[test]
    fn test_deprecation_notice_not_in_window() {
        let engine = LifecycleEngine::new();
        let mut policy = make_policy();
        policy.sunset_date = Some(100_000_000_000);
        policy.deprecation_notice_days = Some("30".into());
        // Well before the notice window
        let check = engine.check_deprecation_status(&policy, 90_000_000_000);
        assert!(!check.should_notify);
    }

    #[test]
    fn test_generate_deprecation_notice_when_should_notify() {
        let engine = LifecycleEngine::new();
        let mut policy = make_policy();
        policy.sunset_date = Some(100_000);
        policy.deprecation_notice_days = Some("30".into());
        // Past sunset — should generate
        let notice = engine.generate_deprecation_notice(&policy, "1.0.0", 200_000);
        assert!(notice.is_some());
        let n = notice.unwrap();
        assert_eq!(n.model_id, "model-1");
        assert_eq!(n.severity, DeprecationSeverity::Immediate);
    }

    #[test]
    fn test_generate_deprecation_notice_no_sunset() {
        let engine = LifecycleEngine::new();
        let mut policy = make_policy();
        policy.sunset_date = None;
        policy.deprecation_notice_days = None;
        let notice = engine.generate_deprecation_notice(&policy, "1.0.0", 50_000);
        assert!(notice.is_none());
    }

    #[test]
    fn test_deployment_age_within_limit() {
        let engine = LifecycleEngine::new();
        let policy = make_policy();
        let deployment = make_deployment(1000);
        // age = (1000 + 100 * 86_400_000 - 1000) but let's use smaller numbers
        // deployed_at=1000, current=86_401_000 → age_ms=86_400_000 → age_days=1
        let check = engine.check_deployment_age(&deployment, &policy, 86_401_000);
        assert!(check.within_limit);
        assert_eq!(check.current_age_days, "1");
        assert_eq!(check.max_age_days, Some("365".to_string()));
    }

    #[test]
    fn test_deployment_age_exceeds_limit() {
        let engine = LifecycleEngine::new();
        let policy = make_policy();
        let deployment = make_deployment(1000);
        // 400 days in ms = 400 * 86_400_000 = 34_560_000_000
        let check = engine.check_deployment_age(&deployment, &policy, 34_560_001_000);
        assert!(!check.within_limit);
    }

    #[test]
    fn test_deployment_age_no_limit() {
        let engine = LifecycleEngine::new();
        let mut policy = make_policy();
        policy.max_deployment_age_days = None;
        let deployment = make_deployment(1000);
        let check = engine.check_deployment_age(&deployment, &policy, 999_999_999_999);
        assert!(check.within_limit);
        assert!(check.max_age_days.is_none());
    }

    #[test]
    fn test_lifecycle_engine_default() {
        let _engine = LifecycleEngine;
    }

    #[test]
    fn test_transition_produces_correct_id() {
        let engine = LifecycleEngine::new();
        let model = make_model(ModelStatus::Draft);
        let transition = engine
            .execute_transition(&model, ModelStatus::Registered, "admin", "init", 5000)
            .unwrap();
        assert_eq!(transition.transition_id, "mlt-5000");
    }
}
