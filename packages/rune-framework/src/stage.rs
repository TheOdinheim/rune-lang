// ═══════════════════════════════════════════════════════════════════════
// Stage — Pipeline stage definitions and built-in evaluators.
//
// StageType identifies the kind of governance check. StageDefinition
// configures a stage with a StageFn function pointer. Five built-in
// evaluators use context flags (string-based) rather than actual crate
// types, keeping dependencies minimal.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::context::GovernanceContext;
use crate::request::{GovernanceRequest, StageResult};

// ── StageType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StageType {
    Identity,
    Permission,
    Policy,
    Privacy,
    Shield,
    Trust,
    Detection,
    Compliance,
}

impl fmt::Display for StageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Identity => "Identity",
            Self::Permission => "Permission",
            Self::Policy => "Policy",
            Self::Privacy => "Privacy",
            Self::Shield => "Shield",
            Self::Trust => "Trust",
            Self::Detection => "Detection",
            Self::Compliance => "Compliance",
        };
        f.write_str(s)
    }
}

// ── FailAction ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailAction {
    /// Deny the request immediately (fail-closed).
    Block,
    /// Log the failure but continue pipeline (fail-open).
    Continue,
    /// Escalate to a human reviewer.
    Escalate,
    /// Skip the remaining stages and return current state.
    Abort,
}

impl fmt::Display for FailAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── StageFn ───────────────────────────────────────────────────────────

/// Function pointer type for stage evaluators.
/// Takes the governance request, mutable context, and stage config.
/// Returns a StageResult.
pub type StageFn =
    fn(&GovernanceRequest, &mut GovernanceContext, &HashMap<String, String>) -> StageResult;

// ── StageDefinition ───────────────────────────────────────────────────

#[derive(Clone)]
pub struct StageDefinition {
    pub name: String,
    pub stage_type: StageType,
    pub evaluator: StageFn,
    pub fail_action: FailAction,
    pub enabled: bool,
    pub order: u32,
    pub config: HashMap<String, String>,
}

impl StageDefinition {
    pub fn new(
        name: impl Into<String>,
        stage_type: StageType,
        evaluator: StageFn,
    ) -> Self {
        Self {
            name: name.into(),
            stage_type,
            evaluator,
            fail_action: FailAction::Block,
            enabled: true,
            order: 0,
            config: HashMap::new(),
        }
    }

    pub fn with_fail_action(mut self, action: FailAction) -> Self {
        self.fail_action = action;
        self
    }

    pub fn with_order(mut self, order: u32) -> Self {
        self.order = order;
        self
    }

    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl fmt::Debug for StageDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StageDefinition")
            .field("name", &self.name)
            .field("stage_type", &self.stage_type)
            .field("fail_action", &self.fail_action)
            .field("enabled", &self.enabled)
            .field("order", &self.order)
            .finish()
    }
}

// ── Built-in stage evaluators ─────────────────────────────────────────

/// Identity stage: checks that the subject has been authenticated.
/// Reads "identity_verified" flag from context. Sets it if subject_id
/// is non-empty.
pub fn identity_stage(
    request: &GovernanceRequest,
    ctx: &mut GovernanceContext,
    _config: &HashMap<String, String>,
) -> StageResult {
    if request.subject.subject_id.is_empty() {
        ctx.add_warning("No subject identity provided".into());
        StageResult::fail("identity", "Subject identity is empty")
    } else {
        ctx.set_flag("identity_verified".into(), "true".into());
        ctx.set_flag("subject_id".into(), request.subject.subject_id.clone());
        StageResult::pass("identity")
    }
}

/// Policy stage: evaluates context flags against policy config.
/// Checks "policy_action" config key — if set to "deny", denies.
/// Otherwise checks if "risk_score" flag exceeds "max_risk" config.
pub fn policy_stage(
    _request: &GovernanceRequest,
    ctx: &mut GovernanceContext,
    config: &HashMap<String, String>,
) -> StageResult {
    if let Some(action) = config.get("policy_action") {
        if action == "deny" {
            ctx.set_flag("policy_decision".into(), "deny".into());
            return StageResult::fail("policy", "Policy explicitly denies this request");
        }
    }

    if let (Some(risk_str), Some(max_str)) = (ctx.get_flag("risk_score"), config.get("max_risk")) {
        if let (Ok(risk), Ok(max)) = (risk_str.parse::<f64>(), max_str.parse::<f64>()) {
            if risk > max {
                ctx.set_flag("policy_decision".into(), "deny".into());
                return StageResult::fail(
                    "policy",
                    format!("Risk score {risk} exceeds maximum {max}"),
                );
            }
        }
    }

    ctx.set_flag("policy_decision".into(), "permit".into());
    StageResult::pass("policy")
}

/// Shield stage: checks for active threats. Reads "threat_active" flag
/// from context. If present, fails with threat info.
pub fn shield_stage(
    _request: &GovernanceRequest,
    ctx: &mut GovernanceContext,
    _config: &HashMap<String, String>,
) -> StageResult {
    if ctx.has_flag("threat_active") {
        let threat = ctx.get_flag("threat_active").unwrap_or("unknown".into());
        ctx.set_flag("shield_verdict".into(), "blocked".into());
        StageResult::fail("shield", format!("Active threat detected: {threat}"))
    } else {
        ctx.set_flag("shield_verdict".into(), "clear".into());
        StageResult::pass("shield")
    }
}

/// Trust stage: evaluates trust score. Reads "trust_score" flag.
/// If below "min_trust" config (default 0.5), fails.
pub fn trust_stage(
    _request: &GovernanceRequest,
    ctx: &mut GovernanceContext,
    config: &HashMap<String, String>,
) -> StageResult {
    let min_trust: f64 = config
        .get("min_trust")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.5);

    let trust: f64 = ctx
        .get_flag("trust_score")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0); // default to trusted if no score set

    ctx.set_flag("trust_evaluated".into(), "true".into());

    if trust < min_trust {
        StageResult::fail(
            "trust",
            format!("Trust score {trust} below minimum {min_trust}"),
        )
    } else {
        StageResult::pass("trust")
    }
}

/// Compliance stage: checks required compliance flags. Reads
/// "required_flags" config (comma-separated). Fails if any are missing.
pub fn compliance_stage(
    _request: &GovernanceRequest,
    ctx: &mut GovernanceContext,
    config: &HashMap<String, String>,
) -> StageResult {
    let required = config.get("required_flags").cloned().unwrap_or_default();
    if required.is_empty() {
        return StageResult::pass("compliance");
    }

    let missing: Vec<&str> = required
        .split(',')
        .map(|s| s.trim())
        .filter(|flag| !flag.is_empty() && !ctx.has_flag(flag))
        .collect();

    if missing.is_empty() {
        StageResult::pass("compliance")
    } else {
        StageResult::fail(
            "compliance",
            format!("Missing required flags: {}", missing.join(", ")),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_type_display_all() {
        let types = vec![
            StageType::Identity,
            StageType::Permission,
            StageType::Policy,
            StageType::Privacy,
            StageType::Shield,
            StageType::Trust,
            StageType::Detection,
            StageType::Compliance,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_fail_action_display() {
        assert_eq!(FailAction::Block.to_string(), "Block");
        assert_eq!(FailAction::Continue.to_string(), "Continue");
        assert_eq!(FailAction::Escalate.to_string(), "Escalate");
        assert_eq!(FailAction::Abort.to_string(), "Abort");
    }

    #[test]
    fn test_stage_definition_builder() {
        let sd = StageDefinition::new("test-stage", StageType::Policy, policy_stage)
            .with_fail_action(FailAction::Continue)
            .with_order(5)
            .with_config("max_risk", "0.8")
            .disabled();
        assert_eq!(sd.name, "test-stage");
        assert_eq!(sd.stage_type, StageType::Policy);
        assert_eq!(sd.fail_action, FailAction::Continue);
        assert_eq!(sd.order, 5);
        assert!(!sd.enabled);
        assert_eq!(sd.config.get("max_risk").unwrap(), "0.8");
    }

    fn test_request() -> GovernanceRequest {
        use crate::request::*;
        GovernanceRequest::new(
            "req-001",
            SubjectInfo::new("user-1", "human"),
            ResourceInfo::new("res-1", "model", "public"),
            RequestContext::new("query", "prod", 1000),
        )
    }

    #[test]
    fn test_identity_stage_pass() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        let result = identity_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_success());
        assert_eq!(ctx.get_flag("identity_verified"), Some("true".into()));
    }

    #[test]
    fn test_identity_stage_fail_empty_subject() {
        use crate::request::*;
        let req = GovernanceRequest::new(
            "req-002",
            SubjectInfo::new("", "unknown"),
            ResourceInfo::new("res-1", "model", "public"),
            RequestContext::new("query", "prod", 1000),
        );
        let mut ctx = GovernanceContext::new();
        let result = identity_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_blocking());
    }

    #[test]
    fn test_policy_stage_explicit_deny() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        let mut config = HashMap::new();
        config.insert("policy_action".into(), "deny".into());
        let result = policy_stage(&req, &mut ctx, &config);
        assert!(result.outcome.is_blocking());
        assert_eq!(ctx.get_flag("policy_decision"), Some("deny".into()));
    }

    #[test]
    fn test_policy_stage_risk_check() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("risk_score".into(), "0.9".into());
        let mut config = HashMap::new();
        config.insert("max_risk".into(), "0.7".into());
        let result = policy_stage(&req, &mut ctx, &config);
        assert!(result.outcome.is_blocking());
    }

    #[test]
    fn test_policy_stage_pass() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        let result = policy_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_success());
        assert_eq!(ctx.get_flag("policy_decision"), Some("permit".into()));
    }

    #[test]
    fn test_shield_stage_no_threat() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        let result = shield_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_success());
        assert_eq!(ctx.get_flag("shield_verdict"), Some("clear".into()));
    }

    #[test]
    fn test_shield_stage_threat_active() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("threat_active".into(), "ransomware".into());
        let result = shield_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_blocking());
        assert_eq!(ctx.get_flag("shield_verdict"), Some("blocked".into()));
    }

    #[test]
    fn test_trust_stage_pass_default() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        let result = trust_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_success());
    }

    #[test]
    fn test_trust_stage_fail_low_trust() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("trust_score".into(), "0.2".into());
        let mut config = HashMap::new();
        config.insert("min_trust".into(), "0.5".into());
        let result = trust_stage(&req, &mut ctx, &config);
        assert!(result.outcome.is_blocking());
    }

    #[test]
    fn test_compliance_stage_no_requirements() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        let result = compliance_stage(&req, &mut ctx, &HashMap::new());
        assert!(result.outcome.is_success());
    }

    #[test]
    fn test_compliance_stage_flags_present() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("gdpr_consent".into(), "true".into());
        ctx.set_flag("data_classification".into(), "done".into());
        let mut config = HashMap::new();
        config.insert("required_flags".into(), "gdpr_consent, data_classification".into());
        let result = compliance_stage(&req, &mut ctx, &config);
        assert!(result.outcome.is_success());
    }

    #[test]
    fn test_compliance_stage_missing_flags() {
        let req = test_request();
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("gdpr_consent".into(), "true".into());
        let mut config = HashMap::new();
        config.insert("required_flags".into(), "gdpr_consent, audit_complete".into());
        let result = compliance_stage(&req, &mut ctx, &config);
        assert!(result.outcome.is_blocking());
    }
}
