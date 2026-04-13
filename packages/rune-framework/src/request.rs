// ═══════════════════════════════════════════════════════════════════════
// Request — Governance request/response types for pipeline evaluation.
//
// GovernanceRequest is the input to the governance pipeline.
// GovernanceDecisionResult is the output. GovernanceOutcome maps to
// the architecture spec's PolicyDecision with to_decision_code().
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

// ── GovernanceRequestId ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GovernanceRequestId(pub String);

impl GovernanceRequestId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for GovernanceRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SubjectInfo ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectInfo {
    pub subject_id: String,
    pub subject_type: String,
    pub attributes: HashMap<String, String>,
}

impl SubjectInfo {
    pub fn new(id: impl Into<String>, subject_type: impl Into<String>) -> Self {
        Self {
            subject_id: id.into(),
            subject_type: subject_type.into(),
            attributes: HashMap::new(),
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

// ── ResourceInfo ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub resource_id: String,
    pub resource_type: String,
    pub classification: String,
    pub attributes: HashMap<String, String>,
}

impl ResourceInfo {
    pub fn new(
        id: impl Into<String>,
        resource_type: impl Into<String>,
        classification: impl Into<String>,
    ) -> Self {
        Self {
            resource_id: id.into(),
            resource_type: resource_type.into(),
            classification: classification.into(),
            attributes: HashMap::new(),
        }
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

// ── RequestContext ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub action: String,
    pub environment: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

impl RequestContext {
    pub fn new(action: impl Into<String>, environment: impl Into<String>, timestamp: i64) -> Self {
        Self {
            action: action.into(),
            environment: environment.into(),
            timestamp,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ── GovernanceRequest ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRequest {
    pub id: GovernanceRequestId,
    pub subject: SubjectInfo,
    pub resource: ResourceInfo,
    pub context: RequestContext,
}

impl GovernanceRequest {
    pub fn new(
        id: impl Into<String>,
        subject: SubjectInfo,
        resource: ResourceInfo,
        context: RequestContext,
    ) -> Self {
        Self {
            id: GovernanceRequestId::new(id),
            subject,
            resource,
            context,
        }
    }
}

// ── GovernanceOutcome ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GovernanceOutcome {
    Permit,
    Deny { reason: String },
    ConditionalPermit { conditions: Vec<String> },
    Escalate { to: String, reason: String },
    Audit { action: String },
    NotApplicable,
}

impl GovernanceOutcome {
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permit | Self::ConditionalPermit { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    pub fn requires_action(&self) -> bool {
        matches!(
            self,
            Self::ConditionalPermit { .. } | Self::Escalate { .. } | Self::Audit { .. }
        )
    }

    pub fn to_decision_code(&self) -> &'static str {
        match self {
            Self::Permit => "PERMIT",
            Self::Deny { .. } => "DENY",
            Self::ConditionalPermit { .. } => "CONDITIONAL_PERMIT",
            Self::Escalate { .. } => "ESCALATE",
            Self::Audit { .. } => "AUDIT",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

impl fmt::Display for GovernanceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permit => write!(f, "Permit"),
            Self::Deny { reason } => write!(f, "Deny: {reason}"),
            Self::ConditionalPermit { conditions } => {
                write!(f, "ConditionalPermit({})", conditions.join(", "))
            }
            Self::Escalate { to, reason } => write!(f, "Escalate to {to}: {reason}"),
            Self::Audit { action } => write!(f, "Audit: {action}"),
            Self::NotApplicable => write!(f, "NotApplicable"),
        }
    }
}

// ── StageOutcome ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StageOutcome {
    Pass,
    Fail { reason: String },
    Warn { message: String },
    Skip { reason: String },
    Error { message: String },
}

impl StageOutcome {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Fail { .. } | Self::Error { .. })
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Pass | Self::Warn { .. } | Self::Skip { .. })
    }
}

impl fmt::Display for StageOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "Pass"),
            Self::Fail { reason } => write!(f, "Fail: {reason}"),
            Self::Warn { message } => write!(f, "Warn: {message}"),
            Self::Skip { reason } => write!(f, "Skip: {reason}"),
            Self::Error { message } => write!(f, "Error: {message}"),
        }
    }
}

// ── StageResult ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage_name: String,
    pub outcome: StageOutcome,
    pub severity: SecuritySeverity,
    pub details: HashMap<String, String>,
    pub duration_ms: u64,
}

impl StageResult {
    pub fn pass(stage_name: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            outcome: StageOutcome::Pass,
            severity: SecuritySeverity::Info,
            details: HashMap::new(),
            duration_ms: 0,
        }
    }

    pub fn fail(stage_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            outcome: StageOutcome::Fail {
                reason: reason.into(),
            },
            severity: SecuritySeverity::High,
            details: HashMap::new(),
            duration_ms: 0,
        }
    }

    pub fn with_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }
}

// ── GovernanceDecisionResult ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceDecisionResult {
    pub request_id: GovernanceRequestId,
    pub outcome: GovernanceOutcome,
    pub stage_results: Vec<StageResult>,
    pub overall_severity: SecuritySeverity,
    pub explanation: String,
    pub duration_ms: u64,
    pub dry_run: bool,
}

impl GovernanceDecisionResult {
    pub fn stage_count(&self) -> usize {
        self.stage_results.len()
    }

    pub fn failed_stages(&self) -> Vec<&StageResult> {
        self.stage_results
            .iter()
            .filter(|s| s.outcome.is_blocking())
            .collect()
    }

    pub fn all_passed(&self) -> bool {
        self.stage_results.iter().all(|s| s.outcome.is_success())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> GovernanceRequest {
        GovernanceRequest::new(
            "req-001",
            SubjectInfo::new("user-1", "human").with_attribute("role", "analyst"),
            ResourceInfo::new("model-1", "ai_model", "confidential")
                .with_attribute("version", "2.0"),
            RequestContext::new("inference", "production", 1000),
        )
    }

    #[test]
    fn test_request_id_display() {
        let id = GovernanceRequestId::new("req-001");
        assert_eq!(id.to_string(), "req-001");
    }

    #[test]
    fn test_request_construction() {
        let req = sample_request();
        assert_eq!(req.id.0, "req-001");
        assert_eq!(req.subject.subject_id, "user-1");
        assert_eq!(req.resource.resource_id, "model-1");
        assert_eq!(req.context.action, "inference");
        assert_eq!(req.subject.attributes.get("role").unwrap(), "analyst");
        assert_eq!(req.resource.attributes.get("version").unwrap(), "2.0");
    }

    #[test]
    fn test_governance_outcome_permit() {
        let o = GovernanceOutcome::Permit;
        assert!(o.is_permitted());
        assert!(!o.is_denied());
        assert!(!o.requires_action());
        assert_eq!(o.to_decision_code(), "PERMIT");
    }

    #[test]
    fn test_governance_outcome_deny() {
        let o = GovernanceOutcome::Deny {
            reason: "policy violation".into(),
        };
        assert!(!o.is_permitted());
        assert!(o.is_denied());
        assert!(!o.requires_action());
        assert_eq!(o.to_decision_code(), "DENY");
    }

    #[test]
    fn test_governance_outcome_conditional() {
        let o = GovernanceOutcome::ConditionalPermit {
            conditions: vec!["mfa".into(), "audit".into()],
        };
        assert!(o.is_permitted());
        assert!(!o.is_denied());
        assert!(o.requires_action());
        assert_eq!(o.to_decision_code(), "CONDITIONAL_PERMIT");
    }

    #[test]
    fn test_governance_outcome_escalate() {
        let o = GovernanceOutcome::Escalate {
            to: "admin".into(),
            reason: "high risk".into(),
        };
        assert!(!o.is_permitted());
        assert!(!o.is_denied());
        assert!(o.requires_action());
        assert_eq!(o.to_decision_code(), "ESCALATE");
    }

    #[test]
    fn test_governance_outcome_all_display() {
        let variants = vec![
            GovernanceOutcome::Permit,
            GovernanceOutcome::Deny { reason: "r".into() },
            GovernanceOutcome::ConditionalPermit { conditions: vec!["c".into()] },
            GovernanceOutcome::Escalate { to: "t".into(), reason: "r".into() },
            GovernanceOutcome::Audit { action: "a".into() },
            GovernanceOutcome::NotApplicable,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn test_stage_outcome_blocking() {
        assert!(!StageOutcome::Pass.is_blocking());
        assert!(StageOutcome::Fail { reason: "r".into() }.is_blocking());
        assert!(StageOutcome::Error { message: "e".into() }.is_blocking());
        assert!(!StageOutcome::Warn { message: "w".into() }.is_blocking());
        assert!(!StageOutcome::Skip { reason: "s".into() }.is_blocking());
    }

    #[test]
    fn test_stage_result_builders() {
        let sr = StageResult::pass("identity")
            .with_severity(SecuritySeverity::Low)
            .with_detail("check", "passed")
            .with_duration(42);
        assert_eq!(sr.stage_name, "identity");
        assert!(sr.outcome.is_success());
        assert_eq!(sr.severity, SecuritySeverity::Low);
        assert_eq!(sr.details.get("check").unwrap(), "passed");
        assert_eq!(sr.duration_ms, 42);
    }

    #[test]
    fn test_stage_result_fail() {
        let sr = StageResult::fail("policy", "denied by rule X");
        assert!(sr.outcome.is_blocking());
        assert_eq!(sr.severity, SecuritySeverity::High);
    }

    #[test]
    fn test_decision_result_methods() {
        let result = GovernanceDecisionResult {
            request_id: GovernanceRequestId::new("req-001"),
            outcome: GovernanceOutcome::Permit,
            stage_results: vec![
                StageResult::pass("identity"),
                StageResult::fail("policy", "denied"),
                StageResult::pass("shield"),
            ],
            overall_severity: SecuritySeverity::High,
            explanation: "test".into(),
            duration_ms: 100,
            dry_run: false,
        };
        assert_eq!(result.stage_count(), 3);
        assert_eq!(result.failed_stages().len(), 1);
        assert!(!result.all_passed());
    }

    #[test]
    fn test_decision_result_all_passed() {
        let result = GovernanceDecisionResult {
            request_id: GovernanceRequestId::new("req-002"),
            outcome: GovernanceOutcome::Permit,
            stage_results: vec![
                StageResult::pass("identity"),
                StageResult::pass("policy"),
            ],
            overall_severity: SecuritySeverity::Info,
            explanation: "all clear".into(),
            duration_ms: 50,
            dry_run: false,
        };
        assert!(result.all_passed());
        assert!(result.failed_stages().is_empty());
    }

    #[test]
    fn test_request_context_metadata() {
        let ctx = RequestContext::new("deploy", "staging", 2000)
            .with_metadata("ticket", "JIRA-123");
        assert_eq!(ctx.metadata.get("ticket").unwrap(), "JIRA-123");
    }
}
