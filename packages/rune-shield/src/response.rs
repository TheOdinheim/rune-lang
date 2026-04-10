// ═══════════════════════════════════════════════════════════════════════
// ShieldAction + ShieldVerdict — the four governance decisions at the
// inference boundary, plus verdict/check wrappers.
//
// Every shield action maps to one of four governance decisions:
//   Permit   = 0
//   Deny     = 1
//   Escalate = 2
//   Quarantine = 3
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;
use serde::{Deserialize, Serialize};

// ── GovernanceDecision ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovernanceDecision {
    Permit = 0,
    Deny = 1,
    Escalate = 2,
    Quarantine = 3,
}

impl fmt::Display for GovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Permit => "Permit",
            Self::Deny => "Deny",
            Self::Escalate => "Escalate",
            Self::Quarantine => "Quarantine",
        };
        f.write_str(s)
    }
}

// ── ShieldAction ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShieldAction {
    Allow,
    Block { reason: String },
    Quarantine { reason: String },
    Escalate { reason: String },
    Modify { modified: String, reason: String },
}

impl ShieldAction {
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Allow | Self::Modify { .. })
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    pub fn is_quarantined(&self) -> bool {
        matches!(self, Self::Quarantine { .. })
    }

    pub fn is_escalated(&self) -> bool {
        matches!(self, Self::Escalate { .. })
    }

    pub fn is_modified(&self) -> bool {
        matches!(self, Self::Modify { .. })
    }

    pub fn to_governance_decision(&self) -> GovernanceDecision {
        match self {
            Self::Allow | Self::Modify { .. } => GovernanceDecision::Permit,
            Self::Block { .. } => GovernanceDecision::Deny,
            Self::Escalate { .. } => GovernanceDecision::Escalate,
            Self::Quarantine { .. } => GovernanceDecision::Quarantine,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Block { reason }
            | Self::Quarantine { reason }
            | Self::Escalate { reason }
            | Self::Modify { reason, .. } => Some(reason),
        }
    }
}

impl fmt::Display for ShieldAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Block { reason } => write!(f, "Block({reason})"),
            Self::Quarantine { reason } => write!(f, "Quarantine({reason})"),
            Self::Escalate { reason } => write!(f, "Escalate({reason})"),
            Self::Modify { reason, .. } => write!(f, "Modify({reason})"),
        }
    }
}

// ── ShieldVerdict ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ShieldVerdict {
    pub action: ShieldAction,
    pub severity: SecuritySeverity,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

impl ShieldVerdict {
    pub fn allow() -> Self {
        Self {
            action: ShieldAction::Allow,
            severity: SecuritySeverity::Info,
            confidence: 1.0,
            evidence: Vec::new(),
        }
    }

    pub fn block(reason: impl Into<String>, severity: SecuritySeverity, confidence: f64) -> Self {
        Self {
            action: ShieldAction::Block { reason: reason.into() },
            severity,
            confidence,
            evidence: Vec::new(),
        }
    }

    pub fn quarantine(
        reason: impl Into<String>,
        severity: SecuritySeverity,
        confidence: f64,
    ) -> Self {
        Self {
            action: ShieldAction::Quarantine { reason: reason.into() },
            severity,
            confidence,
            evidence: Vec::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }
}

// ── CheckResult ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub passed: bool,
    pub confidence: f64,
    pub findings: Vec<String>,
}

impl CheckResult {
    pub fn pass() -> Self {
        Self { passed: true, confidence: 1.0, findings: Vec::new() }
    }

    pub fn fail(confidence: f64) -> Self {
        Self { passed: false, confidence, findings: Vec::new() }
    }

    pub fn with_finding(mut self, finding: impl Into<String>) -> Self {
        self.findings.push(finding.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_predicates() {
        assert!(ShieldAction::Allow.is_permitted());
        assert!(ShieldAction::Block { reason: "r".into() }.is_blocked());
        assert!(ShieldAction::Quarantine { reason: "r".into() }.is_quarantined());
        assert!(ShieldAction::Escalate { reason: "r".into() }.is_escalated());
        let m = ShieldAction::Modify { modified: "x".into(), reason: "r".into() };
        assert!(m.is_modified());
        assert!(m.is_permitted());
    }

    #[test]
    fn test_to_governance_decision() {
        assert_eq!(
            ShieldAction::Allow.to_governance_decision(),
            GovernanceDecision::Permit
        );
        assert_eq!(
            ShieldAction::Block { reason: "r".into() }.to_governance_decision(),
            GovernanceDecision::Deny
        );
        assert_eq!(
            ShieldAction::Quarantine { reason: "r".into() }.to_governance_decision(),
            GovernanceDecision::Quarantine
        );
        assert_eq!(
            ShieldAction::Escalate { reason: "r".into() }.to_governance_decision(),
            GovernanceDecision::Escalate
        );
        assert_eq!(
            ShieldAction::Modify { modified: "x".into(), reason: "r".into() }
                .to_governance_decision(),
            GovernanceDecision::Permit
        );
    }

    #[test]
    fn test_governance_decision_discriminants() {
        assert_eq!(GovernanceDecision::Permit as u8, 0);
        assert_eq!(GovernanceDecision::Deny as u8, 1);
        assert_eq!(GovernanceDecision::Escalate as u8, 2);
        assert_eq!(GovernanceDecision::Quarantine as u8, 3);
    }

    #[test]
    fn test_verdict_constructors() {
        let v = ShieldVerdict::allow();
        assert!(v.action.is_permitted());

        let v = ShieldVerdict::block("bad", SecuritySeverity::High, 0.9)
            .with_evidence("rule-1");
        assert!(v.action.is_blocked());
        assert_eq!(v.evidence.len(), 1);

        let v = ShieldVerdict::quarantine("suspect", SecuritySeverity::Medium, 0.7);
        assert!(v.action.is_quarantined());
    }

    #[test]
    fn test_check_result() {
        let r = CheckResult::pass();
        assert!(r.passed);
        let r = CheckResult::fail(0.8).with_finding("issue");
        assert!(!r.passed);
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn test_action_display_and_reason() {
        assert_eq!(ShieldAction::Allow.to_string(), "Allow");
        assert_eq!(ShieldAction::Allow.reason(), None);
        let b = ShieldAction::Block { reason: "xyz".into() };
        assert!(b.to_string().contains("xyz"));
        assert_eq!(b.reason(), Some("xyz"));
    }
}
