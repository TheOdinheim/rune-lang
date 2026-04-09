// ═══════════════════════════════════════════════════════════════════════
// rune::policy — Policy Evaluation Utilities
//
// Composable building blocks for governance policy evaluation.
// Decision combinators, risk assessment, and request builders.
//
// Pure functions (no effects) unless otherwise noted. These operate on
// in-memory decision values and never perform I/O.
// ═══════════════════════════════════════════════════════════════════════

// ── Decision ────────────────────────────────────────────────────────

/// Policy decision outcome. Matches the i32 encoding used by WASM and
/// native backends (0=Permit, 1=Deny, 2=Escalate, 3=Quarantine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    Permit,
    Deny,
    Escalate,
    Quarantine,
}

impl Decision {
    pub fn is_permit(&self) -> bool {
        matches!(self, Self::Permit)
    }
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
    pub fn is_escalate(&self) -> bool {
        matches!(self, Self::Escalate)
    }
    pub fn is_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine)
    }
    /// True only for Permit.
    pub fn is_allowed(&self) -> bool {
        self.is_permit()
    }
    /// True for Deny, Escalate, and Quarantine.
    pub fn is_blocked(&self) -> bool {
        !self.is_permit()
    }
    /// Severity ordering: Permit=0, Escalate=1, Deny=2, Quarantine=3.
    pub fn severity(&self) -> u8 {
        match self {
            Self::Permit => 0,
            Self::Escalate => 1,
            Self::Deny => 2,
            Self::Quarantine => 3,
        }
    }
    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Permit,
            1 => Self::Deny,
            2 => Self::Escalate,
            3 => Self::Quarantine,
            _ => Self::Deny, // fail-closed
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permit => write!(f, "Permit"),
            Self::Deny => write!(f, "Deny"),
            Self::Escalate => write!(f, "Escalate"),
            Self::Quarantine => write!(f, "Quarantine"),
        }
    }
}

// ── Request builder ─────────────────────────────────────────────────

/// Policy evaluation request.
#[derive(Debug, Clone, Default)]
pub struct PolicyRequest {
    pub subject_id: i64,
    pub action: i64,
    pub resource_id: i64,
    pub risk_score: i64,
}

impl PolicyRequest {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn subject(mut self, id: i64) -> Self {
        self.subject_id = id;
        self
    }
    pub fn action(mut self, action: i64) -> Self {
        self.action = action;
        self
    }
    pub fn resource(mut self, id: i64) -> Self {
        self.resource_id = id;
        self
    }
    pub fn risk(mut self, score: i64) -> Self {
        self.risk_score = score;
        self
    }
}

// ── Decision combinators (pure) ─────────────────────────────────────

/// First non-Permit decision wins. Returns Permit if all permit or empty.
pub fn first_non_permit(decisions: &[Decision]) -> Decision {
    for d in decisions {
        if !d.is_permit() {
            return *d;
        }
    }
    Decision::Permit
}

/// Returns the most severe decision (Quarantine > Deny > Escalate > Permit).
pub fn most_severe(decisions: &[Decision]) -> Decision {
    decisions
        .iter()
        .max_by_key(|d| d.severity())
        .copied()
        .unwrap_or(Decision::Permit)
}

/// True if every decision is Permit.
pub fn all_permit(decisions: &[Decision]) -> bool {
    decisions.iter().all(|d| d.is_permit())
}

/// True if any decision is Deny or more severe.
pub fn any_deny(decisions: &[Decision]) -> bool {
    decisions.iter().any(|d| d.severity() >= Decision::Deny.severity())
}

/// Returns Some(decision) if all decisions are the same, None otherwise.
pub fn unanimous(decisions: &[Decision]) -> Option<Decision> {
    let first = decisions.first()?;
    if decisions.iter().all(|d| d == first) {
        Some(*first)
    } else {
        None
    }
}

// ── Risk assessment (pure) ──────────────────────────────────────────

/// Categorical risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
    /// Lower bound score for this risk level.
    pub fn threshold(&self) -> i64 {
        match self {
            Self::Low => 0,
            Self::Medium => 26,
            Self::High => 51,
            Self::Critical => 76,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Map a numeric risk score (0-100) to a categorical level.
pub fn risk_level(score: i64) -> RiskLevel {
    match score {
        0..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

// ── Policy metadata ─────────────────────────────────────────────────

/// Which of RUNE's four pillars a policy enforces.
#[derive(Debug, Clone, Default)]
pub struct PillarCoverage {
    pub security_baked_in: bool,
    pub assumed_breach: bool,
    pub zero_trust: bool,
    pub no_single_points: bool,
}

/// Descriptive metadata about a policy module.
#[derive(Debug, Clone)]
pub struct PolicyInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub pillar_coverage: PillarCoverage,
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_is_methods() {
        assert!(Decision::Permit.is_permit());
        assert!(Decision::Deny.is_deny());
        assert!(Decision::Escalate.is_escalate());
        assert!(Decision::Quarantine.is_quarantine());
    }

    #[test]
    fn test_decision_is_allowed() {
        assert!(Decision::Permit.is_allowed());
        assert!(!Decision::Deny.is_allowed());
        assert!(!Decision::Escalate.is_allowed());
        assert!(!Decision::Quarantine.is_allowed());
    }

    #[test]
    fn test_decision_is_blocked() {
        assert!(!Decision::Permit.is_blocked());
        assert!(Decision::Deny.is_blocked());
        assert!(Decision::Escalate.is_blocked());
        assert!(Decision::Quarantine.is_blocked());
    }

    #[test]
    fn test_decision_severity() {
        assert!(Decision::Permit.severity() < Decision::Escalate.severity());
        assert!(Decision::Escalate.severity() < Decision::Deny.severity());
        assert!(Decision::Deny.severity() < Decision::Quarantine.severity());
    }

    #[test]
    fn test_request_builder() {
        let req = PolicyRequest::new()
            .subject(42)
            .action(1)
            .resource(100)
            .risk(85);
        assert_eq!(req.subject_id, 42);
        assert_eq!(req.action, 1);
        assert_eq!(req.resource_id, 100);
        assert_eq!(req.risk_score, 85);
    }

    #[test]
    fn test_request_default_zeros() {
        let req = PolicyRequest::new();
        assert_eq!(req.subject_id, 0);
        assert_eq!(req.action, 0);
        assert_eq!(req.resource_id, 0);
        assert_eq!(req.risk_score, 0);
    }

    #[test]
    fn test_first_non_permit_all_permit() {
        let ds = vec![Decision::Permit, Decision::Permit];
        assert_eq!(first_non_permit(&ds), Decision::Permit);
    }

    #[test]
    fn test_first_non_permit_mixed() {
        let ds = vec![Decision::Permit, Decision::Deny];
        assert_eq!(first_non_permit(&ds), Decision::Deny);
    }

    #[test]
    fn test_first_non_permit_first_wins() {
        let ds = vec![Decision::Deny, Decision::Quarantine];
        assert_eq!(first_non_permit(&ds), Decision::Deny);
    }

    #[test]
    fn test_first_non_permit_empty() {
        assert_eq!(first_non_permit(&[]), Decision::Permit);
    }

    #[test]
    fn test_most_severe() {
        let ds = vec![Decision::Permit, Decision::Deny, Decision::Escalate];
        assert_eq!(most_severe(&ds), Decision::Deny);
    }

    #[test]
    fn test_most_severe_quarantine() {
        let ds = vec![Decision::Permit, Decision::Escalate, Decision::Quarantine];
        assert_eq!(most_severe(&ds), Decision::Quarantine);
    }

    #[test]
    fn test_most_severe_empty() {
        assert_eq!(most_severe(&[]), Decision::Permit);
    }

    #[test]
    fn test_all_permit() {
        assert!(all_permit(&[Decision::Permit, Decision::Permit]));
        assert!(!all_permit(&[Decision::Permit, Decision::Deny]));
    }

    #[test]
    fn test_any_deny() {
        assert!(any_deny(&[Decision::Permit, Decision::Deny]));
        assert!(!any_deny(&[Decision::Permit, Decision::Permit]));
        // Quarantine is more severe than Deny, so counts.
        assert!(any_deny(&[Decision::Quarantine]));
    }

    #[test]
    fn test_unanimous_same() {
        assert_eq!(
            unanimous(&[Decision::Deny, Decision::Deny]),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn test_unanimous_mixed() {
        assert_eq!(
            unanimous(&[Decision::Permit, Decision::Deny]),
            None
        );
    }

    #[test]
    fn test_risk_level_boundaries() {
        assert_eq!(risk_level(0), RiskLevel::Low);
        assert_eq!(risk_level(25), RiskLevel::Low);
        assert_eq!(risk_level(26), RiskLevel::Medium);
        assert_eq!(risk_level(50), RiskLevel::Medium);
        assert_eq!(risk_level(51), RiskLevel::High);
        assert_eq!(risk_level(75), RiskLevel::High);
        assert_eq!(risk_level(76), RiskLevel::Critical);
        assert_eq!(risk_level(100), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_as_str() {
        assert_eq!(RiskLevel::Low.as_str(), "Low");
        assert_eq!(RiskLevel::Critical.as_str(), "Critical");
    }

    #[test]
    fn test_policy_info_constructible() {
        let info = PolicyInfo {
            name: "access-control".into(),
            version: "1.0".into(),
            description: "Basic access".into(),
            author: "security-team".into(),
            pillar_coverage: PillarCoverage {
                security_baked_in: true,
                zero_trust: true,
                ..Default::default()
            },
        };
        assert_eq!(info.name, "access-control");
        assert!(info.pillar_coverage.security_baked_in);
        assert!(!info.pillar_coverage.assumed_breach);
    }
}
