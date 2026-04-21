// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — DnsSecurityGovernor trait for governing DNS security:
// query evaluation, DNSSEC validation status, resolver compliance
// checks. Includes BlocklistDnsSecurityGovernor composable wrapper.
//
// Named DnsSecurityGovernor (not DnsGovernor) to avoid collision
// with L1 dns.rs DnsGovernor struct.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

// ── DnsQueryDecision ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsQueryDecision {
    Allow,
    Block,
    Redirect,
    RequireDnssec,
    LogOnly,
}

impl fmt::Display for DnsQueryDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "Allow",
            Self::Block => "Block",
            Self::Redirect => "Redirect",
            Self::RequireDnssec => "RequireDnssec",
            Self::LogOnly => "LogOnly",
        };
        f.write_str(s)
    }
}

// ── DnsQueryEvaluation ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryEvaluation {
    pub domain: String,
    pub query_type: String,
    pub decision: DnsQueryDecision,
    pub justification: String,
    pub dnssec_status: DnssecStatus,
    pub evaluated_at: i64,
}

// ── DnssecStatus ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnssecStatus {
    Validated,
    NotValidated,
    NotRequired,
    ValidationFailed,
}

impl fmt::Display for DnssecStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Validated => "Validated",
            Self::NotValidated => "NotValidated",
            Self::NotRequired => "NotRequired",
            Self::ValidationFailed => "ValidationFailed",
        };
        f.write_str(s)
    }
}

// ── ResolverComplianceResult ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverComplianceResult {
    pub resolver_addr: String,
    pub supports_dnssec: bool,
    pub supports_doh: bool,
    pub supports_dot: bool,
    pub compliant: bool,
    pub issues: Vec<String>,
}

// ── DnsSecurityGovernor trait ──────────────────────────────────────

pub trait DnsSecurityGovernor {
    fn evaluate_query(
        &self,
        domain: &str,
        query_type: &str,
    ) -> Result<DnsQueryEvaluation, NetworkError>;

    fn check_resolver_compliance(
        &self,
        resolver_addr: &str,
    ) -> Result<ResolverComplianceResult, NetworkError>;

    fn is_domain_blocked(&self, domain: &str) -> bool;
    fn is_domain_allowed(&self, domain: &str) -> bool;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryDnsSecurityGovernor ────────────────────────────────────

pub struct InMemoryDnsSecurityGovernor {
    id: String,
    blocked_domains: Vec<String>,
    allowed_domains: Option<Vec<String>>,
    require_dnssec: bool,
    require_encrypted_transport: bool,
}

impl InMemoryDnsSecurityGovernor {
    pub fn new(id: impl Into<String>, require_dnssec: bool) -> Self {
        Self {
            id: id.into(),
            blocked_domains: Vec::new(),
            allowed_domains: None,
            require_dnssec,
            require_encrypted_transport: false,
        }
    }

    pub fn add_blocked_domain(&mut self, domain: impl Into<String>) {
        self.blocked_domains.push(domain.into().to_lowercase());
    }

    pub fn set_allowed_domains(&mut self, domains: Vec<String>) {
        self.allowed_domains = Some(
            domains.into_iter().map(|d| d.to_lowercase()).collect(),
        );
    }

    pub fn set_require_encrypted_transport(&mut self, required: bool) {
        self.require_encrypted_transport = required;
    }
}

impl DnsSecurityGovernor for InMemoryDnsSecurityGovernor {
    fn evaluate_query(
        &self,
        domain: &str,
        query_type: &str,
    ) -> Result<DnsQueryEvaluation, NetworkError> {
        let domain_lower = domain.to_lowercase();

        // Check blocklist
        if self
            .blocked_domains
            .iter()
            .any(|d| d == &domain_lower)
        {
            return Ok(DnsQueryEvaluation {
                domain: domain.into(),
                query_type: query_type.into(),
                decision: DnsQueryDecision::Block,
                justification: format!("Domain {domain} is blocked"),
                dnssec_status: DnssecStatus::NotRequired,
                evaluated_at: 0,
            });
        }

        // Check allowlist mode
        if let Some(ref allowed) = self.allowed_domains
            && !allowed.iter().any(|d| d == &domain_lower)
        {
            return Ok(DnsQueryEvaluation {
                domain: domain.into(),
                query_type: query_type.into(),
                decision: DnsQueryDecision::Block,
                justification: format!("Domain {domain} not in allowed list"),
                dnssec_status: DnssecStatus::NotRequired,
                evaluated_at: 0,
            });
        }

        let dnssec_status = if self.require_dnssec {
            DnssecStatus::NotValidated
        } else {
            DnssecStatus::NotRequired
        };

        Ok(DnsQueryEvaluation {
            domain: domain.into(),
            query_type: query_type.into(),
            decision: DnsQueryDecision::Allow,
            justification: "Query permitted by DNS security policy".into(),
            dnssec_status,
            evaluated_at: 0,
        })
    }

    fn check_resolver_compliance(
        &self,
        resolver_addr: &str,
    ) -> Result<ResolverComplianceResult, NetworkError> {
        let mut issues = Vec::new();
        let supports_dnssec = true; // assumed for in-memory
        let supports_doh = true;
        let supports_dot = true;

        if self.require_dnssec && !supports_dnssec {
            issues.push("DNSSEC not supported".into());
        }
        if self.require_encrypted_transport && !supports_doh && !supports_dot {
            issues.push("No encrypted transport (DoH/DoT) available".into());
        }

        Ok(ResolverComplianceResult {
            resolver_addr: resolver_addr.into(),
            supports_dnssec,
            supports_doh,
            supports_dot,
            compliant: issues.is_empty(),
            issues,
        })
    }

    fn is_domain_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.blocked_domains.iter().any(|d| d == &domain_lower)
    }

    fn is_domain_allowed(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        if let Some(ref allowed) = self.allowed_domains {
            return allowed.iter().any(|d| d == &domain_lower);
        }
        !self.is_domain_blocked(domain)
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── BlocklistDnsSecurityGovernor ───────────────────────────────────
// Composable wrapper that blocks all domains on an additional blocklist.

pub struct BlocklistDnsSecurityGovernor<G: DnsSecurityGovernor> {
    inner: G,
    additional_blocked: Vec<String>,
}

impl<G: DnsSecurityGovernor> BlocklistDnsSecurityGovernor<G> {
    pub fn new(inner: G) -> Self {
        Self {
            inner,
            additional_blocked: Vec::new(),
        }
    }

    pub fn add_blocked_domain(&mut self, domain: impl Into<String>) {
        self.additional_blocked
            .push(domain.into().to_lowercase());
    }
}

impl<G: DnsSecurityGovernor> DnsSecurityGovernor for BlocklistDnsSecurityGovernor<G> {
    fn evaluate_query(
        &self,
        domain: &str,
        query_type: &str,
    ) -> Result<DnsQueryEvaluation, NetworkError> {
        let domain_lower = domain.to_lowercase();
        if self
            .additional_blocked
            .iter()
            .any(|d| d == &domain_lower)
        {
            return Ok(DnsQueryEvaluation {
                domain: domain.into(),
                query_type: query_type.into(),
                decision: DnsQueryDecision::Block,
                justification: format!(
                    "BlocklistDnsSecurityGovernor: domain {domain} on additional blocklist"
                ),
                dnssec_status: DnssecStatus::NotRequired,
                evaluated_at: 0,
            });
        }
        self.inner.evaluate_query(domain, query_type)
    }

    fn check_resolver_compliance(
        &self,
        resolver_addr: &str,
    ) -> Result<ResolverComplianceResult, NetworkError> {
        self.inner.check_resolver_compliance(resolver_addr)
    }

    fn is_domain_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.additional_blocked
            .iter()
            .any(|d| d == &domain_lower)
            || self.inner.is_domain_blocked(domain)
    }

    fn is_domain_allowed(&self, domain: &str) -> bool {
        !self.is_domain_blocked(domain) && self.inner.is_domain_allowed(domain)
    }

    fn governor_id(&self) -> &str {
        self.inner.governor_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullDnsSecurityGovernor ────────────────────────────────────────

pub struct NullDnsSecurityGovernor;

impl DnsSecurityGovernor for NullDnsSecurityGovernor {
    fn evaluate_query(
        &self,
        domain: &str,
        query_type: &str,
    ) -> Result<DnsQueryEvaluation, NetworkError> {
        Ok(DnsQueryEvaluation {
            domain: domain.into(),
            query_type: query_type.into(),
            decision: DnsQueryDecision::Allow,
            justification: "Null governor — no DNS security governance".into(),
            dnssec_status: DnssecStatus::NotRequired,
            evaluated_at: 0,
        })
    }

    fn check_resolver_compliance(
        &self,
        resolver_addr: &str,
    ) -> Result<ResolverComplianceResult, NetworkError> {
        Ok(ResolverComplianceResult {
            resolver_addr: resolver_addr.into(),
            supports_dnssec: false,
            supports_doh: false,
            supports_dot: false,
            compliant: true,
            issues: Vec::new(),
        })
    }

    fn is_domain_blocked(&self, _domain: &str) -> bool {
        false
    }

    fn is_domain_allowed(&self, _domain: &str) -> bool {
        true
    }

    fn governor_id(&self) -> &str {
        "null-dns-security-governor"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_allows_non_blocked() {
        let mut gov = InMemoryDnsSecurityGovernor::new("g1", false);
        gov.add_blocked_domain("evil.com");
        let eval = gov.evaluate_query("good.com", "A").unwrap();
        assert_eq!(eval.decision, DnsQueryDecision::Allow);
    }

    #[test]
    fn test_in_memory_blocks_blocked() {
        let mut gov = InMemoryDnsSecurityGovernor::new("g1", false);
        gov.add_blocked_domain("evil.com");
        let eval = gov.evaluate_query("evil.com", "A").unwrap();
        assert_eq!(eval.decision, DnsQueryDecision::Block);
    }

    #[test]
    fn test_in_memory_allowlist_mode() {
        let mut gov = InMemoryDnsSecurityGovernor::new("g1", true);
        gov.set_allowed_domains(vec!["safe.com".into()]);
        assert!(gov.is_domain_allowed("safe.com"));
        assert!(!gov.is_domain_allowed("other.com"));
        let eval = gov.evaluate_query("other.com", "A").unwrap();
        assert_eq!(eval.decision, DnsQueryDecision::Block);
    }

    #[test]
    fn test_in_memory_dnssec_status() {
        let gov = InMemoryDnsSecurityGovernor::new("g1", true);
        let eval = gov.evaluate_query("example.com", "A").unwrap();
        assert_eq!(eval.dnssec_status, DnssecStatus::NotValidated);

        let gov2 = InMemoryDnsSecurityGovernor::new("g2", false);
        let eval2 = gov2.evaluate_query("example.com", "A").unwrap();
        assert_eq!(eval2.dnssec_status, DnssecStatus::NotRequired);
    }

    #[test]
    fn test_in_memory_resolver_compliance() {
        let gov = InMemoryDnsSecurityGovernor::new("g1", true);
        let result = gov.check_resolver_compliance("8.8.8.8").unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_blocklist_wrapper_blocks() {
        let inner = InMemoryDnsSecurityGovernor::new("g1", false);
        let mut wrapped = BlocklistDnsSecurityGovernor::new(inner);
        wrapped.add_blocked_domain("extra-evil.com");
        let eval = wrapped.evaluate_query("extra-evil.com", "A").unwrap();
        assert_eq!(eval.decision, DnsQueryDecision::Block);
        // Non-blocked domain passes through
        let eval2 = wrapped.evaluate_query("good.com", "A").unwrap();
        assert_eq!(eval2.decision, DnsQueryDecision::Allow);
    }

    #[test]
    fn test_blocklist_wrapper_is_domain_blocked() {
        let mut inner = InMemoryDnsSecurityGovernor::new("g1", false);
        inner.add_blocked_domain("inner-evil.com");
        let mut wrapped = BlocklistDnsSecurityGovernor::new(inner);
        wrapped.add_blocked_domain("outer-evil.com");
        assert!(wrapped.is_domain_blocked("inner-evil.com"));
        assert!(wrapped.is_domain_blocked("outer-evil.com"));
        assert!(!wrapped.is_domain_blocked("good.com"));
    }

    #[test]
    fn test_blocklist_wrapper_delegates() {
        let inner = InMemoryDnsSecurityGovernor::new("g1", false);
        let wrapped = BlocklistDnsSecurityGovernor::new(inner);
        assert_eq!(wrapped.governor_id(), "g1");
        assert!(wrapped.is_active());
    }

    #[test]
    fn test_null_governor() {
        let gov = NullDnsSecurityGovernor;
        assert!(!gov.is_active());
        assert_eq!(gov.governor_id(), "null-dns-security-governor");
        let eval = gov.evaluate_query("anything.com", "A").unwrap();
        assert_eq!(eval.decision, DnsQueryDecision::Allow);
        assert!(!gov.is_domain_blocked("anything.com"));
        assert!(gov.is_domain_allowed("anything.com"));
    }

    #[test]
    fn test_null_governor_resolver() {
        let gov = NullDnsSecurityGovernor;
        let result = gov.check_resolver_compliance("8.8.8.8").unwrap();
        assert!(result.compliant);
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            DnsQueryDecision::Allow,
            DnsQueryDecision::Block,
            DnsQueryDecision::Redirect,
            DnsQueryDecision::RequireDnssec,
            DnsQueryDecision::LogOnly,
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
        assert_eq!(decisions.len(), 5);
    }

    #[test]
    fn test_dnssec_status_display() {
        let statuses = vec![
            DnssecStatus::Validated,
            DnssecStatus::NotValidated,
            DnssecStatus::NotRequired,
            DnssecStatus::ValidationFailed,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_governor_id() {
        let gov = InMemoryDnsSecurityGovernor::new("my-dns-gov", false);
        assert_eq!(gov.governor_id(), "my-dns-gov");
        assert!(gov.is_active());
    }
}
