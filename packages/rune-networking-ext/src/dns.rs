// ═══════════════════════════════════════════════════════════════════════
// DNS — DNS resolution governance and filtering.
// Controls which domains can be resolved, blocks malicious domains,
// and audits all DNS queries.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── DnsQueryType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Ptr,
    Any,
}

impl fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Cname => write!(f, "CNAME"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Srv => write!(f, "SRV"),
            Self::Ptr => write!(f, "PTR"),
            Self::Any => write!(f, "ANY"),
        }
    }
}

// ── DnsQuery ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: String,
    pub domain: String,
    pub query_type: DnsQueryType,
    pub source: String,
    pub timestamp: i64,
}

// ── DnsDecision ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsDecision {
    pub allowed: bool,
    pub domain: String,
    pub reason: Option<String>,
    pub matched_rule: Option<String>,
}

// ── DnsPolicy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPolicy {
    pub id: String,
    pub name: String,
    pub blocked_domains: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub blocked_patterns: Vec<String>,
    pub require_dnssec: bool,
    pub log_all_queries: bool,
    pub max_queries_per_minute: Option<u64>,
}

// ── DnsGovernor ─────────────────────────────────────────────────────

pub struct DnsGovernor {
    policy: DnsPolicy,
    query_log: Vec<DnsQuery>,
    query_counter: u64,
}

impl DnsGovernor {
    pub fn new(policy: DnsPolicy) -> Self {
        Self {
            policy,
            query_log: Vec::new(),
            query_counter: 0,
        }
    }

    pub fn check(&self, domain: &str) -> DnsDecision {
        let domain_lower = domain.to_lowercase();

        // Allowlist mode: if allowed_domains is non-empty, only those are permitted
        if !self.policy.allowed_domains.is_empty() {
            if self.policy.allowed_domains.iter().any(|d| d.to_lowercase() == domain_lower) {
                return DnsDecision {
                    allowed: true,
                    domain: domain.into(),
                    reason: None,
                    matched_rule: Some("allowed_domains".into()),
                };
            }
            return DnsDecision {
                allowed: false,
                domain: domain.into(),
                reason: Some("Domain not in allowed list".into()),
                matched_rule: Some("allowed_domains".into()),
            };
        }

        // Blocked domains
        if self.policy.blocked_domains.iter().any(|d| d.to_lowercase() == domain_lower) {
            return DnsDecision {
                allowed: false,
                domain: domain.into(),
                reason: Some("Domain is blocked".into()),
                matched_rule: Some("blocked_domains".into()),
            };
        }

        // Blocked patterns
        for pattern in &self.policy.blocked_patterns {
            if Self::matches_pattern(&domain_lower, pattern) {
                return DnsDecision {
                    allowed: false,
                    domain: domain.into(),
                    reason: Some(format!("Matches blocked pattern: {pattern}")),
                    matched_rule: Some(format!("blocked_pattern:{pattern}")),
                };
            }
        }

        DnsDecision {
            allowed: true,
            domain: domain.into(),
            reason: None,
            matched_rule: None,
        }
    }

    pub fn record_query(
        &mut self,
        domain: &str,
        query_type: DnsQueryType,
        source: &str,
        now: i64,
    ) -> DnsDecision {
        let decision = self.check(domain);
        self.query_counter += 1;
        self.query_log.push(DnsQuery {
            id: format!("dns_{:08x}", self.query_counter),
            domain: domain.into(),
            query_type,
            source: source.into(),
            timestamp: now,
        });
        decision
    }

    pub fn queries_for_domain(&self, domain: &str) -> Vec<&DnsQuery> {
        let domain_lower = domain.to_lowercase();
        self.query_log
            .iter()
            .filter(|q| q.domain.to_lowercase() == domain_lower)
            .collect()
    }

    pub fn queries_from_source(&self, source: &str) -> Vec<&DnsQuery> {
        self.query_log
            .iter()
            .filter(|q| q.source == source)
            .collect()
    }

    pub fn unique_domains_queried(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for q in &self.query_log {
            if seen.insert(q.domain.as_str()) {
                result.push(q.domain.as_str());
            }
        }
        result
    }

    pub fn query_count(&self) -> usize {
        self.query_log.len()
    }

    pub fn matches_pattern(domain: &str, pattern: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        let domain_lower = domain.to_lowercase();

        if pattern_lower.starts_with("*.") {
            let suffix = &pattern_lower[1..]; // includes the leading "."
            domain_lower.ends_with(suffix) && domain_lower != pattern_lower[2..]
        } else {
            domain_lower == pattern_lower
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> DnsPolicy {
        DnsPolicy {
            id: "test".into(),
            name: "Test DNS".into(),
            blocked_domains: vec!["evil.com".into(), "malware.org".into()],
            allowed_domains: Vec::new(),
            blocked_patterns: vec!["*.malware.com".into(), "*.onion".into()],
            require_dnssec: false,
            log_all_queries: false,
            max_queries_per_minute: None,
        }
    }

    #[test]
    fn test_check_allows_non_blocked() {
        let gov = DnsGovernor::new(default_policy());
        let d = gov.check("example.com");
        assert!(d.allowed);
    }

    #[test]
    fn test_check_blocks_blocked_domain() {
        let gov = DnsGovernor::new(default_policy());
        let d = gov.check("evil.com");
        assert!(!d.allowed);
    }

    #[test]
    fn test_check_blocks_matching_pattern() {
        let gov = DnsGovernor::new(default_policy());
        let d = gov.check("sub.malware.com");
        assert!(!d.allowed);
        let d = gov.check("hidden.onion");
        assert!(!d.allowed);
    }

    #[test]
    fn test_check_blocks_not_in_allowed_domains() {
        let policy = DnsPolicy {
            id: "allow".into(),
            name: "Allowlist".into(),
            blocked_domains: Vec::new(),
            allowed_domains: vec!["safe.com".into(), "trusted.org".into()],
            blocked_patterns: Vec::new(),
            require_dnssec: false,
            log_all_queries: false,
            max_queries_per_minute: None,
        };
        let gov = DnsGovernor::new(policy);
        let d = gov.check("unknown.com");
        assert!(!d.allowed);
    }

    #[test]
    fn test_check_allows_in_allowed_domains() {
        let policy = DnsPolicy {
            id: "allow".into(),
            name: "Allowlist".into(),
            blocked_domains: Vec::new(),
            allowed_domains: vec!["safe.com".into(), "trusted.org".into()],
            blocked_patterns: Vec::new(),
            require_dnssec: false,
            log_all_queries: false,
            max_queries_per_minute: None,
        };
        let gov = DnsGovernor::new(policy);
        let d = gov.check("safe.com");
        assert!(d.allowed);
    }

    #[test]
    fn test_record_query_logs() {
        let mut gov = DnsGovernor::new(default_policy());
        gov.record_query("example.com", DnsQueryType::A, "10.0.0.1", 1000);
        assert_eq!(gov.query_count(), 1);
    }

    #[test]
    fn test_queries_for_domain() {
        let mut gov = DnsGovernor::new(default_policy());
        gov.record_query("example.com", DnsQueryType::A, "10.0.0.1", 1000);
        gov.record_query("other.com", DnsQueryType::A, "10.0.0.1", 2000);
        gov.record_query("example.com", DnsQueryType::Aaaa, "10.0.0.2", 3000);
        assert_eq!(gov.queries_for_domain("example.com").len(), 2);
    }

    #[test]
    fn test_queries_from_source() {
        let mut gov = DnsGovernor::new(default_policy());
        gov.record_query("a.com", DnsQueryType::A, "10.0.0.1", 1000);
        gov.record_query("b.com", DnsQueryType::A, "10.0.0.2", 2000);
        assert_eq!(gov.queries_from_source("10.0.0.1").len(), 1);
    }

    #[test]
    fn test_unique_domains_queried() {
        let mut gov = DnsGovernor::new(default_policy());
        gov.record_query("a.com", DnsQueryType::A, "10.0.0.1", 1000);
        gov.record_query("a.com", DnsQueryType::Aaaa, "10.0.0.1", 2000);
        gov.record_query("b.com", DnsQueryType::A, "10.0.0.1", 3000);
        assert_eq!(gov.unique_domains_queried().len(), 2);
    }

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(DnsGovernor::matches_pattern("sub.example.com", "*.example.com"));
        assert!(DnsGovernor::matches_pattern("deep.sub.example.com", "*.example.com"));
        assert!(!DnsGovernor::matches_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(DnsGovernor::matches_pattern("example.com", "example.com"));
        assert!(!DnsGovernor::matches_pattern("sub.example.com", "example.com"));
    }

    #[test]
    fn test_dns_query_type_display() {
        let types = vec![
            DnsQueryType::A,
            DnsQueryType::Aaaa,
            DnsQueryType::Cname,
            DnsQueryType::Mx,
            DnsQueryType::Txt,
            DnsQueryType::Srv,
            DnsQueryType::Ptr,
            DnsQueryType::Any,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_allowlist_only_mode() {
        let policy = DnsPolicy {
            id: "strict".into(),
            name: "Strict".into(),
            blocked_domains: Vec::new(),
            allowed_domains: vec!["internal.corp".into()],
            blocked_patterns: Vec::new(),
            require_dnssec: false,
            log_all_queries: true,
            max_queries_per_minute: Some(100),
        };
        let gov = DnsGovernor::new(policy);
        assert!(gov.check("internal.corp").allowed);
        assert!(!gov.check("external.com").allowed);
    }
}
