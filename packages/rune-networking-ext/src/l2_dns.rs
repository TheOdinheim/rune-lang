// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — DNS security verification.
//
// DNS security verification with DNSSEC-aware validation, DNS-based
// policy enforcement, and TTL-aware caching.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── DnsRecordType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    CAA,
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::NS => "NS",
            Self::SOA => "SOA",
            Self::SRV => "SRV",
            Self::CAA => "CAA",
        };
        f.write_str(s)
    }
}

// ── DnsRecord ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub hostname: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl_seconds: u32,
    pub resolved_at: i64,
    pub dnssec_validated: bool,
}

// ── DnsCheckResult ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsCheckResult {
    pub allowed: bool,
    pub blocked: bool,
    pub reason: String,
    pub dnssec_required: bool,
}

// ── DnsSecurityChecker ───────────────────────────────────────────

#[derive(Debug)]
pub struct DnsSecurityChecker {
    pub allowed_resolvers: Vec<String>,
    pub require_dnssec: bool,
    blocked_domains: Vec<String>,
    allowed_domains: Option<Vec<String>>,
}

impl DnsSecurityChecker {
    pub fn new(require_dnssec: bool) -> Self {
        Self {
            allowed_resolvers: Vec::new(),
            require_dnssec,
            blocked_domains: Vec::new(),
            allowed_domains: None,
        }
    }

    pub fn add_blocked_domain(&mut self, domain: &str) {
        self.blocked_domains.push(domain.to_lowercase());
    }

    pub fn set_allowed_domains(&mut self, domains: Vec<String>) {
        self.allowed_domains = Some(
            domains.into_iter().map(|d| d.to_lowercase()).collect(),
        );
    }

    pub fn check_domain(&self, hostname: &str) -> DnsCheckResult {
        let hostname_lower = hostname.to_lowercase();

        // Allowlist mode
        if let Some(allowed) = &self.allowed_domains {
            if allowed.iter().any(|d| d == &hostname_lower) {
                return DnsCheckResult {
                    allowed: true,
                    blocked: false,
                    reason: "Domain in allowed list".into(),
                    dnssec_required: self.require_dnssec,
                };
            }
            return DnsCheckResult {
                allowed: false,
                blocked: true,
                reason: "Domain not in allowed list".into(),
                dnssec_required: self.require_dnssec,
            };
        }

        // Blocklist mode
        if self.blocked_domains.iter().any(|d| d == &hostname_lower) {
            return DnsCheckResult {
                allowed: false,
                blocked: true,
                reason: "Domain is blocked".into(),
                dnssec_required: self.require_dnssec,
            };
        }

        DnsCheckResult {
            allowed: true,
            blocked: false,
            reason: "Domain is allowed".into(),
            dnssec_required: self.require_dnssec,
        }
    }

    pub fn is_blocked(&self, hostname: &str) -> bool {
        let result = self.check_domain(hostname);
        result.blocked
    }

    pub fn is_allowed(&self, hostname: &str) -> bool {
        let result = self.check_domain(hostname);
        result.allowed
    }
}

// ── DnsCache ─────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<String, DnsRecord>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: DnsRecord) {
        self.entries.insert(record.hostname.clone(), record);
    }

    pub fn lookup(&self, hostname: &str, now: i64) -> Option<&DnsRecord> {
        self.entries.get(hostname).filter(|r| {
            let expiry = r.resolved_at + (r.ttl_seconds as i64 * 1000);
            now <= expiry
        })
    }

    pub fn evict_expired(&mut self, now: i64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, r| {
            let expiry = r.resolved_at + (r.ttl_seconds as i64 * 1000);
            now <= expiry
        });
        before - self.entries.len()
    }

    pub fn cache_size(&self) -> usize {
        self.entries.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_domain_allows_non_blocked() {
        let mut checker = DnsSecurityChecker::new(false);
        checker.add_blocked_domain("evil.com");
        let result = checker.check_domain("good.com");
        assert!(result.allowed);
        assert!(!result.blocked);
    }

    #[test]
    fn test_check_domain_blocks_blocked() {
        let mut checker = DnsSecurityChecker::new(false);
        checker.add_blocked_domain("evil.com");
        let result = checker.check_domain("evil.com");
        assert!(!result.allowed);
        assert!(result.blocked);
    }

    #[test]
    fn test_allowed_domains_restricts_to_allowlist() {
        let mut checker = DnsSecurityChecker::new(true);
        checker.set_allowed_domains(vec!["safe.com".into(), "trusted.org".into()]);
        assert!(checker.is_allowed("safe.com"));
        assert!(!checker.is_allowed("other.com"));
    }

    #[test]
    fn test_is_blocked_returns_true() {
        let mut checker = DnsSecurityChecker::new(false);
        checker.add_blocked_domain("evil.com");
        assert!(checker.is_blocked("evil.com"));
        assert!(!checker.is_blocked("good.com"));
    }

    #[test]
    fn test_cache_insert_and_lookup_within_ttl() {
        let mut cache = DnsCache::new();
        cache.insert(DnsRecord {
            hostname: "example.com".into(),
            record_type: DnsRecordType::A,
            value: "1.2.3.4".into(),
            ttl_seconds: 300,
            resolved_at: 1000,
            dnssec_validated: true,
        });
        // Within TTL: 1000 + 300*1000 = 301_000
        assert!(cache.lookup("example.com", 50_000).is_some());
    }

    #[test]
    fn test_cache_lookup_returns_none_for_expired() {
        let mut cache = DnsCache::new();
        cache.insert(DnsRecord {
            hostname: "example.com".into(),
            record_type: DnsRecordType::A,
            value: "1.2.3.4".into(),
            ttl_seconds: 60,
            resolved_at: 1000,
            dnssec_validated: false,
        });
        // Expired: 1000 + 60*1000 = 61_000
        assert!(cache.lookup("example.com", 100_000).is_none());
    }

    #[test]
    fn test_cache_evict_expired() {
        let mut cache = DnsCache::new();
        cache.insert(DnsRecord {
            hostname: "short.com".into(),
            record_type: DnsRecordType::A,
            value: "1.2.3.4".into(),
            ttl_seconds: 10,
            resolved_at: 1000,
            dnssec_validated: false,
        });
        cache.insert(DnsRecord {
            hostname: "long.com".into(),
            record_type: DnsRecordType::A,
            value: "5.6.7.8".into(),
            ttl_seconds: 3600,
            resolved_at: 1000,
            dnssec_validated: true,
        });
        let evicted = cache.evict_expired(50_000);
        assert_eq!(evicted, 1);
        assert_eq!(cache.cache_size(), 1);
    }
}
