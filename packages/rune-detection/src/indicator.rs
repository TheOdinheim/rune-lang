// ═══════════════════════════════════════════════════════════════════════
// Indicators of Compromise — IoC matching
//
// Threat-intel IoCs (IPs, domains, URLs, hashes, emails, file names,
// registry keys, processes, user agents) with expiry, active/inactive
// status, and text-scanning for embedded indicators.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;
use serde::{Deserialize, Serialize};

// ── IoCType ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoCType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    EmailAddress,
    FileName,
    RegistryKey,
    ProcessName,
    UserAgent,
    Custom(String),
}

impl fmt::Display for IoCType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IpAddress => write!(f, "IpAddress"),
            Self::Domain => write!(f, "Domain"),
            Self::Url => write!(f, "Url"),
            Self::FileHash => write!(f, "FileHash"),
            Self::EmailAddress => write!(f, "EmailAddress"),
            Self::FileName => write!(f, "FileName"),
            Self::RegistryKey => write!(f, "RegistryKey"),
            Self::ProcessName => write!(f, "ProcessName"),
            Self::UserAgent => write!(f, "UserAgent"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── IoC ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IoC {
    pub indicator_type: IoCType,
    pub value: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub source: String,
    pub added_at: i64,
    pub expires_at: Option<i64>,
    pub tags: Vec<String>,
    pub active: bool,
}

impl IoC {
    pub fn new(
        indicator_type: IoCType,
        value: &str,
        severity: SecuritySeverity,
        source: &str,
    ) -> Self {
        Self {
            indicator_type,
            value: value.into(),
            description: String::new(),
            severity,
            source: source.into(),
            added_at: 0,
            expires_at: None,
            tags: Vec::new(),
            active: true,
        }
    }

    fn is_case_insensitive(&self) -> bool {
        matches!(
            self.indicator_type,
            IoCType::Domain | IoCType::EmailAddress | IoCType::Url | IoCType::UserAgent
        )
    }

    fn matches_value(&self, other: &str) -> bool {
        if self.is_case_insensitive() {
            self.value.eq_ignore_ascii_case(other)
        } else {
            self.value == other
        }
    }

    fn contains_in(&self, text: &str) -> bool {
        if self.is_case_insensitive() {
            text.to_ascii_lowercase().contains(&self.value.to_ascii_lowercase())
        } else {
            text.contains(&self.value)
        }
    }

    fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map(|e| now >= e).unwrap_or(false)
    }
}

// ── IoCDatabase ───────────────────────────────────────────────────────

#[derive(Default)]
pub struct IoCDatabase {
    pub indicators: Vec<IoC>,
}

impl IoCDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, ioc: IoC) {
        self.indicators.push(ioc);
    }

    pub fn check(&self, indicator_type: &IoCType, value: &str, now: i64) -> Option<&IoC> {
        self.indicators.iter().find(|ioc| {
            ioc.active
                && !ioc.is_expired(now)
                && &ioc.indicator_type == indicator_type
                && ioc.matches_value(value)
        })
    }

    pub fn check_text(&self, text: &str, now: i64) -> Vec<&IoC> {
        self.indicators
            .iter()
            .filter(|ioc| {
                ioc.active
                    && !ioc.is_expired(now)
                    && matches!(
                        ioc.indicator_type,
                        IoCType::IpAddress
                            | IoCType::Domain
                            | IoCType::Url
                            | IoCType::FileHash
                            | IoCType::EmailAddress
                    )
                    && ioc.contains_in(text)
            })
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.indicators.iter().filter(|i| i.active).count()
    }

    pub fn by_type(&self, ioc_type: &IoCType) -> Vec<&IoC> {
        self.indicators.iter().filter(|i| &i.indicator_type == ioc_type).collect()
    }

    pub fn by_severity(&self, severity: SecuritySeverity) -> Vec<&IoC> {
        self.indicators.iter().filter(|i| i.severity == severity).collect()
    }

    pub fn expired(&self, now: i64) -> Vec<&IoC> {
        self.indicators.iter().filter(|i| i.is_expired(now)).collect()
    }

    pub fn remove_expired(&mut self, now: i64) -> usize {
        let before = self.indicators.len();
        self.indicators.retain(|i| !i.is_expired(now));
        before - self.indicators.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_check() {
        let mut db = IoCDatabase::new();
        db.add(IoC::new(IoCType::IpAddress, "1.2.3.4", SecuritySeverity::High, "feed"));
        assert!(db.check(&IoCType::IpAddress, "1.2.3.4", 0).is_some());
    }

    #[test]
    fn test_check_unknown_value() {
        let db = IoCDatabase::new();
        assert!(db.check(&IoCType::IpAddress, "9.9.9.9", 0).is_none());
    }

    #[test]
    fn test_check_skips_expired() {
        let mut db = IoCDatabase::new();
        let mut ioc = IoC::new(IoCType::Domain, "evil.com", SecuritySeverity::High, "feed");
        ioc.expires_at = Some(1000);
        db.add(ioc);
        assert!(db.check(&IoCType::Domain, "evil.com", 1500).is_none());
    }

    #[test]
    fn test_check_text_finds_ip() {
        let mut db = IoCDatabase::new();
        db.add(IoC::new(
            IoCType::IpAddress,
            "1.2.3.4",
            SecuritySeverity::High,
            "feed",
        ));
        let hits = db.check_text("connection from 1.2.3.4 to server", 0);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_check_text_finds_domain() {
        let mut db = IoCDatabase::new();
        db.add(IoC::new(
            IoCType::Domain,
            "evil.com",
            SecuritySeverity::High,
            "feed",
        ));
        let hits = db.check_text("resolved evil.com to 1.2.3.4", 0);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_active_count_excludes_inactive() {
        let mut db = IoCDatabase::new();
        let mut ioc = IoC::new(IoCType::IpAddress, "1.1.1.1", SecuritySeverity::Low, "f");
        ioc.active = false;
        db.add(ioc);
        db.add(IoC::new(
            IoCType::IpAddress,
            "2.2.2.2",
            SecuritySeverity::Low,
            "f",
        ));
        assert_eq!(db.active_count(), 1);
    }

    #[test]
    fn test_by_type_filter() {
        let mut db = IoCDatabase::new();
        db.add(IoC::new(IoCType::IpAddress, "1.2.3.4", SecuritySeverity::High, "f"));
        db.add(IoC::new(IoCType::Domain, "evil.com", SecuritySeverity::High, "f"));
        assert_eq!(db.by_type(&IoCType::IpAddress).len(), 1);
        assert_eq!(db.by_type(&IoCType::Domain).len(), 1);
    }

    #[test]
    fn test_remove_expired() {
        let mut db = IoCDatabase::new();
        let mut e = IoC::new(IoCType::Domain, "a.com", SecuritySeverity::Low, "f");
        e.expires_at = Some(100);
        db.add(e);
        db.add(IoC::new(IoCType::Domain, "b.com", SecuritySeverity::Low, "f"));
        assert_eq!(db.remove_expired(500), 1);
        assert_eq!(db.indicators.len(), 1);
    }

    #[test]
    fn test_case_insensitive_domain() {
        let mut db = IoCDatabase::new();
        db.add(IoC::new(
            IoCType::Domain,
            "Evil.COM",
            SecuritySeverity::High,
            "feed",
        ));
        assert!(db.check(&IoCType::Domain, "evil.com", 0).is_some());
        assert!(db.check(&IoCType::Domain, "EVIL.COM", 0).is_some());
    }
}
