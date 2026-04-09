// ═══════════════════════════════════════════════════════════════════════
// Core Permission Types
//
// The atoms of the permission system: Permission, Action, Resource,
// Subject, Classification, Condition, Pillar.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::context::EvalContext;

// ── PermissionId ───────────────────────────────────────────────────

/// Namespaced permission identifier, e.g. "file:read", "model:invoke".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionId(String);

impl PermissionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Everything before the first ':'.
    pub fn namespace(&self) -> &str {
        self.0.split(':').next().unwrap_or(&self.0)
    }

    /// Everything after the first ':'.
    pub fn action_part(&self) -> &str {
        match self.0.find(':') {
            Some(i) => &self.0[i + 1..],
            None => "",
        }
    }

    /// Glob matching: "file:*" matches "file:read", "*" matches anything.
    pub fn matches(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            self.0.starts_with(prefix)
        } else {
            self.0 == pattern
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PermissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Action ─────────────────────────────────────────────────────────

/// Operations that can be performed on resources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Create,
    Delete,
    Execute,
    Approve,
    Deploy,
    Audit,
    Admin,
    Custom(String),
}

impl Action {
    pub fn is_destructive(&self) -> bool {
        matches!(self, Self::Delete | Self::Deploy)
    }

    pub fn is_privileged(&self) -> bool {
        matches!(self, Self::Admin | Self::Approve | Self::Deploy)
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "read" => Self::Read,
            "write" => Self::Write,
            "create" => Self::Create,
            "delete" => Self::Delete,
            "execute" => Self::Execute,
            "approve" => Self::Approve,
            "deploy" => Self::Deploy,
            "audit" => Self::Audit,
            "admin" => Self::Admin,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "Read"),
            Self::Write => write!(f, "Write"),
            Self::Create => write!(f, "Create"),
            Self::Delete => write!(f, "Delete"),
            Self::Execute => write!(f, "Execute"),
            Self::Approve => write!(f, "Approve"),
            Self::Deploy => write!(f, "Deploy"),
            Self::Audit => write!(f, "Audit"),
            Self::Admin => write!(f, "Admin"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ── ResourcePattern ────────────────────────────────────────────────

/// Pattern for matching resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourcePattern {
    /// Exact string match.
    Exact(String),
    /// Prefix match: "models/" matches "models/gpt-4".
    Prefix(String),
    /// Regex pattern stored as string, matched at runtime.
    Regex(String),
    /// Matches everything. Requires explicit opt-in.
    All,
}

impl ResourcePattern {
    pub fn matches(&self, resource: &str) -> bool {
        match self {
            Self::Exact(s) => resource == s,
            Self::Prefix(p) => resource.starts_with(p.as_str()),
            Self::Regex(pattern) => {
                // Simple glob-like matching: * at end = prefix.
                if let Some(prefix) = pattern.strip_suffix('*') {
                    resource.starts_with(prefix)
                } else {
                    resource == pattern
                }
            }
            Self::All => true,
        }
    }

    pub fn is_wildcard(&self) -> bool {
        match self {
            Self::All => true,
            Self::Prefix(p) => p == "*" || p.is_empty(),
            _ => false,
        }
    }
}

impl fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(s) => write!(f, "{s}"),
            Self::Prefix(p) => write!(f, "{p}*"),
            Self::Regex(r) => write!(f, "/{r}/"),
            Self::All => write!(f, "*"),
        }
    }
}

// ── ClassificationLevel ────────────────────────────────────────────

/// Security classification (Bell-LaPadula model). Ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ClassificationLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
    TopSecret = 4,
}

impl ClassificationLevel {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Public => "Public",
            Self::Internal => "Internal",
            Self::Confidential => "Confidential",
            Self::Restricted => "Restricted",
            Self::TopSecret => "TopSecret",
        }
    }

    /// Bell-LaPadula "no read up": true if self >= other.
    pub fn dominates(&self, other: &ClassificationLevel) -> bool {
        *self >= *other
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            "topsecret" | "top_secret" | "top-secret" => Some(Self::TopSecret),
            _ => None,
        }
    }
}

impl fmt::Display for ClassificationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Pillar ─────────────────────────────────────────────────────────

/// RUNE's four foundational governance pillars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Pillar {
    SecurityBakedIn,
    AssumedBreach,
    NoSinglePointsOfFailure,
    ZeroTrustThroughout,
}

impl fmt::Display for Pillar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityBakedIn => write!(f, "Security Baked In"),
            Self::AssumedBreach => write!(f, "Assumed Breach"),
            Self::NoSinglePointsOfFailure => write!(f, "No Single Points of Failure"),
            Self::ZeroTrustThroughout => write!(f, "Zero Trust Throughout"),
        }
    }
}

// ── Condition ──────────────────────────────────────────────────────

/// Conditions that must be satisfied for a permission to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    TimeWindow { start: i64, end: i64 },
    IpRange { cidr: String },
    RiskScoreBelow(i64),
    RiskScoreAbove(i64),
    RequiresMfa,
    RequiresApproval { approver_role: String },
    MaxUsageCount(u64),
    Custom { key: String, value: String },
}

impl Condition {
    /// Evaluate this condition against a request context.
    pub fn evaluate(&self, ctx: &EvalContext) -> bool {
        match self {
            Self::TimeWindow { start, end } => {
                ctx.timestamp >= *start && ctx.timestamp <= *end
            }
            Self::IpRange { cidr } => {
                match &ctx.source_ip {
                    Some(ip) => ip_matches_cidr(ip, cidr),
                    None => false,
                }
            }
            Self::RiskScoreBelow(threshold) => {
                ctx.risk_score.map_or(true, |s| s < *threshold)
            }
            Self::RiskScoreAbove(threshold) => {
                ctx.risk_score.map_or(false, |s| s > *threshold)
            }
            Self::RequiresMfa => ctx.mfa_verified,
            Self::RequiresApproval { .. } => {
                // Approval checks are handled externally; this condition
                // signals that approval is required, not that it was given.
                false
            }
            Self::MaxUsageCount(_) => {
                // Usage counting is handled by the grant store.
                true
            }
            Self::Custom { key, value } => {
                ctx.custom.get(key).map_or(false, |v| v == value)
            }
        }
    }
}

/// Simplified CIDR matching: exact IP or prefix-based.
fn ip_matches_cidr(ip: &str, cidr: &str) -> bool {
    if cidr.contains('/') {
        let prefix = cidr.split('/').next().unwrap_or("");
        // For /0 match all, otherwise match the network prefix part.
        if cidr.ends_with("/0") {
            return true;
        }
        // Simple prefix matching for common cases.
        let parts: Vec<&str> = prefix.split('.').collect();
        let ip_parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 || ip_parts.len() != 4 {
            return false;
        }
        let mask_bits: u32 = cidr.split('/').nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(32);
        let full_octets = (mask_bits / 8) as usize;
        for i in 0..full_octets.min(4) {
            if parts[i] != ip_parts[i] {
                return false;
            }
        }
        true
    } else {
        ip == cidr
    }
}

// ── SubjectId ──────────────────────────────────────────────────────

/// Unique identifier for a subject (user, service, device, AI agent).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectId(String);

impl SubjectId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── SubjectType ────────────────────────────────────────────────────

/// What kind of entity a subject is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectType {
    User,
    Service,
    Device,
    AiAgent,
    System,
}

impl fmt::Display for SubjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "User"),
            Self::Service => write!(f, "Service"),
            Self::Device => write!(f, "Device"),
            Self::AiAgent => write!(f, "AiAgent"),
            Self::System => write!(f, "System"),
        }
    }
}

// ── Subject ────────────────────────────────────────────────────────

/// An entity that can hold roles and request access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub id: SubjectId,
    pub subject_type: SubjectType,
    pub display_name: String,
    pub clearance: ClassificationLevel,
    pub attributes: HashMap<String, String>,
    pub active: bool,
    pub created_at: i64,
}

impl Subject {
    pub fn new(id: impl Into<String>, subject_type: SubjectType, name: impl Into<String>) -> Self {
        Self {
            id: SubjectId::new(id),
            subject_type,
            display_name: name.into(),
            clearance: ClassificationLevel::Public,
            attributes: HashMap::new(),
            active: true,
            created_at: 0,
        }
    }

    pub fn clearance(mut self, level: ClassificationLevel) -> Self {
        self.clearance = level;
        self
    }

    pub fn created_at(mut self, ts: i64) -> Self {
        self.created_at = ts;
        self
    }

    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

// ── Permission ─────────────────────────────────────────────────────

/// A permission defining what actions are allowed on what resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: PermissionId,
    pub resource: ResourcePattern,
    pub actions: Vec<Action>,
    pub conditions: Vec<Condition>,
    pub classification: ClassificationLevel,
    pub pillar_alignment: Vec<Pillar>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

impl Permission {
    pub fn new(id: impl Into<String>, resource: ResourcePattern, actions: Vec<Action>) -> Self {
        Self {
            id: PermissionId::new(id),
            resource,
            actions,
            conditions: Vec::new(),
            classification: ClassificationLevel::Public,
            pillar_alignment: Vec::new(),
            created_at: 0,
            expires_at: None,
        }
    }

    pub fn classification(mut self, level: ClassificationLevel) -> Self {
        self.classification = level;
        self
    }

    pub fn condition(mut self, cond: Condition) -> Self {
        self.conditions.push(cond);
        self
    }

    pub fn pillar(mut self, p: Pillar) -> Self {
        self.pillar_alignment.push(p);
        self
    }

    pub fn expires_at(mut self, ts: i64) -> Self {
        self.expires_at = Some(ts);
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map_or(false, |exp| now > exp)
    }

    /// Check if this permission matches a given action and resource.
    pub fn matches_action(&self, action: &Action) -> bool {
        self.actions.contains(action)
    }

    pub fn matches_resource(&self, resource: &str) -> bool {
        self.resource.matches(resource)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_id_new() {
        let id = PermissionId::new("file:read");
        assert_eq!(id.as_str(), "file:read");
    }

    #[test]
    fn test_permission_id_namespace() {
        assert_eq!(PermissionId::new("file:read").namespace(), "file");
        assert_eq!(PermissionId::new("model:invoke").namespace(), "model");
        assert_eq!(PermissionId::new("nocolon").namespace(), "nocolon");
    }

    #[test]
    fn test_permission_id_action_part() {
        assert_eq!(PermissionId::new("file:read").action_part(), "read");
        assert_eq!(PermissionId::new("nocolon").action_part(), "");
    }

    #[test]
    fn test_permission_id_matches_exact() {
        let id = PermissionId::new("file:read");
        assert!(id.matches("file:read"));
        assert!(!id.matches("file:write"));
    }

    #[test]
    fn test_permission_id_matches_glob() {
        let id = PermissionId::new("file:read");
        assert!(id.matches("file:*"));
        assert!(id.matches("*"));
        assert!(!id.matches("model:*"));
    }

    #[test]
    fn test_permission_id_matches_no_match() {
        let id = PermissionId::new("file:read");
        assert!(!id.matches("model:invoke"));
    }

    #[test]
    fn test_action_from_str_known() {
        assert_eq!(Action::from_str("read"), Action::Read);
        assert_eq!(Action::from_str("Write"), Action::Write);
        assert_eq!(Action::from_str("DELETE"), Action::Delete);
        assert_eq!(Action::from_str("admin"), Action::Admin);
    }

    #[test]
    fn test_action_from_str_unknown() {
        assert_eq!(Action::from_str("custom_op"), Action::Custom("custom_op".into()));
    }

    #[test]
    fn test_action_is_destructive() {
        assert!(Action::Delete.is_destructive());
        assert!(Action::Deploy.is_destructive());
        assert!(!Action::Read.is_destructive());
        assert!(!Action::Admin.is_destructive());
    }

    #[test]
    fn test_action_is_privileged() {
        assert!(Action::Admin.is_privileged());
        assert!(Action::Approve.is_privileged());
        assert!(Action::Deploy.is_privileged());
        assert!(!Action::Read.is_privileged());
        assert!(!Action::Delete.is_privileged());
    }

    #[test]
    fn test_resource_exact_matches() {
        let rp = ResourcePattern::Exact("models/gpt-4".into());
        assert!(rp.matches("models/gpt-4"));
        assert!(!rp.matches("models/gpt-5"));
    }

    #[test]
    fn test_resource_prefix_matches() {
        let rp = ResourcePattern::Prefix("models/".into());
        assert!(rp.matches("models/gpt-4"));
        assert!(rp.matches("models/anything"));
        assert!(!rp.matches("users/admin"));
    }

    #[test]
    fn test_resource_all_matches() {
        let rp = ResourcePattern::All;
        assert!(rp.matches("anything"));
        assert!(rp.matches(""));
    }

    #[test]
    fn test_resource_is_wildcard() {
        assert!(ResourcePattern::All.is_wildcard());
        assert!(!ResourcePattern::Exact("x".into()).is_wildcard());
    }

    #[test]
    fn test_classification_ordering() {
        assert!(ClassificationLevel::Public < ClassificationLevel::Internal);
        assert!(ClassificationLevel::Internal < ClassificationLevel::Confidential);
        assert!(ClassificationLevel::Confidential < ClassificationLevel::Restricted);
        assert!(ClassificationLevel::Restricted < ClassificationLevel::TopSecret);
    }

    #[test]
    fn test_classification_dominates() {
        assert!(ClassificationLevel::TopSecret.dominates(&ClassificationLevel::Public));
        assert!(ClassificationLevel::TopSecret.dominates(&ClassificationLevel::TopSecret));
        assert!(ClassificationLevel::Public.dominates(&ClassificationLevel::Public));
        assert!(!ClassificationLevel::Public.dominates(&ClassificationLevel::Internal));
    }

    #[test]
    fn test_classification_from_str() {
        assert_eq!(ClassificationLevel::from_str("public"), Some(ClassificationLevel::Public));
        assert_eq!(ClassificationLevel::from_str("TopSecret"), Some(ClassificationLevel::TopSecret));
        assert_eq!(ClassificationLevel::from_str("unknown"), None);
    }

    #[test]
    fn test_subject_construction() {
        let s = Subject::new("user1", SubjectType::User, "Alice")
            .clearance(ClassificationLevel::Confidential)
            .created_at(1000)
            .attribute("dept", "engineering");
        assert_eq!(s.id, SubjectId::new("user1"));
        assert_eq!(s.subject_type, SubjectType::User);
        assert_eq!(s.clearance, ClassificationLevel::Confidential);
        assert_eq!(s.attributes.get("dept"), Some(&"engineering".to_string()));
        assert!(s.active);
    }

    #[test]
    fn test_subject_type_display() {
        assert_eq!(SubjectType::User.to_string(), "User");
        assert_eq!(SubjectType::AiAgent.to_string(), "AiAgent");
        assert_eq!(SubjectType::System.to_string(), "System");
    }

    #[test]
    fn test_condition_time_window() {
        let cond = Condition::TimeWindow { start: 100, end: 200 };
        let ctx = EvalContext::for_subject(
            Subject::new("u", SubjectType::User, "U")
        ).timestamp(150).build();
        assert!(cond.evaluate(&ctx));

        let ctx_outside = EvalContext::for_subject(
            Subject::new("u", SubjectType::User, "U")
        ).timestamp(300).build();
        assert!(!cond.evaluate(&ctx_outside));
    }

    #[test]
    fn test_condition_risk_score_below() {
        let cond = Condition::RiskScoreBelow(50);
        let ctx = EvalContext::for_subject(
            Subject::new("u", SubjectType::User, "U")
        ).risk_score(25).build();
        assert!(cond.evaluate(&ctx));

        let ctx_high = EvalContext::for_subject(
            Subject::new("u", SubjectType::User, "U")
        ).risk_score(75).build();
        assert!(!cond.evaluate(&ctx_high));
    }

    #[test]
    fn test_condition_requires_mfa() {
        let cond = Condition::RequiresMfa;
        let ctx_mfa = EvalContext::for_subject(
            Subject::new("u", SubjectType::User, "U")
        ).mfa(true).build();
        assert!(cond.evaluate(&ctx_mfa));

        let ctx_no = EvalContext::for_subject(
            Subject::new("u", SubjectType::User, "U")
        ).build();
        assert!(!cond.evaluate(&ctx_no));
    }

    #[test]
    fn test_pillar_display() {
        assert_eq!(Pillar::SecurityBakedIn.to_string(), "Security Baked In");
        assert_eq!(Pillar::ZeroTrustThroughout.to_string(), "Zero Trust Throughout");
    }

    #[test]
    fn test_permission_is_expired() {
        let p = Permission::new("file:read", ResourcePattern::All, vec![Action::Read])
            .expires_at(100);
        assert!(p.is_expired(200));
        assert!(!p.is_expired(50));
    }

    #[test]
    fn test_permission_matches_action_and_resource() {
        let p = Permission::new(
            "file:read",
            ResourcePattern::Prefix("docs/".into()),
            vec![Action::Read, Action::Write],
        );
        assert!(p.matches_action(&Action::Read));
        assert!(!p.matches_action(&Action::Delete));
        assert!(p.matches_resource("docs/readme.md"));
        assert!(!p.matches_resource("models/gpt-4"));
    }
}
