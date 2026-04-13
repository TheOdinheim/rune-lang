// ═══════════════════════════════════════════════════════════════════════
// Policy — Extended policy type with versioning, ownership, and
// lifecycle metadata. Extends rune-security's SecurityPolicy/SecurityRule
// into a full managed policy system.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::binding::FrameworkBinding;
use crate::error::PolicyExtError;

// ── ManagedPolicyId ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManagedPolicyId(pub String);

impl ManagedPolicyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ManagedPolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── PolicyDomain ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyDomain {
    AccessControl,
    DataProtection,
    NetworkSecurity,
    AiGovernance,
    Privacy,
    IncidentResponse,
    OperationalSecurity,
    Compliance,
    HumanResources,
    PhysicalSecurity,
    Custom(String),
}

impl fmt::Display for PolicyDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessControl => f.write_str("access-control"),
            Self::DataProtection => f.write_str("data-protection"),
            Self::NetworkSecurity => f.write_str("network-security"),
            Self::AiGovernance => f.write_str("ai-governance"),
            Self::Privacy => f.write_str("privacy"),
            Self::IncidentResponse => f.write_str("incident-response"),
            Self::OperationalSecurity => f.write_str("operational-security"),
            Self::Compliance => f.write_str("compliance"),
            Self::HumanResources => f.write_str("human-resources"),
            Self::PhysicalSecurity => f.write_str("physical-security"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── PolicyVersion ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl PolicyVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn initial() -> Self {
        Self { major: 0, minor: 1, patch: 0 }
    }

    pub fn bump_major(&self) -> Self {
        Self { major: self.major + 1, minor: 0, patch: 0 }
    }

    pub fn bump_minor(&self) -> Self {
        Self { major: self.major, minor: self.minor + 1, patch: 0 }
    }

    pub fn bump_patch(&self) -> Self {
        Self { major: self.major, minor: self.minor, patch: self.patch + 1 }
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ── PolicyStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyStatus {
    Draft,
    UnderReview,
    Approved,
    Active,
    Suspended,
    Deprecated,
    Retired,
}

impl PolicyStatus {
    pub fn is_enforceable(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_editable(&self) -> bool {
        matches!(self, Self::Draft | Self::UnderReview)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Retired)
    }
}

impl fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Draft => "Draft",
            Self::UnderReview => "UnderReview",
            Self::Approved => "Approved",
            Self::Active => "Active",
            Self::Suspended => "Suspended",
            Self::Deprecated => "Deprecated",
            Self::Retired => "Retired",
        };
        f.write_str(s)
    }
}

// ── RuleExpression ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleExpression {
    Always,
    Never,
    Equals { field: String, value: String },
    NotEquals { field: String, value: String },
    Contains { field: String, value: String },
    GreaterThan { field: String, value: f64 },
    LessThan { field: String, value: f64 },
    InList { field: String, values: Vec<String> },
    SeverityAtLeast(String),
    ClassificationAtLeast(String),
    And(Vec<RuleExpression>),
    Or(Vec<RuleExpression>),
    Not(Box<RuleExpression>),
}

// ── PolicyAction ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    RequireMfa,
    RequireApproval { approver: String },
    Encrypt,
    Audit,
    Alert { severity: String },
    Quarantine,
    RateLimit { max_per_minute: u64 },
    Escalate { to: String },
    Log { message: String },
    Custom(String),
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Deny => f.write_str("Deny"),
            Self::RequireMfa => f.write_str("RequireMfa"),
            Self::RequireApproval { approver } => write!(f, "RequireApproval({approver})"),
            Self::Encrypt => f.write_str("Encrypt"),
            Self::Audit => f.write_str("Audit"),
            Self::Alert { severity } => write!(f, "Alert({severity})"),
            Self::Quarantine => f.write_str("Quarantine"),
            Self::RateLimit { max_per_minute } => write!(f, "RateLimit({max_per_minute}/min)"),
            Self::Escalate { to } => write!(f, "Escalate({to})"),
            Self::Log { message } => write!(f, "Log({message})"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ── PolicyRule ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: RuleExpression,
    pub action: PolicyAction,
    pub priority: u32,
    pub enabled: bool,
    pub rationale: Option<String>,
}

impl PolicyRule {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        condition: RuleExpression,
        action: PolicyAction,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            condition,
            action,
            priority: 0,
            enabled: true,
            rationale: None,
        }
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ── ManagedPolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedPolicy {
    pub id: ManagedPolicyId,
    pub name: String,
    pub description: String,
    pub category: PolicyDomain,
    pub version: PolicyVersion,
    pub status: PolicyStatus,
    pub rules: Vec<PolicyRule>,
    pub owner: String,
    pub approver: Option<String>,
    pub framework_bindings: Vec<FrameworkBinding>,
    pub effective_from: Option<i64>,
    pub effective_until: Option<i64>,
    pub review_interval_days: Option<u64>,
    pub last_reviewed: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub tags: HashMap<String, String>,
    pub parent_id: Option<ManagedPolicyId>,
    pub metadata: HashMap<String, String>,
}

impl ManagedPolicy {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        domain: PolicyDomain,
        owner: impl Into<String>,
        now: i64,
    ) -> Self {
        Self {
            id: ManagedPolicyId::new(id),
            name: name.into(),
            description: String::new(),
            category: domain,
            version: PolicyVersion::initial(),
            status: PolicyStatus::Draft,
            rules: Vec::new(),
            owner: owner.into(),
            approver: None,
            framework_bindings: Vec::new(),
            effective_from: None,
            effective_until: None,
            review_interval_days: None,
            last_reviewed: None,
            created_at: now,
            updated_at: now,
            tags: HashMap::new(),
            parent_id: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn with_review_interval(mut self, days: u64) -> Self {
        self.review_interval_days = Some(days);
        self
    }
}

// ── ManagedPolicyStore ──────────────────────────────────────────────

pub struct ManagedPolicyStore {
    policies: HashMap<ManagedPolicyId, ManagedPolicy>,
}

impl ManagedPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    pub fn add(&mut self, policy: ManagedPolicy) -> Result<(), PolicyExtError> {
        if self.policies.contains_key(&policy.id) {
            return Err(PolicyExtError::PolicyAlreadyExists(policy.id.0.clone()));
        }
        self.policies.insert(policy.id.clone(), policy);
        Ok(())
    }

    pub fn get(&self, id: &ManagedPolicyId) -> Option<&ManagedPolicy> {
        self.policies.get(id)
    }

    pub fn get_mut(&mut self, id: &ManagedPolicyId) -> Option<&mut ManagedPolicy> {
        self.policies.get_mut(id)
    }

    pub fn by_domain(&self, domain: &PolicyDomain) -> Vec<&ManagedPolicy> {
        self.policies.values().filter(|p| p.category == *domain).collect()
    }

    pub fn by_status(&self, status: &PolicyStatus) -> Vec<&ManagedPolicy> {
        self.policies.values().filter(|p| p.status == *status).collect()
    }

    pub fn active_policies(&self) -> Vec<&ManagedPolicy> {
        self.by_status(&PolicyStatus::Active)
    }

    pub fn policies_due_review(&self, now: i64) -> Vec<&ManagedPolicy> {
        self.policies
            .values()
            .filter(|p| {
                if p.status != PolicyStatus::Active {
                    return false;
                }
                if let Some(interval) = p.review_interval_days {
                    let last = p.last_reviewed.unwrap_or(p.created_at);
                    let due = last + (interval as i64 * 86400);
                    now >= due
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn search(&self, query: &str) -> Vec<&ManagedPolicy> {
        let q = query.to_lowercase();
        self.policies
            .values()
            .filter(|p| {
                p.name.to_lowercase().contains(&q) || p.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.policies.len()
    }

    pub fn remove(&mut self, id: &ManagedPolicyId) -> Result<ManagedPolicy, PolicyExtError> {
        self.policies
            .remove(id)
            .ok_or_else(|| PolicyExtError::PolicyNotFound(id.0.clone()))
    }

    pub fn all(&self) -> impl Iterator<Item = &ManagedPolicy> {
        self.policies.values()
    }

    pub fn all_ids(&self) -> Vec<&ManagedPolicyId> {
        self.policies.keys().collect()
    }
}

impl Default for ManagedPolicyStore {
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

    fn sample_policy(id: &str) -> ManagedPolicy {
        ManagedPolicy::new(id, "Test Policy", PolicyDomain::AccessControl, "security-team", 1000)
            .with_description("A test policy for access control")
            .with_rule(PolicyRule::new("r1", "Deny untrusted", RuleExpression::Always, PolicyAction::Deny).with_priority(10))
    }

    #[test]
    fn test_managed_policy_id_display() {
        let id = ManagedPolicyId::new("pol-001");
        assert_eq!(id.to_string(), "pol-001");
    }

    #[test]
    fn test_managed_policy_construction() {
        let p = sample_policy("p1");
        assert_eq!(p.name, "Test Policy");
        assert_eq!(p.category, PolicyDomain::AccessControl);
        assert_eq!(p.version, PolicyVersion::initial());
        assert_eq!(p.status, PolicyStatus::Draft);
        assert_eq!(p.owner, "security-team");
        assert_eq!(p.rules.len(), 1);
    }

    #[test]
    fn test_policy_domain_display() {
        assert_eq!(PolicyDomain::AccessControl.to_string(), "access-control");
        assert_eq!(PolicyDomain::DataProtection.to_string(), "data-protection");
        assert_eq!(PolicyDomain::NetworkSecurity.to_string(), "network-security");
        assert_eq!(PolicyDomain::AiGovernance.to_string(), "ai-governance");
        assert_eq!(PolicyDomain::Privacy.to_string(), "privacy");
        assert_eq!(PolicyDomain::IncidentResponse.to_string(), "incident-response");
        assert_eq!(PolicyDomain::OperationalSecurity.to_string(), "operational-security");
        assert_eq!(PolicyDomain::Compliance.to_string(), "compliance");
        assert_eq!(PolicyDomain::HumanResources.to_string(), "human-resources");
        assert_eq!(PolicyDomain::PhysicalSecurity.to_string(), "physical-security");
        assert_eq!(PolicyDomain::Custom("test".into()).to_string(), "custom:test");
    }

    #[test]
    fn test_policy_version_display_ordering_bumps() {
        let v = PolicyVersion::initial();
        assert_eq!(v.to_string(), "0.1.0");
        assert!(PolicyVersion::new(1, 0, 0) > PolicyVersion::new(0, 9, 9));
        let v2 = v.bump_patch();
        assert_eq!(v2.to_string(), "0.1.1");
        let v3 = v.bump_minor();
        assert_eq!(v3.to_string(), "0.2.0");
        let v4 = v.bump_major();
        assert_eq!(v4.to_string(), "1.0.0");
    }

    #[test]
    fn test_policy_status_predicates() {
        assert!(PolicyStatus::Active.is_enforceable());
        assert!(!PolicyStatus::Draft.is_enforceable());
        assert!(!PolicyStatus::Retired.is_enforceable());

        assert!(PolicyStatus::Draft.is_editable());
        assert!(PolicyStatus::UnderReview.is_editable());
        assert!(!PolicyStatus::Active.is_editable());

        assert!(PolicyStatus::Retired.is_terminal());
        assert!(!PolicyStatus::Active.is_terminal());
    }

    #[test]
    fn test_policy_action_display() {
        assert_eq!(PolicyAction::Allow.to_string(), "Allow");
        assert_eq!(PolicyAction::Deny.to_string(), "Deny");
        assert_eq!(PolicyAction::RequireMfa.to_string(), "RequireMfa");
        assert_eq!(PolicyAction::Encrypt.to_string(), "Encrypt");
        assert_eq!(PolicyAction::Audit.to_string(), "Audit");
        assert_eq!(PolicyAction::Quarantine.to_string(), "Quarantine");
        assert_eq!(PolicyAction::Escalate { to: "mgr".into() }.to_string(), "Escalate(mgr)");
        assert_eq!(PolicyAction::Log { message: "ok".into() }.to_string(), "Log(ok)");
        assert_eq!(PolicyAction::Custom("x".into()).to_string(), "Custom(x)");
    }

    #[test]
    fn test_store_add_and_get() {
        let mut store = ManagedPolicyStore::new();
        store.add(sample_policy("p1")).unwrap();
        assert!(store.get(&ManagedPolicyId::new("p1")).is_some());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_store_duplicate_fails() {
        let mut store = ManagedPolicyStore::new();
        store.add(sample_policy("p1")).unwrap();
        let result = store.add(sample_policy("p1"));
        assert!(matches!(result, Err(PolicyExtError::PolicyAlreadyExists(_))));
    }

    #[test]
    fn test_store_by_domain() {
        let mut store = ManagedPolicyStore::new();
        store.add(sample_policy("p1")).unwrap();
        store
            .add(ManagedPolicy::new("p2", "Network", PolicyDomain::NetworkSecurity, "team", 1000))
            .unwrap();
        assert_eq!(store.by_domain(&PolicyDomain::AccessControl).len(), 1);
        assert_eq!(store.by_domain(&PolicyDomain::NetworkSecurity).len(), 1);
    }

    #[test]
    fn test_store_by_status_and_active() {
        let mut store = ManagedPolicyStore::new();
        let mut p = sample_policy("p1");
        p.status = PolicyStatus::Active;
        store.add(p).unwrap();
        store.add(sample_policy("p2")).unwrap(); // Draft
        assert_eq!(store.active_policies().len(), 1);
        assert_eq!(store.by_status(&PolicyStatus::Draft).len(), 1);
    }

    #[test]
    fn test_store_search() {
        let mut store = ManagedPolicyStore::new();
        store.add(sample_policy("p1")).unwrap();
        store
            .add(
                ManagedPolicy::new("p2", "Network Firewall", PolicyDomain::NetworkSecurity, "team", 1000)
                    .with_description("Firewall rules for perimeter"),
            )
            .unwrap();
        assert_eq!(store.search("access").len(), 1);
        assert_eq!(store.search("firewall").len(), 1);
        assert_eq!(store.search("FIREWALL").len(), 1); // case insensitive
    }

    #[test]
    fn test_store_policies_due_review() {
        let mut store = ManagedPolicyStore::new();
        let mut p = sample_policy("p1");
        p.status = PolicyStatus::Active;
        p.review_interval_days = Some(30);
        p.last_reviewed = Some(1000);
        store.add(p).unwrap();
        // 30 days = 2_592_000 seconds from last review at 1000
        assert_eq!(store.policies_due_review(2_600_000).len(), 1);
        assert_eq!(store.policies_due_review(1500).len(), 0);
    }

    #[test]
    fn test_store_remove() {
        let mut store = ManagedPolicyStore::new();
        store.add(sample_policy("p1")).unwrap();
        let removed = store.remove(&ManagedPolicyId::new("p1")).unwrap();
        assert_eq!(removed.id, ManagedPolicyId::new("p1"));
        assert_eq!(store.count(), 0);
    }
}
