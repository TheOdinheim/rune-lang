// ═══════════════════════════════════════════════════════════════════════
// Authorization Decision Engine — Pluggable policy evaluation trait.
//
// Layer 3 defines the contract that Layer 5 formal verification will
// target. The four-outcome decision model (Permit/Deny/Indeterminate/
// NotApplicable) matches XACML's decision vocabulary and provides a
// clean formal reasoning surface.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::{IdentityRef, RoleRef};
use crate::error::PermissionError;

// ── EngineType ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineType {
    Rbac,
    Abac,
    Rebac,
    Hybrid,
}

impl std::fmt::Display for EngineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rbac => write!(f, "RBAC"),
            Self::Abac => write!(f, "ABAC"),
            Self::Rebac => write!(f, "ReBAC"),
            Self::Hybrid => write!(f, "Hybrid"),
        }
    }
}

// ── AuthorizationRequest ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub subject: IdentityRef,
    pub action: String,
    pub resource: String,
    pub context: HashMap<String, String>,
}

impl AuthorizationRequest {
    pub fn new(subject: IdentityRef, action: &str, resource: &str) -> Self {
        Self {
            subject,
            action: action.to_string(),
            resource: resource.to_string(),
            context: HashMap::new(),
        }
    }

    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

// ── AuthorizationDecision ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Permit {
        matched_policies: Vec<String>,
        obligations: Vec<String>,
    },
    Deny {
        reason: String,
        matched_policies: Vec<String>,
    },
    Indeterminate {
        reason: String,
    },
    NotApplicable,
}

impl AuthorizationDecision {
    pub fn is_permit(&self) -> bool {
        matches!(self, Self::Permit { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

impl std::fmt::Display for AuthorizationDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permit { matched_policies, .. } => {
                write!(f, "PERMIT (policies: {})", matched_policies.join(", "))
            }
            Self::Deny { reason, .. } => write!(f, "DENY: {reason}"),
            Self::Indeterminate { reason } => write!(f, "INDETERMINATE: {reason}"),
            Self::NotApplicable => write!(f, "NOT_APPLICABLE"),
        }
    }
}

// ── AuthorizationDecisionEngine trait ────────────────────────

pub trait AuthorizationDecisionEngine {
    fn decide(&self, request: &AuthorizationRequest) -> Result<AuthorizationDecision, PermissionError>;
    fn engine_id(&self) -> &str;
    fn engine_type(&self) -> EngineType;
    fn supported_policy_types(&self) -> Vec<String>;
    fn is_active(&self) -> bool;
}

// ── RbacDecisionEngine ───────────────────────────────────────

pub struct RbacDecisionEngine {
    id: String,
    active: bool,
    role_permissions: HashMap<String, Vec<String>>,
    identity_roles: HashMap<String, Vec<String>>,
}

impl RbacDecisionEngine {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            active: true,
            role_permissions: HashMap::new(),
            identity_roles: HashMap::new(),
        }
    }

    pub fn add_role_permission(&mut self, role: &str, permission: &str) {
        self.role_permissions
            .entry(role.to_string())
            .or_default()
            .push(permission.to_string());
    }

    pub fn assign_role(&mut self, identity: &str, role: &str) {
        self.identity_roles
            .entry(identity.to_string())
            .or_default()
            .push(role.to_string());
    }
}

impl AuthorizationDecisionEngine for RbacDecisionEngine {
    fn decide(&self, request: &AuthorizationRequest) -> Result<AuthorizationDecision, PermissionError> {
        let roles = match self.identity_roles.get(request.subject.as_str()) {
            Some(r) => r,
            None => return Ok(AuthorizationDecision::NotApplicable),
        };

        let action_resource = format!("{}:{}", request.action, request.resource);
        let mut matched = Vec::new();

        for role in roles {
            if let Some(perms) = self.role_permissions.get(role) {
                for perm in perms {
                    if *perm == action_resource || *perm == format!("{}:*", request.action) || perm == "*" {
                        matched.push(format!("role:{role}"));
                    }
                }
            }
        }

        if matched.is_empty() {
            Ok(AuthorizationDecision::Deny {
                reason: "no role grants the requested permission".to_string(),
                matched_policies: Vec::new(),
            })
        } else {
            Ok(AuthorizationDecision::Permit {
                matched_policies: matched,
                obligations: Vec::new(),
            })
        }
    }

    fn engine_id(&self) -> &str {
        &self.id
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Rbac
    }

    fn supported_policy_types(&self) -> Vec<String> {
        vec!["rbac".to_string()]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── AbacDecisionEngine ───────────────────────────────────────

pub struct AbacDecisionEngine {
    id: String,
    active: bool,
    attribute_rules: Vec<AttributeRule>,
}

#[derive(Debug, Clone)]
pub struct AttributeRule {
    pub rule_id: String,
    pub required_attributes: HashMap<String, String>,
    pub permitted_action: String,
    pub permitted_resource: String,
}

impl AbacDecisionEngine {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            active: true,
            attribute_rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: AttributeRule) {
        self.attribute_rules.push(rule);
    }
}

impl AuthorizationDecisionEngine for AbacDecisionEngine {
    fn decide(&self, request: &AuthorizationRequest) -> Result<AuthorizationDecision, PermissionError> {
        let mut matched = Vec::new();

        for rule in &self.attribute_rules {
            if rule.permitted_action != request.action && rule.permitted_action != "*" {
                continue;
            }
            if rule.permitted_resource != request.resource && rule.permitted_resource != "*" {
                continue;
            }
            let attrs_match = rule.required_attributes.iter().all(|(k, v)| {
                request.context.get(k).is_some_and(|cv| cv == v)
            });
            if attrs_match {
                matched.push(format!("rule:{}", rule.rule_id));
            }
        }

        if matched.is_empty() {
            Ok(AuthorizationDecision::Deny {
                reason: "no attribute rule matched".to_string(),
                matched_policies: Vec::new(),
            })
        } else {
            Ok(AuthorizationDecision::Permit {
                matched_policies: matched,
                obligations: Vec::new(),
            })
        }
    }

    fn engine_id(&self) -> &str {
        &self.id
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Abac
    }

    fn supported_policy_types(&self) -> Vec<String> {
        vec!["abac".to_string()]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── DenyAllDecisionEngine ────────────────────────────────────

pub struct DenyAllDecisionEngine {
    id: String,
}

impl DenyAllDecisionEngine {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl AuthorizationDecisionEngine for DenyAllDecisionEngine {
    fn decide(&self, _request: &AuthorizationRequest) -> Result<AuthorizationDecision, PermissionError> {
        Ok(AuthorizationDecision::Deny {
            reason: "default deny policy".to_string(),
            matched_policies: vec!["deny-all".to_string()],
        })
    }

    fn engine_id(&self) -> &str {
        &self.id
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Rbac
    }

    fn supported_policy_types(&self) -> Vec<String> {
        vec!["deny-all".to_string()]
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── AllowAllDecisionEngine ───────────────────────────────────
//
// WARNING: This engine unconditionally permits all requests.
// It exists ONLY for integration testing. It MUST NEVER be used
// in production deployments.

pub struct AllowAllDecisionEngine {
    id: String,
}

impl AllowAllDecisionEngine {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl AuthorizationDecisionEngine for AllowAllDecisionEngine {
    fn decide(&self, _request: &AuthorizationRequest) -> Result<AuthorizationDecision, PermissionError> {
        Ok(AuthorizationDecision::Permit {
            matched_policies: vec!["allow-all".to_string()],
            obligations: vec!["TESTING_ONLY".to_string()],
        })
    }

    fn engine_id(&self) -> &str {
        &self.id
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Rbac
    }

    fn supported_policy_types(&self) -> Vec<String> {
        vec!["allow-all".to_string()]
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbac_engine_permit() {
        let mut engine = RbacDecisionEngine::new("rbac-1");
        engine.add_role_permission("viewer", "read:docs");
        engine.assign_role("alice", "viewer");

        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "docs");
        let decision = engine.decide(&req).unwrap();
        assert!(decision.is_permit());
    }

    #[test]
    fn test_rbac_engine_deny_no_role() {
        let engine = RbacDecisionEngine::new("rbac-1");
        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "docs");
        let decision = engine.decide(&req).unwrap();
        assert!(matches!(decision, AuthorizationDecision::NotApplicable));
    }

    #[test]
    fn test_rbac_engine_deny_no_permission() {
        let mut engine = RbacDecisionEngine::new("rbac-1");
        engine.assign_role("alice", "viewer");
        engine.add_role_permission("viewer", "read:docs");

        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "write", "docs");
        let decision = engine.decide(&req).unwrap();
        assert!(decision.is_deny());
    }

    #[test]
    fn test_abac_engine_permit() {
        let mut engine = AbacDecisionEngine::new("abac-1");
        let mut attrs = HashMap::new();
        attrs.insert("department".to_string(), "engineering".to_string());
        engine.add_rule(AttributeRule {
            rule_id: "r1".to_string(),
            required_attributes: attrs,
            permitted_action: "read".to_string(),
            permitted_resource: "code".to_string(),
        });

        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "code")
            .with_context("department", "engineering");
        let decision = engine.decide(&req).unwrap();
        assert!(decision.is_permit());
    }

    #[test]
    fn test_abac_engine_deny_missing_attr() {
        let mut engine = AbacDecisionEngine::new("abac-1");
        let mut attrs = HashMap::new();
        attrs.insert("department".to_string(), "engineering".to_string());
        engine.add_rule(AttributeRule {
            rule_id: "r1".to_string(),
            required_attributes: attrs,
            permitted_action: "read".to_string(),
            permitted_resource: "code".to_string(),
        });

        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "code");
        let decision = engine.decide(&req).unwrap();
        assert!(decision.is_deny());
    }

    #[test]
    fn test_deny_all_engine() {
        let engine = DenyAllDecisionEngine::new("deny");
        let req = AuthorizationRequest::new(IdentityRef::new("anyone"), "any", "any");
        let decision = engine.decide(&req).unwrap();
        assert!(decision.is_deny());
        assert_eq!(engine.engine_id(), "deny");
    }

    #[test]
    fn test_allow_all_engine() {
        let engine = AllowAllDecisionEngine::new("allow");
        let req = AuthorizationRequest::new(IdentityRef::new("anyone"), "any", "any");
        let decision = engine.decide(&req).unwrap();
        assert!(decision.is_permit());
        if let AuthorizationDecision::Permit { obligations, .. } = &decision {
            assert!(obligations.contains(&"TESTING_ONLY".to_string()));
        }
    }

    #[test]
    fn test_engine_types() {
        assert_eq!(EngineType::Rbac.to_string(), "RBAC");
        assert_eq!(EngineType::Abac.to_string(), "ABAC");
        assert_eq!(EngineType::Rebac.to_string(), "ReBAC");
        assert_eq!(EngineType::Hybrid.to_string(), "Hybrid");
    }

    #[test]
    fn test_authorization_decision_display() {
        let permit = AuthorizationDecision::Permit {
            matched_policies: vec!["p1".into()],
            obligations: vec![],
        };
        assert!(permit.to_string().contains("PERMIT"));

        let deny = AuthorizationDecision::Deny {
            reason: "no access".into(),
            matched_policies: vec![],
        };
        assert!(deny.to_string().contains("DENY"));

        let indet = AuthorizationDecision::Indeterminate { reason: "error".into() };
        assert!(indet.to_string().contains("INDETERMINATE"));

        assert!(AuthorizationDecision::NotApplicable.to_string().contains("NOT_APPLICABLE"));
    }

    #[test]
    fn test_request_with_context() {
        let req = AuthorizationRequest::new(IdentityRef::new("alice"), "read", "docs")
            .with_context("env", "production")
            .with_context("time", "business_hours");
        assert_eq!(req.context.len(), 2);
        assert_eq!(req.context["env"], "production");
    }

    #[test]
    fn test_supported_policy_types() {
        let rbac = RbacDecisionEngine::new("r");
        assert!(rbac.supported_policy_types().contains(&"rbac".to_string()));
        let abac = AbacDecisionEngine::new("a");
        assert!(abac.supported_policy_types().contains(&"abac".to_string()));
    }
}
