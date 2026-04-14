// ═══════════════════════════════════════════════════════════════════════
// RBAC Engine
//
// Core access control engine: evaluates whether a subject can perform
// an action on a resource by checking roles, permissions, conditions,
// and classification levels.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::context::EvalContext;
use crate::decision::{
    AccessDecision, DetailedAccessDecision, EvaluationStep, FailedCheck, NearestMiss,
};
use crate::error::PermissionError;
use crate::role::{Role, RoleAssignment, RoleHierarchy, RoleId};
use crate::types::{Action, Permission, PermissionId, SubjectId};

// ── AccessRequest ──────────────────────────────────────────────────

/// A request for access to a resource.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub subject_id: SubjectId,
    pub action: Action,
    pub resource: String,
    pub context: EvalContext,
    pub justification: Option<String>,
}

impl AccessRequest {
    pub fn new(subject_id: SubjectId, action: Action, resource: impl Into<String>) -> AccessRequestBuilder {
        AccessRequestBuilder {
            subject_id,
            action,
            resource: resource.into(),
            context: None,
            justification: None,
        }
    }
}

pub struct AccessRequestBuilder {
    subject_id: SubjectId,
    action: Action,
    resource: String,
    context: Option<EvalContext>,
    justification: Option<String>,
}

impl AccessRequestBuilder {
    pub fn context(mut self, ctx: EvalContext) -> Self {
        self.context = Some(ctx);
        self
    }

    pub fn justification(mut self, j: impl Into<String>) -> Self {
        self.justification = Some(j.into());
        self
    }

    pub fn build(self) -> AccessRequest {
        use crate::types::{Subject, SubjectType};
        let ctx = self.context.unwrap_or_else(|| {
            EvalContext::for_subject(
                Subject::new(self.subject_id.as_str(), SubjectType::User, "")
            ).build()
        });
        AccessRequest {
            subject_id: self.subject_id,
            action: self.action,
            resource: self.resource,
            context: ctx,
            justification: self.justification,
        }
    }
}

// ── RbacEngine ─────────────────────────────────────────────────────

pub struct RbacEngine {
    hierarchy: RoleHierarchy,
    assignments: Vec<RoleAssignment>,
    permissions: HashMap<PermissionId, Permission>,
}

impl RbacEngine {
    pub fn new() -> Self {
        Self {
            hierarchy: RoleHierarchy::new(),
            assignments: Vec::new(),
            permissions: HashMap::new(),
        }
    }

    pub fn with_hierarchy(hierarchy: RoleHierarchy) -> Self {
        Self {
            hierarchy,
            assignments: Vec::new(),
            permissions: HashMap::new(),
        }
    }

    // ── Permission management ──────────────────────────────────

    pub fn register_permission(&mut self, permission: Permission) -> Result<(), PermissionError> {
        if self.permissions.contains_key(&permission.id) {
            return Err(PermissionError::PermissionAlreadyExists(permission.id.clone()));
        }
        self.permissions.insert(permission.id.clone(), permission);
        Ok(())
    }

    pub fn unregister_permission(&mut self, id: &PermissionId) -> Result<Permission, PermissionError> {
        self.permissions.remove(id).ok_or_else(|| PermissionError::PermissionNotFound(id.clone()))
    }

    pub fn get_permission(&self, id: &PermissionId) -> Option<&Permission> {
        self.permissions.get(id)
    }

    pub fn list_permissions(&self) -> Vec<&Permission> {
        self.permissions.values().collect()
    }

    pub fn permissions_for_resource(&self, resource: &str) -> Vec<&Permission> {
        self.permissions
            .values()
            .filter(|p| p.matches_resource(resource))
            .collect()
    }

    // ── Role management ────────────────────────────────────────

    pub fn add_role(&mut self, role: Role) -> Result<(), PermissionError> {
        self.hierarchy.add_role(role)
    }

    pub fn remove_role(&mut self, id: &RoleId) -> Result<Role, PermissionError> {
        self.hierarchy.remove_role(id)
    }

    // ── Assignment management ──────────────────────────────────

    pub fn assign_role(
        &mut self,
        subject_id: SubjectId,
        role_id: RoleId,
        assigned_by: SubjectId,
        reason: String,
    ) -> Result<RoleAssignment, PermissionError> {
        // Role must exist.
        if !self.hierarchy.role_exists(&role_id) {
            return Err(PermissionError::RoleNotFound(role_id));
        }

        // Check mutual exclusion.
        let active = self.active_roles(&subject_id);
        for assignment in &active {
            if self.hierarchy.are_mutually_exclusive(&assignment.role_id, &role_id) {
                return Err(PermissionError::MutualExclusionViolation {
                    role_a: assignment.role_id.clone(),
                    role_b: role_id,
                    subject: subject_id,
                });
            }
        }

        // Check max holders.
        if let Some(role) = self.hierarchy.get_role(&role_id) {
            if let Some(max) = role.max_holders {
                let current = self.role_holder_count(&role_id);
                if current >= max {
                    return Err(PermissionError::MaxHoldersExceeded {
                        role: role_id,
                        max,
                        current,
                    });
                }
            }
        }

        let assignment = RoleAssignment {
            subject_id,
            role_id,
            assigned_by,
            assigned_at: 0,
            expires_at: None,
            reason,
            active: true,
        };
        self.assignments.push(assignment.clone());
        Ok(assignment)
    }

    pub fn revoke_role(
        &mut self,
        subject_id: &SubjectId,
        role_id: &RoleId,
        _revoked_by: &SubjectId,
        _reason: &str,
    ) -> Result<(), PermissionError> {
        let mut found = false;
        for assignment in &mut self.assignments {
            if assignment.subject_id == *subject_id
                && assignment.role_id == *role_id
                && assignment.active
            {
                assignment.active = false;
                found = true;
            }
        }
        if found {
            Ok(())
        } else {
            Err(PermissionError::InvalidOperation(
                format!("no active assignment of role {role_id} for subject {subject_id}"),
            ))
        }
    }

    pub fn active_roles(&self, subject_id: &SubjectId) -> Vec<&RoleAssignment> {
        self.assignments
            .iter()
            .filter(|a| a.subject_id == *subject_id && a.active)
            .collect()
    }

    pub fn subjects_with_role(&self, role_id: &RoleId) -> Vec<&SubjectId> {
        self.assignments
            .iter()
            .filter(|a| a.role_id == *role_id && a.active)
            .map(|a| &a.subject_id)
            .collect()
    }

    pub fn role_holder_count(&self, role_id: &RoleId) -> usize {
        self.subjects_with_role(role_id).len()
    }

    // ── Access decision evaluation ─────────────────────────────

    pub fn check_access(&self, request: &AccessRequest) -> AccessDecision {
        let active_assignments = self.active_roles(&request.subject_id);
        if active_assignments.is_empty() {
            return AccessDecision::Deny {
                reason: "no active roles assigned".into(),
                checked_roles: vec![],
                nearest_miss: None,
            };
        }

        let mut checked_roles = Vec::new();
        let mut nearest_miss: Option<NearestMiss> = None;

        for assignment in &active_assignments {
            checked_roles.push(assignment.role_id.clone());

            // Collect effective permissions for this role.
            let effective_perms = self.hierarchy.effective_permissions(&assignment.role_id);

            for perm_id in &effective_perms {
                let perm = match self.permissions.get(perm_id) {
                    Some(p) => p,
                    None => continue,
                };

                // Check resource match.
                if !perm.matches_resource(&request.resource) {
                    continue;
                }

                // Check action match.
                if !perm.matches_action(&request.action) {
                    continue;
                }

                // Check expiration.
                if perm.is_expired(request.context.timestamp) {
                    nearest_miss = Some(NearestMiss {
                        permission_id: perm_id.clone(),
                        failed_check: FailedCheck::PermissionExpired {
                            expired_at: perm.expires_at.unwrap_or(0),
                        },
                        suggestion: "renew the expired permission".into(),
                    });
                    continue;
                }

                // Check classification.
                if !request.context.subject.clearance.dominates(&perm.classification) {
                    nearest_miss = Some(NearestMiss {
                        permission_id: perm_id.clone(),
                        failed_check: FailedCheck::InsufficientClearance {
                            required: perm.classification,
                            actual: request.context.subject.clearance,
                        },
                        suggestion: format!(
                            "upgrade clearance to {} or higher",
                            perm.classification
                        ),
                    });
                    continue;
                }

                // Check conditions.
                let mut condition_failed = false;
                for cond in &perm.conditions {
                    if !cond.evaluate(&request.context) {
                        nearest_miss = Some(NearestMiss {
                            permission_id: perm_id.clone(),
                            failed_check: FailedCheck::ConditionNotMet {
                                condition: format!("{:?}", cond),
                            },
                            suggestion: format!("satisfy condition: {:?}", cond),
                        });
                        condition_failed = true;
                        break;
                    }
                }
                if condition_failed {
                    continue;
                }

                // All checks passed.
                return AccessDecision::Allow {
                    permission_id: perm_id.clone(),
                    matched_role: Some(assignment.role_id.clone()),
                    reason: "role-based permission granted".into(),
                };
            }
        }

        AccessDecision::Deny {
            reason: "no matching permission found".into(),
            checked_roles,
            nearest_miss,
        }
    }

    pub fn check_access_verbose(&self, request: &AccessRequest) -> DetailedAccessDecision {
        let start = std::time::Instant::now();
        let mut trace = Vec::new();

        let active_assignments = self.active_roles(&request.subject_id);
        trace.push(EvaluationStep {
            step_type: "role_lookup".into(),
            detail: format!("found {} active role(s)", active_assignments.len()),
            result: !active_assignments.is_empty(),
            timestamp: request.context.timestamp,
        });

        let decision = self.check_access(request);

        trace.push(EvaluationStep {
            step_type: "final_decision".into(),
            detail: format!("{}", &decision),
            result: decision.is_allowed(),
            timestamp: request.context.timestamp,
        });

        DetailedAccessDecision {
            decision,
            evaluation_trace: trace,
            duration_us: start.elapsed().as_micros() as u64,
            evaluated_at: request.context.timestamp,
        }
    }

    pub fn can(&self, subject: &SubjectId, action: Action, resource: &str) -> bool {
        use crate::types::{Subject, SubjectType};
        let ctx = EvalContext::for_subject(
            Subject::new(subject.as_str(), SubjectType::User, ""),
        ).build();
        let request = AccessRequest {
            subject_id: subject.clone(),
            action,
            resource: resource.to_string(),
            context: ctx,
            justification: None,
        };
        self.check_access(&request).is_allowed()
    }

    // ── Layer 2: Accessors for snapshot/restore ─────────────────

    pub fn all_assignments(&self) -> &[RoleAssignment] {
        &self.assignments
    }

    pub fn replace_assignments(&mut self, assignments: Vec<RoleAssignment>) {
        self.assignments = assignments;
    }

    pub fn hierarchy(&self) -> &RoleHierarchy {
        &self.hierarchy
    }

    pub fn hierarchy_mut(&mut self) -> &mut RoleHierarchy {
        &mut self.hierarchy
    }

    pub fn all_permissions(&self) -> &HashMap<PermissionId, Permission> {
        &self.permissions
    }

    pub fn replace_permissions(&mut self, permissions: HashMap<PermissionId, Permission>) {
        self.permissions = permissions;
    }

    pub fn effective_permissions_for_subject(&self, subject_id: &SubjectId) -> Vec<&Permission> {
        let mut perm_ids = std::collections::HashSet::new();
        for assignment in self.active_roles(subject_id) {
            for pid in self.hierarchy.effective_permissions(&assignment.role_id) {
                perm_ids.insert(pid);
            }
        }
        perm_ids
            .into_iter()
            .filter_map(|pid| self.permissions.get(&pid))
            .collect()
    }
}

impl Default for RbacEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::EvalContext;
    use crate::role::Role;
    use crate::types::*;

    fn setup_engine() -> RbacEngine {
        let mut engine = RbacEngine::new();
        engine.add_role(Role::viewer()).unwrap();
        engine.add_role(Role::operator()).unwrap();
        engine.add_role(Role::system_admin()).unwrap();
        engine.add_role(Role::security_officer()).unwrap();

        // Register permissions that roles reference.
        engine.register_permission(Permission::new(
            "system:read",
            ResourcePattern::All,
            vec![Action::Read],
        )).unwrap();
        engine.register_permission(Permission::new(
            "system:execute",
            ResourcePattern::All,
            vec![Action::Execute],
        )).unwrap();
        engine.register_permission(Permission::new(
            "system:admin",
            ResourcePattern::All,
            vec![Action::Admin],
        ).classification(ClassificationLevel::TopSecret)).unwrap();
        engine.register_permission(Permission::new(
            "audit:read",
            ResourcePattern::Prefix("audit/".into()),
            vec![Action::Read, Action::Audit],
        )).unwrap();
        engine
    }

    fn admin_subject() -> Subject {
        Subject::new("admin1", SubjectType::User, "Admin")
            .clearance(ClassificationLevel::TopSecret)
    }

    fn viewer_subject() -> Subject {
        Subject::new("viewer1", SubjectType::User, "Viewer")
            .clearance(ClassificationLevel::Public)
    }

    #[test]
    fn test_engine_new() {
        let engine = RbacEngine::new();
        assert!(engine.list_permissions().is_empty());
    }

    #[test]
    fn test_register_and_get_permission() {
        let mut engine = RbacEngine::new();
        let perm = Permission::new("file:read", ResourcePattern::All, vec![Action::Read]);
        engine.register_permission(perm).unwrap();
        assert!(engine.get_permission(&PermissionId::new("file:read")).is_some());
    }

    #[test]
    fn test_assign_role_and_active() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("user1"),
            RoleId::new("viewer"),
            SubjectId::new("admin"),
            "onboarding".into(),
        ).unwrap();
        assert_eq!(engine.active_roles(&SubjectId::new("user1")).len(), 1);
    }

    #[test]
    fn test_check_access_allow() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("viewer1"),
            RoleId::new("viewer"),
            SubjectId::new("admin"),
            "access".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(viewer_subject()).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("viewer1"),
            action: Action::Read,
            resource: "docs/readme.md".into(),
            context: ctx,
            justification: None,
        };
        let decision = engine.check_access(&req);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_check_access_deny_no_role() {
        let engine = setup_engine();
        let ctx = EvalContext::for_subject(viewer_subject()).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("nobody"),
            action: Action::Read,
            resource: "anything".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_denied());
    }

    #[test]
    fn test_check_access_deny_no_matching_action() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("viewer1"),
            RoleId::new("viewer"),
            SubjectId::new("admin"),
            "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(viewer_subject()).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("viewer1"),
            action: Action::Delete, // viewer can only Read
            resource: "docs/readme.md".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_denied());
    }

    #[test]
    fn test_check_access_deny_insufficient_clearance() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("viewer1"),
            RoleId::new("system-admin"),
            SubjectId::new("admin"),
            "r".into(),
        ).unwrap();

        // Viewer has Public clearance but system:admin requires TopSecret.
        let ctx = EvalContext::for_subject(viewer_subject()).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("viewer1"),
            action: Action::Admin,
            resource: "system".into(),
            context: ctx,
            justification: None,
        };
        let decision = engine.check_access(&req);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_check_access_clearance_sufficient() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("admin1"),
            RoleId::new("system-admin"),
            SubjectId::new("admin"),
            "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(admin_subject()).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("admin1"),
            action: Action::Admin,
            resource: "system".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_allowed());
    }

    #[test]
    fn test_check_access_expired_permission() {
        let mut engine = RbacEngine::new();
        engine.add_role(Role::new("temp", "Temp").permission("temp:read")).unwrap();
        engine.register_permission(
            Permission::new("temp:read", ResourcePattern::All, vec![Action::Read])
                .expires_at(100),
        ).unwrap();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("temp"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("u1", SubjectType::User, "U")
        ).timestamp(200).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("u1"),
            action: Action::Read,
            resource: "x".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_denied());
    }

    #[test]
    fn test_check_access_condition_failed() {
        let mut engine = RbacEngine::new();
        engine.add_role(Role::new("mfa", "MFA Role").permission("mfa:read")).unwrap();
        engine.register_permission(
            Permission::new("mfa:read", ResourcePattern::All, vec![Action::Read])
                .condition(Condition::RequiresMfa),
        ).unwrap();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("mfa"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();

        // Without MFA.
        let ctx = EvalContext::for_subject(
            Subject::new("u1", SubjectType::User, "U")
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("u1"),
            action: Action::Read,
            resource: "x".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_denied());
    }

    #[test]
    fn test_check_access_multiple_roles() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("viewer"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("operator"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("u1", SubjectType::User, "U")
                .clearance(ClassificationLevel::Confidential)
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("u1"),
            action: Action::Execute,
            resource: "task".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_allowed());
    }

    #[test]
    fn test_check_access_inherited_permission() {
        let mut engine = RbacEngine::new();
        engine.add_role(
            Role::new("base", "Base").permission("base:read"),
        ).unwrap();
        engine.add_role(
            Role::new("child", "Child").parent("base"),
        ).unwrap();
        engine.register_permission(Permission::new(
            "base:read", ResourcePattern::All, vec![Action::Read],
        )).unwrap();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("child"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("u1", SubjectType::User, "U")
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("u1"),
            action: Action::Read,
            resource: "x".into(),
            context: ctx,
            justification: None,
        };
        assert!(engine.check_access(&req).is_allowed());
    }

    #[test]
    fn test_can_convenience() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("v1"), RoleId::new("viewer"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();
        assert!(engine.can(&SubjectId::new("v1"), Action::Read, "anything"));
        assert!(!engine.can(&SubjectId::new("v1"), Action::Delete, "anything"));
    }

    #[test]
    fn test_effective_permissions_for_subject() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("viewer"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();
        let perms = engine.effective_permissions_for_subject(&SubjectId::new("u1"));
        assert!(!perms.is_empty());
    }

    #[test]
    fn test_check_access_verbose_has_trace() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("v1"), RoleId::new("viewer"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(viewer_subject()).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("v1"),
            action: Action::Read,
            resource: "x".into(),
            context: ctx,
            justification: None,
        };
        let detailed = engine.check_access_verbose(&req);
        assert!(!detailed.evaluation_trace.is_empty());
        assert!(detailed.decision.is_allowed());
    }

    #[test]
    fn test_mutual_exclusion_prevents_assignment() {
        let mut engine = setup_engine();
        engine.assign_role(
            SubjectId::new("u1"), RoleId::new("system-admin"),
            SubjectId::new("a"), "r".into(),
        ).unwrap();
        let result = engine.assign_role(
            SubjectId::new("u1"), RoleId::new("security-officer"),
            SubjectId::new("a"), "r".into(),
        );
        assert!(matches!(result, Err(PermissionError::MutualExclusionViolation { .. })));
    }

    #[test]
    fn test_max_holders_prevents_assignment() {
        let mut engine = setup_engine();
        // system_admin has max_holders = 3.
        for i in 0..3 {
            engine.assign_role(
                SubjectId::new(format!("admin{i}")),
                RoleId::new("system-admin"),
                SubjectId::new("root"), "r".into(),
            ).unwrap();
        }
        let result = engine.assign_role(
            SubjectId::new("admin3"), RoleId::new("system-admin"),
            SubjectId::new("root"), "r".into(),
        );
        assert!(matches!(result, Err(PermissionError::MaxHoldersExceeded { .. })));
    }
}
