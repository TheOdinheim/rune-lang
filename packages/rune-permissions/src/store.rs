// ═══════════════════════════════════════════════════════════════════════
// Permission Store
//
// Unified in-memory store composing RoleHierarchy, RbacEngine, and
// GrantStore. Provides a single entry point for all permission
// operations with audit logging.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::context::EvalContext;
use crate::decision::{AccessDecision, DetailedAccessDecision};
use crate::error::PermissionError;
use crate::grant::{Grant, GrantStore};
use crate::rbac::{AccessRequest, RbacEngine};
use crate::role::{Role, RoleId};
use crate::types::{Action, Permission, Subject, SubjectId, SubjectType};

// ── PermissionEvent ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermissionEventType {
    RoleAssigned,
    RoleRevoked,
    GrantCreated,
    GrantRevoked,
    AccessChecked,
    PermissionRegistered,
    SubjectRegistered,
    SubjectDeactivated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEvent {
    pub event_type: PermissionEventType,
    pub subject_id: SubjectId,
    pub detail: String,
    pub timestamp: i64,
    pub decision: Option<AccessDecision>,
}

// ── PermissionStore ────────────────────────────────────────────────

pub struct PermissionStore {
    engine: RbacEngine,
    grants: GrantStore,
    subjects: HashMap<SubjectId, Subject>,
    audit_log: Vec<PermissionEvent>,
}

impl PermissionStore {
    pub fn new() -> Self {
        Self {
            engine: RbacEngine::new(),
            grants: GrantStore::new(),
            subjects: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

    // ── Subject management ─────────────────────────────────────

    pub fn register_subject(&mut self, subject: Subject) -> Result<(), PermissionError> {
        if self.subjects.contains_key(&subject.id) {
            return Err(PermissionError::SubjectAlreadyExists(subject.id.clone()));
        }
        let id = subject.id.clone();
        self.subjects.insert(id.clone(), subject);
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::SubjectRegistered,
            subject_id: id,
            detail: "subject registered".into(),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn deactivate_subject(&mut self, id: &SubjectId) -> Result<(), PermissionError> {
        let subject = self.subjects.get_mut(id)
            .ok_or_else(|| PermissionError::SubjectNotFound(id.clone()))?;
        subject.active = false;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::SubjectDeactivated,
            subject_id: id.clone(),
            detail: "subject deactivated".into(),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn get_subject(&self, id: &SubjectId) -> Option<&Subject> {
        self.subjects.get(id)
    }

    pub fn list_subjects(&self) -> Vec<&Subject> {
        self.subjects.values().collect()
    }

    pub fn subjects_by_type(&self, subject_type: SubjectType) -> Vec<&Subject> {
        self.subjects.values().filter(|s| s.subject_type == subject_type).collect()
    }

    // ── Delegated operations ───────────────────────────────────

    pub fn add_role(&mut self, role: Role) -> Result<(), PermissionError> {
        self.engine.add_role(role)
    }

    pub fn register_permission(&mut self, permission: Permission) -> Result<(), PermissionError> {
        let id = permission.id.clone();
        self.engine.register_permission(permission)?;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::PermissionRegistered,
            subject_id: SubjectId::new("system"),
            detail: format!("permission {} registered", id),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn assign_role(
        &mut self,
        subject_id: SubjectId,
        role_id: RoleId,
        assigned_by: SubjectId,
        reason: String,
    ) -> Result<(), PermissionError> {
        let sid = subject_id.clone();
        let rid = role_id.clone();
        self.engine.assign_role(subject_id, role_id, assigned_by, reason)?;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::RoleAssigned,
            subject_id: sid,
            detail: format!("role {} assigned", rid),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn revoke_role(
        &mut self,
        subject_id: &SubjectId,
        role_id: &RoleId,
        revoked_by: &SubjectId,
        reason: &str,
    ) -> Result<(), PermissionError> {
        self.engine.revoke_role(subject_id, role_id, revoked_by, reason)?;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::RoleRevoked,
            subject_id: subject_id.clone(),
            detail: format!("role {} revoked: {}", role_id, reason),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    pub fn add_grant(&mut self, grant: Grant) -> Result<(), PermissionError> {
        let sid = grant.subject_id.clone();
        let pid = grant.permission_id.clone();
        self.grants.add_grant(grant)?;
        self.audit_log.push(PermissionEvent {
            event_type: PermissionEventType::GrantCreated,
            subject_id: sid,
            detail: format!("grant for {} created", pid),
            timestamp: 0,
            decision: None,
        });
        Ok(())
    }

    // ── Unified access check ───────────────────────────────────

    /// Check both role-based permissions AND direct grants.
    pub fn check(&self, request: &AccessRequest) -> AccessDecision {
        // Try role-based first.
        let rbac_decision = self.engine.check_access(request);
        if rbac_decision.is_allowed() {
            return rbac_decision;
        }

        // Try direct grants.
        let matching_perms = self.engine.permissions_for_resource(&request.resource);
        for perm in matching_perms {
            if perm.matches_action(&request.action)
                && self.grants.is_granted(
                    &request.subject_id,
                    &perm.id,
                    &request.context,
                )
            {
                return AccessDecision::Allow {
                    permission_id: perm.id.clone(),
                    matched_role: None,
                    reason: "direct grant".into(),
                };
            }
        }

        rbac_decision
    }

    pub fn check_verbose(&self, request: &AccessRequest) -> DetailedAccessDecision {
        let start = std::time::Instant::now();
        let decision = self.check(request);

        DetailedAccessDecision {
            decision,
            evaluation_trace: vec![],
            duration_us: start.elapsed().as_micros() as u64,
            evaluated_at: request.context.timestamp,
        }
    }

    pub fn can(&self, subject: &SubjectId, action: Action, resource: &str) -> bool {
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
        self.check(&request).is_allowed()
    }

    // ── Audit log ──────────────────────────────────────────────

    pub fn audit_log(&self) -> &[PermissionEvent] {
        &self.audit_log
    }

    pub fn audit_log_since(&self, timestamp: i64) -> Vec<&PermissionEvent> {
        self.audit_log
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }
}

impl Default for PermissionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::GrantId;
    use crate::role::Role;
    use crate::types::*;

    fn setup_store() -> PermissionStore {
        let mut store = PermissionStore::new();

        // Register roles.
        store.add_role(Role::viewer()).unwrap();
        store.add_role(Role::operator()).unwrap();
        store.add_role(Role::system_admin()).unwrap();
        store.add_role(Role::security_officer()).unwrap();

        // Register permissions.
        store.register_permission(Permission::new(
            "system:read", ResourcePattern::All, vec![Action::Read],
        )).unwrap();
        store.register_permission(Permission::new(
            "system:execute", ResourcePattern::All, vec![Action::Execute],
        )).unwrap();
        store.register_permission(Permission::new(
            "system:admin", ResourcePattern::All, vec![Action::Admin],
        ).classification(ClassificationLevel::TopSecret)).unwrap();
        store.register_permission(Permission::new(
            "audit:read", ResourcePattern::Prefix("audit/".into()),
            vec![Action::Read, Action::Audit],
        )).unwrap();

        // Register subjects.
        store.register_subject(
            Subject::new("alice", SubjectType::User, "Alice")
                .clearance(ClassificationLevel::Confidential),
        ).unwrap();
        store.register_subject(
            Subject::new("admin", SubjectType::User, "Admin")
                .clearance(ClassificationLevel::TopSecret),
        ).unwrap();

        store
    }

    #[test]
    fn test_store_new() {
        let store = PermissionStore::new();
        assert!(store.list_subjects().is_empty());
    }

    #[test]
    fn test_register_and_get_subject() {
        let mut store = PermissionStore::new();
        store.register_subject(
            Subject::new("u1", SubjectType::User, "User 1"),
        ).unwrap();
        assert!(store.get_subject(&SubjectId::new("u1")).is_some());
    }

    #[test]
    fn test_full_workflow_allow() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "onboarding".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("alice", SubjectType::User, "Alice")
                .clearance(ClassificationLevel::Confidential),
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("alice"),
            action: Action::Read,
            resource: "docs/readme".into(),
            context: ctx,
            justification: None,
        };
        assert!(store.check(&req).is_allowed());
    }

    #[test]
    fn test_full_workflow_deny() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("alice", SubjectType::User, "Alice"),
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("alice"),
            action: Action::Delete, // viewer can't delete
            resource: "docs/readme".into(),
            context: ctx,
            justification: None,
        };
        assert!(store.check(&req).is_denied());
    }

    #[test]
    fn test_direct_grant_overrides_role_denial() {
        let mut store = setup_store();
        // Alice has viewer role (read-only).
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        // But also has a direct grant for execute.
        store.register_permission(Permission::new(
            "special:execute", ResourcePattern::Exact("task-x".into()),
            vec![Action::Execute],
        )).unwrap();
        store.add_grant(Grant::new(
            "grant-1",
            SubjectId::new("alice"),
            PermissionId::new("special:execute"),
            SubjectId::new("admin"),
            "one-time access",
        )).unwrap();

        let ctx = EvalContext::for_subject(
            Subject::new("alice", SubjectType::User, "Alice"),
        ).build();
        let req = AccessRequest {
            subject_id: SubjectId::new("alice"),
            action: Action::Execute,
            resource: "task-x".into(),
            context: ctx,
            justification: None,
        };
        let decision = store.check(&req);
        assert!(decision.is_allowed());
        assert_eq!(decision.reason(), "direct grant");
    }

    #[test]
    fn test_audit_log_records_events() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();

        // Audit log should have: subject registrations, permission registrations, role assignment.
        assert!(!store.audit_log().is_empty());
        let role_events: Vec<_> = store.audit_log().iter()
            .filter(|e| matches!(e.event_type, PermissionEventType::RoleAssigned))
            .collect();
        assert_eq!(role_events.len(), 1);
    }

    #[test]
    fn test_audit_log_since() {
        let store = setup_store();
        // All events have timestamp 0, so since(1) returns none.
        assert!(store.audit_log_since(1).is_empty());
        // since(0) returns all.
        assert!(!store.audit_log_since(0).is_empty());
    }

    #[test]
    fn test_separation_of_duties() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("system-admin"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        let result = store.assign_role(
            SubjectId::new("alice"), RoleId::new("security-officer"),
            SubjectId::new("admin"), "r".into(),
        );
        assert!(matches!(result, Err(PermissionError::MutualExclusionViolation { .. })));
    }

    #[test]
    fn test_max_holders() {
        let mut store = setup_store();
        for i in 0..3 {
            store.assign_role(
                SubjectId::new(format!("admin{i}")), RoleId::new("system-admin"),
                SubjectId::new("root"), "r".into(),
            ).unwrap();
        }
        let result = store.assign_role(
            SubjectId::new("admin3"), RoleId::new("system-admin"),
            SubjectId::new("root"), "r".into(),
        );
        assert!(matches!(result, Err(PermissionError::MaxHoldersExceeded { .. })));
    }

    #[test]
    fn test_subjects_by_type() {
        let store = setup_store();
        let users = store.subjects_by_type(SubjectType::User);
        assert_eq!(users.len(), 2);
        let services = store.subjects_by_type(SubjectType::Service);
        assert!(services.is_empty());
    }

    #[test]
    fn test_deactivate_subject() {
        let mut store = setup_store();
        store.deactivate_subject(&SubjectId::new("alice")).unwrap();
        let subject = store.get_subject(&SubjectId::new("alice")).unwrap();
        assert!(!subject.active);
    }

    #[test]
    fn test_can_convenience() {
        let mut store = setup_store();
        store.assign_role(
            SubjectId::new("alice"), RoleId::new("viewer"),
            SubjectId::new("admin"), "r".into(),
        ).unwrap();
        assert!(store.can(&SubjectId::new("alice"), Action::Read, "x"));
        assert!(!store.can(&SubjectId::new("alice"), Action::Delete, "x"));
    }
}
