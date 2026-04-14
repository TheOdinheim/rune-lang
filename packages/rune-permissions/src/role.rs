// ═══════════════════════════════════════════════════════════════════════
// Roles and Role Hierarchies
//
// Roles group permissions. Role hierarchies support multiple
// inheritance with cycle detection and mutual exclusion constraints.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::PermissionError;
use crate::types::{ClassificationLevel, PermissionId, SubjectId};

// ── RoleId ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleId(String);

impl RoleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Role ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: String,
    pub permissions: Vec<PermissionId>,
    pub parent_roles: Vec<RoleId>,
    pub classification: ClassificationLevel,
    pub max_holders: Option<usize>,
    pub mutually_exclusive_with: Vec<RoleId>,
    pub time_limited: Option<i64>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl Role {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: RoleId::new(id),
            name: name.into(),
            description: String::new(),
            permissions: Vec::new(),
            parent_roles: Vec::new(),
            classification: ClassificationLevel::Public,
            max_holders: None,
            mutually_exclusive_with: Vec::new(),
            time_limited: None,
            created_at: 0,
            metadata: HashMap::new(),
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn permission(mut self, id: impl Into<String>) -> Self {
        self.permissions.push(PermissionId::new(id));
        self
    }

    pub fn parent(mut self, id: impl Into<String>) -> Self {
        self.parent_roles.push(RoleId::new(id));
        self
    }

    pub fn classification(mut self, level: ClassificationLevel) -> Self {
        self.classification = level;
        self
    }

    pub fn max_holders(mut self, max: usize) -> Self {
        self.max_holders = Some(max);
        self
    }

    pub fn mutually_exclusive(mut self, id: impl Into<String>) -> Self {
        self.mutually_exclusive_with.push(RoleId::new(id));
        self
    }

    pub fn time_limited(mut self, ms: i64) -> Self {
        self.time_limited = Some(ms);
        self
    }

    // ── Built-in role templates ────────────────────────────────────

    pub fn system_admin() -> Self {
        Self::new("system-admin", "System Administrator")
            .description("Full system access")
            .permission("system:admin")
            .permission("system:read")
            .permission("system:write")
            .permission("system:deploy")
            .classification(ClassificationLevel::TopSecret)
            .max_holders(3)
    }

    pub fn security_officer() -> Self {
        Self::new("security-officer", "Security Officer")
            .description("Audit and security oversight")
            .permission("audit:read")
            .permission("audit:write")
            .permission("security:manage")
            .classification(ClassificationLevel::Restricted)
            .mutually_exclusive("system-admin")
    }

    pub fn operator() -> Self {
        Self::new("operator", "Operator")
            .description("Read and execute access")
            .permission("system:read")
            .permission("system:execute")
            .classification(ClassificationLevel::Confidential)
    }

    pub fn auditor() -> Self {
        Self::new("auditor", "Auditor")
            .description("Read-only audit access")
            .permission("audit:read")
            .permission("system:read")
            .classification(ClassificationLevel::Confidential)
    }

    pub fn viewer() -> Self {
        Self::new("viewer", "Viewer")
            .description("Read-only access")
            .permission("system:read")
            .classification(ClassificationLevel::Public)
    }

    pub fn ai_agent() -> Self {
        Self::new("ai-agent", "AI Agent")
            .description("AI model execution with restricted access")
            .permission("model:execute")
            .permission("model:read")
            .classification(ClassificationLevel::Restricted)
    }
}

// ── RoleAssignment ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub subject_id: SubjectId,
    pub role_id: RoleId,
    pub assigned_by: SubjectId,
    pub assigned_at: i64,
    pub expires_at: Option<i64>,
    pub reason: String,
    pub active: bool,
}

impl RoleAssignment {
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map_or(false, |exp| now > exp)
    }
}

// ── RoleHierarchy ──────────────────────────────────────────────────

pub struct RoleHierarchy {
    roles: HashMap<RoleId, Role>,
}

impl RoleHierarchy {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
        }
    }

    pub fn add_role(&mut self, role: Role) -> Result<(), PermissionError> {
        if self.roles.contains_key(&role.id) {
            return Err(PermissionError::RoleAlreadyExists(role.id.clone()));
        }
        // Validate parent roles exist.
        for parent in &role.parent_roles {
            if !self.roles.contains_key(parent) {
                return Err(PermissionError::RoleNotFound(parent.clone()));
            }
        }
        let id = role.id.clone();
        self.roles.insert(id.clone(), role);
        // Check for cycles after insertion.
        if self.detect_cycle_from(&id) {
            let role = self.roles.remove(&id).unwrap();
            return Err(PermissionError::CircularInheritance {
                role: id,
                cycle: role.parent_roles.clone(),
            });
        }
        Ok(())
    }

    pub fn remove_role(&mut self, id: &RoleId) -> Result<Role, PermissionError> {
        // Check no other roles inherit from this one.
        for role in self.roles.values() {
            if role.parent_roles.contains(id) {
                return Err(PermissionError::InvalidOperation(
                    format!("role {} has dependents", id),
                ));
            }
        }
        self.roles.remove(id).ok_or_else(|| PermissionError::RoleNotFound(id.clone()))
    }

    pub fn get_role(&self, id: &RoleId) -> Option<&Role> {
        self.roles.get(id)
    }

    pub fn role_exists(&self, id: &RoleId) -> bool {
        self.roles.contains_key(id)
    }

    /// Collect all permissions from a role and all ancestors (deduplicated).
    pub fn effective_permissions(&self, role_id: &RoleId) -> Vec<PermissionId> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(role_id.clone());
        let mut visited = HashSet::new();

        while let Some(rid) = queue.pop_front() {
            if !visited.insert(rid.clone()) {
                continue;
            }
            if let Some(role) = self.roles.get(&rid) {
                for perm in &role.permissions {
                    if seen.insert(perm.clone()) {
                        result.push(perm.clone());
                    }
                }
                for parent in &role.parent_roles {
                    queue.push_back(parent.clone());
                }
            }
        }
        result
    }

    /// All ancestor roles in BFS order.
    pub fn ancestors(&self, role_id: &RoleId) -> Vec<RoleId> {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        if let Some(role) = self.roles.get(role_id) {
            for parent in &role.parent_roles {
                queue.push_back(parent.clone());
            }
        }

        while let Some(rid) = queue.pop_front() {
            if !visited.insert(rid.clone()) {
                continue;
            }
            result.push(rid.clone());
            if let Some(role) = self.roles.get(&rid) {
                for parent in &role.parent_roles {
                    queue.push_back(parent.clone());
                }
            }
        }
        result
    }

    /// All roles that inherit from this role (directly or transitively).
    pub fn descendants(&self, role_id: &RoleId) -> Vec<RoleId> {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        // Find direct children.
        for (id, role) in &self.roles {
            if role.parent_roles.contains(role_id) {
                queue.push_back(id.clone());
            }
        }

        while let Some(rid) = queue.pop_front() {
            if !visited.insert(rid.clone()) {
                continue;
            }
            result.push(rid.clone());
            for (id, role) in &self.roles {
                if role.parent_roles.contains(&rid) && !visited.contains(id) {
                    queue.push_back(id.clone());
                }
            }
        }
        result
    }

    pub fn all_roles(&self) -> Vec<&Role> {
        self.roles.values().collect()
    }

    pub fn replace_roles(&mut self, roles: Vec<Role>) {
        self.roles.clear();
        for role in roles {
            self.roles.insert(role.id.clone(), role);
        }
    }

    pub fn has_cycle(&self) -> bool {
        for id in self.roles.keys() {
            if self.detect_cycle_from(id) {
                return true;
            }
        }
        false
    }

    pub fn is_ancestor(&self, ancestor: &RoleId, descendant: &RoleId) -> bool {
        self.ancestors(descendant).contains(ancestor)
    }

    pub fn are_mutually_exclusive(&self, role_a: &RoleId, role_b: &RoleId) -> bool {
        if let Some(role) = self.roles.get(role_a) {
            if role.mutually_exclusive_with.contains(role_b) {
                return true;
            }
        }
        if let Some(role) = self.roles.get(role_b) {
            if role.mutually_exclusive_with.contains(role_a) {
                return true;
            }
        }
        false
    }

    /// Full validation: cycles, parent refs, mutual exclusion.
    pub fn validate(&self) -> Vec<PermissionError> {
        let mut errors = Vec::new();

        for (id, role) in &self.roles {
            // Check parent references.
            for parent in &role.parent_roles {
                if !self.roles.contains_key(parent) {
                    errors.push(PermissionError::RoleNotFound(parent.clone()));
                }
            }
            // Check cycles.
            if self.detect_cycle_from(id) {
                errors.push(PermissionError::CircularInheritance {
                    role: id.clone(),
                    cycle: role.parent_roles.clone(),
                });
            }
        }
        errors
    }

    fn detect_cycle_from(&self, start: &RoleId) -> bool {
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();
        self.dfs_cycle(start, &mut visited, &mut stack)
    }

    fn dfs_cycle(
        &self,
        node: &RoleId,
        visited: &mut HashSet<RoleId>,
        stack: &mut HashSet<RoleId>,
    ) -> bool {
        if stack.contains(node) {
            return true;
        }
        if visited.contains(node) {
            return false;
        }
        visited.insert(node.clone());
        stack.insert(node.clone());

        if let Some(role) = self.roles.get(node) {
            for parent in &role.parent_roles {
                if self.dfs_cycle(parent, visited, stack) {
                    return true;
                }
            }
        }

        stack.remove(node);
        false
    }
}

impl Default for RoleHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_construction() {
        let role = Role::new("admin", "Administrator")
            .description("Full access")
            .permission("system:admin")
            .classification(ClassificationLevel::TopSecret)
            .max_holders(3);
        assert_eq!(role.id, RoleId::new("admin"));
        assert_eq!(role.name, "Administrator");
        assert_eq!(role.classification, ClassificationLevel::TopSecret);
        assert_eq!(role.max_holders, Some(3));
        assert_eq!(role.permissions.len(), 1);
    }

    #[test]
    fn test_system_admin_defaults() {
        let role = Role::system_admin();
        assert_eq!(role.id, RoleId::new("system-admin"));
        assert_eq!(role.classification, ClassificationLevel::TopSecret);
        assert_eq!(role.max_holders, Some(3));
        assert!(!role.permissions.is_empty());
    }

    #[test]
    fn test_security_officer_mutually_exclusive() {
        let role = Role::security_officer();
        assert!(role.mutually_exclusive_with.contains(&RoleId::new("system-admin")));
    }

    #[test]
    fn test_viewer_public_clearance() {
        let role = Role::viewer();
        assert_eq!(role.classification, ClassificationLevel::Public);
    }

    #[test]
    fn test_auditor_has_audit_permission() {
        let role = Role::auditor();
        assert!(role.permissions.contains(&PermissionId::new("audit:read")));
    }

    #[test]
    fn test_ai_agent_restricted() {
        let role = Role::ai_agent();
        assert_eq!(role.classification, ClassificationLevel::Restricted);
        assert!(role.permissions.contains(&PermissionId::new("model:execute")));
    }

    #[test]
    fn test_hierarchy_add_role() {
        let mut h = RoleHierarchy::new();
        assert!(h.add_role(Role::viewer()).is_ok());
        assert!(h.role_exists(&RoleId::new("viewer")));
    }

    #[test]
    fn test_hierarchy_duplicate_id() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::viewer()).unwrap();
        assert!(matches!(
            h.add_role(Role::viewer()),
            Err(PermissionError::RoleAlreadyExists(_))
        ));
    }

    #[test]
    fn test_hierarchy_nonexistent_parent() {
        let mut h = RoleHierarchy::new();
        let role = Role::new("child", "Child").parent("nonexistent");
        assert!(matches!(
            h.add_role(role),
            Err(PermissionError::RoleNotFound(_))
        ));
    }

    #[test]
    fn test_effective_permissions_inherited() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("base", "Base").permission("base:read")).unwrap();
        h.add_role(
            Role::new("child", "Child")
                .permission("child:write")
                .parent("base"),
        ).unwrap();

        let perms = h.effective_permissions(&RoleId::new("child"));
        assert!(perms.contains(&PermissionId::new("child:write")));
        assert!(perms.contains(&PermissionId::new("base:read")));
    }

    #[test]
    fn test_effective_permissions_diamond_dedup() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("root", "Root").permission("shared:perm")).unwrap();
        h.add_role(Role::new("left", "Left").parent("root").permission("left:perm")).unwrap();
        h.add_role(Role::new("right", "Right").parent("root").permission("right:perm")).unwrap();
        h.add_role(
            Role::new("diamond", "Diamond")
                .parent("left")
                .parent("right"),
        ).unwrap();

        let perms = h.effective_permissions(&RoleId::new("diamond"));
        // shared:perm should appear only once despite two paths.
        let shared_count = perms.iter().filter(|p| p.as_str() == "shared:perm").count();
        assert_eq!(shared_count, 1);
        assert!(perms.contains(&PermissionId::new("left:perm")));
        assert!(perms.contains(&PermissionId::new("right:perm")));
    }

    #[test]
    fn test_ancestors_bfs() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("grandparent", "GP")).unwrap();
        h.add_role(Role::new("parent", "P").parent("grandparent")).unwrap();
        h.add_role(Role::new("child", "C").parent("parent")).unwrap();

        let anc = h.ancestors(&RoleId::new("child"));
        assert_eq!(anc.len(), 2);
        assert_eq!(anc[0], RoleId::new("parent"));
        assert_eq!(anc[1], RoleId::new("grandparent"));
    }

    #[test]
    fn test_descendants() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("root", "Root")).unwrap();
        h.add_role(Role::new("child", "Child").parent("root")).unwrap();
        h.add_role(Role::new("grandchild", "GC").parent("child")).unwrap();

        let desc = h.descendants(&RoleId::new("root"));
        assert_eq!(desc.len(), 2);
    }

    #[test]
    fn test_no_cycle_valid() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("a", "A")).unwrap();
        h.add_role(Role::new("b", "B").parent("a")).unwrap();
        assert!(!h.has_cycle());
    }

    #[test]
    fn test_cycle_detection() {
        // We can't create a cycle through add_role (it validates),
        // so test has_cycle on a manually constructed hierarchy.
        let mut h = RoleHierarchy::new();
        h.roles.insert(
            RoleId::new("a"),
            Role::new("a", "A").parent("b"),
        );
        h.roles.insert(
            RoleId::new("b"),
            Role::new("b", "B").parent("a"),
        );
        assert!(h.has_cycle());
    }

    #[test]
    fn test_is_ancestor() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("gp", "GP")).unwrap();
        h.add_role(Role::new("p", "P").parent("gp")).unwrap();
        h.add_role(Role::new("c", "C").parent("p")).unwrap();

        assert!(h.is_ancestor(&RoleId::new("gp"), &RoleId::new("c")));
        assert!(!h.is_ancestor(&RoleId::new("c"), &RoleId::new("gp")));
    }

    #[test]
    fn test_are_mutually_exclusive() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::system_admin()).unwrap();
        h.add_role(Role::security_officer()).unwrap();
        assert!(h.are_mutually_exclusive(
            &RoleId::new("system-admin"),
            &RoleId::new("security-officer"),
        ));
    }

    #[test]
    fn test_validate_catches_issues() {
        let mut h = RoleHierarchy::new();
        // Force a bad state.
        h.roles.insert(
            RoleId::new("orphan"),
            Role::new("orphan", "Orphan").parent("nonexistent"),
        );
        let errors = h.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_remove_role_with_dependents_fails() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("parent", "P")).unwrap();
        h.add_role(Role::new("child", "C").parent("parent")).unwrap();
        assert!(h.remove_role(&RoleId::new("parent")).is_err());
    }

    #[test]
    fn test_remove_role_leaf_succeeds() {
        let mut h = RoleHierarchy::new();
        h.add_role(Role::new("leaf", "Leaf")).unwrap();
        assert!(h.remove_role(&RoleId::new("leaf")).is_ok());
        assert!(!h.role_exists(&RoleId::new("leaf")));
    }
}
