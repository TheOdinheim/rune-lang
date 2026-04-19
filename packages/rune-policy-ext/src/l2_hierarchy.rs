// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Policy inheritance hierarchies.
//
// Hierarchical policy trees with parent/child relationships,
// override modes, cycle detection, and ancestry traversal.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fmt;

// ── OverrideMode ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideMode {
    Inherit,
    Extend,
    Override,
    Replace,
}

impl fmt::Display for OverrideMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Inherit => "inherit",
            Self::Extend => "extend",
            Self::Override => "override",
            Self::Replace => "replace",
        };
        f.write_str(s)
    }
}

// ── PolicyHierarchyNode ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyHierarchyNode {
    pub policy_id: String,
    pub parent_id: Option<String>,
    pub children: Vec<String>,
    pub override_mode: OverrideMode,
}

// ── PolicyHierarchyStore ───────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PolicyHierarchyStore {
    nodes: HashMap<String, PolicyHierarchyNode>,
}

impl PolicyHierarchyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, policy_id: &str, parent_id: Option<&str>, override_mode: OverrideMode) {
        // Update parent's children list
        if let Some(pid) = parent_id {
            if let Some(parent_node) = self.nodes.get_mut(pid) {
                parent_node.children.push(policy_id.to_string());
            }
        }

        self.nodes.insert(
            policy_id.to_string(),
            PolicyHierarchyNode {
                policy_id: policy_id.to_string(),
                parent_id: parent_id.map(|s| s.to_string()),
                children: Vec::new(),
                override_mode,
            },
        );
    }

    pub fn parent_of(&self, policy_id: &str) -> Option<&str> {
        self.nodes
            .get(policy_id)
            .and_then(|n| n.parent_id.as_deref())
    }

    pub fn children_of(&self, policy_id: &str) -> Vec<&str> {
        self.nodes
            .get(policy_id)
            .map(|n| n.children.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn ancestors(&self, policy_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = policy_id.to_string();
        let mut visited = HashSet::new();
        while let Some(parent) = self.parent_of(&current) {
            if !visited.insert(parent.to_string()) {
                break; // cycle protection
            }
            result.push(parent.to_string());
            current = parent.to_string();
        }
        result
    }

    pub fn depth(&self, policy_id: &str) -> usize {
        self.ancestors(policy_id).len()
    }

    pub fn root_policies(&self) -> Vec<&str> {
        self.nodes
            .values()
            .filter(|n| n.parent_id.is_none())
            .map(|n| n.policy_id.as_str())
            .collect()
    }

    pub fn effective_mode(&self, policy_id: &str) -> OverrideMode {
        self.nodes
            .get(policy_id)
            .map(|n| n.override_mode.clone())
            .unwrap_or(OverrideMode::Inherit)
    }

    pub fn has_cycle(&self) -> bool {
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        for key in self.nodes.keys() {
            if !visited.contains(key.as_str()) {
                if self.dfs_cycle(key, &mut visited, &mut in_stack) {
                    return true;
                }
            }
        }
        false
    }

    fn dfs_cycle<'a>(
        &'a self,
        node_id: &'a str,
        visited: &mut HashSet<&'a str>,
        in_stack: &mut HashSet<&'a str>,
    ) -> bool {
        visited.insert(node_id);
        in_stack.insert(node_id);

        if let Some(node) = self.nodes.get(node_id) {
            for child_id in &node.children {
                if !visited.contains(child_id.as_str()) {
                    if self.dfs_cycle(child_id, visited, in_stack) {
                        return true;
                    }
                } else if in_stack.contains(child_id.as_str()) {
                    return true;
                }
            }
        }

        in_stack.remove(node_id);
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
    fn test_add_node_and_parent_of() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("root", None, OverrideMode::Inherit);
        store.add_node("child", Some("root"), OverrideMode::Extend);
        assert_eq!(store.parent_of("child"), Some("root"));
        assert_eq!(store.parent_of("root"), None);
    }

    #[test]
    fn test_children_of_returns_children() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("root", None, OverrideMode::Inherit);
        store.add_node("child1", Some("root"), OverrideMode::Extend);
        store.add_node("child2", Some("root"), OverrideMode::Override);
        let children = store.children_of("root");
        assert_eq!(children.len(), 2);
        assert!(children.contains(&"child1"));
        assert!(children.contains(&"child2"));
    }

    #[test]
    fn test_ancestors_returns_root_to_parent_chain() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("root", None, OverrideMode::Inherit);
        store.add_node("mid", Some("root"), OverrideMode::Extend);
        store.add_node("leaf", Some("mid"), OverrideMode::Override);
        let ancestors = store.ancestors("leaf");
        assert_eq!(ancestors, vec!["mid", "root"]);
    }

    #[test]
    fn test_depth_calculates_correctly() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("root", None, OverrideMode::Inherit);
        store.add_node("mid", Some("root"), OverrideMode::Extend);
        store.add_node("leaf", Some("mid"), OverrideMode::Override);
        assert_eq!(store.depth("root"), 0);
        assert_eq!(store.depth("mid"), 1);
        assert_eq!(store.depth("leaf"), 2);
    }

    #[test]
    fn test_root_policies_returns_parentless() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("root1", None, OverrideMode::Inherit);
        store.add_node("root2", None, OverrideMode::Inherit);
        store.add_node("child", Some("root1"), OverrideMode::Extend);
        let roots = store.root_policies();
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&"root1"));
        assert!(roots.contains(&"root2"));
    }

    #[test]
    fn test_has_cycle_detects_cycle() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("a", None, OverrideMode::Inherit);
        store.add_node("b", Some("a"), OverrideMode::Extend);
        // Manually create a cycle: make a point to b as child, and b points back to a
        store.nodes.get_mut("b").unwrap().children.push("a".to_string());
        assert!(store.has_cycle());
    }

    #[test]
    fn test_has_cycle_false_for_valid_tree() {
        let mut store = PolicyHierarchyStore::new();
        store.add_node("root", None, OverrideMode::Inherit);
        store.add_node("child1", Some("root"), OverrideMode::Extend);
        store.add_node("child2", Some("root"), OverrideMode::Override);
        store.add_node("grandchild", Some("child1"), OverrideMode::Replace);
        assert!(!store.has_cycle());
    }
}
