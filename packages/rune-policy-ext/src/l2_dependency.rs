// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Cross-policy dependency tracking.
//
// Dependency graph with cycle detection, transitive closure,
// cascade impact analysis, and dependency validation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── PolicyDependencyGraph ──────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PolicyDependencyGraph {
    dependencies: HashMap<String, Vec<String>>,
}

impl PolicyDependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_dependency(&mut self, policy_id: &str, depends_on: &str) {
        self.dependencies
            .entry(policy_id.to_string())
            .or_default()
            .push(depends_on.to_string());
        // Ensure the dependency target exists in the graph
        self.dependencies
            .entry(depends_on.to_string())
            .or_default();
    }

    pub fn dependencies_of(&self, policy_id: &str) -> Vec<&str> {
        self.dependencies
            .get(policy_id)
            .map(|deps| deps.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn dependents_of(&self, policy_id: &str) -> Vec<String> {
        self.dependencies
            .iter()
            .filter(|(_, deps)| deps.iter().any(|d| d == policy_id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn transitive_dependencies(&self, policy_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Seed with direct dependencies
        if let Some(deps) = self.dependencies.get(policy_id) {
            for dep in deps {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }

        while let Some(current) = queue.pop_front() {
            result.push(current.clone());
            if let Some(deps) = self.dependencies.get(&current) {
                for dep in deps {
                    if visited.insert(dep.clone()) {
                        queue.push_back(dep.clone());
                    }
                }
            }
        }

        result
    }

    pub fn has_cycle(&self) -> bool {
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        for key in self.dependencies.keys() {
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
        node: &'a str,
        visited: &mut HashSet<&'a str>,
        in_stack: &mut HashSet<&'a str>,
    ) -> bool {
        visited.insert(node);
        in_stack.insert(node);

        if let Some(deps) = self.dependencies.get(node) {
            for dep in deps {
                if !visited.contains(dep.as_str()) {
                    if self.dfs_cycle(dep, visited, in_stack) {
                        return true;
                    }
                } else if in_stack.contains(dep.as_str()) {
                    return true;
                }
            }
        }

        in_stack.remove(node);
        false
    }

    pub fn leaf_policies(&self) -> Vec<&str> {
        self.dependencies
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn root_policies(&self) -> Vec<String> {
        let all_ids: HashSet<&str> = self.dependencies.keys().map(|s| s.as_str()).collect();
        let depended_on: HashSet<&str> = self
            .dependencies
            .values()
            .flatten()
            .map(|s| s.as_str())
            .collect();

        all_ids
            .difference(&depended_on)
            .map(|s| s.to_string())
            .collect()
    }

    pub fn cascade_impact(&self, policy_id: &str) -> CascadeImpact {
        let directly_affected = self.dependents_of(policy_id);
        let mut transitively_affected = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(policy_id.to_string());

        let mut queue: VecDeque<String> = directly_affected.iter().cloned().collect();
        for d in &directly_affected {
            visited.insert(d.clone());
        }

        let mut max_depth = 0;
        let mut current_depth_items: Vec<String> = directly_affected.clone();

        while !current_depth_items.is_empty() {
            max_depth += 1;
            let mut next_level = Vec::new();
            for item in &current_depth_items {
                let deps_of = self.dependents_of(item);
                for dep in deps_of {
                    if visited.insert(dep.clone()) {
                        transitively_affected.push(dep.clone());
                        next_level.push(dep);
                    }
                }
            }
            current_depth_items = next_level;
        }

        // Remove queue items that were never used
        drop(queue);

        let total_affected = directly_affected.len() + transitively_affected.len();

        CascadeImpact {
            source_policy: policy_id.to_string(),
            directly_affected,
            transitively_affected,
            total_affected,
            max_depth,
        }
    }

    pub fn validate_dependencies(&self) -> Vec<DependencyIssue> {
        let mut issues = Vec::new();

        // Check for cycles
        if self.has_cycle() {
            issues.push(DependencyIssue {
                issue_type: DependencyIssueType::CyclicDependency,
                affected_policies: self.dependencies.keys().cloned().collect(),
                description: "Cyclic dependency detected in the policy graph".into(),
            });
        }

        // Check for missing dependencies
        let all_ids: HashSet<&str> = self.dependencies.keys().map(|s| s.as_str()).collect();
        for (policy_id, deps) in &self.dependencies {
            for dep in deps {
                if !all_ids.contains(dep.as_str()) {
                    issues.push(DependencyIssue {
                        issue_type: DependencyIssueType::MissingDependency,
                        affected_policies: vec![policy_id.clone(), dep.clone()],
                        description: format!("{} depends on {} which does not exist", policy_id, dep),
                    });
                }
            }
        }

        // Check for orphan policies
        for (policy_id, deps) in &self.dependencies {
            if deps.is_empty() && self.dependents_of(policy_id).is_empty() {
                issues.push(DependencyIssue {
                    issue_type: DependencyIssueType::OrphanPolicy,
                    affected_policies: vec![policy_id.clone()],
                    description: format!("{} is neither depended on nor depends on anything", policy_id),
                });
            }
        }

        // Check for deep chains
        for policy_id in self.dependencies.keys() {
            let transitive = self.transitive_dependencies(policy_id);
            if transitive.len() > 5 {
                issues.push(DependencyIssue {
                    issue_type: DependencyIssueType::DeepChain {
                        depth: transitive.len(),
                    },
                    affected_policies: vec![policy_id.clone()],
                    description: format!(
                        "{} has a dependency chain of depth {}",
                        policy_id,
                        transitive.len()
                    ),
                });
            }
        }

        issues
    }
}

// ── CascadeImpact ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CascadeImpact {
    pub source_policy: String,
    pub directly_affected: Vec<String>,
    pub transitively_affected: Vec<String>,
    pub total_affected: usize,
    pub max_depth: usize,
}

// ── DependencyIssue ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DependencyIssue {
    pub issue_type: DependencyIssueType,
    pub affected_policies: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyIssueType {
    CyclicDependency,
    MissingDependency,
    OrphanPolicy,
    DeepChain { depth: usize },
}

impl fmt::Display for DependencyIssueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CyclicDependency => f.write_str("cyclic-dependency"),
            Self::MissingDependency => f.write_str("missing-dependency"),
            Self::OrphanPolicy => f.write_str("orphan-policy"),
            Self::DeepChain { depth } => write!(f, "deep-chain({})", depth),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_dependencies_of() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p2");
        graph.add_dependency("p1", "p3");
        let deps = graph.dependencies_of("p1");
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&"p2"));
        assert!(deps.contains(&"p3"));
    }

    #[test]
    fn test_dependents_of_reverse_lookup() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p3");
        graph.add_dependency("p2", "p3");
        let dependents = graph.dependents_of("p3");
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&"p1".to_string()));
        assert!(dependents.contains(&"p2".to_string()));
    }

    #[test]
    fn test_transitive_dependencies_full_closure() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p2");
        graph.add_dependency("p2", "p3");
        graph.add_dependency("p3", "p4");
        let transitive = graph.transitive_dependencies("p1");
        assert_eq!(transitive.len(), 3);
        assert!(transitive.contains(&"p2".to_string()));
        assert!(transitive.contains(&"p3".to_string()));
        assert!(transitive.contains(&"p4".to_string()));
    }

    #[test]
    fn test_has_cycle_detects_cycle() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p2");
        graph.add_dependency("p2", "p3");
        graph.add_dependency("p3", "p1"); // cycle
        assert!(graph.has_cycle());
    }

    #[test]
    fn test_has_cycle_false_for_dag() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p2");
        graph.add_dependency("p1", "p3");
        graph.add_dependency("p2", "p4");
        graph.add_dependency("p3", "p4");
        assert!(!graph.has_cycle());
    }

    #[test]
    fn test_leaf_policies_correct() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p2");
        graph.add_dependency("p2", "p3");
        let leaves = graph.leaf_policies();
        assert!(leaves.contains(&"p3"));
        assert!(!leaves.contains(&"p1"));
    }

    #[test]
    fn test_cascade_impact_returns_directly_and_transitively_affected() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p2", "p1");
        graph.add_dependency("p3", "p2");
        graph.add_dependency("p4", "p3");
        let impact = graph.cascade_impact("p1");
        assert!(impact.directly_affected.contains(&"p2".to_string()));
        assert!(impact.transitively_affected.contains(&"p3".to_string()));
        assert!(impact.transitively_affected.contains(&"p4".to_string()));
        assert_eq!(impact.total_affected, 3);
    }

    #[test]
    fn test_validate_dependencies_detects_missing_dependency() {
        let mut graph = PolicyDependencyGraph::new();
        // p1 depends on "nonexistent" which is auto-added to graph
        // We need a truly missing one — add manually
        graph.dependencies.insert("p1".to_string(), vec!["missing_policy".to_string()]);
        let issues = graph.validate_dependencies();
        assert!(issues.iter().any(|i| i.issue_type == DependencyIssueType::MissingDependency));
    }

    #[test]
    fn test_validate_dependencies_detects_cyclic_dependency() {
        let mut graph = PolicyDependencyGraph::new();
        graph.add_dependency("p1", "p2");
        graph.add_dependency("p2", "p1");
        let issues = graph.validate_dependencies();
        assert!(issues.iter().any(|i| i.issue_type == DependencyIssueType::CyclicDependency));
    }

    #[test]
    fn test_validate_dependencies_detects_orphan_policy() {
        let mut graph = PolicyDependencyGraph::new();
        graph.dependencies.insert("orphan".to_string(), Vec::new());
        let issues = graph.validate_dependencies();
        assert!(issues.iter().any(|i| i.issue_type == DependencyIssueType::OrphanPolicy));
    }
}
