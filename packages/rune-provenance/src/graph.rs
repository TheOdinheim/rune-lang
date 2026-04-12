// ═══════════════════════════════════════════════════════════════════════
// Graph — provenance DAG traversal and querying.
//
// ProvenanceGraph stores nodes (artifacts) and directed edges
// (relationships) and provides BFS-based ancestry, descendancy, path
// finding, cycle detection, and depth computation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;

// ── ProvenanceNodeType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceNodeType {
    DataSource,
    Transformation,
    ModelTraining,
    ModelOutput,
    PolicyDecision,
    Artifact,
}

impl fmt::Display for ProvenanceNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataSource => f.write_str("data-source"),
            Self::Transformation => f.write_str("transformation"),
            Self::ModelTraining => f.write_str("model-training"),
            Self::ModelOutput => f.write_str("model-output"),
            Self::PolicyDecision => f.write_str("policy-decision"),
            Self::Artifact => f.write_str("artifact"),
        }
    }
}

// ── EdgeRelationship ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeRelationship {
    ProducedBy,
    DerivedFrom,
    InputTo,
    TrainedOn,
    EvaluatedWith,
    DeployedAs,
    DependsOn,
}

impl fmt::Display for EdgeRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProducedBy => f.write_str("produced-by"),
            Self::DerivedFrom => f.write_str("derived-from"),
            Self::InputTo => f.write_str("input-to"),
            Self::TrainedOn => f.write_str("trained-on"),
            Self::EvaluatedWith => f.write_str("evaluated-with"),
            Self::DeployedAs => f.write_str("deployed-as"),
            Self::DependsOn => f.write_str("depends-on"),
        }
    }
}

// ── ProvenanceNode ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProvenanceNode {
    pub artifact_id: ArtifactId,
    pub node_type: ProvenanceNodeType,
    pub label: String,
}

// ── ProvenanceEdge ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProvenanceEdge {
    pub from: ArtifactId,
    pub to: ArtifactId,
    pub relationship: EdgeRelationship,
    pub timestamp: i64,
}

// ── ProvenanceGraph ───────────────────────────────────────────────────

#[derive(Default)]
pub struct ProvenanceGraph {
    pub nodes: HashMap<ArtifactId, ProvenanceNode>,
    pub edges: Vec<ProvenanceEdge>,
}

impl ProvenanceGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: ProvenanceNode) {
        self.nodes.insert(node.artifact_id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: ProvenanceEdge) {
        self.edges.push(edge);
    }

    /// BFS upstream — follow edges backward (where edge.to == id, walk to edge.from).
    pub fn ancestors(&self, artifact_id: &ArtifactId) -> Vec<ArtifactId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        for e in &self.edges {
            if &e.to == artifact_id && visited.insert(e.from.clone()) {
                queue.push_back(e.from.clone());
            }
        }
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());
            for e in &self.edges {
                if e.to == current && visited.insert(e.from.clone()) {
                    queue.push_back(e.from.clone());
                }
            }
        }
        result
    }

    /// BFS downstream — follow edges forward (where edge.from == id, walk to edge.to).
    pub fn descendants(&self, artifact_id: &ArtifactId) -> Vec<ArtifactId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        for e in &self.edges {
            if &e.from == artifact_id && visited.insert(e.to.clone()) {
                queue.push_back(e.to.clone());
            }
        }
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());
            for e in &self.edges {
                if e.from == current && visited.insert(e.to.clone()) {
                    queue.push_back(e.to.clone());
                }
            }
        }
        result
    }

    /// BFS path from `from` to `to`. Returns None if disconnected.
    pub fn path(&self, from: &ArtifactId, to: &ArtifactId) -> Option<Vec<ArtifactId>> {
        if from == to {
            return Some(vec![from.clone()]);
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<ArtifactId, ArtifactId> = HashMap::new();

        visited.insert(from.clone());
        queue.push_back(from.clone());

        while let Some(current) = queue.pop_front() {
            for e in &self.edges {
                if e.from == current && visited.insert(e.to.clone()) {
                    parent.insert(e.to.clone(), current.clone());
                    if &e.to == to {
                        let mut path = vec![to.clone()];
                        let mut cur = to.clone();
                        while let Some(p) = parent.get(&cur) {
                            path.push(p.clone());
                            cur = p.clone();
                        }
                        path.reverse();
                        return Some(path);
                    }
                    queue.push_back(e.to.clone());
                }
            }
        }
        None
    }

    /// Nodes with no incoming edges (original data sources).
    pub fn roots(&self) -> Vec<ArtifactId> {
        let targets: HashSet<_> = self.edges.iter().map(|e| &e.to).collect();
        self.nodes
            .keys()
            .filter(|id| !targets.contains(id))
            .cloned()
            .collect()
    }

    /// Nodes with no outgoing edges (final outputs).
    pub fn leaves(&self) -> Vec<ArtifactId> {
        let sources: HashSet<_> = self.edges.iter().map(|e| &e.from).collect();
        self.nodes
            .keys()
            .filter(|id| !sources.contains(id))
            .cloned()
            .collect()
    }

    pub fn edges_from(&self, artifact_id: &ArtifactId) -> Vec<&ProvenanceEdge> {
        self.edges.iter().filter(|e| &e.from == artifact_id).collect()
    }

    pub fn edges_to(&self, artifact_id: &ArtifactId) -> Vec<&ProvenanceEdge> {
        self.edges.iter().filter(|e| &e.to == artifact_id).collect()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Detect cycles using DFS coloring.
    pub fn has_cycle(&self) -> bool {
        let mut white: HashSet<_> = self.nodes.keys().cloned().collect();
        let mut gray = HashSet::new();

        while let Some(start) = white.iter().next().cloned() {
            if self.dfs_cycle(&start, &mut white, &mut gray) {
                return true;
            }
        }
        false
    }

    fn dfs_cycle(
        &self,
        node: &ArtifactId,
        white: &mut HashSet<ArtifactId>,
        gray: &mut HashSet<ArtifactId>,
    ) -> bool {
        white.remove(node);
        gray.insert(node.clone());

        for e in &self.edges {
            if &e.from == node {
                if gray.contains(&e.to) {
                    return true;
                }
                if white.contains(&e.to) && self.dfs_cycle(&e.to, white, gray) {
                    return true;
                }
            }
        }
        gray.remove(node);
        false // mark as black by simply removing from gray; no explicit black set needed
    }

    /// Longest path from any root to this node.
    pub fn depth(&self, artifact_id: &ArtifactId) -> usize {
        let roots = self.roots();
        let mut max_depth = 0;
        for root in &roots {
            if let Some(path) = self.path(root, artifact_id) {
                max_depth = max_depth.max(path.len().saturating_sub(1));
            }
        }
        max_depth
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, nt: ProvenanceNodeType) -> ProvenanceNode {
        ProvenanceNode {
            artifact_id: ArtifactId::new(id),
            node_type: nt,
            label: id.into(),
        }
    }

    fn edge(from: &str, to: &str, rel: EdgeRelationship) -> ProvenanceEdge {
        ProvenanceEdge {
            from: ArtifactId::new(from),
            to: ArtifactId::new(to),
            relationship: rel,
            timestamp: 1000,
        }
    }

    fn dag() -> ProvenanceGraph {
        // data → preprocess → model → output
        let mut g = ProvenanceGraph::new();
        g.add_node(node("data", ProvenanceNodeType::DataSource));
        g.add_node(node("preprocess", ProvenanceNodeType::Transformation));
        g.add_node(node("model", ProvenanceNodeType::ModelTraining));
        g.add_node(node("output", ProvenanceNodeType::ModelOutput));
        g.add_edge(edge("data", "preprocess", EdgeRelationship::InputTo));
        g.add_edge(edge("preprocess", "model", EdgeRelationship::InputTo));
        g.add_edge(edge("model", "output", EdgeRelationship::ProducedBy));
        g
    }

    #[test]
    fn test_add_node_and_edge() {
        let g = dag();
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.edge_count(), 3);
    }

    #[test]
    fn test_ancestors() {
        let g = dag();
        let anc = g.ancestors(&ArtifactId::new("output"));
        assert_eq!(anc.len(), 3);
    }

    #[test]
    fn test_descendants() {
        let g = dag();
        let desc = g.descendants(&ArtifactId::new("data"));
        assert_eq!(desc.len(), 3);
    }

    #[test]
    fn test_path_exists() {
        let g = dag();
        let p = g.path(&ArtifactId::new("data"), &ArtifactId::new("output"));
        assert!(p.is_some());
        let path = p.unwrap();
        assert_eq!(path.first().unwrap(), &ArtifactId::new("data"));
        assert_eq!(path.last().unwrap(), &ArtifactId::new("output"));
    }

    #[test]
    fn test_path_disconnected() {
        let mut g = ProvenanceGraph::new();
        g.add_node(node("a", ProvenanceNodeType::Artifact));
        g.add_node(node("b", ProvenanceNodeType::Artifact));
        assert!(g.path(&ArtifactId::new("a"), &ArtifactId::new("b")).is_none());
    }

    #[test]
    fn test_roots() {
        let g = dag();
        let roots = g.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], ArtifactId::new("data"));
    }

    #[test]
    fn test_leaves() {
        let g = dag();
        let leaves = g.leaves();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], ArtifactId::new("output"));
    }

    #[test]
    fn test_has_cycle_false_for_dag() {
        let g = dag();
        assert!(!g.has_cycle());
    }

    #[test]
    fn test_has_cycle_true() {
        let mut g = ProvenanceGraph::new();
        g.add_node(node("a", ProvenanceNodeType::Artifact));
        g.add_node(node("b", ProvenanceNodeType::Artifact));
        g.add_edge(edge("a", "b", EdgeRelationship::DerivedFrom));
        g.add_edge(edge("b", "a", EdgeRelationship::DerivedFrom));
        assert!(g.has_cycle());
    }

    #[test]
    fn test_depth() {
        let g = dag();
        assert_eq!(g.depth(&ArtifactId::new("data")), 0);
        assert_eq!(g.depth(&ArtifactId::new("output")), 3);
    }

    #[test]
    fn test_edges_from_and_to() {
        let g = dag();
        assert_eq!(g.edges_from(&ArtifactId::new("data")).len(), 1);
        assert_eq!(g.edges_to(&ArtifactId::new("output")).len(), 1);
    }

    #[test]
    fn test_node_type_display() {
        assert_eq!(ProvenanceNodeType::DataSource.to_string(), "data-source");
        assert_eq!(ProvenanceNodeType::Transformation.to_string(), "transformation");
        assert_eq!(ProvenanceNodeType::ModelTraining.to_string(), "model-training");
        assert_eq!(ProvenanceNodeType::ModelOutput.to_string(), "model-output");
        assert_eq!(ProvenanceNodeType::PolicyDecision.to_string(), "policy-decision");
        assert_eq!(ProvenanceNodeType::Artifact.to_string(), "artifact");
    }

    #[test]
    fn test_edge_relationship_display() {
        assert_eq!(EdgeRelationship::ProducedBy.to_string(), "produced-by");
        assert_eq!(EdgeRelationship::DerivedFrom.to_string(), "derived-from");
        assert_eq!(EdgeRelationship::InputTo.to_string(), "input-to");
        assert_eq!(EdgeRelationship::TrainedOn.to_string(), "trained-on");
        assert_eq!(EdgeRelationship::EvaluatedWith.to_string(), "evaluated-with");
        assert_eq!(EdgeRelationship::DeployedAs.to_string(), "deployed-as");
        assert_eq!(EdgeRelationship::DependsOn.to_string(), "depends-on");
    }
}
