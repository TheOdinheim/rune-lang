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
// Layer 2: Provenance Graph Analysis
// ═══════════════════════════════════════════════════════════════════════

/// Aggregate metrics for a provenance graph.
#[derive(Debug, Clone)]
pub struct ProvenanceGraphMetrics {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub max_depth: usize,
    pub avg_depth: f64,
    pub root_count: usize,
    pub leaf_count: usize,
    pub longest_chain_length: usize,
    pub orphan_count: usize,
}

impl ProvenanceGraph {
    /// Compute aggregate metrics for the graph.
    pub fn compute_metrics(&self) -> ProvenanceGraphMetrics {
        let roots = self.roots();
        let leaves = self.leaves();
        let root_count = roots.len();
        let leaf_count = leaves.len();

        // Nodes that have no edges at all (neither incoming nor outgoing)
        let sources: HashSet<_> = self.edges.iter().map(|e| &e.from).collect();
        let targets: HashSet<_> = self.edges.iter().map(|e| &e.to).collect();
        let orphan_count = self.nodes.keys()
            .filter(|id| !sources.contains(id) && !targets.contains(id))
            .count();

        // Compute depths for all nodes
        let mut max_depth = 0;
        let mut total_depth: usize = 0;
        let mut depth_count: usize = 0;
        for id in self.nodes.keys() {
            let d = self.depth(id);
            if d > max_depth {
                max_depth = d;
            }
            total_depth += d;
            depth_count += 1;
        }
        let avg_depth = if depth_count > 0 {
            total_depth as f64 / depth_count as f64
        } else {
            0.0
        };

        // Longest chain = max_depth + 1 (nodes in chain) if there are edges, else 1 if nodes exist
        let longest_chain_length = if self.edges.is_empty() {
            if self.nodes.is_empty() { 0 } else { 1 }
        } else {
            max_depth + 1
        };

        ProvenanceGraphMetrics {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            max_depth,
            avg_depth,
            root_count,
            leaf_count,
            longest_chain_length,
            orphan_count,
        }
    }

    /// Compute impact analysis: which nodes are affected if `artifact_id` changes.
    pub fn impact_analysis(&self, artifact_id: &ArtifactId) -> ImpactAnalysis {
        // Directly affected = immediate downstream neighbors
        let directly_affected: Vec<ArtifactId> = self.edges.iter()
            .filter(|e| &e.from == artifact_id)
            .map(|e| e.to.clone())
            .collect();

        // Transitively affected = all descendants
        let transitively_affected = self.descendants(artifact_id);

        ImpactAnalysis {
            directly_affected,
            transitively_affected,
        }
    }

    /// Diff two lineage chains by comparing ancestors of two nodes.
    pub fn diff_lineage(&self, a: &ArtifactId, b: &ArtifactId) -> LineageDiff {
        let ancestors_a: HashSet<ArtifactId> = self.ancestors(a).into_iter().collect();
        let ancestors_b: HashSet<ArtifactId> = self.ancestors(b).into_iter().collect();

        let common_ancestors: Vec<ArtifactId> = ancestors_a.intersection(&ancestors_b).cloned().collect();
        let only_in_a: Vec<ArtifactId> = ancestors_a.difference(&ancestors_b).cloned().collect();
        let only_in_b: Vec<ArtifactId> = ancestors_b.difference(&ancestors_a).cloned().collect();

        // Divergence point: the common ancestor with the greatest depth
        let divergence_point = common_ancestors.iter()
            .max_by_key(|id| self.depth(id))
            .cloned();

        LineageDiff {
            common_ancestors,
            only_in_a,
            only_in_b,
            divergence_point,
        }
    }

    /// Export graph in DOT format for Graphviz visualization.
    pub fn export_dot(&self) -> String {
        let mut out = String::from("digraph provenance {\n");
        for (id, node) in &self.nodes {
            out.push_str(&format!(
                "  \"{}\" [label=\"{}\\n({})\"];\n",
                id, node.label, node.node_type
            ));
        }
        for edge in &self.edges {
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                edge.from, edge.to, edge.relationship
            ));
        }
        out.push_str("}\n");
        out
    }

    /// Export graph as JSON.
    pub fn export_json(&self) -> String {
        let nodes: Vec<serde_json::Value> = self.nodes.iter().map(|(id, node)| {
            serde_json::json!({
                "id": id.to_string(),
                "label": node.label,
                "type": format!("{}", node.node_type),
            })
        }).collect();
        let edges: Vec<serde_json::Value> = self.edges.iter().map(|e| {
            serde_json::json!({
                "from": e.from.to_string(),
                "to": e.to.to_string(),
                "relationship": format!("{}", e.relationship),
                "timestamp": e.timestamp,
            })
        }).collect();
        serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        }).to_string()
    }
}

/// Impact analysis result.
#[derive(Debug, Clone)]
pub struct ImpactAnalysis {
    pub directly_affected: Vec<ArtifactId>,
    pub transitively_affected: Vec<ArtifactId>,
}

/// Diff between two lineage paths.
#[derive(Debug, Clone)]
pub struct LineageDiff {
    pub common_ancestors: Vec<ArtifactId>,
    pub only_in_a: Vec<ArtifactId>,
    pub only_in_b: Vec<ArtifactId>,
    pub divergence_point: Option<ArtifactId>,
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_compute_metrics_dag() {
        let g = dag();
        let m = g.compute_metrics();
        assert_eq!(m.total_nodes, 4);
        assert_eq!(m.total_edges, 3);
        assert_eq!(m.root_count, 1);
        assert_eq!(m.leaf_count, 1);
        assert_eq!(m.max_depth, 3);
        assert_eq!(m.longest_chain_length, 4);
        assert_eq!(m.orphan_count, 0);
    }

    #[test]
    fn test_compute_metrics_orphan() {
        let mut g = dag();
        g.add_node(node("orphan", ProvenanceNodeType::Artifact));
        let m = g.compute_metrics();
        assert_eq!(m.orphan_count, 1);
        assert_eq!(m.total_nodes, 5);
    }

    #[test]
    fn test_compute_metrics_empty() {
        let g = ProvenanceGraph::new();
        let m = g.compute_metrics();
        assert_eq!(m.total_nodes, 0);
        assert_eq!(m.total_edges, 0);
        assert_eq!(m.longest_chain_length, 0);
    }

    #[test]
    fn test_impact_analysis() {
        let g = dag();
        let impact = g.impact_analysis(&ArtifactId::new("data"));
        assert_eq!(impact.directly_affected.len(), 1);
        assert_eq!(impact.directly_affected[0], ArtifactId::new("preprocess"));
        assert_eq!(impact.transitively_affected.len(), 3);
    }

    #[test]
    fn test_impact_analysis_leaf() {
        let g = dag();
        let impact = g.impact_analysis(&ArtifactId::new("output"));
        assert!(impact.directly_affected.is_empty());
        assert!(impact.transitively_affected.is_empty());
    }

    #[test]
    fn test_diff_lineage() {
        // data → preprocess → model → output
        //                  ↘ branch
        let mut g = dag();
        g.add_node(node("branch", ProvenanceNodeType::Artifact));
        g.add_edge(edge("preprocess", "branch", EdgeRelationship::DerivedFrom));
        let diff = g.diff_lineage(&ArtifactId::new("output"), &ArtifactId::new("branch"));
        assert!(!diff.common_ancestors.is_empty());
        // "data" and "preprocess" should be common ancestors
        let common_set: HashSet<_> = diff.common_ancestors.iter().collect();
        assert!(common_set.contains(&ArtifactId::new("data")));
        assert!(common_set.contains(&ArtifactId::new("preprocess")));
    }

    #[test]
    fn test_diff_lineage_no_common() {
        let mut g = ProvenanceGraph::new();
        g.add_node(node("a", ProvenanceNodeType::Artifact));
        g.add_node(node("b", ProvenanceNodeType::Artifact));
        let diff = g.diff_lineage(&ArtifactId::new("a"), &ArtifactId::new("b"));
        assert!(diff.common_ancestors.is_empty());
        assert!(diff.divergence_point.is_none());
    }

    #[test]
    fn test_export_dot() {
        let g = dag();
        let dot = g.export_dot();
        assert!(dot.starts_with("digraph provenance {"));
        assert!(dot.contains("->"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn test_export_json() {
        let g = dag();
        let json = g.export_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["nodes"].is_array());
        assert!(parsed["edges"].is_array());
        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 4);
        assert_eq!(parsed["edges"].as_array().unwrap().len(), 3);
    }
}
