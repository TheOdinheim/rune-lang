// ═══════════════════════════════════════════════════════════════════════
// Lineage Tracker — Layer 3 lineage tracking trait boundary.
//
// LineageTracker is the Layer 3 trait for recording and querying
// derivation relationships between artifacts. Separate from the
// Layer 1 LineageRegistry (which models source→transform→output
// chains) because the tracker models artifact-to-artifact
// derivation graphs with typed relationships and cycle detection.
//
// InMemoryLineageTracker detects cycles on insert via DFS.
// DepthLimitedLineageTracker wraps any tracker and enforces a
// maximum ancestry depth.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::backend::ArtifactRef;
use crate::error::ProvenanceError;

// ── LineageRelationship ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageRelationship {
    DerivedFrom,
    TransformedFrom,
    MergedFrom,
    ExtractedFrom,
    Signed,
    Copied,
}

impl fmt::Display for LineageRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DerivedFrom => f.write_str("derived-from"),
            Self::TransformedFrom => f.write_str("transformed-from"),
            Self::MergedFrom => f.write_str("merged-from"),
            Self::ExtractedFrom => f.write_str("extracted-from"),
            Self::Signed => f.write_str("signed"),
            Self::Copied => f.write_str("copied"),
        }
    }
}

// ── LineageEdge ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LineageEdge {
    pub child: ArtifactRef,
    pub parent: ArtifactRef,
    pub relationship: LineageRelationship,
    pub recorded_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── LineageQueryResult ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LineageQueryResult {
    pub root: ArtifactRef,
    pub ancestors: Vec<ArtifactRef>,
    pub depth: usize,
}

// ── LineageTracker trait ───────────────────────────────────────────

pub trait LineageTracker {
    fn record_edge(&mut self, edge: LineageEdge) -> Result<(), ProvenanceError>;
    fn parents_of(&self, artifact: &ArtifactRef) -> Result<Vec<LineageEdge>, ProvenanceError>;
    fn children_of(&self, artifact: &ArtifactRef) -> Result<Vec<LineageEdge>, ProvenanceError>;
    fn ancestors(&self, artifact: &ArtifactRef) -> Result<LineageQueryResult, ProvenanceError>;
    fn has_ancestor(&self, artifact: &ArtifactRef, candidate: &ArtifactRef) -> Result<bool, ProvenanceError>;
    fn edge_count(&self) -> usize;
    fn tracker_id(&self) -> &str;
}

// ── InMemoryLineageTracker ─────────────────────────────────────────

pub struct InMemoryLineageTracker {
    id: String,
    edges: Vec<LineageEdge>,
    // child → [parent indices]
    child_index: HashMap<String, Vec<usize>>,
    // parent → [child indices]
    parent_index: HashMap<String, Vec<usize>>,
}

impl InMemoryLineageTracker {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            edges: Vec::new(),
            child_index: HashMap::new(),
            parent_index: HashMap::new(),
        }
    }

    fn would_create_cycle(&self, child: &ArtifactRef, parent: &ArtifactRef) -> bool {
        if child == parent {
            return true;
        }
        // DFS from parent's ancestors to see if child is reachable
        let mut visited = HashSet::new();
        let mut stack = vec![parent.as_str().to_string()];
        while let Some(current) = stack.pop() {
            if current == child.as_str() {
                return true;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(indices) = self.child_index.get(&current) {
                for &idx in indices {
                    stack.push(self.edges[idx].parent.as_str().to_string());
                }
            }
        }
        false
    }
}

impl LineageTracker for InMemoryLineageTracker {
    fn record_edge(&mut self, edge: LineageEdge) -> Result<(), ProvenanceError> {
        if self.would_create_cycle(&edge.child, &edge.parent) {
            return Err(ProvenanceError::CycleDetected {
                path: vec![
                    edge.child.as_str().to_string(),
                    edge.parent.as_str().to_string(),
                    edge.child.as_str().to_string(),
                ],
            });
        }
        let idx = self.edges.len();
        self.child_index.entry(edge.child.as_str().to_string()).or_default().push(idx);
        self.parent_index.entry(edge.parent.as_str().to_string()).or_default().push(idx);
        self.edges.push(edge);
        Ok(())
    }

    fn parents_of(&self, artifact: &ArtifactRef) -> Result<Vec<LineageEdge>, ProvenanceError> {
        let indices = self.child_index.get(artifact.as_str()).cloned().unwrap_or_default();
        Ok(indices.iter().map(|&i| self.edges[i].clone()).collect())
    }

    fn children_of(&self, artifact: &ArtifactRef) -> Result<Vec<LineageEdge>, ProvenanceError> {
        let indices = self.parent_index.get(artifact.as_str()).cloned().unwrap_or_default();
        Ok(indices.iter().map(|&i| self.edges[i].clone()).collect())
    }

    fn ancestors(&self, artifact: &ArtifactRef) -> Result<LineageQueryResult, ProvenanceError> {
        let mut visited = HashSet::new();
        let mut stack = vec![(artifact.as_str().to_string(), 0usize)];
        let mut ancestors = Vec::new();
        let mut max_depth = 0usize;

        while let Some((current, depth)) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if current != artifact.as_str() {
                ancestors.push(ArtifactRef::new(&current));
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            if let Some(indices) = self.child_index.get(&current) {
                for &idx in indices {
                    let parent = self.edges[idx].parent.as_str().to_string();
                    if !visited.contains(&parent) {
                        stack.push((parent, depth + 1));
                    }
                }
            }
        }
        Ok(LineageQueryResult { root: artifact.clone(), ancestors, depth: max_depth })
    }

    fn has_ancestor(&self, artifact: &ArtifactRef, candidate: &ArtifactRef) -> Result<bool, ProvenanceError> {
        let result = self.ancestors(artifact)?;
        Ok(result.ancestors.contains(candidate))
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }

    fn tracker_id(&self) -> &str {
        &self.id
    }
}

// ── DepthLimitedLineageTracker ─────────────────────────────────────

pub struct DepthLimitedLineageTracker<T: LineageTracker> {
    inner: T,
    max_depth: usize,
}

impl<T: LineageTracker> DepthLimitedLineageTracker<T> {
    pub fn new(inner: T, max_depth: usize) -> Self {
        Self { inner, max_depth }
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
}

impl<T: LineageTracker> LineageTracker for DepthLimitedLineageTracker<T> {
    fn record_edge(&mut self, edge: LineageEdge) -> Result<(), ProvenanceError> {
        // Check if adding this edge would exceed the depth limit
        let parent_result = self.inner.ancestors(&edge.parent)?;
        if parent_result.depth + 1 > self.max_depth {
            return Err(ProvenanceError::InvalidOperation(
                format!("lineage depth would exceed limit of {}", self.max_depth)
            ));
        }
        self.inner.record_edge(edge)
    }

    fn parents_of(&self, artifact: &ArtifactRef) -> Result<Vec<LineageEdge>, ProvenanceError> {
        self.inner.parents_of(artifact)
    }

    fn children_of(&self, artifact: &ArtifactRef) -> Result<Vec<LineageEdge>, ProvenanceError> {
        self.inner.children_of(artifact)
    }

    fn ancestors(&self, artifact: &ArtifactRef) -> Result<LineageQueryResult, ProvenanceError> {
        self.inner.ancestors(artifact)
    }

    fn has_ancestor(&self, artifact: &ArtifactRef, candidate: &ArtifactRef) -> Result<bool, ProvenanceError> {
        self.inner.has_ancestor(artifact, candidate)
    }

    fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    fn tracker_id(&self) -> &str {
        self.inner.tracker_id()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(child: &str, parent: &str, rel: LineageRelationship) -> LineageEdge {
        LineageEdge {
            child: ArtifactRef::new(child),
            parent: ArtifactRef::new(parent),
            relationship: rel,
            recorded_at: 1000,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_record_and_query_parents() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("child", "parent", LineageRelationship::DerivedFrom)).unwrap();
        let parents = tracker.parents_of(&ArtifactRef::new("child")).unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].parent.as_str(), "parent");
    }

    #[test]
    fn test_query_children() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("c1", "p1", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c2", "p1", LineageRelationship::Copied)).unwrap();
        let children = tracker.children_of(&ArtifactRef::new("p1")).unwrap();
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_cycle_detection_self() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        assert!(tracker.record_edge(edge("a", "a", LineageRelationship::DerivedFrom)).is_err());
    }

    #[test]
    fn test_cycle_detection_indirect() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("b", "a", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c", "b", LineageRelationship::DerivedFrom)).unwrap();
        // c → b → a, now a → c would create cycle
        assert!(tracker.record_edge(edge("a", "c", LineageRelationship::DerivedFrom)).is_err());
    }

    #[test]
    fn test_ancestors() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("b", "a", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c", "b", LineageRelationship::TransformedFrom)).unwrap();
        let result = tracker.ancestors(&ArtifactRef::new("c")).unwrap();
        assert_eq!(result.ancestors.len(), 2);
        assert_eq!(result.depth, 2);
    }

    #[test]
    fn test_has_ancestor() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("b", "a", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c", "b", LineageRelationship::DerivedFrom)).unwrap();
        assert!(tracker.has_ancestor(&ArtifactRef::new("c"), &ArtifactRef::new("a")).unwrap());
        assert!(!tracker.has_ancestor(&ArtifactRef::new("a"), &ArtifactRef::new("c")).unwrap());
    }

    #[test]
    fn test_merged_from_multiple_parents() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("merged", "src1", LineageRelationship::MergedFrom)).unwrap();
        tracker.record_edge(edge("merged", "src2", LineageRelationship::MergedFrom)).unwrap();
        let parents = tracker.parents_of(&ArtifactRef::new("merged")).unwrap();
        assert_eq!(parents.len(), 2);
    }

    #[test]
    fn test_edge_count() {
        let mut tracker = InMemoryLineageTracker::new("t1");
        tracker.record_edge(edge("b", "a", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c", "b", LineageRelationship::Signed)).unwrap();
        assert_eq!(tracker.edge_count(), 2);
    }

    #[test]
    fn test_relationship_display() {
        assert_eq!(LineageRelationship::DerivedFrom.to_string(), "derived-from");
        assert_eq!(LineageRelationship::TransformedFrom.to_string(), "transformed-from");
        assert_eq!(LineageRelationship::MergedFrom.to_string(), "merged-from");
        assert_eq!(LineageRelationship::ExtractedFrom.to_string(), "extracted-from");
        assert_eq!(LineageRelationship::Signed.to_string(), "signed");
        assert_eq!(LineageRelationship::Copied.to_string(), "copied");
    }

    #[test]
    fn test_tracker_id() {
        let tracker = InMemoryLineageTracker::new("my-tracker");
        assert_eq!(tracker.tracker_id(), "my-tracker");
    }

    #[test]
    fn test_empty_parents() {
        let tracker = InMemoryLineageTracker::new("t1");
        let parents = tracker.parents_of(&ArtifactRef::new("nonexistent")).unwrap();
        assert!(parents.is_empty());
    }

    #[test]
    fn test_depth_limited_tracker_allows_within_limit() {
        let inner = InMemoryLineageTracker::new("t1");
        let mut tracker = DepthLimitedLineageTracker::new(inner, 3);
        tracker.record_edge(edge("b", "a", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c", "b", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("d", "c", LineageRelationship::DerivedFrom)).unwrap();
        assert_eq!(tracker.edge_count(), 3);
    }

    #[test]
    fn test_depth_limited_tracker_rejects_beyond_limit() {
        let inner = InMemoryLineageTracker::new("t1");
        let mut tracker = DepthLimitedLineageTracker::new(inner, 2);
        tracker.record_edge(edge("b", "a", LineageRelationship::DerivedFrom)).unwrap();
        tracker.record_edge(edge("c", "b", LineageRelationship::DerivedFrom)).unwrap();
        // depth is now 2, adding another should fail
        assert!(tracker.record_edge(edge("d", "c", LineageRelationship::DerivedFrom)).is_err());
    }

    #[test]
    fn test_depth_limited_max_depth() {
        let inner = InMemoryLineageTracker::new("t1");
        let tracker = DepthLimitedLineageTracker::new(inner, 5);
        assert_eq!(tracker.max_depth(), 5);
    }
}
