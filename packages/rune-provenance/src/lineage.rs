// ═══════════════════════════════════════════════════════════════════════
// Lineage — data lineage: source → transform → output chains.
//
// DataLineage describes where an artifact came from, what
// transformations were applied, and what was produced. LineageRegistry
// stores lineage records and supports upstream/downstream tracing via
// BFS.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;
use crate::error::ProvenanceError;
use crate::transform::TransformationRef;

// ── LineageId ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LineageId(pub String);

impl LineageId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for LineageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SourceRelationship ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceRelationship {
    PrimarySource,
    AugmentationSource,
    ValidationSource,
    ReferenceSource,
    DerivedFrom,
    MergedFrom,
    FilteredFrom,
    SampledFrom,
}

impl fmt::Display for SourceRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimarySource => f.write_str("primary-source"),
            Self::AugmentationSource => f.write_str("augmentation-source"),
            Self::ValidationSource => f.write_str("validation-source"),
            Self::ReferenceSource => f.write_str("reference-source"),
            Self::DerivedFrom => f.write_str("derived-from"),
            Self::MergedFrom => f.write_str("merged-from"),
            Self::FilteredFrom => f.write_str("filtered-from"),
            Self::SampledFrom => f.write_str("sampled-from"),
        }
    }
}

// ── LineageSource ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LineageSource {
    pub artifact_id: ArtifactId,
    pub relationship: SourceRelationship,
    pub contribution: Option<f64>,
    pub accessed_at: i64,
    pub verified: bool,
}

// ── DataLineage ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataLineage {
    pub id: LineageId,
    pub artifact_id: ArtifactId,
    pub sources: Vec<LineageSource>,
    pub transformations: Vec<TransformationRef>,
    pub outputs: Vec<ArtifactId>,
    pub created_at: i64,
    pub created_by: String,
    pub classification: Option<String>,
    pub license: Option<String>,
    pub retention_policy: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl DataLineage {
    pub fn new(
        id: impl Into<String>,
        artifact_id: ArtifactId,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            id: LineageId::new(id),
            artifact_id,
            sources: Vec::new(),
            transformations: Vec::new(),
            outputs: Vec::new(),
            created_at,
            created_by: created_by.into(),
            classification: None,
            license: None,
            retention_policy: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_source(mut self, source: LineageSource) -> Self {
        self.sources.push(source);
        self
    }

    pub fn with_output(mut self, output: ArtifactId) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn with_transformation(mut self, t: TransformationRef) -> Self {
        self.transformations.push(t);
        self
    }

    pub fn with_license(mut self, l: impl Into<String>) -> Self {
        self.license = Some(l.into());
        self
    }

    pub fn with_classification(mut self, c: impl Into<String>) -> Self {
        self.classification = Some(c.into());
        self
    }
}

// ── LineageRegistry ───────────────────────────────────────────────────

#[derive(Default)]
pub struct LineageRegistry {
    pub lineages: HashMap<LineageId, DataLineage>,
    pub artifact_lineage: HashMap<ArtifactId, LineageId>,
}

impl LineageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, lineage: DataLineage) -> Result<(), ProvenanceError> {
        if self.lineages.contains_key(&lineage.id) {
            return Err(ProvenanceError::LineageAlreadyExists(lineage.id.0.clone()));
        }
        let lid = lineage.id.clone();
        self.artifact_lineage
            .insert(lineage.artifact_id.clone(), lid.clone());
        self.lineages.insert(lid, lineage);
        Ok(())
    }

    pub fn get(&self, id: &LineageId) -> Option<&DataLineage> {
        self.lineages.get(id)
    }

    pub fn lineage_for(&self, artifact_id: &ArtifactId) -> Option<&DataLineage> {
        self.artifact_lineage
            .get(artifact_id)
            .and_then(|lid| self.lineages.get(lid))
    }

    pub fn sources_of(&self, artifact_id: &ArtifactId) -> Vec<&LineageSource> {
        self.lineage_for(artifact_id)
            .map(|l| l.sources.iter().collect())
            .unwrap_or_default()
    }

    /// Find all artifacts that list `artifact_id` as a source.
    pub fn outputs_of(&self, artifact_id: &ArtifactId) -> Vec<&ArtifactId> {
        self.lineages
            .values()
            .filter(|l| l.sources.iter().any(|s| &s.artifact_id == artifact_id))
            .map(|l| &l.artifact_id)
            .collect()
    }

    /// BFS upstream — all ancestor source artifacts.
    pub fn trace_upstream(&self, artifact_id: &ArtifactId) -> Vec<ArtifactId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        // Seed with direct sources.
        if let Some(lineage) = self.lineage_for(artifact_id) {
            for src in &lineage.sources {
                if visited.insert(src.artifact_id.clone()) {
                    queue.push_back(src.artifact_id.clone());
                }
            }
        }
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());
            if let Some(lineage) = self.lineage_for(&current) {
                for src in &lineage.sources {
                    if visited.insert(src.artifact_id.clone()) {
                        queue.push_back(src.artifact_id.clone());
                    }
                }
            }
        }
        result
    }

    /// BFS downstream — all descendant artifacts.
    pub fn trace_downstream(&self, artifact_id: &ArtifactId) -> Vec<ArtifactId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        for child in self.outputs_of(artifact_id) {
            if visited.insert(child.clone()) {
                queue.push_back(child.clone());
            }
        }
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());
            for child in self.outputs_of(&current) {
                if visited.insert(child.clone()) {
                    queue.push_back(child.clone());
                }
            }
        }
        result
    }

    pub fn has_lineage(&self, artifact_id: &ArtifactId) -> bool {
        self.artifact_lineage.contains_key(artifact_id)
    }

    pub fn count(&self) -> usize {
        self.lineages.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn source(id: &str, rel: SourceRelationship) -> LineageSource {
        LineageSource {
            artifact_id: ArtifactId::new(id),
            relationship: rel,
            contribution: None,
            accessed_at: 1000,
            verified: true,
        }
    }

    #[test]
    fn test_source_relationship_display() {
        assert_eq!(SourceRelationship::PrimarySource.to_string(), "primary-source");
        assert_eq!(SourceRelationship::DerivedFrom.to_string(), "derived-from");
        assert_eq!(SourceRelationship::MergedFrom.to_string(), "merged-from");
        assert_eq!(SourceRelationship::FilteredFrom.to_string(), "filtered-from");
        assert_eq!(SourceRelationship::SampledFrom.to_string(), "sampled-from");
        assert_eq!(SourceRelationship::AugmentationSource.to_string(), "augmentation-source");
        assert_eq!(SourceRelationship::ValidationSource.to_string(), "validation-source");
        assert_eq!(SourceRelationship::ReferenceSource.to_string(), "reference-source");
    }

    #[test]
    fn test_lineage_construction() {
        let l = DataLineage::new("l1", ArtifactId::new("a1"), "alice", 1000)
            .with_source(source("src1", SourceRelationship::PrimarySource))
            .with_output(ArtifactId::new("out1"))
            .with_license("CC-BY-4.0")
            .with_classification("public");
        assert_eq!(l.sources.len(), 1);
        assert_eq!(l.outputs.len(), 1);
        assert_eq!(l.license.as_deref(), Some("CC-BY-4.0"));
        assert_eq!(l.classification.as_deref(), Some("public"));
    }

    #[test]
    fn test_registry_record_and_get() {
        let mut r = LineageRegistry::new();
        r.record(DataLineage::new("l1", ArtifactId::new("a1"), "alice", 1000))
            .unwrap();
        assert!(r.get(&LineageId::new("l1")).is_some());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn test_registry_duplicate_fails() {
        let mut r = LineageRegistry::new();
        r.record(DataLineage::new("l1", ArtifactId::new("a1"), "alice", 1000))
            .unwrap();
        let err = r
            .record(DataLineage::new("l1", ArtifactId::new("a2"), "bob", 2000))
            .unwrap_err();
        assert!(matches!(err, ProvenanceError::LineageAlreadyExists(_)));
    }

    #[test]
    fn test_lineage_for_artifact() {
        let mut r = LineageRegistry::new();
        r.record(DataLineage::new("l1", ArtifactId::new("a1"), "alice", 1000))
            .unwrap();
        assert!(r.lineage_for(&ArtifactId::new("a1")).is_some());
        assert!(r.lineage_for(&ArtifactId::new("missing")).is_none());
    }

    #[test]
    fn test_sources_of() {
        let mut r = LineageRegistry::new();
        r.record(
            DataLineage::new("l1", ArtifactId::new("a1"), "alice", 1000)
                .with_source(source("src1", SourceRelationship::PrimarySource))
                .with_source(source("src2", SourceRelationship::AugmentationSource)),
        )
        .unwrap();
        assert_eq!(r.sources_of(&ArtifactId::new("a1")).len(), 2);
    }

    #[test]
    fn test_outputs_of() {
        let mut r = LineageRegistry::new();
        // a1 has source src1
        r.record(
            DataLineage::new("l1", ArtifactId::new("a1"), "alice", 1000)
                .with_source(source("src1", SourceRelationship::DerivedFrom)),
        )
        .unwrap();
        // a2 also has source src1
        r.record(
            DataLineage::new("l2", ArtifactId::new("a2"), "alice", 2000)
                .with_source(source("src1", SourceRelationship::FilteredFrom)),
        )
        .unwrap();
        let outs = r.outputs_of(&ArtifactId::new("src1"));
        assert_eq!(outs.len(), 2);
    }

    #[test]
    fn test_trace_upstream() {
        let mut r = LineageRegistry::new();
        // chain: root → mid → leaf
        r.record(
            DataLineage::new("l-mid", ArtifactId::new("mid"), "a", 1)
                .with_source(source("root", SourceRelationship::PrimarySource)),
        )
        .unwrap();
        r.record(
            DataLineage::new("l-leaf", ArtifactId::new("leaf"), "a", 2)
                .with_source(source("mid", SourceRelationship::DerivedFrom)),
        )
        .unwrap();
        let upstream = r.trace_upstream(&ArtifactId::new("leaf"));
        assert_eq!(upstream.len(), 2);
        assert!(upstream.contains(&ArtifactId::new("mid")));
        assert!(upstream.contains(&ArtifactId::new("root")));
    }

    #[test]
    fn test_trace_downstream() {
        let mut r = LineageRegistry::new();
        // chain: root → mid → leaf
        r.record(
            DataLineage::new("l-mid", ArtifactId::new("mid"), "a", 1)
                .with_source(source("root", SourceRelationship::PrimarySource)),
        )
        .unwrap();
        r.record(
            DataLineage::new("l-leaf", ArtifactId::new("leaf"), "a", 2)
                .with_source(source("mid", SourceRelationship::DerivedFrom)),
        )
        .unwrap();
        let downstream = r.trace_downstream(&ArtifactId::new("root"));
        assert_eq!(downstream.len(), 2);
        assert!(downstream.contains(&ArtifactId::new("mid")));
        assert!(downstream.contains(&ArtifactId::new("leaf")));
    }

    #[test]
    fn test_has_lineage() {
        let mut r = LineageRegistry::new();
        r.record(DataLineage::new("l1", ArtifactId::new("a1"), "a", 1))
            .unwrap();
        assert!(r.has_lineage(&ArtifactId::new("a1")));
        assert!(!r.has_lineage(&ArtifactId::new("a2")));
    }

    #[test]
    fn test_contributions_sum() {
        let l = DataLineage::new("l1", ArtifactId::new("a1"), "a", 1)
            .with_source(LineageSource {
                artifact_id: ArtifactId::new("s1"),
                relationship: SourceRelationship::PrimarySource,
                contribution: Some(0.7),
                accessed_at: 1,
                verified: true,
            })
            .with_source(LineageSource {
                artifact_id: ArtifactId::new("s2"),
                relationship: SourceRelationship::AugmentationSource,
                contribution: Some(0.3),
                accessed_at: 1,
                verified: true,
            });
        let total: f64 = l
            .sources
            .iter()
            .filter_map(|s| s.contribution)
            .sum();
        assert!((total - 1.0).abs() < 1e-9);
    }
}
