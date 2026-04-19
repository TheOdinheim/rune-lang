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
// Layer 2: Cryptographic Lineage Chains
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

/// Compute SHA3-256 hash for a lineage record.
pub fn compute_record_hash(
    record_id: &str,
    artifact_id: &str,
    input_hash: &str,
    output_hash: &str,
    previous_hash: Option<&str>,
    timestamp: i64,
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(record_id.as_bytes());
    hasher.update(artifact_id.as_bytes());
    hasher.update(input_hash.as_bytes());
    hasher.update(output_hash.as_bytes());
    hasher.update(previous_hash.unwrap_or("").as_bytes());
    hasher.update(timestamp.to_le_bytes());
    hex::encode(hasher.finalize())
}

/// A cryptographically chained lineage record.
#[derive(Debug, Clone)]
pub struct LineageRecord {
    pub record_id: String,
    pub artifact_id: String,
    pub parent_artifact_id: Option<String>,
    pub transformation: String,
    pub actor: String,
    pub timestamp: i64,
    pub input_hash: String,
    pub output_hash: String,
    pub previous_record_hash: Option<String>,
    pub record_hash: String,
}

/// Verification result for a lineage chain.
#[derive(Debug, Clone)]
pub struct LineageChainVerification {
    pub valid: bool,
    pub verified_links: usize,
    pub broken_at: Option<usize>,
    pub chain_root_hash: Option<String>,
    pub chain_tip_hash: Option<String>,
}

/// Cryptographic lineage chain store.
#[derive(Default)]
pub struct LineageChainStore {
    pub records: Vec<LineageRecord>,
    next_id: u64,
}

impl LineageChainStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_record(
        &mut self,
        artifact_id: &str,
        parent_id: Option<&str>,
        transformation: &str,
        actor: &str,
        input_hash: &str,
        output_hash: &str,
        now: i64,
    ) -> &LineageRecord {
        self.next_id += 1;
        let record_id = format!("lr-{}", self.next_id);
        let previous_hash = self.records.last().map(|r| r.record_hash.clone());
        let record_hash = compute_record_hash(
            &record_id,
            artifact_id,
            input_hash,
            output_hash,
            previous_hash.as_deref(),
            now,
        );
        let record = LineageRecord {
            record_id,
            artifact_id: artifact_id.to_string(),
            parent_artifact_id: parent_id.map(|s| s.to_string()),
            transformation: transformation.to_string(),
            actor: actor.to_string(),
            timestamp: now,
            input_hash: input_hash.to_string(),
            output_hash: output_hash.to_string(),
            previous_record_hash: previous_hash,
            record_hash,
        };
        self.records.push(record);
        self.records.last().unwrap()
    }

    pub fn verify_chain(&self) -> LineageChainVerification {
        if self.records.is_empty() {
            return LineageChainVerification {
                valid: true,
                verified_links: 0,
                broken_at: None,
                chain_root_hash: None,
                chain_tip_hash: None,
            };
        }
        let mut verified = 0;
        for (i, record) in self.records.iter().enumerate() {
            let prev_hash = if i == 0 {
                None
            } else {
                Some(self.records[i - 1].record_hash.as_str())
            };
            // Verify the previous_record_hash matches
            if record.previous_record_hash.as_deref() != prev_hash {
                return LineageChainVerification {
                    valid: false,
                    verified_links: verified,
                    broken_at: Some(i),
                    chain_root_hash: Some(self.records[0].record_hash.clone()),
                    chain_tip_hash: Some(self.records.last().unwrap().record_hash.clone()),
                };
            }
            // Re-compute and verify record hash
            let expected = compute_record_hash(
                &record.record_id,
                &record.artifact_id,
                &record.input_hash,
                &record.output_hash,
                prev_hash,
                record.timestamp,
            );
            if expected != record.record_hash {
                return LineageChainVerification {
                    valid: false,
                    verified_links: verified,
                    broken_at: Some(i),
                    chain_root_hash: Some(self.records[0].record_hash.clone()),
                    chain_tip_hash: Some(self.records.last().unwrap().record_hash.clone()),
                };
            }
            verified += 1;
        }
        LineageChainVerification {
            valid: true,
            verified_links: verified,
            broken_at: None,
            chain_root_hash: Some(self.records[0].record_hash.clone()),
            chain_tip_hash: Some(self.records.last().unwrap().record_hash.clone()),
        }
    }

    pub fn chain_length(&self) -> usize {
        self.records.len()
    }

    pub fn records_for_artifact(&self, artifact_id: &str) -> Vec<&LineageRecord> {
        self.records.iter().filter(|r| r.artifact_id == artifact_id).collect()
    }

    /// Trace lineage from root to the given artifact following parent links.
    pub fn full_lineage(&self, artifact_id: &str) -> Vec<&LineageRecord> {
        // Build artifact → record map (latest record per artifact)
        let mut artifact_records: HashMap<&str, &LineageRecord> = HashMap::new();
        for r in &self.records {
            artifact_records.insert(&r.artifact_id, r);
        }
        // Walk backward from artifact through parent_artifact_id
        let mut chain = Vec::new();
        let mut current = artifact_id;
        let mut visited = HashSet::new();
        while let Some(record) = artifact_records.get(current) {
            if !visited.insert(current) {
                break;
            }
            chain.push(*record);
            match &record.parent_artifact_id {
                Some(parent) => current = parent.as_str(),
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    pub fn lineage_depth(&self, artifact_id: &str) -> usize {
        let chain = self.full_lineage(artifact_id);
        if chain.is_empty() { 0 } else { chain.len() - 1 }
    }

    pub fn common_ancestor(&self, artifact_a: &str, artifact_b: &str) -> Option<String> {
        let chain_a: Vec<String> = self.full_lineage(artifact_a)
            .iter().map(|r| r.artifact_id.clone()).collect();
        let chain_b: Vec<String> = self.full_lineage(artifact_b)
            .iter().map(|r| r.artifact_id.clone()).collect();
        let set_a: HashSet<&String> = chain_a.iter().collect();
        // Walk chain_b from root and find last common element
        let mut ancestor = None;
        for id in &chain_b {
            if set_a.contains(id) {
                ancestor = Some(id.clone());
            }
        }
        ancestor
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_lineage_chain_append_creates_chained() {
        let mut store = LineageChainStore::new();
        let r1 = store.append_record("a1", None, "ingest", "alice", "h_in1", "h_out1", 1000);
        assert!(r1.previous_record_hash.is_none());
        let r1_hash = r1.record_hash.clone();
        let r2 = store.append_record("a2", Some("a1"), "transform", "bob", "h_out1", "h_out2", 2000);
        assert_eq!(r2.previous_record_hash.as_deref(), Some(r1_hash.as_str()));
    }

    #[test]
    fn test_lineage_chain_verify_valid() {
        let mut store = LineageChainStore::new();
        store.append_record("a1", None, "ingest", "alice", "h1", "h2", 1000);
        store.append_record("a2", Some("a1"), "transform", "bob", "h2", "h3", 2000);
        let v = store.verify_chain();
        assert!(v.valid);
        assert_eq!(v.verified_links, 2);
        assert!(v.broken_at.is_none());
    }

    #[test]
    fn test_lineage_chain_verify_tampered() {
        let mut store = LineageChainStore::new();
        store.append_record("a1", None, "ingest", "alice", "h1", "h2", 1000);
        store.append_record("a2", Some("a1"), "transform", "bob", "h2", "h3", 2000);
        // Tamper with first record
        store.records[0].record_hash = "tampered".to_string();
        let v = store.verify_chain();
        assert!(!v.valid);
    }

    #[test]
    fn test_lineage_chain_records_for_artifact() {
        let mut store = LineageChainStore::new();
        store.append_record("a1", None, "ingest", "alice", "h1", "h2", 1000);
        store.append_record("a2", Some("a1"), "t", "bob", "h2", "h3", 2000);
        store.append_record("a1", None, "re-ingest", "alice", "h4", "h5", 3000);
        assert_eq!(store.records_for_artifact("a1").len(), 2);
    }

    #[test]
    fn test_compute_record_hash_deterministic() {
        let h1 = compute_record_hash("r1", "a1", "in", "out", None, 1000);
        let h2 = compute_record_hash("r1", "a1", "in", "out", None, 1000);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_full_lineage() {
        let mut store = LineageChainStore::new();
        store.append_record("root", None, "create", "alice", "h0", "h1", 1000);
        store.append_record("mid", Some("root"), "transform", "bob", "h1", "h2", 2000);
        store.append_record("leaf", Some("mid"), "refine", "charlie", "h2", "h3", 3000);
        let chain = store.full_lineage("leaf");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].artifact_id, "root");
        assert_eq!(chain[2].artifact_id, "leaf");
    }

    #[test]
    fn test_lineage_depth() {
        let mut store = LineageChainStore::new();
        store.append_record("root", None, "create", "alice", "h0", "h1", 1000);
        store.append_record("mid", Some("root"), "t", "bob", "h1", "h2", 2000);
        store.append_record("leaf", Some("mid"), "t", "charlie", "h2", "h3", 3000);
        assert_eq!(store.lineage_depth("root"), 0);
        assert_eq!(store.lineage_depth("leaf"), 2);
    }

    #[test]
    fn test_common_ancestor() {
        let mut store = LineageChainStore::new();
        store.append_record("root", None, "create", "alice", "h0", "h1", 1000);
        store.append_record("branch_a", Some("root"), "t", "bob", "h1", "h2", 2000);
        store.append_record("branch_b", Some("root"), "t", "charlie", "h1", "h3", 3000);
        let ancestor = store.common_ancestor("branch_a", "branch_b");
        assert_eq!(ancestor.as_deref(), Some("root"));
    }

    #[test]
    fn test_common_ancestor_none() {
        let mut store = LineageChainStore::new();
        store.append_record("a", None, "create", "alice", "h0", "h1", 1000);
        store.append_record("b", None, "create", "bob", "h2", "h3", 2000);
        assert!(store.common_ancestor("a", "b").is_none());
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
