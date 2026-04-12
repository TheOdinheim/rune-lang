// ═══════════════════════════════════════════════════════════════════════
// Artifact — versioned, hash-identified artifacts with a type taxonomy.
//
// Every provenance-tracked item is an Artifact: datasets, models, code,
// policies, reports. ArtifactVersion follows semver ordering. ArtifactStore
// provides registration, version chains, and tag-based search.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::ProvenanceError;

// ── ArtifactId ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

impl ArtifactId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ArtifactType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    Dataset,
    Model,
    ModelArchitecture,
    Configuration,
    Code,
    Policy,
    Report,
    Certificate,
    Checkpoint,
    Pipeline,
    Custom(String),
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dataset => f.write_str("dataset"),
            Self::Model => f.write_str("model"),
            Self::ModelArchitecture => f.write_str("model-architecture"),
            Self::Configuration => f.write_str("configuration"),
            Self::Code => f.write_str("code"),
            Self::Policy => f.write_str("policy"),
            Self::Report => f.write_str("report"),
            Self::Certificate => f.write_str("certificate"),
            Self::Checkpoint => f.write_str("checkpoint"),
            Self::Pipeline => f.write_str("pipeline"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── ArtifactVersion ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
    pub build_metadata: Option<String>,
}

impl ArtifactVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            prerelease: None,
            build_metadata: None,
        }
    }

    pub fn initial() -> Self {
        Self::new(0, 1, 0)
    }

    pub fn with_prerelease(mut self, pre: impl Into<String>) -> Self {
        self.prerelease = Some(pre.into());
        self
    }

    pub fn with_build_metadata(mut self, meta: impl Into<String>) -> Self {
        self.build_metadata = Some(meta.into());
        self
    }

    pub fn bump_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }

    pub fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }

    pub fn bump_patch(&self) -> Self {
        Self::new(self.major, self.minor, self.patch + 1)
    }
}

impl Ord for ArtifactVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| {
                // A version with a prerelease tag has lower precedence.
                match (&self.prerelease, &other.prerelease) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (Some(a), Some(b)) => a.cmp(b),
                }
            })
    }
}

impl PartialOrd for ArtifactVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ArtifactVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.prerelease {
            write!(f, "-{pre}")?;
        }
        if let Some(meta) = &self.build_metadata {
            write!(f, "+{meta}")?;
        }
        Ok(())
    }
}

// ── Artifact ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Artifact {
    pub id: ArtifactId,
    pub name: String,
    pub artifact_type: ArtifactType,
    pub version: ArtifactVersion,
    pub content_hash: String,
    pub size_bytes: Option<u64>,
    pub created_at: i64,
    pub created_by: String,
    pub description: String,
    pub tags: HashMap<String, String>,
    pub parent_id: Option<ArtifactId>,
    pub metadata: HashMap<String, String>,
}

impl Artifact {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        artifact_type: ArtifactType,
        version: ArtifactVersion,
        content_hash: impl Into<String>,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            id: ArtifactId::new(id),
            name: name.into(),
            artifact_type,
            version,
            content_hash: content_hash.into(),
            size_bytes: None,
            created_at,
            created_by: created_by.into(),
            description: String::new(),
            tags: HashMap::new(),
            parent_id: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn with_tag(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.tags.insert(k.into(), v.into());
        self
    }

    pub fn with_parent(mut self, parent: ArtifactId) -> Self {
        self.parent_id = Some(parent);
        self
    }

    pub fn with_size(mut self, bytes: u64) -> Self {
        self.size_bytes = Some(bytes);
        self
    }
}

// ── ArtifactStore ─────────────────────────────────────────────────────

#[derive(Default)]
pub struct ArtifactStore {
    pub artifacts: HashMap<ArtifactId, Artifact>,
    pub version_chains: HashMap<String, Vec<ArtifactId>>,
}

impl ArtifactStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, artifact: Artifact) -> Result<(), ProvenanceError> {
        if self.artifacts.contains_key(&artifact.id) {
            return Err(ProvenanceError::ArtifactAlreadyExists(artifact.id.0.clone()));
        }
        let name = artifact.name.clone();
        let id = artifact.id.clone();
        self.artifacts.insert(id.clone(), artifact);
        self.version_chains.entry(name).or_default().push(id);
        Ok(())
    }

    pub fn get(&self, id: &ArtifactId) -> Option<&Artifact> {
        self.artifacts.get(id)
    }

    pub fn latest_version(&self, name: &str) -> Option<&Artifact> {
        self.version_chains
            .get(name)?
            .iter()
            .filter_map(|id| self.artifacts.get(id))
            .max_by(|a, b| a.version.cmp(&b.version))
    }

    pub fn all_versions(&self, name: &str) -> Vec<&Artifact> {
        let mut v: Vec<&Artifact> = self
            .version_chains
            .get(name)
            .map(|ids| ids.iter().filter_map(|id| self.artifacts.get(id)).collect())
            .unwrap_or_default();
        v.sort_by(|a, b| a.version.cmp(&b.version));
        v
    }

    pub fn by_type(&self, artifact_type: &ArtifactType) -> Vec<&Artifact> {
        self.artifacts
            .values()
            .filter(|a| &a.artifact_type == artifact_type)
            .collect()
    }

    pub fn by_creator(&self, creator: &str) -> Vec<&Artifact> {
        self.artifacts
            .values()
            .filter(|a| a.created_by == creator)
            .collect()
    }

    pub fn verify_hash(&self, id: &ArtifactId, content_hash: &str) -> bool {
        self.artifacts
            .get(id)
            .map(|a| a.content_hash == content_hash)
            .unwrap_or(false)
    }

    pub fn count(&self) -> usize {
        self.artifacts.len()
    }

    pub fn search_tags(&self, key: &str, value: &str) -> Vec<&Artifact> {
        self.artifacts
            .values()
            .filter(|a| a.tags.get(key).map(|v| v == value).unwrap_or(false))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset(id: &str, version: ArtifactVersion) -> Artifact {
        Artifact::new(id, "dataset-x", ArtifactType::Dataset, version, "hash123", "alice", 1000)
    }

    #[test]
    fn test_artifact_id_display() {
        let id = ArtifactId::new("art:model-v1");
        assert_eq!(id.to_string(), "art:model-v1");
    }

    #[test]
    fn test_artifact_type_display() {
        assert_eq!(ArtifactType::Dataset.to_string(), "dataset");
        assert_eq!(ArtifactType::Model.to_string(), "model");
        assert_eq!(ArtifactType::ModelArchitecture.to_string(), "model-architecture");
        assert_eq!(ArtifactType::Configuration.to_string(), "configuration");
        assert_eq!(ArtifactType::Code.to_string(), "code");
        assert_eq!(ArtifactType::Policy.to_string(), "policy");
        assert_eq!(ArtifactType::Report.to_string(), "report");
        assert_eq!(ArtifactType::Certificate.to_string(), "certificate");
        assert_eq!(ArtifactType::Checkpoint.to_string(), "checkpoint");
        assert_eq!(ArtifactType::Pipeline.to_string(), "pipeline");
        assert_eq!(ArtifactType::Custom("x".into()).to_string(), "custom:x");
    }

    #[test]
    fn test_version_display() {
        assert_eq!(ArtifactVersion::new(1, 2, 3).to_string(), "1.2.3");
        assert_eq!(
            ArtifactVersion::new(1, 2, 3).with_prerelease("alpha").to_string(),
            "1.2.3-alpha"
        );
        assert_eq!(
            ArtifactVersion::new(1, 2, 3)
                .with_prerelease("rc1")
                .with_build_metadata("build.42")
                .to_string(),
            "1.2.3-rc1+build.42"
        );
    }

    #[test]
    fn test_version_ordering() {
        let v100 = ArtifactVersion::new(1, 0, 0);
        let v101 = ArtifactVersion::new(1, 0, 1);
        let v110 = ArtifactVersion::new(1, 1, 0);
        let v200 = ArtifactVersion::new(2, 0, 0);
        assert!(v100 < v101);
        assert!(v101 < v110);
        assert!(v110 < v200);
    }

    #[test]
    fn test_prerelease_lower_precedence() {
        let release = ArtifactVersion::new(1, 0, 0);
        let alpha = ArtifactVersion::new(1, 0, 0).with_prerelease("alpha");
        assert!(alpha < release);
    }

    #[test]
    fn test_version_bump() {
        let v = ArtifactVersion::new(1, 2, 3);
        assert_eq!(v.bump_major(), ArtifactVersion::new(2, 0, 0));
        assert_eq!(v.bump_minor(), ArtifactVersion::new(1, 3, 0));
        assert_eq!(v.bump_patch(), ArtifactVersion::new(1, 2, 4));
    }

    #[test]
    fn test_version_initial() {
        assert_eq!(ArtifactVersion::initial(), ArtifactVersion::new(0, 1, 0));
    }

    #[test]
    fn test_store_register_and_get() {
        let mut s = ArtifactStore::new();
        let a = dataset("d1", ArtifactVersion::new(1, 0, 0));
        s.register(a).unwrap();
        assert!(s.get(&ArtifactId::new("d1")).is_some());
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn test_store_duplicate_fails() {
        let mut s = ArtifactStore::new();
        s.register(dataset("d1", ArtifactVersion::new(1, 0, 0))).unwrap();
        let err = s.register(dataset("d1", ArtifactVersion::new(1, 0, 1))).unwrap_err();
        assert!(matches!(err, ProvenanceError::ArtifactAlreadyExists(_)));
    }

    #[test]
    fn test_store_latest_version() {
        let mut s = ArtifactStore::new();
        s.register(dataset("d1-v1", ArtifactVersion::new(1, 0, 0))).unwrap();
        s.register(dataset("d1-v2", ArtifactVersion::new(2, 0, 0))).unwrap();
        let latest = s.latest_version("dataset-x").unwrap();
        assert_eq!(latest.version, ArtifactVersion::new(2, 0, 0));
    }

    #[test]
    fn test_store_all_versions_sorted() {
        let mut s = ArtifactStore::new();
        s.register(dataset("v2", ArtifactVersion::new(2, 0, 0))).unwrap();
        s.register(dataset("v1", ArtifactVersion::new(1, 0, 0))).unwrap();
        let all = s.all_versions("dataset-x");
        assert_eq!(all.len(), 2);
        assert!(all[0].version < all[1].version);
    }

    #[test]
    fn test_store_by_type() {
        let mut s = ArtifactStore::new();
        s.register(dataset("d1", ArtifactVersion::new(1, 0, 0))).unwrap();
        s.register(Artifact::new("m1", "model-y", ArtifactType::Model, ArtifactVersion::new(1, 0, 0), "h", "b", 1))
            .unwrap();
        assert_eq!(s.by_type(&ArtifactType::Dataset).len(), 1);
        assert_eq!(s.by_type(&ArtifactType::Model).len(), 1);
    }

    #[test]
    fn test_store_verify_hash() {
        let mut s = ArtifactStore::new();
        s.register(dataset("d1", ArtifactVersion::new(1, 0, 0))).unwrap();
        assert!(s.verify_hash(&ArtifactId::new("d1"), "hash123"));
        assert!(!s.verify_hash(&ArtifactId::new("d1"), "wrong"));
        assert!(!s.verify_hash(&ArtifactId::new("missing"), "hash123"));
    }

    #[test]
    fn test_store_search_tags() {
        let mut s = ArtifactStore::new();
        s.register(
            dataset("d1", ArtifactVersion::new(1, 0, 0)).with_tag("env", "prod"),
        )
        .unwrap();
        s.register(
            dataset("d2", ArtifactVersion::new(1, 0, 1)).with_tag("env", "staging"),
        )
        .unwrap();
        assert_eq!(s.search_tags("env", "prod").len(), 1);
    }

    #[test]
    fn test_artifact_builders() {
        let a = Artifact::new("a1", "n", ArtifactType::Code, ArtifactVersion::initial(), "h", "c", 1)
            .with_description("desc")
            .with_tag("k", "v")
            .with_parent(ArtifactId::new("a0"))
            .with_size(1024);
        assert_eq!(a.description, "desc");
        assert_eq!(a.tags.get("k").map(String::as_str), Some("v"));
        assert_eq!(a.parent_id, Some(ArtifactId::new("a0")));
        assert_eq!(a.size_bytes, Some(1024));
    }
}
