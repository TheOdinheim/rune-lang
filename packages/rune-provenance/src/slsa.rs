// ═══════════════════════════════════════════════════════════════════════
// SLSA — Supply-chain Levels for Software Artifacts provenance predicates.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;

// ── SlsaLevel ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SlsaLevel {
    Level0 = 0,
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
    Level4 = 4,
}

impl fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Level0 => f.write_str("SLSA L0"),
            Self::Level1 => f.write_str("SLSA L1"),
            Self::Level2 => f.write_str("SLSA L2"),
            Self::Level3 => f.write_str("SLSA L3"),
            Self::Level4 => f.write_str("SLSA L4"),
        }
    }
}

// ── SlsaCompleteness ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaCompleteness {
    pub parameters: bool,
    pub environment: bool,
    pub materials: bool,
}

impl SlsaCompleteness {
    pub fn all_complete() -> Self {
        Self {
            parameters: true,
            environment: true,
            materials: true,
        }
    }

    pub fn incomplete() -> Self {
        Self {
            parameters: false,
            environment: false,
            materials: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.parameters && self.environment && self.materials
    }
}

// ── BuildInvocation ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInvocation {
    pub config_source: String,
    pub parameters: HashMap<String, String>,
    pub environment: Option<HashMap<String, String>>,
}

// ── SlsaMaterial ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaMaterial {
    pub uri: String,
    pub digest: HashMap<String, String>,
}

impl SlsaMaterial {
    pub fn new(uri: impl Into<String>, algorithm: impl Into<String>, hash: impl Into<String>) -> Self {
        let mut digest = HashMap::new();
        digest.insert(algorithm.into(), hash.into());
        Self {
            uri: uri.into(),
            digest,
        }
    }
}

// ── SlsaMetadata ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaMetadata {
    pub build_started_at: Option<i64>,
    pub build_completed_at: Option<i64>,
    pub completeness: SlsaCompleteness,
    pub reproducible: bool,
}

impl SlsaMetadata {
    pub fn basic() -> Self {
        Self {
            build_started_at: None,
            build_completed_at: None,
            completeness: SlsaCompleteness::incomplete(),
            reproducible: false,
        }
    }
}

// ── SlsaPredicate ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaPredicate {
    pub build_type: String,
    pub builder_id: String,
    pub invocation: BuildInvocation,
    pub materials: Vec<SlsaMaterial>,
    pub metadata: SlsaMetadata,
}

impl SlsaPredicate {
    pub fn new(
        build_type: impl Into<String>,
        builder_id: impl Into<String>,
        invocation: BuildInvocation,
        metadata: SlsaMetadata,
    ) -> Self {
        Self {
            build_type: build_type.into(),
            builder_id: builder_id.into(),
            invocation,
            materials: Vec::new(),
            metadata,
        }
    }

    pub fn with_material(mut self, material: SlsaMaterial) -> Self {
        self.materials.push(material);
        self
    }
}

// ── SlsaProvenanceStore ───────────────────────────────────────────────

#[derive(Default)]
pub struct SlsaProvenanceStore {
    pub predicates: HashMap<ArtifactId, SlsaPredicate>,
}

impl SlsaProvenanceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, artifact_id: ArtifactId, predicate: SlsaPredicate) {
        self.predicates.insert(artifact_id, predicate);
    }

    pub fn get(&self, artifact_id: &ArtifactId) -> Option<&SlsaPredicate> {
        self.predicates.get(artifact_id)
    }

    /// Assess SLSA level from predicate completeness.
    pub fn assess_level(&self, artifact_id: &ArtifactId) -> SlsaLevel {
        let pred = match self.predicates.get(artifact_id) {
            None => return SlsaLevel::Level0,
            Some(p) => p,
        };
        // Level1: has a predicate at all (documentation of build process)
        if pred.builder_id.is_empty() {
            return SlsaLevel::Level1;
        }
        // Level2: has authenticated builder_id
        if !pred.metadata.completeness.is_complete() || !pred.metadata.reproducible {
            return SlsaLevel::Level2;
        }
        // Level3: completeness all true + reproducible
        // Level4 requires two-party review (check for it in metadata invocation parameters)
        let has_review = pred
            .invocation
            .parameters
            .get("two_party_review")
            .map(|v| v == "true")
            .unwrap_or(false);
        if has_review {
            SlsaLevel::Level4
        } else {
            SlsaLevel::Level3
        }
    }

    pub fn artifacts_at_level(&self, level: SlsaLevel) -> Vec<&ArtifactId> {
        // For Level0 we need to know which artifacts don't have predicates;
        // this store only tracks artifacts WITH predicates, so Level0 is
        // external and we return all predicates *at exactly* the given level.
        self.predicates
            .keys()
            .filter(|id| self.assess_level(id) == level)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.predicates.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_invocation() -> BuildInvocation {
        BuildInvocation {
            config_source: "https://github.com/rune-lang/rune".into(),
            parameters: HashMap::new(),
            environment: None,
        }
    }

    fn basic_predicate() -> SlsaPredicate {
        SlsaPredicate::new(
            "https://rune-lang.org/build/v1",
            "rune-ci",
            basic_invocation(),
            SlsaMetadata::basic(),
        )
    }

    fn complete_predicate() -> SlsaPredicate {
        SlsaPredicate::new(
            "https://rune-lang.org/build/v1",
            "rune-ci",
            basic_invocation(),
            SlsaMetadata {
                build_started_at: Some(1000),
                build_completed_at: Some(2000),
                completeness: SlsaCompleteness::all_complete(),
                reproducible: true,
            },
        )
    }

    #[test]
    fn test_slsa_level_ordering() {
        assert!(SlsaLevel::Level0 < SlsaLevel::Level1);
        assert!(SlsaLevel::Level1 < SlsaLevel::Level2);
        assert!(SlsaLevel::Level2 < SlsaLevel::Level3);
        assert!(SlsaLevel::Level3 < SlsaLevel::Level4);
    }

    #[test]
    fn test_slsa_level_display() {
        assert_eq!(SlsaLevel::Level0.to_string(), "SLSA L0");
        assert_eq!(SlsaLevel::Level4.to_string(), "SLSA L4");
    }

    #[test]
    fn test_record_and_get() {
        let mut store = SlsaProvenanceStore::new();
        store.record(ArtifactId::new("a1"), basic_predicate());
        assert!(store.get(&ArtifactId::new("a1")).is_some());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_assess_level0_missing() {
        let store = SlsaProvenanceStore::new();
        assert_eq!(store.assess_level(&ArtifactId::new("missing")), SlsaLevel::Level0);
    }

    #[test]
    fn test_assess_level1_basic() {
        let mut store = SlsaProvenanceStore::new();
        let mut pred = basic_predicate();
        pred.builder_id.clear();
        store.record(ArtifactId::new("a1"), pred);
        assert_eq!(store.assess_level(&ArtifactId::new("a1")), SlsaLevel::Level1);
    }

    #[test]
    fn test_assess_level2_with_builder() {
        let mut store = SlsaProvenanceStore::new();
        store.record(ArtifactId::new("a1"), basic_predicate());
        assert_eq!(store.assess_level(&ArtifactId::new("a1")), SlsaLevel::Level2);
    }

    #[test]
    fn test_assess_level3_complete_reproducible() {
        let mut store = SlsaProvenanceStore::new();
        store.record(ArtifactId::new("a1"), complete_predicate());
        assert_eq!(store.assess_level(&ArtifactId::new("a1")), SlsaLevel::Level3);
    }

    #[test]
    fn test_assess_level4_two_party_review() {
        let mut store = SlsaProvenanceStore::new();
        let mut pred = complete_predicate();
        pred.invocation.parameters.insert("two_party_review".into(), "true".into());
        store.record(ArtifactId::new("a1"), pred);
        assert_eq!(store.assess_level(&ArtifactId::new("a1")), SlsaLevel::Level4);
    }

    #[test]
    fn test_artifacts_at_level() {
        let mut store = SlsaProvenanceStore::new();
        store.record(ArtifactId::new("a1"), basic_predicate());
        store.record(ArtifactId::new("a2"), complete_predicate());
        assert_eq!(store.artifacts_at_level(SlsaLevel::Level2).len(), 1);
        assert_eq!(store.artifacts_at_level(SlsaLevel::Level3).len(), 1);
    }

    #[test]
    fn test_completeness() {
        assert!(SlsaCompleteness::all_complete().is_complete());
        assert!(!SlsaCompleteness::incomplete().is_complete());
    }

    #[test]
    fn test_material_construction() {
        let m = SlsaMaterial::new("https://example.com/data.tar", "sha3-256", "abc123");
        assert_eq!(m.digest.get("sha3-256").map(String::as_str), Some("abc123"));
    }
}
