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
// Layer 2: SLSA Hardening
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

/// SLSA build metadata for attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaBuildMetadata {
    pub invocation_id: String,
    pub started_on: i64,
    pub finished_on: i64,
    pub reproducible: bool,
}

/// Full SLSA attestation with computed hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaAttestation {
    pub predicate_type: String,
    pub builder_id: String,
    pub build_type: String,
    pub invocation_config_source: Option<String>,
    pub materials: Vec<SlsaMaterial>,
    pub metadata: SlsaBuildMetadata,
    pub attestation_hash: String,
}

fn compute_attestation_hash(
    builder_id: &str,
    materials: &[SlsaMaterial],
    metadata: &SlsaBuildMetadata,
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(builder_id.as_bytes());
    for m in materials {
        hasher.update(m.uri.as_bytes());
        let mut digests: Vec<_> = m.digest.iter().collect();
        digests.sort_by_key(|(k, _)| k.clone());
        for (algo, hash) in digests {
            hasher.update(algo.as_bytes());
            hasher.update(hash.as_bytes());
        }
    }
    hasher.update(metadata.invocation_id.as_bytes());
    hasher.update(metadata.started_on.to_le_bytes());
    hasher.update(metadata.finished_on.to_le_bytes());
    hex::encode(hasher.finalize())
}

/// Generate an SLSA attestation with computed hash.
pub fn generate_attestation(
    builder_id: &str,
    materials: Vec<SlsaMaterial>,
    metadata: SlsaBuildMetadata,
) -> SlsaAttestation {
    let hash = compute_attestation_hash(builder_id, &materials, &metadata);
    SlsaAttestation {
        predicate_type: "https://slsa.dev/provenance/v1".to_string(),
        builder_id: builder_id.to_string(),
        build_type: "https://slsa.dev/build/v1".to_string(),
        invocation_config_source: None,
        materials,
        metadata,
        attestation_hash: hash,
    }
}

/// Verification result for an SLSA attestation.
#[derive(Debug, Clone)]
pub struct SlsaAttestationVerification {
    pub valid: bool,
    pub hash_verified: bool,
    pub materials_present: bool,
    pub builder_identified: bool,
    pub issues: Vec<String>,
}

/// Verify an SLSA attestation.
pub fn verify_attestation(attestation: &SlsaAttestation) -> SlsaAttestationVerification {
    let mut issues = Vec::new();
    let expected_hash = compute_attestation_hash(
        &attestation.builder_id,
        &attestation.materials,
        &attestation.metadata,
    );
    let hash_verified = expected_hash == attestation.attestation_hash;
    if !hash_verified {
        issues.push("Attestation hash does not match computed hash".into());
    }
    let materials_present = !attestation.materials.is_empty();
    if !materials_present {
        issues.push("No materials listed in attestation".into());
    }
    let builder_identified = !attestation.builder_id.is_empty();
    if !builder_identified {
        issues.push("Builder ID is empty".into());
    }
    SlsaAttestationVerification {
        valid: hash_verified && materials_present && builder_identified,
        hash_verified,
        materials_present,
        builder_identified,
        issues,
    }
}

/// Evidence for a specific SLSA requirement.
#[derive(Debug, Clone)]
pub struct SlsaEvidence {
    pub requirement: String,
    pub satisfied: bool,
    pub detail: String,
}

/// Detailed SLSA level assessment with evidence.
#[derive(Debug, Clone)]
pub struct SlsaLevelEvidence {
    pub assessed_level: SlsaLevel,
    pub evidence: Vec<SlsaEvidence>,
    pub missing_for_next_level: Vec<String>,
}

/// Assess SLSA level with detailed evidence.
pub fn assess_with_evidence(attestation: &SlsaAttestation) -> SlsaLevelEvidence {
    let mut evidence = Vec::new();
    let mut level = SlsaLevel::Level0;

    // L1: Has build provenance
    let has_provenance = !attestation.predicate_type.is_empty();
    evidence.push(SlsaEvidence {
        requirement: "Build provenance exists".into(),
        satisfied: has_provenance,
        detail: if has_provenance { "Attestation predicate present".into() } else { "No predicate type".into() },
    });
    if has_provenance {
        level = SlsaLevel::Level1;
    }

    // L2: Authenticated builder
    let has_builder = !attestation.builder_id.is_empty();
    evidence.push(SlsaEvidence {
        requirement: "Authenticated builder".into(),
        satisfied: has_builder,
        detail: if has_builder { format!("Builder: {}", attestation.builder_id) } else { "No builder ID".into() },
    });
    if has_builder {
        level = SlsaLevel::Level2;
    }

    // L3: Complete provenance + reproducible
    let has_materials = !attestation.materials.is_empty();
    evidence.push(SlsaEvidence {
        requirement: "Complete materials list".into(),
        satisfied: has_materials,
        detail: format!("{} material(s)", attestation.materials.len()),
    });
    let is_reproducible = attestation.metadata.reproducible;
    evidence.push(SlsaEvidence {
        requirement: "Reproducible build".into(),
        satisfied: is_reproducible,
        detail: if is_reproducible { "Build marked reproducible".into() } else { "Build not reproducible".into() },
    });
    if has_builder && has_materials && is_reproducible {
        level = SlsaLevel::Level3;
    }

    // L4: Two-party review (check invocation_config_source as proxy)
    let has_review = attestation.invocation_config_source.is_some();
    evidence.push(SlsaEvidence {
        requirement: "Two-party review".into(),
        satisfied: has_review,
        detail: if has_review { "Config source verified".into() } else { "No two-party review evidence".into() },
    });
    if level == SlsaLevel::Level3 && has_review {
        level = SlsaLevel::Level4;
    }

    let missing = match level {
        SlsaLevel::Level0 => vec!["Build provenance documentation".into()],
        SlsaLevel::Level1 => vec!["Authenticated builder identity".into()],
        SlsaLevel::Level2 => {
            let mut m = Vec::new();
            if !has_materials { m.push("Complete materials list".into()); }
            if !is_reproducible { m.push("Reproducible build".into()); }
            m
        }
        SlsaLevel::Level3 => vec!["Two-party review process".into()],
        SlsaLevel::Level4 => Vec::new(),
    };

    SlsaLevelEvidence {
        assessed_level: level,
        evidence,
        missing_for_next_level: missing,
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    fn test_materials() -> Vec<SlsaMaterial> {
        vec![
            SlsaMaterial::new("https://example.com/src.tar", "sha3-256", "aaa111"),
            SlsaMaterial::new("https://example.com/dep.tar", "sha3-256", "bbb222"),
        ]
    }

    fn test_metadata() -> SlsaBuildMetadata {
        SlsaBuildMetadata {
            invocation_id: "inv-001".into(),
            started_on: 1000,
            finished_on: 2000,
            reproducible: true,
        }
    }

    #[test]
    fn test_generate_attestation_produces_valid_hash() {
        let att = generate_attestation("builder-ci", test_materials(), test_metadata());
        assert_eq!(att.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(att.builder_id, "builder-ci");
        assert!(!att.attestation_hash.is_empty());
        assert_eq!(att.attestation_hash.len(), 64); // SHA3-256 hex
        assert_eq!(att.materials.len(), 2);
    }

    #[test]
    fn test_generate_attestation_deterministic() {
        let a1 = generate_attestation("builder-ci", test_materials(), test_metadata());
        let a2 = generate_attestation("builder-ci", test_materials(), test_metadata());
        assert_eq!(a1.attestation_hash, a2.attestation_hash);
    }

    #[test]
    fn test_verify_attestation_passes() {
        let att = generate_attestation("builder-ci", test_materials(), test_metadata());
        let v = verify_attestation(&att);
        assert!(v.valid);
        assert!(v.hash_verified);
        assert!(v.materials_present);
        assert!(v.builder_identified);
        assert!(v.issues.is_empty());
    }

    #[test]
    fn test_verify_attestation_fails_tampered_hash() {
        let mut att = generate_attestation("builder-ci", test_materials(), test_metadata());
        att.attestation_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();
        let v = verify_attestation(&att);
        assert!(!v.valid);
        assert!(!v.hash_verified);
    }

    #[test]
    fn test_verify_attestation_fails_empty_builder() {
        let att = generate_attestation("", test_materials(), test_metadata());
        let v = verify_attestation(&att);
        assert!(!v.valid);
        assert!(!v.builder_identified);
    }

    #[test]
    fn test_verify_attestation_fails_no_materials() {
        let att = generate_attestation("builder-ci", vec![], test_metadata());
        let v = verify_attestation(&att);
        assert!(!v.valid);
        assert!(!v.materials_present);
    }

    #[test]
    fn test_assess_with_evidence_level3() {
        let att = generate_attestation("builder-ci", test_materials(), test_metadata());
        let ev = assess_with_evidence(&att);
        assert_eq!(ev.assessed_level, SlsaLevel::Level3);
        assert!(!ev.evidence.is_empty());
        assert!(!ev.missing_for_next_level.is_empty());
    }

    #[test]
    fn test_assess_with_evidence_level4() {
        let mut att = generate_attestation("builder-ci", test_materials(), test_metadata());
        att.invocation_config_source = Some("https://github.com/rune/config".into());
        let ev = assess_with_evidence(&att);
        assert_eq!(ev.assessed_level, SlsaLevel::Level4);
        assert!(ev.missing_for_next_level.is_empty());
    }

    #[test]
    fn test_assess_with_evidence_level2_not_reproducible() {
        let meta = SlsaBuildMetadata {
            invocation_id: "inv-002".into(),
            started_on: 1000,
            finished_on: 2000,
            reproducible: false,
        };
        let att = generate_attestation("builder-ci", test_materials(), meta);
        let ev = assess_with_evidence(&att);
        assert_eq!(ev.assessed_level, SlsaLevel::Level2);
    }

    #[test]
    fn test_slsa_build_metadata_construction() {
        let m = test_metadata();
        assert_eq!(m.invocation_id, "inv-001");
        assert_eq!(m.started_on, 1000);
        assert_eq!(m.finished_on, 2000);
        assert!(m.reproducible);
    }
}
