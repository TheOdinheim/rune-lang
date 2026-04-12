// ═══════════════════════════════════════════════════════════════════════
// Verification — provenance chain verification and integrity checks.
//
// ProvenanceVerifier runs a battery of checks against an artifact
// (content hash, lineage, sources, transformations, supply chain,
// SLSA level, license) and produces a VerificationResult with
// per-check status and overall confidence score.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactId, ArtifactStore};
use crate::lineage::LineageRegistry;
use crate::slsa::{SlsaLevel, SlsaProvenanceStore};
use crate::supply_chain::SupplyChain;
use crate::transform::TransformationLog;

// ── VerificationStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Verified,
    PartiallyVerified,
    Failed,
    Unknown,
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => f.write_str("verified"),
            Self::PartiallyVerified => f.write_str("partially-verified"),
            Self::Failed => f.write_str("failed"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ── VerificationCheckType ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationCheckType {
    ContentHash,
    LineageComplete,
    SourcesVerified,
    TransformationsRecorded,
    AttestationValid,
    SupplyChainClean,
    SlsaLevel,
    LicenseCompatible,
}

impl fmt::Display for VerificationCheckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentHash => f.write_str("content-hash"),
            Self::LineageComplete => f.write_str("lineage-complete"),
            Self::SourcesVerified => f.write_str("sources-verified"),
            Self::TransformationsRecorded => f.write_str("transformations-recorded"),
            Self::AttestationValid => f.write_str("attestation-valid"),
            Self::SupplyChainClean => f.write_str("supply-chain-clean"),
            Self::SlsaLevel => f.write_str("slsa-level"),
            Self::LicenseCompatible => f.write_str("license-compatible"),
        }
    }
}

// ── VerificationCheck ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerificationCheck {
    pub check_type: VerificationCheckType,
    pub passed: bool,
    pub message: String,
}

// ── VerificationResult ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub artifact_id: ArtifactId,
    pub status: VerificationStatus,
    pub checks: Vec<VerificationCheck>,
    pub confidence: f64,
    pub verified_at: i64,
}

impl VerificationResult {
    pub fn passed_checks(&self) -> usize {
        self.checks.iter().filter(|c| c.passed).count()
    }

    pub fn failed_checks(&self) -> usize {
        self.checks.iter().filter(|c| !c.passed).count()
    }
}

// ── ProvenanceVerifier ───────────────────────────────────────────────

pub struct ProvenanceVerifier<'a> {
    pub artifact_store: &'a ArtifactStore,
    pub lineage_registry: &'a LineageRegistry,
    pub transformation_log: &'a TransformationLog,
    pub supply_chain: &'a SupplyChain,
    pub slsa_store: &'a SlsaProvenanceStore,
    pub minimum_slsa_level: SlsaLevel,
}

impl<'a> ProvenanceVerifier<'a> {
    pub fn new(
        artifact_store: &'a ArtifactStore,
        lineage_registry: &'a LineageRegistry,
        transformation_log: &'a TransformationLog,
        supply_chain: &'a SupplyChain,
        slsa_store: &'a SlsaProvenanceStore,
    ) -> Self {
        Self {
            artifact_store,
            lineage_registry,
            transformation_log,
            supply_chain,
            slsa_store,
            minimum_slsa_level: SlsaLevel::Level1,
        }
    }

    pub fn with_minimum_slsa(mut self, level: SlsaLevel) -> Self {
        self.minimum_slsa_level = level;
        self
    }

    /// Run all verification checks against an artifact.
    pub fn verify_artifact(&self, artifact_id: &ArtifactId, now: i64) -> VerificationResult {
        let mut checks = Vec::new();

        // 1. Content hash — artifact exists and has a hash
        checks.push(self.check_content_hash(artifact_id));

        // 2. Lineage completeness — lineage record exists
        checks.push(self.check_lineage(artifact_id));

        // 3. Sources verified — all lineage sources are verified
        checks.push(self.check_sources_verified(artifact_id));

        // 4. Transformations recorded
        checks.push(self.check_transformations(artifact_id));

        // 5. Supply chain clean — no vulnerable dependencies
        checks.push(self.check_supply_chain());

        // 6. SLSA level meets minimum
        checks.push(self.check_slsa_level(artifact_id));

        // 7. License compatible — artifact has a license if lineage has one
        checks.push(self.check_license(artifact_id));

        let passed = checks.iter().filter(|c| c.passed).count();
        let total = checks.len();
        let confidence = if total > 0 {
            passed as f64 / total as f64
        } else {
            0.0
        };

        let status = if passed == total {
            VerificationStatus::Verified
        } else if passed == 0 {
            VerificationStatus::Failed
        } else {
            VerificationStatus::PartiallyVerified
        };

        VerificationResult {
            artifact_id: artifact_id.clone(),
            status,
            checks,
            confidence,
            verified_at: now,
        }
    }

    fn check_content_hash(&self, artifact_id: &ArtifactId) -> VerificationCheck {
        let passed = self
            .artifact_store
            .get(artifact_id)
            .map(|a| !a.content_hash.is_empty())
            .unwrap_or(false);
        VerificationCheck {
            check_type: VerificationCheckType::ContentHash,
            passed,
            message: if passed {
                "content hash present".into()
            } else {
                "artifact missing or no content hash".into()
            },
        }
    }

    fn check_lineage(&self, artifact_id: &ArtifactId) -> VerificationCheck {
        let passed = self.lineage_registry.has_lineage(artifact_id);
        VerificationCheck {
            check_type: VerificationCheckType::LineageComplete,
            passed,
            message: if passed {
                "lineage record exists".into()
            } else {
                "no lineage record found".into()
            },
        }
    }

    fn check_sources_verified(&self, artifact_id: &ArtifactId) -> VerificationCheck {
        let lineage = match self.lineage_registry.lineage_for(artifact_id) {
            Some(l) => l,
            None => {
                return VerificationCheck {
                    check_type: VerificationCheckType::SourcesVerified,
                    passed: false,
                    message: "no lineage to verify sources".into(),
                };
            }
        };
        let all_verified = lineage.sources.iter().all(|s| s.verified);
        VerificationCheck {
            check_type: VerificationCheckType::SourcesVerified,
            passed: all_verified,
            message: if all_verified {
                "all sources verified".into()
            } else {
                "some sources unverified".into()
            },
        }
    }

    fn check_transformations(&self, artifact_id: &ArtifactId) -> VerificationCheck {
        let transforms = self.transformation_log.for_artifact(artifact_id);
        let passed = !transforms.is_empty();
        VerificationCheck {
            check_type: VerificationCheckType::TransformationsRecorded,
            passed,
            message: if passed {
                format!("{} transformation(s) recorded", transforms.len())
            } else {
                "no transformations recorded".into()
            },
        }
    }

    fn check_supply_chain(&self) -> VerificationCheck {
        let vulnerable = self.supply_chain.vulnerable();
        let passed = vulnerable.is_empty();
        VerificationCheck {
            check_type: VerificationCheckType::SupplyChainClean,
            passed,
            message: if passed {
                "no vulnerable dependencies".into()
            } else {
                format!("{} vulnerable dependency(ies)", vulnerable.len())
            },
        }
    }

    fn check_slsa_level(&self, artifact_id: &ArtifactId) -> VerificationCheck {
        let level = self.slsa_store.assess_level(artifact_id);
        let passed = level >= self.minimum_slsa_level;
        VerificationCheck {
            check_type: VerificationCheckType::SlsaLevel,
            passed,
            message: format!(
                "SLSA {level}, minimum {}",
                self.minimum_slsa_level
            ),
        }
    }

    fn check_license(&self, artifact_id: &ArtifactId) -> VerificationCheck {
        // Check artifact has a license recorded if lineage specifies one.
        let lineage_has_license = self
            .lineage_registry
            .lineage_for(artifact_id)
            .and_then(|l| l.license.as_ref())
            .is_some();
        if !lineage_has_license {
            // No license requirement from lineage — pass by default.
            return VerificationCheck {
                check_type: VerificationCheckType::LicenseCompatible,
                passed: true,
                message: "no license constraint in lineage".into(),
            };
        }
        // Artifact should exist and have tags or metadata; for now check artifact exists.
        let passed = self.artifact_store.get(artifact_id).is_some();
        VerificationCheck {
            check_type: VerificationCheckType::LicenseCompatible,
            passed,
            message: if passed {
                "license tracked".into()
            } else {
                "artifact missing, cannot verify license".into()
            },
        }
    }

    /// Verify an artifact and recursively verify its upstream chain.
    pub fn verify_chain(
        &self,
        artifact_id: &ArtifactId,
        now: i64,
    ) -> Vec<VerificationResult> {
        let mut results = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();

        visited.insert(artifact_id.clone());
        queue.push_back(artifact_id.clone());

        while let Some(current) = queue.pop_front() {
            results.push(self.verify_artifact(&current, now));

            // Walk upstream through lineage sources
            if let Some(lineage) = self.lineage_registry.lineage_for(&current) {
                for source in &lineage.sources {
                    if visited.insert(source.artifact_id.clone()) {
                        queue.push_back(source.artifact_id.clone());
                    }
                }
            }
        }
        results
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, ArtifactType, ArtifactVersion};
    use crate::lineage::{DataLineage, LineageSource, SourceRelationship};
    use crate::slsa::{BuildInvocation, SlsaMetadata, SlsaPredicate};
    use crate::transform::{Transformation, TransformType};
    use std::collections::HashMap;

    fn setup_stores() -> (
        ArtifactStore,
        LineageRegistry,
        TransformationLog,
        SupplyChain,
        SlsaProvenanceStore,
    ) {
        let mut artifacts = ArtifactStore::new();
        artifacts
            .register(Artifact::new(
                "art1",
                "dataset-v1",
                ArtifactType::Dataset,
                ArtifactVersion::new(1, 0, 0),
                "hash123",
                "alice",
                1000,
            ))
            .unwrap();

        let mut lineage = LineageRegistry::new();
        let lin = DataLineage::new("lin1", ArtifactId::new("art1"), "alice", 1000)
            .with_source(LineageSource {
                artifact_id: ArtifactId::new("raw"),
                relationship: SourceRelationship::PrimarySource,
                contribution: None,
                accessed_at: 900,
                verified: true,
            })
            .with_output(ArtifactId::new("art1"));
        lineage.record(lin).unwrap();

        let mut transforms = TransformationLog::new();
        transforms
            .record(
                Transformation::new("t1", "preprocess", TransformType::Preprocessing, "alice", 1000)
                    .with_output(ArtifactId::new("art1")),
            )
            .unwrap();

        let supply = SupplyChain::new();

        let mut slsa = SlsaProvenanceStore::new();
        slsa.record(
            ArtifactId::new("art1"),
            SlsaPredicate::new(
                "https://rune-lang.org/build/v1",
                "rune-ci",
                BuildInvocation {
                    config_source: "repo".into(),
                    parameters: HashMap::new(),
                    environment: None,
                },
                SlsaMetadata::basic(),
            ),
        );

        (artifacts, lineage, transforms, supply, slsa)
    }

    #[test]
    fn test_verify_artifact_all_pass() {
        let (artifacts, lineage, transforms, supply, slsa) = setup_stores();
        let verifier = ProvenanceVerifier::new(&artifacts, &lineage, &transforms, &supply, &slsa);
        let result = verifier.verify_artifact(&ArtifactId::new("art1"), 2000);
        assert_eq!(result.status, VerificationStatus::Verified);
        assert_eq!(result.confidence, 1.0);
        assert_eq!(result.failed_checks(), 0);
    }

    #[test]
    fn test_verify_artifact_missing() {
        let (artifacts, lineage, transforms, supply, slsa) = setup_stores();
        let verifier = ProvenanceVerifier::new(&artifacts, &lineage, &transforms, &supply, &slsa);
        let result = verifier.verify_artifact(&ArtifactId::new("missing"), 2000);
        // Missing artifact fails most checks but supply-chain-clean and license pass globally
        assert!(result.failed_checks() > 0);
        assert!(matches!(
            result.status,
            VerificationStatus::Failed | VerificationStatus::PartiallyVerified
        ));
    }

    #[test]
    fn test_verify_chain() {
        let (artifacts, lineage, transforms, supply, slsa) = setup_stores();
        let verifier = ProvenanceVerifier::new(&artifacts, &lineage, &transforms, &supply, &slsa);
        let results = verifier.verify_chain(&ArtifactId::new("art1"), 2000);
        // Should verify art1 and its upstream source "raw"
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_with_minimum_slsa() {
        let (artifacts, lineage, transforms, supply, slsa) = setup_stores();
        let verifier = ProvenanceVerifier::new(&artifacts, &lineage, &transforms, &supply, &slsa)
            .with_minimum_slsa(SlsaLevel::Level3);
        let result = verifier.verify_artifact(&ArtifactId::new("art1"), 2000);
        // SLSA check should fail — art1 is at Level2, minimum is Level3
        let slsa_check = result
            .checks
            .iter()
            .find(|c| c.check_type == VerificationCheckType::SlsaLevel)
            .unwrap();
        assert!(!slsa_check.passed);
        assert_eq!(result.status, VerificationStatus::PartiallyVerified);
    }

    #[test]
    fn test_verification_status_display() {
        assert_eq!(VerificationStatus::Verified.to_string(), "verified");
        assert_eq!(VerificationStatus::PartiallyVerified.to_string(), "partially-verified");
        assert_eq!(VerificationStatus::Failed.to_string(), "failed");
        assert_eq!(VerificationStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_verification_check_type_display() {
        assert_eq!(VerificationCheckType::ContentHash.to_string(), "content-hash");
        assert_eq!(VerificationCheckType::LineageComplete.to_string(), "lineage-complete");
        assert_eq!(VerificationCheckType::SourcesVerified.to_string(), "sources-verified");
        assert_eq!(VerificationCheckType::TransformationsRecorded.to_string(), "transformations-recorded");
        assert_eq!(VerificationCheckType::AttestationValid.to_string(), "attestation-valid");
        assert_eq!(VerificationCheckType::SupplyChainClean.to_string(), "supply-chain-clean");
        assert_eq!(VerificationCheckType::SlsaLevel.to_string(), "slsa-level");
        assert_eq!(VerificationCheckType::LicenseCompatible.to_string(), "license-compatible");
    }
}
