// ═══════════════════════════════════════════════════════════════════════
// Trust Score — aggregate trust assessment combining all truth signals.
//
// TruthAssessor combines confidence, consistency, attribution,
// contradiction freedom, ground truth accuracy, and provenance into a
// single TruthAssessment with trust level, flags, and recommendation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::contradiction::ContradictionSeverity;

// ── TruthTrustLevel ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TruthTrustLevel {
    Untrusted = 0,
    Suspect = 1,
    Provisional = 2,
    Trusted = 3,
    Verified = 4,
}

impl TruthTrustLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.2 => Self::Untrusted,
            s if s < 0.4 => Self::Suspect,
            s if s < 0.6 => Self::Provisional,
            s if s < 0.8 => Self::Trusted,
            _ => Self::Verified,
        }
    }
}

impl fmt::Display for TruthTrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Untrusted => f.write_str("untrusted"),
            Self::Suspect => f.write_str("suspect"),
            Self::Provisional => f.write_str("provisional"),
            Self::Trusted => f.write_str("trusted"),
            Self::Verified => f.write_str("verified"),
        }
    }
}

// ── TruthComponents ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct TruthComponents {
    pub confidence: Option<f64>,
    pub consistency: Option<f64>,
    pub attribution_coverage: Option<f64>,
    pub contradiction_free: Option<f64>,
    pub ground_truth_accuracy: Option<f64>,
    pub provenance_verified: Option<f64>,
}

// ── TruthFlag ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TruthFlag {
    LowConfidence,
    InconsistentOutputs,
    UnattributedContent,
    ContradictionDetected { severity: ContradictionSeverity },
    GroundTruthMismatch,
    ProvenanceIncomplete,
    NoGroundTruth,
    SelfContradiction,
}

impl fmt::Display for TruthFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LowConfidence => f.write_str("low-confidence"),
            Self::InconsistentOutputs => f.write_str("inconsistent-outputs"),
            Self::UnattributedContent => f.write_str("unattributed-content"),
            Self::ContradictionDetected { severity } => {
                write!(f, "contradiction-detected:{severity}")
            }
            Self::GroundTruthMismatch => f.write_str("ground-truth-mismatch"),
            Self::ProvenanceIncomplete => f.write_str("provenance-incomplete"),
            Self::NoGroundTruth => f.write_str("no-ground-truth"),
            Self::SelfContradiction => f.write_str("self-contradiction"),
        }
    }
}

// ── TruthRecommendation ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TruthRecommendation {
    Accept,
    AcceptWithCaveat { caveat: String },
    ManualReview,
    Reject { reason: String },
}

impl fmt::Display for TruthRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => f.write_str("accept"),
            Self::AcceptWithCaveat { caveat } => write!(f, "accept-with-caveat: {caveat}"),
            Self::ManualReview => f.write_str("manual-review"),
            Self::Reject { reason } => write!(f, "reject: {reason}"),
        }
    }
}

// ── TruthWeights ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TruthWeights {
    pub confidence: f64,
    pub consistency: f64,
    pub attribution: f64,
    pub contradiction_free: f64,
    pub ground_truth: f64,
    pub provenance: f64,
}

impl TruthWeights {
    pub fn sum(&self) -> f64 {
        self.confidence
            + self.consistency
            + self.attribution
            + self.contradiction_free
            + self.ground_truth
            + self.provenance
    }
}

impl Default for TruthWeights {
    fn default() -> Self {
        Self {
            confidence: 0.25,
            consistency: 0.20,
            attribution: 0.15,
            contradiction_free: 0.20,
            ground_truth: 0.10,
            provenance: 0.10,
        }
    }
}

// ── TruthAssessment ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TruthAssessment {
    pub output_id: String,
    pub trust_score: f64,
    pub trust_level: TruthTrustLevel,
    pub components: TruthComponents,
    pub assessed_at: i64,
    pub flags: Vec<TruthFlag>,
    pub recommendation: TruthRecommendation,
}

// ── TruthAssessor ────────────────────────────────────────────────────

pub struct TruthAssessor {
    pub component_weights: TruthWeights,
}

impl TruthAssessor {
    pub fn new() -> Self {
        Self {
            component_weights: TruthWeights::default(),
        }
    }

    pub fn with_weights(weights: TruthWeights) -> Self {
        Self {
            component_weights: weights,
        }
    }

    pub fn assess(
        &self,
        output_id: &str,
        components: TruthComponents,
        now: i64,
    ) -> TruthAssessment {
        let w = &self.component_weights;

        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;

        if let Some(v) = components.confidence {
            weighted_sum += v * w.confidence;
            weight_total += w.confidence;
        }
        if let Some(v) = components.consistency {
            weighted_sum += v * w.consistency;
            weight_total += w.consistency;
        }
        if let Some(v) = components.attribution_coverage {
            weighted_sum += v * w.attribution;
            weight_total += w.attribution;
        }
        if let Some(v) = components.contradiction_free {
            weighted_sum += v * w.contradiction_free;
            weight_total += w.contradiction_free;
        }
        if let Some(v) = components.ground_truth_accuracy {
            weighted_sum += v * w.ground_truth;
            weight_total += w.ground_truth;
        }
        if let Some(v) = components.provenance_verified {
            weighted_sum += v * w.provenance;
            weight_total += w.provenance;
        }

        let trust_score = if weight_total > 0.0 {
            (weighted_sum / weight_total).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let trust_level = TruthTrustLevel::from_score(trust_score);

        // Generate flags.
        let mut flags = Vec::new();

        if let Some(v) = components.confidence {
            if v < 0.4 {
                flags.push(TruthFlag::LowConfidence);
            }
        }
        if let Some(v) = components.consistency {
            if v < 0.5 {
                flags.push(TruthFlag::InconsistentOutputs);
            }
        }
        if let Some(v) = components.attribution_coverage {
            if v < 0.3 {
                flags.push(TruthFlag::UnattributedContent);
            }
        }
        if let Some(v) = components.contradiction_free {
            if v < 0.5 {
                flags.push(TruthFlag::ContradictionDetected {
                    severity: if v < 0.2 {
                        ContradictionSeverity::Critical
                    } else {
                        ContradictionSeverity::Major
                    },
                });
            }
        }
        if let Some(v) = components.ground_truth_accuracy {
            if v < 0.5 {
                flags.push(TruthFlag::GroundTruthMismatch);
            }
        } else {
            flags.push(TruthFlag::NoGroundTruth);
        }
        if let Some(v) = components.provenance_verified {
            if v < 0.5 {
                flags.push(TruthFlag::ProvenanceIncomplete);
            }
        }

        // Determine recommendation.
        let has_critical_contradiction = flags.iter().any(|f| {
            matches!(
                f,
                TruthFlag::ContradictionDetected {
                    severity: ContradictionSeverity::Critical,
                }
            )
        });

        let has_major_flag = flags.iter().any(|f| {
            matches!(
                f,
                TruthFlag::ContradictionDetected {
                    severity: ContradictionSeverity::Major,
                }
            )
        });

        let recommendation = if has_critical_contradiction {
            TruthRecommendation::Reject {
                reason: "critical contradiction detected".into(),
            }
        } else if trust_score < 0.3 {
            TruthRecommendation::Reject {
                reason: format!("trust score too low: {trust_score:.2}"),
            }
        } else if trust_score < 0.5 || has_major_flag {
            TruthRecommendation::ManualReview
        } else if trust_score < 0.7 {
            TruthRecommendation::AcceptWithCaveat {
                caveat: format!("moderate trust score: {trust_score:.2}"),
            }
        } else {
            TruthRecommendation::Accept
        };

        TruthAssessment {
            output_id: output_id.into(),
            trust_score,
            trust_level,
            components,
            assessed_at: now,
            flags,
            recommendation,
        }
    }
}

impl Default for TruthAssessor {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Merkle Audit Tree
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

/// Side of a sibling in a Merkle proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Proof of inclusion for a leaf in a Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub sibling_hashes: Vec<(String, Side)>,
    pub root_hash: String,
}

/// Compute parent hash from two children.
pub fn compute_parent(left: &str, right: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

/// SHA3-256 hash of arbitrary data.
fn sha3_hash(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Merkle tree for truth records.
pub struct MerkleTree {
    pub leaves: Vec<String>,
    pub nodes: Vec<Vec<String>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            nodes: Vec::new(),
        }
    }

    pub fn add_leaf(&mut self, data: &[u8]) {
        let hash = sha3_hash(data);
        self.leaves.push(hash);
        self.rebuild_tree();
    }

    pub fn root_hash(&self) -> Option<String> {
        self.nodes.last().and_then(|level| level.first().cloned())
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn verify_inclusion(&self, leaf_hash: &str) -> bool {
        self.leaves.iter().any(|h| h == leaf_hash)
    }

    pub fn proof_for_leaf(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() || self.nodes.is_empty() {
            return None;
        }
        let root = self.root_hash()?;
        let mut siblings = Vec::new();
        let mut idx = index;

        for level in &self.nodes[..self.nodes.len().saturating_sub(1)] {
            if idx % 2 == 0 {
                // sibling is on the right
                if idx + 1 < level.len() {
                    siblings.push((level[idx + 1].clone(), Side::Right));
                }
            } else {
                // sibling is on the left
                siblings.push((level[idx - 1].clone(), Side::Left));
            }
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_hash: self.leaves[index].clone(),
            sibling_hashes: siblings,
            root_hash: root,
        })
    }

    pub fn verify_proof(root: &str, leaf_hash: &str, proof: &MerkleProof) -> bool {
        let mut current = leaf_hash.to_string();
        for (sibling, side) in &proof.sibling_hashes {
            current = match side {
                Side::Left => compute_parent(sibling, &current),
                Side::Right => compute_parent(&current, sibling),
            };
        }
        current == root
    }

    fn rebuild_tree(&mut self) {
        if self.leaves.is_empty() {
            self.nodes.clear();
            return;
        }
        self.nodes.clear();
        let mut current_level = self.leaves.clone();
        self.nodes.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    next_level.push(compute_parent(&current_level[i], &current_level[i + 1]));
                } else {
                    // Odd node: duplicate it
                    next_level.push(compute_parent(&current_level[i], &current_level[i]));
                }
                i += 2;
            }
            self.nodes.push(next_level.clone());
            current_level = next_level;
        }
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn all_high() -> TruthComponents {
        TruthComponents {
            confidence: Some(0.9),
            consistency: Some(0.95),
            attribution_coverage: Some(0.85),
            contradiction_free: Some(1.0),
            ground_truth_accuracy: Some(0.9),
            provenance_verified: Some(0.8),
        }
    }

    fn all_low() -> TruthComponents {
        TruthComponents {
            confidence: Some(0.1),
            consistency: Some(0.1),
            attribution_coverage: Some(0.05),
            contradiction_free: Some(0.1),
            ground_truth_accuracy: Some(0.1),
            provenance_verified: Some(0.1),
        }
    }

    #[test]
    fn test_assess_all_high() {
        let assessor = TruthAssessor::new();
        let result = assessor.assess("o1", all_high(), 1000);
        assert_eq!(result.trust_level, TruthTrustLevel::Verified);
        assert_eq!(result.recommendation, TruthRecommendation::Accept);
        assert!(result.trust_score > 0.8);
    }

    #[test]
    fn test_assess_all_low() {
        let assessor = TruthAssessor::new();
        let result = assessor.assess("o1", all_low(), 1000);
        assert_eq!(result.trust_level, TruthTrustLevel::Untrusted);
        assert!(matches!(
            result.recommendation,
            TruthRecommendation::Reject { .. }
        ));
    }

    #[test]
    fn test_assess_mixed() {
        let assessor = TruthAssessor::new();
        let components = TruthComponents {
            confidence: Some(0.7),
            consistency: Some(0.8),
            attribution_coverage: Some(0.5),
            contradiction_free: Some(0.9),
            ground_truth_accuracy: Some(0.6),
            provenance_verified: Some(0.5),
        };
        let result = assessor.assess("o1", components, 1000);
        assert!(result.trust_score > 0.5 && result.trust_score < 0.9);
    }

    #[test]
    fn test_assess_missing_components() {
        let assessor = TruthAssessor::new();
        let components = TruthComponents {
            confidence: Some(0.8),
            consistency: None,
            attribution_coverage: None,
            contradiction_free: Some(1.0),
            ground_truth_accuracy: None,
            provenance_verified: None,
        };
        let result = assessor.assess("o1", components, 1000);
        // Should normalize by present weights only (confidence 0.25 + contradiction 0.20)
        // (0.8*0.25 + 1.0*0.20) / (0.25 + 0.20) = 0.40/0.45 ≈ 0.889
        assert!(result.trust_score > 0.8);
    }

    #[test]
    fn test_assess_generates_low_confidence_flag() {
        let assessor = TruthAssessor::new();
        let components = TruthComponents {
            confidence: Some(0.3),
            ..all_high()
        };
        let result = assessor.assess("o1", components, 1000);
        assert!(result.flags.contains(&TruthFlag::LowConfidence));
    }

    #[test]
    fn test_assess_generates_contradiction_flag() {
        let assessor = TruthAssessor::new();
        let components = TruthComponents {
            contradiction_free: Some(0.3),
            ..all_high()
        };
        let result = assessor.assess("o1", components, 1000);
        assert!(result.flags.iter().any(|f| matches!(
            f,
            TruthFlag::ContradictionDetected { .. }
        )));
    }

    #[test]
    fn test_assess_critical_contradiction_rejects() {
        let assessor = TruthAssessor::new();
        let components = TruthComponents {
            contradiction_free: Some(0.1), // < 0.2 → Critical
            ..all_high()
        };
        let result = assessor.assess("o1", components, 1000);
        assert!(matches!(
            result.recommendation,
            TruthRecommendation::Reject { .. }
        ));
    }

    #[test]
    fn test_trust_level_from_score() {
        assert_eq!(TruthTrustLevel::from_score(0.0), TruthTrustLevel::Untrusted);
        assert_eq!(TruthTrustLevel::from_score(0.3), TruthTrustLevel::Suspect);
        assert_eq!(TruthTrustLevel::from_score(0.5), TruthTrustLevel::Provisional);
        assert_eq!(TruthTrustLevel::from_score(0.7), TruthTrustLevel::Trusted);
        assert_eq!(TruthTrustLevel::from_score(0.9), TruthTrustLevel::Verified);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TruthTrustLevel::Untrusted < TruthTrustLevel::Suspect);
        assert!(TruthTrustLevel::Suspect < TruthTrustLevel::Provisional);
        assert!(TruthTrustLevel::Provisional < TruthTrustLevel::Trusted);
        assert!(TruthTrustLevel::Trusted < TruthTrustLevel::Verified);
    }

    #[test]
    fn test_truth_recommendation_display() {
        assert_eq!(TruthRecommendation::Accept.to_string(), "accept");
        assert!(TruthRecommendation::AcceptWithCaveat {
            caveat: "low".into()
        }
        .to_string()
        .contains("low"));
        assert_eq!(TruthRecommendation::ManualReview.to_string(), "manual-review");
        assert!(TruthRecommendation::Reject {
            reason: "bad".into()
        }
        .to_string()
        .contains("bad"));
    }

    #[test]
    fn test_truth_weights_default_sums_to_one() {
        let w = TruthWeights::default();
        assert!((w.sum() - 1.0).abs() < 1e-9);
    }

    // ── Layer 2 Merkle tree tests ────────────────────────────────────

    #[test]
    fn test_merkle_single_leaf() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"hello");
        assert_eq!(tree.leaf_count(), 1);
        let root = tree.root_hash().unwrap();
        assert_eq!(root, tree.leaves[0]);
    }

    #[test]
    fn test_merkle_two_leaves() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"hello");
        tree.add_leaf(b"world");
        assert_eq!(tree.leaf_count(), 2);
        let root = tree.root_hash().unwrap();
        let expected = compute_parent(&tree.leaves[0], &tree.leaves[1]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_changes_on_add() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"a");
        let root1 = tree.root_hash().unwrap();
        tree.add_leaf(b"b");
        let root2 = tree.root_hash().unwrap();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_merkle_verify_inclusion_true() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"data");
        assert!(tree.verify_inclusion(&tree.leaves[0]));
    }

    #[test]
    fn test_merkle_verify_inclusion_false() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"data");
        assert!(!tree.verify_inclusion("nonexistent"));
    }

    #[test]
    fn test_merkle_proof_valid() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"a");
        tree.add_leaf(b"b");
        tree.add_leaf(b"c");
        let root = tree.root_hash().unwrap();
        let proof = tree.proof_for_leaf(0).unwrap();
        assert!(MerkleTree::verify_proof(&root, &proof.leaf_hash, &proof));
    }

    #[test]
    fn test_merkle_verify_proof_succeeds() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"x");
        tree.add_leaf(b"y");
        let root = tree.root_hash().unwrap();
        let proof = tree.proof_for_leaf(1).unwrap();
        assert!(MerkleTree::verify_proof(&root, &proof.leaf_hash, &proof));
    }

    #[test]
    fn test_merkle_verify_proof_fails_wrong_root() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"x");
        tree.add_leaf(b"y");
        let proof = tree.proof_for_leaf(0).unwrap();
        assert!(!MerkleTree::verify_proof("wrong_root", &proof.leaf_hash, &proof));
    }

    #[test]
    fn test_compute_parent_deterministic() {
        let a = compute_parent("abc", "def");
        let b = compute_parent("abc", "def");
        assert_eq!(a, b);
        // Different inputs produce different output
        let c = compute_parent("abc", "ghi");
        assert_ne!(a, c);
    }
}
