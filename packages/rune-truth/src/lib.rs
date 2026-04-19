// ═══════════════════════════════════════════════════════════════════════
// rune-truth — output trustworthiness verification for the RUNE
// governance ecosystem: confidence scoring, consistency checking,
// source attribution, contradiction detection, and ground truth
// comparison.
// ═══════════════════════════════════════════════════════════════════════

pub mod attribution;
pub mod audit;
pub mod claim;
pub mod confidence;
pub mod consistency;
pub mod contradiction;
pub mod error;
pub mod ground_truth;
pub mod trust_score;

pub use attribution::{
    Attribution, AttributionEngine, AttributionMethod, InfluenceType, SourceInfluence,
};
pub use audit::{TruthAuditEvent, TruthAuditLog, TruthEventType};
pub use claim::{
    ClaimStatus, Evidence, EvidenceStrength, EvidenceType, TruthClaim, TruthClaimRegistry,
    TruthClaimType,
    // Layer 2
    ConsensusEngine, ConsensusResult, SourceReliabilityTracker, SourceRecord,
};
pub use confidence::{
    ConfidenceCalculator, ConfidenceFactor, ConfidenceFactorType, ConfidenceLevel, ConfidenceScore,
    // Layer 2
    RunningStats, CalibratedScorer, confidence_interval, z_score_for_level,
};
pub use consistency::{
    ConsistencyCheck, ConsistencyChecker, ConsistencyResult, OutputRecord,
    // Layer 2
    ConsistencyTest, ConsistencyTestType, check_mean_consistency,
    TemporalConsistencyTracker, ConsistencyWindow, DriftEvent, Trend,
    OutputFingerprint, fingerprint_output, outputs_match, similarity_score,
};
pub use contradiction::{
    Contradiction, ContradictionDetector, ContradictionResolution, ContradictionSeverity,
    ContradictionType, ResolutionType, Statement, StatementSource,
    // Layer 2
    Claim, ClaimValue, ClaimStore, ClaimContradiction, ClaimContradictionType,
    ClaimContradictionSeverity, ClaimResolutionStrategy, ClaimConflictResolution,
    resolve_claim_contradiction,
};
pub use error::TruthError;
pub use ground_truth::{
    ComparisonResult, GroundTruthEntry, GroundTruthStore, MatchType,
    // Layer 2
    TypedGroundTruth, TypedGroundTruthStore, GroundTruthVerification,
    AccuracyTracker,
};
pub use trust_score::{
    TruthAssessment, TruthAssessor, TruthComponents, TruthFlag, TruthRecommendation,
    TruthTrustLevel, TruthWeights,
    // Layer 2
    MerkleTree, MerkleProof, Side, compute_parent,
};
