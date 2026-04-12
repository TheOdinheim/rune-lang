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
};
pub use confidence::{
    ConfidenceCalculator, ConfidenceFactor, ConfidenceFactorType, ConfidenceLevel, ConfidenceScore,
};
pub use consistency::{ConsistencyCheck, ConsistencyChecker, ConsistencyResult, OutputRecord};
pub use contradiction::{
    Contradiction, ContradictionDetector, ContradictionResolution, ContradictionSeverity,
    ContradictionType, ResolutionType, Statement, StatementSource,
};
pub use error::TruthError;
pub use ground_truth::{ComparisonResult, GroundTruthEntry, GroundTruthStore, MatchType};
pub use trust_score::{
    TruthAssessment, TruthAssessor, TruthComponents, TruthFlag, TruthRecommendation,
    TruthTrustLevel, TruthWeights,
};
