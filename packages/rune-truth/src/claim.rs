// ═══════════════════════════════════════════════════════════════════════
// Claim — verifiable truth claims with evidence and lifecycle.
//
// TruthClaimRegistry manages structured assertions about output truth
// with evidence collection, verification, dispute, and retraction.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::TruthError;

// ── TruthClaimType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TruthClaimType {
    FactualAccuracy,
    Completeness,
    Consistency,
    Attribution,
    Unbiased,
    TimelyCurrent,
}

impl fmt::Display for TruthClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FactualAccuracy => f.write_str("factual-accuracy"),
            Self::Completeness => f.write_str("completeness"),
            Self::Consistency => f.write_str("consistency"),
            Self::Attribution => f.write_str("attribution"),
            Self::Unbiased => f.write_str("unbiased"),
            Self::TimelyCurrent => f.write_str("timely-current"),
        }
    }
}

// ── EvidenceType ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    GroundTruthMatch,
    ExpertReview,
    ConsistencyCheck,
    SourceVerification,
    StatisticalValidation,
    CrossReference,
    AutomatedTest,
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroundTruthMatch => f.write_str("ground-truth-match"),
            Self::ExpertReview => f.write_str("expert-review"),
            Self::ConsistencyCheck => f.write_str("consistency-check"),
            Self::SourceVerification => f.write_str("source-verification"),
            Self::StatisticalValidation => f.write_str("statistical-validation"),
            Self::CrossReference => f.write_str("cross-reference"),
            Self::AutomatedTest => f.write_str("automated-test"),
        }
    }
}

// ── EvidenceStrength ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceStrength {
    Weak = 0,
    Moderate = 1,
    Strong = 2,
    Conclusive = 3,
}

impl fmt::Display for EvidenceStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Weak => f.write_str("weak"),
            Self::Moderate => f.write_str("moderate"),
            Self::Strong => f.write_str("strong"),
            Self::Conclusive => f.write_str("conclusive"),
        }
    }
}

// ── Evidence ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub description: String,
    pub source: String,
    pub strength: EvidenceStrength,
    pub timestamp: i64,
}

// ── ClaimStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    Pending,
    Verified,
    Disputed,
    Retracted,
    Expired,
}

impl fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Verified => f.write_str("verified"),
            Self::Disputed => f.write_str("disputed"),
            Self::Retracted => f.write_str("retracted"),
            Self::Expired => f.write_str("expired"),
        }
    }
}

// ── TruthClaim ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TruthClaim {
    pub id: String,
    pub claim: String,
    pub claim_type: TruthClaimType,
    pub evidence: Vec<Evidence>,
    pub confidence: f64,
    pub status: ClaimStatus,
    pub claimed_by: String,
    pub claimed_at: i64,
    pub verified_at: Option<i64>,
    pub verified_by: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl TruthClaim {
    pub fn new(
        id: impl Into<String>,
        claim: impl Into<String>,
        claim_type: TruthClaimType,
        confidence: f64,
        claimed_by: impl Into<String>,
        claimed_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            claim: claim.into(),
            claim_type,
            evidence: Vec::new(),
            confidence: confidence.clamp(0.0, 1.0),
            status: ClaimStatus::Pending,
            claimed_by: claimed_by.into(),
            claimed_at,
            verified_at: None,
            verified_by: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}

// ── TruthClaimRegistry ──────────────────────────────────────────────

#[derive(Default)]
pub struct TruthClaimRegistry {
    claims: HashMap<String, TruthClaim>,
}

impl TruthClaimRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, claim: TruthClaim) -> Result<(), TruthError> {
        if self.claims.contains_key(&claim.id) {
            return Err(TruthError::ClaimAlreadyExists(claim.id.clone()));
        }
        self.claims.insert(claim.id.clone(), claim);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&TruthClaim> {
        self.claims.get(id)
    }

    pub fn verify(&mut self, id: &str, verifier: &str, now: i64) -> Result<(), TruthError> {
        let claim = self
            .claims
            .get_mut(id)
            .ok_or_else(|| TruthError::ClaimNotFound(id.into()))?;
        if claim.status == ClaimStatus::Verified {
            return Err(TruthError::ClaimAlreadyVerified(id.into()));
        }
        claim.status = ClaimStatus::Verified;
        claim.verified_at = Some(now);
        claim.verified_by = Some(verifier.into());
        Ok(())
    }

    pub fn dispute(&mut self, id: &str, _reason: &str) -> Result<(), TruthError> {
        let claim = self
            .claims
            .get_mut(id)
            .ok_or_else(|| TruthError::ClaimNotFound(id.into()))?;
        claim.status = ClaimStatus::Disputed;
        Ok(())
    }

    pub fn retract(&mut self, id: &str) -> Result<(), TruthError> {
        let claim = self
            .claims
            .get_mut(id)
            .ok_or_else(|| TruthError::ClaimNotFound(id.into()))?;
        claim.status = ClaimStatus::Retracted;
        Ok(())
    }

    pub fn claims_by_type(&self, claim_type: &TruthClaimType) -> Vec<&TruthClaim> {
        self.claims
            .values()
            .filter(|c| &c.claim_type == claim_type)
            .collect()
    }

    pub fn claims_by_status(&self, status: &ClaimStatus) -> Vec<&TruthClaim> {
        self.claims
            .values()
            .filter(|c| &c.status == status)
            .collect()
    }

    pub fn verified_claims(&self) -> Vec<&TruthClaim> {
        self.claims_by_status(&ClaimStatus::Verified)
    }

    pub fn pending_claims(&self) -> Vec<&TruthClaim> {
        self.claims_by_status(&ClaimStatus::Pending)
    }

    pub fn disputed_claims(&self) -> Vec<&TruthClaim> {
        self.claims_by_status(&ClaimStatus::Disputed)
    }

    pub fn average_confidence(&self) -> f64 {
        if self.claims.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.claims.values().map(|c| c.confidence).sum();
        sum / self.claims.len() as f64
    }

    pub fn count(&self) -> usize {
        self.claims.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Layer 2: Truth Consensus Mechanisms
// ═══════════════════════════════════════════════════════════════════════

use crate::contradiction::{Claim, ClaimValue};

/// Result of a consensus evaluation.
#[derive(Debug, Clone)]
pub struct ConsensusResult {
    pub reached: bool,
    pub consensus_value: Option<ClaimValue>,
    pub agreement_score: f64,
    pub participating_sources: usize,
    pub dissenting_sources: Vec<String>,
    pub confidence: f64,
}

/// Weighted voting consensus engine.
pub struct ConsensusEngine {
    pub source_weights: HashMap<String, f64>,
    pub min_sources: usize,
    pub agreement_threshold: f64,
}

impl ConsensusEngine {
    pub fn new(min_sources: usize, agreement_threshold: f64) -> Self {
        Self {
            source_weights: HashMap::new(),
            min_sources,
            agreement_threshold,
        }
    }

    pub fn set_source_weight(&mut self, source: &str, weight: f64) {
        self.source_weights.insert(source.to_string(), weight);
    }

    pub fn evaluate(&self, claims: &[&Claim]) -> ConsensusResult {
        if claims.len() < self.min_sources {
            return ConsensusResult {
                reached: false,
                consensus_value: None,
                agreement_score: 0.0,
                participating_sources: claims.len(),
                dissenting_sources: Vec::new(),
                confidence: 0.0,
            };
        }

        // Group claims by value, computing weighted votes
        let mut value_weights: Vec<(ClaimValue, f64, Vec<String>)> = Vec::new();
        let mut total_weight = 0.0;

        for claim in claims {
            let weight = self.source_weights.get(&claim.source).copied().unwrap_or(1.0);
            total_weight += weight;
            if let Some(entry) = value_weights.iter_mut().find(|(v, _, _)| *v == claim.value) {
                entry.1 += weight;
                entry.2.push(claim.source.clone());
            } else {
                value_weights.push((claim.value.clone(), weight, vec![claim.source.clone()]));
            }
        }

        // Find the value with highest weighted vote
        value_weights.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        let (best_value, best_weight, _best_sources) = &value_weights[0];
        let agreement_score = if total_weight > 0.0 {
            *best_weight / total_weight
        } else {
            0.0
        };

        let reached = agreement_score >= self.agreement_threshold;

        let dissenting: Vec<String> = value_weights[1..].iter()
            .flat_map(|(_, _, sources)| sources.clone())
            .collect();

        let confidence = agreement_score * (claims.len() as f64 / self.min_sources.max(1) as f64).min(1.0);

        ConsensusResult {
            reached,
            consensus_value: if reached { Some(best_value.clone()) } else { None },
            agreement_score,
            participating_sources: claims.len(),
            dissenting_sources: dissenting,
            confidence: confidence.min(1.0),
        }
    }
}

/// Record tracking source reliability.
#[derive(Debug, Clone)]
pub struct SourceRecord {
    pub source: String,
    pub total_claims: u64,
    pub verified_correct: u64,
    pub verified_incorrect: u64,
    pub last_activity_at: i64,
    pub reliability_score: f64,
}

/// Tracks reliability of claim sources over time.
#[derive(Default)]
pub struct SourceReliabilityTracker {
    pub source_records: HashMap<String, SourceRecord>,
}

impl SourceReliabilityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_outcome(&mut self, source: &str, correct: bool, now: i64) {
        let record = self.source_records.entry(source.to_string()).or_insert_with(|| {
            SourceRecord {
                source: source.to_string(),
                total_claims: 0,
                verified_correct: 0,
                verified_incorrect: 0,
                last_activity_at: now,
                reliability_score: 0.0,
            }
        });
        record.total_claims += 1;
        if correct {
            record.verified_correct += 1;
        } else {
            record.verified_incorrect += 1;
        }
        record.last_activity_at = now;
        let total_verified = record.verified_correct + record.verified_incorrect;
        record.reliability_score = if total_verified > 0 {
            record.verified_correct as f64 / total_verified as f64
        } else {
            0.0
        };
    }

    pub fn reliability(&self, source: &str) -> Option<f64> {
        self.source_records.get(source).map(|r| r.reliability_score)
    }

    pub fn most_reliable_sources(&self, n: usize) -> Vec<(&str, f64)> {
        let mut sources: Vec<(&str, f64)> = self.source_records.iter()
            .map(|(k, v)| (k.as_str(), v.reliability_score))
            .collect();
        sources.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        sources.truncate(n);
        sources
    }

    pub fn least_reliable_sources(&self, n: usize) -> Vec<(&str, f64)> {
        let mut sources: Vec<(&str, f64)> = self.source_records.iter()
            .map(|(k, v)| (k.as_str(), v.reliability_score))
            .collect();
        sources.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        sources.truncate(n);
        sources
    }

    pub fn sources_above_threshold(&self, threshold: f64) -> Vec<&str> {
        self.source_records.iter()
            .filter(|(_, v)| v.reliability_score >= threshold)
            .map(|(k, _)| k.as_str())
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claim(id: &str, confidence: f64) -> TruthClaim {
        TruthClaim::new(
            id,
            "This output is factually correct",
            TruthClaimType::FactualAccuracy,
            confidence,
            "alice",
            1000,
        )
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        assert!(reg.get("c1").is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_verify() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.verify("c1", "bob", 2000).unwrap();
        let claim = reg.get("c1").unwrap();
        assert_eq!(claim.status, ClaimStatus::Verified);
        assert_eq!(claim.verified_by.as_deref(), Some("bob"));
    }

    #[test]
    fn test_dispute() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.dispute("c1", "contradicting evidence").unwrap();
        assert_eq!(reg.get("c1").unwrap().status, ClaimStatus::Disputed);
    }

    #[test]
    fn test_retract() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.retract("c1").unwrap();
        assert_eq!(reg.get("c1").unwrap().status, ClaimStatus::Retracted);
    }

    #[test]
    fn test_verify_already_verified_fails() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.verify("c1", "bob", 2000).unwrap();
        let err = reg.verify("c1", "carol", 3000).unwrap_err();
        assert!(matches!(err, TruthError::ClaimAlreadyVerified(_)));
    }

    #[test]
    fn test_claims_by_type() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.register(TruthClaim::new(
            "c2",
            "Output is complete",
            TruthClaimType::Completeness,
            0.8,
            "alice",
            1000,
        ))
        .unwrap();
        assert_eq!(
            reg.claims_by_type(&TruthClaimType::FactualAccuracy).len(),
            1
        );
    }

    #[test]
    fn test_claims_by_status() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.register(test_claim("c2", 0.8)).unwrap();
        reg.verify("c1", "bob", 2000).unwrap();
        assert_eq!(reg.claims_by_status(&ClaimStatus::Verified).len(), 1);
        assert_eq!(reg.claims_by_status(&ClaimStatus::Pending).len(), 1);
    }

    #[test]
    fn test_verified_claims() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.verify("c1", "bob", 2000).unwrap();
        assert_eq!(reg.verified_claims().len(), 1);
    }

    #[test]
    fn test_pending_claims() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        assert_eq!(reg.pending_claims().len(), 1);
    }

    #[test]
    fn test_disputed_claims() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.9)).unwrap();
        reg.dispute("c1", "bad").unwrap();
        assert_eq!(reg.disputed_claims().len(), 1);
    }

    #[test]
    fn test_average_confidence() {
        let mut reg = TruthClaimRegistry::new();
        reg.register(test_claim("c1", 0.8)).unwrap();
        reg.register(test_claim("c2", 0.6)).unwrap();
        assert!((reg.average_confidence() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_truth_claim_type_display() {
        assert_eq!(TruthClaimType::FactualAccuracy.to_string(), "factual-accuracy");
        assert_eq!(TruthClaimType::Completeness.to_string(), "completeness");
        assert_eq!(TruthClaimType::Consistency.to_string(), "consistency");
        assert_eq!(TruthClaimType::Attribution.to_string(), "attribution");
        assert_eq!(TruthClaimType::Unbiased.to_string(), "unbiased");
        assert_eq!(TruthClaimType::TimelyCurrent.to_string(), "timely-current");
    }

    #[test]
    fn test_claim_status_display() {
        assert_eq!(ClaimStatus::Pending.to_string(), "pending");
        assert_eq!(ClaimStatus::Verified.to_string(), "verified");
        assert_eq!(ClaimStatus::Disputed.to_string(), "disputed");
        assert_eq!(ClaimStatus::Retracted.to_string(), "retracted");
        assert_eq!(ClaimStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_evidence_strength_ordering() {
        assert!(EvidenceStrength::Weak < EvidenceStrength::Moderate);
        assert!(EvidenceStrength::Moderate < EvidenceStrength::Strong);
        assert!(EvidenceStrength::Strong < EvidenceStrength::Conclusive);
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    fn make_claim(id: &str, source: &str, value: ClaimValue) -> Claim {
        Claim::new(id, source, "subject", "predicate", value, 0.9, 1000)
    }

    #[test]
    fn test_consensus_reaches_agreement() {
        let engine = ConsensusEngine::new(2, 0.66);
        let c1 = make_claim("c1", "s1", ClaimValue::Boolean(true));
        let c2 = make_claim("c2", "s2", ClaimValue::Boolean(true));
        let c3 = make_claim("c3", "s3", ClaimValue::Boolean(false));
        let result = engine.evaluate(&[&c1, &c2, &c3]);
        assert!(result.reached);
        assert_eq!(result.consensus_value, Some(ClaimValue::Boolean(true)));
    }

    #[test]
    fn test_consensus_fails_below_threshold() {
        let engine = ConsensusEngine::new(2, 0.67);
        let c1 = make_claim("c1", "s1", ClaimValue::Boolean(true));
        let c2 = make_claim("c2", "s2", ClaimValue::Boolean(false));
        let result = engine.evaluate(&[&c1, &c2]);
        assert!(!result.reached);
    }

    #[test]
    fn test_consensus_respects_min_sources() {
        let engine = ConsensusEngine::new(5, 0.5);
        let c1 = make_claim("c1", "s1", ClaimValue::Boolean(true));
        let result = engine.evaluate(&[&c1]);
        assert!(!result.reached);
        assert_eq!(result.participating_sources, 1);
    }

    #[test]
    fn test_consensus_weighted_voting() {
        let mut engine = ConsensusEngine::new(2, 0.5);
        engine.set_source_weight("expert", 10.0);
        engine.set_source_weight("novice", 1.0);
        let c1 = make_claim("c1", "expert", ClaimValue::Boolean(true));
        let c2 = make_claim("c2", "novice", ClaimValue::Boolean(false));
        let result = engine.evaluate(&[&c1, &c2]);
        assert!(result.reached);
        assert_eq!(result.consensus_value, Some(ClaimValue::Boolean(true)));
    }

    #[test]
    fn test_consensus_dissenting_sources() {
        let engine = ConsensusEngine::new(2, 0.67);
        let c1 = make_claim("c1", "s1", ClaimValue::Boolean(true));
        let c2 = make_claim("c2", "s2", ClaimValue::Boolean(true));
        let c3 = make_claim("c3", "dissenter", ClaimValue::Boolean(false));
        let result = engine.evaluate(&[&c1, &c2, &c3]);
        assert!(result.dissenting_sources.contains(&"dissenter".to_string()));
    }

    #[test]
    fn test_source_reliability_record_outcome() {
        let mut tracker = SourceReliabilityTracker::new();
        tracker.record_outcome("s1", true, 1000);
        tracker.record_outcome("s1", true, 2000);
        tracker.record_outcome("s1", false, 3000);
        let r = tracker.reliability("s1").unwrap();
        assert!((r - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_source_reliability_calculates() {
        let mut tracker = SourceReliabilityTracker::new();
        tracker.record_outcome("good", true, 1000);
        tracker.record_outcome("good", true, 2000);
        tracker.record_outcome("bad", false, 1000);
        tracker.record_outcome("bad", false, 2000);
        assert!((tracker.reliability("good").unwrap() - 1.0).abs() < 1e-9);
        assert!((tracker.reliability("bad").unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_most_reliable_sources_sorted() {
        let mut tracker = SourceReliabilityTracker::new();
        tracker.record_outcome("good", true, 1000);
        tracker.record_outcome("good", true, 2000);
        tracker.record_outcome("bad", false, 1000);
        tracker.record_outcome("medium", true, 1000);
        tracker.record_outcome("medium", false, 2000);
        let most = tracker.most_reliable_sources(3);
        assert_eq!(most[0].0, "good");
        assert!((most[0].1 - 1.0).abs() < 1e-9);
    }
}
