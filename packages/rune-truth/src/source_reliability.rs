// ═══════════════════════════════════════════════════════════════════════
// Source Reliability — Scoring sources by their historical claim
// accuracy.
//
// ReliabilityClass is a 5-variant enum (Unknown / LowReliability /
// ModerateReliability / HighReliability / Authoritative) rather than
// a continuous numeric score.  Discrete classes avoid the spurious
// precision of a float and make thresholding decisions explicit.
//
// ReliabilityScore bundles the class with the underlying ratio so
// that callers who need the numbers can still access them, while
// callers who only need the classification use the class.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::TruthError;

// ── ReliabilityClass ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReliabilityClass {
    Unknown,
    LowReliability,
    ModerateReliability,
    HighReliability,
    Authoritative,
}

impl ReliabilityClass {
    pub fn from_ratio(correct: usize, total: usize) -> Self {
        if total == 0 {
            return Self::Unknown;
        }
        let ratio = correct as f64 / total as f64;
        if ratio >= 0.95 {
            Self::Authoritative
        } else if ratio >= 0.80 {
            Self::HighReliability
        } else if ratio >= 0.50 {
            Self::ModerateReliability
        } else {
            Self::LowReliability
        }
    }
}

impl fmt::Display for ReliabilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("Unknown"),
            Self::LowReliability => f.write_str("LowReliability"),
            Self::ModerateReliability => f.write_str("ModerateReliability"),
            Self::HighReliability => f.write_str("HighReliability"),
            Self::Authoritative => f.write_str("Authoritative"),
        }
    }
}

// ── ReliabilityScore ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReliabilityScore {
    pub source_id: String,
    pub class: ReliabilityClass,
    pub correct_claims: usize,
    pub total_claims: usize,
}

impl ReliabilityScore {
    pub fn ratio(&self) -> f64 {
        if self.total_claims == 0 {
            return 0.0;
        }
        self.correct_claims as f64 / self.total_claims as f64
    }
}

impl fmt::Display for ReliabilityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({}/{})",
            self.source_id, self.class, self.correct_claims, self.total_claims
        )
    }
}

// ── ClaimOutcome ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    Correct,
    Incorrect,
}

// ── SourceReliabilityScorer trait ─────────────────────────────────

pub trait SourceReliabilityScorer {
    fn score_source(&self, source_id: &str) -> Result<ReliabilityScore, TruthError>;

    fn record_claim_outcome(
        &mut self,
        source_id: &str,
        outcome: ClaimOutcome,
    ) -> Result<(), TruthError>;

    fn reset_source(&mut self, source_id: &str) -> Result<(), TruthError>;

    fn scorer_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── SimpleRatioReliabilityScorer ──────────────────────────────────

struct SourceRecord {
    correct: usize,
    total: usize,
}

pub struct SimpleRatioReliabilityScorer {
    id: String,
    sources: HashMap<String, SourceRecord>,
}

impl SimpleRatioReliabilityScorer {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            sources: HashMap::new(),
        }
    }
}

impl SourceReliabilityScorer for SimpleRatioReliabilityScorer {
    fn score_source(&self, source_id: &str) -> Result<ReliabilityScore, TruthError> {
        let (correct, total) = self
            .sources
            .get(source_id)
            .map(|r| (r.correct, r.total))
            .unwrap_or((0, 0));

        Ok(ReliabilityScore {
            source_id: source_id.to_string(),
            class: ReliabilityClass::from_ratio(correct, total),
            correct_claims: correct,
            total_claims: total,
        })
    }

    fn record_claim_outcome(
        &mut self,
        source_id: &str,
        outcome: ClaimOutcome,
    ) -> Result<(), TruthError> {
        let record = self.sources.entry(source_id.to_string()).or_insert(SourceRecord {
            correct: 0,
            total: 0,
        });
        record.total += 1;
        if outcome == ClaimOutcome::Correct {
            record.correct += 1;
        }
        Ok(())
    }

    fn reset_source(&mut self, source_id: &str) -> Result<(), TruthError> {
        self.sources.remove(source_id);
        Ok(())
    }

    fn scorer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── TimeDecayReliabilityScorer ────────────────────────────────────
// Stores timestamped outcomes and weights recent outcomes more heavily
// when computing the class.  Uses a simple approach: outcomes within
// `recent_window` seconds count double.

struct TimestampedOutcome {
    outcome: ClaimOutcome,
    timestamp: i64,
}

pub struct TimeDecayReliabilityScorer {
    id: String,
    sources: HashMap<String, Vec<TimestampedOutcome>>,
    recent_window: i64,
    current_time: i64,
}

impl TimeDecayReliabilityScorer {
    pub fn new(id: &str, recent_window: i64) -> Self {
        Self {
            id: id.to_string(),
            sources: HashMap::new(),
            recent_window,
            current_time: 0,
        }
    }

    pub fn set_current_time(&mut self, t: i64) {
        self.current_time = t;
    }
}

impl SourceReliabilityScorer for TimeDecayReliabilityScorer {
    fn score_source(&self, source_id: &str) -> Result<ReliabilityScore, TruthError> {
        let outcomes = match self.sources.get(source_id) {
            Some(v) => v,
            None => {
                return Ok(ReliabilityScore {
                    source_id: source_id.to_string(),
                    class: ReliabilityClass::Unknown,
                    correct_claims: 0,
                    total_claims: 0,
                });
            }
        };

        let cutoff = self.current_time - self.recent_window;
        let mut weighted_correct: usize = 0;
        let mut weighted_total: usize = 0;

        for o in outcomes {
            let weight = if o.timestamp >= cutoff { 2 } else { 1 };
            weighted_total += weight;
            if o.outcome == ClaimOutcome::Correct {
                weighted_correct += weight;
            }
        }

        Ok(ReliabilityScore {
            source_id: source_id.to_string(),
            class: ReliabilityClass::from_ratio(weighted_correct, weighted_total),
            correct_claims: outcomes.iter().filter(|o| o.outcome == ClaimOutcome::Correct).count(),
            total_claims: outcomes.len(),
        })
    }

    fn record_claim_outcome(
        &mut self,
        source_id: &str,
        outcome: ClaimOutcome,
    ) -> Result<(), TruthError> {
        self.sources
            .entry(source_id.to_string())
            .or_default()
            .push(TimestampedOutcome {
                outcome,
                timestamp: self.current_time,
            });
        Ok(())
    }

    fn reset_source(&mut self, source_id: &str) -> Result<(), TruthError> {
        self.sources.remove(source_id);
        Ok(())
    }

    fn scorer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullReliabilityScorer ─────────────────────────────────────────

pub struct NullReliabilityScorer {
    id: String,
}

impl NullReliabilityScorer {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl SourceReliabilityScorer for NullReliabilityScorer {
    fn score_source(&self, source_id: &str) -> Result<ReliabilityScore, TruthError> {
        Ok(ReliabilityScore {
            source_id: source_id.to_string(),
            class: ReliabilityClass::Unknown,
            correct_claims: 0,
            total_claims: 0,
        })
    }

    fn record_claim_outcome(&mut self, _: &str, _: ClaimOutcome) -> Result<(), TruthError> {
        Ok(())
    }

    fn reset_source(&mut self, _: &str) -> Result<(), TruthError> {
        Ok(())
    }

    fn scorer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reliability_class_from_ratio() {
        assert_eq!(ReliabilityClass::from_ratio(0, 0), ReliabilityClass::Unknown);
        assert_eq!(ReliabilityClass::from_ratio(2, 10), ReliabilityClass::LowReliability);
        assert_eq!(ReliabilityClass::from_ratio(6, 10), ReliabilityClass::ModerateReliability);
        assert_eq!(ReliabilityClass::from_ratio(8, 10), ReliabilityClass::HighReliability);
        assert_eq!(ReliabilityClass::from_ratio(10, 10), ReliabilityClass::Authoritative);
    }

    #[test]
    fn test_simple_scorer_unknown_source() {
        let scorer = SimpleRatioReliabilityScorer::new("sr-1");
        let score = scorer.score_source("unknown-source").unwrap();
        assert_eq!(score.class, ReliabilityClass::Unknown);
        assert_eq!(score.total_claims, 0);
    }

    #[test]
    fn test_simple_scorer_record_and_score() {
        let mut scorer = SimpleRatioReliabilityScorer::new("sr-1");
        for _ in 0..9 {
            scorer.record_claim_outcome("alice", ClaimOutcome::Correct).unwrap();
        }
        scorer.record_claim_outcome("alice", ClaimOutcome::Incorrect).unwrap();

        let score = scorer.score_source("alice").unwrap();
        assert_eq!(score.class, ReliabilityClass::HighReliability);
        assert_eq!(score.correct_claims, 9);
        assert_eq!(score.total_claims, 10);
    }

    #[test]
    fn test_simple_scorer_authoritative() {
        let mut scorer = SimpleRatioReliabilityScorer::new("sr-1");
        for _ in 0..20 {
            scorer.record_claim_outcome("alice", ClaimOutcome::Correct).unwrap();
        }
        let score = scorer.score_source("alice").unwrap();
        assert_eq!(score.class, ReliabilityClass::Authoritative);
    }

    #[test]
    fn test_simple_scorer_reset() {
        let mut scorer = SimpleRatioReliabilityScorer::new("sr-1");
        scorer.record_claim_outcome("alice", ClaimOutcome::Correct).unwrap();
        scorer.reset_source("alice").unwrap();
        let score = scorer.score_source("alice").unwrap();
        assert_eq!(score.class, ReliabilityClass::Unknown);
    }

    #[test]
    fn test_time_decay_recent_weighted() {
        let mut scorer = TimeDecayReliabilityScorer::new("td-1", 100);

        // Old outcomes (before window)
        scorer.set_current_time(50);
        for _ in 0..5 {
            scorer.record_claim_outcome("alice", ClaimOutcome::Incorrect).unwrap();
        }

        // Recent outcomes (within window)
        scorer.set_current_time(200);
        for _ in 0..5 {
            scorer.record_claim_outcome("alice", ClaimOutcome::Correct).unwrap();
        }

        let score = scorer.score_source("alice").unwrap();
        // 5 old incorrect (weight 1 each = 5 total, 0 correct)
        // 5 recent correct (weight 2 each = 10 total, 10 correct)
        // weighted: 10/15 = 0.667 → ModerateReliability
        assert_eq!(score.class, ReliabilityClass::ModerateReliability);
    }

    #[test]
    fn test_time_decay_reset() {
        let mut scorer = TimeDecayReliabilityScorer::new("td-1", 100);
        scorer.record_claim_outcome("alice", ClaimOutcome::Correct).unwrap();
        scorer.reset_source("alice").unwrap();
        let score = scorer.score_source("alice").unwrap();
        assert_eq!(score.class, ReliabilityClass::Unknown);
    }

    #[test]
    fn test_null_scorer() {
        let mut scorer = NullReliabilityScorer::new("null-1");
        scorer.record_claim_outcome("alice", ClaimOutcome::Correct).unwrap();
        let score = scorer.score_source("alice").unwrap();
        assert_eq!(score.class, ReliabilityClass::Unknown);
        assert!(!scorer.is_active());
    }

    #[test]
    fn test_reliability_score_ratio() {
        let score = ReliabilityScore {
            source_id: "s1".to_string(),
            class: ReliabilityClass::HighReliability,
            correct_claims: 8,
            total_claims: 10,
        };
        assert!((score.ratio() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reliability_score_display() {
        let score = ReliabilityScore {
            source_id: "alice".to_string(),
            class: ReliabilityClass::Authoritative,
            correct_claims: 20,
            total_claims: 20,
        };
        let s = score.to_string();
        assert!(s.contains("alice"));
        assert!(s.contains("Authoritative"));
    }

    #[test]
    fn test_reliability_class_display() {
        assert_eq!(ReliabilityClass::Unknown.to_string(), "Unknown");
        assert_eq!(ReliabilityClass::Authoritative.to_string(), "Authoritative");
    }

    #[test]
    fn test_scorer_metadata() {
        let scorer = SimpleRatioReliabilityScorer::new("sr-1");
        assert_eq!(scorer.scorer_id(), "sr-1");
        assert!(scorer.is_active());
    }

    #[test]
    fn test_reliability_score_zero_total_ratio() {
        let score = ReliabilityScore {
            source_id: "s1".to_string(),
            class: ReliabilityClass::Unknown,
            correct_claims: 0,
            total_claims: 0,
        };
        assert!((score.ratio() - 0.0).abs() < f64::EPSILON);
    }
}
