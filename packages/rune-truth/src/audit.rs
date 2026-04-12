// ═══════════════════════════════════════════════════════════════════════
// Audit — truth-specific audit events and log.
//
// TruthAuditLog records timestamped events for all truth verification
// actions: confidence computation, consistency checks, attribution,
// contradictions, ground truth comparisons, trust assessments, and
// claim lifecycle.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── TruthEventType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TruthEventType {
    ConfidenceComputed { output_id: String, score: f64 },
    ConsistencyChecked { input_hash: String, score: f64 },
    AttributionComputed { output_id: String, sources: usize },
    ContradictionDetected { contradiction_id: String, severity: String },
    ContradictionResolved { contradiction_id: String, resolution: String },
    GroundTruthCompared { ground_truth_id: String, correct: bool },
    TrustAssessed { output_id: String, score: f64, recommendation: String },
    ClaimRegistered { claim_id: String, claim_type: String },
    ClaimVerified { claim_id: String },
    ClaimDisputed { claim_id: String },
}

impl fmt::Display for TruthEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfidenceComputed { output_id, score } => {
                write!(f, "confidence-computed:{output_id}={score:.2}")
            }
            Self::ConsistencyChecked { input_hash, score } => {
                write!(f, "consistency-checked:{input_hash}={score:.2}")
            }
            Self::AttributionComputed { output_id, sources } => {
                write!(f, "attribution-computed:{output_id} ({sources} sources)")
            }
            Self::ContradictionDetected {
                contradiction_id,
                severity,
            } => write!(f, "contradiction-detected:{contradiction_id} [{severity}]"),
            Self::ContradictionResolved {
                contradiction_id,
                resolution,
            } => write!(f, "contradiction-resolved:{contradiction_id} [{resolution}]"),
            Self::GroundTruthCompared {
                ground_truth_id,
                correct,
            } => write!(f, "ground-truth-compared:{ground_truth_id} correct={correct}"),
            Self::TrustAssessed {
                output_id,
                score,
                recommendation,
            } => write!(f, "trust-assessed:{output_id}={score:.2} [{recommendation}]"),
            Self::ClaimRegistered {
                claim_id,
                claim_type,
            } => write!(f, "claim-registered:{claim_id} [{claim_type}]"),
            Self::ClaimVerified { claim_id } => write!(f, "claim-verified:{claim_id}"),
            Self::ClaimDisputed { claim_id } => write!(f, "claim-disputed:{claim_id}"),
        }
    }
}

impl TruthEventType {
    fn type_name(&self) -> &str {
        match self {
            Self::ConfidenceComputed { .. } => "confidence-computed",
            Self::ConsistencyChecked { .. } => "consistency-checked",
            Self::AttributionComputed { .. } => "attribution-computed",
            Self::ContradictionDetected { .. } => "contradiction-detected",
            Self::ContradictionResolved { .. } => "contradiction-resolved",
            Self::GroundTruthCompared { .. } => "ground-truth-compared",
            Self::TrustAssessed { .. } => "trust-assessed",
            Self::ClaimRegistered { .. } => "claim-registered",
            Self::ClaimVerified { .. } => "claim-verified",
            Self::ClaimDisputed { .. } => "claim-disputed",
        }
    }
}

// ── TruthAuditEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TruthAuditEvent {
    pub event_type: TruthEventType,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
    pub output_id: Option<String>,
}

impl TruthAuditEvent {
    pub fn new(
        event_type: TruthEventType,
        actor: impl Into<String>,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        let output_id = match &event_type {
            TruthEventType::ConfidenceComputed { output_id, .. }
            | TruthEventType::AttributionComputed { output_id, .. }
            | TruthEventType::TrustAssessed { output_id, .. } => Some(output_id.clone()),
            _ => None,
        };
        Self {
            event_type,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
            output_id,
        }
    }
}

// ── TruthAuditLog ────────────────────────────────────────────────────

#[derive(Default)]
pub struct TruthAuditLog {
    pub events: Vec<TruthAuditEvent>,
}

impl TruthAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: TruthAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_output(&self, output_id: &str) -> Vec<&TruthAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.output_id.as_deref() == Some(output_id))
            .collect()
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&TruthAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.type_name() == type_name)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&TruthAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn contradiction_events(&self) -> Vec<&TruthAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    TruthEventType::ContradictionDetected { .. }
                        | TruthEventType::ContradictionResolved { .. }
                )
            })
            .collect()
    }

    pub fn assessment_events(&self) -> Vec<&TruthAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, TruthEventType::TrustAssessed { .. }))
            .collect()
    }

    pub fn claim_events(&self) -> Vec<&TruthAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    TruthEventType::ClaimRegistered { .. }
                        | TruthEventType::ClaimVerified { .. }
                        | TruthEventType::ClaimDisputed { .. }
                )
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_retrieve() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::ConfidenceComputed {
                output_id: "o1".into(),
                score: 0.9,
            },
            "system",
            1000,
            "computed",
        ));
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_events_for_output() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::ConfidenceComputed {
                output_id: "o1".into(),
                score: 0.9,
            },
            "system",
            1000,
            "computed",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::TrustAssessed {
                output_id: "o2".into(),
                score: 0.8,
                recommendation: "accept".into(),
            },
            "system",
            2000,
            "assessed",
        ));
        assert_eq!(log.events_for_output("o1").len(), 1);
    }

    #[test]
    fn test_contradiction_events() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::ContradictionDetected {
                contradiction_id: "c1".into(),
                severity: "major".into(),
            },
            "system",
            1000,
            "found",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::ContradictionResolved {
                contradiction_id: "c1".into(),
                resolution: "false-positive".into(),
            },
            "alice",
            2000,
            "resolved",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::ConfidenceComputed {
                output_id: "o1".into(),
                score: 0.5,
            },
            "system",
            3000,
            "irrelevant",
        ));
        assert_eq!(log.contradiction_events().len(), 2);
    }

    #[test]
    fn test_assessment_events() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::TrustAssessed {
                output_id: "o1".into(),
                score: 0.8,
                recommendation: "accept".into(),
            },
            "system",
            1000,
            "assessed",
        ));
        assert_eq!(log.assessment_events().len(), 1);
    }

    #[test]
    fn test_claim_events() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::ClaimRegistered {
                claim_id: "cl1".into(),
                claim_type: "factual-accuracy".into(),
            },
            "alice",
            1000,
            "registered",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::ClaimVerified {
                claim_id: "cl1".into(),
            },
            "bob",
            2000,
            "verified",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::ClaimDisputed {
                claim_id: "cl2".into(),
            },
            "carol",
            3000,
            "disputed",
        ));
        assert_eq!(log.claim_events().len(), 3);
    }

    #[test]
    fn test_truth_event_type_display() {
        let events = vec![
            TruthEventType::ConfidenceComputed { output_id: "o1".into(), score: 0.9 },
            TruthEventType::ConsistencyChecked { input_hash: "h1".into(), score: 0.8 },
            TruthEventType::AttributionComputed { output_id: "o1".into(), sources: 3 },
            TruthEventType::ContradictionDetected { contradiction_id: "c1".into(), severity: "major".into() },
            TruthEventType::ContradictionResolved { contradiction_id: "c1".into(), resolution: "corrected".into() },
            TruthEventType::GroundTruthCompared { ground_truth_id: "gt1".into(), correct: true },
            TruthEventType::TrustAssessed { output_id: "o1".into(), score: 0.8, recommendation: "accept".into() },
            TruthEventType::ClaimRegistered { claim_id: "cl1".into(), claim_type: "accuracy".into() },
            TruthEventType::ClaimVerified { claim_id: "cl1".into() },
            TruthEventType::ClaimDisputed { claim_id: "cl2".into() },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
    }
}
