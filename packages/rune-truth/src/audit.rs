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
    // Layer 2 event types
    RunningStatsUpdated { count: u64, mean: f64 },
    ConfidenceCalibrated { raw: f64, calibrated: f64 },
    BrierScoreComputed { score: f64 },
    ConsistencyTestRun { test_type: String, passed: bool },
    DriftDetected { drift_type: String, magnitude: f64 },
    OutputFingerprinted { hash_prefix: String },
    ClaimRecorded { source: String, subject: String },
    ContradictionFound { subject: String, severity: String },
    ContradictionResolvedL2 { strategy: String },
    GroundTruthSet { key: String, source: String },
    GroundTruthVerified { key: String, matches: bool },
    AccuracyComputed { overall: f64, subjects: usize },
    ConsensusReached { agreement: f64, sources: usize },
    ConsensusNotReached { sources: usize, threshold: f64 },
    MerkleRootComputed { leaf_count: usize, root_prefix: String },
    // Layer 3 event types
    TruthBackendChanged { backend_id: String },
    ClaimPersisted { claim_id: String },
    ClaimRetrieved { claim_id: String },
    ClaimRetracted { claim_id: String },
    ClaimConsistencyCheckPassed { claim_id: String, checker_id: String },
    ClaimConsistencyCheckFailed { claim_id: String, checker_id: String, reason: String },
    ContradictionDetectedEvent { claim_a: String, claim_b: String, explanation: String },
    ContradictionResolvedEvent { claim_a: String, claim_b: String },
    CorroborationRecordedEvent { claim_a: String, claim_b: String },
    EvidenceLinkCreated { claim_id: String, attestation_ref: String },
    EvidenceLinkRemoved { claim_id: String, attestation_ref: String },
    EvidenceAdequacyAssessed { claim_id: String, adequate: bool },
    ClaimExported { claim_id: String, format: String },
    ClaimExportFailed { claim_id: String, reason: String },
    TruthSubscriberRegistered { subscriber_id: String },
    TruthSubscriberRemoved { subscriber_id: String },
    TruthEventPublished { event_type_name: String },
    SourceReliabilityUpdated { source_id: String, class: String },
    SourceReliabilityQueried { source_id: String },
    SourceReliabilityReset { source_id: String },
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
            Self::RunningStatsUpdated { count, mean } => write!(f, "running-stats-updated:n={count},mean={mean:.4}"),
            Self::ConfidenceCalibrated { raw, calibrated } => write!(f, "confidence-calibrated:{raw:.2}->{calibrated:.2}"),
            Self::BrierScoreComputed { score } => write!(f, "brier-score-computed:{score:.4}"),
            Self::ConsistencyTestRun { test_type, passed } => write!(f, "consistency-test-run:{test_type} passed={passed}"),
            Self::DriftDetected { drift_type, magnitude } => write!(f, "drift-detected:{drift_type} mag={magnitude:.4}"),
            Self::OutputFingerprinted { hash_prefix } => write!(f, "output-fingerprinted:{hash_prefix}"),
            Self::ClaimRecorded { source, subject } => write!(f, "claim-recorded:{source}/{subject}"),
            Self::ContradictionFound { subject, severity } => write!(f, "contradiction-found:{subject} [{severity}]"),
            Self::ContradictionResolvedL2 { strategy } => write!(f, "contradiction-resolved-l2:{strategy}"),
            Self::GroundTruthSet { key, source } => write!(f, "ground-truth-set:{key} from {source}"),
            Self::GroundTruthVerified { key, matches } => write!(f, "ground-truth-verified:{key} matches={matches}"),
            Self::AccuracyComputed { overall, subjects } => write!(f, "accuracy-computed:{overall:.4} ({subjects} subjects)"),
            Self::ConsensusReached { agreement, sources } => write!(f, "consensus-reached:{agreement:.2} ({sources} sources)"),
            Self::ConsensusNotReached { sources, threshold } => write!(f, "consensus-not-reached:{sources} sources, threshold={threshold:.2}"),
            Self::MerkleRootComputed { leaf_count, root_prefix } => write!(f, "merkle-root-computed:{leaf_count} leaves, root={root_prefix}"),
            Self::TruthBackendChanged { backend_id } => write!(f, "truth-backend-changed:{backend_id}"),
            Self::ClaimPersisted { claim_id } => write!(f, "claim-persisted:{claim_id}"),
            Self::ClaimRetrieved { claim_id } => write!(f, "claim-retrieved:{claim_id}"),
            Self::ClaimRetracted { claim_id } => write!(f, "claim-retracted:{claim_id}"),
            Self::ClaimConsistencyCheckPassed { claim_id, checker_id } => write!(f, "claim-consistency-check-passed:{claim_id} [{checker_id}]"),
            Self::ClaimConsistencyCheckFailed { claim_id, checker_id, reason } => write!(f, "claim-consistency-check-failed:{claim_id} [{checker_id}] {reason}"),
            Self::ContradictionDetectedEvent { claim_a, claim_b, explanation } => write!(f, "contradiction-detected-event:{claim_a}/{claim_b} {explanation}"),
            Self::ContradictionResolvedEvent { claim_a, claim_b } => write!(f, "contradiction-resolved-event:{claim_a}/{claim_b}"),
            Self::CorroborationRecordedEvent { claim_a, claim_b } => write!(f, "corroboration-recorded-event:{claim_a}/{claim_b}"),
            Self::EvidenceLinkCreated { claim_id, attestation_ref } => write!(f, "evidence-link-created:{claim_id}->{attestation_ref}"),
            Self::EvidenceLinkRemoved { claim_id, attestation_ref } => write!(f, "evidence-link-removed:{claim_id}->{attestation_ref}"),
            Self::EvidenceAdequacyAssessed { claim_id, adequate } => write!(f, "evidence-adequacy-assessed:{claim_id} adequate={adequate}"),
            Self::ClaimExported { claim_id, format } => write!(f, "claim-exported:{claim_id} [{format}]"),
            Self::ClaimExportFailed { claim_id, reason } => write!(f, "claim-export-failed:{claim_id} {reason}"),
            Self::TruthSubscriberRegistered { subscriber_id } => write!(f, "truth-subscriber-registered:{subscriber_id}"),
            Self::TruthSubscriberRemoved { subscriber_id } => write!(f, "truth-subscriber-removed:{subscriber_id}"),
            Self::TruthEventPublished { event_type_name } => write!(f, "truth-event-published:{event_type_name}"),
            Self::SourceReliabilityUpdated { source_id, class } => write!(f, "source-reliability-updated:{source_id} [{class}]"),
            Self::SourceReliabilityQueried { source_id } => write!(f, "source-reliability-queried:{source_id}"),
            Self::SourceReliabilityReset { source_id } => write!(f, "source-reliability-reset:{source_id}"),
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
            Self::RunningStatsUpdated { .. } => "running-stats-updated",
            Self::ConfidenceCalibrated { .. } => "confidence-calibrated",
            Self::BrierScoreComputed { .. } => "brier-score-computed",
            Self::ConsistencyTestRun { .. } => "consistency-test-run",
            Self::DriftDetected { .. } => "drift-detected",
            Self::OutputFingerprinted { .. } => "output-fingerprinted",
            Self::ClaimRecorded { .. } => "claim-recorded",
            Self::ContradictionFound { .. } => "contradiction-found",
            Self::ContradictionResolvedL2 { .. } => "contradiction-resolved-l2",
            Self::GroundTruthSet { .. } => "ground-truth-set",
            Self::GroundTruthVerified { .. } => "ground-truth-verified",
            Self::AccuracyComputed { .. } => "accuracy-computed",
            Self::ConsensusReached { .. } => "consensus-reached",
            Self::ConsensusNotReached { .. } => "consensus-not-reached",
            Self::MerkleRootComputed { .. } => "merkle-root-computed",
            Self::TruthBackendChanged { .. } => "truth-backend-changed",
            Self::ClaimPersisted { .. } => "claim-persisted",
            Self::ClaimRetrieved { .. } => "claim-retrieved",
            Self::ClaimRetracted { .. } => "claim-retracted",
            Self::ClaimConsistencyCheckPassed { .. } => "claim-consistency-check-passed",
            Self::ClaimConsistencyCheckFailed { .. } => "claim-consistency-check-failed",
            Self::ContradictionDetectedEvent { .. } => "contradiction-detected-event",
            Self::ContradictionResolvedEvent { .. } => "contradiction-resolved-event",
            Self::CorroborationRecordedEvent { .. } => "corroboration-recorded-event",
            Self::EvidenceLinkCreated { .. } => "evidence-link-created",
            Self::EvidenceLinkRemoved { .. } => "evidence-link-removed",
            Self::EvidenceAdequacyAssessed { .. } => "evidence-adequacy-assessed",
            Self::ClaimExported { .. } => "claim-exported",
            Self::ClaimExportFailed { .. } => "claim-export-failed",
            Self::TruthSubscriberRegistered { .. } => "truth-subscriber-registered",
            Self::TruthSubscriberRemoved { .. } => "truth-subscriber-removed",
            Self::TruthEventPublished { .. } => "truth-event-published",
            Self::SourceReliabilityUpdated { .. } => "source-reliability-updated",
            Self::SourceReliabilityQueried { .. } => "source-reliability-queried",
            Self::SourceReliabilityReset { .. } => "source-reliability-reset",
        }
    }
}

impl TruthEventType {
    pub fn is_backend_event(&self) -> bool {
        matches!(self, Self::TruthBackendChanged { .. })
    }

    pub fn is_backend_claim_event(&self) -> bool {
        matches!(
            self,
            Self::ClaimPersisted { .. }
                | Self::ClaimRetrieved { .. }
                | Self::ClaimRetracted { .. }
                | Self::ClaimConsistencyCheckPassed { .. }
                | Self::ClaimConsistencyCheckFailed { .. }
                | Self::ClaimExported { .. }
                | Self::ClaimExportFailed { .. }
        )
    }

    pub fn is_contradiction_relation_event(&self) -> bool {
        matches!(
            self,
            Self::ContradictionDetectedEvent { .. }
                | Self::ContradictionResolvedEvent { .. }
                | Self::CorroborationRecordedEvent { .. }
        )
    }

    pub fn is_evidence_event(&self) -> bool {
        matches!(
            self,
            Self::EvidenceLinkCreated { .. }
                | Self::EvidenceLinkRemoved { .. }
                | Self::EvidenceAdequacyAssessed { .. }
        )
    }

    pub fn is_reliability_event(&self) -> bool {
        matches!(
            self,
            Self::SourceReliabilityUpdated { .. }
                | Self::SourceReliabilityQueried { .. }
                | Self::SourceReliabilityReset { .. }
        )
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer2_event_type_display() {
        let events = vec![
            TruthEventType::RunningStatsUpdated { count: 10, mean: 5.0 },
            TruthEventType::ConfidenceCalibrated { raw: 0.8, calibrated: 0.75 },
            TruthEventType::BrierScoreComputed { score: 0.05 },
            TruthEventType::ConsistencyTestRun { test_type: "mean-drift".into(), passed: true },
            TruthEventType::DriftDetected { drift_type: "mean".into(), magnitude: 3.5 },
            TruthEventType::OutputFingerprinted { hash_prefix: "abc123".into() },
            TruthEventType::ClaimRecorded { source: "s1".into(), subject: "x".into() },
            TruthEventType::ContradictionFound { subject: "x".into(), severity: "high".into() },
            TruthEventType::ContradictionResolvedL2 { strategy: "highest-confidence".into() },
            TruthEventType::GroundTruthSet { key: "k1".into(), source: "test".into() },
            TruthEventType::GroundTruthVerified { key: "k1".into(), matches: true },
            TruthEventType::AccuracyComputed { overall: 0.95, subjects: 10 },
            TruthEventType::ConsensusReached { agreement: 0.8, sources: 5 },
            TruthEventType::ConsensusNotReached { sources: 3, threshold: 0.67 },
            TruthEventType::MerkleRootComputed { leaf_count: 100, root_prefix: "def456".into() },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
    }

    #[test]
    fn test_layer2_events_by_type() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::DriftDetected { drift_type: "mean".into(), magnitude: 2.0 },
            "system",
            1000,
            "drift found",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::ConsensusReached { agreement: 0.9, sources: 3 },
            "system",
            2000,
            "consensus",
        ));
        assert_eq!(log.events_by_type("drift-detected").len(), 1);
        assert_eq!(log.events_by_type("consensus-reached").len(), 1);
    }

    // ── Layer 3 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer3_event_type_display() {
        let events = vec![
            TruthEventType::TruthBackendChanged { backend_id: "mem-1".into() },
            TruthEventType::ClaimPersisted { claim_id: "c1".into() },
            TruthEventType::ClaimRetrieved { claim_id: "c1".into() },
            TruthEventType::ClaimRetracted { claim_id: "c1".into() },
            TruthEventType::ClaimConsistencyCheckPassed { claim_id: "c1".into(), checker_id: "sc-1".into() },
            TruthEventType::ClaimConsistencyCheckFailed { claim_id: "c1".into(), checker_id: "sc-1".into(), reason: "bad".into() },
            TruthEventType::ContradictionDetectedEvent { claim_a: "c1".into(), claim_b: "c2".into(), explanation: "conflict".into() },
            TruthEventType::ContradictionResolvedEvent { claim_a: "c1".into(), claim_b: "c2".into() },
            TruthEventType::CorroborationRecordedEvent { claim_a: "c1".into(), claim_b: "c2".into() },
            TruthEventType::EvidenceLinkCreated { claim_id: "c1".into(), attestation_ref: "att-1".into() },
            TruthEventType::EvidenceLinkRemoved { claim_id: "c1".into(), attestation_ref: "att-1".into() },
            TruthEventType::EvidenceAdequacyAssessed { claim_id: "c1".into(), adequate: true },
            TruthEventType::ClaimExported { claim_id: "c1".into(), format: "json".into() },
            TruthEventType::ClaimExportFailed { claim_id: "c1".into(), reason: "err".into() },
            TruthEventType::TruthSubscriberRegistered { subscriber_id: "s1".into() },
            TruthEventType::TruthSubscriberRemoved { subscriber_id: "s1".into() },
            TruthEventType::TruthEventPublished { event_type_name: "claim_persisted".into() },
            TruthEventType::SourceReliabilityUpdated { source_id: "alice".into(), class: "High".into() },
            TruthEventType::SourceReliabilityQueried { source_id: "alice".into() },
            TruthEventType::SourceReliabilityReset { source_id: "alice".into() },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
            assert!(!event.type_name().is_empty());
        }
    }

    #[test]
    fn test_classification_methods() {
        assert!(TruthEventType::TruthBackendChanged { backend_id: "b".into() }.is_backend_event());
        assert!(!TruthEventType::ClaimPersisted { claim_id: "c".into() }.is_backend_event());

        assert!(TruthEventType::ClaimPersisted { claim_id: "c".into() }.is_backend_claim_event());
        assert!(TruthEventType::ClaimRetracted { claim_id: "c".into() }.is_backend_claim_event());
        assert!(TruthEventType::ClaimExported { claim_id: "c".into(), format: "json".into() }.is_backend_claim_event());

        assert!(TruthEventType::ContradictionDetectedEvent { claim_a: "a".into(), claim_b: "b".into(), explanation: "x".into() }.is_contradiction_relation_event());
        assert!(TruthEventType::ContradictionResolvedEvent { claim_a: "a".into(), claim_b: "b".into() }.is_contradiction_relation_event());
        assert!(TruthEventType::CorroborationRecordedEvent { claim_a: "a".into(), claim_b: "b".into() }.is_contradiction_relation_event());

        assert!(TruthEventType::EvidenceLinkCreated { claim_id: "c".into(), attestation_ref: "a".into() }.is_evidence_event());
        assert!(TruthEventType::EvidenceAdequacyAssessed { claim_id: "c".into(), adequate: true }.is_evidence_event());

        assert!(TruthEventType::SourceReliabilityUpdated { source_id: "s".into(), class: "H".into() }.is_reliability_event());
        assert!(TruthEventType::SourceReliabilityReset { source_id: "s".into() }.is_reliability_event());
    }

    #[test]
    fn test_layer3_events_by_type() {
        let mut log = TruthAuditLog::new();
        log.record(TruthAuditEvent::new(
            TruthEventType::ClaimPersisted { claim_id: "c1".into() },
            "system",
            1000,
            "stored",
        ));
        log.record(TruthAuditEvent::new(
            TruthEventType::EvidenceLinkCreated { claim_id: "c1".into(), attestation_ref: "att-1".into() },
            "system",
            2000,
            "linked",
        ));
        assert_eq!(log.events_by_type("claim-persisted").len(), 1);
        assert_eq!(log.events_by_type("evidence-link-created").len(), 1);
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
