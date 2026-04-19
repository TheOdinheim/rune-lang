// ═══════════════════════════════════════════════════════════════════════
// Audit — provenance audit events and log.
//
// ProvenanceAuditLog records timestamped events for all provenance-
// related actions: registration, versioning, lineage, transformations,
// model lifecycle, dependency tracking, and verification outcomes.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactId;

// ── ProvenanceEventType ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceEventType {
    ArtifactRegistered,
    ArtifactVersioned,
    LineageRecorded,
    TransformationRecorded,
    ModelRegistered,
    ModelDeployed,
    ModelRetired,
    DependencyAdded,
    DependencyVerified,
    VulnerabilityFound,
    SlsaAssessed,
    VerificationCompleted,
    ProvenanceChainBroken,
    // Layer 2 event types
    ArtifactHashComputed,
    ArtifactIntegrityVerified,
    ContentAddressedStored,
    LineageRecordAppended,
    LineageChainVerified,
    LineageAncestryQueried,
    DependencyCycleDetected,
    BuildReproducibilityChecked,
    SlsaAttestationGenerated,
    SlsaAttestationVerified,
    ProvenanceGraphMetricsComputed,
    ImpactAnalysisPerformed,
    TrainingDataRegistered,
    ModelCardGenerated,
    DependencyGraphAnalyzed,
}

impl fmt::Display for ProvenanceEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactRegistered => f.write_str("artifact-registered"),
            Self::ArtifactVersioned => f.write_str("artifact-versioned"),
            Self::LineageRecorded => f.write_str("lineage-recorded"),
            Self::TransformationRecorded => f.write_str("transformation-recorded"),
            Self::ModelRegistered => f.write_str("model-registered"),
            Self::ModelDeployed => f.write_str("model-deployed"),
            Self::ModelRetired => f.write_str("model-retired"),
            Self::DependencyAdded => f.write_str("dependency-added"),
            Self::DependencyVerified => f.write_str("dependency-verified"),
            Self::VulnerabilityFound => f.write_str("vulnerability-found"),
            Self::SlsaAssessed => f.write_str("slsa-assessed"),
            Self::VerificationCompleted => f.write_str("verification-completed"),
            Self::ProvenanceChainBroken => f.write_str("provenance-chain-broken"),
            Self::ArtifactHashComputed => f.write_str("artifact-hash-computed"),
            Self::ArtifactIntegrityVerified => f.write_str("artifact-integrity-verified"),
            Self::ContentAddressedStored => f.write_str("content-addressed-stored"),
            Self::LineageRecordAppended => f.write_str("lineage-record-appended"),
            Self::LineageChainVerified => f.write_str("lineage-chain-verified"),
            Self::LineageAncestryQueried => f.write_str("lineage-ancestry-queried"),
            Self::DependencyCycleDetected => f.write_str("dependency-cycle-detected"),
            Self::BuildReproducibilityChecked => f.write_str("build-reproducibility-checked"),
            Self::SlsaAttestationGenerated => f.write_str("slsa-attestation-generated"),
            Self::SlsaAttestationVerified => f.write_str("slsa-attestation-verified"),
            Self::ProvenanceGraphMetricsComputed => f.write_str("provenance-graph-metrics-computed"),
            Self::ImpactAnalysisPerformed => f.write_str("impact-analysis-performed"),
            Self::TrainingDataRegistered => f.write_str("training-data-registered"),
            Self::ModelCardGenerated => f.write_str("model-card-generated"),
            Self::DependencyGraphAnalyzed => f.write_str("dependency-graph-analyzed"),
        }
    }
}

// ── ProvenanceAuditEvent ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProvenanceAuditEvent {
    pub event_type: ProvenanceEventType,
    pub artifact_id: ArtifactId,
    pub actor: String,
    pub timestamp: i64,
    pub description: String,
}

impl ProvenanceAuditEvent {
    pub fn new(
        event_type: ProvenanceEventType,
        artifact_id: impl Into<String>,
        actor: impl Into<String>,
        timestamp: i64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            artifact_id: ArtifactId::new(artifact_id),
            actor: actor.into(),
            timestamp,
            description: description.into(),
        }
    }
}

// ── ProvenanceAuditLog ───────────────────────────────────────────────

#[derive(Default)]
pub struct ProvenanceAuditLog {
    pub events: Vec<ProvenanceAuditEvent>,
}

impl ProvenanceAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: ProvenanceAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_artifact(&self, artifact_id: &ArtifactId) -> Vec<&ProvenanceAuditEvent> {
        self.events
            .iter()
            .filter(|e| &e.artifact_id == artifact_id)
            .collect()
    }

    pub fn events_by_type(&self, event_type: &ProvenanceEventType) -> Vec<&ProvenanceAuditEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&ProvenanceAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn verification_events(&self) -> Vec<&ProvenanceAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    ProvenanceEventType::VerificationCompleted
                        | ProvenanceEventType::ProvenanceChainBroken
                )
            })
            .collect()
    }

    pub fn vulnerability_events(&self) -> Vec<&ProvenanceAuditEvent> {
        self.events_by_type(&ProvenanceEventType::VulnerabilityFound)
    }

    pub fn model_events(&self) -> Vec<&ProvenanceAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    ProvenanceEventType::ModelRegistered
                        | ProvenanceEventType::ModelDeployed
                        | ProvenanceEventType::ModelRetired
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

    fn event(etype: ProvenanceEventType, id: &str, ts: i64) -> ProvenanceAuditEvent {
        ProvenanceAuditEvent::new(etype, id, "alice", ts, "test event")
    }

    #[test]
    fn test_record_and_count() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a1", 1000));
        log.record(event(ProvenanceEventType::LineageRecorded, "a1", 2000));
        assert_eq!(log.count(), 2);
    }

    #[test]
    fn test_events_for_artifact() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a1", 1000));
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a2", 2000));
        assert_eq!(log.events_for_artifact(&ArtifactId::new("a1")).len(), 1);
    }

    #[test]
    fn test_events_by_type() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a1", 1000));
        log.record(event(ProvenanceEventType::ModelRegistered, "m1", 2000));
        assert_eq!(
            log.events_by_type(&ProvenanceEventType::ArtifactRegistered).len(),
            1
        );
    }

    #[test]
    fn test_since() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a1", 1000));
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a2", 2000));
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a3", 3000));
        assert_eq!(log.since(2000).len(), 2);
    }

    #[test]
    fn test_verification_events() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::VerificationCompleted, "a1", 1000));
        log.record(event(ProvenanceEventType::ProvenanceChainBroken, "a2", 2000));
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a3", 3000));
        assert_eq!(log.verification_events().len(), 2);
    }

    #[test]
    fn test_vulnerability_events() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::VulnerabilityFound, "a1", 1000));
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a2", 2000));
        assert_eq!(log.vulnerability_events().len(), 1);
    }

    #[test]
    fn test_model_events() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::ModelRegistered, "m1", 1000));
        log.record(event(ProvenanceEventType::ModelDeployed, "m1", 2000));
        log.record(event(ProvenanceEventType::ModelRetired, "m1", 3000));
        log.record(event(ProvenanceEventType::ArtifactRegistered, "a1", 4000));
        assert_eq!(log.model_events().len(), 3);
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(ProvenanceEventType::ArtifactRegistered.to_string(), "artifact-registered");
        assert_eq!(ProvenanceEventType::ArtifactVersioned.to_string(), "artifact-versioned");
        assert_eq!(ProvenanceEventType::LineageRecorded.to_string(), "lineage-recorded");
        assert_eq!(ProvenanceEventType::TransformationRecorded.to_string(), "transformation-recorded");
        assert_eq!(ProvenanceEventType::ModelRegistered.to_string(), "model-registered");
        assert_eq!(ProvenanceEventType::ModelDeployed.to_string(), "model-deployed");
        assert_eq!(ProvenanceEventType::ModelRetired.to_string(), "model-retired");
        assert_eq!(ProvenanceEventType::DependencyAdded.to_string(), "dependency-added");
        assert_eq!(ProvenanceEventType::DependencyVerified.to_string(), "dependency-verified");
        assert_eq!(ProvenanceEventType::VulnerabilityFound.to_string(), "vulnerability-found");
        assert_eq!(ProvenanceEventType::SlsaAssessed.to_string(), "slsa-assessed");
        assert_eq!(ProvenanceEventType::VerificationCompleted.to_string(), "verification-completed");
        assert_eq!(ProvenanceEventType::ProvenanceChainBroken.to_string(), "provenance-chain-broken");
    }

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_layer2_event_type_display() {
        assert_eq!(ProvenanceEventType::ArtifactHashComputed.to_string(), "artifact-hash-computed");
        assert_eq!(ProvenanceEventType::ArtifactIntegrityVerified.to_string(), "artifact-integrity-verified");
        assert_eq!(ProvenanceEventType::ContentAddressedStored.to_string(), "content-addressed-stored");
        assert_eq!(ProvenanceEventType::LineageRecordAppended.to_string(), "lineage-record-appended");
        assert_eq!(ProvenanceEventType::LineageChainVerified.to_string(), "lineage-chain-verified");
        assert_eq!(ProvenanceEventType::LineageAncestryQueried.to_string(), "lineage-ancestry-queried");
        assert_eq!(ProvenanceEventType::DependencyCycleDetected.to_string(), "dependency-cycle-detected");
        assert_eq!(ProvenanceEventType::BuildReproducibilityChecked.to_string(), "build-reproducibility-checked");
        assert_eq!(ProvenanceEventType::SlsaAttestationGenerated.to_string(), "slsa-attestation-generated");
        assert_eq!(ProvenanceEventType::SlsaAttestationVerified.to_string(), "slsa-attestation-verified");
        assert_eq!(ProvenanceEventType::ProvenanceGraphMetricsComputed.to_string(), "provenance-graph-metrics-computed");
        assert_eq!(ProvenanceEventType::ImpactAnalysisPerformed.to_string(), "impact-analysis-performed");
        assert_eq!(ProvenanceEventType::TrainingDataRegistered.to_string(), "training-data-registered");
        assert_eq!(ProvenanceEventType::ModelCardGenerated.to_string(), "model-card-generated");
        assert_eq!(ProvenanceEventType::DependencyGraphAnalyzed.to_string(), "dependency-graph-analyzed");
    }

    #[test]
    fn test_layer2_events_by_type() {
        let mut log = ProvenanceAuditLog::new();
        log.record(event(ProvenanceEventType::ArtifactHashComputed, "a1", 1000));
        log.record(event(ProvenanceEventType::SlsaAttestationGenerated, "a1", 2000));
        log.record(event(ProvenanceEventType::ArtifactHashComputed, "a2", 3000));
        assert_eq!(
            log.events_by_type(&ProvenanceEventType::ArtifactHashComputed).len(),
            2
        );
        assert_eq!(
            log.events_by_type(&ProvenanceEventType::SlsaAttestationGenerated).len(),
            1
        );
    }

    #[test]
    fn test_layer2_event_construction() {
        let e = ProvenanceAuditEvent::new(
            ProvenanceEventType::LineageChainVerified,
            "chain-1",
            "system",
            5000,
            "Chain verified with 10 links",
        );
        assert_eq!(e.event_type, ProvenanceEventType::LineageChainVerified);
        assert_eq!(e.artifact_id, ArtifactId::new("chain-1"));
        assert_eq!(e.timestamp, 5000);
    }

    #[test]
    fn test_layer2_event_serialization() {
        let et = ProvenanceEventType::ModelCardGenerated;
        let json = serde_json::to_string(&et).unwrap();
        let deserialized: ProvenanceEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, et);
    }
}
