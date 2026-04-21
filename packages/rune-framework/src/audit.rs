// ═══════════════════════════════════════════════════════════════════════
// Audit — Framework-level audit logging.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── FrameworkEventType ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameworkEventType {
    PipelineEvaluated,
    PipelineDryRun,
    StageExecuted,
    StageFailed,
    ComponentRegistered,
    ComponentDeregistered,
    ComponentStatusChanged,
    HealthAssessed,
    ConfigValidated,
    WorkflowApplied,
    // ── Layer 2 event types ──────────────────────────────────────
    FrameworkRegistered,
    FrameworkControlAdded,
    ControlMappingCreated,
    ControlEquivalenceAssessed,
    GapAnalysisPerformed,
    ComplianceScoreCalculated,
    MaturityAssessed,
    MaturityTrendDetected,
    EvidenceRequirementCreated,
    EvidenceCollected,
    EvidenceVerified,
    EvidenceOverdue,
    RegulatoryChangeTracked,
    RegulatoryImpactAssessed,
    RegulatoryChangeEffective,
    // ── Layer 3 event types ─────────────────────────────────────
    FrameworkBackendChanged { backend_id: String },
    FrameworkManifestStored { framework_id: String, version: String },
    FrameworkManifestRetrieved { framework_id: String },
    FrameworkManifestDeleted { framework_id: String },
    FrameworkRequirementStored { requirement_id: String, framework_id: String },
    ManifestFrameworkVersionResolved { name: String, version: String },
    CrossFrameworkMappingStored { mapping_id: String, source: String, target: String },
    CrossFrameworkMappingQueried { requirement_id: String, result_count: String },
    ComplianceEvidenceRecordStored { record_id: String, framework_id: String },
    ComplianceEvidenceLinked { link_id: String, requirement_id: String },
    ComplianceEvidenceUnlinked { link_id: String },
    ComplianceEvidenceFreshnessChecked { link_id: String, freshness: String },
    ComplianceEvidenceReviewRecorded { link_id: String, verdict: String },
    FrameworkManifestRegistered { framework_id: String, registry_id: String },
    FrameworkManifestUnregistered { framework_id: String, registry_id: String },
    FrameworkRegistrySubscribed { framework_id: String, subscription_id: String },
    FrameworkManifestExported { framework_id: String, format: String },
    FrameworkManifestExportFailed { framework_id: String, reason: String },
    FrameworkManifestValidated { framework_id: String, passed: bool },
    FrameworkManifestValidationFailed { framework_id: String, severity: String },
    FrameworkSubscriberRegistered { subscriber_id: String },
    FrameworkSubscriberRemoved { subscriber_id: String },
    FrameworkLifecycleEventPublished { event_count: String },
}

impl fmt::Display for FrameworkEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PipelineEvaluated => "PipelineEvaluated",
            Self::PipelineDryRun => "PipelineDryRun",
            Self::StageExecuted => "StageExecuted",
            Self::StageFailed => "StageFailed",
            Self::ComponentRegistered => "ComponentRegistered",
            Self::ComponentDeregistered => "ComponentDeregistered",
            Self::ComponentStatusChanged => "ComponentStatusChanged",
            Self::HealthAssessed => "HealthAssessed",
            Self::ConfigValidated => "ConfigValidated",
            Self::WorkflowApplied => "WorkflowApplied",
            Self::FrameworkRegistered => "FrameworkRegistered",
            Self::FrameworkControlAdded => "FrameworkControlAdded",
            Self::ControlMappingCreated => "ControlMappingCreated",
            Self::ControlEquivalenceAssessed => "ControlEquivalenceAssessed",
            Self::GapAnalysisPerformed => "GapAnalysisPerformed",
            Self::ComplianceScoreCalculated => "ComplianceScoreCalculated",
            Self::MaturityAssessed => "MaturityAssessed",
            Self::MaturityTrendDetected => "MaturityTrendDetected",
            Self::EvidenceRequirementCreated => "EvidenceRequirementCreated",
            Self::EvidenceCollected => "EvidenceCollected",
            Self::EvidenceVerified => "EvidenceVerified",
            Self::EvidenceOverdue => "EvidenceOverdue",
            Self::RegulatoryChangeTracked => "RegulatoryChangeTracked",
            Self::RegulatoryImpactAssessed => "RegulatoryImpactAssessed",
            Self::RegulatoryChangeEffective => "RegulatoryChangeEffective",
            // L3 variants — delegate to type_name for consistency
            Self::FrameworkBackendChanged { .. }
            | Self::FrameworkManifestStored { .. }
            | Self::FrameworkManifestRetrieved { .. }
            | Self::FrameworkManifestDeleted { .. }
            | Self::FrameworkRequirementStored { .. }
            | Self::ManifestFrameworkVersionResolved { .. }
            | Self::CrossFrameworkMappingStored { .. }
            | Self::CrossFrameworkMappingQueried { .. }
            | Self::ComplianceEvidenceRecordStored { .. }
            | Self::ComplianceEvidenceLinked { .. }
            | Self::ComplianceEvidenceUnlinked { .. }
            | Self::ComplianceEvidenceFreshnessChecked { .. }
            | Self::ComplianceEvidenceReviewRecorded { .. }
            | Self::FrameworkManifestRegistered { .. }
            | Self::FrameworkManifestUnregistered { .. }
            | Self::FrameworkRegistrySubscribed { .. }
            | Self::FrameworkManifestExported { .. }
            | Self::FrameworkManifestExportFailed { .. }
            | Self::FrameworkManifestValidated { .. }
            | Self::FrameworkManifestValidationFailed { .. }
            | Self::FrameworkSubscriberRegistered { .. }
            | Self::FrameworkSubscriberRemoved { .. }
            | Self::FrameworkLifecycleEventPublished { .. } => {
                return f.write_str(self.type_name());
            }
        };
        f.write_str(s)
    }
}

impl FrameworkEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::PipelineEvaluated => "pipeline-evaluated",
            Self::PipelineDryRun => "pipeline-dry-run",
            Self::StageExecuted => "stage-executed",
            Self::StageFailed => "stage-failed",
            Self::ComponentRegistered => "component-registered",
            Self::ComponentDeregistered => "component-deregistered",
            Self::ComponentStatusChanged => "component-status-changed",
            Self::HealthAssessed => "health-assessed",
            Self::ConfigValidated => "config-validated",
            Self::WorkflowApplied => "workflow-applied",
            Self::FrameworkRegistered => "framework-registered",
            Self::FrameworkControlAdded => "framework-control-added",
            Self::ControlMappingCreated => "control-mapping-created",
            Self::ControlEquivalenceAssessed => "control-equivalence-assessed",
            Self::GapAnalysisPerformed => "gap-analysis-performed",
            Self::ComplianceScoreCalculated => "compliance-score-calculated",
            Self::MaturityAssessed => "maturity-assessed",
            Self::MaturityTrendDetected => "maturity-trend-detected",
            Self::EvidenceRequirementCreated => "evidence-requirement-created",
            Self::EvidenceCollected => "evidence-collected",
            Self::EvidenceVerified => "evidence-verified",
            Self::EvidenceOverdue => "evidence-overdue",
            Self::RegulatoryChangeTracked => "regulatory-change-tracked",
            Self::RegulatoryImpactAssessed => "regulatory-impact-assessed",
            Self::RegulatoryChangeEffective => "regulatory-change-effective",
            // L3 variants
            Self::FrameworkBackendChanged { .. } => "framework-backend-changed",
            Self::FrameworkManifestStored { .. } => "framework-manifest-stored",
            Self::FrameworkManifestRetrieved { .. } => "framework-manifest-retrieved",
            Self::FrameworkManifestDeleted { .. } => "framework-manifest-deleted",
            Self::FrameworkRequirementStored { .. } => "framework-requirement-stored",
            Self::ManifestFrameworkVersionResolved { .. } => "manifest-framework-version-resolved",
            Self::CrossFrameworkMappingStored { .. } => "cross-framework-mapping-stored",
            Self::CrossFrameworkMappingQueried { .. } => "cross-framework-mapping-queried",
            Self::ComplianceEvidenceRecordStored { .. } => "compliance-evidence-record-stored",
            Self::ComplianceEvidenceLinked { .. } => "compliance-evidence-linked",
            Self::ComplianceEvidenceUnlinked { .. } => "compliance-evidence-unlinked",
            Self::ComplianceEvidenceFreshnessChecked { .. } => "compliance-evidence-freshness-checked",
            Self::ComplianceEvidenceReviewRecorded { .. } => "compliance-evidence-review-recorded",
            Self::FrameworkManifestRegistered { .. } => "framework-manifest-registered",
            Self::FrameworkManifestUnregistered { .. } => "framework-manifest-unregistered",
            Self::FrameworkRegistrySubscribed { .. } => "framework-registry-subscribed",
            Self::FrameworkManifestExported { .. } => "framework-manifest-exported",
            Self::FrameworkManifestExportFailed { .. } => "framework-manifest-export-failed",
            Self::FrameworkManifestValidated { .. } => "framework-manifest-validated",
            Self::FrameworkManifestValidationFailed { .. } => "framework-manifest-validation-failed",
            Self::FrameworkSubscriberRegistered { .. } => "framework-subscriber-registered",
            Self::FrameworkSubscriberRemoved { .. } => "framework-subscriber-removed",
            Self::FrameworkLifecycleEventPublished { .. } => "framework-lifecycle-event-published",
        }
    }

    pub fn kind(&self) -> &str {
        self.type_name()
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::FrameworkBackendChanged { .. }
                | Self::FrameworkManifestStored { .. }
                | Self::FrameworkManifestRetrieved { .. }
                | Self::FrameworkManifestDeleted { .. }
                | Self::FrameworkRequirementStored { .. }
                | Self::ManifestFrameworkVersionResolved { .. }
                | Self::ComplianceEvidenceRecordStored { .. }
        )
    }

    pub fn is_framework_event(&self) -> bool {
        matches!(
            self,
            Self::FrameworkManifestRegistered { .. }
                | Self::FrameworkManifestUnregistered { .. }
                | Self::FrameworkRegistrySubscribed { .. }
        )
    }

    pub fn is_mapping_event(&self) -> bool {
        matches!(
            self,
            Self::CrossFrameworkMappingStored { .. }
                | Self::CrossFrameworkMappingQueried { .. }
        )
    }

    pub fn is_evidence_event(&self) -> bool {
        matches!(
            self,
            Self::ComplianceEvidenceLinked { .. }
                | Self::ComplianceEvidenceUnlinked { .. }
                | Self::ComplianceEvidenceFreshnessChecked { .. }
                | Self::ComplianceEvidenceReviewRecorded { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::FrameworkManifestExported { .. }
                | Self::FrameworkManifestExportFailed { .. }
        )
    }

    pub fn is_validation_event(&self) -> bool {
        matches!(
            self,
            Self::FrameworkManifestValidated { .. }
                | Self::FrameworkManifestValidationFailed { .. }
        )
    }
}

// ── FrameworkAuditEvent ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkAuditEvent {
    pub event_type: FrameworkEventType,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
}

impl FrameworkAuditEvent {
    pub fn new(
        event_type: FrameworkEventType,
        timestamp: i64,
        actor: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
        }
    }
}

// ── FrameworkAuditLog ─────────────────────────────────────────────────

pub struct FrameworkAuditLog {
    events: Vec<FrameworkAuditEvent>,
}

impl FrameworkAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: FrameworkAuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[FrameworkAuditEvent] {
        &self.events
    }

    pub fn events_by_type(&self, event_type: &FrameworkEventType) -> Vec<&FrameworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .collect()
    }

    pub fn events_since(&self, timestamp: i64) -> Vec<&FrameworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn pipeline_events(&self) -> Vec<&FrameworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    FrameworkEventType::PipelineEvaluated
                        | FrameworkEventType::PipelineDryRun
                        | FrameworkEventType::StageExecuted
                        | FrameworkEventType::StageFailed
                )
            })
            .collect()
    }

    pub fn component_events(&self) -> Vec<&FrameworkAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    FrameworkEventType::ComponentRegistered
                        | FrameworkEventType::ComponentDeregistered
                        | FrameworkEventType::ComponentStatusChanged
                )
            })
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for FrameworkAuditLog {
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

    #[test]
    fn test_event_type_display_all() {
        let types = vec![
            FrameworkEventType::PipelineEvaluated,
            FrameworkEventType::PipelineDryRun,
            FrameworkEventType::StageExecuted,
            FrameworkEventType::StageFailed,
            FrameworkEventType::ComponentRegistered,
            FrameworkEventType::ComponentDeregistered,
            FrameworkEventType::ComponentStatusChanged,
            FrameworkEventType::HealthAssessed,
            FrameworkEventType::ConfigValidated,
            FrameworkEventType::WorkflowApplied,
            FrameworkEventType::FrameworkRegistered,
            FrameworkEventType::FrameworkControlAdded,
            FrameworkEventType::ControlMappingCreated,
            FrameworkEventType::ControlEquivalenceAssessed,
            FrameworkEventType::GapAnalysisPerformed,
            FrameworkEventType::ComplianceScoreCalculated,
            FrameworkEventType::MaturityAssessed,
            FrameworkEventType::MaturityTrendDetected,
            FrameworkEventType::EvidenceRequirementCreated,
            FrameworkEventType::EvidenceCollected,
            FrameworkEventType::EvidenceVerified,
            FrameworkEventType::EvidenceOverdue,
            FrameworkEventType::RegulatoryChangeTracked,
            FrameworkEventType::RegulatoryImpactAssessed,
            FrameworkEventType::RegulatoryChangeEffective,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 25);
    }

    #[test]
    fn test_l3_event_type_display_and_kind() {
        let l3_types = vec![
            FrameworkEventType::FrameworkBackendChanged { backend_id: "b1".into() },
            FrameworkEventType::FrameworkManifestStored { framework_id: "f1".into(), version: "1.0".into() },
            FrameworkEventType::FrameworkManifestRetrieved { framework_id: "f1".into() },
            FrameworkEventType::FrameworkManifestDeleted { framework_id: "f1".into() },
            FrameworkEventType::FrameworkRequirementStored { requirement_id: "r1".into(), framework_id: "f1".into() },
            FrameworkEventType::ManifestFrameworkVersionResolved { name: "n".into(), version: "1.0".into() },
            FrameworkEventType::CrossFrameworkMappingStored { mapping_id: "m1".into(), source: "s".into(), target: "t".into() },
            FrameworkEventType::CrossFrameworkMappingQueried { requirement_id: "r1".into(), result_count: "3".into() },
            FrameworkEventType::ComplianceEvidenceRecordStored { record_id: "ev1".into(), framework_id: "f1".into() },
            FrameworkEventType::ComplianceEvidenceLinked { link_id: "l1".into(), requirement_id: "r1".into() },
            FrameworkEventType::ComplianceEvidenceUnlinked { link_id: "l1".into() },
            FrameworkEventType::ComplianceEvidenceFreshnessChecked { link_id: "l1".into(), freshness: "Current".into() },
            FrameworkEventType::ComplianceEvidenceReviewRecorded { link_id: "l1".into(), verdict: "Adequate".into() },
            FrameworkEventType::FrameworkManifestRegistered { framework_id: "f1".into(), registry_id: "reg".into() },
            FrameworkEventType::FrameworkManifestUnregistered { framework_id: "f1".into(), registry_id: "reg".into() },
            FrameworkEventType::FrameworkRegistrySubscribed { framework_id: "f1".into(), subscription_id: "sub".into() },
            FrameworkEventType::FrameworkManifestExported { framework_id: "f1".into(), format: "JSON".into() },
            FrameworkEventType::FrameworkManifestExportFailed { framework_id: "f1".into(), reason: "err".into() },
            FrameworkEventType::FrameworkManifestValidated { framework_id: "f1".into(), passed: true },
            FrameworkEventType::FrameworkManifestValidationFailed { framework_id: "f1".into(), severity: "Error".into() },
            FrameworkEventType::FrameworkSubscriberRegistered { subscriber_id: "s1".into() },
            FrameworkEventType::FrameworkSubscriberRemoved { subscriber_id: "s1".into() },
            FrameworkEventType::FrameworkLifecycleEventPublished { event_count: "5".into() },
        ];
        for t in &l3_types {
            assert!(!t.to_string().is_empty(), "Display empty for {:?}", t);
            assert!(!t.kind().is_empty(), "kind() empty for {:?}", t);
            assert!(!t.type_name().is_empty());
        }
        assert_eq!(l3_types.len(), 23);
    }

    #[test]
    fn test_is_backend_event() {
        assert!(FrameworkEventType::FrameworkBackendChanged { backend_id: "b".into() }.is_backend_event());
        assert!(FrameworkEventType::FrameworkManifestStored { framework_id: "f".into(), version: "1".into() }.is_backend_event());
        assert!(!FrameworkEventType::ComplianceEvidenceLinked { link_id: "l".into(), requirement_id: "r".into() }.is_backend_event());
    }

    #[test]
    fn test_is_framework_event() {
        assert!(FrameworkEventType::FrameworkManifestRegistered { framework_id: "f".into(), registry_id: "r".into() }.is_framework_event());
        assert!(!FrameworkEventType::FrameworkBackendChanged { backend_id: "b".into() }.is_framework_event());
    }

    #[test]
    fn test_is_mapping_event() {
        assert!(FrameworkEventType::CrossFrameworkMappingStored { mapping_id: "m".into(), source: "s".into(), target: "t".into() }.is_mapping_event());
        assert!(FrameworkEventType::CrossFrameworkMappingQueried { requirement_id: "r".into(), result_count: "1".into() }.is_mapping_event());
        assert!(!FrameworkEventType::FrameworkBackendChanged { backend_id: "b".into() }.is_mapping_event());
    }

    #[test]
    fn test_is_evidence_event() {
        assert!(FrameworkEventType::ComplianceEvidenceLinked { link_id: "l".into(), requirement_id: "r".into() }.is_evidence_event());
        assert!(FrameworkEventType::ComplianceEvidenceReviewRecorded { link_id: "l".into(), verdict: "v".into() }.is_evidence_event());
        assert!(!FrameworkEventType::FrameworkManifestExported { framework_id: "f".into(), format: "j".into() }.is_evidence_event());
    }

    #[test]
    fn test_is_export_event() {
        assert!(FrameworkEventType::FrameworkManifestExported { framework_id: "f".into(), format: "j".into() }.is_export_event());
        assert!(FrameworkEventType::FrameworkManifestExportFailed { framework_id: "f".into(), reason: "r".into() }.is_export_event());
    }

    #[test]
    fn test_is_validation_event() {
        assert!(FrameworkEventType::FrameworkManifestValidated { framework_id: "f".into(), passed: true }.is_validation_event());
        assert!(FrameworkEventType::FrameworkManifestValidationFailed { framework_id: "f".into(), severity: "s".into() }.is_validation_event());
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut log = FrameworkAuditLog::new();
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1000,
            "system",
            "req-001 evaluated",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::ComponentRegistered,
            1001,
            "admin",
            "sec-1 registered",
        ));
        assert_eq!(log.event_count(), 2);
        assert_eq!(log.events().len(), 2);
    }

    #[test]
    fn test_events_by_type() {
        let mut log = FrameworkAuditLog::new();
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1000,
            "system",
            "a",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::StageFailed,
            1001,
            "system",
            "b",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1002,
            "system",
            "c",
        ));
        assert_eq!(
            log.events_by_type(&FrameworkEventType::PipelineEvaluated)
                .len(),
            2
        );
    }

    #[test]
    fn test_events_since() {
        let mut log = FrameworkAuditLog::new();
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            900,
            "s",
            "a",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1000,
            "s",
            "b",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1100,
            "s",
            "c",
        ));
        assert_eq!(log.events_since(1000).len(), 2);
    }

    #[test]
    fn test_pipeline_events() {
        let mut log = FrameworkAuditLog::new();
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1000,
            "s",
            "a",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::StageFailed,
            1001,
            "s",
            "b",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::ComponentRegistered,
            1002,
            "s",
            "c",
        ));
        assert_eq!(log.pipeline_events().len(), 2);
    }

    #[test]
    fn test_component_events() {
        let mut log = FrameworkAuditLog::new();
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::ComponentRegistered,
            1000,
            "s",
            "a",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::ComponentDeregistered,
            1001,
            "s",
            "b",
        ));
        log.record(FrameworkAuditEvent::new(
            FrameworkEventType::PipelineEvaluated,
            1002,
            "s",
            "c",
        ));
        assert_eq!(log.component_events().len(), 2);
    }
}
