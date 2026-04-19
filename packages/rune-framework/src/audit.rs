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
        };
        f.write_str(s)
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
