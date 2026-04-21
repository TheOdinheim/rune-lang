// ═══════════════════════════════════════════════════════════════════════
// Audit — explainability-specific audit events and log.
//
// ExplainabilityAuditLog records timestamped events for decision
// recording, trace generation, factor analysis, counterfactual
// generation, narrative creation, audience adaptation, transparency
// reports, and errors.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── ExplainabilityEventType ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExplainabilityEventType {
    DecisionRecorded { decision_id: String, decision_type: String },
    TraceGenerated { decision_id: String, steps: usize },
    FactorAnalyzed { decision_id: String, factors: usize },
    CounterfactualGenerated { decision_id: String, changes: usize },
    NarrativeCreated { decision_id: String, detail_level: String },
    AudienceAdapted { decision_id: String, audience: String },
    ReportGenerated { report_title: String, decisions: usize },
    ExplainabilityError { operation: String, detail: String },
    // ── Layer 2 event types ─────────────────────────────────────────
    ExplanationTreeCreated { decision_id: String, depth: usize },
    ExplanationTreeQueried { decision_id: String, query_type: String },
    FeatureAttributionComputed { decision_id: String, features: usize },
    TopFeatureIdentified { decision_id: String, feature_name: String },
    L2CounterfactualGenerated { decision_id: String, changes: usize, feasibility: String },
    CounterfactualActionable { decision_id: String, distance: f64 },
    ExplanationRendered { decision_id: String, audience: String },
    CompletenessChecked { decision_id: String, score: f64 },
    RegulatoryCheckPerformed { decision_id: String, framework: String, passed: bool },
    ExplanationApproved { decision_id: String, reviewer: String },
    DecisionPatternRecorded { decision_id: String, outcome: String },
    BehaviorSummaryGenerated { total_decisions: usize },
    FairnessComputed { groups: usize, parity_diff: f64 },
    ExplanationComplianceRate { rate: f64 },
    ExplanationVersionCreated { decision_id: String, version: String },
    // ── Layer 3 event types ─────────────────────────────────────────
    ExplanationBackendChanged { backend_id: String },
    ExplanationStored { explanation_id: String, subject_id: String },
    ExplanationRetrieved { explanation_id: String },
    ExplanationExported { explanation_id: String, format: String },
    ExplanationExportFailed { explanation_id: String, format: String },
    ReasoningTraceBegun { trace_id: String, decision_id: String },
    ReasoningStepRecorded { trace_id: String, step_number: usize },
    ReasoningTraceCompleted { trace_id: String },
    ReasoningTraceAbandoned { trace_id: String },
    BackendFeatureAttributionComputed { prediction_id: String, method: String },
    FeatureAttributionFailed { prediction_id: String, method: String },
    BackendCounterfactualGenerated { prediction_id: String, examples: usize },
    CounterfactualGenerationFailed { prediction_id: String },
    RuleFiringRecorded { rule_id: String, decision_id: String },
    ExplanationQualityAssessed { explanation_id: String, quality_class: String },
    ExplanationQualityBreached { explanation_id: String, dimension: String },
    ExplanationSubscriberRegistered { subscriber_id: String },
    ExplanationSubscriberRemoved { subscriber_id: String },
    ExplanationEventPublished { event_type: String },
}

impl fmt::Display for ExplainabilityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionRecorded { decision_id, decision_type } => {
                write!(f, "decision-recorded:{decision_id} [{decision_type}]")
            }
            Self::TraceGenerated { decision_id, steps } => {
                write!(f, "trace-generated:{decision_id} ({steps} steps)")
            }
            Self::FactorAnalyzed { decision_id, factors } => {
                write!(f, "factor-analyzed:{decision_id} ({factors} factors)")
            }
            Self::CounterfactualGenerated { decision_id, changes } => {
                write!(f, "counterfactual-generated:{decision_id} ({changes} changes)")
            }
            Self::NarrativeCreated { decision_id, detail_level } => {
                write!(f, "narrative-created:{decision_id} [{detail_level}]")
            }
            Self::AudienceAdapted { decision_id, audience } => {
                write!(f, "audience-adapted:{decision_id} [{audience}]")
            }
            Self::ReportGenerated { report_title, decisions } => {
                write!(f, "report-generated:{report_title} ({decisions} decisions)")
            }
            Self::ExplainabilityError { operation, detail } => {
                write!(f, "explainability-error:{operation} [{detail}]")
            }
            Self::ExplanationTreeCreated { decision_id, depth } => {
                write!(f, "explanation-tree-created:{decision_id} (depth {depth})")
            }
            Self::ExplanationTreeQueried { decision_id, query_type } => {
                write!(f, "explanation-tree-queried:{decision_id} [{query_type}]")
            }
            Self::FeatureAttributionComputed { decision_id, features } => {
                write!(f, "feature-attribution-computed:{decision_id} ({features} features)")
            }
            Self::TopFeatureIdentified { decision_id, feature_name } => {
                write!(f, "top-feature-identified:{decision_id} [{feature_name}]")
            }
            Self::L2CounterfactualGenerated { decision_id, changes, feasibility } => {
                write!(f, "l2-counterfactual-generated:{decision_id} ({changes} changes, {feasibility})")
            }
            Self::CounterfactualActionable { decision_id, distance } => {
                write!(f, "counterfactual-actionable:{decision_id} (distance {distance:.2})")
            }
            Self::ExplanationRendered { decision_id, audience } => {
                write!(f, "explanation-rendered:{decision_id} [{audience}]")
            }
            Self::CompletenessChecked { decision_id, score } => {
                write!(f, "completeness-checked:{decision_id} (score {score:.2})")
            }
            Self::RegulatoryCheckPerformed { decision_id, framework, passed } => {
                write!(f, "regulatory-check:{decision_id} [{framework}] {}", if *passed { "passed" } else { "failed" })
            }
            Self::ExplanationApproved { decision_id, reviewer } => {
                write!(f, "explanation-approved:{decision_id} by {reviewer}")
            }
            Self::DecisionPatternRecorded { decision_id, outcome } => {
                write!(f, "decision-pattern-recorded:{decision_id} [{outcome}]")
            }
            Self::BehaviorSummaryGenerated { total_decisions } => {
                write!(f, "behavior-summary-generated ({total_decisions} decisions)")
            }
            Self::FairnessComputed { groups, parity_diff } => {
                write!(f, "fairness-computed ({groups} groups, parity diff {parity_diff:.4})")
            }
            Self::ExplanationComplianceRate { rate } => {
                write!(f, "explanation-compliance-rate ({rate:.2})")
            }
            Self::ExplanationVersionCreated { decision_id, version } => {
                write!(f, "explanation-version-created:{decision_id} [v{version}]")
            }
            Self::ExplanationBackendChanged { backend_id } => {
                write!(f, "explanation-backend-changed [{backend_id}]")
            }
            Self::ExplanationStored { explanation_id, subject_id } => {
                write!(f, "explanation-stored:{explanation_id} subject:{subject_id}")
            }
            Self::ExplanationRetrieved { explanation_id } => {
                write!(f, "explanation-retrieved:{explanation_id}")
            }
            Self::ExplanationExported { explanation_id, format } => {
                write!(f, "explanation-exported:{explanation_id} [{format}]")
            }
            Self::ExplanationExportFailed { explanation_id, format } => {
                write!(f, "explanation-export-failed:{explanation_id} [{format}]")
            }
            Self::ReasoningTraceBegun { trace_id, decision_id } => {
                write!(f, "reasoning-trace-begun:{trace_id} decision:{decision_id}")
            }
            Self::ReasoningStepRecorded { trace_id, step_number } => {
                write!(f, "reasoning-step-recorded:{trace_id} step:{step_number}")
            }
            Self::ReasoningTraceCompleted { trace_id } => {
                write!(f, "reasoning-trace-completed:{trace_id}")
            }
            Self::ReasoningTraceAbandoned { trace_id } => {
                write!(f, "reasoning-trace-abandoned:{trace_id}")
            }
            Self::BackendFeatureAttributionComputed { prediction_id, method } => {
                write!(f, "backend-feature-attribution-computed:{prediction_id} [{method}]")
            }
            Self::FeatureAttributionFailed { prediction_id, method } => {
                write!(f, "feature-attribution-failed:{prediction_id} [{method}]")
            }
            Self::BackendCounterfactualGenerated { prediction_id, examples } => {
                write!(f, "backend-counterfactual-generated:{prediction_id} ({examples} examples)")
            }
            Self::CounterfactualGenerationFailed { prediction_id } => {
                write!(f, "counterfactual-generation-failed:{prediction_id}")
            }
            Self::RuleFiringRecorded { rule_id, decision_id } => {
                write!(f, "rule-firing-recorded:{rule_id} decision:{decision_id}")
            }
            Self::ExplanationQualityAssessed { explanation_id, quality_class } => {
                write!(f, "explanation-quality-assessed:{explanation_id} [{quality_class}]")
            }
            Self::ExplanationQualityBreached { explanation_id, dimension } => {
                write!(f, "explanation-quality-breached:{explanation_id} [{dimension}]")
            }
            Self::ExplanationSubscriberRegistered { subscriber_id } => {
                write!(f, "explanation-subscriber-registered:{subscriber_id}")
            }
            Self::ExplanationSubscriberRemoved { subscriber_id } => {
                write!(f, "explanation-subscriber-removed:{subscriber_id}")
            }
            Self::ExplanationEventPublished { event_type } => {
                write!(f, "explanation-event-published [{event_type}]")
            }
        }
    }
}

impl ExplainabilityEventType {
    fn type_name(&self) -> &str {
        match self {
            Self::DecisionRecorded { .. } => "decision-recorded",
            Self::TraceGenerated { .. } => "trace-generated",
            Self::FactorAnalyzed { .. } => "factor-analyzed",
            Self::CounterfactualGenerated { .. } => "counterfactual-generated",
            Self::NarrativeCreated { .. } => "narrative-created",
            Self::AudienceAdapted { .. } => "audience-adapted",
            Self::ReportGenerated { .. } => "report-generated",
            Self::ExplainabilityError { .. } => "explainability-error",
            Self::ExplanationTreeCreated { .. } => "explanation-tree-created",
            Self::ExplanationTreeQueried { .. } => "explanation-tree-queried",
            Self::FeatureAttributionComputed { .. } => "feature-attribution-computed",
            Self::TopFeatureIdentified { .. } => "top-feature-identified",
            Self::L2CounterfactualGenerated { .. } => "l2-counterfactual-generated",
            Self::CounterfactualActionable { .. } => "counterfactual-actionable",
            Self::ExplanationRendered { .. } => "explanation-rendered",
            Self::CompletenessChecked { .. } => "completeness-checked",
            Self::RegulatoryCheckPerformed { .. } => "regulatory-check-performed",
            Self::ExplanationApproved { .. } => "explanation-approved",
            Self::DecisionPatternRecorded { .. } => "decision-pattern-recorded",
            Self::BehaviorSummaryGenerated { .. } => "behavior-summary-generated",
            Self::FairnessComputed { .. } => "fairness-computed",
            Self::ExplanationComplianceRate { .. } => "explanation-compliance-rate",
            Self::ExplanationVersionCreated { .. } => "explanation-version-created",
            Self::ExplanationBackendChanged { .. } => "explanation-backend-changed",
            Self::ExplanationStored { .. } => "explanation-stored",
            Self::ExplanationRetrieved { .. } => "explanation-retrieved",
            Self::ExplanationExported { .. } => "explanation-exported",
            Self::ExplanationExportFailed { .. } => "explanation-export-failed",
            Self::ReasoningTraceBegun { .. } => "reasoning-trace-begun",
            Self::ReasoningStepRecorded { .. } => "reasoning-step-recorded",
            Self::ReasoningTraceCompleted { .. } => "reasoning-trace-completed",
            Self::ReasoningTraceAbandoned { .. } => "reasoning-trace-abandoned",
            Self::BackendFeatureAttributionComputed { .. } => "backend-feature-attribution-computed",
            Self::FeatureAttributionFailed { .. } => "feature-attribution-failed",
            Self::BackendCounterfactualGenerated { .. } => "backend-counterfactual-generated",
            Self::CounterfactualGenerationFailed { .. } => "counterfactual-generation-failed",
            Self::RuleFiringRecorded { .. } => "rule-firing-recorded",
            Self::ExplanationQualityAssessed { .. } => "explanation-quality-assessed",
            Self::ExplanationQualityBreached { .. } => "explanation-quality-breached",
            Self::ExplanationSubscriberRegistered { .. } => "explanation-subscriber-registered",
            Self::ExplanationSubscriberRemoved { .. } => "explanation-subscriber-removed",
            Self::ExplanationEventPublished { .. } => "explanation-event-published",
        }
    }

    pub fn kind(&self) -> &str {
        self.type_name()
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(self,
            Self::ExplanationBackendChanged { .. } |
            Self::ExplanationStored { .. } |
            Self::ExplanationRetrieved { .. }
        )
    }

    pub fn is_trace_event(&self) -> bool {
        matches!(self,
            Self::ReasoningTraceBegun { .. } |
            Self::ReasoningStepRecorded { .. } |
            Self::ReasoningTraceCompleted { .. } |
            Self::ReasoningTraceAbandoned { .. }
        )
    }

    pub fn is_attribution_event(&self) -> bool {
        matches!(self,
            Self::BackendFeatureAttributionComputed { .. } |
            Self::FeatureAttributionFailed { .. }
        )
    }

    pub fn is_counterfactual_event(&self) -> bool {
        matches!(self,
            Self::BackendCounterfactualGenerated { .. } |
            Self::CounterfactualGenerationFailed { .. }
        )
    }

    pub fn is_quality_event(&self) -> bool {
        matches!(self,
            Self::ExplanationQualityAssessed { .. } |
            Self::ExplanationQualityBreached { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(self,
            Self::ExplanationExported { .. } |
            Self::ExplanationExportFailed { .. }
        )
    }
}

// ── ExplainabilityAuditEvent ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExplainabilityAuditEvent {
    pub event_type: ExplainabilityEventType,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
    pub decision_id: Option<String>,
}

impl ExplainabilityAuditEvent {
    pub fn new(
        event_type: ExplainabilityEventType,
        actor: impl Into<String>,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        let decision_id = match &event_type {
            ExplainabilityEventType::DecisionRecorded { decision_id, .. }
            | ExplainabilityEventType::TraceGenerated { decision_id, .. }
            | ExplainabilityEventType::FactorAnalyzed { decision_id, .. }
            | ExplainabilityEventType::CounterfactualGenerated { decision_id, .. }
            | ExplainabilityEventType::NarrativeCreated { decision_id, .. }
            | ExplainabilityEventType::AudienceAdapted { decision_id, .. }
            | ExplainabilityEventType::ExplanationTreeCreated { decision_id, .. }
            | ExplainabilityEventType::ExplanationTreeQueried { decision_id, .. }
            | ExplainabilityEventType::FeatureAttributionComputed { decision_id, .. }
            | ExplainabilityEventType::TopFeatureIdentified { decision_id, .. }
            | ExplainabilityEventType::L2CounterfactualGenerated { decision_id, .. }
            | ExplainabilityEventType::CounterfactualActionable { decision_id, .. }
            | ExplainabilityEventType::ExplanationRendered { decision_id, .. }
            | ExplainabilityEventType::CompletenessChecked { decision_id, .. }
            | ExplainabilityEventType::RegulatoryCheckPerformed { decision_id, .. }
            | ExplainabilityEventType::ExplanationApproved { decision_id, .. }
            | ExplainabilityEventType::DecisionPatternRecorded { decision_id, .. }
            | ExplainabilityEventType::ExplanationVersionCreated { decision_id, .. }
            | ExplainabilityEventType::ReasoningTraceBegun { decision_id, .. }
            | ExplainabilityEventType::RuleFiringRecorded { decision_id, .. } => {
                Some(decision_id.clone())
            }
            _ => None,
        };
        Self {
            event_type,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
            decision_id,
        }
    }
}

// ── ExplainabilityAuditLog ──────────────────────────────────────────

#[derive(Default)]
pub struct ExplainabilityAuditLog {
    pub events: Vec<ExplainabilityAuditEvent>,
}

impl ExplainabilityAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: ExplainabilityAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_decision(&self, decision_id: &str) -> Vec<&ExplainabilityAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.decision_id.as_deref() == Some(decision_id))
            .collect()
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&ExplainabilityAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.type_name() == type_name)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&ExplainabilityAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn trace_events(&self) -> Vec<&ExplainabilityAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, ExplainabilityEventType::TraceGenerated { .. }))
            .collect()
    }

    pub fn error_events(&self) -> Vec<&ExplainabilityAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    ExplainabilityEventType::ExplainabilityError { .. }
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
    fn test_record_and_count() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::DecisionRecorded {
                decision_id: "d1".into(),
                decision_type: "access-control".into(),
            },
            "system",
            1000,
            "recorded",
        ));
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_events_for_decision() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::DecisionRecorded {
                decision_id: "d1".into(),
                decision_type: "access-control".into(),
            },
            "system",
            1000,
            "recorded",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::TraceGenerated {
                decision_id: "d1".into(),
                steps: 3,
            },
            "system",
            2000,
            "traced",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::TraceGenerated {
                decision_id: "d2".into(),
                steps: 2,
            },
            "system",
            3000,
            "traced",
        ));
        assert_eq!(log.events_for_decision("d1").len(), 2);
        assert_eq!(log.events_for_decision("d2").len(), 1);
    }

    #[test]
    fn test_events_by_type() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::TraceGenerated {
                decision_id: "d1".into(),
                steps: 3,
            },
            "system",
            1000,
            "traced",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::FactorAnalyzed {
                decision_id: "d1".into(),
                factors: 2,
            },
            "system",
            2000,
            "analyzed",
        ));
        assert_eq!(log.events_by_type("trace-generated").len(), 1);
        assert_eq!(log.events_by_type("factor-analyzed").len(), 1);
    }

    #[test]
    fn test_trace_events() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::TraceGenerated {
                decision_id: "d1".into(),
                steps: 3,
            },
            "system",
            1000,
            "traced",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::DecisionRecorded {
                decision_id: "d1".into(),
                decision_type: "access-control".into(),
            },
            "system",
            2000,
            "recorded",
        ));
        assert_eq!(log.trace_events().len(), 1);
    }

    #[test]
    fn test_error_events() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::ExplainabilityError {
                operation: "trace".into(),
                detail: "decision not found".into(),
            },
            "system",
            1000,
            "error",
        ));
        assert_eq!(log.error_events().len(), 1);
        // Error events have no decision_id
        assert!(log.error_events()[0].decision_id.is_none());
    }

    #[test]
    fn test_since_filter() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::DecisionRecorded {
                decision_id: "d1".into(),
                decision_type: "ac".into(),
            },
            "system",
            1000,
            "",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::DecisionRecorded {
                decision_id: "d2".into(),
                decision_type: "ac".into(),
            },
            "system",
            3000,
            "",
        ));
        assert_eq!(log.since(2000).len(), 1);
    }

    #[test]
    fn test_event_type_display() {
        let events = vec![
            ExplainabilityEventType::DecisionRecorded {
                decision_id: "d1".into(),
                decision_type: "ac".into(),
            },
            ExplainabilityEventType::TraceGenerated {
                decision_id: "d1".into(),
                steps: 3,
            },
            ExplainabilityEventType::FactorAnalyzed {
                decision_id: "d1".into(),
                factors: 2,
            },
            ExplainabilityEventType::CounterfactualGenerated {
                decision_id: "d1".into(),
                changes: 1,
            },
            ExplainabilityEventType::NarrativeCreated {
                decision_id: "d1".into(),
                detail_level: "detailed".into(),
            },
            ExplainabilityEventType::AudienceAdapted {
                decision_id: "d1".into(),
                audience: "executive".into(),
            },
            ExplainabilityEventType::ReportGenerated {
                report_title: "Q1".into(),
                decisions: 10,
            },
            ExplainabilityEventType::ExplainabilityError {
                operation: "trace".into(),
                detail: "fail".into(),
            },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
    }

    #[test]
    fn test_l2_event_type_display() {
        let events = vec![
            ExplainabilityEventType::ExplanationTreeCreated {
                decision_id: "d1".into(),
                depth: 3,
            },
            ExplainabilityEventType::ExplanationTreeQueried {
                decision_id: "d1".into(),
                query_type: "critical-path".into(),
            },
            ExplainabilityEventType::FeatureAttributionComputed {
                decision_id: "d1".into(),
                features: 5,
            },
            ExplainabilityEventType::TopFeatureIdentified {
                decision_id: "d1".into(),
                feature_name: "income".into(),
            },
            ExplainabilityEventType::L2CounterfactualGenerated {
                decision_id: "d1".into(),
                changes: 2,
                feasibility: "easy".into(),
            },
            ExplainabilityEventType::CounterfactualActionable {
                decision_id: "d1".into(),
                distance: 5.0,
            },
            ExplainabilityEventType::ExplanationRendered {
                decision_id: "d1".into(),
                audience: "technical".into(),
            },
            ExplainabilityEventType::CompletenessChecked {
                decision_id: "d1".into(),
                score: 0.83,
            },
            ExplainabilityEventType::RegulatoryCheckPerformed {
                decision_id: "d1".into(),
                framework: "GDPR Art. 22".into(),
                passed: true,
            },
            ExplainabilityEventType::ExplanationApproved {
                decision_id: "d1".into(),
                reviewer: "alice".into(),
            },
            ExplainabilityEventType::DecisionPatternRecorded {
                decision_id: "d1".into(),
                outcome: "approved".into(),
            },
            ExplainabilityEventType::BehaviorSummaryGenerated {
                total_decisions: 100,
            },
            ExplainabilityEventType::FairnessComputed {
                groups: 3,
                parity_diff: 0.05,
            },
            ExplainabilityEventType::ExplanationComplianceRate { rate: 0.95 },
            ExplainabilityEventType::ExplanationVersionCreated {
                decision_id: "d1".into(),
                version: "2.0".into(),
            },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
        assert_eq!(events.len(), 15);
    }

    #[test]
    fn test_l2_event_decision_id_extraction() {
        let event = ExplainabilityAuditEvent::new(
            ExplainabilityEventType::ExplanationTreeCreated {
                decision_id: "d99".into(),
                depth: 2,
            },
            "system",
            5000,
            "tree created",
        );
        assert_eq!(event.decision_id.as_deref(), Some("d99"));
    }

    #[test]
    fn test_l2_event_no_decision_id() {
        let event = ExplainabilityAuditEvent::new(
            ExplainabilityEventType::BehaviorSummaryGenerated {
                total_decisions: 50,
            },
            "system",
            5000,
            "summary",
        );
        assert!(event.decision_id.is_none());
    }

    #[test]
    fn test_l2_events_by_type() {
        let mut log = ExplainabilityAuditLog::new();
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::ExplanationTreeCreated {
                decision_id: "d1".into(),
                depth: 2,
            },
            "system",
            1000,
            "",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::ExplanationTreeCreated {
                decision_id: "d2".into(),
                depth: 3,
            },
            "system",
            2000,
            "",
        ));
        log.record(ExplainabilityAuditEvent::new(
            ExplainabilityEventType::FairnessComputed {
                groups: 2,
                parity_diff: 0.1,
            },
            "system",
            3000,
            "",
        ));
        assert_eq!(log.events_by_type("explanation-tree-created").len(), 2);
        assert_eq!(log.events_by_type("fairness-computed").len(), 1);
    }

    #[test]
    fn test_l3_event_type_display() {
        let events = vec![
            ExplainabilityEventType::ExplanationBackendChanged { backend_id: "b1".into() },
            ExplainabilityEventType::ExplanationStored { explanation_id: "e1".into(), subject_id: "s1".into() },
            ExplainabilityEventType::ExplanationRetrieved { explanation_id: "e1".into() },
            ExplainabilityEventType::ExplanationExported { explanation_id: "e1".into(), format: "json".into() },
            ExplainabilityEventType::ExplanationExportFailed { explanation_id: "e1".into(), format: "json".into() },
            ExplainabilityEventType::ReasoningTraceBegun { trace_id: "t1".into(), decision_id: "d1".into() },
            ExplainabilityEventType::ReasoningStepRecorded { trace_id: "t1".into(), step_number: 0 },
            ExplainabilityEventType::ReasoningTraceCompleted { trace_id: "t1".into() },
            ExplainabilityEventType::ReasoningTraceAbandoned { trace_id: "t1".into() },
            ExplainabilityEventType::BackendFeatureAttributionComputed { prediction_id: "p1".into(), method: "SHAP".into() },
            ExplainabilityEventType::FeatureAttributionFailed { prediction_id: "p1".into(), method: "SHAP".into() },
            ExplainabilityEventType::BackendCounterfactualGenerated { prediction_id: "p1".into(), examples: 3 },
            ExplainabilityEventType::CounterfactualGenerationFailed { prediction_id: "p1".into() },
            ExplainabilityEventType::RuleFiringRecorded { rule_id: "r1".into(), decision_id: "d1".into() },
            ExplainabilityEventType::ExplanationQualityAssessed { explanation_id: "e1".into(), quality_class: "excellent".into() },
            ExplainabilityEventType::ExplanationQualityBreached { explanation_id: "e1".into(), dimension: "faithfulness".into() },
            ExplainabilityEventType::ExplanationSubscriberRegistered { subscriber_id: "sub-1".into() },
            ExplainabilityEventType::ExplanationSubscriberRemoved { subscriber_id: "sub-1".into() },
            ExplainabilityEventType::ExplanationEventPublished { event_type: "trace-completed".into() },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
        assert_eq!(events.len(), 19);
    }

    #[test]
    fn test_l3_kind_method() {
        let event = ExplainabilityEventType::ExplanationStored {
            explanation_id: "e1".into(),
            subject_id: "s1".into(),
        };
        assert_eq!(event.kind(), "explanation-stored");
    }

    #[test]
    fn test_l3_classification_methods() {
        assert!(ExplainabilityEventType::ExplanationBackendChanged { backend_id: "b1".into() }.is_backend_event());
        assert!(ExplainabilityEventType::ExplanationStored { explanation_id: "e1".into(), subject_id: "s1".into() }.is_backend_event());
        assert!(ExplainabilityEventType::ExplanationRetrieved { explanation_id: "e1".into() }.is_backend_event());

        assert!(ExplainabilityEventType::ReasoningTraceBegun { trace_id: "t1".into(), decision_id: "d1".into() }.is_trace_event());
        assert!(ExplainabilityEventType::ReasoningTraceCompleted { trace_id: "t1".into() }.is_trace_event());
        assert!(ExplainabilityEventType::ReasoningTraceAbandoned { trace_id: "t1".into() }.is_trace_event());
        assert!(ExplainabilityEventType::ReasoningStepRecorded { trace_id: "t1".into(), step_number: 0 }.is_trace_event());

        assert!(ExplainabilityEventType::BackendFeatureAttributionComputed { prediction_id: "p1".into(), method: "SHAP".into() }.is_attribution_event());
        assert!(ExplainabilityEventType::FeatureAttributionFailed { prediction_id: "p1".into(), method: "SHAP".into() }.is_attribution_event());

        assert!(ExplainabilityEventType::BackendCounterfactualGenerated { prediction_id: "p1".into(), examples: 3 }.is_counterfactual_event());
        assert!(ExplainabilityEventType::CounterfactualGenerationFailed { prediction_id: "p1".into() }.is_counterfactual_event());

        assert!(ExplainabilityEventType::ExplanationQualityAssessed { explanation_id: "e1".into(), quality_class: "good".into() }.is_quality_event());
        assert!(ExplainabilityEventType::ExplanationQualityBreached { explanation_id: "e1".into(), dimension: "stability".into() }.is_quality_event());

        assert!(ExplainabilityEventType::ExplanationExported { explanation_id: "e1".into(), format: "json".into() }.is_export_event());
        assert!(ExplainabilityEventType::ExplanationExportFailed { explanation_id: "e1".into(), format: "json".into() }.is_export_event());
    }

    #[test]
    fn test_l3_event_decision_id_extraction() {
        let event = ExplainabilityAuditEvent::new(
            ExplainabilityEventType::ReasoningTraceBegun {
                trace_id: "t1".into(),
                decision_id: "d42".into(),
            },
            "system",
            5000,
            "trace begun",
        );
        assert_eq!(event.decision_id.as_deref(), Some("d42"));

        let event = ExplainabilityAuditEvent::new(
            ExplainabilityEventType::RuleFiringRecorded {
                rule_id: "r1".into(),
                decision_id: "d99".into(),
            },
            "system",
            5001,
            "rule fired",
        );
        assert_eq!(event.decision_id.as_deref(), Some("d99"));
    }

    #[test]
    fn test_l3_event_no_decision_id() {
        let event = ExplainabilityAuditEvent::new(
            ExplainabilityEventType::ExplanationSubscriberRegistered {
                subscriber_id: "sub-1".into(),
            },
            "system",
            5000,
            "registered",
        );
        assert!(event.decision_id.is_none());
    }
}
