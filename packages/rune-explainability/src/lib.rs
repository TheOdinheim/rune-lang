// ═══════════════════════════════════════════════════════════════════════
// rune-explainability — decision traces, factor attribution,
// counterfactual analysis, transparency reports, and human-readable
// explanations for the RUNE governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod audience;
pub mod audit;
pub mod counterfactual;
pub mod decision;
pub mod error;
pub mod factor;
pub mod narrative;
pub mod trace;
pub mod transparency;

// ── Layer 2 modules ─────────────────────────────────────────────────
pub mod attribution;
pub mod behavior;
pub mod compliance;
pub mod l2_counterfactual;
pub mod template;
pub mod tree;

// ── Layer 3 modules ─────────────────────────────────────────────────
pub mod backend;
pub mod counterfactual_example;
pub mod explanation_export;
pub mod explanation_quality;
pub mod explanation_stream;
pub mod feature_attribution;
pub mod reasoning_trace;

pub use audience::{Audience, AudienceAdapter};
pub use audit::{ExplainabilityAuditEvent, ExplainabilityAuditLog, ExplainabilityEventType};
pub use counterfactual::{
    ChangeDifficulty, Counterfactual, CounterfactualFeasibility, CounterfactualGenerator,
    RequiredChange,
};
pub use decision::{
    Decision, DecisionContext, DecisionFactor, DecisionId, DecisionOutcome, DecisionStore,
    DecisionType, FactorDirection, FactorType,
};
pub use error::ExplainabilityError;
pub use factor::{
    AnalyzedFactor, DivergentFactor, FactorAnalysis, FactorAnalyzer, FactorComparison,
};
pub use narrative::{DetailLevel, Narrative, NarrativeGenerator, NarrativeSection};
pub use trace::{DecisionTrace, DecisionTracer, RootCause, RootCauseType, TraceStep};
pub use transparency::{
    ReportMetric, ReportSection, ReportSummary, TransparencyReport, TransparencyReportBuilder,
};

// ── Layer 2 re-exports ──────────────────────────────────────────────
pub use attribution::{
    AttributionDirection, AttributionMethod, AttributionSet, FeatureAttribution,
};
pub use behavior::{
    compute_fairness, demographic_parity_difference, is_within_tolerance, BehaviorSummary,
    ConfidenceTrend, DecisionPatternTracker, DecisionRecord, FairnessIndicator, GroupOutcome,
};
pub use compliance::{
    check_eu_ai_act, check_gdpr_art22, ExplanationAuditEntry, ExplanationCompletenessCheck,
    L2ExplanationAuditLog, RegulatoryFramework, RegulatoryRequirement,
};
pub use l2_counterfactual::{
    ChangeType, CounterfactualSet, FeatureChange, L2Counterfactual,
    L2CounterfactualFeasibility, L2CounterfactualGenerator,
};
pub use template::{
    end_user_template, regulatory_template, technical_template, ExplanationAudience,
    ExplanationRenderer, ExplanationTemplate, SectionContentType, TemplateSection,
};
pub use tree::{
    ExplanationNode, ExplanationNodeType, ExplanationTree, ExplanationTreeBuilder,
};

// ── Layer 3 re-exports ──────────────────────────────────────────────
pub use backend::{
    ExplanationBackend, ExplanationBackendInfo, ExplanationType, InMemoryExplanationBackend,
    StoredCounterfactualExample, StoredExplanation, StoredFeatureAttributionSet,
    StoredReasoningStep, StoredReasoningTrace, StoredRuleFiringRecord, SubjectIdRef,
};
pub use counterfactual_example::{
    ActionableChange, ChangeDirection, CounterfactualExample, CounterfactualExampleGenerator,
    FeaturePerturbationCounterfactualGenerator, NearestNeighborCounterfactualGenerator,
    NullCounterfactualExampleGenerator,
};
pub use explanation_export::{
    EcoaAdverseActionExporter, ExplanationExporter, ExportableExplanation, ExportableFactor,
    GdprArticle22Exporter, JsonExplanationExporter, MarkdownExplanationExporter,
    SubjectContext, W3cProvPredicateExporter,
};
pub use explanation_quality::{
    ExplanationQualityAssessor, NullExplanationQualityAssessor, OverallQualityClass,
    QualityAssessment, ReadabilityAssessor, StructuralFaithfulnessAssessor,
};
pub use explanation_stream::{
    ExplanationEventCollector, ExplanationEventSubscriber, ExplanationEventSubscriberRegistry,
    ExplanationLifecycleEvent, ExplanationLifecycleEventType,
    FilteredExplanationEventSubscriber, NullExplanationEventSubscriber,
};
pub use feature_attribution::{
    AttributionValueDirection, ExplainerAttributionMethod, ExplainerFeatureAttributionSet,
    FeatureAttributionExplainer, FeatureAttributionRecord, LinearCoefficientExplainer,
    NullFeatureAttributionExplainer, PermutationImportanceExplainer,
};
pub use reasoning_trace::{
    DepthLimitedReasoningTraceRecorder, InMemoryReasoningTraceRecorder, ReasoningStep,
    ReasoningTraceRecorder, RecordedReasoningTrace, StepType,
};
