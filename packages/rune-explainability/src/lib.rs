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
