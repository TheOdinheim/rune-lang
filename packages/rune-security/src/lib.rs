// ═══════════════════════════════════════════════════════════════════════
// rune-security — Threat Modeling, Vulnerability Scoring, Security Context
//
// Layer 1: the common security vocabulary and posture assessment system
// for the RUNE governance ecosystem. Every other Tier 2+ security library
// speaks in rune-security's types: SecuritySeverity, ThreatCategory,
// SecurityContext, SecurityMetric.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod context;
pub mod error;
pub mod incident;
pub mod metrics;
pub mod policy;
pub mod posture;
pub mod severity;
pub mod threat;
pub mod vulnerability;

pub use audit::{SecurityAuditEvent, SecurityAuditLog, SecurityEventType};
pub use context::{ContextStack, SecurityContext};
pub use error::SecurityError;
pub use incident::{
    EscalationLevel, EscalationPolicy, Incident, IncidentEvent, IncidentEventType, IncidentId,
    IncidentStatus, IncidentTracker,
};
pub use metrics::{
    DashboardSummary, MetricStore, MetricTrend, MetricType, SecurityDashboard, SecurityMetric,
};
pub use policy::{
    evaluate_rule, PolicyCategory, RuleAction, RuleCondition, SecurityPolicy, SecurityPolicySet,
    SecurityRule,
};
pub use posture::{
    DimensionCategory, PostureAssessor, PostureDimension, PostureGrade, SecurityPosture,
};
pub use severity::{SecuritySeverity, SeverityChange};
pub use threat::{
    ActorMotivation, ActorSophistication, AttackSurface, ExposureLevel, IdentifiedThreat,
    SurfaceType, ThreatActor, ThreatActorType, ThreatCategory, ThreatModel, ThreatModelBuilder,
    ThreatStatus,
};
pub use vulnerability::{
    calculate_cvss_base, AiImpact, AttackComplexity, AttackVector, Impact, PrivilegesRequired,
    UserInteraction, Vulnerability, VulnScope, VulnStatus, VulnerabilityDatabase, VulnerabilityId,
};

// Layer 2 re-exports
pub use threat::{
    AttackNode, AttackNodeType, AttackTree, EntryPoint, L2AttackSurface, L2ExposureLevel,
};
pub use vulnerability::{
    CvssEnvironmentalMetrics, CvssFullAssessment, CvssTemporalMetrics,
    ExploitMaturity, RemediationLevel, ReportConfidence, SecurityRequirement,
};
pub use context::{
    ContextChainEntry, ContextChainStore, ContextChainVerification, ContextDiff,
    compute_context_hash, diff_contexts,
};
pub use incident::{
    EscalationChain, IncidentLifecycle, IncidentTimelineEntry, L2EscalationLevel,
    L2IncidentStatus, PlaybookStore, PlaybookTrigger, ResponseAction, ResponsePlaybook,
    ResponseStep,
};
pub use posture::{
    DimensionScore, PostureFinding, PostureTrend, SecurityPostureScore, TrendDirection,
    calculate_overall, critical_findings, default_dimensions, posture_grade,
};
pub use metrics::{
    SecurityMetricsTracker, SecuritySla, SlaComplianceResult, aggregate_metrics,
};
