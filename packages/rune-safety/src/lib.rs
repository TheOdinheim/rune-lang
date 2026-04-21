// ═══════════════════════════════════════════════════════════════════════
// rune-safety — Safety constraints, safety cases, hazard analysis,
// fail-safe behaviors, safety integrity levels, and safety monitors.
// ═══════════════════════════════════════════════════════════════════════

pub mod assessment;
pub mod audit;
pub mod boundary;
pub mod constraint;
pub mod error;
pub mod failsafe;
pub mod hazard;
pub mod integrity;
pub mod monitor;
pub mod safety_case;

// ── Layer 2 modules ─────────────────────────────────────────────────
pub mod l2_boundary;
pub mod l2_constraint;
pub mod l2_dashboard;
pub mod l2_gate;
pub mod l2_incident;
pub mod l2_test_harness;

pub use assessment::{
    HazardSummary, MonitorSummary, SafetyAssessment, SafetyAssessor, SafetyLevel,
};
pub use audit::{SafetyAuditEvent, SafetyAuditLog, SafetyEventType};
pub use boundary::{
    BoundaryCheckResult, BoundaryStatus, BoundaryType, OperatingLimit, SafetyBoundary,
    SafetyBoundarySet,
};
pub use constraint::{
    evaluate_safety_condition, ConstraintEvaluation, ConstraintId, ConstraintSeverity,
    ConstraintStore, ConstraintType, SafetyCondition, SafetyConstraint,
};
pub use error::SafetyError;
pub use failsafe::{
    FailsafeAction, FailsafeBehavior, FailsafeId, FailsafeRegistry, FailsafeTrigger,
    RecoveryProcedure,
};
pub use hazard::{
    Hazard, HazardId, HazardLikelihood, HazardMitigation, HazardRegistry, HazardStatus,
    HazardType, MitigationEffectiveness, MitigationType, RiskLevel,
};
pub use integrity::{
    AutomotiveSafetyLevel, DesignAssuranceLevel, SafetyClassification, SafetyIntegrityLevel,
};
pub use monitor::{
    MonitorCheckResult, MonitorResponse, MonitorStatus, SafetyMonitor, SafetyMonitorEngine,
    SafetyMonitorId,
};
pub use safety_case::{
    EvidenceStrength, EvidenceType, GoalStatus, SafetyCase, SafetyCaseId, SafetyCaseStatus,
    SafetyCaseStore, SafetyEvidence, SafetyGoal, SafetyStrategy,
};

// ── Layer 2 re-exports ──────────────────────────────────────────────
pub use l2_boundary::{
    L2BoundaryCheckResult, L2BoundaryChecker, L2BoundaryStore, L2BoundaryType, L2BoundaryViolation,
    L2EnforcementMode, L2SafetyBoundary,
};
pub use l2_constraint::{
    L2ConstraintPriority, L2ConstraintType, L2ConstraintVerification,
    L2ConstraintVerificationReport, L2ConstraintVerifier, L2SafetyConstraint,
};
pub use l2_dashboard::{SafetyDashboard, SafetyMetrics, SafetyTrend};
pub use l2_gate::{
    ApprovalGate, ApproverDecision, ApproverRecord, GateApproval, GateManager, GateStatus,
    GateType,
};
pub use l2_incident::{
    ActionStatus, CorrectiveAction, CorrectiveActionType, SafetyIncident, SafetyIncidentCategory,
    SafetyIncidentSeverity, SafetyIncidentStatus, SafetyIncidentTracker,
};
pub use l2_test_harness::{
    SafetyTestCase, SafetyTestCategory, SafetyTestResult, SafetyTestRunner, SafetyTestSuite,
};

// ── Layer 3 modules ─────────────────────────────────────────────────
pub mod backend;
pub mod emergency_shutdown;
pub mod safety_case_builder;
pub mod safety_envelope;
pub mod safety_export;
pub mod safety_metrics;
pub mod safety_stream;

// ── Layer 3 re-exports ──────────────────────────────────────────────
pub use backend::{
    ConstraintCategory, ConstraintSeverityLevel, InMemorySafetyBackend, SafetyBackend,
    SafetyBackendInfo, SafetyCaseMethodology, SafetyCaseRecordStatus, ShutdownType,
    StoredBoundaryViolationRecord, StoredEnvelopeStatus, StoredSafetyCaseRecord,
    StoredSafetyConstraint, StoredSafetyEnvelope, StoredShutdownRecord,
};
pub use emergency_shutdown::{
    AuditedEmergencyShutdownController, EmergencyShutdownController,
    InMemoryEmergencyShutdownController, NullEmergencyShutdownController, ShutdownHandle,
    ShutdownStatus,
};
pub use safety_case_builder::{
    CompletenessAssessment, InMemorySafetyCaseBuilder, NullSafetyCaseBuilder, SafetyArgument,
    SafetyArgumentType, SafetyCaseBuilder, SafetyClaim, SafetyClaimStatus, SafetyClaimType,
};
pub use safety_envelope::{
    EnvelopeConstraintEntry, EnvelopeStatus, InMemorySafetyEnvelopeMonitor,
    NullSafetyEnvelopeMonitor, RecommendedSafetyResponse, SafetyEnvelopeMonitor,
    ThresholdBasedSafetyEnvelopeMonitor, ThresholdComparison,
};
pub use safety_export::{
    BowTieExporter, GsnXmlExporter, IncidentReportExporter, JsonSafetyExporter,
    SafetyCaseReportExporter, SafetyExporter,
};
pub use safety_metrics::{
    InMemorySafetyMetricsCollector, NullSafetyMetricsCollector, SafetyMetricSnapshot,
    SafetyMetricsCollector,
};
pub use safety_stream::{
    FilteredSafetyEventSubscriber, SafetyEventCollector, SafetyEventSubscriber,
    SafetyEventSubscriberRegistry, SafetyLifecycleEvent, SafetyLifecycleEventType,
};
