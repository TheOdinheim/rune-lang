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
