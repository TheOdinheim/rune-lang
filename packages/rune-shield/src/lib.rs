// ═══════════════════════════════════════════════════════════════════════
// rune-shield — AI Inference Immune System
//
// Active defense for the RUNE governance ecosystem. Where rune-detection
// observes and reports, rune-shield observes, decides, and acts at the
// inference boundary. Every shield action maps to one of four governance
// decisions: Permit, Deny, Escalate, Quarantine.
// ═══════════════════════════════════════════════════════════════════════

pub mod adversarial;
pub mod audit;
pub mod error;
pub mod exfiltration;
pub mod injection;
pub mod input;
pub mod memory;
pub mod output;
pub mod policy;
pub mod quarantine;
pub mod response;
pub mod shield;

pub use adversarial::{
    AdversarialDetector, AdversarialFinding, AdversarialResult, AdversarialType,
};
pub use audit::{ShieldAuditEvent, ShieldAuditLog, ShieldEventType};
pub use error::ShieldError;
pub use exfiltration::{
    redact_pii, ExfiltrationDetector, ExfiltrationFinding, ExfiltrationResult, SensitivePattern,
    SensitivePatternType,
};
pub use injection::{
    neutralize, InjectionDetector, InjectionResult, InjectionStrategy, StrategyResult,
};
pub use input::{InputSanitizer, InputValidation, InputValidator};
pub use memory::{AttackSignature, FalsePositivePattern, ImmuneMemory};
pub use output::{OutputFilter, OutputFilterResult, OutputFinding, OutputFindingType};
pub use policy::{ShieldLevel, ShieldPolicy};
pub use quarantine::{
    QuarantineContentType, QuarantineEntry, QuarantineId, QuarantineStore, QuarantineVerdict,
};
pub use response::{CheckResult, GovernanceDecision, ShieldAction, ShieldVerdict};
pub use shield::{Shield, ShieldStats};
