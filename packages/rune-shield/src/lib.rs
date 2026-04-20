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
pub mod backend;
pub mod enforcement;
pub mod error;
pub mod exfiltration;
pub mod export_format;
pub mod fingerprint;
pub mod injection;
pub mod input;
pub mod memory;
pub mod metrics_export;
pub mod output;
pub mod pattern;
pub mod policy;
pub mod quarantine;
pub mod response;
pub mod shield;
pub mod signature_loader;
pub mod threat_feed;
pub mod token;
pub mod verdict_stream;

pub use adversarial::{
    AdversarialDetector, AdversarialFinding, AdversarialResult, AdversarialType,
};
pub use audit::{ShieldAuditEvent, ShieldAuditLog, ShieldEventType};
pub use error::ShieldError;
pub use exfiltration::{
    contains_base64_block, contains_hex_block, contains_sensitive_json_keys, redact_pii,
    ExfiltrationAnalysis, ExfiltrationAnalyzer, ExfiltrationDetector, ExfiltrationFinding,
    ExfiltrationResult, SensitivePattern, SensitivePatternType,
};
pub use fingerprint::{
    shannon_entropy, fingerprint, ContentFingerprint, FingerprintStore,
};
pub use injection::{
    neutralize, InjectionDetector, InjectionResult, InjectionStrategy, StrategyResult,
};
pub use input::{InputSanitizer, InputValidation, InputValidator};
pub use memory::{AttackSignature, FalsePositivePattern, ImmuneMemory};
pub use pattern::{
    InjectionCategory, InjectionPattern, InjectionScore, InjectionScorer,
    indirect_injection_patterns, jailbreak_patterns, prompt_injection_patterns,
};
pub use token::{
    PiiTokenType, SecretTokenType, TokenClassification, TokenClassifier, TokenType,
};
pub use output::{OutputFilter, OutputFilterResult, OutputFinding, OutputFindingType};
pub use policy::{ShieldLevel, ShieldPolicy};
pub use quarantine::{
    QuarantineContentType, QuarantineEntry, QuarantineId, QuarantineStore, QuarantineVerdict,
};
pub use response::{CheckResult, GovernanceDecision, ShieldAction, ShieldVerdict};
pub use shield::{Shield, ShieldStats};

// ── Layer 3 re-exports ──────────────────────────────────────────────
pub use backend::{
    BackendInfo, DetectionRule, DetectionRuleBackend, DetectionSignature,
    InMemoryShieldBackend, StoredVerdict,
};
pub use enforcement::{
    ChainedEnforcementHook, EnforcementHook, MitigationAction,
    RecordingEnforcementHook, verdict_to_mitigation,
};
pub use export_format::{
    JsonVerdictExporter, MispVerdictExporter, OcsfVerdictExporter,
    SigmaRuleExporter, StixVerdictExporter, VerdictExporter,
};
pub use metrics_export::{
    CounterMetric, GaugeMetric, HistogramMetric, OtelMetricsExporter,
    PrometheusMetricsExporter, ShieldMetricsExporter, ShieldMetricsStore,
};
pub use signature_loader::{
    InMemorySignatureLoader, JsonSignatureLoader, RulePack,
    RulePackValidationError, SignatureLoader,
};
pub use threat_feed::{
    InMemoryThreatFeed, IndicatorType, ThreatFeedSource, ThreatIndicator,
};
pub use verdict_stream::{
    FilteredVerdictSubscriber, VerdictCollector, VerdictLifecycleEvent,
    VerdictLifecycleEventType, VerdictSubscriber, VerdictSubscriberRegistry,
};
