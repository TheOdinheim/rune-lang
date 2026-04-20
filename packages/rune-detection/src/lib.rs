// ═══════════════════════════════════════════════════════════════════════
// rune-detection — Anomaly Detection, Pattern Matching, Threat Sensing
//
// The sensing layer of RUNE's active defense. Observes, analyzes, and
// reports — but does not act. rune-shield acts on what rune-detection
// senses. Detection and response are independent concerns that can be
// configured, tested, and audited separately.
// ═══════════════════════════════════════════════════════════════════════

pub mod alert;
pub mod anomaly;
pub mod audit;
pub mod behavioral;
pub mod error;
pub mod indicator;
pub mod pattern;
pub mod pipeline;
pub mod rule;
pub mod scoring;
pub mod signal;

// Layer 3 modules
pub mod alert_export;
pub mod backend;
pub mod baseline_store;
pub mod correlation;
pub mod finding_stream;
pub mod model_adapter;
pub mod timeseries_ingest;

pub use alert::{Alert, AlertId, AlertManager, AlertSource, AlertStatus};
pub use alert::{
    AlertCorrelator, CorrelatedAlert, CorrelationCondition, CorrelationRule,
};
pub use anomaly::{AnomalyDetector, AnomalyMethod, AnomalyResult};
pub use anomaly::StatisticalDetector;
pub use audit::{DetectionAuditEvent, DetectionAuditLog, DetectionEventType};
pub use behavioral::{
    BehaviorAnalyzer, BehaviorProfile, BehaviorResult, BehaviorStatus, MetricBaseline,
};
pub use behavioral::{
    BehavioralBaseline, MetricConfig, MetricStats, NormalRange,
};
pub use error::DetectionError;
pub use indicator::{IoC, IoCDatabase, IoCType};
pub use pattern::{
    detect_command_injection, detect_data_exfiltration, detect_encoded_payload,
    detect_path_traversal, detect_prompt_injection, detect_sql_injection, detect_xss,
    CustomPattern, PatternCategory, PatternLocation, PatternMatch, PatternScanner,
};
pub use pattern::{
    builtin_detection_patterns, DetectionPattern, RegexPatternMatch, RegexPatternMatcher,
};
pub use pipeline::{DetectionPipeline, PipelineResult, PipelineStage, StageType};
pub use rule::{
    evaluate_rule, DetectionRule, RuleCondition, RuleEvalContext, RuleSet,
};
pub use scoring::{DetectionScore, DetectionScorer, DetectionWeights, ScoreComponent};
pub use signal::{Signal, SignalBatch, SignalSource, SignalType, SignalValue};

// ── Layer 3 re-exports ──────────────────────────────────────────
pub use alert_export::{
    AlertExporter, CefAlertExporter, EcsAlertExporter, JsonAlertExporter,
    OcsfAlertExporter, SplunkNotableExporter,
};
pub use backend::{
    BackendInfo, DetectionBackend, DetectionFinding, InMemoryDetectionBackend, StoredBaseline,
};
pub use baseline_store::{Baseline, BaselineMetadata, BaselineStore, InMemoryBaselineStore};
pub use correlation::{
    AttributeCorrelator, CorrelationResult, FindingCorrelator, TimeWindowCorrelator,
};
pub use finding_stream::{
    FilteredFindingSubscriber, FindingCollector, FindingLifecycleEvent,
    FindingLifecycleEventType, FindingSubscriber, FindingSubscriberRegistry,
};
pub use model_adapter::{
    DetectionModelAdapter, ModelInfo, NullDetectionModel, PredictionResult, RulesOnlyModel,
};
pub use timeseries_ingest::{
    InMemoryTimeSeriesIngestor, TimeSeriesIngestor, TimeSeriesPoint,
};
