// ═══════════════════════════════════════════════════════════════════════
// rune-privacy — Privacy Engineering for the RUNE Governance Ecosystem
//
// Layer 1: PII detection, anonymization, differential privacy,
// consent management, data subject rights (GDPR/CCPA), purpose limitation,
// retention policies, privacy impact assessment, and audit logging.
// ═══════════════════════════════════════════════════════════════════════

pub mod anonymize;
pub mod audit;
pub mod consent;
pub mod differential;
pub mod error;
pub mod impact;
pub mod pii;
pub mod purpose;
pub mod retention;
pub mod rights;
pub mod backend;
pub mod consent_store;
pub mod redaction_engine;
pub mod privacy_export;
pub mod subject_rights_stream;
pub mod retention_engine;
pub mod pii_classifier;

pub use anonymize::{
    AnonymizationMethod, AnonymizationPipeline, AnonymizationStep, KAnonymityChecker,
    LDiversityChecker, TClosenessChecker,
    // Layer 2
    AnonymizationGroup, GeneralizationHierarchy, ReidentificationRisk, RiskLevel,
    check_l_diversity, check_t_closeness, reidentification_risk,
};
pub use audit::{PrivacyAuditEvent, PrivacyAuditLog, PrivacyEventType};
pub use consent::{
    Consent, ConsentEvidence, ConsentId, ConsentMethod, ConsentScope, ConsentStatus, ConsentStore,
    // Layer 2
    ConsentProof, ConsentVersion, ConsentVersionStore, PurposeDependencyGraph, WithdrawalResult,
};
pub use differential::{
    DpEngine, DpMechanism, DpQuery, DpQueryResult, PrivacyBudget, QueryType,
    // Layer 2
    BudgetQuery, PrivacyBudgetTracker, calibrate_gaussian, calibrate_laplace, gaussian_noise,
};
pub use error::PrivacyError;
pub use impact::{
    DataFlow, Mitigation, PiaBuilder, PrivacyImpactAssessment, PrivacyRisk, RiskCategory,
    RiskRating, RiskStatus,
    // Layer 2
    PiaRecommendation, PiaScore, RecommendationPriority, RegulatoryRequirement,
    calculate_pia_score, generate_pia_recommendations, map_to_regulations,
};
pub use pii::{
    PiiCategory, PiiDetection, PiiDetector, PiiFieldTag, PiiHandling, PiiPattern, PiiSensitivity,
    // Layer 2
    PiiConfidence, PiiFieldMatch, PiiMatch, PiiRegexScanner,
};
pub use purpose::{
    DataMinimization, DataTag, LegalBasis, MinimizationResult, Purpose, PurposeCheck,
    PurposeRegistry,
};
pub use retention::{
    RetentionAction, RetentionActionItem, RetentionCheck, RetentionDataItem, RetentionManager,
    RetentionPolicy, RetentionScope,
};
pub use rights::{
    RequestStatus, ResponseType, RightsManager, RightsRequest, RightsResponse, SubjectRight,
    // Layer 2
    DataInventory, DataInventoryEntry, DataSubjectRequest, DataSubjectRequestTracker,
};

// ── Layer 3 re-exports ──────────────────────────────────────────────

pub use backend::{
    DeletionStrategy, InMemoryPrivacyBackend, PrivacyBackend, PrivacyBackendInfo,
    RequestType, StoredDataSubjectRecord, StoredDataSubjectRequest,
    StoredPiiClassification, StoredProcessingRecord, StoredRetentionPolicyDefinition,
    SubjectRef,
};
pub use consent_store::{
    ConsentLegalBasis, ConsentRecord, ConsentRecordStore, ConsentStoreInfo,
    InMemoryConsentRecordStore, StoredConsentStatus,
};
pub use redaction_engine::{
    MaskRedactionStrategy, PseudonymizeRedactionStrategy, RedactionContext,
    RedactionEngine, RedactionStrategy, RemoveRedactionStrategy,
    Sha3HashRedactionStrategy, StrategyType, TokenizeRedactionStrategy,
    TruncateRedactionStrategy,
};
pub use privacy_export::{
    CcpaDsarExporter, DsarExporter, GdprArticle15Exporter, HtmlDsarExporter,
    JsonDsarExporter, SubjectDossier, XmlDsarExporter,
};
pub use subject_rights_stream::{
    FilteredSubjectRightsSubscriber, SubjectRightsCollector, SubjectRightsEvent,
    SubjectRightsEventType, SubjectRightsSubscriber, SubjectRightsSubscriberRegistry,
};
pub use retention_engine::{
    EventBasedRetentionEngine, LegalHoldAwareRetentionEngine, PurposeBasedRetentionEngine,
    RetentionDecision, RetentionPolicyDef, RetentionPolicyEngine, RetentionRecord,
    TimeBasedRetentionEngine,
};
pub use pii_classifier::{
    ClassifiedPiiCategory, ClassifierType, HeuristicPiiClassifier, NullPiiClassifier,
    PiiClassificationResult, PiiClassifier, RegexPiiClassifier,
};
