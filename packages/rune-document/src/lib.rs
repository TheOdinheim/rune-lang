// ═══════════════════════════════════════════════════════════════════════
// rune-document — compliance document generation from live governance
// data: GDPR Article 30, NIST AI RMF, CMMC, privacy impact
// assessments, and system security plans.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod cmmc;
pub mod document;
pub mod error;
pub mod gdpr;
pub mod nist;
pub mod pia;
pub mod renderer;
pub mod ssp;
pub mod template;

// ── Layer 2 modules ─────────────────────────────────────────────────
pub mod classification;
pub mod compliance_doc;
pub mod integrity;
pub mod lifecycle;
pub mod retention;
pub mod version_diff;

pub use audit::{DocumentAuditEvent, DocumentAuditLog, DocumentEventType};
pub use cmmc::{CmmcAssessment, CmmcDocumentBuilder, CmmcDomain, CmmcLevel, CmmcPractice};
pub use document::{
    ComplianceFramework, ComplianceStatus, Document, DocumentField, DocumentId, DocumentSection,
    DocumentStatus, DocumentStore, DocumentType, DocumentVersion, FieldType,
};
pub use error::DocumentError;
pub use gdpr::{
    ControllerInfo, GdprDocumentBuilder, GdprGap, InternationalTransfer, ProcessingActivity,
};
pub use nist::{
    MaturityLevel, NistAiRmfProfile, NistCategory, NistDocumentBuilder, NistFunction,
    NistSubcategory, ProfileType,
};
pub use pia::{
    NecessityAssessment, PiaConsultation, PiaDataFlow, PiaDocument, PiaDocumentBuilder,
    PiaMitigation, PiaRisk, RiskLevel,
};
pub use renderer::{completion_summary, CompletionSummary, DocumentRenderer, RenderFormat};
pub use ssp::{
    ImpactLevel, ImplementationStatus, SecurityControlEntry, SspBuilder, SystemSecurityPlan,
    SystemType,
};
pub use template::{
    instantiate_template, DocumentTemplate, TemplateFieldDef, TemplateRegistry, TemplateSectionDef,
};

// ── Layer 2 re-exports ──────────────────────────────────────────────
pub use classification::{
    auto_classify, score_sensitivity, ClassificationStore, DocumentCategory,
    DocumentClassification, SensitivityLevel, SensitivityScore,
};
pub use compliance_doc::{
    ComplianceDocument as L2ComplianceDocument, ComplianceDocumentBuilder as L2ComplianceDocumentBuilder,
    CompliancePackage, ComplianceSection as L2ComplianceSection,
    ComplianceSectionStatus as L2ComplianceSectionStatus,
};
pub use integrity::{
    hash_document_content, hash_document_metadata, verify_document_hash, ChainVerification,
    DocumentHashChain, DocumentIntegrityRecord, DocumentIntegrityStore, HashChainEntry,
    IntegrityVerification,
};
pub use lifecycle::{
    check_policy, is_valid_transition, DocumentLifecycleState, DocumentLifecycleTracker,
    LifecyclePolicy, LifecycleTransition, PolicyViolation, ViolationSeverity,
};
pub use retention::{
    DisposalMethod, DocumentRetentionRecord, LegalHold, RetentionPolicy, RetentionTracker,
};
pub use version_diff::{
    diff_versions, MetadataChange, MetadataChangeType, VersionDiff, VersionHistoryStore,
    VersionSnapshot,
};

// ── Layer 3 modules ─────────────────────────────────────────────────
pub mod backend;
pub mod content_format_converter;
pub mod content_ingestion;
pub mod document_export;
pub mod document_stream;
pub mod retention_integration;
pub mod version_control;

// ── Layer 3 re-exports ──────────────────────────────────────────────
pub use backend::{
    ClassificationLevel, DocumentBackend, DocumentBackendInfo, InMemoryDocumentBackend,
    StoredContentBlob, StoredDocumentCategory, StoredDocumentRecord, StoredDocumentRetentionRecord,
    StoredDocumentVersion,
};
pub use content_format_converter::{
    ContentFormatConverter, ConversionPair, HtmlToPlainTextConverter, MarkdownToHtmlConverter,
    NullContentFormatConverter,
};
pub use content_ingestion::{
    ContentIngestor, ContentSourceFormat, HtmlContentIngestor, MarkdownContentIngestor,
    NormalizedContent, NullContentIngestor, PlainTextContentIngestor,
};
pub use document_export::{
    AtomFeedExporter, DitaTopicExporter, DocbookExporter, DocumentExporter, ExportableDocument,
    JsonDocumentExporter, PdfAExporter,
};
pub use document_stream::{
    DocumentEventCollector, DocumentEventSubscriber, DocumentEventSubscriberRegistry,
    DocumentLifecycleEvent, DocumentLifecycleEventType, FilteredDocumentEventSubscriber,
};
pub use retention_integration::{
    DisposalEligibility, DisposalRecord, InMemoryRetentionPolicyLinker,
    LegalHoldAwareRetentionPolicyLinker, NullRetentionPolicyLinker, RetentionPolicyLinker,
};
pub use version_control::{
    ChronologicalOrder, DocumentTag, DocumentVersionController, FieldChangeType,
    InMemoryDocumentVersionController, LinearDocumentVersionController, MetadataFieldChange,
    NullDocumentVersionController, VersionComparison,
};
