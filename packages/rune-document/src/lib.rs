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
