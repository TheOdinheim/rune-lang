// ═══════════════════════════════════════════════════════════════════════
// Document — core document type with versioning, metadata, sections,
// and compliance status tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::DocumentError;

// ── DocumentId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentId(pub String);

impl DocumentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DocumentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DocumentId {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

// ── DocumentType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentType {
    RecordOfProcessing,
    RiskManagementProfile,
    MaturityAssessment,
    PrivacyImpactAssessment,
    SystemSecurityPlan,
    DataProtectionImpactAssessment,
    IncidentResponsePlan,
    ComplianceReport,
    PolicyDocument,
    AuditReport,
    Custom(String),
}

impl fmt::Display for DocumentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordOfProcessing => f.write_str("record-of-processing"),
            Self::RiskManagementProfile => f.write_str("risk-management-profile"),
            Self::MaturityAssessment => f.write_str("maturity-assessment"),
            Self::PrivacyImpactAssessment => f.write_str("privacy-impact-assessment"),
            Self::SystemSecurityPlan => f.write_str("system-security-plan"),
            Self::DataProtectionImpactAssessment => {
                f.write_str("data-protection-impact-assessment")
            }
            Self::IncidentResponsePlan => f.write_str("incident-response-plan"),
            Self::ComplianceReport => f.write_str("compliance-report"),
            Self::PolicyDocument => f.write_str("policy-document"),
            Self::AuditReport => f.write_str("audit-report"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── DocumentVersion ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentVersion {
    pub major: u32,
    pub minor: u32,
    pub revision: u32,
}

impl DocumentVersion {
    pub fn new(major: u32, minor: u32, revision: u32) -> Self {
        Self {
            major,
            minor,
            revision,
        }
    }
    pub fn initial() -> Self {
        Self::new(1, 0, 0)
    }
    pub fn bump_revision(&self) -> Self {
        Self::new(self.major, self.minor, self.revision + 1)
    }
    pub fn bump_minor(&self) -> Self {
        Self::new(self.major, self.minor + 1, 0)
    }
    pub fn bump_major(&self) -> Self {
        Self::new(self.major + 1, 0, 0)
    }
}

impl fmt::Display for DocumentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.revision)
    }
}

impl Ord for DocumentVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.revision.cmp(&other.revision))
    }
}

impl PartialOrd for DocumentVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ── DocumentStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentStatus {
    Draft,
    UnderReview,
    Approved { approver: String, date: i64 },
    Published,
    Superseded { by: DocumentId },
    Archived,
}

impl DocumentStatus {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Draft | Self::UnderReview | Self::Approved { .. } | Self::Published
        )
    }
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Superseded { .. } | Self::Archived)
    }
    fn name(&self) -> &str {
        match self {
            Self::Draft => "draft",
            Self::UnderReview => "under-review",
            Self::Approved { .. } => "approved",
            Self::Published => "published",
            Self::Superseded { .. } => "superseded",
            Self::Archived => "archived",
        }
    }
}

impl fmt::Display for DocumentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => f.write_str("draft"),
            Self::UnderReview => f.write_str("under-review"),
            Self::Approved { approver, .. } => write!(f, "approved by {approver}"),
            Self::Published => f.write_str("published"),
            Self::Superseded { by } => write!(f, "superseded by {by}"),
            Self::Archived => f.write_str("archived"),
        }
    }
}

// ── ComplianceFramework ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    GdprEu,
    GdprUk,
    NistAiRmf,
    NistCsf,
    Cmmc,
    EuAiAct,
    Ccpa,
    Hipaa,
    Sox,
    FedRamp,
    Iso27001,
    Custom(String),
}

impl ComplianceFramework {
    pub fn jurisdiction(&self) -> &str {
        match self {
            Self::GdprEu | Self::EuAiAct => "EU",
            Self::GdprUk => "UK",
            Self::NistAiRmf | Self::NistCsf | Self::Cmmc | Self::Hipaa | Self::Sox
            | Self::FedRamp => "US",
            Self::Ccpa => "US-CA",
            Self::Iso27001 => "International",
            Self::Custom(_) => "Unknown",
        }
    }

    pub fn full_name(&self) -> &str {
        match self {
            Self::GdprEu => "EU General Data Protection Regulation",
            Self::GdprUk => "UK General Data Protection Regulation",
            Self::NistAiRmf => "NIST AI Risk Management Framework",
            Self::NistCsf => "NIST Cybersecurity Framework",
            Self::Cmmc => "Cybersecurity Maturity Model Certification",
            Self::EuAiAct => "EU Artificial Intelligence Act",
            Self::Ccpa => "California Consumer Privacy Act",
            Self::Hipaa => "Health Insurance Portability and Accountability Act",
            Self::Sox => "Sarbanes-Oxley Act",
            Self::FedRamp => "Federal Risk and Authorization Management Program",
            Self::Iso27001 => "ISO/IEC 27001",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GdprEu => f.write_str("GDPR-EU"),
            Self::GdprUk => f.write_str("GDPR-UK"),
            Self::NistAiRmf => f.write_str("NIST-AI-RMF"),
            Self::NistCsf => f.write_str("NIST-CSF"),
            Self::Cmmc => f.write_str("CMMC"),
            Self::EuAiAct => f.write_str("EU-AI-Act"),
            Self::Ccpa => f.write_str("CCPA"),
            Self::Hipaa => f.write_str("HIPAA"),
            Self::Sox => f.write_str("SOX"),
            Self::FedRamp => f.write_str("FedRAMP"),
            Self::Iso27001 => f.write_str("ISO-27001"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ── FieldType ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    Text,
    Date,
    YesNo,
    Selection(Vec<String>),
    Numeric,
    Reference(String),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => f.write_str("text"),
            Self::Date => f.write_str("date"),
            Self::YesNo => f.write_str("yes/no"),
            Self::Selection(_) => f.write_str("selection"),
            Self::Numeric => f.write_str("numeric"),
            Self::Reference(r) => write!(f, "reference:{r}"),
        }
    }
}

// ── ComplianceStatus ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant { gaps: Vec<String> },
    NonCompliant { reason: String },
    NotAssessed,
    NotApplicable,
}

impl fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compliant => f.write_str("compliant"),
            Self::PartiallyCompliant { gaps } => {
                write!(f, "partially-compliant ({} gaps)", gaps.len())
            }
            Self::NonCompliant { reason } => write!(f, "non-compliant: {reason}"),
            Self::NotAssessed => f.write_str("not-assessed"),
            Self::NotApplicable => f.write_str("not-applicable"),
        }
    }
}

// ── DocumentField ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentField {
    pub name: String,
    pub value: String,
    pub field_type: FieldType,
    pub required: bool,
    pub filled: bool,
}

impl DocumentField {
    pub fn new(
        name: impl Into<String>,
        field_type: FieldType,
        required: bool,
    ) -> Self {
        Self {
            name: name.into(),
            value: String::new(),
            field_type,
            required,
            filled: false,
        }
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self.filled = !self.value.is_empty();
        self
    }
}

// ── DocumentSection ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSection {
    pub id: String,
    pub title: String,
    pub content: String,
    pub section_number: Option<String>,
    pub subsections: Vec<DocumentSection>,
    pub fields: Vec<DocumentField>,
    pub compliance_status: Option<ComplianceStatus>,
}

impl DocumentSection {
    pub fn new(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            content: String::new(),
            section_number: None,
            subsections: Vec::new(),
            fields: Vec::new(),
            compliance_status: None,
        }
    }

    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    pub fn with_number(mut self, num: impl Into<String>) -> Self {
        self.section_number = Some(num.into());
        self
    }

    pub fn with_subsection(mut self, sub: DocumentSection) -> Self {
        self.subsections.push(sub);
        self
    }

    pub fn with_field(mut self, field: DocumentField) -> Self {
        self.fields.push(field);
        self
    }

    pub fn with_status(mut self, status: ComplianceStatus) -> Self {
        self.compliance_status = Some(status);
        self
    }
}

// ── Document ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: DocumentId,
    pub title: String,
    pub document_type: DocumentType,
    pub version: DocumentVersion,
    pub status: DocumentStatus,
    pub framework: ComplianceFramework,
    pub created_at: i64,
    pub updated_at: i64,
    pub created_by: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
    pub sections: Vec<DocumentSection>,
    pub metadata: HashMap<String, String>,
    pub classification: Option<String>,
    pub review_due: Option<i64>,
}

impl Document {
    pub fn new(
        id: DocumentId,
        title: impl Into<String>,
        document_type: DocumentType,
        framework: ComplianceFramework,
        created_by: impl Into<String>,
        now: i64,
    ) -> Self {
        Self {
            id,
            title: title.into(),
            document_type,
            version: DocumentVersion::initial(),
            status: DocumentStatus::Draft,
            framework,
            created_at: now,
            updated_at: now,
            created_by: created_by.into(),
            approved_by: None,
            approved_at: None,
            sections: Vec::new(),
            metadata: HashMap::new(),
            classification: None,
            review_due: None,
        }
    }

    pub fn with_section(mut self, section: DocumentSection) -> Self {
        self.sections.push(section);
        self
    }

    pub fn with_review_due(mut self, due: i64) -> Self {
        self.review_due = Some(due);
        self
    }

    pub fn with_classification(mut self, cls: impl Into<String>) -> Self {
        self.classification = Some(cls.into());
        self
    }
}

// ── DocumentStore ───────────────────────────────────────────────────

#[derive(Default)]
pub struct DocumentStore {
    documents: HashMap<DocumentId, Document>,
}

impl DocumentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, doc: Document) -> Result<(), DocumentError> {
        if self.documents.contains_key(&doc.id) {
            return Err(DocumentError::DocumentAlreadyExists(doc.id.0.clone()));
        }
        self.documents.insert(doc.id.clone(), doc);
        Ok(())
    }

    pub fn get(&self, id: &DocumentId) -> Option<&Document> {
        self.documents.get(id)
    }

    pub fn by_type(&self, doc_type: &DocumentType) -> Vec<&Document> {
        self.documents
            .values()
            .filter(|d| &d.document_type == doc_type)
            .collect()
    }

    pub fn by_framework(&self, framework: &ComplianceFramework) -> Vec<&Document> {
        self.documents
            .values()
            .filter(|d| &d.framework == framework)
            .collect()
    }

    pub fn by_status(&self, status_name: &str) -> Vec<&Document> {
        self.documents
            .values()
            .filter(|d| d.status.name() == status_name)
            .collect()
    }

    pub fn active_documents(&self) -> Vec<&Document> {
        self.documents
            .values()
            .filter(|d| d.status.is_active())
            .collect()
    }

    pub fn documents_due_review(&self, now: i64) -> Vec<&Document> {
        self.documents
            .values()
            .filter(|d| d.review_due.is_some_and(|due| due <= now) && d.status.is_active())
            .collect()
    }

    pub fn latest_version(&self, title: &str) -> Option<&Document> {
        self.documents
            .values()
            .filter(|d| d.title == title)
            .max_by_key(|d| d.version.clone())
    }

    pub fn approve(
        &mut self,
        id: &DocumentId,
        approver: &str,
        now: i64,
    ) -> Result<(), DocumentError> {
        let doc = self
            .documents
            .get_mut(id)
            .ok_or_else(|| DocumentError::DocumentNotFound(id.0.clone()))?;
        doc.status = DocumentStatus::Approved {
            approver: approver.into(),
            date: now,
        };
        doc.approved_by = Some(approver.into());
        doc.approved_at = Some(now);
        doc.updated_at = now;
        Ok(())
    }

    pub fn archive(&mut self, id: &DocumentId) -> Result<(), DocumentError> {
        let doc = self
            .documents
            .get_mut(id)
            .ok_or_else(|| DocumentError::DocumentNotFound(id.0.clone()))?;
        doc.status = DocumentStatus::Archived;
        Ok(())
    }

    pub fn supersede(
        &mut self,
        old_id: &DocumentId,
        new_id: &DocumentId,
    ) -> Result<(), DocumentError> {
        if !self.documents.contains_key(new_id) {
            return Err(DocumentError::DocumentNotFound(new_id.0.clone()));
        }
        let doc = self
            .documents
            .get_mut(old_id)
            .ok_or_else(|| DocumentError::DocumentNotFound(old_id.0.clone()))?;
        doc.status = DocumentStatus::Superseded {
            by: new_id.clone(),
        };
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.documents.len()
    }

    pub fn completion_rate(&self, id: &DocumentId) -> Option<f64> {
        let doc = self.documents.get(id)?;
        let mut required = 0usize;
        let mut filled = 0usize;
        count_fields(&doc.sections, &mut required, &mut filled);
        if required == 0 {
            return Some(1.0);
        }
        Some(filled as f64 / required as f64)
    }
}

fn count_fields(sections: &[DocumentSection], required: &mut usize, filled: &mut usize) {
    for section in sections {
        for field in &section.fields {
            if field.required {
                *required += 1;
                if field.filled {
                    *filled += 1;
                }
            }
        }
        count_fields(&section.subsections, required, filled);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc(id: &str) -> Document {
        Document::new(
            DocumentId::new(id),
            "Test Document",
            DocumentType::ComplianceReport,
            ComplianceFramework::GdprEu,
            "author",
            1000,
        )
    }

    fn doc_with_fields(id: &str) -> Document {
        sample_doc(id)
            .with_section(
                DocumentSection::new("s1", "Section 1")
                    .with_field(
                        DocumentField::new("name", FieldType::Text, true)
                            .with_value("filled"),
                    )
                    .with_field(DocumentField::new("empty", FieldType::Text, true)),
            )
    }

    #[test]
    fn test_document_id_display() {
        let id = DocumentId::new("doc-1");
        assert_eq!(id.to_string(), "doc-1");
        assert_eq!(id.as_str(), "doc-1");
    }

    #[test]
    fn test_document_construction() {
        let doc = sample_doc("d1");
        assert_eq!(doc.title, "Test Document");
        assert_eq!(doc.status, DocumentStatus::Draft);
        assert_eq!(doc.version, DocumentVersion::initial());
    }

    #[test]
    fn test_document_type_display() {
        assert_eq!(DocumentType::RecordOfProcessing.to_string(), "record-of-processing");
        assert_eq!(DocumentType::RiskManagementProfile.to_string(), "risk-management-profile");
        assert_eq!(DocumentType::MaturityAssessment.to_string(), "maturity-assessment");
        assert_eq!(DocumentType::PrivacyImpactAssessment.to_string(), "privacy-impact-assessment");
        assert_eq!(DocumentType::SystemSecurityPlan.to_string(), "system-security-plan");
        assert_eq!(DocumentType::DataProtectionImpactAssessment.to_string(), "data-protection-impact-assessment");
        assert_eq!(DocumentType::IncidentResponsePlan.to_string(), "incident-response-plan");
        assert_eq!(DocumentType::ComplianceReport.to_string(), "compliance-report");
        assert_eq!(DocumentType::PolicyDocument.to_string(), "policy-document");
        assert_eq!(DocumentType::AuditReport.to_string(), "audit-report");
        assert!(DocumentType::Custom("x".into()).to_string().contains("x"));
    }

    #[test]
    fn test_version_display_and_ordering() {
        let v = DocumentVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "v1.2.3");
        assert!(DocumentVersion::new(1, 0, 0) < DocumentVersion::new(1, 0, 1));
        assert!(DocumentVersion::new(1, 0, 1) < DocumentVersion::new(1, 1, 0));
        assert!(DocumentVersion::new(1, 1, 0) < DocumentVersion::new(2, 0, 0));
    }

    #[test]
    fn test_version_bumps() {
        let v = DocumentVersion::new(1, 2, 3);
        assert_eq!(v.bump_revision(), DocumentVersion::new(1, 2, 4));
        assert_eq!(v.bump_minor(), DocumentVersion::new(1, 3, 0));
        assert_eq!(v.bump_major(), DocumentVersion::new(2, 0, 0));
    }

    #[test]
    fn test_status_is_active_and_final() {
        assert!(DocumentStatus::Draft.is_active());
        assert!(DocumentStatus::UnderReview.is_active());
        assert!(DocumentStatus::Approved { approver: "a".into(), date: 0 }.is_active());
        assert!(DocumentStatus::Published.is_active());
        assert!(!DocumentStatus::Archived.is_active());
        assert!(!DocumentStatus::Superseded { by: DocumentId::new("x") }.is_active());

        assert!(DocumentStatus::Archived.is_final());
        assert!(DocumentStatus::Superseded { by: DocumentId::new("x") }.is_final());
        assert!(!DocumentStatus::Draft.is_final());
    }

    #[test]
    fn test_framework_jurisdiction() {
        assert_eq!(ComplianceFramework::GdprEu.jurisdiction(), "EU");
        assert_eq!(ComplianceFramework::GdprUk.jurisdiction(), "UK");
        assert_eq!(ComplianceFramework::NistAiRmf.jurisdiction(), "US");
        assert_eq!(ComplianceFramework::Ccpa.jurisdiction(), "US-CA");
        assert_eq!(ComplianceFramework::Iso27001.jurisdiction(), "International");
    }

    #[test]
    fn test_framework_full_name() {
        assert!(ComplianceFramework::GdprEu.full_name().contains("Data Protection"));
        assert!(ComplianceFramework::NistAiRmf.full_name().contains("Risk Management"));
        assert!(ComplianceFramework::Cmmc.full_name().contains("Maturity"));
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(ComplianceStatus::Compliant.to_string(), "compliant");
        assert!(ComplianceStatus::PartiallyCompliant { gaps: vec!["g".into()] }.to_string().contains("1 gaps"));
        assert!(ComplianceStatus::NonCompliant { reason: "r".into() }.to_string().contains("r"));
        assert_eq!(ComplianceStatus::NotAssessed.to_string(), "not-assessed");
        assert_eq!(ComplianceStatus::NotApplicable.to_string(), "not-applicable");
    }

    #[test]
    fn test_field_type_display() {
        assert_eq!(FieldType::Text.to_string(), "text");
        assert_eq!(FieldType::Date.to_string(), "date");
        assert_eq!(FieldType::YesNo.to_string(), "yes/no");
        assert_eq!(FieldType::Selection(vec![]).to_string(), "selection");
        assert_eq!(FieldType::Numeric.to_string(), "numeric");
        assert!(FieldType::Reference("doc-1".into()).to_string().contains("doc-1"));
    }

    #[test]
    fn test_store_add_and_get() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        assert!(store.get(&DocumentId::new("d1")).is_some());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_store_duplicate_add() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        assert!(matches!(
            store.add(sample_doc("d1")),
            Err(DocumentError::DocumentAlreadyExists(_))
        ));
    }

    #[test]
    fn test_store_by_type() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        store.add(Document::new(
            DocumentId::new("d2"),
            "SSP",
            DocumentType::SystemSecurityPlan,
            ComplianceFramework::FedRamp,
            "author",
            1000,
        )).unwrap();
        assert_eq!(store.by_type(&DocumentType::ComplianceReport).len(), 1);
        assert_eq!(store.by_type(&DocumentType::SystemSecurityPlan).len(), 1);
    }

    #[test]
    fn test_store_by_framework() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        assert_eq!(store.by_framework(&ComplianceFramework::GdprEu).len(), 1);
        assert_eq!(store.by_framework(&ComplianceFramework::Cmmc).len(), 0);
    }

    #[test]
    fn test_store_active_documents() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        store.add(sample_doc("d2")).unwrap();
        store.archive(&DocumentId::new("d2")).unwrap();
        assert_eq!(store.active_documents().len(), 1);
    }

    #[test]
    fn test_store_approve() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        store.approve(&DocumentId::new("d1"), "boss", 2000).unwrap();
        let doc = store.get(&DocumentId::new("d1")).unwrap();
        assert!(matches!(doc.status, DocumentStatus::Approved { .. }));
        assert_eq!(doc.approved_by.as_deref(), Some("boss"));
    }

    #[test]
    fn test_store_archive() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        store.archive(&DocumentId::new("d1")).unwrap();
        let doc = store.get(&DocumentId::new("d1")).unwrap();
        assert_eq!(doc.status, DocumentStatus::Archived);
    }

    #[test]
    fn test_store_supersede() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1")).unwrap();
        store.add(sample_doc("d2")).unwrap();
        store.supersede(&DocumentId::new("d1"), &DocumentId::new("d2")).unwrap();
        let old = store.get(&DocumentId::new("d1")).unwrap();
        assert!(matches!(old.status, DocumentStatus::Superseded { .. }));
    }

    #[test]
    fn test_store_documents_due_review() {
        let mut store = DocumentStore::new();
        store.add(sample_doc("d1").with_review_due(1500)).unwrap();
        store.add(sample_doc("d2").with_review_due(3000)).unwrap();
        assert_eq!(store.documents_due_review(2000).len(), 1);
    }

    #[test]
    fn test_store_completion_rate() {
        let mut store = DocumentStore::new();
        store.add(doc_with_fields("d1")).unwrap();
        let rate = store.completion_rate(&DocumentId::new("d1")).unwrap();
        assert!((rate - 0.5).abs() < 1e-9);
    }
}
