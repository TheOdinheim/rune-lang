// ═══════════════════════════════════════════════════════════════════════
// Audit — document-specific audit events and log.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::document::DocumentId;

// ── DocumentEventType ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DocumentEventType {
    DocumentCreated { document_type: String, framework: String },
    DocumentUpdated { section: String },
    DocumentApproved { approver: String },
    DocumentPublished,
    DocumentArchived,
    DocumentSuperseded { by: String },
    TemplateInstantiated { template_id: String },
    ComplianceGapFound { framework: String, gap: String },
    ReviewDue { document_id: String, due_date: i64 },
    DocumentRendered { format: String },
    // ── Layer 2 event types ─────────────────────────────────────────
    DocumentHashComputed { doc_id: String, algorithm: String },
    DocumentIntegrityVerified { doc_id: String, version: u32, matches: bool },
    DocumentHashChainVerified { chain_length: usize, valid: bool },
    LifecycleTransitioned { doc_id: String, from: String, to: String },
    LifecyclePolicyChecked { doc_id: String, violations: usize },
    VersionDiffComputed { doc_id: String, from_version: u32, to_version: u32 },
    VersionSnapshotCreated { doc_id: String, version: u32 },
    DocumentClassified { doc_id: String, level: String },
    SensitivityScored { doc_id: String, score: f64, level: String },
    ComplianceDocumentGenerated { doc_id: String, framework: String, completeness: f64 },
    CompliancePackageCreated { package_id: String, documents: usize },
    RetentionPolicyApplied { doc_id: String, policy_id: String },
    DocumentExpired { doc_id: String, policy_id: String },
    LegalHoldPlaced { doc_id: String, hold_id: String },
    DocumentDisposed { doc_id: String, method: String },
    // ── Layer 3 event types ─────────────────────────────────────────
    DocumentBackendChanged { backend_id: String },
    DocumentRecordStored { doc_id: String, category: String },
    DocumentRecordRetrieved { doc_id: String },
    DocumentRecordDeleted { doc_id: String },
    DocumentVersionStored { doc_id: String, version_id: String },
    ContentBlobStored { doc_id: String, blob_size: usize },
    DocumentMetadataSearched { query: String, result_count: usize },
    DocumentExported { doc_id: String, format: String },
    DocumentExportFailed { doc_id: String, format: String, reason: String },
    ContentIngested { content_id: String, source_format: String },
    ContentIngestionFailed { content_id: String, reason: String },
    VersionControllerActionPerformed { doc_id: String, action: String },
    DocumentTagCreated { doc_id: String, tag: String },
    VersionComparisonComputed { doc_id: String, version_a: String, version_b: String },
    RetentionPolicyLinked { doc_id: String, policy_id: String },
    RetentionPolicyUnlinked { doc_id: String, policy_id: String },
    DocumentDisposalRecorded { doc_id: String, method: String },
    ContentFormatConverted { from_format: String, to_format: String },
    ContentFormatConversionFailed { from_format: String, to_format: String, reason: String },
    DocumentSubscriberRegistered { subscriber_id: String },
    DocumentSubscriberRemoved { subscriber_id: String },
    DocumentEventPublished { event_type: String, subscriber_count: usize },
}

impl fmt::Display for DocumentEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentCreated { document_type, framework } => {
                write!(f, "document-created:{document_type} [{framework}]")
            }
            Self::DocumentUpdated { section } => {
                write!(f, "document-updated:{section}")
            }
            Self::DocumentApproved { approver } => {
                write!(f, "document-approved by {approver}")
            }
            Self::DocumentPublished => f.write_str("document-published"),
            Self::DocumentArchived => f.write_str("document-archived"),
            Self::DocumentSuperseded { by } => {
                write!(f, "document-superseded by {by}")
            }
            Self::TemplateInstantiated { template_id } => {
                write!(f, "template-instantiated:{template_id}")
            }
            Self::ComplianceGapFound { framework, gap } => {
                write!(f, "compliance-gap:{framework} [{gap}]")
            }
            Self::ReviewDue { document_id, due_date } => {
                write!(f, "review-due:{document_id} at {due_date}")
            }
            Self::DocumentRendered { format } => {
                write!(f, "document-rendered:{format}")
            }
            Self::DocumentHashComputed { doc_id, algorithm } => {
                write!(f, "document-hash-computed:{doc_id} [{algorithm}]")
            }
            Self::DocumentIntegrityVerified { doc_id, version, matches } => {
                write!(f, "document-integrity-verified:{doc_id} v{version} {}", if *matches { "ok" } else { "mismatch" })
            }
            Self::DocumentHashChainVerified { chain_length, valid } => {
                write!(f, "document-hash-chain-verified ({chain_length} entries, {})", if *valid { "valid" } else { "broken" })
            }
            Self::LifecycleTransitioned { doc_id, from, to } => {
                write!(f, "lifecycle-transitioned:{doc_id} {from} -> {to}")
            }
            Self::LifecyclePolicyChecked { doc_id, violations } => {
                write!(f, "lifecycle-policy-checked:{doc_id} ({violations} violations)")
            }
            Self::VersionDiffComputed { doc_id, from_version, to_version } => {
                write!(f, "version-diff-computed:{doc_id} v{from_version} -> v{to_version}")
            }
            Self::VersionSnapshotCreated { doc_id, version } => {
                write!(f, "version-snapshot-created:{doc_id} v{version}")
            }
            Self::DocumentClassified { doc_id, level } => {
                write!(f, "document-classified:{doc_id} [{level}]")
            }
            Self::SensitivityScored { doc_id, score, level } => {
                write!(f, "sensitivity-scored:{doc_id} score={score:.1} [{level}]")
            }
            Self::ComplianceDocumentGenerated { doc_id, framework, completeness } => {
                write!(f, "compliance-document-generated:{doc_id} [{framework}] {completeness:.1}%")
            }
            Self::CompliancePackageCreated { package_id, documents } => {
                write!(f, "compliance-package-created:{package_id} ({documents} docs)")
            }
            Self::RetentionPolicyApplied { doc_id, policy_id } => {
                write!(f, "retention-policy-applied:{doc_id} [{policy_id}]")
            }
            Self::DocumentExpired { doc_id, policy_id } => {
                write!(f, "document-expired:{doc_id} [{policy_id}]")
            }
            Self::LegalHoldPlaced { doc_id, hold_id } => {
                write!(f, "legal-hold-placed:{doc_id} [{hold_id}]")
            }
            Self::DocumentDisposed { doc_id, method } => {
                write!(f, "document-disposed:{doc_id} [{method}]")
            }
            Self::DocumentBackendChanged { backend_id } => {
                write!(f, "document-backend-changed:{backend_id}")
            }
            Self::DocumentRecordStored { doc_id, category } => {
                write!(f, "document-record-stored:{doc_id} [{category}]")
            }
            Self::DocumentRecordRetrieved { doc_id } => {
                write!(f, "document-record-retrieved:{doc_id}")
            }
            Self::DocumentRecordDeleted { doc_id } => {
                write!(f, "document-record-deleted:{doc_id}")
            }
            Self::DocumentVersionStored { doc_id, version_id } => {
                write!(f, "document-version-stored:{doc_id} [{version_id}]")
            }
            Self::ContentBlobStored { doc_id, blob_size } => {
                write!(f, "content-blob-stored:{doc_id} ({blob_size} bytes)")
            }
            Self::DocumentMetadataSearched { query, result_count } => {
                write!(f, "document-metadata-searched:{query} ({result_count} results)")
            }
            Self::DocumentExported { doc_id, format } => {
                write!(f, "document-exported:{doc_id} [{format}]")
            }
            Self::DocumentExportFailed { doc_id, format, reason } => {
                write!(f, "document-export-failed:{doc_id} [{format}] {reason}")
            }
            Self::ContentIngested { content_id, source_format } => {
                write!(f, "content-ingested:{content_id} [{source_format}]")
            }
            Self::ContentIngestionFailed { content_id, reason } => {
                write!(f, "content-ingestion-failed:{content_id} {reason}")
            }
            Self::VersionControllerActionPerformed { doc_id, action } => {
                write!(f, "version-controller-action:{doc_id} [{action}]")
            }
            Self::DocumentTagCreated { doc_id, tag } => {
                write!(f, "document-tag-created:{doc_id} [{tag}]")
            }
            Self::VersionComparisonComputed { doc_id, version_a, version_b } => {
                write!(f, "version-comparison-computed:{doc_id} {version_a} vs {version_b}")
            }
            Self::RetentionPolicyLinked { doc_id, policy_id } => {
                write!(f, "retention-policy-linked:{doc_id} [{policy_id}]")
            }
            Self::RetentionPolicyUnlinked { doc_id, policy_id } => {
                write!(f, "retention-policy-unlinked:{doc_id} [{policy_id}]")
            }
            Self::DocumentDisposalRecorded { doc_id, method } => {
                write!(f, "document-disposal-recorded:{doc_id} [{method}]")
            }
            Self::ContentFormatConverted { from_format, to_format } => {
                write!(f, "content-format-converted:{from_format} -> {to_format}")
            }
            Self::ContentFormatConversionFailed { from_format, to_format, reason } => {
                write!(f, "content-format-conversion-failed:{from_format} -> {to_format} {reason}")
            }
            Self::DocumentSubscriberRegistered { subscriber_id } => {
                write!(f, "document-subscriber-registered:{subscriber_id}")
            }
            Self::DocumentSubscriberRemoved { subscriber_id } => {
                write!(f, "document-subscriber-removed:{subscriber_id}")
            }
            Self::DocumentEventPublished { event_type, subscriber_count } => {
                write!(f, "document-event-published:{event_type} ({subscriber_count} subscribers)")
            }
        }
    }
}

impl DocumentEventType {
    fn type_name(&self) -> &str {
        match self {
            Self::DocumentCreated { .. } => "document-created",
            Self::DocumentUpdated { .. } => "document-updated",
            Self::DocumentApproved { .. } => "document-approved",
            Self::DocumentPublished => "document-published",
            Self::DocumentArchived => "document-archived",
            Self::DocumentSuperseded { .. } => "document-superseded",
            Self::TemplateInstantiated { .. } => "template-instantiated",
            Self::ComplianceGapFound { .. } => "compliance-gap-found",
            Self::ReviewDue { .. } => "review-due",
            Self::DocumentRendered { .. } => "document-rendered",
            Self::DocumentHashComputed { .. } => "document-hash-computed",
            Self::DocumentIntegrityVerified { .. } => "document-integrity-verified",
            Self::DocumentHashChainVerified { .. } => "document-hash-chain-verified",
            Self::LifecycleTransitioned { .. } => "lifecycle-transitioned",
            Self::LifecyclePolicyChecked { .. } => "lifecycle-policy-checked",
            Self::VersionDiffComputed { .. } => "version-diff-computed",
            Self::VersionSnapshotCreated { .. } => "version-snapshot-created",
            Self::DocumentClassified { .. } => "document-classified",
            Self::SensitivityScored { .. } => "sensitivity-scored",
            Self::ComplianceDocumentGenerated { .. } => "compliance-document-generated",
            Self::CompliancePackageCreated { .. } => "compliance-package-created",
            Self::RetentionPolicyApplied { .. } => "retention-policy-applied",
            Self::DocumentExpired { .. } => "document-expired",
            Self::LegalHoldPlaced { .. } => "legal-hold-placed",
            Self::DocumentDisposed { .. } => "document-disposed",
            Self::DocumentBackendChanged { .. } => "document-backend-changed",
            Self::DocumentRecordStored { .. } => "document-record-stored",
            Self::DocumentRecordRetrieved { .. } => "document-record-retrieved",
            Self::DocumentRecordDeleted { .. } => "document-record-deleted",
            Self::DocumentVersionStored { .. } => "document-version-stored",
            Self::ContentBlobStored { .. } => "content-blob-stored",
            Self::DocumentMetadataSearched { .. } => "document-metadata-searched",
            Self::DocumentExported { .. } => "document-exported",
            Self::DocumentExportFailed { .. } => "document-export-failed",
            Self::ContentIngested { .. } => "content-ingested",
            Self::ContentIngestionFailed { .. } => "content-ingestion-failed",
            Self::VersionControllerActionPerformed { .. } => "version-controller-action-performed",
            Self::DocumentTagCreated { .. } => "document-tag-created",
            Self::VersionComparisonComputed { .. } => "version-comparison-computed",
            Self::RetentionPolicyLinked { .. } => "retention-policy-linked",
            Self::RetentionPolicyUnlinked { .. } => "retention-policy-unlinked",
            Self::DocumentDisposalRecorded { .. } => "document-disposal-recorded",
            Self::ContentFormatConverted { .. } => "content-format-converted",
            Self::ContentFormatConversionFailed { .. } => "content-format-conversion-failed",
            Self::DocumentSubscriberRegistered { .. } => "document-subscriber-registered",
            Self::DocumentSubscriberRemoved { .. } => "document-subscriber-removed",
            Self::DocumentEventPublished { .. } => "document-event-published",
        }
    }

    pub fn kind(&self) -> &str {
        self.type_name()
    }

    pub fn is_backend_event(&self) -> bool {
        matches!(
            self,
            Self::DocumentBackendChanged { .. }
                | Self::DocumentRecordStored { .. }
                | Self::DocumentRecordRetrieved { .. }
                | Self::DocumentRecordDeleted { .. }
                | Self::ContentBlobStored { .. }
                | Self::DocumentMetadataSearched { .. }
        )
    }

    pub fn is_version_event(&self) -> bool {
        matches!(
            self,
            Self::DocumentVersionStored { .. }
                | Self::VersionControllerActionPerformed { .. }
                | Self::DocumentTagCreated { .. }
                | Self::VersionComparisonComputed { .. }
        )
    }

    pub fn is_retention_event(&self) -> bool {
        matches!(
            self,
            Self::RetentionPolicyLinked { .. }
                | Self::RetentionPolicyUnlinked { .. }
                | Self::DocumentDisposalRecorded { .. }
        )
    }

    pub fn is_ingestion_event(&self) -> bool {
        matches!(
            self,
            Self::ContentIngested { .. } | Self::ContentIngestionFailed { .. }
        )
    }

    pub fn is_conversion_event(&self) -> bool {
        matches!(
            self,
            Self::ContentFormatConverted { .. } | Self::ContentFormatConversionFailed { .. }
        )
    }

    pub fn is_export_event(&self) -> bool {
        matches!(
            self,
            Self::DocumentExported { .. } | Self::DocumentExportFailed { .. }
        )
    }
}

// ── DocumentAuditEvent ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DocumentAuditEvent {
    pub event_type: DocumentEventType,
    pub timestamp: i64,
    pub actor: String,
    pub detail: String,
    pub document_id: Option<DocumentId>,
}

impl DocumentAuditEvent {
    pub fn new(
        event_type: DocumentEventType,
        actor: impl Into<String>,
        timestamp: i64,
        detail: impl Into<String>,
    ) -> Self {
        let document_id = match &event_type {
            DocumentEventType::ReviewDue { document_id, .. } => {
                Some(DocumentId::new(document_id))
            }
            DocumentEventType::DocumentHashComputed { doc_id, .. }
            | DocumentEventType::DocumentIntegrityVerified { doc_id, .. }
            | DocumentEventType::LifecycleTransitioned { doc_id, .. }
            | DocumentEventType::LifecyclePolicyChecked { doc_id, .. }
            | DocumentEventType::VersionDiffComputed { doc_id, .. }
            | DocumentEventType::VersionSnapshotCreated { doc_id, .. }
            | DocumentEventType::DocumentClassified { doc_id, .. }
            | DocumentEventType::SensitivityScored { doc_id, .. }
            | DocumentEventType::ComplianceDocumentGenerated { doc_id, .. }
            | DocumentEventType::RetentionPolicyApplied { doc_id, .. }
            | DocumentEventType::DocumentExpired { doc_id, .. }
            | DocumentEventType::LegalHoldPlaced { doc_id, .. }
            | DocumentEventType::DocumentDisposed { doc_id, .. }
            | DocumentEventType::DocumentRecordStored { doc_id, .. }
            | DocumentEventType::DocumentRecordRetrieved { doc_id, .. }
            | DocumentEventType::DocumentRecordDeleted { doc_id, .. }
            | DocumentEventType::DocumentVersionStored { doc_id, .. }
            | DocumentEventType::ContentBlobStored { doc_id, .. }
            | DocumentEventType::DocumentExported { doc_id, .. }
            | DocumentEventType::DocumentExportFailed { doc_id, .. }
            | DocumentEventType::VersionControllerActionPerformed { doc_id, .. }
            | DocumentEventType::DocumentTagCreated { doc_id, .. }
            | DocumentEventType::VersionComparisonComputed { doc_id, .. }
            | DocumentEventType::RetentionPolicyLinked { doc_id, .. }
            | DocumentEventType::RetentionPolicyUnlinked { doc_id, .. }
            | DocumentEventType::DocumentDisposalRecorded { doc_id, .. } => {
                Some(DocumentId::new(doc_id))
            }
            _ => None,
        };
        Self {
            event_type,
            timestamp,
            actor: actor.into(),
            detail: detail.into(),
            document_id,
        }
    }

    pub fn for_document(mut self, id: DocumentId) -> Self {
        self.document_id = Some(id);
        self
    }
}

// ── DocumentAuditLog ────────────────────────────────────────────────

#[derive(Default)]
pub struct DocumentAuditLog {
    pub events: Vec<DocumentAuditEvent>,
}

impl DocumentAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: DocumentAuditEvent) {
        self.events.push(event);
    }

    pub fn events_for_document(&self, id: &DocumentId) -> Vec<&DocumentAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.document_id.as_ref() == Some(id))
            .collect()
    }

    pub fn events_by_type(&self, type_name: &str) -> Vec<&DocumentAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event_type.type_name() == type_name)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&DocumentAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn approval_events(&self) -> Vec<&DocumentAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, DocumentEventType::DocumentApproved { .. }))
            .collect()
    }

    pub fn compliance_gap_events(&self) -> Vec<&DocumentAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, DocumentEventType::ComplianceGapFound { .. }))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_retrieve() {
        let mut log = DocumentAuditLog::new();
        log.record(
            DocumentAuditEvent::new(
                DocumentEventType::DocumentCreated {
                    document_type: "ssp".into(),
                    framework: "FedRAMP".into(),
                },
                "system",
                1000,
                "created",
            )
            .for_document(DocumentId::new("d1")),
        );
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_events_for_document() {
        let mut log = DocumentAuditLog::new();
        log.record(
            DocumentAuditEvent::new(
                DocumentEventType::DocumentCreated {
                    document_type: "ssp".into(),
                    framework: "FedRAMP".into(),
                },
                "system",
                1000,
                "created",
            )
            .for_document(DocumentId::new("d1")),
        );
        log.record(
            DocumentAuditEvent::new(
                DocumentEventType::DocumentApproved {
                    approver: "boss".into(),
                },
                "boss",
                2000,
                "approved",
            )
            .for_document(DocumentId::new("d2")),
        );
        assert_eq!(log.events_for_document(&DocumentId::new("d1")).len(), 1);
    }

    #[test]
    fn test_approval_events() {
        let mut log = DocumentAuditLog::new();
        log.record(DocumentAuditEvent::new(
            DocumentEventType::DocumentApproved {
                approver: "boss".into(),
            },
            "boss",
            1000,
            "approved",
        ));
        log.record(DocumentAuditEvent::new(
            DocumentEventType::DocumentPublished,
            "system",
            2000,
            "published",
        ));
        assert_eq!(log.approval_events().len(), 1);
    }

    #[test]
    fn test_compliance_gap_events() {
        let mut log = DocumentAuditLog::new();
        log.record(DocumentAuditEvent::new(
            DocumentEventType::ComplianceGapFound {
                framework: "GDPR".into(),
                gap: "missing legal basis".into(),
            },
            "system",
            1000,
            "gap found",
        ));
        assert_eq!(log.compliance_gap_events().len(), 1);
    }

    #[test]
    fn test_event_type_display() {
        let events = vec![
            DocumentEventType::DocumentCreated { document_type: "ssp".into(), framework: "FedRAMP".into() },
            DocumentEventType::DocumentUpdated { section: "s1".into() },
            DocumentEventType::DocumentApproved { approver: "boss".into() },
            DocumentEventType::DocumentPublished,
            DocumentEventType::DocumentArchived,
            DocumentEventType::DocumentSuperseded { by: "d2".into() },
            DocumentEventType::TemplateInstantiated { template_id: "t1".into() },
            DocumentEventType::ComplianceGapFound { framework: "GDPR".into(), gap: "g1".into() },
            DocumentEventType::ReviewDue { document_id: "d1".into(), due_date: 1000 },
            DocumentEventType::DocumentRendered { format: "json".into() },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
    }

    #[test]
    fn test_l2_event_type_display() {
        let events = vec![
            DocumentEventType::DocumentHashComputed { doc_id: "d1".into(), algorithm: "SHA3-256".into() },
            DocumentEventType::DocumentIntegrityVerified { doc_id: "d1".into(), version: 1, matches: true },
            DocumentEventType::DocumentHashChainVerified { chain_length: 5, valid: true },
            DocumentEventType::LifecycleTransitioned { doc_id: "d1".into(), from: "draft".into(), to: "review".into() },
            DocumentEventType::LifecyclePolicyChecked { doc_id: "d1".into(), violations: 0 },
            DocumentEventType::VersionDiffComputed { doc_id: "d1".into(), from_version: 1, to_version: 2 },
            DocumentEventType::VersionSnapshotCreated { doc_id: "d1".into(), version: 1 },
            DocumentEventType::DocumentClassified { doc_id: "d1".into(), level: "confidential".into() },
            DocumentEventType::SensitivityScored { doc_id: "d1".into(), score: 55.0, level: "confidential".into() },
            DocumentEventType::ComplianceDocumentGenerated { doc_id: "d1".into(), framework: "NIST".into(), completeness: 0.8 },
            DocumentEventType::CompliancePackageCreated { package_id: "pkg1".into(), documents: 3 },
            DocumentEventType::RetentionPolicyApplied { doc_id: "d1".into(), policy_id: "p1".into() },
            DocumentEventType::DocumentExpired { doc_id: "d1".into(), policy_id: "p1".into() },
            DocumentEventType::LegalHoldPlaced { doc_id: "d1".into(), hold_id: "h1".into() },
            DocumentEventType::DocumentDisposed { doc_id: "d1".into(), method: "archive".into() },
        ];
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
        assert_eq!(events.len(), 15);
    }

    #[test]
    fn test_l2_event_doc_id_extraction() {
        let event = DocumentAuditEvent::new(
            DocumentEventType::DocumentHashComputed {
                doc_id: "d99".into(),
                algorithm: "SHA3-256".into(),
            },
            "system",
            5000,
            "hashed",
        );
        assert_eq!(event.document_id, Some(DocumentId::new("d99")));
    }

    #[test]
    fn test_l2_event_no_doc_id() {
        let event = DocumentAuditEvent::new(
            DocumentEventType::DocumentHashChainVerified {
                chain_length: 3,
                valid: true,
            },
            "system",
            5000,
            "verified",
        );
        assert!(event.document_id.is_none());
    }

    #[test]
    fn test_l2_events_by_type() {
        let mut log = DocumentAuditLog::new();
        log.record(DocumentAuditEvent::new(
            DocumentEventType::DocumentHashComputed { doc_id: "d1".into(), algorithm: "SHA3-256".into() },
            "system", 1000, "",
        ));
        log.record(DocumentAuditEvent::new(
            DocumentEventType::DocumentHashComputed { doc_id: "d2".into(), algorithm: "SHA3-256".into() },
            "system", 2000, "",
        ));
        log.record(DocumentAuditEvent::new(
            DocumentEventType::LifecycleTransitioned { doc_id: "d1".into(), from: "draft".into(), to: "review".into() },
            "system", 3000, "",
        ));
        assert_eq!(log.events_by_type("document-hash-computed").len(), 2);
        assert_eq!(log.events_by_type("lifecycle-transitioned").len(), 1);
    }

    #[test]
    fn test_l3_event_type_display() {
        let events = vec![
            DocumentEventType::DocumentBackendChanged { backend_id: "b1".into() },
            DocumentEventType::DocumentRecordStored { doc_id: "d1".into(), category: "policy".into() },
            DocumentEventType::DocumentRecordRetrieved { doc_id: "d1".into() },
            DocumentEventType::DocumentRecordDeleted { doc_id: "d1".into() },
            DocumentEventType::DocumentVersionStored { doc_id: "d1".into(), version_id: "v1".into() },
            DocumentEventType::ContentBlobStored { doc_id: "d1".into(), blob_size: 1024 },
            DocumentEventType::DocumentMetadataSearched { query: "q".into(), result_count: 5 },
            DocumentEventType::DocumentExported { doc_id: "d1".into(), format: "json".into() },
            DocumentEventType::DocumentExportFailed { doc_id: "d1".into(), format: "pdf".into(), reason: "err".into() },
            DocumentEventType::ContentIngested { content_id: "c1".into(), source_format: "markdown".into() },
            DocumentEventType::ContentIngestionFailed { content_id: "c1".into(), reason: "bad".into() },
            DocumentEventType::VersionControllerActionPerformed { doc_id: "d1".into(), action: "create".into() },
            DocumentEventType::DocumentTagCreated { doc_id: "d1".into(), tag: "v1.0".into() },
            DocumentEventType::VersionComparisonComputed { doc_id: "d1".into(), version_a: "v1".into(), version_b: "v2".into() },
            DocumentEventType::RetentionPolicyLinked { doc_id: "d1".into(), policy_id: "p1".into() },
            DocumentEventType::RetentionPolicyUnlinked { doc_id: "d1".into(), policy_id: "p1".into() },
            DocumentEventType::DocumentDisposalRecorded { doc_id: "d1".into(), method: "archive".into() },
            DocumentEventType::ContentFormatConverted { from_format: "md".into(), to_format: "html".into() },
            DocumentEventType::ContentFormatConversionFailed { from_format: "md".into(), to_format: "pdf".into(), reason: "err".into() },
            DocumentEventType::DocumentSubscriberRegistered { subscriber_id: "s1".into() },
            DocumentEventType::DocumentSubscriberRemoved { subscriber_id: "s1".into() },
            DocumentEventType::DocumentEventPublished { event_type: "created".into(), subscriber_count: 3 },
        ];
        assert_eq!(events.len(), 22);
        for event in &events {
            assert!(!event.to_string().is_empty());
        }
    }

    #[test]
    fn test_l3_event_doc_id_extraction() {
        let event = DocumentAuditEvent::new(
            DocumentEventType::DocumentRecordStored {
                doc_id: "d42".into(),
                category: "policy".into(),
            },
            "system",
            6000,
            "stored",
        );
        assert_eq!(event.document_id, Some(DocumentId::new("d42")));
    }

    #[test]
    fn test_l3_event_no_doc_id() {
        let event = DocumentAuditEvent::new(
            DocumentEventType::DocumentBackendChanged {
                backend_id: "b1".into(),
            },
            "system",
            6000,
            "changed",
        );
        assert!(event.document_id.is_none());

        let event2 = DocumentAuditEvent::new(
            DocumentEventType::ContentIngested {
                content_id: "c1".into(),
                source_format: "md".into(),
            },
            "system",
            6000,
            "ingested",
        );
        assert!(event2.document_id.is_none());
    }

    #[test]
    fn test_kind_method() {
        let event = DocumentEventType::DocumentCreated {
            document_type: "ssp".into(),
            framework: "FedRAMP".into(),
        };
        assert_eq!(event.kind(), "document-created");

        let event2 = DocumentEventType::DocumentExported {
            doc_id: "d1".into(),
            format: "json".into(),
        };
        assert_eq!(event2.kind(), "document-exported");
    }

    #[test]
    fn test_is_backend_event() {
        assert!(DocumentEventType::DocumentBackendChanged { backend_id: "b".into() }.is_backend_event());
        assert!(DocumentEventType::DocumentRecordStored { doc_id: "d".into(), category: "c".into() }.is_backend_event());
        assert!(DocumentEventType::DocumentRecordRetrieved { doc_id: "d".into() }.is_backend_event());
        assert!(DocumentEventType::DocumentRecordDeleted { doc_id: "d".into() }.is_backend_event());
        assert!(DocumentEventType::ContentBlobStored { doc_id: "d".into(), blob_size: 0 }.is_backend_event());
        assert!(DocumentEventType::DocumentMetadataSearched { query: "q".into(), result_count: 0 }.is_backend_event());
        assert!(!DocumentEventType::DocumentExported { doc_id: "d".into(), format: "f".into() }.is_backend_event());
    }

    #[test]
    fn test_is_version_event() {
        assert!(DocumentEventType::DocumentVersionStored { doc_id: "d".into(), version_id: "v".into() }.is_version_event());
        assert!(DocumentEventType::VersionControllerActionPerformed { doc_id: "d".into(), action: "a".into() }.is_version_event());
        assert!(DocumentEventType::DocumentTagCreated { doc_id: "d".into(), tag: "t".into() }.is_version_event());
        assert!(DocumentEventType::VersionComparisonComputed { doc_id: "d".into(), version_a: "a".into(), version_b: "b".into() }.is_version_event());
        assert!(!DocumentEventType::DocumentPublished.is_version_event());
    }

    #[test]
    fn test_is_retention_event() {
        assert!(DocumentEventType::RetentionPolicyLinked { doc_id: "d".into(), policy_id: "p".into() }.is_retention_event());
        assert!(DocumentEventType::RetentionPolicyUnlinked { doc_id: "d".into(), policy_id: "p".into() }.is_retention_event());
        assert!(DocumentEventType::DocumentDisposalRecorded { doc_id: "d".into(), method: "m".into() }.is_retention_event());
        assert!(!DocumentEventType::DocumentPublished.is_retention_event());
    }

    #[test]
    fn test_is_ingestion_event() {
        assert!(DocumentEventType::ContentIngested { content_id: "c".into(), source_format: "md".into() }.is_ingestion_event());
        assert!(DocumentEventType::ContentIngestionFailed { content_id: "c".into(), reason: "r".into() }.is_ingestion_event());
        assert!(!DocumentEventType::DocumentPublished.is_ingestion_event());
    }

    #[test]
    fn test_is_conversion_event() {
        assert!(DocumentEventType::ContentFormatConverted { from_format: "a".into(), to_format: "b".into() }.is_conversion_event());
        assert!(DocumentEventType::ContentFormatConversionFailed { from_format: "a".into(), to_format: "b".into(), reason: "r".into() }.is_conversion_event());
        assert!(!DocumentEventType::DocumentPublished.is_conversion_event());
    }

    #[test]
    fn test_is_export_event() {
        assert!(DocumentEventType::DocumentExported { doc_id: "d".into(), format: "f".into() }.is_export_event());
        assert!(DocumentEventType::DocumentExportFailed { doc_id: "d".into(), format: "f".into(), reason: "r".into() }.is_export_event());
        assert!(!DocumentEventType::DocumentPublished.is_export_event());
    }

    #[test]
    fn test_l3_events_by_type() {
        let mut log = DocumentAuditLog::new();
        log.record(DocumentAuditEvent::new(
            DocumentEventType::DocumentExported { doc_id: "d1".into(), format: "json".into() },
            "system", 1000, "",
        ));
        log.record(DocumentAuditEvent::new(
            DocumentEventType::DocumentExported { doc_id: "d2".into(), format: "pdf-a".into() },
            "system", 2000, "",
        ));
        log.record(DocumentAuditEvent::new(
            DocumentEventType::ContentIngested { content_id: "c1".into(), source_format: "md".into() },
            "system", 3000, "",
        ));
        assert_eq!(log.events_by_type("document-exported").len(), 2);
        assert_eq!(log.events_by_type("content-ingested").len(), 1);
    }
}
