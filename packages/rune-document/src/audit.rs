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
        }
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
            | DocumentEventType::DocumentDisposed { doc_id, .. } => {
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
}
