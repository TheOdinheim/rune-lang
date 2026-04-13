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
}
