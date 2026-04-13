// ═══════════════════════════════════════════════════════════════════════
// GDPR — Article 30 records of processing activities.
// ═══════════════════════════════════════════════════════════════════════

use crate::document::*;

// ── ControllerInfo ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ControllerInfo {
    pub name: String,
    pub address: String,
    pub contact: String,
    pub representative: Option<String>,
    pub dpo: Option<String>,
}

impl ControllerInfo {
    pub fn new(
        name: impl Into<String>,
        address: impl Into<String>,
        contact: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            contact: contact.into(),
            representative: None,
            dpo: None,
        }
    }
}

// ── InternationalTransfer ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InternationalTransfer {
    pub destination_country: String,
    pub legal_basis: String,
    pub safeguards: Vec<String>,
}

// ── ProcessingActivity ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessingActivity {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub legal_basis: String,
    pub data_categories: Vec<String>,
    pub data_subjects: Vec<String>,
    pub recipients: Vec<String>,
    pub international_transfers: Vec<InternationalTransfer>,
    pub retention_period: String,
    pub security_measures: Vec<String>,
    pub automated_decision_making: bool,
    pub dpia_required: bool,
    pub dpia_reference: Option<String>,
}

impl ProcessingActivity {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        purpose: impl Into<String>,
        legal_basis: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            purpose: purpose.into(),
            legal_basis: legal_basis.into(),
            data_categories: Vec::new(),
            data_subjects: Vec::new(),
            recipients: Vec::new(),
            international_transfers: Vec::new(),
            retention_period: String::new(),
            security_measures: Vec::new(),
            automated_decision_making: false,
            dpia_required: false,
            dpia_reference: None,
        }
    }

    pub fn with_data_category(mut self, cat: impl Into<String>) -> Self {
        self.data_categories.push(cat.into());
        self
    }

    pub fn with_data_subject(mut self, sub: impl Into<String>) -> Self {
        self.data_subjects.push(sub.into());
        self
    }

    pub fn with_recipient(mut self, rec: impl Into<String>) -> Self {
        self.recipients.push(rec.into());
        self
    }

    pub fn with_retention(mut self, period: impl Into<String>) -> Self {
        self.retention_period = period.into();
        self
    }

    pub fn with_security_measure(mut self, measure: impl Into<String>) -> Self {
        self.security_measures.push(measure.into());
        self
    }

    pub fn with_transfer(mut self, transfer: InternationalTransfer) -> Self {
        self.international_transfers.push(transfer);
        self
    }
}

// ── GdprGap ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GdprGap {
    pub article: String,
    pub requirement: String,
    pub current_state: String,
    pub recommendation: String,
}

// ── GdprDocumentBuilder ─────────────────────────────────────────────

pub struct GdprDocumentBuilder {
    controller: ControllerInfo,
    dpo_contact: Option<String>,
    activities: Vec<ProcessingActivity>,
}

impl GdprDocumentBuilder {
    pub fn new(controller: ControllerInfo) -> Self {
        Self {
            controller,
            dpo_contact: None,
            activities: Vec::new(),
        }
    }

    pub fn dpo(&mut self, contact: &str) -> &mut Self {
        self.dpo_contact = Some(contact.into());
        self
    }

    pub fn add_activity(&mut self, activity: ProcessingActivity) -> &mut Self {
        self.activities.push(activity);
        self
    }

    pub fn build(&self, now: i64) -> Document {
        let mut doc = Document::new(
            DocumentId::new(format!("gdpr-art30-{now}")),
            "Record of Processing Activities (GDPR Article 30)",
            DocumentType::RecordOfProcessing,
            ComplianceFramework::GdprEu,
            "system",
            now,
        );

        // Section 1: Controller identification
        let mut s1 = DocumentSection::new("controller", "Controller Identification")
            .with_number("Art. 30(1)(a)")
            .with_field(
                DocumentField::new("controller_name", FieldType::Text, true)
                    .with_value(&self.controller.name),
            )
            .with_field(
                DocumentField::new("controller_address", FieldType::Text, true)
                    .with_value(&self.controller.address),
            )
            .with_field(
                DocumentField::new("controller_contact", FieldType::Text, true)
                    .with_value(&self.controller.contact),
            );
        if let Some(dpo) = &self.dpo_contact {
            s1 = s1.with_field(
                DocumentField::new("dpo_contact", FieldType::Text, false)
                    .with_value(dpo),
            );
        }
        s1 = s1.with_status(ComplianceStatus::Compliant);
        doc.sections.push(s1);

        // Section 2: Purposes of processing
        let mut s2 = DocumentSection::new("purposes", "Purposes of Processing")
            .with_number("Art. 30(1)(b)");
        for activity in &self.activities {
            s2 = s2.with_subsection(
                DocumentSection::new(&activity.id, &activity.name)
                    .with_content(format!(
                        "Purpose: {}. Legal basis: {}.",
                        activity.purpose, activity.legal_basis
                    ))
                    .with_field(
                        DocumentField::new("purpose", FieldType::Text, true)
                            .with_value(&activity.purpose),
                    )
                    .with_field(
                        DocumentField::new("legal_basis", FieldType::Text, true)
                            .with_value(&activity.legal_basis),
                    ),
            );
        }
        let purpose_status = if self.activities.iter().all(|a| !a.purpose.is_empty() && !a.legal_basis.is_empty()) {
            ComplianceStatus::Compliant
        } else if self.activities.iter().any(|a| a.legal_basis.is_empty()) {
            ComplianceStatus::NonCompliant { reason: "missing legal basis".into() }
        } else {
            ComplianceStatus::PartiallyCompliant { gaps: vec!["incomplete purposes".into()] }
        };
        s2 = s2.with_status(purpose_status);
        doc.sections.push(s2);

        // Section 3: Categories of data subjects and personal data
        let mut s3 = DocumentSection::new("data-categories", "Categories of Data Subjects and Personal Data")
            .with_number("Art. 30(1)(c)");
        for activity in &self.activities {
            let cats = activity.data_categories.join(", ");
            let subs = activity.data_subjects.join(", ");
            s3 = s3.with_subsection(
                DocumentSection::new(format!("{}-data", activity.id), &activity.name)
                    .with_content(format!("Data categories: {cats}. Data subjects: {subs}.")),
            );
        }
        doc.sections.push(s3);

        // Section 4: Recipients
        let s4 = DocumentSection::new("recipients", "Recipients")
            .with_number("Art. 30(1)(d)")
            .with_content(
                self.activities
                    .iter()
                    .flat_map(|a| a.recipients.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        doc.sections.push(s4);

        // Section 5: International transfers
        let mut s5 = DocumentSection::new("transfers", "International Transfers")
            .with_number("Art. 30(1)(e)");
        for activity in &self.activities {
            for transfer in &activity.international_transfers {
                s5 = s5.with_subsection(
                    DocumentSection::new(
                        format!("transfer-{}", transfer.destination_country),
                        format!("Transfer to {}", transfer.destination_country),
                    )
                    .with_content(format!(
                        "Legal basis: {}. Safeguards: {}.",
                        transfer.legal_basis,
                        transfer.safeguards.join(", ")
                    )),
                );
            }
        }
        doc.sections.push(s5);

        // Section 6: Retention periods
        let s6 = DocumentSection::new("retention", "Retention Periods")
            .with_number("Art. 30(1)(f)")
            .with_content(
                self.activities
                    .iter()
                    .map(|a| format!("{}: {}", a.name, a.retention_period))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        doc.sections.push(s6);

        // Section 7: Security measures
        let s7 = DocumentSection::new("security", "Technical and Organizational Security Measures")
            .with_number("Art. 30(1)(g)")
            .with_content(
                self.activities
                    .iter()
                    .flat_map(|a| a.security_measures.iter())
                    .cloned()
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        doc.sections.push(s7);

        doc
    }

    pub fn validate(&self) -> Vec<GdprGap> {
        let mut gaps = Vec::new();
        if self.controller.name.is_empty() {
            gaps.push(GdprGap {
                article: "Art. 30(1)(a)".into(),
                requirement: "Controller name".into(),
                current_state: "Missing".into(),
                recommendation: "Provide controller name".into(),
            });
        }
        for activity in &self.activities {
            if activity.purpose.is_empty() {
                gaps.push(GdprGap {
                    article: "Art. 30(1)(b)".into(),
                    requirement: format!("Purpose for activity '{}'", activity.name),
                    current_state: "Missing".into(),
                    recommendation: "Document the purpose of processing".into(),
                });
            }
            if activity.legal_basis.is_empty() {
                gaps.push(GdprGap {
                    article: "Art. 30(1)(b)".into(),
                    requirement: format!("Legal basis for activity '{}'", activity.name),
                    current_state: "Missing".into(),
                    recommendation: "Identify the legal basis under Art. 6".into(),
                });
            }
            if activity.data_categories.is_empty() {
                gaps.push(GdprGap {
                    article: "Art. 30(1)(c)".into(),
                    requirement: format!("Data categories for activity '{}'", activity.name),
                    current_state: "Missing".into(),
                    recommendation: "List categories of personal data processed".into(),
                });
            }
            if activity.retention_period.is_empty() {
                gaps.push(GdprGap {
                    article: "Art. 30(1)(f)".into(),
                    requirement: format!("Retention period for activity '{}'", activity.name),
                    current_state: "Missing".into(),
                    recommendation: "Define retention periods or criteria".into(),
                });
            }
        }
        gaps
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> ControllerInfo {
        ControllerInfo::new("Acme Corp", "123 Main St", "dpo@acme.com")
    }

    fn full_activity() -> ProcessingActivity {
        ProcessingActivity::new("pa1", "User Analytics", "Marketing analysis", "Consent (Art. 6(1)(a))")
            .with_data_category("Email")
            .with_data_category("Usage data")
            .with_data_subject("Customers")
            .with_recipient("Marketing dept")
            .with_retention("2 years")
            .with_security_measure("Encryption at rest")
    }

    #[test]
    fn test_builder_constructs_valid_record() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(full_activity());
        let doc = builder.build(1000);
        assert_eq!(doc.document_type, DocumentType::RecordOfProcessing);
        assert_eq!(doc.framework, ComplianceFramework::GdprEu);
    }

    #[test]
    fn test_build_produces_seven_sections() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(full_activity());
        let doc = builder.build(1000);
        assert_eq!(doc.sections.len(), 7);
    }

    #[test]
    fn test_section_titles_match_art30() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(full_activity());
        let doc = builder.build(1000);
        assert_eq!(doc.sections[0].title, "Controller Identification");
        assert_eq!(doc.sections[1].title, "Purposes of Processing");
        assert_eq!(doc.sections[2].title, "Categories of Data Subjects and Personal Data");
        assert_eq!(doc.sections[3].title, "Recipients");
        assert_eq!(doc.sections[4].title, "International Transfers");
        assert_eq!(doc.sections[5].title, "Retention Periods");
        assert_eq!(doc.sections[6].title, "Technical and Organizational Security Measures");
    }

    #[test]
    fn test_full_activity_compliant() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(full_activity());
        let doc = builder.build(1000);
        assert_eq!(
            doc.sections[1].compliance_status,
            Some(ComplianceStatus::Compliant)
        );
    }

    #[test]
    fn test_missing_legal_basis_noncompliant() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(ProcessingActivity::new("pa1", "Analytics", "Marketing", ""));
        let doc = builder.build(1000);
        assert!(matches!(
            doc.sections[1].compliance_status,
            Some(ComplianceStatus::NonCompliant { .. })
        ));
    }

    #[test]
    fn test_validate_identifies_gaps() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(ProcessingActivity::new("pa1", "Analytics", "", ""));
        let gaps = builder.validate();
        assert!(gaps.len() >= 2); // missing purpose + missing legal basis + more
    }

    #[test]
    fn test_international_transfer_section() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(
            full_activity().with_transfer(InternationalTransfer {
                destination_country: "US".into(),
                legal_basis: "SCCs".into(),
                safeguards: vec!["Standard Contractual Clauses".into()],
            }),
        );
        let doc = builder.build(1000);
        assert_eq!(doc.sections[4].subsections.len(), 1);
    }

    #[test]
    fn test_dpo_contact_included() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.dpo("dpo@acme.com");
        builder.add_activity(full_activity());
        let doc = builder.build(1000);
        let dpo_field = doc.sections[0]
            .fields
            .iter()
            .find(|f| f.name == "dpo_contact");
        assert!(dpo_field.is_some());
    }

    #[test]
    fn test_multiple_activities_multiple_subsections() {
        let mut builder = GdprDocumentBuilder::new(controller());
        builder.add_activity(full_activity());
        builder.add_activity(
            ProcessingActivity::new("pa2", "HR Processing", "Employment", "Contract (Art. 6(1)(b))")
                .with_data_category("Name")
                .with_data_subject("Employees")
                .with_retention("7 years"),
        );
        let doc = builder.build(1000);
        assert_eq!(doc.sections[1].subsections.len(), 2);
    }

    #[test]
    fn test_empty_builder_controller_only() {
        let builder = GdprDocumentBuilder::new(controller());
        let doc = builder.build(1000);
        assert_eq!(doc.sections.len(), 7);
        assert!(doc.sections[1].subsections.is_empty());
    }
}
