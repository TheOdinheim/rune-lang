// ═══════════════════════════════════════════════════════════════════════
// Template — reusable document templates and section definitions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::document::*;

// ── TemplateFieldDef ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TemplateFieldDef {
    pub name: String,
    pub description: String,
    pub field_type: FieldType,
    pub required: bool,
    pub default_value: Option<String>,
    pub guidance: Option<String>,
}

impl TemplateFieldDef {
    pub fn new(
        name: impl Into<String>,
        field_type: FieldType,
        required: bool,
    ) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            field_type,
            required,
            default_value: None,
            guidance: None,
        }
    }

    pub fn with_guidance(mut self, guidance: impl Into<String>) -> Self {
        self.guidance = Some(guidance.into());
        self
    }
}

// ── TemplateSectionDef ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TemplateSectionDef {
    pub id: String,
    pub title: String,
    pub description: String,
    pub required: bool,
    pub fields: Vec<TemplateFieldDef>,
    pub subsections: Vec<TemplateSectionDef>,
}

impl TemplateSectionDef {
    pub fn new(id: impl Into<String>, title: impl Into<String>, required: bool) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            required,
            fields: Vec::new(),
            subsections: Vec::new(),
        }
    }

    pub fn with_field(mut self, field: TemplateFieldDef) -> Self {
        self.fields.push(field);
        self
    }

    pub fn with_subsection(mut self, sub: TemplateSectionDef) -> Self {
        self.subsections.push(sub);
        self
    }
}

// ── DocumentTemplate ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DocumentTemplate {
    pub id: String,
    pub name: String,
    pub framework: ComplianceFramework,
    pub document_type: DocumentType,
    pub sections: Vec<TemplateSectionDef>,
    pub description: String,
}

impl DocumentTemplate {
    pub fn gdpr_article30() -> Self {
        Self {
            id: "gdpr-art30".into(),
            name: "GDPR Article 30 Record of Processing".into(),
            framework: ComplianceFramework::GdprEu,
            document_type: DocumentType::RecordOfProcessing,
            description: "Record of processing activities per GDPR Article 30".into(),
            sections: vec![
                TemplateSectionDef::new("controller", "Controller Identification", true)
                    .with_field(TemplateFieldDef::new("controller_name", FieldType::Text, true)),
                TemplateSectionDef::new("purposes", "Purposes of Processing", true)
                    .with_field(TemplateFieldDef::new("purpose", FieldType::Text, true))
                    .with_field(TemplateFieldDef::new("legal_basis", FieldType::Text, true)),
                TemplateSectionDef::new("data-categories", "Data Categories", true),
                TemplateSectionDef::new("recipients", "Recipients", true),
                TemplateSectionDef::new("transfers", "International Transfers", false),
                TemplateSectionDef::new("retention", "Retention Periods", true),
                TemplateSectionDef::new("security", "Security Measures", true),
            ],
        }
    }

    pub fn nist_ai_rmf() -> Self {
        Self {
            id: "nist-ai-rmf".into(),
            name: "NIST AI RMF Profile".into(),
            framework: ComplianceFramework::NistAiRmf,
            document_type: DocumentType::RiskManagementProfile,
            description: "NIST AI Risk Management Framework profile".into(),
            sections: vec![
                TemplateSectionDef::new("executive-summary", "Executive Summary", true),
                TemplateSectionDef::new("govern", "GOVERN Function", true),
                TemplateSectionDef::new("map", "MAP Function", true),
                TemplateSectionDef::new("measure", "MEASURE Function", true),
                TemplateSectionDef::new("manage", "MANAGE Function", true),
            ],
        }
    }

    pub fn cmmc_assessment() -> Self {
        Self {
            id: "cmmc-assessment".into(),
            name: "CMMC Assessment".into(),
            framework: ComplianceFramework::Cmmc,
            document_type: DocumentType::MaturityAssessment,
            description: "CMMC maturity level assessment".into(),
            sections: vec![
                TemplateSectionDef::new("executive-summary", "Executive Summary", true),
                TemplateSectionDef::new("domains", "Domain Assessments", true),
                TemplateSectionDef::new("gap-analysis", "Gap Analysis", true),
                TemplateSectionDef::new("remediation", "Remediation Roadmap", true),
            ],
        }
    }

    pub fn dpia() -> Self {
        Self {
            id: "dpia".into(),
            name: "Data Protection Impact Assessment".into(),
            framework: ComplianceFramework::GdprEu,
            document_type: DocumentType::DataProtectionImpactAssessment,
            description: "DPIA per GDPR Article 35".into(),
            sections: vec![
                TemplateSectionDef::new("project", "Project Description", true),
                TemplateSectionDef::new("necessity", "Necessity Assessment", true),
                TemplateSectionDef::new("data-flows", "Data Flows", true),
                TemplateSectionDef::new("risks", "Risk Assessment", true),
                TemplateSectionDef::new("mitigations", "Mitigations", true),
                TemplateSectionDef::new("consultation", "Consultation", false),
                TemplateSectionDef::new("decision", "Decision", true),
            ],
        }
    }

    pub fn ssp() -> Self {
        Self {
            id: "ssp".into(),
            name: "System Security Plan".into(),
            framework: ComplianceFramework::FedRamp,
            document_type: DocumentType::SystemSecurityPlan,
            description: "System Security Plan per NIST SP 800-18".into(),
            sections: vec![
                TemplateSectionDef::new("system-id", "System Identification", true),
                TemplateSectionDef::new("categorization", "System Categorization", true),
                TemplateSectionDef::new("boundary", "Authorization Boundary", true),
                TemplateSectionDef::new("controls", "Security Controls", true),
                TemplateSectionDef::new("summary", "Implementation Summary", true),
            ],
        }
    }
}

// ── TemplateRegistry ────────────────────────────────────────────────

#[derive(Default)]
pub struct TemplateRegistry {
    templates: HashMap<String, DocumentTemplate>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, template: DocumentTemplate) {
        self.templates.insert(template.id.clone(), template);
    }

    pub fn get(&self, id: &str) -> Option<&DocumentTemplate> {
        self.templates.get(id)
    }

    pub fn by_framework(&self, framework: &ComplianceFramework) -> Vec<&DocumentTemplate> {
        self.templates
            .values()
            .filter(|t| &t.framework == framework)
            .collect()
    }

    pub fn by_type(&self, doc_type: &DocumentType) -> Vec<&DocumentTemplate> {
        self.templates
            .values()
            .filter(|t| &t.document_type == doc_type)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.templates.len()
    }
}

// ── instantiate_template ────────────────────────────────────────────

pub fn instantiate_template(
    template: &DocumentTemplate,
    now: i64,
    author: &str,
) -> Document {
    let mut doc = Document::new(
        DocumentId::new(format!("{}-{now}", template.id)),
        &template.name,
        template.document_type.clone(),
        template.framework.clone(),
        author,
        now,
    );

    for section_def in &template.sections {
        doc.sections.push(instantiate_section(section_def));
    }

    doc
}

fn instantiate_section(def: &TemplateSectionDef) -> DocumentSection {
    let mut section = DocumentSection::new(&def.id, &def.title);
    for field_def in &def.fields {
        let mut field = DocumentField::new(&field_def.name, field_def.field_type.clone(), field_def.required);
        if let Some(default) = &field_def.default_value {
            field = field.with_value(default);
        }
        section = section.with_field(field);
    }
    for sub_def in &def.subsections {
        section = section.with_subsection(instantiate_section(sub_def));
    }
    if def.required {
        section = section.with_status(ComplianceStatus::NotAssessed);
    }
    section
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdpr_article30_template() {
        let t = DocumentTemplate::gdpr_article30();
        assert_eq!(t.framework, ComplianceFramework::GdprEu);
        assert_eq!(t.document_type, DocumentType::RecordOfProcessing);
        assert_eq!(t.sections.len(), 7);
    }

    #[test]
    fn test_nist_ai_rmf_template() {
        let t = DocumentTemplate::nist_ai_rmf();
        assert_eq!(t.framework, ComplianceFramework::NistAiRmf);
        assert_eq!(t.sections.len(), 5);
    }

    #[test]
    fn test_cmmc_assessment_template() {
        let t = DocumentTemplate::cmmc_assessment();
        assert_eq!(t.framework, ComplianceFramework::Cmmc);
        assert_eq!(t.sections.len(), 4);
    }

    #[test]
    fn test_dpia_template() {
        let t = DocumentTemplate::dpia();
        assert_eq!(t.framework, ComplianceFramework::GdprEu);
        assert_eq!(t.sections.len(), 7);
    }

    #[test]
    fn test_ssp_template() {
        let t = DocumentTemplate::ssp();
        assert_eq!(t.framework, ComplianceFramework::FedRamp);
        assert_eq!(t.sections.len(), 5);
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = TemplateRegistry::new();
        reg.register(DocumentTemplate::gdpr_article30());
        assert!(reg.get("gdpr-art30").is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_registry_by_framework() {
        let mut reg = TemplateRegistry::new();
        reg.register(DocumentTemplate::gdpr_article30());
        reg.register(DocumentTemplate::nist_ai_rmf());
        assert_eq!(reg.by_framework(&ComplianceFramework::GdprEu).len(), 1);
    }

    #[test]
    fn test_registry_by_type() {
        let mut reg = TemplateRegistry::new();
        reg.register(DocumentTemplate::gdpr_article30());
        reg.register(DocumentTemplate::ssp());
        assert_eq!(reg.by_type(&DocumentType::RecordOfProcessing).len(), 1);
        assert_eq!(reg.by_type(&DocumentType::SystemSecurityPlan).len(), 1);
    }

    #[test]
    fn test_instantiate_template() {
        let t = DocumentTemplate::gdpr_article30();
        let doc = instantiate_template(&t, 1000, "author");
        assert_eq!(doc.document_type, DocumentType::RecordOfProcessing);
        assert_eq!(doc.sections.len(), 7);
    }

    #[test]
    fn test_instantiated_document_section_structure() {
        let t = DocumentTemplate::gdpr_article30();
        let doc = instantiate_template(&t, 1000, "author");
        // Controller section has required fields
        assert!(!doc.sections[0].fields.is_empty());
        // Required sections get NotAssessed status
        assert_eq!(
            doc.sections[0].compliance_status,
            Some(ComplianceStatus::NotAssessed)
        );
    }
}
