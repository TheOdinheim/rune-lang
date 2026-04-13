// ═══════════════════════════════════════════════════════════════════════
// NIST — AI Risk Management Framework profile generation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::document::*;

// ── MaturityLevel ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MaturityLevel {
    NotImplemented = 0,
    Initial = 1,
    Developing = 2,
    Defined = 3,
    Managed = 4,
    Optimizing = 5,
}

impl fmt::Display for MaturityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => f.write_str("not-implemented"),
            Self::Initial => f.write_str("initial"),
            Self::Developing => f.write_str("developing"),
            Self::Defined => f.write_str("defined"),
            Self::Managed => f.write_str("managed"),
            Self::Optimizing => f.write_str("optimizing"),
        }
    }
}

// ── ProfileType ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileType {
    Current,
    Target,
    Gap,
}

impl fmt::Display for ProfileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => f.write_str("current"),
            Self::Target => f.write_str("target"),
            Self::Gap => f.write_str("gap"),
        }
    }
}

// ── NistSubcategory ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NistSubcategory {
    pub id: String,
    pub description: String,
    pub current_state: String,
    pub target_state: Option<String>,
    pub gap: Option<String>,
    pub maturity: MaturityLevel,
    pub evidence: Vec<String>,
    pub controls: Vec<String>,
}

impl NistSubcategory {
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            current_state: String::new(),
            target_state: None,
            gap: None,
            maturity: MaturityLevel::NotImplemented,
            evidence: Vec::new(),
            controls: Vec::new(),
        }
    }

    pub fn with_maturity(mut self, m: MaturityLevel) -> Self {
        self.maturity = m;
        self
    }
}

// ── NistCategory ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NistCategory {
    pub id: String,
    pub name: String,
    pub subcategories: Vec<NistSubcategory>,
    pub maturity: MaturityLevel,
}

impl NistCategory {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            subcategories: Vec::new(),
            maturity: MaturityLevel::NotImplemented,
        }
    }

    pub fn with_subcategory(mut self, sub: NistSubcategory) -> Self {
        self.subcategories.push(sub);
        self
    }
}

// ── NistFunction ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NistFunction {
    pub id: String,
    pub name: String,
    pub categories: Vec<NistCategory>,
    pub maturity: MaturityLevel,
}

impl NistFunction {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            categories: Vec::new(),
            maturity: MaturityLevel::NotImplemented,
        }
    }

    pub fn with_category(mut self, cat: NistCategory) -> Self {
        self.categories.push(cat);
        self
    }

    pub fn with_maturity(mut self, m: MaturityLevel) -> Self {
        self.maturity = m;
        self
    }
}

// ── NistAiRmfProfile ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NistAiRmfProfile {
    pub organization: String,
    pub profile_type: ProfileType,
    pub functions: Vec<NistFunction>,
    pub overall_maturity: MaturityLevel,
    pub generated_at: i64,
    pub assessed_by: String,
}

// ── NistDocumentBuilder ─────────────────────────────────────────────

pub struct NistDocumentBuilder {
    organization: String,
    profile_type: ProfileType,
    functions: Vec<NistFunction>,
    assessed_by: String,
}

impl NistDocumentBuilder {
    pub fn new(organization: &str, profile_type: ProfileType) -> Self {
        Self {
            organization: organization.into(),
            profile_type,
            functions: Vec::new(),
            assessed_by: "system".into(),
        }
    }

    pub fn add_function(&mut self, function: NistFunction) -> &mut Self {
        self.functions.push(function);
        self
    }

    pub fn assess_maturity(&self) -> MaturityLevel {
        self.functions
            .iter()
            .map(|f| f.maturity)
            .min()
            .unwrap_or(MaturityLevel::NotImplemented)
    }

    pub fn build(&self, now: i64) -> Document {
        let overall = self.assess_maturity();

        let mut doc = Document::new(
            DocumentId::new(format!("nist-ai-rmf-{now}")),
            format!("NIST AI RMF {} Profile — {}", self.profile_type, self.organization),
            DocumentType::RiskManagementProfile,
            ComplianceFramework::NistAiRmf,
            &self.assessed_by,
            now,
        );

        // Executive summary
        doc.sections.push(
            DocumentSection::new("executive-summary", "Executive Summary")
                .with_content(format!(
                    "Organization: {}. Profile type: {}. Overall maturity: {}.",
                    self.organization, self.profile_type, overall
                )),
        );

        // One section per function
        for func in &self.functions {
            let mut section = DocumentSection::new(&func.id, &func.name)
                .with_content(format!("Maturity: {}", func.maturity));
            for cat in &func.categories {
                let mut cat_section = DocumentSection::new(&cat.id, &cat.name);
                for sub in &cat.subcategories {
                    cat_section = cat_section.with_subsection(
                        DocumentSection::new(&sub.id, &sub.description)
                            .with_content(format!("Maturity: {}", sub.maturity)),
                    );
                }
                section = section.with_subsection(cat_section);
            }
            doc.sections.push(section);
        }

        // Gap analysis section for Gap profiles
        if self.profile_type == ProfileType::Gap {
            doc.sections.push(
                DocumentSection::new("gap-analysis", "Gap Analysis")
                    .with_content("Gap analysis between current and target profiles."),
            );
        }

        doc
    }

    pub fn ai_rmf_skeleton() -> Self {
        let govern = NistFunction::new("GOVERN", "Govern")
            .with_category(NistCategory::new("GOVERN-1", "Governance Policies"))
            .with_category(NistCategory::new("GOVERN-2", "Accountability Structures"))
            .with_category(NistCategory::new("GOVERN-3", "Workforce Diversity"))
            .with_category(NistCategory::new("GOVERN-4", "Organizational Culture"))
            .with_category(NistCategory::new("GOVERN-5", "Stakeholder Engagement"))
            .with_category(NistCategory::new("GOVERN-6", "Policies and Procedures"));

        let map = NistFunction::new("MAP", "Map")
            .with_category(NistCategory::new("MAP-1", "Context Establishment"))
            .with_category(NistCategory::new("MAP-2", "Categorization"))
            .with_category(NistCategory::new("MAP-3", "Benefit-Cost Analysis"))
            .with_category(NistCategory::new("MAP-4", "Risk Identification"))
            .with_category(NistCategory::new("MAP-5", "Impact Characterization"));

        let measure = NistFunction::new("MEASURE", "Measure")
            .with_category(NistCategory::new("MEASURE-1", "Risk Metrics"))
            .with_category(NistCategory::new("MEASURE-2", "Evaluation Methods"))
            .with_category(NistCategory::new("MEASURE-3", "Tracking"))
            .with_category(NistCategory::new("MEASURE-4", "Feedback"));

        let manage = NistFunction::new("MANAGE", "Manage")
            .with_category(NistCategory::new("MANAGE-1", "Risk Response"))
            .with_category(NistCategory::new("MANAGE-2", "Risk Treatment"))
            .with_category(NistCategory::new("MANAGE-3", "Communication"))
            .with_category(NistCategory::new("MANAGE-4", "Monitoring"));

        let mut builder = Self::new("Organization", ProfileType::Current);
        builder.add_function(govern);
        builder.add_function(map);
        builder.add_function(measure);
        builder.add_function(manage);
        builder
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_constructs_valid_profile() {
        let mut builder = NistDocumentBuilder::new("Acme", ProfileType::Current);
        builder.add_function(
            NistFunction::new("GOVERN", "Govern").with_maturity(MaturityLevel::Defined),
        );
        let doc = builder.build(1000);
        assert_eq!(doc.document_type, DocumentType::RiskManagementProfile);
        assert_eq!(doc.framework, ComplianceFramework::NistAiRmf);
    }

    #[test]
    fn test_build_produces_function_sections() {
        let mut builder = NistDocumentBuilder::new("Acme", ProfileType::Current);
        builder.add_function(NistFunction::new("GOVERN", "Govern"));
        builder.add_function(NistFunction::new("MAP", "Map"));
        let doc = builder.build(1000);
        // Executive Summary + GOVERN + MAP = 3
        assert_eq!(doc.sections.len(), 3);
    }

    #[test]
    fn test_ai_rmf_skeleton_has_four_functions() {
        let builder = NistDocumentBuilder::ai_rmf_skeleton();
        assert_eq!(builder.functions.len(), 4);
        assert_eq!(builder.functions[0].id, "GOVERN");
        assert_eq!(builder.functions[1].id, "MAP");
        assert_eq!(builder.functions[2].id, "MEASURE");
        assert_eq!(builder.functions[3].id, "MANAGE");
    }

    #[test]
    fn test_maturity_level_ordering() {
        assert!(MaturityLevel::NotImplemented < MaturityLevel::Initial);
        assert!(MaturityLevel::Initial < MaturityLevel::Developing);
        assert!(MaturityLevel::Developing < MaturityLevel::Defined);
        assert!(MaturityLevel::Defined < MaturityLevel::Managed);
        assert!(MaturityLevel::Managed < MaturityLevel::Optimizing);
    }

    #[test]
    fn test_assess_maturity_returns_minimum() {
        let mut builder = NistDocumentBuilder::new("Acme", ProfileType::Current);
        builder.add_function(NistFunction::new("GOVERN", "Govern").with_maturity(MaturityLevel::Managed));
        builder.add_function(NistFunction::new("MAP", "Map").with_maturity(MaturityLevel::Initial));
        assert_eq!(builder.assess_maturity(), MaturityLevel::Initial);
    }

    #[test]
    fn test_profile_types() {
        assert_eq!(ProfileType::Current.to_string(), "current");
        assert_eq!(ProfileType::Target.to_string(), "target");
        assert_eq!(ProfileType::Gap.to_string(), "gap");
    }

    #[test]
    fn test_subcategory_with_evidence() {
        let sub = NistSubcategory::new("GOVERN-1.1", "Policy exists")
            .with_maturity(MaturityLevel::Defined);
        assert_eq!(sub.maturity, MaturityLevel::Defined);
    }

    #[test]
    fn test_empty_function_still_produces_section() {
        let mut builder = NistDocumentBuilder::new("Acme", ProfileType::Current);
        builder.add_function(NistFunction::new("GOVERN", "Govern"));
        let doc = builder.build(1000);
        assert_eq!(doc.sections.len(), 2); // exec summary + GOVERN
    }
}
