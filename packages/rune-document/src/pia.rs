// ═══════════════════════════════════════════════════════════════════════
// PIA — Privacy Impact Assessment / DPIA document generation.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::document::*;

// ── RiskLevel ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    VeryHigh = 3,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::VeryHigh => f.write_str("very-high"),
        }
    }
}

// ── PiaDataFlow ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiaDataFlow {
    pub description: String,
    pub data_types: Vec<String>,
    pub purpose: String,
    pub legal_basis: String,
    pub recipients: Vec<String>,
    pub retention: String,
    pub cross_border: bool,
}

impl PiaDataFlow {
    pub fn new(
        description: impl Into<String>,
        purpose: impl Into<String>,
        legal_basis: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            data_types: Vec::new(),
            purpose: purpose.into(),
            legal_basis: legal_basis.into(),
            recipients: Vec::new(),
            retention: String::new(),
            cross_border: false,
        }
    }

    pub fn with_data_type(mut self, dt: impl Into<String>) -> Self {
        self.data_types.push(dt.into());
        self
    }
}

// ── PiaRisk ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiaRisk {
    pub id: String,
    pub description: String,
    pub likelihood: RiskLevel,
    pub impact: RiskLevel,
    pub residual_risk: RiskLevel,
    pub affected_rights: Vec<String>,
}

impl PiaRisk {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        likelihood: RiskLevel,
        impact: RiskLevel,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            likelihood,
            impact,
            residual_risk: std::cmp::max(likelihood, impact),
            affected_rights: Vec::new(),
        }
    }

    pub fn with_residual(mut self, level: RiskLevel) -> Self {
        self.residual_risk = level;
        self
    }

    pub fn with_affected_right(mut self, right: impl Into<String>) -> Self {
        self.affected_rights.push(right.into());
        self
    }
}

// ── PiaMitigation ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiaMitigation {
    pub risk_id: String,
    pub description: String,
    pub implemented: bool,
    pub effectiveness: RiskLevel,
}

impl PiaMitigation {
    pub fn new(
        risk_id: impl Into<String>,
        description: impl Into<String>,
        effectiveness: RiskLevel,
    ) -> Self {
        Self {
            risk_id: risk_id.into(),
            description: description.into(),
            implemented: false,
            effectiveness,
        }
    }

    pub fn implemented(mut self) -> Self {
        self.implemented = true;
        self
    }
}

// ── PiaConsultation ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiaConsultation {
    pub dpo_consulted: bool,
    pub dpo_opinion: Option<String>,
    pub supervisory_authority_consulted: bool,
    pub data_subjects_consulted: bool,
    pub consultation_summary: Option<String>,
}

impl PiaConsultation {
    pub fn new() -> Self {
        Self {
            dpo_consulted: false,
            dpo_opinion: None,
            supervisory_authority_consulted: false,
            data_subjects_consulted: false,
            consultation_summary: None,
        }
    }

    pub fn with_dpo(mut self, opinion: impl Into<String>) -> Self {
        self.dpo_consulted = true;
        self.dpo_opinion = Some(opinion.into());
        self
    }
}

impl Default for PiaConsultation {
    fn default() -> Self {
        Self::new()
    }
}

// ── NecessityAssessment ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NecessityAssessment {
    pub is_necessary: bool,
    pub proportionality: String,
    pub alternatives_considered: Vec<String>,
    pub chosen_justification: String,
}

impl NecessityAssessment {
    pub fn new(is_necessary: bool, proportionality: impl Into<String>) -> Self {
        Self {
            is_necessary,
            proportionality: proportionality.into(),
            alternatives_considered: Vec::new(),
            chosen_justification: String::new(),
        }
    }
}

// ── PiaDocument ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PiaDocument {
    pub project_name: String,
    pub project_description: String,
    pub data_flows: Vec<PiaDataFlow>,
    pub risks: Vec<PiaRisk>,
    pub mitigations: Vec<PiaMitigation>,
    pub consultation: Option<PiaConsultation>,
    pub necessity_assessment: NecessityAssessment,
    pub generated_at: i64,
    pub assessor: String,
}

// ── PiaDocumentBuilder ──────────────────────────────────────────────

pub struct PiaDocumentBuilder {
    project_name: String,
    project_description: String,
    data_flows: Vec<PiaDataFlow>,
    risks: Vec<PiaRisk>,
    mitigations: Vec<PiaMitigation>,
    consultation: Option<PiaConsultation>,
    necessity: Option<NecessityAssessment>,
    assessor: String,
}

impl PiaDocumentBuilder {
    pub fn new(project: &str, assessor: &str) -> Self {
        Self {
            project_name: project.into(),
            project_description: String::new(),
            data_flows: Vec::new(),
            risks: Vec::new(),
            mitigations: Vec::new(),
            consultation: None,
            necessity: None,
            assessor: assessor.into(),
        }
    }

    pub fn description(&mut self, desc: &str) -> &mut Self {
        self.project_description = desc.into();
        self
    }

    pub fn add_data_flow(&mut self, flow: PiaDataFlow) -> &mut Self {
        self.data_flows.push(flow);
        self
    }

    pub fn add_risk(&mut self, risk: PiaRisk) -> &mut Self {
        self.risks.push(risk);
        self
    }

    pub fn add_mitigation(&mut self, mitigation: PiaMitigation) -> &mut Self {
        self.mitigations.push(mitigation);
        self
    }

    pub fn consultation(&mut self, consultation: PiaConsultation) -> &mut Self {
        self.consultation = Some(consultation);
        self
    }

    pub fn necessity(&mut self, assessment: NecessityAssessment) -> &mut Self {
        self.necessity = Some(assessment);
        self
    }

    pub fn risk_matrix(&self) -> Vec<(String, RiskLevel, RiskLevel)> {
        self.risks
            .iter()
            .map(|r| (r.id.clone(), r.likelihood, r.impact))
            .collect()
    }

    pub fn high_risks(&self) -> Vec<&PiaRisk> {
        self.risks
            .iter()
            .filter(|r| r.residual_risk >= RiskLevel::High)
            .collect()
    }

    pub fn build(&self, now: i64) -> Document {
        let mut doc = Document::new(
            DocumentId::new(format!("pia-{now}")),
            format!("Privacy Impact Assessment — {}", self.project_name),
            DocumentType::PrivacyImpactAssessment,
            ComplianceFramework::GdprEu,
            &self.assessor,
            now,
        );

        // Section 1: Project description
        doc.sections.push(
            DocumentSection::new("project", "Project Description and Scope")
                .with_content(if self.project_description.is_empty() {
                    self.project_name.clone()
                } else {
                    self.project_description.clone()
                }),
        );

        // Section 2: Necessity and proportionality
        let necessity_content = if let Some(n) = &self.necessity {
            format!(
                "Necessary: {}. Proportionality: {}. Alternatives considered: {}.",
                if n.is_necessary { "Yes" } else { "No" },
                n.proportionality,
                if n.alternatives_considered.is_empty() {
                    "None".to_string()
                } else {
                    n.alternatives_considered.join(", ")
                }
            )
        } else {
            "Not assessed.".into()
        };
        doc.sections.push(
            DocumentSection::new("necessity", "Necessity and Proportionality Assessment")
                .with_content(necessity_content),
        );

        // Section 3: Data flows
        let mut s3 = DocumentSection::new("data-flows", "Data Flow Descriptions");
        for (i, flow) in self.data_flows.iter().enumerate() {
            s3 = s3.with_subsection(
                DocumentSection::new(format!("flow-{i}"), &flow.description)
                    .with_content(format!(
                        "Purpose: {}. Legal basis: {}. Data types: {}. Cross-border: {}.",
                        flow.purpose,
                        flow.legal_basis,
                        flow.data_types.join(", "),
                        if flow.cross_border { "Yes" } else { "No" }
                    )),
            );
        }
        doc.sections.push(s3);

        // Section 4: Risk assessment
        let mut s4 = DocumentSection::new("risks", "Risk Assessment");
        for risk in &self.risks {
            s4 = s4.with_subsection(
                DocumentSection::new(&risk.id, &risk.description)
                    .with_content(format!(
                        "Likelihood: {}. Impact: {}. Residual: {}. Affected rights: {}.",
                        risk.likelihood,
                        risk.impact,
                        risk.residual_risk,
                        risk.affected_rights.join(", ")
                    )),
            );
        }
        doc.sections.push(s4);

        // Section 5: Mitigations
        let mut s5 = DocumentSection::new("mitigations", "Mitigations and Residual Risks");
        for mit in &self.mitigations {
            s5 = s5.with_subsection(
                DocumentSection::new(format!("mit-{}", mit.risk_id), &mit.description)
                    .with_content(format!(
                        "For risk: {}. Implemented: {}. Effectiveness: {}.",
                        mit.risk_id,
                        if mit.implemented { "Yes" } else { "No" },
                        mit.effectiveness
                    )),
            );
        }
        doc.sections.push(s5);

        // Section 6: Consultation
        let consult_content = if let Some(c) = &self.consultation {
            format!(
                "DPO consulted: {}. Supervisory authority: {}. Data subjects: {}. {}",
                if c.dpo_consulted { "Yes" } else { "No" },
                if c.supervisory_authority_consulted { "Yes" } else { "No" },
                if c.data_subjects_consulted { "Yes" } else { "No" },
                c.consultation_summary.as_deref().unwrap_or("")
            )
        } else {
            "No consultation recorded.".into()
        };
        doc.sections.push(
            DocumentSection::new("consultation", "Consultation Outcomes")
                .with_content(consult_content),
        );

        // Section 7: Decision
        let high = self.high_risks();
        let decision = if high.is_empty() {
            "No high residual risks identified. Processing may proceed.".into()
        } else {
            format!(
                "{} high/very-high residual risk(s) identified. Consider supervisory authority consultation (Art. 36).",
                high.len()
            )
        };
        doc.sections.push(
            DocumentSection::new("decision", "Decision and Recommendations")
                .with_content(decision),
        );

        doc
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_builder() -> PiaDocumentBuilder {
        let mut builder = PiaDocumentBuilder::new("AI Model Deployment", "privacy-team");
        builder.description("Deploying a model that processes user data");
        builder.add_data_flow(
            PiaDataFlow::new("User data collection", "Model training", "Consent")
                .with_data_type("Email")
                .with_data_type("Usage patterns"),
        );
        builder.add_risk(
            PiaRisk::new("R1", "Data breach risk", RiskLevel::Medium, RiskLevel::High)
                .with_residual(RiskLevel::Low)
                .with_affected_right("Right to erasure"),
        );
        builder.add_risk(
            PiaRisk::new("R2", "Re-identification risk", RiskLevel::High, RiskLevel::VeryHigh),
        );
        builder.add_mitigation(
            PiaMitigation::new("R1", "Encryption at rest", RiskLevel::Medium).implemented(),
        );
        builder.necessity(NecessityAssessment::new(true, "Essential for service delivery"));
        builder
    }

    #[test]
    fn test_builder_constructs_valid_assessment() {
        let builder = sample_builder();
        let doc = builder.build(1000);
        assert_eq!(doc.document_type, DocumentType::PrivacyImpactAssessment);
        assert_eq!(doc.framework, ComplianceFramework::GdprEu);
    }

    #[test]
    fn test_build_produces_seven_sections() {
        let builder = sample_builder();
        let doc = builder.build(1000);
        assert_eq!(doc.sections.len(), 7);
    }

    #[test]
    fn test_risk_matrix() {
        let builder = sample_builder();
        let matrix = builder.risk_matrix();
        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix[0].0, "R1");
    }

    #[test]
    fn test_high_risks() {
        let builder = sample_builder();
        let high = builder.high_risks();
        // R1 residual=Low (not high), R2 residual=VeryHigh (high)
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].id, "R2");
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::VeryHigh);
    }

    #[test]
    fn test_mitigation_reduces_residual() {
        let risk = PiaRisk::new("R1", "Test", RiskLevel::High, RiskLevel::High)
            .with_residual(RiskLevel::Low);
        assert_eq!(risk.residual_risk, RiskLevel::Low);
    }

    #[test]
    fn test_consultation_section() {
        let mut builder = sample_builder();
        builder.consultation(PiaConsultation::new().with_dpo("Approved with conditions"));
        let doc = builder.build(1000);
        let consult = &doc.sections[5];
        assert!(consult.content.contains("DPO consulted: Yes"));
    }

    #[test]
    fn test_necessity_section() {
        let builder = sample_builder();
        let doc = builder.build(1000);
        let necessity = &doc.sections[1];
        assert!(necessity.content.contains("Necessary: Yes"));
    }

    #[test]
    fn test_empty_risks() {
        let mut builder = PiaDocumentBuilder::new("Empty Project", "assessor");
        builder.description("No risks");
        let doc = builder.build(1000);
        assert_eq!(doc.sections.len(), 7);
        assert!(doc.sections[6].content.contains("No high residual risks"));
    }
}
