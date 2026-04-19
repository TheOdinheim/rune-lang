// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Explanation templates and formatting.
//
// ExplanationTemplate defines audience-targeted templates with typed
// sections. ExplanationRenderer produces plain-text, JSON, and summary
// output. Built-in templates cover technical, regulatory, and end-user
// audiences.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── ExplanationAudience ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplanationAudience {
    Technical,
    Business,
    Regulatory,
    EndUser,
}

impl fmt::Display for ExplanationAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Technical => f.write_str("technical"),
            Self::Business => f.write_str("business"),
            Self::Regulatory => f.write_str("regulatory"),
            Self::EndUser => f.write_str("end-user"),
        }
    }
}

// ── SectionContentType ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionContentType {
    DecisionSummary,
    FactorBreakdown,
    EvidenceListing,
    CounterfactualSuggestions,
    RegulatoryMapping,
    CustomText,
}

impl fmt::Display for SectionContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionSummary => f.write_str("decision-summary"),
            Self::FactorBreakdown => f.write_str("factor-breakdown"),
            Self::EvidenceListing => f.write_str("evidence-listing"),
            Self::CounterfactualSuggestions => f.write_str("counterfactual-suggestions"),
            Self::RegulatoryMapping => f.write_str("regulatory-mapping"),
            Self::CustomText => f.write_str("custom-text"),
        }
    }
}

// ── TemplateSection ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TemplateSection {
    pub title: String,
    pub content_type: SectionContentType,
    pub required: bool,
    pub content: String,
}

impl TemplateSection {
    pub fn new(
        title: impl Into<String>,
        content_type: SectionContentType,
        required: bool,
    ) -> Self {
        Self {
            title: title.into(),
            content_type,
            required,
            content: String::new(),
        }
    }

    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }
}

// ── ExplanationTemplate ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExplanationTemplate {
    pub name: String,
    pub audience: ExplanationAudience,
    pub sections: Vec<TemplateSection>,
    pub version: String,
}

impl ExplanationTemplate {
    pub fn new(
        name: impl Into<String>,
        audience: ExplanationAudience,
        version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            audience,
            sections: Vec::new(),
            version: version.into(),
        }
    }

    pub fn add_section(&mut self, section: TemplateSection) {
        self.sections.push(section);
    }

    pub fn with_section(mut self, section: TemplateSection) -> Self {
        self.sections.push(section);
        self
    }

    pub fn required_sections(&self) -> Vec<&TemplateSection> {
        self.sections.iter().filter(|s| s.required).collect()
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
}

// ── Built-in templates ──────────────────────────────────────────────

pub fn technical_template() -> ExplanationTemplate {
    ExplanationTemplate::new("Technical Explanation", ExplanationAudience::Technical, "1.0")
        .with_section(TemplateSection::new(
            "Decision Summary",
            SectionContentType::DecisionSummary,
            true,
        ))
        .with_section(TemplateSection::new(
            "Factor Analysis",
            SectionContentType::FactorBreakdown,
            true,
        ))
        .with_section(TemplateSection::new(
            "Evidence",
            SectionContentType::EvidenceListing,
            true,
        ))
        .with_section(TemplateSection::new(
            "Counterfactuals",
            SectionContentType::CounterfactualSuggestions,
            false,
        ))
}

pub fn regulatory_template() -> ExplanationTemplate {
    ExplanationTemplate::new("Regulatory Explanation", ExplanationAudience::Regulatory, "1.0")
        .with_section(TemplateSection::new(
            "Decision Summary",
            SectionContentType::DecisionSummary,
            true,
        ))
        .with_section(TemplateSection::new(
            "Factor Breakdown",
            SectionContentType::FactorBreakdown,
            true,
        ))
        .with_section(TemplateSection::new(
            "Evidence Listing",
            SectionContentType::EvidenceListing,
            true,
        ))
        .with_section(TemplateSection::new(
            "Regulatory Mapping",
            SectionContentType::RegulatoryMapping,
            true,
        ))
        .with_section(TemplateSection::new(
            "Counterfactual Analysis",
            SectionContentType::CounterfactualSuggestions,
            true,
        ))
}

pub fn end_user_template() -> ExplanationTemplate {
    ExplanationTemplate::new("End User Explanation", ExplanationAudience::EndUser, "1.0")
        .with_section(TemplateSection::new(
            "What happened",
            SectionContentType::DecisionSummary,
            true,
        ))
        .with_section(TemplateSection::new(
            "Why",
            SectionContentType::FactorBreakdown,
            true,
        ))
        .with_section(TemplateSection::new(
            "What you can do",
            SectionContentType::CounterfactualSuggestions,
            false,
        ))
}

// ── ExplanationRenderer ─────────────────────────────────────────────

pub struct ExplanationRenderer;

impl ExplanationRenderer {
    pub fn render_plain_text(template: &ExplanationTemplate) -> String {
        let mut out = String::new();
        out.push_str(&format!("=== {} ===\n", template.name));
        out.push_str(&format!("Audience: {}\n", template.audience));
        out.push_str(&format!("Version: {}\n\n", template.version));
        for section in &template.sections {
            out.push_str(&format!("--- {} ---\n", section.title));
            if section.content.is_empty() {
                out.push_str("[No content provided]\n");
            } else {
                out.push_str(&section.content);
                out.push('\n');
            }
            out.push('\n');
        }
        out
    }

    pub fn render_json(template: &ExplanationTemplate) -> String {
        let sections: Vec<String> = template
            .sections
            .iter()
            .map(|s| {
                format!(
                    "{{\"title\":\"{}\",\"type\":\"{}\",\"required\":{},\"content\":\"{}\"}}",
                    s.title, s.content_type, s.required, s.content
                )
            })
            .collect();
        format!(
            "{{\"name\":\"{}\",\"audience\":\"{}\",\"version\":\"{}\",\"sections\":[{}]}}",
            template.name,
            template.audience,
            template.version,
            sections.join(",")
        )
    }

    pub fn render_summary(template: &ExplanationTemplate) -> String {
        let required = template.required_sections().len();
        let filled = template
            .sections
            .iter()
            .filter(|s| !s.content.is_empty())
            .count();
        format!(
            "{} ({}): {} sections ({} required, {} filled)",
            template.name,
            template.audience,
            template.section_count(),
            required,
            filled,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_display() {
        assert_eq!(ExplanationAudience::Technical.to_string(), "technical");
        assert_eq!(ExplanationAudience::Business.to_string(), "business");
        assert_eq!(ExplanationAudience::Regulatory.to_string(), "regulatory");
        assert_eq!(ExplanationAudience::EndUser.to_string(), "end-user");
    }

    #[test]
    fn test_section_content_type_display() {
        assert_eq!(
            SectionContentType::DecisionSummary.to_string(),
            "decision-summary"
        );
        assert_eq!(
            SectionContentType::RegulatoryMapping.to_string(),
            "regulatory-mapping"
        );
        assert_eq!(SectionContentType::CustomText.to_string(), "custom-text");
    }

    #[test]
    fn test_template_construction() {
        let tmpl = ExplanationTemplate::new("T1", ExplanationAudience::Technical, "1.0")
            .with_section(TemplateSection::new(
                "Summary",
                SectionContentType::DecisionSummary,
                true,
            ))
            .with_section(TemplateSection::new(
                "Details",
                SectionContentType::FactorBreakdown,
                false,
            ));
        assert_eq!(tmpl.section_count(), 2);
        assert_eq!(tmpl.required_sections().len(), 1);
    }

    #[test]
    fn test_template_section_with_content() {
        let section = TemplateSection::new("Title", SectionContentType::CustomText, false)
            .with_content("Hello world");
        assert_eq!(section.content, "Hello world");
    }

    #[test]
    fn test_technical_template() {
        let tmpl = technical_template();
        assert_eq!(tmpl.audience, ExplanationAudience::Technical);
        assert_eq!(tmpl.section_count(), 4);
        assert_eq!(tmpl.required_sections().len(), 3);
    }

    #[test]
    fn test_regulatory_template() {
        let tmpl = regulatory_template();
        assert_eq!(tmpl.audience, ExplanationAudience::Regulatory);
        assert_eq!(tmpl.section_count(), 5);
        assert_eq!(tmpl.required_sections().len(), 5);
    }

    #[test]
    fn test_end_user_template() {
        let tmpl = end_user_template();
        assert_eq!(tmpl.audience, ExplanationAudience::EndUser);
        assert_eq!(tmpl.section_count(), 3);
        assert_eq!(tmpl.required_sections().len(), 2);
    }

    #[test]
    fn test_render_plain_text() {
        let tmpl = ExplanationTemplate::new("Test", ExplanationAudience::Business, "1.0")
            .with_section(
                TemplateSection::new("Summary", SectionContentType::DecisionSummary, true)
                    .with_content("Loan was approved"),
            );
        let text = ExplanationRenderer::render_plain_text(&tmpl);
        assert!(text.contains("=== Test ==="));
        assert!(text.contains("Audience: business"));
        assert!(text.contains("Loan was approved"));
    }

    #[test]
    fn test_render_plain_text_empty_content() {
        let tmpl = ExplanationTemplate::new("Test", ExplanationAudience::Business, "1.0")
            .with_section(TemplateSection::new(
                "Summary",
                SectionContentType::DecisionSummary,
                true,
            ));
        let text = ExplanationRenderer::render_plain_text(&tmpl);
        assert!(text.contains("[No content provided]"));
    }

    #[test]
    fn test_render_json() {
        let tmpl = ExplanationTemplate::new("Test", ExplanationAudience::Technical, "2.0")
            .with_section(
                TemplateSection::new("Summary", SectionContentType::DecisionSummary, true)
                    .with_content("ok"),
            );
        let json = ExplanationRenderer::render_json(&tmpl);
        assert!(json.contains("\"name\":\"Test\""));
        assert!(json.contains("\"audience\":\"technical\""));
        assert!(json.contains("\"version\":\"2.0\""));
        assert!(json.contains("\"type\":\"decision-summary\""));
    }

    #[test]
    fn test_render_summary() {
        let tmpl = ExplanationTemplate::new("Test", ExplanationAudience::EndUser, "1.0")
            .with_section(
                TemplateSection::new("A", SectionContentType::DecisionSummary, true)
                    .with_content("filled"),
            )
            .with_section(TemplateSection::new(
                "B",
                SectionContentType::FactorBreakdown,
                false,
            ));
        let summary = ExplanationRenderer::render_summary(&tmpl);
        assert!(summary.contains("2 sections"));
        assert!(summary.contains("1 required"));
        assert!(summary.contains("1 filled"));
    }
}
