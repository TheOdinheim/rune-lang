// ═══════════════════════════════════════════════════════════════════════
// Renderer — render documents to text, Markdown, and JSON.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::document::*;

// ── RenderFormat ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderFormat {
    PlainText,
    Markdown,
    Json,
}

impl fmt::Display for RenderFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlainText => f.write_str("plain-text"),
            Self::Markdown => f.write_str("markdown"),
            Self::Json => f.write_str("json"),
        }
    }
}

// ── CompletionSummary ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompletionSummary {
    pub total_sections: usize,
    pub completed_sections: usize,
    pub total_required_fields: usize,
    pub filled_required_fields: usize,
    pub completion_percentage: f64,
    pub missing_required: Vec<String>,
    pub compliance_summary: HashMap<String, usize>,
}

pub fn completion_summary(doc: &Document) -> CompletionSummary {
    let mut total_sections = 0usize;
    let mut completed_sections = 0usize;
    let mut total_required = 0usize;
    let mut filled_required = 0usize;
    let mut missing = Vec::new();
    let mut compliance: HashMap<String, usize> = HashMap::new();

    count_sections(
        &doc.sections,
        &mut total_sections,
        &mut completed_sections,
        &mut total_required,
        &mut filled_required,
        &mut missing,
        &mut compliance,
    );

    let pct = if total_required > 0 {
        filled_required as f64 / total_required as f64 * 100.0
    } else {
        100.0
    };

    CompletionSummary {
        total_sections,
        completed_sections,
        total_required_fields: total_required,
        filled_required_fields: filled_required,
        completion_percentage: pct,
        missing_required: missing,
        compliance_summary: compliance,
    }
}

fn count_sections(
    sections: &[DocumentSection],
    total: &mut usize,
    completed: &mut usize,
    req_fields: &mut usize,
    filled_fields: &mut usize,
    missing: &mut Vec<String>,
    compliance: &mut HashMap<String, usize>,
) {
    for section in sections {
        *total += 1;
        let mut section_complete = true;
        for field in &section.fields {
            if field.required {
                *req_fields += 1;
                if field.filled {
                    *filled_fields += 1;
                } else {
                    section_complete = false;
                    missing.push(field.name.clone());
                }
            }
        }
        if section_complete && !section.content.is_empty() {
            *completed += 1;
        }
        if let Some(status) = &section.compliance_status {
            let key = match status {
                ComplianceStatus::Compliant => "compliant",
                ComplianceStatus::PartiallyCompliant { .. } => "partially-compliant",
                ComplianceStatus::NonCompliant { .. } => "non-compliant",
                ComplianceStatus::NotAssessed => "not-assessed",
                ComplianceStatus::NotApplicable => "not-applicable",
            };
            *compliance.entry(key.to_string()).or_insert(0) += 1;
        }
        count_sections(
            &section.subsections,
            total,
            completed,
            req_fields,
            filled_fields,
            missing,
            compliance,
        );
    }
}

// ── DocumentRenderer ────────────────────────────────────────────────

pub struct DocumentRenderer;

impl DocumentRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn render(&self, doc: &Document, format: RenderFormat) -> String {
        match format {
            RenderFormat::PlainText => self.render_text(doc),
            RenderFormat::Markdown => self.render_markdown(doc),
            RenderFormat::Json => self.render_json(doc),
        }
    }

    pub fn render_text(&self, doc: &Document) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{} ({})\n",
            doc.title, doc.version
        ));
        out.push_str(&format!(
            "Framework: {} | Status: {} | Created: {}\n\n",
            doc.framework, doc.status, doc.created_at
        ));
        for section in &doc.sections {
            out.push_str(&self.render_section(section, RenderFormat::PlainText, 1));
        }
        out
    }

    pub fn render_markdown(&self, doc: &Document) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {} {}\n\n", doc.title, doc.version));
        out.push_str(&format!(
            "| Field | Value |\n|-------|-------|\n| Framework | {} |\n| Status | {} |\n| Created | {} |\n| Author | {} |\n\n",
            doc.framework, doc.status, doc.created_at, doc.created_by
        ));
        for section in &doc.sections {
            out.push_str(&self.render_section(section, RenderFormat::Markdown, 2));
        }
        out
    }

    pub fn render_json(&self, doc: &Document) -> String {
        serde_json::to_string_pretty(doc).unwrap_or_else(|_| "{}".into())
    }

    pub fn render_section(
        &self,
        section: &DocumentSection,
        format: RenderFormat,
        depth: usize,
    ) -> String {
        match format {
            RenderFormat::PlainText => {
                let mut out = String::new();
                let indent = "  ".repeat(depth.saturating_sub(1));
                out.push_str(&format!("{indent}{}\n", section.title));
                if !section.content.is_empty() {
                    out.push_str(&format!("{indent}  {}\n", section.content));
                }
                for field in &section.fields {
                    let status = if field.filled { "[x]" } else { "[ ]" };
                    out.push_str(&format!(
                        "{indent}  {status} {}: {}\n",
                        field.name, field.value
                    ));
                }
                if let Some(status) = &section.compliance_status {
                    out.push_str(&format!("{indent}  Status: {status}\n"));
                }
                for sub in &section.subsections {
                    out.push_str(&self.render_section(sub, RenderFormat::PlainText, depth + 1));
                }
                out.push('\n');
                out
            }
            RenderFormat::Markdown => {
                let mut out = String::new();
                let heading = "#".repeat(depth.min(6));
                let num = section
                    .section_number
                    .as_deref()
                    .map(|n| format!("{n} "))
                    .unwrap_or_default();
                out.push_str(&format!("{heading} {num}{}\n\n", section.title));
                if !section.content.is_empty() {
                    out.push_str(&format!("{}\n\n", section.content));
                }
                for field in &section.fields {
                    out.push_str(&format!("- **{}**: {}\n", field.name, field.value));
                }
                if let Some(status) = &section.compliance_status {
                    let badge = match status {
                        ComplianceStatus::Compliant => "Compliant",
                        ComplianceStatus::PartiallyCompliant { .. } => "Partial",
                        ComplianceStatus::NonCompliant { .. } => "Non-Compliant",
                        ComplianceStatus::NotAssessed => "Not Assessed",
                        ComplianceStatus::NotApplicable => "N/A",
                    };
                    out.push_str(&format!("\n**Status:** {badge}\n"));
                }
                out.push('\n');
                for sub in &section.subsections {
                    out.push_str(&self.render_section(sub, RenderFormat::Markdown, depth + 1));
                }
                out
            }
            RenderFormat::Json => {
                serde_json::to_string_pretty(section).unwrap_or_else(|_| "{}".into())
            }
        }
    }
}

impl Default for DocumentRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> Document {
        Document::new(
            DocumentId::new("doc-1"),
            "Test Document",
            DocumentType::ComplianceReport,
            ComplianceFramework::GdprEu,
            "author",
            1000,
        )
        .with_section(
            DocumentSection::new("s1", "Section One")
                .with_content("Section content here.")
                .with_field(
                    DocumentField::new("name", FieldType::Text, true).with_value("filled"),
                )
                .with_field(DocumentField::new("empty_field", FieldType::Text, true))
                .with_status(ComplianceStatus::PartiallyCompliant {
                    gaps: vec!["missing field".into()],
                }),
        )
        .with_section(
            DocumentSection::new("s2", "Section Two")
                .with_content("More content.")
                .with_status(ComplianceStatus::Compliant),
        )
    }

    #[test]
    fn test_render_text() {
        let renderer = DocumentRenderer::new();
        let text = renderer.render_text(&sample_doc());
        assert!(text.contains("Test Document"));
        assert!(text.contains("Section One"));
        assert!(text.contains("Section content here."));
    }

    #[test]
    fn test_render_markdown() {
        let renderer = DocumentRenderer::new();
        let md = renderer.render_markdown(&sample_doc());
        assert!(md.contains("# Test Document"));
        assert!(md.contains("## Section One"));
        assert!(md.contains("**Status:**"));
    }

    #[test]
    fn test_render_markdown_includes_badges() {
        let renderer = DocumentRenderer::new();
        let md = renderer.render_markdown(&sample_doc());
        assert!(md.contains("Partial"));
        assert!(md.contains("Compliant"));
    }

    #[test]
    fn test_render_json() {
        let renderer = DocumentRenderer::new();
        let json = renderer.render_json(&sample_doc());
        assert!(json.contains("\"title\""));
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_render_json_roundtrip() {
        let renderer = DocumentRenderer::new();
        let json = renderer.render_json(&sample_doc());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["title"], "Test Document");
    }

    #[test]
    fn test_render_section_depth() {
        let renderer = DocumentRenderer::new();
        let section = DocumentSection::new("s1", "Test Section").with_content("Content");
        let md2 = renderer.render_section(&section, RenderFormat::Markdown, 2);
        assert!(md2.starts_with("## "));
        let md4 = renderer.render_section(&section, RenderFormat::Markdown, 4);
        assert!(md4.starts_with("#### "));
    }

    #[test]
    fn test_completion_summary() {
        let summary = completion_summary(&sample_doc());
        assert_eq!(summary.total_sections, 2);
        assert_eq!(summary.total_required_fields, 2);
        assert_eq!(summary.filled_required_fields, 1);
        assert!((summary.completion_percentage - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_completion_summary_missing_fields() {
        let summary = completion_summary(&sample_doc());
        assert_eq!(summary.missing_required, vec!["empty_field"]);
    }

    #[test]
    fn test_render_format_display() {
        assert_eq!(RenderFormat::PlainText.to_string(), "plain-text");
        assert_eq!(RenderFormat::Markdown.to_string(), "markdown");
        assert_eq!(RenderFormat::Json.to_string(), "json");
    }

    #[test]
    fn test_empty_document_renders() {
        let renderer = DocumentRenderer::new();
        let doc = Document::new(
            DocumentId::new("empty"),
            "Empty",
            DocumentType::ComplianceReport,
            ComplianceFramework::GdprEu,
            "author",
            1000,
        );
        let text = renderer.render_text(&doc);
        assert!(text.contains("Empty"));
        let md = renderer.render_markdown(&doc);
        assert!(md.contains("# Empty"));
        let json = renderer.render_json(&doc);
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }
}
