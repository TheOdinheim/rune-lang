// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Compliance document generation.
//
// ComplianceDocumentBuilder constructs compliance-grade document
// packages with sections, completeness tracking, and SHA3-256
// content hashing.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::integrity::hash_document_content;

// ── ComplianceSectionStatus ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceSectionStatus {
    Complete,
    Partial,
    Missing,
    NotApplicable,
}

impl fmt::Display for ComplianceSectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => f.write_str("complete"),
            Self::Partial => f.write_str("partial"),
            Self::Missing => f.write_str("missing"),
            Self::NotApplicable => f.write_str("not-applicable"),
        }
    }
}

// ── ComplianceSection ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceSection {
    pub heading: String,
    pub content: String,
    pub requirement_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub status: ComplianceSectionStatus,
}

impl ComplianceSection {
    pub fn new(
        heading: impl Into<String>,
        content: impl Into<String>,
        status: ComplianceSectionStatus,
    ) -> Self {
        Self {
            heading: heading.into(),
            content: content.into(),
            requirement_ref: None,
            evidence_refs: Vec::new(),
            status,
        }
    }

    pub fn with_requirement_ref(mut self, reference: impl Into<String>) -> Self {
        self.requirement_ref = Some(reference.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence_refs.push(evidence.into());
        self
    }
}

// ── ComplianceDocument ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceDocument {
    pub doc_id: String,
    pub title: String,
    pub framework: String,
    pub sections: Vec<ComplianceSection>,
    pub completeness_score: f64,
    pub generated_at: i64,
    pub content_hash: String,
}

impl ComplianceDocument {
    pub fn is_complete(&self) -> bool {
        (self.completeness_score - 1.0).abs() < f64::EPSILON
    }

    pub fn missing_sections(&self) -> Vec<&ComplianceSection> {
        self.sections
            .iter()
            .filter(|s| {
                s.status == ComplianceSectionStatus::Missing
                    || s.status == ComplianceSectionStatus::Partial
            })
            .collect()
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
}

// ── ComplianceDocumentBuilder ───────────────────────────────────────

#[derive(Debug)]
pub struct ComplianceDocumentBuilder {
    pub doc_id: String,
    pub title: String,
    pub sections: Vec<ComplianceSection>,
    pub framework: String,
    pub generated_at: i64,
}

impl ComplianceDocumentBuilder {
    pub fn new(doc_id: &str, title: &str, framework: &str, now: i64) -> Self {
        Self {
            doc_id: doc_id.into(),
            title: title.into(),
            sections: Vec::new(),
            framework: framework.into(),
            generated_at: now,
        }
    }

    pub fn add_section(&mut self, section: ComplianceSection) -> &mut Self {
        self.sections.push(section);
        self
    }

    pub fn build(&self) -> ComplianceDocument {
        let complete_count = self
            .sections
            .iter()
            .filter(|s| {
                s.status == ComplianceSectionStatus::Complete
                    || s.status == ComplianceSectionStatus::NotApplicable
            })
            .count();
        let completeness_score = if self.sections.is_empty() {
            1.0
        } else {
            complete_count as f64 / self.sections.len() as f64
        };

        // Build content for hashing
        let serialized: String = self
            .sections
            .iter()
            .map(|s| format!("{}:{}", s.heading, s.content))
            .collect::<Vec<_>>()
            .join("|");
        let content_hash = hash_document_content(serialized.as_bytes());

        ComplianceDocument {
            doc_id: self.doc_id.clone(),
            title: self.title.clone(),
            framework: self.framework.clone(),
            sections: self.sections.clone(),
            completeness_score,
            generated_at: self.generated_at,
            content_hash,
        }
    }
}

// ── CompliancePackage ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompliancePackage {
    pub package_id: String,
    pub documents: Vec<ComplianceDocument>,
    pub framework: String,
    pub overall_completeness: f64,
    pub generated_at: i64,
}

impl CompliancePackage {
    pub fn new(package_id: &str, framework: &str, now: i64) -> Self {
        Self {
            package_id: package_id.into(),
            documents: Vec::new(),
            framework: framework.into(),
            overall_completeness: 0.0,
            generated_at: now,
        }
    }

    pub fn add_document(&mut self, doc: ComplianceDocument) {
        self.documents.push(doc);
        self.overall_completeness = self.compute_overall();
    }

    pub fn overall_completeness(&self) -> f64 {
        self.overall_completeness
    }

    fn compute_overall(&self) -> f64 {
        if self.documents.is_empty() {
            return 0.0;
        }
        let total: f64 = self.documents.iter().map(|d| d.completeness_score).sum();
        total / self.documents.len() as f64
    }

    pub fn incomplete_documents(&self) -> Vec<&ComplianceDocument> {
        self.documents
            .iter()
            .filter(|d| !d.is_complete())
            .collect()
    }

    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creates_document() {
        let mut builder = ComplianceDocumentBuilder::new("doc1", "Test Doc", "NIST AI RMF", 1000);
        builder.add_section(ComplianceSection::new(
            "Section 1",
            "Content here",
            ComplianceSectionStatus::Complete,
        ));
        builder.add_section(ComplianceSection::new(
            "Section 2",
            "More content",
            ComplianceSectionStatus::Partial,
        ));
        let doc = builder.build();
        assert_eq!(doc.section_count(), 2);
    }

    #[test]
    fn test_completeness_score() {
        let mut builder =
            ComplianceDocumentBuilder::new("doc1", "Test", "SOC 2", 1000);
        builder.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        builder.add_section(ComplianceSection::new("S2", "C2", ComplianceSectionStatus::Complete));
        builder.add_section(ComplianceSection::new(
            "S3",
            "C3",
            ComplianceSectionStatus::Missing,
        ));
        let doc = builder.build();
        assert!((doc.completeness_score - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_missing_sections() {
        let mut builder =
            ComplianceDocumentBuilder::new("doc1", "Test", "SOC 2", 1000);
        builder.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        builder.add_section(ComplianceSection::new("S2", "C2", ComplianceSectionStatus::Missing));
        builder.add_section(ComplianceSection::new("S3", "C3", ComplianceSectionStatus::Partial));
        let doc = builder.build();
        assert_eq!(doc.missing_sections().len(), 2);
    }

    #[test]
    fn test_is_complete() {
        let mut builder =
            ComplianceDocumentBuilder::new("doc1", "Test", "SOC 2", 1000);
        builder.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        builder.add_section(ComplianceSection::new(
            "S2",
            "C2",
            ComplianceSectionStatus::NotApplicable,
        ));
        let doc = builder.build();
        assert!(doc.is_complete());
    }

    #[test]
    fn test_content_hash_computed() {
        let mut builder =
            ComplianceDocumentBuilder::new("doc1", "Test", "SOC 2", 1000);
        builder.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        let doc = builder.build();
        assert_eq!(doc.content_hash.len(), 64);
    }

    #[test]
    fn test_compliance_package_overall() {
        let mut pkg = CompliancePackage::new("pkg1", "NIST", 1000);

        let mut b1 = ComplianceDocumentBuilder::new("d1", "T1", "NIST", 1000);
        b1.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        pkg.add_document(b1.build()); // 100%

        let mut b2 = ComplianceDocumentBuilder::new("d2", "T2", "NIST", 1000);
        b2.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        b2.add_section(ComplianceSection::new("S2", "C2", ComplianceSectionStatus::Missing));
        pkg.add_document(b2.build()); // 50%

        assert!((pkg.overall_completeness() - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_compliance_package_incomplete() {
        let mut pkg = CompliancePackage::new("pkg1", "NIST", 1000);

        let mut b1 = ComplianceDocumentBuilder::new("d1", "T1", "NIST", 1000);
        b1.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Complete));
        pkg.add_document(b1.build()); // complete

        let mut b2 = ComplianceDocumentBuilder::new("d2", "T2", "NIST", 1000);
        b2.add_section(ComplianceSection::new("S1", "C1", ComplianceSectionStatus::Missing));
        pkg.add_document(b2.build()); // incomplete

        assert_eq!(pkg.incomplete_documents().len(), 1);
        assert_eq!(pkg.document_count(), 2);
    }
}
