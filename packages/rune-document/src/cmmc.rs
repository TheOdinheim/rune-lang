// ═══════════════════════════════════════════════════════════════════════
// CMMC — Cybersecurity Maturity Model Certification assessment.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::document::*;

// ── CmmcLevel ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CmmcLevel {
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
}

impl fmt::Display for CmmcLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Level1 => f.write_str("Level 1"),
            Self::Level2 => f.write_str("Level 2"),
            Self::Level3 => f.write_str("Level 3"),
        }
    }
}

// ── CmmcPractice ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CmmcPractice {
    pub id: String,
    pub description: String,
    pub level: CmmcLevel,
    pub implemented: bool,
    pub evidence: Vec<String>,
    pub gaps: Vec<String>,
}

impl CmmcPractice {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        level: CmmcLevel,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            level,
            implemented: false,
            evidence: Vec::new(),
            gaps: Vec::new(),
        }
    }

    pub fn implemented(mut self) -> Self {
        self.implemented = true;
        self
    }
}

// ── CmmcDomain ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CmmcDomain {
    pub id: String,
    pub name: String,
    pub practices: Vec<CmmcPractice>,
    pub domain_score: f64,
}

impl CmmcDomain {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            practices: Vec::new(),
            domain_score: 0.0,
        }
    }

    pub fn with_practice(mut self, practice: CmmcPractice) -> Self {
        self.practices.push(practice);
        self.recalculate_score();
        self
    }

    fn recalculate_score(&mut self) {
        if self.practices.is_empty() {
            self.domain_score = 0.0;
            return;
        }
        let implemented = self.practices.iter().filter(|p| p.implemented).count();
        self.domain_score = implemented as f64 / self.practices.len() as f64;
    }
}

// ── CmmcAssessment ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CmmcAssessment {
    pub organization: String,
    pub target_level: CmmcLevel,
    pub domains: Vec<CmmcDomain>,
    pub overall_score: f64,
    pub meets_target: bool,
    pub assessed_at: i64,
    pub assessed_by: String,
}

// ── CmmcDocumentBuilder ─────────────────────────────────────────────

pub struct CmmcDocumentBuilder {
    organization: String,
    target_level: CmmcLevel,
    domains: Vec<CmmcDomain>,
}

impl CmmcDocumentBuilder {
    pub fn new(organization: &str, target_level: CmmcLevel) -> Self {
        Self {
            organization: organization.into(),
            target_level,
            domains: Vec::new(),
        }
    }

    pub fn add_domain(&mut self, domain: CmmcDomain) -> &mut Self {
        self.domains.push(domain);
        self
    }

    pub fn score(&self) -> f64 {
        let target_practices: Vec<&CmmcPractice> = self
            .domains
            .iter()
            .flat_map(|d| d.practices.iter())
            .filter(|p| p.level <= self.target_level)
            .collect();
        if target_practices.is_empty() {
            return 0.0;
        }
        let implemented = target_practices.iter().filter(|p| p.implemented).count();
        implemented as f64 / target_practices.len() as f64
    }

    pub fn unmet_practices(&self) -> Vec<&CmmcPractice> {
        self.domains
            .iter()
            .flat_map(|d| d.practices.iter())
            .filter(|p| p.level <= self.target_level && !p.implemented)
            .collect()
    }

    pub fn build(&self, now: i64) -> Document {
        let score = self.score();
        let meets = (score - 1.0).abs() < 1e-9;

        let mut doc = Document::new(
            DocumentId::new(format!("cmmc-assessment-{now}")),
            format!("CMMC {} Assessment — {}", self.target_level, self.organization),
            DocumentType::MaturityAssessment,
            ComplianceFramework::Cmmc,
            "assessor",
            now,
        );

        // Executive summary
        doc.sections.push(
            DocumentSection::new("executive-summary", "Executive Summary")
                .with_content(format!(
                    "Organization: {}. Target: {}. Score: {:.1}%. Meets target: {}.",
                    self.organization,
                    self.target_level,
                    score * 100.0,
                    if meets { "Yes" } else { "No" }
                ))
                .with_status(if meets {
                    ComplianceStatus::Compliant
                } else {
                    ComplianceStatus::PartiallyCompliant {
                        gaps: self.unmet_practices().iter().map(|p| p.id.clone()).collect(),
                    }
                }),
        );

        // One section per domain
        for domain in &self.domains {
            let mut section = DocumentSection::new(&domain.id, &domain.name)
                .with_content(format!("Domain score: {:.1}%", domain.domain_score * 100.0));
            for practice in &domain.practices {
                section = section.with_subsection(
                    DocumentSection::new(&practice.id, &practice.description)
                        .with_content(if practice.implemented {
                            "Implemented".to_string()
                        } else {
                            format!("Not implemented. Gaps: {}", practice.gaps.join(", "))
                        })
                        .with_status(if practice.implemented {
                            ComplianceStatus::Compliant
                        } else {
                            ComplianceStatus::NonCompliant {
                                reason: "practice not implemented".into(),
                            }
                        }),
                );
            }
            doc.sections.push(section);
        }

        // Gap analysis
        let unmet = self.unmet_practices();
        if !unmet.is_empty() {
            doc.sections.push(
                DocumentSection::new("gap-analysis", "Gap Analysis")
                    .with_content(format!(
                        "{} practices not yet implemented at {}.",
                        unmet.len(),
                        self.target_level
                    )),
            );
        }

        // Remediation roadmap
        doc.sections.push(
            DocumentSection::new("remediation", "Remediation Roadmap")
                .with_content("Prioritized remediation steps for unmet practices."),
        );

        doc
    }

    pub fn level1_skeleton() -> Self {
        let ac = CmmcDomain::new("AC", "Access Control")
            .with_practice(CmmcPractice::new(
                "AC.L1-3.1.1",
                "Limit system access to authorized users",
                CmmcLevel::Level1,
            ))
            .with_practice(CmmcPractice::new(
                "AC.L1-3.1.2",
                "Limit system access to authorized functions",
                CmmcLevel::Level1,
            ));

        let ia = CmmcDomain::new("IA", "Identification and Authentication")
            .with_practice(CmmcPractice::new(
                "IA.L1-3.5.1",
                "Identify system users",
                CmmcLevel::Level1,
            ))
            .with_practice(CmmcPractice::new(
                "IA.L1-3.5.2",
                "Authenticate users",
                CmmcLevel::Level1,
            ));

        let mp = CmmcDomain::new("MP", "Media Protection")
            .with_practice(CmmcPractice::new(
                "MP.L1-3.8.3",
                "Sanitize media before disposal",
                CmmcLevel::Level1,
            ));

        let pe = CmmcDomain::new("PE", "Physical Protection")
            .with_practice(CmmcPractice::new(
                "PE.L1-3.10.1",
                "Limit physical access",
                CmmcLevel::Level1,
            ));

        let sc = CmmcDomain::new("SC", "System and Communications Protection")
            .with_practice(CmmcPractice::new(
                "SC.L1-3.13.1",
                "Monitor communications at boundaries",
                CmmcLevel::Level1,
            ));

        let si = CmmcDomain::new("SI", "System and Information Integrity")
            .with_practice(CmmcPractice::new(
                "SI.L1-3.14.1",
                "Identify and report flaws",
                CmmcLevel::Level1,
            ));

        let mut builder = Self::new("Organization", CmmcLevel::Level1);
        builder.add_domain(ac);
        builder.add_domain(ia);
        builder.add_domain(mp);
        builder.add_domain(pe);
        builder.add_domain(sc);
        builder.add_domain(si);
        builder
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_domain() -> CmmcDomain {
        CmmcDomain::new("AC", "Access Control")
            .with_practice(CmmcPractice::new("AC.L1-1", "Limit access", CmmcLevel::Level1).implemented())
            .with_practice(CmmcPractice::new("AC.L1-2", "Limit functions", CmmcLevel::Level1))
    }

    #[test]
    fn test_builder_constructs_valid_assessment() {
        let mut builder = CmmcDocumentBuilder::new("Acme", CmmcLevel::Level1);
        builder.add_domain(sample_domain());
        let doc = builder.build(1000);
        assert_eq!(doc.document_type, DocumentType::MaturityAssessment);
        assert_eq!(doc.framework, ComplianceFramework::Cmmc);
    }

    #[test]
    fn test_build_produces_domain_sections() {
        let mut builder = CmmcDocumentBuilder::new("Acme", CmmcLevel::Level1);
        builder.add_domain(sample_domain());
        let doc = builder.build(1000);
        // Exec summary + AC domain + gap analysis + remediation = 4
        assert!(doc.sections.len() >= 3);
    }

    #[test]
    fn test_cmmc_level_ordering() {
        assert!(CmmcLevel::Level1 < CmmcLevel::Level2);
        assert!(CmmcLevel::Level2 < CmmcLevel::Level3);
    }

    #[test]
    fn test_level1_skeleton() {
        let builder = CmmcDocumentBuilder::level1_skeleton();
        assert!(builder.domains.len() >= 4);
        assert!(builder.domains.iter().all(|d| d.practices.iter().all(|p| p.level == CmmcLevel::Level1)));
    }

    #[test]
    fn test_score_calculates_percentage() {
        let mut builder = CmmcDocumentBuilder::new("Acme", CmmcLevel::Level1);
        builder.add_domain(sample_domain()); // 1 of 2 implemented
        assert!((builder.score() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_unmet_practices() {
        let mut builder = CmmcDocumentBuilder::new("Acme", CmmcLevel::Level1);
        builder.add_domain(sample_domain());
        assert_eq!(builder.unmet_practices().len(), 1);
    }

    #[test]
    fn test_all_implemented_scores_1() {
        let domain = CmmcDomain::new("AC", "Access Control")
            .with_practice(CmmcPractice::new("AC.L1-1", "Test", CmmcLevel::Level1).implemented())
            .with_practice(CmmcPractice::new("AC.L1-2", "Test", CmmcLevel::Level1).implemented());
        let mut builder = CmmcDocumentBuilder::new("Acme", CmmcLevel::Level1);
        builder.add_domain(domain);
        assert!((builder.score() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_none_implemented_scores_0() {
        let domain = CmmcDomain::new("AC", "Access Control")
            .with_practice(CmmcPractice::new("AC.L1-1", "Test", CmmcLevel::Level1))
            .with_practice(CmmcPractice::new("AC.L1-2", "Test", CmmcLevel::Level1));
        let mut builder = CmmcDocumentBuilder::new("Acme", CmmcLevel::Level1);
        builder.add_domain(domain);
        assert!((builder.score() - 0.0).abs() < 1e-9);
    }
}
