// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Automated compliance gap analysis.
//
// Tracks evidence against framework controls, identifies gaps, and
// computes compliance scores across single and multiple frameworks.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── EvidenceType ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceType {
    Document,
    TestResult,
    AuditReport,
    SystemLog,
    Attestation,
    Configuration,
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Document => "Document",
            Self::TestResult => "TestResult",
            Self::AuditReport => "AuditReport",
            Self::SystemLog => "SystemLog",
            Self::Attestation => "Attestation",
            Self::Configuration => "Configuration",
        };
        f.write_str(s)
    }
}

// ── EvidenceStatus ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceStatus {
    Valid,
    Expired,
    Pending,
    Rejected,
}

impl fmt::Display for EvidenceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Valid => "Valid",
            Self::Expired => "Expired",
            Self::Pending => "Pending",
            Self::Rejected => "Rejected",
        };
        f.write_str(s)
    }
}

// ── ComplianceEvidence ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceEvidence {
    pub evidence_id: String,
    pub control_id: String,
    pub framework_id: String,
    pub evidence_type: EvidenceType,
    pub status: EvidenceStatus,
    pub description: String,
    pub collected_at: i64,
    pub expires_at: Option<i64>,
}

impl ComplianceEvidence {
    pub fn new(
        evidence_id: impl Into<String>,
        control_id: impl Into<String>,
        framework_id: impl Into<String>,
        evidence_type: EvidenceType,
        status: EvidenceStatus,
        collected_at: i64,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            control_id: control_id.into(),
            framework_id: framework_id.into(),
            evidence_type,
            status,
            description: String::new(),
            collected_at,
            expires_at: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_expiry(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.status == EvidenceStatus::Valid
    }
}

// ── GapType ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapType {
    NoEvidence,
    ExpiredEvidence,
    InsufficientEvidence,
    RejectedEvidence,
}

impl fmt::Display for GapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NoEvidence => "NoEvidence",
            Self::ExpiredEvidence => "ExpiredEvidence",
            Self::InsufficientEvidence => "InsufficientEvidence",
            Self::RejectedEvidence => "RejectedEvidence",
        };
        f.write_str(s)
    }
}

// ── ComplianceGap ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceGap {
    pub control_id: String,
    pub framework_id: String,
    pub gap_type: GapType,
    pub description: String,
}

// ── GapAnalysisReport ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GapAnalysisReport {
    pub framework_id: String,
    pub total_controls: usize,
    pub covered_controls: usize,
    pub gaps: Vec<ComplianceGap>,
    pub compliance_score: f64,
}

impl GapAnalysisReport {
    pub fn gap_count(&self) -> usize {
        self.gaps.len()
    }

    pub fn is_fully_compliant(&self) -> bool {
        self.gaps.is_empty()
    }
}

// ── GapAnalyzer ───────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct GapAnalyzer {
    evidence: Vec<ComplianceEvidence>,
    /// control_id → framework_id list of known required controls
    required_controls: HashMap<String, Vec<String>>,
}

impl GapAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_evidence(&mut self, ev: ComplianceEvidence) {
        self.evidence.push(ev);
    }

    pub fn register_control(&mut self, framework_id: &str, control_id: &str) {
        self.required_controls
            .entry(control_id.to_string())
            .or_default()
            .push(framework_id.to_string());
    }

    pub fn analyze(&self, framework_id: &str) -> GapAnalysisReport {
        let control_ids: Vec<&String> = self
            .required_controls
            .iter()
            .filter(|(_, fws)| fws.contains(&framework_id.to_string()))
            .map(|(cid, _)| cid)
            .collect();

        let total_controls = control_ids.len();
        let mut gaps = Vec::new();
        let mut covered = 0usize;

        for cid in &control_ids {
            let evidence_for_control: Vec<&ComplianceEvidence> = self
                .evidence
                .iter()
                .filter(|e| &e.control_id == *cid && e.framework_id == framework_id)
                .collect();

            if evidence_for_control.is_empty() {
                gaps.push(ComplianceGap {
                    control_id: cid.to_string(),
                    framework_id: framework_id.to_string(),
                    gap_type: GapType::NoEvidence,
                    description: format!("No evidence found for control {}", cid),
                });
            } else if evidence_for_control.iter().all(|e| e.status == EvidenceStatus::Rejected) {
                gaps.push(ComplianceGap {
                    control_id: cid.to_string(),
                    framework_id: framework_id.to_string(),
                    gap_type: GapType::RejectedEvidence,
                    description: format!("All evidence for control {} was rejected", cid),
                });
            } else if evidence_for_control.iter().all(|e| e.status == EvidenceStatus::Expired) {
                gaps.push(ComplianceGap {
                    control_id: cid.to_string(),
                    framework_id: framework_id.to_string(),
                    gap_type: GapType::ExpiredEvidence,
                    description: format!("All evidence for control {} has expired", cid),
                });
            } else if evidence_for_control.iter().any(|e| e.is_valid()) {
                covered += 1;
            } else {
                gaps.push(ComplianceGap {
                    control_id: cid.to_string(),
                    framework_id: framework_id.to_string(),
                    gap_type: GapType::InsufficientEvidence,
                    description: format!("No valid evidence for control {}", cid),
                });
            }
        }

        let compliance_score = if total_controls == 0 {
            0.0
        } else {
            covered as f64 / total_controls as f64 * 100.0
        };

        GapAnalysisReport {
            framework_id: framework_id.to_string(),
            total_controls,
            covered_controls: covered,
            gaps,
            compliance_score,
        }
    }

    pub fn analyze_all(&self) -> Vec<GapAnalysisReport> {
        let mut framework_ids: Vec<String> = self
            .required_controls
            .values()
            .flatten()
            .cloned()
            .collect();
        framework_ids.sort();
        framework_ids.dedup();
        framework_ids.iter().map(|fid| self.analyze(fid)).collect()
    }

    pub fn cross_framework_score(&self) -> f64 {
        let reports = self.analyze_all();
        if reports.is_empty() {
            return 0.0;
        }
        let total: f64 = reports.iter().map(|r| r.compliance_score).sum();
        total / reports.len() as f64
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_analyzer() -> GapAnalyzer {
        let mut ga = GapAnalyzer::new();
        ga.register_control("nist-ai-rmf", "GOV-1");
        ga.register_control("nist-ai-rmf", "GOV-2");
        ga.register_control("nist-ai-rmf", "MEA-1");
        ga
    }

    #[test]
    fn test_gap_analyzer_no_evidence_produces_gaps() {
        let ga = setup_analyzer();
        let report = ga.analyze("nist-ai-rmf");
        assert_eq!(report.total_controls, 3);
        assert_eq!(report.covered_controls, 0);
        assert_eq!(report.gap_count(), 3);
        assert!(report.gaps.iter().all(|g| g.gap_type == GapType::NoEvidence));
    }

    #[test]
    fn test_gap_analyzer_valid_evidence_covers_control() {
        let mut ga = setup_analyzer();
        ga.add_evidence(ComplianceEvidence::new(
            "ev-1", "GOV-1", "nist-ai-rmf", EvidenceType::Document,
            EvidenceStatus::Valid, 1000,
        ));
        ga.add_evidence(ComplianceEvidence::new(
            "ev-2", "GOV-2", "nist-ai-rmf", EvidenceType::AuditReport,
            EvidenceStatus::Valid, 1000,
        ));
        ga.add_evidence(ComplianceEvidence::new(
            "ev-3", "MEA-1", "nist-ai-rmf", EvidenceType::TestResult,
            EvidenceStatus::Valid, 1000,
        ));
        let report = ga.analyze("nist-ai-rmf");
        assert_eq!(report.covered_controls, 3);
        assert!(report.is_fully_compliant());
        assert!((report.compliance_score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gap_analyzer_expired_evidence_produces_gap() {
        let mut ga = setup_analyzer();
        ga.add_evidence(ComplianceEvidence::new(
            "ev-1", "GOV-1", "nist-ai-rmf", EvidenceType::Document,
            EvidenceStatus::Expired, 1000,
        ));
        let report = ga.analyze("nist-ai-rmf");
        let gov1_gaps: Vec<_> = report.gaps.iter().filter(|g| g.control_id == "GOV-1").collect();
        assert_eq!(gov1_gaps.len(), 1);
        assert_eq!(gov1_gaps[0].gap_type, GapType::ExpiredEvidence);
    }

    #[test]
    fn test_gap_analyzer_rejected_evidence_produces_gap() {
        let mut ga = setup_analyzer();
        ga.add_evidence(ComplianceEvidence::new(
            "ev-1", "GOV-1", "nist-ai-rmf", EvidenceType::Document,
            EvidenceStatus::Rejected, 1000,
        ));
        let report = ga.analyze("nist-ai-rmf");
        let gov1_gaps: Vec<_> = report.gaps.iter().filter(|g| g.control_id == "GOV-1").collect();
        assert_eq!(gov1_gaps.len(), 1);
        assert_eq!(gov1_gaps[0].gap_type, GapType::RejectedEvidence);
    }

    #[test]
    fn test_analyze_all_covers_multiple_frameworks() {
        let mut ga = GapAnalyzer::new();
        ga.register_control("fw-a", "C-1");
        ga.register_control("fw-b", "C-2");
        ga.add_evidence(ComplianceEvidence::new(
            "ev-1", "C-1", "fw-a", EvidenceType::Document,
            EvidenceStatus::Valid, 1000,
        ));
        let reports = ga.analyze_all();
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_cross_framework_score() {
        let mut ga = GapAnalyzer::new();
        ga.register_control("fw-a", "C-1");
        ga.register_control("fw-b", "C-2");
        ga.add_evidence(ComplianceEvidence::new(
            "ev-1", "C-1", "fw-a", EvidenceType::Document,
            EvidenceStatus::Valid, 1000,
        ));
        // fw-a: 100%, fw-b: 0% → average 50%
        let score = ga.cross_framework_score();
        assert!((score - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_evidence_with_expiry() {
        let ev = ComplianceEvidence::new(
            "ev-1", "GOV-1", "nist", EvidenceType::Document,
            EvidenceStatus::Valid, 1000,
        )
        .with_expiry(2000)
        .with_description("Governance policy document");
        assert!(ev.is_valid());
        assert_eq!(ev.expires_at, Some(2000));
        assert_eq!(ev.description, "Governance policy document");
    }
}
