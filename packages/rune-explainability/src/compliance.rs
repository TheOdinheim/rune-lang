// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Explanation compliance audit.
//
// ExplanationCompletenessCheck scores how complete an explanation is.
// RegulatoryRequirement checks EU AI Act Art 13/14 and GDPR Art 22.
// ExplanationAuditLog (L2) tracks per-entry approval status.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── ExplanationCompletenessCheck ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExplanationCompletenessCheck {
    pub decision_id: String,
    pub has_outcome: bool,
    pub has_factors: bool,
    pub has_evidence: bool,
    pub has_counterfactual: bool,
    pub has_audience_adaptation: bool,
    pub has_trace: bool,
    pub score: f64,
}

impl ExplanationCompletenessCheck {
    pub fn check_completeness(
        decision_id: impl Into<String>,
        has_outcome: bool,
        has_factors: bool,
        has_evidence: bool,
        has_counterfactual: bool,
        has_audience_adaptation: bool,
        has_trace: bool,
    ) -> Self {
        let checks = [
            has_outcome,
            has_factors,
            has_evidence,
            has_counterfactual,
            has_audience_adaptation,
            has_trace,
        ];
        let passed = checks.iter().filter(|&&c| c).count();
        let score = passed as f64 / checks.len() as f64;
        Self {
            decision_id: decision_id.into(),
            has_outcome,
            has_factors,
            has_evidence,
            has_counterfactual,
            has_audience_adaptation,
            has_trace,
            score,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.score >= 1.0
    }

    pub fn is_sufficient(&self) -> bool {
        self.score >= 0.5
    }

    pub fn missing_items(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.has_outcome {
            missing.push("outcome");
        }
        if !self.has_factors {
            missing.push("factors");
        }
        if !self.has_evidence {
            missing.push("evidence");
        }
        if !self.has_counterfactual {
            missing.push("counterfactual");
        }
        if !self.has_audience_adaptation {
            missing.push("audience_adaptation");
        }
        if !self.has_trace {
            missing.push("trace");
        }
        missing
    }
}

// ── RegulatoryFramework ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegulatoryFramework {
    EuAiActArt13,
    EuAiActArt14,
    GdprArt22,
}

impl fmt::Display for RegulatoryFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EuAiActArt13 => f.write_str("EU AI Act Art. 13"),
            Self::EuAiActArt14 => f.write_str("EU AI Act Art. 14"),
            Self::GdprArt22 => f.write_str("GDPR Art. 22"),
        }
    }
}

// ── RegulatoryRequirement ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RegulatoryRequirement {
    pub framework: RegulatoryFramework,
    pub requirement: String,
    pub met: bool,
    pub detail: String,
}

impl RegulatoryRequirement {
    pub fn new(
        framework: RegulatoryFramework,
        requirement: impl Into<String>,
        met: bool,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            framework,
            requirement: requirement.into(),
            met,
            detail: detail.into(),
        }
    }
}

/// Check EU AI Act Art 13/14 requirements against a completeness check.
pub fn check_eu_ai_act(check: &ExplanationCompletenessCheck) -> Vec<RegulatoryRequirement> {
    vec![
        RegulatoryRequirement::new(
            RegulatoryFramework::EuAiActArt13,
            "Transparency of AI system operation",
            check.has_outcome && check.has_factors,
            if check.has_outcome && check.has_factors {
                "Outcome and factors documented"
            } else {
                "Missing outcome or factor documentation"
            },
        ),
        RegulatoryRequirement::new(
            RegulatoryFramework::EuAiActArt14,
            "Human oversight measures",
            check.has_trace && check.has_evidence,
            if check.has_trace && check.has_evidence {
                "Trace and evidence available for oversight"
            } else {
                "Insufficient trace or evidence for human oversight"
            },
        ),
    ]
}

/// Check GDPR Art 22 requirements against a completeness check.
pub fn check_gdpr_art22(check: &ExplanationCompletenessCheck) -> Vec<RegulatoryRequirement> {
    vec![
        RegulatoryRequirement::new(
            RegulatoryFramework::GdprArt22,
            "Meaningful information about logic involved",
            check.has_factors && check.has_evidence,
            if check.has_factors && check.has_evidence {
                "Logic information provided via factors and evidence"
            } else {
                "Insufficient information about decision logic"
            },
        ),
        RegulatoryRequirement::new(
            RegulatoryFramework::GdprArt22,
            "Right to obtain human intervention",
            check.has_counterfactual,
            if check.has_counterfactual {
                "Counterfactual analysis available for contestation"
            } else {
                "No counterfactual analysis for contestation support"
            },
        ),
    ]
}

// ── ExplanationAuditEntry ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExplanationAuditEntry {
    pub decision_id: String,
    pub timestamp: i64,
    pub reviewer: String,
    pub approved: bool,
    pub completeness_score: f64,
    pub regulatory_checks_passed: usize,
    pub regulatory_checks_total: usize,
    pub notes: String,
}

impl ExplanationAuditEntry {
    pub fn new(
        decision_id: impl Into<String>,
        timestamp: i64,
        reviewer: impl Into<String>,
        approved: bool,
        completeness_score: f64,
        regulatory_checks_passed: usize,
        regulatory_checks_total: usize,
    ) -> Self {
        Self {
            decision_id: decision_id.into(),
            timestamp,
            reviewer: reviewer.into(),
            approved,
            completeness_score,
            regulatory_checks_passed,
            regulatory_checks_total,
            notes: String::new(),
        }
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }
}

// ── L2ExplanationAuditLog ───────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2ExplanationAuditLog {
    pub entries: Vec<ExplanationAuditEntry>,
}

impl L2ExplanationAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, entry: ExplanationAuditEntry) {
        self.entries.push(entry);
    }

    pub fn compliance_rate(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let approved = self.entries.iter().filter(|e| e.approved).count();
        approved as f64 / self.entries.len() as f64
    }

    pub fn unapproved_entries(&self) -> Vec<&ExplanationAuditEntry> {
        self.entries.iter().filter(|e| !e.approved).collect()
    }

    pub fn entries_for_decision(&self, decision_id: &str) -> Vec<&ExplanationAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.decision_id == decision_id)
            .collect()
    }

    pub fn average_completeness(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let total: f64 = self.entries.iter().map(|e| e.completeness_score).sum();
        total / self.entries.len() as f64
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completeness_all_present() {
        let check =
            ExplanationCompletenessCheck::check_completeness("d1", true, true, true, true, true, true);
        assert!(check.is_complete());
        assert!(check.is_sufficient());
        assert!(check.missing_items().is_empty());
        assert!((check.score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_completeness_partial() {
        let check =
            ExplanationCompletenessCheck::check_completeness("d1", true, true, true, false, false, false);
        assert!(!check.is_complete());
        assert!(check.is_sufficient()); // 3/6 = 0.5
        assert_eq!(check.missing_items().len(), 3);
    }

    #[test]
    fn test_completeness_insufficient() {
        let check = ExplanationCompletenessCheck::check_completeness(
            "d1", true, true, false, false, false, false,
        );
        assert!(!check.is_sufficient()); // 2/6 < 0.5
    }

    #[test]
    fn test_eu_ai_act_all_met() {
        let check =
            ExplanationCompletenessCheck::check_completeness("d1", true, true, true, true, true, true);
        let reqs = check_eu_ai_act(&check);
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().all(|r| r.met));
    }

    #[test]
    fn test_eu_ai_act_partial() {
        let check = ExplanationCompletenessCheck::check_completeness(
            "d1", true, true, false, false, false, false,
        );
        let reqs = check_eu_ai_act(&check);
        assert!(reqs[0].met); // outcome + factors
        assert!(!reqs[1].met); // no trace or evidence
    }

    #[test]
    fn test_gdpr_art22_all_met() {
        let check =
            ExplanationCompletenessCheck::check_completeness("d1", true, true, true, true, true, true);
        let reqs = check_gdpr_art22(&check);
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().all(|r| r.met));
    }

    #[test]
    fn test_gdpr_art22_no_counterfactual() {
        let check = ExplanationCompletenessCheck::check_completeness(
            "d1", true, true, true, false, true, true,
        );
        let reqs = check_gdpr_art22(&check);
        assert!(reqs[0].met); // factors + evidence
        assert!(!reqs[1].met); // no counterfactual
    }

    #[test]
    fn test_regulatory_framework_display() {
        assert_eq!(
            RegulatoryFramework::EuAiActArt13.to_string(),
            "EU AI Act Art. 13"
        );
        assert_eq!(
            RegulatoryFramework::GdprArt22.to_string(),
            "GDPR Art. 22"
        );
    }

    #[test]
    fn test_audit_entry_with_notes() {
        let entry = ExplanationAuditEntry::new("d1", 1000, "reviewer1", true, 0.9, 3, 4)
            .with_notes("Looks good");
        assert_eq!(entry.notes, "Looks good");
        assert!(entry.approved);
    }

    #[test]
    fn test_l2_audit_log_compliance_rate() {
        let mut log = L2ExplanationAuditLog::new();
        log.record(ExplanationAuditEntry::new("d1", 1000, "r1", true, 1.0, 4, 4));
        log.record(ExplanationAuditEntry::new("d2", 2000, "r1", false, 0.5, 2, 4));
        log.record(ExplanationAuditEntry::new("d3", 3000, "r1", true, 0.8, 3, 4));
        assert!((log.compliance_rate() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_l2_audit_log_unapproved() {
        let mut log = L2ExplanationAuditLog::new();
        log.record(ExplanationAuditEntry::new("d1", 1000, "r1", true, 1.0, 4, 4));
        log.record(ExplanationAuditEntry::new("d2", 2000, "r1", false, 0.5, 2, 4));
        let unapproved = log.unapproved_entries();
        assert_eq!(unapproved.len(), 1);
        assert_eq!(unapproved[0].decision_id, "d2");
    }

    #[test]
    fn test_l2_audit_log_average_completeness() {
        let mut log = L2ExplanationAuditLog::new();
        log.record(ExplanationAuditEntry::new("d1", 1000, "r1", true, 1.0, 4, 4));
        log.record(ExplanationAuditEntry::new("d2", 2000, "r1", true, 0.5, 2, 4));
        assert!((log.average_completeness() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_l2_audit_log_empty() {
        let log = L2ExplanationAuditLog::new();
        assert_eq!(log.count(), 0);
        assert!((log.compliance_rate()).abs() < f64::EPSILON);
        assert!((log.average_completeness()).abs() < f64::EPSILON);
    }
}
