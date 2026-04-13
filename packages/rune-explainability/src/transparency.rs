// ═══════════════════════════════════════════════════════════════════════
// Transparency — structured transparency reports.
//
// TransparencyReportBuilder collects decisions and produces reports
// with sections, metrics, summaries, and JSON rendering.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::decision::{Decision, DecisionOutcome, DecisionStore};

// ── ReportMetric ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetric {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub description: String,
}

impl ReportMetric {
    pub fn new(
        name: impl Into<String>,
        value: f64,
        unit: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            unit: unit.into(),
            description: String::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ── ReportSection ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub content: String,
    pub metrics: Vec<ReportMetric>,
}

impl ReportSection {
    pub fn new(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            content: content.into(),
            metrics: Vec::new(),
        }
    }

    pub fn with_metric(mut self, metric: ReportMetric) -> Self {
        self.metrics.push(metric);
        self
    }
}

// ── ReportSummary ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_decisions: usize,
    pub approved_count: usize,
    pub denied_count: usize,
    pub escalated_count: usize,
    pub approval_rate: f64,
    pub decision_type_breakdown: HashMap<String, usize>,
}

// ── TransparencyReport ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyReport {
    pub title: String,
    pub period: String,
    pub sections: Vec<ReportSection>,
    pub summary: ReportSummary,
    pub generated_at: i64,
}

impl TransparencyReport {
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    pub fn render_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

// ── TransparencyReportBuilder ───────────────────────────────────────

pub struct TransparencyReportBuilder {
    title: String,
    period: String,
    sections: Vec<ReportSection>,
}

impl TransparencyReportBuilder {
    pub fn new(title: impl Into<String>, period: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            period: period.into(),
            sections: Vec::new(),
        }
    }

    pub fn with_section(mut self, section: ReportSection) -> Self {
        self.sections.push(section);
        self
    }

    pub fn build_from_decisions(
        self,
        decisions: &[&Decision],
        now: i64,
    ) -> TransparencyReport {
        let total = decisions.len();
        let mut approved = 0usize;
        let mut denied = 0usize;
        let mut escalated = 0usize;
        let mut type_breakdown: HashMap<String, usize> = HashMap::new();

        for d in decisions {
            match &d.outcome {
                DecisionOutcome::Approved | DecisionOutcome::ConditionallyApproved { .. } => {
                    approved += 1;
                }
                DecisionOutcome::Denied => denied += 1,
                DecisionOutcome::Escalated => escalated += 1,
                _ => {}
            }
            *type_breakdown
                .entry(d.decision_type.to_string())
                .or_insert(0) += 1;
        }

        let approval_rate = if total > 0 {
            approved as f64 / total as f64
        } else {
            0.0
        };

        let summary = ReportSummary {
            total_decisions: total,
            approved_count: approved,
            denied_count: denied,
            escalated_count: escalated,
            approval_rate,
            decision_type_breakdown: type_breakdown,
        };

        // Auto-generate overview section
        let mut sections = vec![ReportSection::new(
            "Overview",
            format!(
                "This report covers {} decisions during period {}. Approval rate: {:.1}%.",
                total,
                self.period,
                approval_rate * 100.0
            ),
        )
        .with_metric(ReportMetric::new("total_decisions", total as f64, "count"))
        .with_metric(
            ReportMetric::new("approval_rate", approval_rate * 100.0, "percent"),
        )];

        sections.extend(self.sections);

        TransparencyReport {
            title: self.title,
            period: self.period,
            sections,
            summary,
            generated_at: now,
        }
    }

    pub fn build_from_store(
        self,
        store: &DecisionStore,
        now: i64,
    ) -> TransparencyReport {
        let decisions: Vec<&Decision> = store.all();
        self.build_from_decisions(&decisions, now)
    }

    pub fn governance_template(period: impl Into<String>) -> Self {
        Self::new("Governance Transparency Report", period)
            .with_section(ReportSection::new(
                "Policy Compliance",
                "Summary of policy enforcement actions and compliance status.",
            ))
            .with_section(ReportSection::new(
                "Risk Assessment",
                "Overview of risk-related decisions and their outcomes.",
            ))
    }

    pub fn compliance_template(period: impl Into<String>) -> Self {
        Self::new("Compliance Transparency Report", period)
            .with_section(ReportSection::new(
                "Regulatory Actions",
                "Decisions made in response to regulatory requirements.",
            ))
            .with_section(ReportSection::new(
                "Audit Findings",
                "Summary of audit-related decisions and dispositions.",
            ))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::*;

    fn ctx() -> DecisionContext {
        DecisionContext::new("alice", "db", "read", 1000)
    }

    fn decisions() -> Vec<Decision> {
        vec![
            Decision::new(
                DecisionId::new("d1"),
                DecisionType::AccessControl,
                DecisionOutcome::Approved,
                ctx(),
                "engine",
                1000,
            ),
            Decision::new(
                DecisionId::new("d2"),
                DecisionType::AccessControl,
                DecisionOutcome::Denied,
                ctx(),
                "engine",
                2000,
            ),
            Decision::new(
                DecisionId::new("d3"),
                DecisionType::RiskAssessment,
                DecisionOutcome::Escalated,
                ctx(),
                "engine",
                3000,
            ),
        ]
    }

    #[test]
    fn test_build_from_decisions() {
        let decs = decisions();
        let refs: Vec<&Decision> = decs.iter().collect();
        let report = TransparencyReportBuilder::new("Test Report", "Q1 2026")
            .build_from_decisions(&refs, 4000);
        assert_eq!(report.summary.total_decisions, 3);
        assert_eq!(report.summary.approved_count, 1);
        assert_eq!(report.summary.denied_count, 1);
        assert_eq!(report.summary.escalated_count, 1);
    }

    #[test]
    fn test_approval_rate() {
        let decs = decisions();
        let refs: Vec<&Decision> = decs.iter().collect();
        let report = TransparencyReportBuilder::new("Test", "Q1")
            .build_from_decisions(&refs, 4000);
        assert!((report.summary.approval_rate - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_type_breakdown() {
        let decs = decisions();
        let refs: Vec<&Decision> = decs.iter().collect();
        let report = TransparencyReportBuilder::new("Test", "Q1")
            .build_from_decisions(&refs, 4000);
        assert_eq!(
            report.summary.decision_type_breakdown["access-control"],
            2
        );
        assert_eq!(
            report.summary.decision_type_breakdown["risk-assessment"],
            1
        );
    }

    #[test]
    fn test_auto_overview_section() {
        let decs = decisions();
        let refs: Vec<&Decision> = decs.iter().collect();
        let report = TransparencyReportBuilder::new("Test", "Q1")
            .build_from_decisions(&refs, 4000);
        assert_eq!(report.sections[0].title, "Overview");
        assert_eq!(report.sections[0].metrics.len(), 2);
    }

    #[test]
    fn test_custom_sections_appended() {
        let decs = decisions();
        let refs: Vec<&Decision> = decs.iter().collect();
        let report = TransparencyReportBuilder::new("Test", "Q1")
            .with_section(ReportSection::new("Custom", "Custom content"))
            .build_from_decisions(&refs, 4000);
        assert_eq!(report.sections.len(), 2); // Overview + Custom
        assert_eq!(report.sections[1].title, "Custom");
    }

    #[test]
    fn test_render_json() {
        let decs = decisions();
        let refs: Vec<&Decision> = decs.iter().collect();
        let report = TransparencyReportBuilder::new("Test", "Q1")
            .build_from_decisions(&refs, 4000);
        let json = report.render_json();
        assert!(json.contains("\"title\""));
        assert!(json.contains("Test"));
        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["summary"]["total_decisions"], 3);
    }

    #[test]
    fn test_governance_template() {
        let builder = TransparencyReportBuilder::governance_template("Q1 2026");
        let report = builder.build_from_decisions(&[], 4000);
        assert_eq!(report.title, "Governance Transparency Report");
        // Overview + Policy Compliance + Risk Assessment = 3
        assert_eq!(report.section_count(), 3);
    }

    #[test]
    fn test_compliance_template() {
        let builder = TransparencyReportBuilder::compliance_template("Q1 2026");
        let report = builder.build_from_decisions(&[], 4000);
        assert_eq!(report.title, "Compliance Transparency Report");
        assert_eq!(report.section_count(), 3);
    }

    #[test]
    fn test_empty_decisions() {
        let report = TransparencyReportBuilder::new("Empty", "Q1")
            .build_from_decisions(&[], 4000);
        assert_eq!(report.summary.total_decisions, 0);
        assert_eq!(report.summary.approval_rate, 0.0);
    }

    #[test]
    fn test_build_from_store() {
        let mut store = DecisionStore::new();
        for d in decisions() {
            store.register(d).unwrap();
        }
        let report = TransparencyReportBuilder::new("Store Test", "Q1")
            .build_from_store(&store, 4000);
        assert_eq!(report.summary.total_decisions, 3);
    }

    #[test]
    fn test_report_metric_builder() {
        let m = ReportMetric::new("latency", 42.5, "ms")
            .with_description("Average decision latency");
        assert_eq!(m.name, "latency");
        assert_eq!(m.value, 42.5);
        assert_eq!(m.description, "Average decision latency");
    }

    #[test]
    fn test_report_section_with_metric() {
        let s = ReportSection::new("Performance", "Performance metrics")
            .with_metric(ReportMetric::new("throughput", 100.0, "decisions/sec"));
        assert_eq!(s.metrics.len(), 1);
    }
}
