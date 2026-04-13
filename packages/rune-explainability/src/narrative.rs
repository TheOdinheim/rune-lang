// ═══════════════════════════════════════════════════════════════════════
// Narrative — human-readable explanation generation.
//
// NarrativeGenerator produces structured narratives from decisions,
// with configurable detail levels and sections.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::decision::{Decision, FactorDirection};

// ── DetailLevel ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DetailLevel {
    Summary = 0,
    Standard = 1,
    Detailed = 2,
}

impl fmt::Display for DetailLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Summary => f.write_str("summary"),
            Self::Standard => f.write_str("standard"),
            Self::Detailed => f.write_str("detailed"),
        }
    }
}

// ── NarrativeSection ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NarrativeSection {
    pub title: String,
    pub content: String,
    pub detail_level: DetailLevel,
}

impl NarrativeSection {
    pub fn new(
        title: impl Into<String>,
        content: impl Into<String>,
        detail_level: DetailLevel,
    ) -> Self {
        Self {
            title: title.into(),
            content: content.into(),
            detail_level,
        }
    }
}

// ── Narrative ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Narrative {
    pub decision_id: String,
    pub headline: String,
    pub sections: Vec<NarrativeSection>,
    pub detail_level: DetailLevel,
    pub generated_at: i64,
}

impl Narrative {
    pub fn full_text(&self) -> String {
        let mut parts = vec![self.headline.clone()];
        for section in &self.sections {
            parts.push(format!("\n## {}\n{}", section.title, section.content));
        }
        parts.join("\n")
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
}

// ── NarrativeGenerator ──────────────────────────────────────────────

pub struct NarrativeGenerator;

impl NarrativeGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(
        &self,
        decision: &Decision,
        detail_level: DetailLevel,
        now: i64,
    ) -> Narrative {
        let headline = format!(
            "Decision {} ({}): {}",
            decision.id, decision.decision_type, decision.outcome
        );

        let mut sections = Vec::new();

        // Overview section (always included)
        sections.push(NarrativeSection::new(
            "Overview",
            format!(
                "A {} decision was made by {} at timestamp {}, resulting in {}.",
                decision.decision_type,
                decision.made_by,
                decision.made_at,
                decision.outcome
            ),
            DetailLevel::Summary,
        ));

        // Context section (standard and above)
        if detail_level >= DetailLevel::Standard {
            let ctx = &decision.context;
            let env_str = if ctx.environment.is_empty() {
                "none".to_string()
            } else {
                ctx.environment
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            sections.push(NarrativeSection::new(
                "Context",
                format!(
                    "Subject: {}, Resource: {}, Action: {}, Environment: {}",
                    ctx.subject, ctx.resource, ctx.action, env_str
                ),
                DetailLevel::Standard,
            ));
        }

        // Factors section (standard and above)
        if detail_level >= DetailLevel::Standard && !decision.factors.is_empty() {
            let factor_lines: Vec<String> = decision
                .factors
                .iter()
                .map(|f| {
                    format!(
                        "- {} ({}): {} [weight={:.2}, {}]",
                        f.name, f.factor_type, f.value, f.weight, f.direction
                    )
                })
                .collect();
            sections.push(NarrativeSection::new(
                "Factors",
                factor_lines.join("\n"),
                DetailLevel::Standard,
            ));
        }

        // Rationale section (detailed only)
        if detail_level >= DetailLevel::Detailed {
            let rationale = if decision.rationale.is_empty() {
                "No explicit rationale provided.".to_string()
            } else {
                decision.rationale.clone()
            };
            sections.push(NarrativeSection::new(
                "Rationale",
                rationale,
                DetailLevel::Detailed,
            ));

            // Factor breakdown
            if !decision.factors.is_empty() {
                let supporting: Vec<_> = decision
                    .factors
                    .iter()
                    .filter(|f| f.direction == FactorDirection::Supporting)
                    .collect();
                let opposing: Vec<_> = decision
                    .factors
                    .iter()
                    .filter(|f| f.direction == FactorDirection::Opposing)
                    .collect();
                sections.push(NarrativeSection::new(
                    "Factor Breakdown",
                    format!(
                        "{} supporting factor(s), {} opposing factor(s) out of {} total.",
                        supporting.len(),
                        opposing.len(),
                        decision.factors.len()
                    ),
                    DetailLevel::Detailed,
                ));
            }
        }

        Narrative {
            decision_id: decision.id.0.clone(),
            headline,
            sections,
            detail_level,
            generated_at: now,
        }
    }
}

impl Default for NarrativeGenerator {
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
    use crate::decision::*;

    fn ctx() -> DecisionContext {
        DecisionContext::new("alice", "db", "read", 1000)
            .with_env("ip", "10.0.0.1")
    }

    fn sample_decision() -> Decision {
        Decision::new(
            DecisionId::new("d1"),
            DecisionType::AccessControl,
            DecisionOutcome::Denied,
            ctx(),
            "policy-engine",
            1000,
        )
        .with_factor(DecisionFactor::new(
            "policy",
            FactorType::SecurityPolicy,
            FactorDirection::Opposing,
            0.7,
            "deny-rule",
        ))
        .with_factor(DecisionFactor::new(
            "trust",
            FactorType::TrustLevel,
            FactorDirection::Supporting,
            0.3,
            "high",
        ))
        .with_rationale("Policy rule #42 denies access to db for role guest")
    }

    #[test]
    fn test_summary_level() {
        let nargen = NarrativeGenerator::new();
        let nar = nargen.generate(&sample_decision(), DetailLevel::Summary, 2000);
        assert_eq!(nar.section_count(), 1);
        assert!(nar.headline.contains("denied"));
    }

    #[test]
    fn test_standard_level() {
        let nargen = NarrativeGenerator::new();
        let nar = nargen.generate(&sample_decision(), DetailLevel::Standard, 2000);
        // Overview + Context + Factors = 3
        assert_eq!(nar.section_count(), 3);
    }

    #[test]
    fn test_detailed_level() {
        let nargen = NarrativeGenerator::new();
        let nar = nargen.generate(&sample_decision(), DetailLevel::Detailed, 2000);
        // Overview + Context + Factors + Rationale + Factor Breakdown = 5
        assert_eq!(nar.section_count(), 5);
    }

    #[test]
    fn test_full_text_contains_headline() {
        let nargen = NarrativeGenerator::new();
        let nar = nargen.generate(&sample_decision(), DetailLevel::Standard, 2000);
        let text = nar.full_text();
        assert!(text.contains("Decision d1"));
        assert!(text.contains("## Overview"));
        assert!(text.contains("## Factors"));
    }

    #[test]
    fn test_context_section_includes_env() {
        let nargen = NarrativeGenerator::new();
        let nar = nargen.generate(&sample_decision(), DetailLevel::Standard, 2000);
        let ctx_section = nar.sections.iter().find(|s| s.title == "Context").unwrap();
        assert!(ctx_section.content.contains("10.0.0.1"));
    }

    #[test]
    fn test_rationale_in_detailed() {
        let nargen = NarrativeGenerator::new();
        let nar = nargen.generate(&sample_decision(), DetailLevel::Detailed, 2000);
        let rat_section = nar.sections.iter().find(|s| s.title == "Rationale").unwrap();
        assert!(rat_section.content.contains("Policy rule #42"));
    }

    #[test]
    fn test_no_rationale_fallback() {
        let nargen = NarrativeGenerator::new();
        let d = Decision::new(
            DecisionId::new("d2"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            DecisionContext::new("bob", "api", "write", 1000),
            "engine",
            1000,
        );
        let nar = nargen.generate(&d, DetailLevel::Detailed, 2000);
        let rat_section = nar.sections.iter().find(|s| s.title == "Rationale").unwrap();
        assert!(rat_section.content.contains("No explicit rationale"));
    }

    #[test]
    fn test_empty_factors_no_factor_section() {
        let nargen = NarrativeGenerator::new();
        let d = Decision::new(
            DecisionId::new("d2"),
            DecisionType::AccessControl,
            DecisionOutcome::Approved,
            DecisionContext::new("bob", "api", "write", 1000),
            "engine",
            1000,
        );
        let nar = nargen.generate(&d, DetailLevel::Standard, 2000);
        assert!(nar.sections.iter().all(|s| s.title != "Factors"));
    }

    #[test]
    fn test_detail_level_display() {
        assert_eq!(DetailLevel::Summary.to_string(), "summary");
        assert_eq!(DetailLevel::Standard.to_string(), "standard");
        assert_eq!(DetailLevel::Detailed.to_string(), "detailed");
    }

    #[test]
    fn test_detail_level_ordering() {
        assert!(DetailLevel::Summary < DetailLevel::Standard);
        assert!(DetailLevel::Standard < DetailLevel::Detailed);
    }
}
