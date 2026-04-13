// ═══════════════════════════════════════════════════════════════════════
// Audience — audience-adapted explanations.
//
// AudienceAdapter transforms decision outcomes, factors, and severity
// descriptions into language appropriate for Technical, Executive,
// Regulatory, Operator, and DataSubject audiences.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::decision::{DecisionOutcome, FactorDirection, FactorType};

// ── Audience ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Audience {
    Technical,
    Executive,
    Regulatory,
    Operator,
    DataSubject,
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Technical => f.write_str("technical"),
            Self::Executive => f.write_str("executive"),
            Self::Regulatory => f.write_str("regulatory"),
            Self::Operator => f.write_str("operator"),
            Self::DataSubject => f.write_str("data-subject"),
        }
    }
}

// ── AudienceAdapter ─────────────────────────────────────────────────

pub struct AudienceAdapter;

impl AudienceAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn adapt_outcome(&self, outcome: &DecisionOutcome, audience: &Audience) -> String {
        match audience {
            Audience::Technical => format!("Outcome: {outcome}"),
            Audience::Executive => match outcome {
                DecisionOutcome::Approved => "Request was approved.".into(),
                DecisionOutcome::Denied => "Request was denied due to policy constraints.".into(),
                DecisionOutcome::Escalated => {
                    "Request requires senior review before proceeding.".into()
                }
                DecisionOutcome::Deferred => "Decision has been deferred for further analysis.".into(),
                DecisionOutcome::ConditionallyApproved { conditions } => {
                    format!(
                        "Approved with conditions: {}.",
                        conditions.join(", ")
                    )
                }
                DecisionOutcome::Error { reason } => {
                    format!("Decision could not be completed: {reason}.")
                }
            },
            Audience::Regulatory => match outcome {
                DecisionOutcome::Approved => {
                    "The system authorized this action in compliance with applicable policies.".into()
                }
                DecisionOutcome::Denied => {
                    "The system denied this action pursuant to security and compliance requirements."
                        .into()
                }
                DecisionOutcome::Escalated => {
                    "The action was escalated for human review per governance procedures.".into()
                }
                DecisionOutcome::Deferred => {
                    "The action was deferred pending additional compliance review.".into()
                }
                DecisionOutcome::ConditionallyApproved { conditions } => {
                    format!(
                        "Conditionally authorized subject to: {}.",
                        conditions.join("; ")
                    )
                }
                DecisionOutcome::Error { reason } => {
                    format!("Processing error encountered: {reason}. Manual review required.")
                }
            },
            Audience::Operator => match outcome {
                DecisionOutcome::Approved => "APPROVED — no action required.".into(),
                DecisionOutcome::Denied => "DENIED — check policy rules.".into(),
                DecisionOutcome::Escalated => "ESCALATED — awaiting senior review.".into(),
                DecisionOutcome::Deferred => "DEFERRED — will be retried.".into(),
                DecisionOutcome::ConditionallyApproved { conditions } => {
                    format!("CONDITIONAL — requires: {}", conditions.join(", "))
                }
                DecisionOutcome::Error { reason } => format!("ERROR — {reason}"),
            },
            Audience::DataSubject => match outcome {
                DecisionOutcome::Approved => {
                    "Your request has been approved.".into()
                }
                DecisionOutcome::Denied => {
                    "Your request could not be approved at this time. You may contact support for more information.".into()
                }
                DecisionOutcome::Escalated => {
                    "Your request is being reviewed by a human specialist.".into()
                }
                DecisionOutcome::Deferred => {
                    "Your request is being processed and will be completed shortly.".into()
                }
                DecisionOutcome::ConditionallyApproved { conditions } => {
                    format!(
                        "Your request has been approved, but the following steps are needed: {}.",
                        conditions.join(", ")
                    )
                }
                DecisionOutcome::Error { .. } => {
                    "We encountered an issue processing your request. Please try again or contact support.".into()
                }
            },
        }
    }

    pub fn adapt_factor(
        &self,
        factor_name: &str,
        factor_type: &FactorType,
        direction: &FactorDirection,
        audience: &Audience,
    ) -> String {
        match audience {
            Audience::Technical => {
                format!("{factor_name} ({factor_type}): {direction}")
            }
            Audience::Executive => {
                let impact = match direction {
                    FactorDirection::Supporting => "positive influence",
                    FactorDirection::Opposing => "risk factor",
                    FactorDirection::Neutral => "informational",
                };
                format!("{}: {impact}", self.terminology(factor_name, audience))
            }
            Audience::Regulatory => {
                let role = match direction {
                    FactorDirection::Supporting => "supporting factor",
                    FactorDirection::Opposing => "adverse factor",
                    FactorDirection::Neutral => "neutral factor",
                };
                format!(
                    "{} ({}) — {}",
                    self.terminology(factor_name, audience),
                    factor_type,
                    role
                )
            }
            Audience::Operator => {
                let arrow = match direction {
                    FactorDirection::Supporting => "+",
                    FactorDirection::Opposing => "-",
                    FactorDirection::Neutral => "~",
                };
                format!("[{arrow}] {factor_name}")
            }
            Audience::DataSubject => {
                let desc = match direction {
                    FactorDirection::Supporting => "worked in your favor",
                    FactorDirection::Opposing => "was a concern",
                    FactorDirection::Neutral => "was considered",
                };
                format!("{} {desc}", self.terminology(factor_name, audience))
            }
        }
    }

    pub fn adapt_severity(&self, severity: &str, audience: &Audience) -> String {
        match audience {
            Audience::Technical => format!("Severity: {severity}"),
            Audience::Executive => match severity {
                "critical" | "emergency" => "Immediate executive attention required.".into(),
                "high" => "Significant risk identified.".into(),
                "medium" => "Moderate concern noted.".into(),
                _ => "Low-priority observation.".into(),
            },
            Audience::Regulatory => match severity {
                "critical" | "emergency" => {
                    "Critical finding requiring immediate remediation.".into()
                }
                "high" => "High-severity finding requiring prompt attention.".into(),
                "medium" => "Medium-severity finding for scheduled remediation.".into(),
                _ => "Low-severity informational finding.".into(),
            },
            Audience::Operator => format!("[{severity}]"),
            Audience::DataSubject => match severity {
                "critical" | "emergency" | "high" => {
                    "An important issue was identified that may affect you.".into()
                }
                _ => "A minor issue was noted.".into(),
            },
        }
    }

    pub fn terminology(&self, term: &str, audience: &Audience) -> String {
        match audience {
            Audience::DataSubject => match term {
                "policy" | "policy-check" | "security-policy" => "security rules".into(),
                "trust" | "trust-score" | "trust-level" => "your trust rating".into(),
                "risk" | "risk-score" => "risk assessment".into(),
                "compliance" | "compliance-requirement" => "regulatory requirements".into(),
                _ => humanize(term),
            },
            Audience::Executive => match term {
                "policy" | "policy-check" | "security-policy" => "security policy".into(),
                "trust" | "trust-score" | "trust-level" => "trust assessment".into(),
                "risk" | "risk-score" => "risk indicator".into(),
                _ => humanize(term),
            },
            _ => term.to_string(),
        }
    }
}

impl Default for AudienceAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn humanize(term: &str) -> String {
    term.replace(['-', '_'], " ")
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_display() {
        assert_eq!(Audience::Technical.to_string(), "technical");
        assert_eq!(Audience::Executive.to_string(), "executive");
        assert_eq!(Audience::Regulatory.to_string(), "regulatory");
        assert_eq!(Audience::Operator.to_string(), "operator");
        assert_eq!(Audience::DataSubject.to_string(), "data-subject");
    }

    #[test]
    fn test_adapt_outcome_denied_all_audiences() {
        let adapter = AudienceAdapter::new();
        let denied = DecisionOutcome::Denied;
        let audiences = [
            Audience::Technical,
            Audience::Executive,
            Audience::Regulatory,
            Audience::Operator,
            Audience::DataSubject,
        ];
        let mut results: Vec<String> = audiences
            .iter()
            .map(|a| adapter.adapt_outcome(&denied, a))
            .collect();
        // Each audience should produce distinct output
        results.sort();
        results.dedup();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_adapt_outcome_approved_data_subject() {
        let adapter = AudienceAdapter::new();
        let result = adapter.adapt_outcome(&DecisionOutcome::Approved, &Audience::DataSubject);
        assert!(result.contains("approved"));
    }

    #[test]
    fn test_adapt_outcome_conditional() {
        let adapter = AudienceAdapter::new();
        let cond = DecisionOutcome::ConditionallyApproved {
            conditions: vec!["mfa".into(), "audit".into()],
        };
        let result = adapter.adapt_outcome(&cond, &Audience::Executive);
        assert!(result.contains("mfa"));
    }

    #[test]
    fn test_adapt_factor_technical() {
        let adapter = AudienceAdapter::new();
        let result = adapter.adapt_factor(
            "policy-check",
            &FactorType::SecurityPolicy,
            &FactorDirection::Opposing,
            &Audience::Technical,
        );
        assert!(result.contains("policy-check"));
        assert!(result.contains("opposing"));
    }

    #[test]
    fn test_adapt_factor_operator_arrows() {
        let adapter = AudienceAdapter::new();
        let sup = adapter.adapt_factor(
            "trust",
            &FactorType::TrustLevel,
            &FactorDirection::Supporting,
            &Audience::Operator,
        );
        assert!(sup.starts_with("[+]"));
        let opp = adapter.adapt_factor(
            "risk",
            &FactorType::RiskScore,
            &FactorDirection::Opposing,
            &Audience::Operator,
        );
        assert!(opp.starts_with("[-]"));
    }

    #[test]
    fn test_adapt_factor_data_subject() {
        let adapter = AudienceAdapter::new();
        let result = adapter.adapt_factor(
            "trust-score",
            &FactorType::TrustLevel,
            &FactorDirection::Supporting,
            &Audience::DataSubject,
        );
        assert!(result.contains("your trust rating"));
        assert!(result.contains("worked in your favor"));
    }

    #[test]
    fn test_adapt_severity_all_audiences() {
        let adapter = AudienceAdapter::new();
        let audiences = [
            Audience::Technical,
            Audience::Executive,
            Audience::Regulatory,
            Audience::Operator,
            Audience::DataSubject,
        ];
        let mut results: Vec<String> = audiences
            .iter()
            .map(|a| adapter.adapt_severity("critical", a))
            .collect();
        results.sort();
        results.dedup();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_terminology_data_subject() {
        let adapter = AudienceAdapter::new();
        assert_eq!(
            adapter.terminology("policy-check", &Audience::DataSubject),
            "security rules"
        );
        assert_eq!(
            adapter.terminology("trust-score", &Audience::DataSubject),
            "your trust rating"
        );
        assert_eq!(
            adapter.terminology("some-unknown", &Audience::DataSubject),
            "some unknown"
        );
    }

    #[test]
    fn test_terminology_executive() {
        let adapter = AudienceAdapter::new();
        assert_eq!(
            adapter.terminology("risk-score", &Audience::Executive),
            "risk indicator"
        );
    }

    #[test]
    fn test_terminology_technical_passthrough() {
        let adapter = AudienceAdapter::new();
        assert_eq!(
            adapter.terminology("raw-term", &Audience::Technical),
            "raw-term"
        );
    }
}
