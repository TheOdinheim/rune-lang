// ═══════════════════════════════════════════════════════════════════════
// Autonomy — Autonomy levels, boundaries, and envelopes that define
// what an agent is allowed to do autonomously.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent::AgentId;

// ── AutonomyLevel ────────────────────────────────────────────────────

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum AutonomyLevel {
    None = 0,
    Observe = 1,
    Suggest = 2,
    ActLowRisk = 3,
    ActMediumRisk = 4,
    ActHighRisk = 5,
    Full = 6,
}

impl AutonomyLevel {
    pub fn can_observe(&self) -> bool {
        *self >= Self::Observe
    }

    pub fn can_suggest(&self) -> bool {
        *self >= Self::Suggest
    }

    pub fn can_act(&self) -> bool {
        *self >= Self::ActLowRisk
    }

    pub fn max_risk_level(&self) -> Option<String> {
        match self {
            Self::None | Self::Observe | Self::Suggest => None,
            Self::ActLowRisk => Some("low".into()),
            Self::ActMediumRisk => Some("medium".into()),
            Self::ActHighRisk | Self::Full => Some("high".into()),
        }
    }
}

impl fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Observe => write!(f, "Observe"),
            Self::Suggest => write!(f, "Suggest"),
            Self::ActLowRisk => write!(f, "ActLowRisk"),
            Self::ActMediumRisk => write!(f, "ActMediumRisk"),
            Self::ActHighRisk => write!(f, "ActHighRisk"),
            Self::Full => write!(f, "Full"),
        }
    }
}

// ── TimeWindow ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days: Vec<String>,
    pub timezone: String,
}

impl TimeWindow {
    pub fn new(start_hour: u8, end_hour: u8) -> Self {
        Self {
            start_hour,
            end_hour,
            days: Vec::new(),
            timezone: "UTC".into(),
        }
    }

    pub fn is_active(&self, hour: u8, day: &str) -> bool {
        let hour_ok = if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Wraps midnight
            hour >= self.start_hour || hour < self.end_hour
        };
        let day_ok = self.days.is_empty() || self.days.iter().any(|d| d.eq_ignore_ascii_case(day));
        hour_ok && day_ok
    }
}

// ── AutonomyBoundary ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyBoundary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub allowed_actions: Vec<String>,
    pub denied_actions: Vec<String>,
    pub allowed_resources: Vec<String>,
    pub denied_resources: Vec<String>,
    pub max_cost: Option<f64>,
    pub max_impact: Option<String>,
    pub time_window: Option<TimeWindow>,
    pub requires_justification: bool,
    pub metadata: HashMap<String, String>,
}

impl AutonomyBoundary {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            allowed_actions: Vec::new(),
            denied_actions: Vec::new(),
            allowed_resources: Vec::new(),
            denied_resources: Vec::new(),
            max_cost: None,
            max_impact: None,
            time_window: None,
            requires_justification: false,
            metadata: HashMap::new(),
        }
    }

    pub fn with_denied_actions(mut self, actions: Vec<String>) -> Self {
        self.denied_actions = actions;
        self
    }

    pub fn with_allowed_actions(mut self, actions: Vec<String>) -> Self {
        self.allowed_actions = actions;
        self
    }

    pub fn with_denied_resources(mut self, resources: Vec<String>) -> Self {
        self.denied_resources = resources;
        self
    }

    pub fn with_requires_justification(mut self) -> Self {
        self.requires_justification = true;
        self
    }
}

// ── AutonomyOutcome ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AutonomyOutcome {
    Permitted,
    Denied { reason: String },
    RequiresEscalation { to: String, reason: String },
    RequiresJustification,
    RequiresApproval { approver: String },
    ExceedsBudget { limit: f64 },
    OutsideTimeWindow,
}

impl fmt::Display for AutonomyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permitted => write!(f, "Permitted"),
            Self::Denied { reason } => write!(f, "Denied: {reason}"),
            Self::RequiresEscalation { to, reason } => {
                write!(f, "RequiresEscalation(to={to}): {reason}")
            }
            Self::RequiresJustification => write!(f, "RequiresJustification"),
            Self::RequiresApproval { approver } => write!(f, "RequiresApproval({approver})"),
            Self::ExceedsBudget { limit } => write!(f, "ExceedsBudget(limit={limit})"),
            Self::OutsideTimeWindow => write!(f, "OutsideTimeWindow"),
        }
    }
}

// ── AutonomyCheck ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AutonomyCheck {
    pub permitted: bool,
    pub outcome: AutonomyOutcome,
    pub detail: String,
}

// ── AutonomyEnvelope ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AutonomyEnvelope {
    pub agent_id: AgentId,
    pub level: AutonomyLevel,
    pub boundaries: Vec<AutonomyBoundary>,
    pub escalation_target: Option<String>,
    pub override_allowed: bool,
}

impl AutonomyEnvelope {
    pub fn new(agent_id: AgentId, level: AutonomyLevel) -> Self {
        Self {
            agent_id,
            level,
            boundaries: Vec::new(),
            escalation_target: None,
            override_allowed: false,
        }
    }

    pub fn add_boundary(&mut self, boundary: AutonomyBoundary) -> &mut Self {
        self.boundaries.push(boundary);
        self
    }

    pub fn with_escalation(mut self, target: impl Into<String>) -> Self {
        self.escalation_target = Some(target.into());
        self
    }

    pub fn check_action(
        &self,
        action: &str,
        resource: Option<&str>,
        risk_level: &str,
    ) -> AutonomyCheck {
        // a. Check denied actions across all boundaries
        for b in &self.boundaries {
            if b.denied_actions.iter().any(|a| a == action) {
                return AutonomyCheck {
                    permitted: false,
                    outcome: AutonomyOutcome::Denied {
                        reason: format!("Action '{action}' explicitly denied by boundary '{}'", b.name),
                    },
                    detail: format!("Boundary '{}' denies action '{action}'", b.name),
                };
            }
        }

        // b. Check denied resources
        if let Some(res) = resource {
            for b in &self.boundaries {
                if b.denied_resources.iter().any(|r| r == res) {
                    return AutonomyCheck {
                        permitted: false,
                        outcome: AutonomyOutcome::Denied {
                            reason: format!("Resource '{res}' explicitly denied by boundary '{}'", b.name),
                        },
                        detail: format!("Boundary '{}' denies resource '{res}'", b.name),
                    };
                }
            }
        }

        // c. Check allowed actions (if any boundary specifies allowed_actions, action must be in it)
        for b in &self.boundaries {
            if !b.allowed_actions.is_empty() && !b.allowed_actions.iter().any(|a| a == action) {
                return AutonomyCheck {
                    permitted: false,
                    outcome: AutonomyOutcome::Denied {
                        reason: format!("Action '{action}' not in allowed list for boundary '{}'", b.name),
                    },
                    detail: format!("Boundary '{}' does not allow '{action}'", b.name),
                };
            }
        }

        // d. Check risk level against autonomy level
        let max_risk = self.level.max_risk_level();
        let risk_exceeds = match (risk_level, max_risk.as_deref()) {
            (_, None) => true, // Can't act at all
            ("low", Some("low" | "medium" | "high")) => false,
            ("medium", Some("medium" | "high")) => false,
            ("high", Some("high")) => false,
            _ => true,
        };
        if risk_exceeds && !self.level.can_act() {
            return AutonomyCheck {
                permitted: false,
                outcome: AutonomyOutcome::Denied {
                    reason: format!("Autonomy level '{}' cannot act", self.level),
                },
                detail: "Agent autonomy level does not permit actions".into(),
            };
        }
        if risk_exceeds {
            let target = self.escalation_target.clone().unwrap_or_else(|| "operator".into());
            return AutonomyCheck {
                permitted: false,
                outcome: AutonomyOutcome::RequiresEscalation {
                    to: target.clone(),
                    reason: format!(
                        "Risk level '{risk_level}' exceeds autonomy level '{}' max risk",
                        self.level
                    ),
                },
                detail: format!("Escalating to {target}"),
            };
        }

        // e. Check justification requirement
        for b in &self.boundaries {
            if b.requires_justification {
                return AutonomyCheck {
                    permitted: false,
                    outcome: AutonomyOutcome::RequiresJustification,
                    detail: format!("Boundary '{}' requires justification", b.name),
                };
            }
        }

        // f. Permitted
        AutonomyCheck {
            permitted: true,
            outcome: AutonomyOutcome::Permitted,
            detail: "Action permitted within autonomy envelope".into(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autonomy_level_ordering() {
        assert!(AutonomyLevel::None < AutonomyLevel::Observe);
        assert!(AutonomyLevel::Observe < AutonomyLevel::Suggest);
        assert!(AutonomyLevel::Suggest < AutonomyLevel::ActLowRisk);
        assert!(AutonomyLevel::ActLowRisk < AutonomyLevel::ActMediumRisk);
        assert!(AutonomyLevel::ActMediumRisk < AutonomyLevel::ActHighRisk);
        assert!(AutonomyLevel::ActHighRisk < AutonomyLevel::Full);
    }

    #[test]
    fn test_autonomy_level_can_observe_suggest_act() {
        assert!(!AutonomyLevel::None.can_observe());
        assert!(AutonomyLevel::Observe.can_observe());
        assert!(AutonomyLevel::Suggest.can_observe());
        assert!(!AutonomyLevel::None.can_suggest());
        assert!(!AutonomyLevel::Observe.can_suggest());
        assert!(AutonomyLevel::Suggest.can_suggest());
        assert!(!AutonomyLevel::Suggest.can_act());
        assert!(AutonomyLevel::ActLowRisk.can_act());
        assert!(AutonomyLevel::Full.can_act());
    }

    #[test]
    fn test_autonomy_level_max_risk() {
        assert_eq!(AutonomyLevel::None.max_risk_level(), None);
        assert_eq!(AutonomyLevel::Observe.max_risk_level(), None);
        assert_eq!(AutonomyLevel::ActLowRisk.max_risk_level(), Some("low".into()));
        assert_eq!(AutonomyLevel::ActMediumRisk.max_risk_level(), Some("medium".into()));
        assert_eq!(AutonomyLevel::ActHighRisk.max_risk_level(), Some("high".into()));
        assert_eq!(AutonomyLevel::Full.max_risk_level(), Some("high".into()));
    }

    #[test]
    fn test_autonomy_boundary_construction() {
        let b = AutonomyBoundary::new("b1", "test boundary")
            .with_denied_actions(vec!["delete".into()])
            .with_allowed_actions(vec!["read".into(), "write".into()])
            .with_requires_justification();
        assert_eq!(b.id, "b1");
        assert!(b.requires_justification);
        assert_eq!(b.denied_actions, vec!["delete"]);
    }

    #[test]
    fn test_envelope_permits_allowed_action() {
        let envelope = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActMediumRisk);
        let check = envelope.check_action("read", None, "low");
        assert!(check.permitted);
        assert_eq!(check.outcome, AutonomyOutcome::Permitted);
    }

    #[test]
    fn test_envelope_denies_denied_action() {
        let mut envelope = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActMediumRisk);
        envelope.add_boundary(
            AutonomyBoundary::new("b1", "deny delete").with_denied_actions(vec!["delete".into()]),
        );
        let check = envelope.check_action("delete", None, "low");
        assert!(!check.permitted);
        assert!(matches!(check.outcome, AutonomyOutcome::Denied { .. }));
    }

    #[test]
    fn test_envelope_denies_denied_resource() {
        let mut envelope = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActMediumRisk);
        envelope.add_boundary(
            AutonomyBoundary::new("b1", "deny secret")
                .with_denied_resources(vec!["secret_db".into()]),
        );
        let check = envelope.check_action("read", Some("secret_db"), "low");
        assert!(!check.permitted);
    }

    #[test]
    fn test_envelope_escalates_when_risk_exceeds() {
        let envelope = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActLowRisk)
            .with_escalation("admin");
        let check = envelope.check_action("deploy", None, "high");
        assert!(!check.permitted);
        assert!(matches!(check.outcome, AutonomyOutcome::RequiresEscalation { .. }));
    }

    #[test]
    fn test_envelope_requires_justification() {
        let mut envelope = AutonomyEnvelope::new(AgentId::new("a1"), AutonomyLevel::ActMediumRisk);
        envelope.add_boundary(
            AutonomyBoundary::new("b1", "justify all").with_requires_justification(),
        );
        let check = envelope.check_action("write", None, "low");
        assert!(!check.permitted);
        assert_eq!(check.outcome, AutonomyOutcome::RequiresJustification);
    }

    #[test]
    fn test_time_window_is_active() {
        let tw = TimeWindow {
            start_hour: 9,
            end_hour: 17,
            days: vec!["Mon".into(), "Tue".into()],
            timezone: "UTC".into(),
        };
        assert!(tw.is_active(10, "Mon"));
        assert!(!tw.is_active(18, "Mon"));
        assert!(!tw.is_active(10, "Sat"));
        // Empty days = all days
        let tw2 = TimeWindow::new(0, 24);
        assert!(tw2.is_active(12, "Fri"));
    }

    #[test]
    fn test_autonomy_outcome_display() {
        let outcomes = vec![
            AutonomyOutcome::Permitted,
            AutonomyOutcome::Denied { reason: "no".into() },
            AutonomyOutcome::RequiresEscalation { to: "admin".into(), reason: "risk".into() },
            AutonomyOutcome::RequiresJustification,
            AutonomyOutcome::RequiresApproval { approver: "ops".into() },
            AutonomyOutcome::ExceedsBudget { limit: 100.0 },
            AutonomyOutcome::OutsideTimeWindow,
        ];
        for o in &outcomes {
            assert!(!o.to_string().is_empty());
        }
        assert_eq!(outcomes.len(), 7);
    }
}
