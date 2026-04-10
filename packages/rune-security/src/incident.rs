// ═══════════════════════════════════════════════════════════════════════
// Incident Management — classification, response, escalation, metrics
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SecurityError;
use crate::severity::SecuritySeverity;
use crate::threat::ThreatCategory;

// ── IncidentId ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IncidentId(String);

impl IncidentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IncidentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── IncidentStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    Acknowledged,
    Investigating,
    Containing,
    Eradicating,
    Recovering,
    Resolved,
    Closed,
}

impl IncidentStatus {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::New
                | Self::Acknowledged
                | Self::Investigating
                | Self::Containing
                | Self::Eradicating
                | Self::Recovering
        )
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Resolved | Self::Closed)
    }

    pub fn next_valid_statuses(&self) -> Vec<IncidentStatus> {
        match self {
            Self::New => vec![Self::Acknowledged],
            Self::Acknowledged => vec![Self::Investigating],
            Self::Investigating => vec![Self::Containing, Self::Resolved],
            Self::Containing => vec![Self::Eradicating],
            Self::Eradicating => vec![Self::Recovering],
            Self::Recovering => vec![Self::Resolved],
            Self::Resolved => vec![Self::Closed],
            Self::Closed => vec![],
        }
    }
}

impl fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── IncidentEventType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentEventType {
    Reported,
    Acknowledged,
    EscalationTriggered,
    AssigneeChanged,
    StatusChanged,
    EvidenceAdded,
    ContainmentAction,
    CommunicationSent,
    RootCauseIdentified,
    ResolutionApplied,
    PostMortemCompleted,
}

impl fmt::Display for IncidentEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── IncidentEvent ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncidentEvent {
    pub timestamp: i64,
    pub event_type: IncidentEventType,
    pub actor: String,
    pub detail: String,
}

// ── Incident ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: IncidentId,
    pub title: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub category: ThreatCategory,
    pub status: IncidentStatus,
    pub reported_at: i64,
    pub acknowledged_at: Option<i64>,
    pub resolved_at: Option<i64>,
    pub closed_at: Option<i64>,
    pub reporter: String,
    pub assignee: Option<String>,
    pub affected_systems: Vec<String>,
    pub indicators: Vec<String>,
    pub timeline: Vec<IncidentEvent>,
    pub root_cause: Option<String>,
    pub lessons_learned: Option<String>,
}

// ── EscalationLevel / EscalationPolicy ────────────────────────────────

#[derive(Debug, Clone)]
pub struct EscalationLevel {
    pub severity: SecuritySeverity,
    pub response_time_hours: u64,
    pub notify: Vec<String>,
    pub auto_escalate: bool,
}

#[derive(Debug, Clone, Default)]
pub struct EscalationPolicy {
    pub levels: Vec<EscalationLevel>,
}

impl EscalationPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_level(&mut self, level: EscalationLevel) -> &mut Self {
        self.levels.push(level);
        self
    }

    pub fn escalation_for_severity(&self, severity: SecuritySeverity) -> Option<&EscalationLevel> {
        self.levels.iter().find(|l| l.severity == severity)
    }

    /// True if the incident has exceeded its response time for its severity.
    pub fn should_escalate(&self, incident: &Incident, now: i64) -> bool {
        if incident.status.is_closed() {
            return false;
        }
        let level = match self.escalation_for_severity(incident.severity) {
            Some(l) => l,
            None => return false,
        };
        let elapsed_ms = now - incident.reported_at;
        let deadline_ms = (level.response_time_hours as i64) * 60 * 60 * 1000;
        elapsed_ms > deadline_ms
    }
}

// ── IncidentTracker ───────────────────────────────────────────────────

pub struct IncidentTracker {
    pub incidents: HashMap<IncidentId, Incident>,
    pub escalation_policy: EscalationPolicy,
    next_id: u64,
}

impl IncidentTracker {
    pub fn new(policy: EscalationPolicy) -> Self {
        Self {
            incidents: HashMap::new(),
            escalation_policy: policy,
            next_id: 0,
        }
    }

    pub fn report(
        &mut self,
        title: &str,
        description: &str,
        severity: SecuritySeverity,
        category: ThreatCategory,
        reporter: &str,
    ) -> Incident {
        self.next_id += 1;
        let id = IncidentId::new(format!("inc-{}", self.next_id));
        let now = 0_i64;
        let incident = Incident {
            id: id.clone(),
            title: title.into(),
            description: description.into(),
            severity,
            category,
            status: IncidentStatus::New,
            reported_at: now,
            acknowledged_at: None,
            resolved_at: None,
            closed_at: None,
            reporter: reporter.into(),
            assignee: None,
            affected_systems: Vec::new(),
            indicators: Vec::new(),
            timeline: vec![IncidentEvent {
                timestamp: now,
                event_type: IncidentEventType::Reported,
                actor: reporter.into(),
                detail: format!("Incident reported: {title}"),
            }],
            root_cause: None,
            lessons_learned: None,
        };
        self.incidents.insert(id.clone(), incident.clone());
        incident
    }

    pub fn acknowledge(&mut self, id: &IncidentId, by: &str) -> Result<(), SecurityError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| SecurityError::IncidentNotFound(id.to_string()))?;
        if !matches!(inc.status, IncidentStatus::New) {
            return Err(SecurityError::InvalidStatusTransition {
                from: inc.status.to_string(),
                to: IncidentStatus::Acknowledged.to_string(),
            });
        }
        inc.status = IncidentStatus::Acknowledged;
        inc.acknowledged_at = Some(inc.reported_at + 1);
        inc.timeline.push(IncidentEvent {
            timestamp: inc.reported_at + 1,
            event_type: IncidentEventType::Acknowledged,
            actor: by.into(),
            detail: "acknowledged".into(),
        });
        Ok(())
    }

    pub fn update_status(
        &mut self,
        id: &IncidentId,
        status: IncidentStatus,
        by: &str,
        detail: &str,
    ) -> Result<(), SecurityError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| SecurityError::IncidentNotFound(id.to_string()))?;
        if !inc.status.next_valid_statuses().contains(&status) {
            return Err(SecurityError::InvalidStatusTransition {
                from: inc.status.to_string(),
                to: status.to_string(),
            });
        }
        let from = inc.status.clone();
        inc.status = status.clone();
        inc.timeline.push(IncidentEvent {
            timestamp: inc.reported_at + 1,
            event_type: IncidentEventType::StatusChanged,
            actor: by.into(),
            detail: format!("{from} → {status}: {detail}"),
        });
        Ok(())
    }

    pub fn assign(
        &mut self,
        id: &IncidentId,
        assignee: &str,
        by: &str,
    ) -> Result<(), SecurityError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| SecurityError::IncidentNotFound(id.to_string()))?;
        inc.assignee = Some(assignee.into());
        inc.timeline.push(IncidentEvent {
            timestamp: inc.reported_at + 1,
            event_type: IncidentEventType::AssigneeChanged,
            actor: by.into(),
            detail: format!("assigned to {assignee}"),
        });
        Ok(())
    }

    pub fn resolve(
        &mut self,
        id: &IncidentId,
        root_cause: &str,
        by: &str,
    ) -> Result<(), SecurityError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| SecurityError::IncidentNotFound(id.to_string()))?;
        inc.status = IncidentStatus::Resolved;
        inc.root_cause = Some(root_cause.into());
        inc.resolved_at = Some(inc.reported_at + 100);
        inc.timeline.push(IncidentEvent {
            timestamp: inc.reported_at + 100,
            event_type: IncidentEventType::ResolutionApplied,
            actor: by.into(),
            detail: format!("resolved: {root_cause}"),
        });
        Ok(())
    }

    pub fn close(
        &mut self,
        id: &IncidentId,
        lessons: &str,
        by: &str,
    ) -> Result<(), SecurityError> {
        let inc = self
            .incidents
            .get_mut(id)
            .ok_or_else(|| SecurityError::IncidentNotFound(id.to_string()))?;
        if !matches!(inc.status, IncidentStatus::Resolved) {
            return Err(SecurityError::InvalidStatusTransition {
                from: inc.status.to_string(),
                to: IncidentStatus::Closed.to_string(),
            });
        }
        inc.status = IncidentStatus::Closed;
        inc.lessons_learned = Some(lessons.into());
        inc.closed_at = Some(inc.reported_at + 200);
        inc.timeline.push(IncidentEvent {
            timestamp: inc.reported_at + 200,
            event_type: IncidentEventType::PostMortemCompleted,
            actor: by.into(),
            detail: format!("closed: {lessons}"),
        });
        Ok(())
    }

    pub fn active_incidents(&self) -> Vec<&Incident> {
        self.incidents.values().filter(|i| i.status.is_active()).collect()
    }

    pub fn incidents_by_severity(&self, severity: SecuritySeverity) -> Vec<&Incident> {
        self.incidents.values().filter(|i| i.severity == severity).collect()
    }

    pub fn incidents_needing_escalation(&self, now: i64) -> Vec<&Incident> {
        self.incidents
            .values()
            .filter(|i| self.escalation_policy.should_escalate(i, now))
            .collect()
    }

    pub fn mean_time_to_acknowledge(&self) -> Option<f64> {
        let times: Vec<f64> = self
            .incidents
            .values()
            .filter_map(|i| i.acknowledged_at.map(|a| (a - i.reported_at) as f64))
            .collect();
        if times.is_empty() {
            None
        } else {
            Some(times.iter().sum::<f64>() / times.len() as f64)
        }
    }

    pub fn mean_time_to_resolve(&self) -> Option<f64> {
        let times: Vec<f64> = self
            .incidents
            .values()
            .filter_map(|i| i.resolved_at.map(|r| (r - i.reported_at) as f64))
            .collect();
        if times.is_empty() {
            None
        } else {
            Some(times.iter().sum::<f64>() / times.len() as f64)
        }
    }

    pub fn incident_count_by_status(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for inc in self.incidents.values() {
            *map.entry(inc.status.to_string()).or_insert(0) += 1;
        }
        map
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> EscalationPolicy {
        let mut p = EscalationPolicy::new();
        p.add_level(EscalationLevel {
            severity: SecuritySeverity::Critical,
            response_time_hours: 4,
            notify: vec!["oncall".into()],
            auto_escalate: true,
        })
        .add_level(EscalationLevel {
            severity: SecuritySeverity::High,
            response_time_hours: 24,
            notify: vec!["team".into()],
            auto_escalate: false,
        });
        p
    }

    #[test]
    fn test_status_is_active_and_closed() {
        assert!(IncidentStatus::New.is_active());
        assert!(IncidentStatus::Investigating.is_active());
        assert!(IncidentStatus::Recovering.is_active());
        assert!(!IncidentStatus::Resolved.is_active());
        assert!(IncidentStatus::Resolved.is_closed());
        assert!(IncidentStatus::Closed.is_closed());
    }

    #[test]
    fn test_next_valid_statuses() {
        assert_eq!(
            IncidentStatus::New.next_valid_statuses(),
            vec![IncidentStatus::Acknowledged]
        );
        assert!(IncidentStatus::Closed.next_valid_statuses().is_empty());
    }

    #[test]
    fn test_report_creates_incident() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "API compromise",
            "suspicious auth",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "analyst",
        );
        assert_eq!(inc.status, IncidentStatus::New);
        assert_eq!(inc.timeline.len(), 1);
    }

    #[test]
    fn test_acknowledge_sets_timestamp() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "title",
            "desc",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "analyst",
        );
        t.acknowledge(&inc.id, "responder").unwrap();
        let stored = t.incidents.get(&inc.id).unwrap();
        assert_eq!(stored.status, IncidentStatus::Acknowledged);
        assert!(stored.acknowledged_at.is_some());
    }

    #[test]
    fn test_valid_status_transition() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        t.acknowledge(&inc.id, "r").unwrap();
        assert!(t
            .update_status(&inc.id, IncidentStatus::Investigating, "r", "")
            .is_ok());
    }

    #[test]
    fn test_invalid_status_transition_rejected() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        // New → Closed is not valid
        let result = t.update_status(&inc.id, IncidentStatus::Closed, "r", "");
        assert!(matches!(
            result,
            Err(SecurityError::InvalidStatusTransition { .. })
        ));
    }

    #[test]
    fn test_assign_sets_assignee() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        t.assign(&inc.id, "bob", "manager").unwrap();
        assert_eq!(
            t.incidents.get(&inc.id).unwrap().assignee,
            Some("bob".into())
        );
    }

    #[test]
    fn test_resolve_and_close() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        t.resolve(&inc.id, "patched", "r").unwrap();
        t.close(&inc.id, "document in runbook", "r").unwrap();
        let stored = t.incidents.get(&inc.id).unwrap();
        assert_eq!(stored.status, IncidentStatus::Closed);
        assert!(stored.root_cause.is_some());
        assert!(stored.lessons_learned.is_some());
    }

    #[test]
    fn test_active_incidents_filter() {
        let mut t = IncidentTracker::new(default_policy());
        let _ = t.report(
            "t1",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        let inc2 = t.report(
            "t2",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        t.resolve(&inc2.id, "done", "r").unwrap();
        assert_eq!(t.active_incidents().len(), 1);
    }

    #[test]
    fn test_incidents_by_severity() {
        let mut t = IncidentTracker::new(default_policy());
        t.report("t1", "d", SecuritySeverity::High, ThreatCategory::Spoofing, "a");
        t.report(
            "t2",
            "d",
            SecuritySeverity::Critical,
            ThreatCategory::Spoofing,
            "a",
        );
        assert_eq!(t.incidents_by_severity(SecuritySeverity::High).len(), 1);
        assert_eq!(t.incidents_by_severity(SecuritySeverity::Critical).len(), 1);
    }

    #[test]
    fn test_should_escalate_overdue() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::Critical,
            ThreatCategory::Spoofing,
            "a",
        );
        let five_hours_ms = 5 * 60 * 60 * 1000;
        let escalation_candidates = t.incidents_needing_escalation(inc.reported_at + five_hours_ms);
        assert_eq!(escalation_candidates.len(), 1);
    }

    #[test]
    fn test_should_not_escalate_within_sla() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::Critical,
            ThreatCategory::Spoofing,
            "a",
        );
        let two_hours_ms = 2 * 60 * 60 * 1000;
        let escalation_candidates = t.incidents_needing_escalation(inc.reported_at + two_hours_ms);
        assert_eq!(escalation_candidates.len(), 0);
    }

    #[test]
    fn test_mean_time_to_acknowledge() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        t.acknowledge(&inc.id, "r").unwrap();
        assert!(t.mean_time_to_acknowledge().is_some());
    }

    #[test]
    fn test_mean_time_to_resolve() {
        let mut t = IncidentTracker::new(default_policy());
        let inc = t.report(
            "t",
            "d",
            SecuritySeverity::High,
            ThreatCategory::Spoofing,
            "a",
        );
        t.resolve(&inc.id, "done", "r").unwrap();
        assert!(t.mean_time_to_resolve().is_some());
    }
}
