// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Safety incident tracking.
//
// Structured safety incident tracking with severity, root cause
// analysis, corrective action management, and resolution metrics.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── SafetyIncidentSeverity ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyIncidentSeverity {
    Informational = 0,
    Minor = 1,
    Major = 2,
    Critical = 3,
    Catastrophic = 4,
}

impl fmt::Display for SafetyIncidentSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Informational => "Informational",
            Self::Minor => "Minor",
            Self::Major => "Major",
            Self::Critical => "Critical",
            Self::Catastrophic => "Catastrophic",
        };
        f.write_str(s)
    }
}

// ── SafetyIncidentCategory ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyIncidentCategory {
    BoundaryViolation,
    UnexpectedBehavior,
    BiasDetected,
    DataLeakage,
    SystemFailure,
    HumanOversightFailure,
}

impl fmt::Display for SafetyIncidentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BoundaryViolation => "BoundaryViolation",
            Self::UnexpectedBehavior => "UnexpectedBehavior",
            Self::BiasDetected => "BiasDetected",
            Self::DataLeakage => "DataLeakage",
            Self::SystemFailure => "SystemFailure",
            Self::HumanOversightFailure => "HumanOversightFailure",
        };
        f.write_str(s)
    }
}

// ── SafetyIncidentStatus ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyIncidentStatus {
    Open,
    Investigating,
    Mitigated,
    Resolved,
    Closed,
}

impl fmt::Display for SafetyIncidentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Open => "Open",
            Self::Investigating => "Investigating",
            Self::Mitigated => "Mitigated",
            Self::Resolved => "Resolved",
            Self::Closed => "Closed",
        };
        f.write_str(s)
    }
}

// ── CorrectiveActionType ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrectiveActionType {
    Immediate,
    ShortTerm,
    LongTerm,
    Preventive,
}

impl fmt::Display for CorrectiveActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Immediate => "Immediate",
            Self::ShortTerm => "ShortTerm",
            Self::LongTerm => "LongTerm",
            Self::Preventive => "Preventive",
        };
        f.write_str(s)
    }
}

// ── ActionStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionStatus {
    Pending,
    InProgress,
    Completed,
    Overdue,
}

impl fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "Pending",
            Self::InProgress => "InProgress",
            Self::Completed => "Completed",
            Self::Overdue => "Overdue",
        };
        f.write_str(s)
    }
}

// ── CorrectiveAction ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrectiveAction {
    pub id: String,
    pub description: String,
    pub action_type: CorrectiveActionType,
    pub status: ActionStatus,
    pub assigned_to: String,
    pub due_date: i64,
    pub completed_at: Option<i64>,
}

impl CorrectiveAction {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        action_type: CorrectiveActionType,
        assigned_to: impl Into<String>,
        due_date: i64,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            action_type,
            status: ActionStatus::Pending,
            assigned_to: assigned_to.into(),
            due_date,
            completed_at: None,
        }
    }

    pub fn is_overdue(&self, now: i64) -> bool {
        self.status != ActionStatus::Completed && now > self.due_date
    }
}

// ── SafetyIncident ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SafetyIncident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: SafetyIncidentSeverity,
    pub category: SafetyIncidentCategory,
    pub status: SafetyIncidentStatus,
    pub reported_at: i64,
    pub resolved_at: Option<i64>,
    pub reported_by: String,
    pub assigned_to: Option<String>,
    pub root_cause: Option<String>,
    pub corrective_actions: Vec<CorrectiveAction>,
    pub affected_boundaries: Vec<String>,
}

impl SafetyIncident {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: SafetyIncidentSeverity,
        category: SafetyIncidentCategory,
        reported_by: impl Into<String>,
        reported_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            category,
            status: SafetyIncidentStatus::Open,
            reported_at,
            resolved_at: None,
            reported_by: reported_by.into(),
            assigned_to: None,
            root_cause: None,
            corrective_actions: Vec::new(),
            affected_boundaries: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_affected_boundaries(mut self, boundaries: Vec<String>) -> Self {
        self.affected_boundaries = boundaries;
        self
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self.status,
            SafetyIncidentStatus::Open | SafetyIncidentStatus::Investigating
        )
    }

    pub fn time_to_resolve_ms(&self) -> Option<i64> {
        self.resolved_at.map(|r| r - self.reported_at)
    }
}

// ── SafetyIncidentTracker ─────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SafetyIncidentTracker {
    incidents: Vec<SafetyIncident>,
}

impl SafetyIncidentTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn report(&mut self, incident: SafetyIncident) -> &SafetyIncident {
        self.incidents.push(incident);
        self.incidents.last().unwrap()
    }

    pub fn update_status(
        &mut self,
        id: &str,
        status: SafetyIncidentStatus,
        now: i64,
    ) -> bool {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == id) {
            if matches!(
                status,
                SafetyIncidentStatus::Resolved | SafetyIncidentStatus::Closed
            ) && inc.resolved_at.is_none()
            {
                inc.resolved_at = Some(now);
            }
            inc.status = status;
            true
        } else {
            false
        }
    }

    pub fn assign(&mut self, id: &str, assignee: &str) -> bool {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == id) {
            inc.assigned_to = Some(assignee.to_string());
            true
        } else {
            false
        }
    }

    pub fn set_root_cause(&mut self, id: &str, root_cause: &str) -> bool {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == id) {
            inc.root_cause = Some(root_cause.to_string());
            true
        } else {
            false
        }
    }

    pub fn add_corrective_action(
        &mut self,
        incident_id: &str,
        action: CorrectiveAction,
    ) -> bool {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            inc.corrective_actions.push(action);
            true
        } else {
            false
        }
    }

    pub fn open_incidents(&self) -> Vec<&SafetyIncident> {
        self.incidents.iter().filter(|i| i.is_open()).collect()
    }

    pub fn incidents_by_severity(
        &self,
        severity: &SafetyIncidentSeverity,
    ) -> Vec<&SafetyIncident> {
        self.incidents
            .iter()
            .filter(|i| &i.severity == severity)
            .collect()
    }

    pub fn mean_time_to_resolve_ms(&self) -> Option<f64> {
        let resolved: Vec<i64> = self
            .incidents
            .iter()
            .filter_map(|i| i.time_to_resolve_ms())
            .collect();
        if resolved.is_empty() {
            None
        } else {
            let sum: i64 = resolved.iter().sum();
            Some(sum as f64 / resolved.len() as f64)
        }
    }

    pub fn overdue_actions(&self, now: i64) -> Vec<(&str, &CorrectiveAction)> {
        let mut result = Vec::new();
        for inc in &self.incidents {
            for action in &inc.corrective_actions {
                if action.is_overdue(now) {
                    result.push((inc.id.as_str(), action));
                }
            }
        }
        result
    }

    pub fn incident_count(&self) -> usize {
        self.incidents.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_tracker_report_creates_incident() {
        let mut tracker = SafetyIncidentTracker::new();
        let inc = SafetyIncident::new(
            "inc-1", "Boundary breach",
            SafetyIncidentSeverity::Critical,
            SafetyIncidentCategory::BoundaryViolation,
            "system", 1000,
        );
        tracker.report(inc);
        assert_eq!(tracker.incident_count(), 1);
    }

    #[test]
    fn test_incident_tracker_update_status() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Test",
            SafetyIncidentSeverity::Minor,
            SafetyIncidentCategory::UnexpectedBehavior,
            "user", 1000,
        ));
        assert!(tracker.update_status("inc-1", SafetyIncidentStatus::Investigating, 1100));
        assert!(tracker.update_status("inc-1", SafetyIncidentStatus::Resolved, 2000));
        assert!(!tracker.update_status("nonexistent", SafetyIncidentStatus::Closed, 3000));
    }

    #[test]
    fn test_incident_tracker_assign() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Test",
            SafetyIncidentSeverity::Major,
            SafetyIncidentCategory::BiasDetected,
            "system", 1000,
        ));
        assert!(tracker.assign("inc-1", "alice"));
    }

    #[test]
    fn test_incident_tracker_set_root_cause() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Test",
            SafetyIncidentSeverity::Critical,
            SafetyIncidentCategory::DataLeakage,
            "system", 1000,
        ));
        assert!(tracker.set_root_cause("inc-1", "Missing input validation"));
    }

    #[test]
    fn test_incident_tracker_add_corrective_action() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Test",
            SafetyIncidentSeverity::Major,
            SafetyIncidentCategory::SystemFailure,
            "system", 1000,
        ));
        let action = CorrectiveAction::new(
            "ca-1", "Add input validation",
            CorrectiveActionType::Immediate, "dev-team", 5000,
        );
        assert!(tracker.add_corrective_action("inc-1", action));
    }

    #[test]
    fn test_incident_tracker_open_incidents() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Open",
            SafetyIncidentSeverity::Minor,
            SafetyIncidentCategory::UnexpectedBehavior,
            "system", 1000,
        ));
        tracker.report(SafetyIncident::new(
            "inc-2", "Will close",
            SafetyIncidentSeverity::Minor,
            SafetyIncidentCategory::UnexpectedBehavior,
            "system", 1000,
        ));
        tracker.update_status("inc-2", SafetyIncidentStatus::Closed, 2000);
        assert_eq!(tracker.open_incidents().len(), 1);
    }

    #[test]
    fn test_incident_tracker_incidents_by_severity() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Critical",
            SafetyIncidentSeverity::Critical,
            SafetyIncidentCategory::BoundaryViolation,
            "system", 1000,
        ));
        tracker.report(SafetyIncident::new(
            "inc-2", "Minor",
            SafetyIncidentSeverity::Minor,
            SafetyIncidentCategory::UnexpectedBehavior,
            "system", 1000,
        ));
        assert_eq!(
            tracker.incidents_by_severity(&SafetyIncidentSeverity::Critical).len(),
            1
        );
    }

    #[test]
    fn test_incident_tracker_mean_time_to_resolve() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "A",
            SafetyIncidentSeverity::Minor,
            SafetyIncidentCategory::UnexpectedBehavior,
            "system", 1000,
        ));
        tracker.report(SafetyIncident::new(
            "inc-2", "B",
            SafetyIncidentSeverity::Minor,
            SafetyIncidentCategory::UnexpectedBehavior,
            "system", 2000,
        ));
        tracker.update_status("inc-1", SafetyIncidentStatus::Resolved, 2000); // 1000ms
        tracker.update_status("inc-2", SafetyIncidentStatus::Resolved, 5000); // 3000ms
        let mttr = tracker.mean_time_to_resolve_ms().unwrap();
        assert!((mttr - 2000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_incident_tracker_overdue_actions() {
        let mut tracker = SafetyIncidentTracker::new();
        tracker.report(SafetyIncident::new(
            "inc-1", "Test",
            SafetyIncidentSeverity::Major,
            SafetyIncidentCategory::SystemFailure,
            "system", 1000,
        ));
        tracker.add_corrective_action(
            "inc-1",
            CorrectiveAction::new("ca-1", "Fix now", CorrectiveActionType::Immediate, "alice", 2000),
        );
        tracker.add_corrective_action(
            "inc-1",
            CorrectiveAction::new("ca-2", "Fix later", CorrectiveActionType::LongTerm, "bob", 10000),
        );
        let overdue = tracker.overdue_actions(5000);
        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0].1.id, "ca-1");
    }
}
