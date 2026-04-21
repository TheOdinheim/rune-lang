// ═══════════════════════════════════════════════════════════════════════
// Incident Response Workflow — NIST SP 800-61 aligned incident
// lifecycle management.
//
// IncidentState uses different variant names from the existing
// IncidentStatus (L1) to avoid collision while covering the NIST
// SP 800-61 lifecycle phases.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::SecurityError;

// ── IncidentState ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IncidentState {
    Declared,
    Triaging,
    Containing,
    Eradicating,
    Recovering,
    PostIncident,
    Closed,
}

impl IncidentState {
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Valid next states per NIST SP 800-61 lifecycle.
    pub fn valid_transitions(&self) -> Vec<IncidentState> {
        match self {
            Self::Declared => vec![Self::Triaging],
            Self::Triaging => vec![Self::Containing],
            Self::Containing => vec![Self::Eradicating],
            Self::Eradicating => vec![Self::Recovering],
            Self::Recovering => vec![Self::PostIncident],
            Self::PostIncident => vec![Self::Closed],
            Self::Closed => vec![],
        }
    }

    pub fn can_transition_to(&self, target: &IncidentState) -> bool {
        self.valid_transitions().contains(target)
    }
}

impl fmt::Display for IncidentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ResponseActionType ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseActionType {
    Containment,
    Eradication,
    Recovery,
    Communication,
    Investigation,
    Documentation,
}

impl fmt::Display for ResponseActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── IncidentResponseAction ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentResponseAction {
    pub action_id: String,
    pub incident_id: String,
    pub actor: String,
    pub action_type: ResponseActionType,
    pub description: String,
    pub executed_at: i64,
    pub outcome: String,
}

// ── IncidentDeclaration ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncidentDeclaration {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub declared_by: String,
    pub declared_at: i64,
    pub affected_systems: Vec<String>,
}

// ── ManagedIncident ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ManagedIncident {
    pub incident_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub state: IncidentState,
    pub declared_at: i64,
    pub closed_at: Option<i64>,
    pub declared_by: String,
    pub affected_systems: Vec<String>,
    pub actions: Vec<IncidentResponseAction>,
    pub lessons_learned: Option<String>,
}

// ── IncidentResponseWorkflow trait ────────────────────────────────

pub trait IncidentResponseWorkflow {
    fn declare_incident(&mut self, declaration: IncidentDeclaration) -> Result<String, SecurityError>;
    fn update_incident_state(&mut self, incident_id: &str, new_state: IncidentState) -> Result<(), SecurityError>;
    fn record_response_action(&mut self, action: IncidentResponseAction) -> Result<(), SecurityError>;
    fn record_containment(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError>;
    fn record_eradication(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError>;
    fn record_recovery(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError>;
    fn record_lessons_learned(&mut self, incident_id: &str, lessons: &str) -> Result<(), SecurityError>;
    fn close_incident(&mut self, incident_id: &str, at: i64) -> Result<(), SecurityError>;
    fn list_active_incidents(&self) -> Vec<&ManagedIncident>;
    fn list_incidents_by_severity(&self, severity: &str) -> Vec<&ManagedIncident>;
    fn workflow_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryIncidentResponseWorkflow ──────────────────────────────

pub struct InMemoryIncidentResponseWorkflow {
    id: String,
    incidents: HashMap<String, ManagedIncident>,
    next_id: u64,
}

impl InMemoryIncidentResponseWorkflow {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            incidents: HashMap::new(),
            next_id: 0,
        }
    }

    fn get_mut(&mut self, incident_id: &str) -> Result<&mut ManagedIncident, SecurityError> {
        self.incidents.get_mut(incident_id)
            .ok_or_else(|| SecurityError::IncidentNotFound(incident_id.to_string()))
    }
}

impl IncidentResponseWorkflow for InMemoryIncidentResponseWorkflow {
    fn declare_incident(&mut self, declaration: IncidentDeclaration) -> Result<String, SecurityError> {
        self.next_id += 1;
        let incident_id = format!("ir-inc-{}", self.next_id);
        let incident = ManagedIncident {
            incident_id: incident_id.clone(),
            title: declaration.title,
            description: declaration.description,
            severity: declaration.severity,
            state: IncidentState::Declared,
            declared_at: declaration.declared_at,
            closed_at: None,
            declared_by: declaration.declared_by,
            affected_systems: declaration.affected_systems,
            actions: Vec::new(),
            lessons_learned: None,
        };
        self.incidents.insert(incident_id.clone(), incident);
        Ok(incident_id)
    }

    fn update_incident_state(&mut self, incident_id: &str, new_state: IncidentState) -> Result<(), SecurityError> {
        let incident = self.get_mut(incident_id)?;
        incident.state = new_state;
        Ok(())
    }

    fn record_response_action(&mut self, action: IncidentResponseAction) -> Result<(), SecurityError> {
        let incident = self.get_mut(&action.incident_id)?;
        incident.actions.push(action);
        Ok(())
    }

    fn record_containment(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError> {
        self.record_response_action(IncidentResponseAction {
            action_id: format!("{incident_id}-contain"),
            incident_id: incident_id.to_string(),
            actor: actor.to_string(),
            action_type: ResponseActionType::Containment,
            description: description.to_string(),
            executed_at: at,
            outcome: "containment recorded".to_string(),
        })
    }

    fn record_eradication(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError> {
        self.record_response_action(IncidentResponseAction {
            action_id: format!("{incident_id}-eradicate"),
            incident_id: incident_id.to_string(),
            actor: actor.to_string(),
            action_type: ResponseActionType::Eradication,
            description: description.to_string(),
            executed_at: at,
            outcome: "eradication recorded".to_string(),
        })
    }

    fn record_recovery(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError> {
        self.record_response_action(IncidentResponseAction {
            action_id: format!("{incident_id}-recover"),
            incident_id: incident_id.to_string(),
            actor: actor.to_string(),
            action_type: ResponseActionType::Recovery,
            description: description.to_string(),
            executed_at: at,
            outcome: "recovery recorded".to_string(),
        })
    }

    fn record_lessons_learned(&mut self, incident_id: &str, lessons: &str) -> Result<(), SecurityError> {
        let incident = self.get_mut(incident_id)?;
        incident.lessons_learned = Some(lessons.to_string());
        Ok(())
    }

    fn close_incident(&mut self, incident_id: &str, at: i64) -> Result<(), SecurityError> {
        let incident = self.get_mut(incident_id)?;
        incident.state = IncidentState::Closed;
        incident.closed_at = Some(at);
        Ok(())
    }

    fn list_active_incidents(&self) -> Vec<&ManagedIncident> {
        self.incidents.values().filter(|i| i.state.is_active()).collect()
    }

    fn list_incidents_by_severity(&self, severity: &str) -> Vec<&ManagedIncident> {
        self.incidents.values().filter(|i| i.severity == severity).collect()
    }

    fn workflow_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NistSp80061IncidentResponseWorkflow ───────────────────────────
// Enforces NIST SP 800-61 state transition ordering.

pub struct NistSp80061IncidentResponseWorkflow {
    inner: InMemoryIncidentResponseWorkflow,
}

impl NistSp80061IncidentResponseWorkflow {
    pub fn new(id: &str) -> Self {
        Self {
            inner: InMemoryIncidentResponseWorkflow::new(id),
        }
    }
}

impl IncidentResponseWorkflow for NistSp80061IncidentResponseWorkflow {
    fn declare_incident(&mut self, declaration: IncidentDeclaration) -> Result<String, SecurityError> {
        self.inner.declare_incident(declaration)
    }

    fn update_incident_state(&mut self, incident_id: &str, new_state: IncidentState) -> Result<(), SecurityError> {
        let incident = self.inner.incidents.get(incident_id)
            .ok_or_else(|| SecurityError::IncidentNotFound(incident_id.to_string()))?;

        if !incident.state.can_transition_to(&new_state) {
            return Err(SecurityError::InvalidStatusTransition {
                from: incident.state.to_string(),
                to: new_state.to_string(),
            });
        }
        self.inner.update_incident_state(incident_id, new_state)
    }

    fn record_response_action(&mut self, action: IncidentResponseAction) -> Result<(), SecurityError> {
        self.inner.record_response_action(action)
    }

    fn record_containment(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError> {
        self.inner.record_containment(incident_id, description, actor, at)
    }

    fn record_eradication(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError> {
        self.inner.record_eradication(incident_id, description, actor, at)
    }

    fn record_recovery(&mut self, incident_id: &str, description: &str, actor: &str, at: i64) -> Result<(), SecurityError> {
        self.inner.record_recovery(incident_id, description, actor, at)
    }

    fn record_lessons_learned(&mut self, incident_id: &str, lessons: &str) -> Result<(), SecurityError> {
        self.inner.record_lessons_learned(incident_id, lessons)
    }

    fn close_incident(&mut self, incident_id: &str, at: i64) -> Result<(), SecurityError> {
        let incident = self.inner.incidents.get(incident_id)
            .ok_or_else(|| SecurityError::IncidentNotFound(incident_id.to_string()))?;
        if !incident.state.can_transition_to(&IncidentState::Closed) {
            return Err(SecurityError::InvalidStatusTransition {
                from: incident.state.to_string(),
                to: "Closed".to_string(),
            });
        }
        self.inner.close_incident(incident_id, at)
    }

    fn list_active_incidents(&self) -> Vec<&ManagedIncident> {
        self.inner.list_active_incidents()
    }

    fn list_incidents_by_severity(&self, severity: &str) -> Vec<&ManagedIncident> {
        self.inner.list_incidents_by_severity(severity)
    }

    fn workflow_id(&self) -> &str { self.inner.workflow_id() }
    fn is_active(&self) -> bool { true }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_declaration() -> IncidentDeclaration {
        IncidentDeclaration {
            title: "Data breach".to_string(),
            description: "PII exposed".to_string(),
            severity: "Critical".to_string(),
            declared_by: "soc-analyst".to_string(),
            declared_at: 1000,
            affected_systems: vec!["db-prod".to_string()],
        }
    }

    #[test]
    fn test_declare_and_list_active() {
        let mut wf = InMemoryIncidentResponseWorkflow::new("wf-1");
        let id = wf.declare_incident(make_declaration()).unwrap();
        let active = wf.list_active_incidents();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].incident_id, id);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut wf = InMemoryIncidentResponseWorkflow::new("wf-1");
        let id = wf.declare_incident(make_declaration()).unwrap();
        wf.update_incident_state(&id, IncidentState::Triaging).unwrap();
        wf.update_incident_state(&id, IncidentState::Containing).unwrap();
        wf.record_containment(&id, "isolated server", "responder", 2000).unwrap();
        wf.update_incident_state(&id, IncidentState::Eradicating).unwrap();
        wf.record_eradication(&id, "removed malware", "responder", 3000).unwrap();
        wf.update_incident_state(&id, IncidentState::Recovering).unwrap();
        wf.record_recovery(&id, "restored from backup", "responder", 4000).unwrap();
        wf.update_incident_state(&id, IncidentState::PostIncident).unwrap();
        wf.record_lessons_learned(&id, "improve monitoring").unwrap();
        wf.close_incident(&id, 5000).unwrap();
        assert!(wf.list_active_incidents().is_empty());
    }

    #[test]
    fn test_list_by_severity() {
        let mut wf = InMemoryIncidentResponseWorkflow::new("wf-1");
        wf.declare_incident(make_declaration()).unwrap();
        let mut low_decl = make_declaration();
        low_decl.severity = "Low".to_string();
        wf.declare_incident(low_decl).unwrap();
        assert_eq!(wf.list_incidents_by_severity("Critical").len(), 1);
    }

    #[test]
    fn test_nist_enforces_order() {
        let mut wf = NistSp80061IncidentResponseWorkflow::new("nist-1");
        let id = wf.declare_incident(make_declaration()).unwrap();
        // Cannot skip Triaging and go straight to Containing
        let result = wf.update_incident_state(&id, IncidentState::Containing);
        assert!(result.is_err());
        // Must go through Triaging first
        wf.update_incident_state(&id, IncidentState::Triaging).unwrap();
        wf.update_incident_state(&id, IncidentState::Containing).unwrap();
    }

    #[test]
    fn test_nist_cannot_close_before_post_incident() {
        let mut wf = NistSp80061IncidentResponseWorkflow::new("nist-1");
        let id = wf.declare_incident(make_declaration()).unwrap();
        assert!(wf.close_incident(&id, 5000).is_err());
    }

    #[test]
    fn test_nist_full_valid_lifecycle() {
        let mut wf = NistSp80061IncidentResponseWorkflow::new("nist-1");
        let id = wf.declare_incident(make_declaration()).unwrap();
        for state in [
            IncidentState::Triaging,
            IncidentState::Containing,
            IncidentState::Eradicating,
            IncidentState::Recovering,
            IncidentState::PostIncident,
        ] {
            wf.update_incident_state(&id, state).unwrap();
        }
        wf.close_incident(&id, 9000).unwrap();
    }

    #[test]
    fn test_incident_state_display() {
        assert_eq!(IncidentState::Declared.to_string(), "Declared");
        assert_eq!(IncidentState::Closed.to_string(), "Closed");
    }

    #[test]
    fn test_incident_state_valid_transitions() {
        let transitions = IncidentState::Declared.valid_transitions();
        assert_eq!(transitions, vec![IncidentState::Triaging]);
        assert!(IncidentState::Closed.valid_transitions().is_empty());
    }

    #[test]
    fn test_workflow_metadata() {
        let wf = InMemoryIncidentResponseWorkflow::new("wf-1");
        assert_eq!(wf.workflow_id(), "wf-1");
        assert!(wf.is_active());
    }

    #[test]
    fn test_response_action_type_display() {
        assert_eq!(ResponseActionType::Containment.to_string(), "Containment");
        assert_eq!(ResponseActionType::Documentation.to_string(), "Documentation");
    }
}
