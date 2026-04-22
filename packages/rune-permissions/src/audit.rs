// ═══════════════════════════════════════════════════════════════════════
// Audit — Permission audit events for the RUNE governance ecosystem.
//
// Provides the standard PermissionsAuditEvent / PermissionsAuditLog
// interface on top of the existing PermissionEventType enum defined
// in store.rs.  This module brings rune-permissions in line with
// every other governance library's audit pattern.
// ═══════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

use crate::store::PermissionEventType;

// ── PermissionsAuditEvent ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsAuditEvent {
    pub event: PermissionEventType,
    pub actor: String,
    pub timestamp: i64,
    pub description: String,
}

impl PermissionsAuditEvent {
    pub fn new(
        event: PermissionEventType,
        actor: impl Into<String>,
        timestamp: i64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event,
            actor: actor.into(),
            timestamp,
            description: description.into(),
        }
    }
}

// ── PermissionsAuditLog ────────────────────────────────────────────

pub struct PermissionsAuditLog {
    events: Vec<PermissionsAuditEvent>,
}

impl PermissionsAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: PermissionsAuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[PermissionsAuditEvent] {
        &self.events
    }

    pub fn events_by_kind(&self, kind: &str) -> Vec<&PermissionsAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event.kind() == kind)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&PermissionsAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for PermissionsAuditLog {
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

    fn make_event(event_type: PermissionEventType) -> PermissionsAuditEvent {
        PermissionsAuditEvent::new(event_type, "test-actor", 1000, "test description")
    }

    #[test]
    fn new_audit_event() {
        let evt = PermissionsAuditEvent::new(
            PermissionEventType::RoleAssigned,
            "admin",
            42,
            "assigned manager role",
        );
        assert_eq!(evt.actor, "admin");
        assert_eq!(evt.timestamp, 42);
        assert_eq!(evt.description, "assigned manager role");
        assert_eq!(evt.event.type_name(), "RoleAssigned");
    }

    #[test]
    fn audit_log_record_and_count() {
        let mut log = PermissionsAuditLog::new();
        assert_eq!(log.event_count(), 0);

        log.record(make_event(PermissionEventType::RoleAssigned));
        log.record(make_event(PermissionEventType::GrantCreated));
        assert_eq!(log.event_count(), 2);
    }

    #[test]
    fn audit_log_events() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::AccessChecked));
        let events = log.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event.type_name(), "AccessChecked");
    }

    #[test]
    fn audit_log_events_by_kind_role() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::RoleAssigned));
        log.record(make_event(PermissionEventType::RoleRevoked));
        log.record(make_event(PermissionEventType::GrantCreated));
        let role_events = log.events_by_kind("role");
        assert_eq!(role_events.len(), 2);
    }

    #[test]
    fn audit_log_events_by_kind_grant() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::GrantCreated));
        log.record(make_event(PermissionEventType::GrantRevoked));
        log.record(make_event(PermissionEventType::AccessChecked));
        let grant_events = log.events_by_kind("grant");
        assert_eq!(grant_events.len(), 2);
    }

    #[test]
    fn audit_log_events_by_kind_access() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::AccessChecked));
        assert_eq!(log.events_by_kind("access").len(), 1);
    }

    #[test]
    fn audit_log_events_by_kind_registration() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::PermissionRegistered));
        log.record(make_event(PermissionEventType::SubjectRegistered));
        log.record(make_event(PermissionEventType::SubjectDeactivated));
        assert_eq!(log.events_by_kind("registration").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_snapshot() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::PermissionSnapshotCreated));
        log.record(make_event(PermissionEventType::PermissionSnapshotRestored));
        assert_eq!(log.events_by_kind("snapshot").len(), 2);
    }

    #[test]
    fn audit_log_events_by_kind_maintenance() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::BulkGrantExecuted));
        log.record(make_event(PermissionEventType::ExpiredGrantsCleaned));
        log.record(make_event(PermissionEventType::GrantIndexRebuilt));
        log.record(make_event(PermissionEventType::CacheInvalidated));
        assert_eq!(log.events_by_kind("maintenance").len(), 4);
    }

    #[test]
    fn audit_log_events_by_kind_analysis() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::PermissionSimulated));
        log.record(make_event(PermissionEventType::EffectivePermissionsQueried));
        log.record(make_event(PermissionEventType::LeastPrivilegeAnalyzed));
        assert_eq!(log.events_by_kind("analysis").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_delegation() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::DelegationCascadeRevoked));
        log.record(make_event(PermissionEventType::DelegationDepthChecked));
        log.record(make_event(PermissionEventType::TemporalDelegationCreated));
        assert_eq!(log.events_by_kind("delegation").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_sod() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::RoleConflictDetected));
        log.record(make_event(PermissionEventType::SodViolationDetected));
        log.record(make_event(PermissionEventType::SodPolicyAdded));
        assert_eq!(log.events_by_kind("sod").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_backend() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::PermissionBackendChanged {
            backend_type: "postgres".into(),
        }));
        log.record(make_event(PermissionEventType::PolicyDefinitionStored {
            policy_id: "p1".into(),
        }));
        log.record(make_event(PermissionEventType::RoleDefinitionStored {
            role_id: "r1".into(),
        }));
        assert_eq!(log.events_by_kind("backend").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_decision() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::AuthorizationPermit {
            matched_policies: "pol-1".into(),
        }));
        log.record(make_event(PermissionEventType::AuthorizationDeny {
            reason: "no matching policy".into(),
        }));
        log.record(make_event(PermissionEventType::DecisionEngineInvoked {
            engine_id: "rbac".into(),
        }));
        assert_eq!(log.events_by_kind("decision").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_export() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::PolicyExported {
            format: "rego".into(),
        }));
        log.record(make_event(PermissionEventType::PolicyExportFailed {
            format: "cedar".into(),
            reason: "unsupported".into(),
        }));
        assert_eq!(log.events_by_kind("export").len(), 2);
    }

    #[test]
    fn audit_log_events_by_kind_streaming() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::DecisionSubscriberRegistered {
            subscriber_id: "s1".into(),
        }));
        log.record(make_event(PermissionEventType::DecisionSubscriberRemoved {
            subscriber_id: "s1".into(),
        }));
        log.record(make_event(PermissionEventType::DecisionEventPublished {
            event_type: "permit".into(),
        }));
        assert_eq!(log.events_by_kind("streaming").len(), 3);
    }

    #[test]
    fn audit_log_events_by_kind_external() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::ExternalEvaluatorInvoked {
            evaluator_id: "opa".into(),
        }));
        log.record(make_event(PermissionEventType::RoleProviderQueried {
            provider_id: "ldap".into(),
        }));
        assert_eq!(log.events_by_kind("external").len(), 2);
    }

    #[test]
    fn audit_log_events_by_kind_capability() {
        let mut log = PermissionsAuditLog::new();
        log.record(make_event(PermissionEventType::CapabilityTokenVerified {
            token_id: "tok1".into(),
        }));
        log.record(make_event(PermissionEventType::CapabilityTokenRejected {
            token_id: "tok2".into(),
            reason: "expired".into(),
        }));
        assert_eq!(log.events_by_kind("capability").len(), 2);
    }

    #[test]
    fn audit_log_since() {
        let mut log = PermissionsAuditLog::new();
        log.record(PermissionsAuditEvent::new(
            PermissionEventType::RoleAssigned,
            "actor",
            100,
            "early event",
        ));
        log.record(PermissionsAuditEvent::new(
            PermissionEventType::GrantCreated,
            "actor",
            200,
            "later event",
        ));
        log.record(PermissionsAuditEvent::new(
            PermissionEventType::AccessChecked,
            "actor",
            300,
            "latest event",
        ));
        let recent = log.since(200);
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn audit_log_default() {
        let log = PermissionsAuditLog::default();
        assert_eq!(log.event_count(), 0);
    }

    #[test]
    fn kind_covers_all_l1_variants() {
        // Verify all L1 fieldless variants return non-empty kind
        let variants = vec![
            PermissionEventType::RoleAssigned,
            PermissionEventType::RoleRevoked,
            PermissionEventType::GrantCreated,
            PermissionEventType::GrantRevoked,
            PermissionEventType::AccessChecked,
            PermissionEventType::PermissionRegistered,
            PermissionEventType::SubjectRegistered,
            PermissionEventType::SubjectDeactivated,
        ];
        for v in variants {
            assert!(!v.kind().is_empty(), "kind() empty for {}", v.type_name());
        }
    }

    #[test]
    fn kind_covers_all_l2_variants() {
        let variants = vec![
            PermissionEventType::PermissionSnapshotCreated,
            PermissionEventType::PermissionSnapshotRestored,
            PermissionEventType::BulkGrantExecuted,
            PermissionEventType::ExpiredGrantsCleaned,
            PermissionEventType::GrantIndexRebuilt,
            PermissionEventType::CacheInvalidated,
            PermissionEventType::PermissionSimulated,
            PermissionEventType::EffectivePermissionsQueried,
            PermissionEventType::LeastPrivilegeAnalyzed,
            PermissionEventType::DelegationCascadeRevoked,
            PermissionEventType::DelegationDepthChecked,
            PermissionEventType::TemporalDelegationCreated,
            PermissionEventType::RoleConflictDetected,
            PermissionEventType::SodViolationDetected,
            PermissionEventType::SodPolicyAdded,
        ];
        for v in variants {
            assert!(!v.kind().is_empty(), "kind() empty for {}", v.type_name());
        }
    }

    #[test]
    fn kind_covers_all_l3_variants() {
        let variants: Vec<PermissionEventType> = vec![
            PermissionEventType::PermissionBackendChanged { backend_type: "mem".into() },
            PermissionEventType::PolicyDefinitionStored { policy_id: "p".into() },
            PermissionEventType::PolicyDefinitionRemoved { policy_id: "p".into() },
            PermissionEventType::RoleDefinitionStored { role_id: "r".into() },
            PermissionEventType::RoleDefinitionRemoved { role_id: "r".into() },
            PermissionEventType::PermissionGrantRecordCreated { grant_id: "g".into() },
            PermissionEventType::PermissionGrantRecordRevoked { grant_id: "g".into() },
            PermissionEventType::AuthorizationDecisionMade { outcome: "permit".into() },
            PermissionEventType::AuthorizationPermit { matched_policies: "p1".into() },
            PermissionEventType::AuthorizationDeny { reason: "denied".into() },
            PermissionEventType::AuthorizationIndeterminate { reason: "unknown".into() },
            PermissionEventType::AuthorizationNotApplicable,
            PermissionEventType::DecisionEngineInvoked { engine_id: "rbac".into() },
            PermissionEventType::PolicyExported { format: "rego".into() },
            PermissionEventType::PolicyExportFailed { format: "x".into(), reason: "y".into() },
            PermissionEventType::DecisionSubscriberRegistered { subscriber_id: "s".into() },
            PermissionEventType::DecisionSubscriberRemoved { subscriber_id: "s".into() },
            PermissionEventType::DecisionEventPublished { event_type: "e".into() },
            PermissionEventType::ExternalEvaluatorInvoked { evaluator_id: "opa".into() },
            PermissionEventType::ExternalEvaluatorFailed { evaluator_id: "o".into(), reason: "r".into() },
            PermissionEventType::RoleProviderQueried { provider_id: "ldap".into() },
            PermissionEventType::CapabilityTokenVerified { token_id: "t".into() },
            PermissionEventType::CapabilityTokenRejected { token_id: "t".into(), reason: "exp".into() },
        ];
        for v in variants {
            assert!(!v.kind().is_empty(), "kind() empty for {}", v.type_name());
        }
    }

    #[test]
    fn is_streaming_event_classifier() {
        assert!(PermissionEventType::DecisionSubscriberRegistered {
            subscriber_id: "s".into()
        }.is_streaming_event());
        assert!(!PermissionEventType::RoleAssigned.is_streaming_event());
    }
}
