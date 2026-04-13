// ═══════════════════════════════════════════════════════════════════════
// Lifecycle — Policy lifecycle management.
//
// Draft → UnderReview → Approved → Active → Deprecated → Retired
// with valid transition enforcement and history tracking.
// ═══════════════════════════════════════════════════════════════════════

use crate::error::PolicyExtError;
use crate::policy::*;

// ── LifecycleTransition ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LifecycleTransition {
    pub policy_id: ManagedPolicyId,
    pub from_status: PolicyStatus,
    pub to_status: PolicyStatus,
    pub transitioned_by: String,
    pub transitioned_at: i64,
    pub reason: String,
    pub approval: Option<String>,
}

// ── LifecycleManager ────────────────────────────────────────────────

pub struct LifecycleManager {
    transitions: Vec<LifecycleTransition>,
}

impl LifecycleManager {
    pub fn new() -> Self {
        Self {
            transitions: Vec::new(),
        }
    }

    pub fn transition(
        &mut self,
        policy: &mut ManagedPolicy,
        to: PolicyStatus,
        by: &str,
        reason: &str,
        now: i64,
    ) -> Result<(), PolicyExtError> {
        if !self.is_valid_transition(&policy.status, &to) {
            return Err(PolicyExtError::InvalidTransition {
                from: policy.status.to_string(),
                to: to.to_string(),
            });
        }

        let from = policy.status.clone();
        policy.status = to.clone();
        policy.updated_at = now;

        self.transitions.push(LifecycleTransition {
            policy_id: policy.id.clone(),
            from_status: from,
            to_status: to,
            transitioned_by: by.into(),
            transitioned_at: now,
            reason: reason.into(),
            approval: None,
        });

        Ok(())
    }

    pub fn transition_with_approval(
        &mut self,
        policy: &mut ManagedPolicy,
        to: PolicyStatus,
        by: &str,
        approver: &str,
        reason: &str,
        now: i64,
    ) -> Result<(), PolicyExtError> {
        if !self.is_valid_transition(&policy.status, &to) {
            return Err(PolicyExtError::InvalidTransition {
                from: policy.status.to_string(),
                to: to.to_string(),
            });
        }

        let from = policy.status.clone();
        policy.status = to.clone();
        policy.updated_at = now;
        policy.approver = Some(approver.into());

        self.transitions.push(LifecycleTransition {
            policy_id: policy.id.clone(),
            from_status: from,
            to_status: to,
            transitioned_by: by.into(),
            transitioned_at: now,
            reason: reason.into(),
            approval: Some(approver.into()),
        });

        Ok(())
    }

    pub fn history(&self, policy_id: &ManagedPolicyId) -> Vec<&LifecycleTransition> {
        self.transitions
            .iter()
            .filter(|t| t.policy_id == *policy_id)
            .collect()
    }

    pub fn valid_transitions(&self, status: &PolicyStatus) -> Vec<PolicyStatus> {
        match status {
            PolicyStatus::Draft => vec![PolicyStatus::UnderReview],
            PolicyStatus::UnderReview => vec![PolicyStatus::Approved, PolicyStatus::Draft],
            PolicyStatus::Approved => vec![PolicyStatus::Active, PolicyStatus::Draft],
            PolicyStatus::Active => vec![PolicyStatus::Suspended, PolicyStatus::Deprecated],
            PolicyStatus::Suspended => vec![PolicyStatus::Active, PolicyStatus::Deprecated],
            PolicyStatus::Deprecated => vec![PolicyStatus::Retired],
            PolicyStatus::Retired => vec![], // terminal
        }
    }

    pub fn is_valid_transition(&self, from: &PolicyStatus, to: &PolicyStatus) -> bool {
        self.valid_transitions(from).contains(to)
    }

    pub fn policies_needing_review<'a>(
        &self,
        store: &'a ManagedPolicyStore,
        now: i64,
    ) -> Vec<&'a ManagedPolicy> {
        store.policies_due_review(now)
    }

    pub fn time_in_status(&self, policy_id: &ManagedPolicyId, status: &PolicyStatus) -> Option<i64> {
        let transitions: Vec<&LifecycleTransition> = self
            .transitions
            .iter()
            .filter(|t| t.policy_id == *policy_id)
            .collect();

        let mut total = 0i64;
        for i in 0..transitions.len() {
            if transitions[i].to_status == *status {
                // Find when it left this status
                let entered = transitions[i].transitioned_at;
                let exited = transitions
                    .get(i + 1)
                    .map(|t| t.transitioned_at)
                    .unwrap_or(entered); // still in this status
                total += exited - entered;
            }
        }

        if total > 0 { Some(total) } else { None }
    }
}

impl Default for LifecycleManager {
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

    fn draft_policy() -> ManagedPolicy {
        ManagedPolicy::new("p1", "Test", PolicyDomain::AccessControl, "team", 1000)
    }

    #[test]
    fn test_draft_to_under_review() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        mgr.transition(&mut p, PolicyStatus::UnderReview, "alice", "ready for review", 2000)
            .unwrap();
        assert_eq!(p.status, PolicyStatus::UnderReview);
    }

    #[test]
    fn test_under_review_to_approved() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        mgr.transition(&mut p, PolicyStatus::UnderReview, "alice", "submit", 2000)
            .unwrap();
        mgr.transition(&mut p, PolicyStatus::Approved, "bob", "looks good", 3000)
            .unwrap();
        assert_eq!(p.status, PolicyStatus::Approved);
    }

    #[test]
    fn test_approved_to_active() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        mgr.transition(&mut p, PolicyStatus::UnderReview, "a", "r", 2000).unwrap();
        mgr.transition(&mut p, PolicyStatus::Approved, "b", "r", 3000).unwrap();
        mgr.transition(&mut p, PolicyStatus::Active, "c", "deploy", 4000).unwrap();
        assert_eq!(p.status, PolicyStatus::Active);
    }

    #[test]
    fn test_active_to_suspended() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        p.status = PolicyStatus::Active;
        mgr.transition(&mut p, PolicyStatus::Suspended, "a", "emergency", 5000)
            .unwrap();
        assert_eq!(p.status, PolicyStatus::Suspended);
    }

    #[test]
    fn test_active_to_deprecated() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        p.status = PolicyStatus::Active;
        mgr.transition(&mut p, PolicyStatus::Deprecated, "a", "replacing", 5000)
            .unwrap();
        assert_eq!(p.status, PolicyStatus::Deprecated);
    }

    #[test]
    fn test_deprecated_to_retired() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        p.status = PolicyStatus::Deprecated;
        mgr.transition(&mut p, PolicyStatus::Retired, "a", "done", 6000)
            .unwrap();
        assert_eq!(p.status, PolicyStatus::Retired);
    }

    #[test]
    fn test_retired_is_terminal() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        p.status = PolicyStatus::Retired;
        let result = mgr.transition(&mut p, PolicyStatus::Active, "a", "reactivate", 7000);
        assert!(matches!(result, Err(PolicyExtError::InvalidTransition { .. })));
    }

    #[test]
    fn test_draft_to_active_fails() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        let result = mgr.transition(&mut p, PolicyStatus::Active, "a", "skip", 2000);
        assert!(matches!(result, Err(PolicyExtError::InvalidTransition { .. })));
    }

    #[test]
    fn test_active_to_draft_fails() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        p.status = PolicyStatus::Active;
        let result = mgr.transition(&mut p, PolicyStatus::Draft, "a", "revert", 5000);
        assert!(matches!(result, Err(PolicyExtError::InvalidTransition { .. })));
    }

    #[test]
    fn test_valid_transitions_for_each_status() {
        let mgr = LifecycleManager::new();
        assert_eq!(mgr.valid_transitions(&PolicyStatus::Draft), vec![PolicyStatus::UnderReview]);
        assert_eq!(
            mgr.valid_transitions(&PolicyStatus::UnderReview),
            vec![PolicyStatus::Approved, PolicyStatus::Draft]
        );
        assert_eq!(
            mgr.valid_transitions(&PolicyStatus::Approved),
            vec![PolicyStatus::Active, PolicyStatus::Draft]
        );
        assert_eq!(
            mgr.valid_transitions(&PolicyStatus::Active),
            vec![PolicyStatus::Suspended, PolicyStatus::Deprecated]
        );
        assert!(mgr.valid_transitions(&PolicyStatus::Retired).is_empty());
    }

    #[test]
    fn test_history() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        mgr.transition(&mut p, PolicyStatus::UnderReview, "a", "r", 2000).unwrap();
        mgr.transition(&mut p, PolicyStatus::Approved, "b", "r", 3000).unwrap();
        let history = mgr.history(&ManagedPolicyId::new("p1"));
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_transition_with_approval() {
        let mut mgr = LifecycleManager::new();
        let mut p = draft_policy();
        mgr.transition(&mut p, PolicyStatus::UnderReview, "alice", "submit", 2000)
            .unwrap();
        mgr.transition_with_approval(
            &mut p,
            PolicyStatus::Approved,
            "bob",
            "carol",
            "approved",
            3000,
        )
        .unwrap();
        assert_eq!(p.approver, Some("carol".into()));
        let history = mgr.history(&ManagedPolicyId::new("p1"));
        assert_eq!(history[1].approval, Some("carol".into()));
    }

    #[test]
    fn test_policies_needing_review() {
        let mgr = LifecycleManager::new();
        let mut store = ManagedPolicyStore::new();
        let mut p = draft_policy();
        p.status = PolicyStatus::Active;
        p.review_interval_days = Some(30);
        p.last_reviewed = Some(1000);
        store.add(p).unwrap();
        let due = mgr.policies_needing_review(&store, 3_000_000);
        assert_eq!(due.len(), 1);
    }
}
