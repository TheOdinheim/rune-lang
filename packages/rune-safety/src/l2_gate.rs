// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Human-in-the-loop gate management.
//
// Structured human oversight gates that require human approval before
// AI actions proceed, with timeout and multi-approver support.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::SafetyError;

// ── GateType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateType {
    PreExecution,
    PostExecution,
    Periodic,
    ExceptionBased,
}

impl fmt::Display for GateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PreExecution => "PreExecution",
            Self::PostExecution => "PostExecution",
            Self::Periodic => "Periodic",
            Self::ExceptionBased => "ExceptionBased",
        };
        f.write_str(s)
    }
}

// ── ApprovalGate ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ApprovalGate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub gate_type: GateType,
    pub required_approvers: usize,
    pub timeout_ms: i64,
    pub auto_deny_on_timeout: bool,
    pub created_at: i64,
}

impl ApprovalGate {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        gate_type: GateType,
        required_approvers: usize,
        timeout_ms: i64,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            gate_type,
            required_approvers,
            timeout_ms,
            auto_deny_on_timeout: true,
            created_at,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_auto_deny(mut self, auto_deny: bool) -> Self {
        self.auto_deny_on_timeout = auto_deny;
        self
    }
}

// ── GateStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    Pending,
    Approved,
    Denied,
    TimedOut,
    Escalated,
}

impl fmt::Display for GateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Denied => "Denied",
            Self::TimedOut => "TimedOut",
            Self::Escalated => "Escalated",
        };
        f.write_str(s)
    }
}

// ── ApproverDecision ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverDecision {
    Approve,
    Deny,
    Abstain,
}

impl fmt::Display for ApproverDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Approve => "Approve",
            Self::Deny => "Deny",
            Self::Abstain => "Abstain",
        };
        f.write_str(s)
    }
}

// ── ApproverRecord ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ApproverRecord {
    pub name: String,
    pub decision: ApproverDecision,
    pub decided_at: i64,
    pub reason: Option<String>,
}

// ── GateApproval ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GateApproval {
    pub gate_id: String,
    pub decision_id: String,
    pub status: GateStatus,
    pub approvers: Vec<ApproverRecord>,
    pub requested_at: i64,
    pub decided_at: Option<i64>,
    pub timeout_at: i64,
}

impl GateApproval {
    pub fn is_pending(&self) -> bool {
        self.status == GateStatus::Pending
    }
}

// ── GateManager ───────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct GateManager {
    gates: HashMap<String, ApprovalGate>,
    pending_approvals: Vec<GateApproval>,
    completed_approvals: Vec<GateApproval>,
}

impl GateManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_gate(&mut self, gate: ApprovalGate) {
        self.gates.insert(gate.id.clone(), gate);
    }

    pub fn request_approval(
        &mut self,
        gate_id: &str,
        decision_id: &str,
        now: i64,
    ) -> Result<&GateApproval, SafetyError> {
        let gate = self
            .gates
            .get(gate_id)
            .ok_or_else(|| SafetyError::GateNotFound(gate_id.to_string()))?;

        let approval = GateApproval {
            gate_id: gate_id.to_string(),
            decision_id: decision_id.to_string(),
            status: GateStatus::Pending,
            approvers: Vec::new(),
            requested_at: now,
            decided_at: None,
            timeout_at: now + gate.timeout_ms,
        };

        self.pending_approvals.push(approval);
        Ok(self.pending_approvals.last().unwrap())
    }

    pub fn record_decision(
        &mut self,
        gate_id: &str,
        decision_id: &str,
        approver: &str,
        decision: ApproverDecision,
        reason: Option<&str>,
        now: i64,
    ) -> Result<GateStatus, SafetyError> {
        let gate = self
            .gates
            .get(gate_id)
            .ok_or_else(|| SafetyError::GateNotFound(gate_id.to_string()))?
            .clone();

        let approval_idx = self
            .pending_approvals
            .iter()
            .position(|a| a.gate_id == gate_id && a.decision_id == decision_id)
            .ok_or_else(|| SafetyError::ApprovalNotFound(decision_id.to_string()))?;

        let approval = &mut self.pending_approvals[approval_idx];

        approval.approvers.push(ApproverRecord {
            name: approver.to_string(),
            decision: decision.clone(),
            decided_at: now,
            reason: reason.map(|s| s.to_string()),
        });

        // If any deny, status becomes Denied
        if decision == ApproverDecision::Deny {
            approval.status = GateStatus::Denied;
            approval.decided_at = Some(now);
            let completed = self.pending_approvals.remove(approval_idx);
            self.completed_approvals.push(completed);
            return Ok(GateStatus::Denied);
        }

        // Count approvals (exclude abstentions)
        let approve_count = approval
            .approvers
            .iter()
            .filter(|a| a.decision == ApproverDecision::Approve)
            .count();

        if approve_count >= gate.required_approvers {
            approval.status = GateStatus::Approved;
            approval.decided_at = Some(now);
            let completed = self.pending_approvals.remove(approval_idx);
            self.completed_approvals.push(completed);
            return Ok(GateStatus::Approved);
        }

        Ok(GateStatus::Pending)
    }

    pub fn check_timeouts(&mut self, now: i64) -> Vec<String> {
        let mut timed_out = Vec::new();
        let mut indices_to_remove = Vec::new();

        for (i, approval) in self.pending_approvals.iter_mut().enumerate() {
            if now >= approval.timeout_at {
                let gate = self.gates.get(&approval.gate_id);
                let auto_deny = gate.map(|g| g.auto_deny_on_timeout).unwrap_or(true);
                approval.status = if auto_deny {
                    GateStatus::TimedOut
                } else {
                    GateStatus::Escalated
                };
                approval.decided_at = Some(now);
                timed_out.push(approval.decision_id.clone());
                indices_to_remove.push(i);
            }
        }

        // Remove in reverse order to preserve indices
        for i in indices_to_remove.into_iter().rev() {
            let completed = self.pending_approvals.remove(i);
            self.completed_approvals.push(completed);
        }

        timed_out
    }

    pub fn pending_count(&self) -> usize {
        self.pending_approvals.len()
    }

    pub fn approval_rate(&self) -> f64 {
        if self.completed_approvals.is_empty() {
            return 0.0;
        }
        let approved = self
            .completed_approvals
            .iter()
            .filter(|a| a.status == GateStatus::Approved)
            .count();
        approved as f64 / self.completed_approvals.len() as f64
    }

    pub fn average_decision_time_ms(&self) -> Option<f64> {
        let times: Vec<i64> = self
            .completed_approvals
            .iter()
            .filter_map(|a| a.decided_at.map(|d| d - a.requested_at))
            .collect();
        if times.is_empty() {
            None
        } else {
            let sum: i64 = times.iter().sum();
            Some(sum as f64 / times.len() as f64)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_manager() -> GateManager {
        let mut mgr = GateManager::new();
        mgr.register_gate(ApprovalGate::new(
            "gate-1", "Pre-execution gate", GateType::PreExecution, 2, 60000, 1000,
        ));
        mgr
    }

    #[test]
    fn test_gate_manager_register_and_request_approval() {
        let mut mgr = setup_manager();
        let approval = mgr.request_approval("gate-1", "dec-1", 2000).unwrap();
        assert_eq!(approval.status, GateStatus::Pending);
        assert_eq!(approval.timeout_at, 62000);
        assert_eq!(mgr.pending_count(), 1);
    }

    #[test]
    fn test_gate_manager_approve_when_enough_approvers() {
        let mut mgr = setup_manager();
        mgr.request_approval("gate-1", "dec-1", 2000).unwrap();
        let status = mgr
            .record_decision("gate-1", "dec-1", "alice", ApproverDecision::Approve, None, 3000)
            .unwrap();
        assert_eq!(status, GateStatus::Pending); // need 2 approvers

        let status = mgr
            .record_decision("gate-1", "dec-1", "bob", ApproverDecision::Approve, None, 4000)
            .unwrap();
        assert_eq!(status, GateStatus::Approved);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_gate_manager_deny_on_first_deny() {
        let mut mgr = setup_manager();
        mgr.request_approval("gate-1", "dec-1", 2000).unwrap();
        let status = mgr
            .record_decision(
                "gate-1", "dec-1", "alice", ApproverDecision::Deny,
                Some("Too risky"), 3000,
            )
            .unwrap();
        assert_eq!(status, GateStatus::Denied);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_gate_manager_check_timeouts() {
        let mut mgr = setup_manager();
        mgr.request_approval("gate-1", "dec-1", 2000).unwrap();
        // timeout_at = 2000 + 60000 = 62000
        let timed_out = mgr.check_timeouts(70000);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], "dec-1");
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_gate_manager_pending_count() {
        let mut mgr = setup_manager();
        mgr.request_approval("gate-1", "dec-1", 2000).unwrap();
        mgr.request_approval("gate-1", "dec-2", 3000).unwrap();
        assert_eq!(mgr.pending_count(), 2);
    }

    #[test]
    fn test_gate_manager_approval_rate() {
        let mut mgr = setup_manager();
        mgr.request_approval("gate-1", "dec-1", 1000).unwrap();
        mgr.request_approval("gate-1", "dec-2", 1000).unwrap();
        // Approve dec-1 (need 2 approvers)
        mgr.record_decision("gate-1", "dec-1", "alice", ApproverDecision::Approve, None, 2000).unwrap();
        mgr.record_decision("gate-1", "dec-1", "bob", ApproverDecision::Approve, None, 2000).unwrap();
        // Deny dec-2
        mgr.record_decision("gate-1", "dec-2", "alice", ApproverDecision::Deny, None, 3000).unwrap();
        assert!((mgr.approval_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gate_manager_average_decision_time() {
        let mut mgr = setup_manager();
        mgr.request_approval("gate-1", "dec-1", 1000).unwrap();
        mgr.request_approval("gate-1", "dec-2", 2000).unwrap();
        mgr.record_decision("gate-1", "dec-1", "alice", ApproverDecision::Deny, None, 2000).unwrap();
        mgr.record_decision("gate-1", "dec-2", "bob", ApproverDecision::Deny, None, 6000).unwrap();
        // dec-1: 2000-1000=1000, dec-2: 6000-2000=4000 → avg 2500
        let avg = mgr.average_decision_time_ms().unwrap();
        assert!((avg - 2500.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gate_approval_timeout_with_auto_deny() {
        let mut mgr = GateManager::new();
        mgr.register_gate(
            ApprovalGate::new("gate-ad", "Auto-deny gate", GateType::PreExecution, 1, 5000, 1000)
                .with_auto_deny(true),
        );
        mgr.register_gate(
            ApprovalGate::new("gate-esc", "Escalate gate", GateType::PreExecution, 1, 5000, 1000)
                .with_auto_deny(false),
        );
        mgr.request_approval("gate-ad", "dec-ad", 2000).unwrap();
        mgr.request_approval("gate-esc", "dec-esc", 2000).unwrap();

        mgr.check_timeouts(10000);
        // Auto-deny gate → TimedOut, escalate gate → Escalated
        let ad = mgr.completed_approvals.iter().find(|a| a.decision_id == "dec-ad").unwrap();
        assert_eq!(ad.status, GateStatus::TimedOut);
        let esc = mgr.completed_approvals.iter().find(|a| a.decision_id == "dec-esc").unwrap();
        assert_eq!(esc.status, GateStatus::Escalated);
    }
}
