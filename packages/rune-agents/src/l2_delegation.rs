// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Agent task delegation with approval gates.
//
// Structured task delegation with capability verification, delegation
// chains, deadline tracking, and completion metrics.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::AgentError;

// ── TaskPriority ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for TaskPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── L2DelegationStatus ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2DelegationStatus {
    Pending,
    Accepted,
    InProgress,
    Completed,
    Failed,
    Rejected,
    TimedOut,
}

impl fmt::Display for L2DelegationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "Pending",
            Self::Accepted => "Accepted",
            Self::InProgress => "InProgress",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Rejected => "Rejected",
            Self::TimedOut => "TimedOut",
        };
        f.write_str(s)
    }
}

// ── DelegatedTask ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DelegatedTask {
    pub task_id: String,
    pub description: String,
    pub delegator: String,
    pub delegatee: String,
    pub required_capabilities: Vec<String>,
    pub priority: TaskPriority,
    pub status: L2DelegationStatus,
    pub delegated_at: i64,
    pub deadline: Option<i64>,
    pub completed_at: Option<i64>,
    pub result: Option<String>,
}

impl DelegatedTask {
    pub fn new(
        task_id: impl Into<String>,
        description: impl Into<String>,
        delegator: impl Into<String>,
        delegatee: impl Into<String>,
        priority: TaskPriority,
        delegated_at: i64,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            description: description.into(),
            delegator: delegator.into(),
            delegatee: delegatee.into(),
            required_capabilities: Vec::new(),
            priority,
            status: L2DelegationStatus::Pending,
            delegated_at,
            deadline: None,
            completed_at: None,
            result: None,
        }
    }

    pub fn with_deadline(mut self, deadline: i64) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn with_required_capabilities(mut self, caps: Vec<String>) -> Self {
        self.required_capabilities = caps;
        self
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            L2DelegationStatus::Completed
                | L2DelegationStatus::Failed
                | L2DelegationStatus::Rejected
                | L2DelegationStatus::TimedOut
        )
    }
}

// ── L2DelegationManager ───────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2DelegationManager {
    tasks: HashMap<String, DelegatedTask>,
    delegation_chains: HashMap<String, Vec<String>>,
}

impl L2DelegationManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn delegate(&mut self, task: DelegatedTask) -> &DelegatedTask {
        let task_id = task.task_id.clone();
        let delegator = task.delegator.clone();
        self.delegation_chains
            .entry(task_id.clone())
            .or_insert_with(|| vec![delegator]);
        self.tasks.insert(task_id.clone(), task);
        self.tasks.get(&task_id).unwrap()
    }

    pub fn accept_task(&mut self, task_id: &str, _now: i64) -> Result<(), AgentError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| AgentError::L2TaskNotFound(task_id.to_string()))?;
        if task.status != L2DelegationStatus::Pending {
            return Err(AgentError::InvalidOperation(format!(
                "Task {task_id} is not pending"
            )));
        }
        task.status = L2DelegationStatus::Accepted;
        Ok(())
    }

    pub fn reject_task(
        &mut self,
        task_id: &str,
        _reason: &str,
        _now: i64,
    ) -> Result<(), AgentError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| AgentError::L2TaskNotFound(task_id.to_string()))?;
        task.status = L2DelegationStatus::Rejected;
        Ok(())
    }

    pub fn complete_task(
        &mut self,
        task_id: &str,
        result: &str,
        now: i64,
    ) -> Result<(), AgentError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| AgentError::L2TaskNotFound(task_id.to_string()))?;
        task.status = L2DelegationStatus::Completed;
        task.completed_at = Some(now);
        task.result = Some(result.to_string());
        Ok(())
    }

    pub fn fail_task(
        &mut self,
        task_id: &str,
        reason: &str,
        now: i64,
    ) -> Result<(), AgentError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| AgentError::L2TaskNotFound(task_id.to_string()))?;
        task.status = L2DelegationStatus::Failed;
        task.completed_at = Some(now);
        task.result = Some(reason.to_string());
        Ok(())
    }

    pub fn redelegate(
        &mut self,
        task_id: &str,
        new_delegatee: &str,
        _now: i64,
    ) -> Result<(), AgentError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| AgentError::L2TaskNotFound(task_id.to_string()))?;
        let old_delegatee = task.delegatee.clone();
        task.delegatee = new_delegatee.to_string();
        task.status = L2DelegationStatus::Pending;
        self.delegation_chains
            .entry(task_id.to_string())
            .or_default()
            .push(old_delegatee);
        Ok(())
    }

    pub fn check_deadlines(&mut self, now: i64) -> Vec<String> {
        let mut timed_out = Vec::new();
        for task in self.tasks.values_mut() {
            if !task.is_terminal() {
                if let Some(deadline) = task.deadline {
                    if now > deadline {
                        task.status = L2DelegationStatus::TimedOut;
                        task.completed_at = Some(now);
                        timed_out.push(task.task_id.clone());
                    }
                }
            }
        }
        timed_out
    }

    pub fn tasks_for_agent(&self, agent_id: &str) -> Vec<&DelegatedTask> {
        self.tasks
            .values()
            .filter(|t| t.delegatee == agent_id)
            .collect()
    }

    pub fn tasks_by_agent(&self, agent_id: &str) -> Vec<&DelegatedTask> {
        self.tasks
            .values()
            .filter(|t| t.delegator == agent_id)
            .collect()
    }

    pub fn delegation_depth(&self, task_id: &str) -> usize {
        self.delegation_chains
            .get(task_id)
            .map(|chain| {
                if chain.is_empty() {
                    0
                } else {
                    chain.len() - 1
                }
            })
            .unwrap_or(0)
    }

    pub fn completion_rate(&self) -> f64 {
        let terminal: Vec<_> = self.tasks.values().filter(|t| t.is_terminal()).collect();
        if terminal.is_empty() {
            return 0.0;
        }
        let completed = terminal
            .iter()
            .filter(|t| t.status == L2DelegationStatus::Completed)
            .count();
        completed as f64 / terminal.len() as f64
    }

    pub fn average_completion_time_ms(&self) -> Option<f64> {
        let times: Vec<i64> = self
            .tasks
            .values()
            .filter(|t| t.status == L2DelegationStatus::Completed)
            .filter_map(|t| t.completed_at.map(|c| c - t.delegated_at))
            .collect();
        if times.is_empty() {
            None
        } else {
            let sum: i64 = times.iter().sum();
            Some(sum as f64 / times.len() as f64)
        }
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegate_creates_task() {
        let mut mgr = L2DelegationManager::new();
        let task = DelegatedTask::new("t-1", "Analyze data", "a1", "a2", TaskPriority::High, 1000);
        mgr.delegate(task);
        assert_eq!(mgr.task_count(), 1);
    }

    #[test]
    fn test_accept_task_changes_status() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "Task", "a1", "a2", TaskPriority::Medium, 1000));
        mgr.accept_task("t-1", 2000).unwrap();
        assert_eq!(mgr.tasks.get("t-1").unwrap().status, L2DelegationStatus::Accepted);
    }

    #[test]
    fn test_complete_task_records_result() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "Task", "a1", "a2", TaskPriority::Medium, 1000));
        mgr.complete_task("t-1", "success output", 3000).unwrap();
        let task = mgr.tasks.get("t-1").unwrap();
        assert_eq!(task.status, L2DelegationStatus::Completed);
        assert_eq!(task.result.as_deref(), Some("success output"));
        assert_eq!(task.completed_at, Some(3000));
    }

    #[test]
    fn test_reject_task_sets_status() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "Task", "a1", "a2", TaskPriority::Low, 1000));
        mgr.reject_task("t-1", "too complex", 2000).unwrap();
        assert_eq!(mgr.tasks.get("t-1").unwrap().status, L2DelegationStatus::Rejected);
    }

    #[test]
    fn test_redelegate_changes_delegatee_and_chain() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "Task", "a1", "a2", TaskPriority::High, 1000));
        mgr.redelegate("t-1", "a3", 2000).unwrap();
        assert_eq!(mgr.tasks.get("t-1").unwrap().delegatee, "a3");
        assert_eq!(mgr.delegation_depth("t-1"), 1);
    }

    #[test]
    fn test_delegation_depth_tracks_redelegation() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "Task", "a1", "a2", TaskPriority::High, 1000));
        mgr.redelegate("t-1", "a3", 2000).unwrap();
        mgr.redelegate("t-1", "a4", 3000).unwrap();
        assert_eq!(mgr.delegation_depth("t-1"), 2);
    }

    #[test]
    fn test_check_deadlines_detects_overdue() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(
            DelegatedTask::new("t-1", "Task", "a1", "a2", TaskPriority::High, 1000)
                .with_deadline(5000),
        );
        let overdue = mgr.check_deadlines(6000);
        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0], "t-1");
    }

    #[test]
    fn test_tasks_for_agent() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "A", "a1", "a2", TaskPriority::Low, 1000));
        mgr.delegate(DelegatedTask::new("t-2", "B", "a1", "a3", TaskPriority::Low, 1000));
        mgr.delegate(DelegatedTask::new("t-3", "C", "a3", "a2", TaskPriority::Low, 1000));
        assert_eq!(mgr.tasks_for_agent("a2").len(), 2);
        assert_eq!(mgr.tasks_by_agent("a1").len(), 2);
    }

    #[test]
    fn test_completion_rate() {
        let mut mgr = L2DelegationManager::new();
        mgr.delegate(DelegatedTask::new("t-1", "A", "a1", "a2", TaskPriority::Low, 1000));
        mgr.delegate(DelegatedTask::new("t-2", "B", "a1", "a3", TaskPriority::Low, 1000));
        mgr.complete_task("t-1", "done", 2000).unwrap();
        mgr.fail_task("t-2", "error", 2000).unwrap();
        assert!((mgr.completion_rate() - 0.5).abs() < f64::EPSILON);
    }
}
