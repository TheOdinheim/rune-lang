// ═══════════════════════════════════════════════════════════════════════
// Coordination — Multi-agent coordination and communication governance.
// Governs who can talk to whom and how collective decisions are made.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent::AgentId;
use crate::error::AgentError;

// ── MessageType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    TaskAssignment,
    StatusUpdate,
    DataShare,
    Query,
    Response,
    Alert,
    Coordination,
    Custom(String),
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskAssignment => write!(f, "TaskAssignment"),
            Self::StatusUpdate => write!(f, "StatusUpdate"),
            Self::DataShare => write!(f, "DataShare"),
            Self::Query => write!(f, "Query"),
            Self::Response => write!(f, "Response"),
            Self::Alert => write!(f, "Alert"),
            Self::Coordination => write!(f, "Coordination"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── AgentMessage ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub id: String,
    pub sender: AgentId,
    pub receiver: AgentId,
    pub message_type: MessageType,
    pub content: String,
    pub encrypted: bool,
    pub timestamp: i64,
    pub correlation_id: Option<String>,
    pub reply_to: Option<String>,
}

// ── CoordinationPolicy ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CoordinationPolicy {
    pub id: String,
    pub name: String,
    pub allowed_pairs: Vec<(AgentId, AgentId)>,
    pub denied_pairs: Vec<(AgentId, AgentId)>,
    pub max_message_size: usize,
    pub require_encryption: bool,
    pub max_messages_per_minute: Option<u64>,
    pub metadata: HashMap<String, String>,
}

impl CoordinationPolicy {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            allowed_pairs: Vec::new(),
            denied_pairs: Vec::new(),
            max_message_size: 65536,
            require_encryption: false,
            max_messages_per_minute: None,
            metadata: HashMap::new(),
        }
    }

    pub fn open(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name) // No restrictions
    }

    pub fn with_denied_pairs(mut self, pairs: Vec<(AgentId, AgentId)>) -> Self {
        self.denied_pairs = pairs;
        self
    }

    pub fn with_allowed_pairs(mut self, pairs: Vec<(AgentId, AgentId)>) -> Self {
        self.allowed_pairs = pairs;
        self
    }
}

// ── CoordinationResult ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CoordinationResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

// ── CoordinationGovernor ─────────────────────────────────────────────

pub struct CoordinationGovernor {
    policy: CoordinationPolicy,
    messages: Vec<AgentMessage>,
    message_counter: u64,
}

impl CoordinationGovernor {
    pub fn new(policy: CoordinationPolicy) -> Self {
        Self {
            policy,
            messages: Vec::new(),
            message_counter: 0,
        }
    }

    pub fn check_communication(
        &self,
        sender: &AgentId,
        receiver: &AgentId,
    ) -> CoordinationResult {
        // Check denied pairs (both directions)
        let is_denied = self.policy.denied_pairs.iter().any(|(a, b)| {
            (a == sender && b == receiver) || (a == receiver && b == sender)
        });
        if is_denied {
            return CoordinationResult {
                allowed: false,
                reason: Some(format!("Communication denied between {} and {}", sender, receiver)),
            };
        }

        // Check allowed pairs (if non-empty, pair must be listed)
        if !self.policy.allowed_pairs.is_empty() {
            let is_allowed = self.policy.allowed_pairs.iter().any(|(a, b)| {
                (a == sender && b == receiver) || (a == receiver && b == sender)
            });
            if !is_allowed {
                return CoordinationResult {
                    allowed: false,
                    reason: Some(format!(
                        "Communication not in allowed pairs for {} and {}",
                        sender, receiver
                    )),
                };
            }
        }

        CoordinationResult {
            allowed: true,
            reason: None,
        }
    }

    pub fn send_message(
        &mut self,
        sender: &AgentId,
        receiver: &AgentId,
        message_type: MessageType,
        content: &str,
        encrypted: bool,
        now: i64,
    ) -> Result<AgentMessage, AgentError> {
        let check = self.check_communication(sender, receiver);
        if !check.allowed {
            return Err(AgentError::CommunicationDenied {
                sender: sender.0.clone(),
                receiver: receiver.0.clone(),
                reason: check.reason.unwrap_or_else(|| "denied".into()),
            });
        }

        self.message_counter += 1;
        let msg = AgentMessage {
            id: format!("msg_{:08x}", self.message_counter),
            sender: sender.clone(),
            receiver: receiver.clone(),
            message_type,
            content: content.into(),
            encrypted,
            timestamp: now,
            correlation_id: None,
            reply_to: None,
        };
        self.messages.push(msg.clone());
        Ok(msg)
    }

    pub fn messages_between(
        &self,
        agent_a: &AgentId,
        agent_b: &AgentId,
    ) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| {
                (&m.sender == agent_a && &m.receiver == agent_b)
                    || (&m.sender == agent_b && &m.receiver == agent_a)
            })
            .collect()
    }

    pub fn messages_for_agent(&self, agent_id: &AgentId) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| &m.sender == agent_id || &m.receiver == agent_id)
            .collect()
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn messages_since(&self, timestamp: i64) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| m.timestamp >= timestamp)
            .collect()
    }
}

// ── VoteDecision ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDecision {
    Approve,
    Reject,
    Abstain,
}

impl fmt::Display for VoteDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approve => write!(f, "Approve"),
            Self::Reject => write!(f, "Reject"),
            Self::Abstain => write!(f, "Abstain"),
        }
    }
}

// ── Vote ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub decision: VoteDecision,
    pub confidence: f64,
    pub reasoning: String,
    pub cast_at: i64,
}

// ── CollectiveStatus ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectiveStatus {
    Open,
    Decided { outcome: String },
    Expired,
}

impl fmt::Display for CollectiveStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::Decided { outcome } => write!(f, "Decided: {outcome}"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

// ── CollectiveDecision ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CollectiveDecision {
    pub id: String,
    pub description: String,
    pub participants: Vec<AgentId>,
    pub votes: HashMap<AgentId, Vote>,
    pub required_majority: f64,
    pub status: CollectiveStatus,
    pub created_at: i64,
    pub deadline: Option<i64>,
}

impl CollectiveDecision {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        participants: Vec<AgentId>,
        required_majority: f64,
        now: i64,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            participants,
            votes: HashMap::new(),
            required_majority,
            status: CollectiveStatus::Open,
            created_at: now,
            deadline: None,
        }
    }

    pub fn cast_vote(&mut self, agent_id: AgentId, vote: Vote) {
        self.votes.insert(agent_id, vote);
    }
}

// ── VoteTally ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VoteTally {
    pub approve: usize,
    pub reject: usize,
    pub abstain: usize,
    pub total_participants: usize,
    pub majority_reached: bool,
    pub outcome: Option<VoteDecision>,
}

pub fn tally_votes(decision: &CollectiveDecision) -> VoteTally {
    let approve = decision
        .votes
        .values()
        .filter(|v| v.decision == VoteDecision::Approve)
        .count();
    let reject = decision
        .votes
        .values()
        .filter(|v| v.decision == VoteDecision::Reject)
        .count();
    let abstain = decision
        .votes
        .values()
        .filter(|v| v.decision == VoteDecision::Abstain)
        .count();
    let total = decision.participants.len();
    // Majority calculated over non-abstaining votes
    let voting = approve + reject;
    let (majority_reached, outcome) = if voting == 0 {
        (false, None)
    } else {
        let approve_frac = approve as f64 / voting as f64;
        let reject_frac = reject as f64 / voting as f64;
        if approve_frac >= decision.required_majority {
            (true, Some(VoteDecision::Approve))
        } else if reject_frac >= decision.required_majority {
            (true, Some(VoteDecision::Reject))
        } else {
            (false, None)
        }
    };

    VoteTally {
        approve,
        reject,
        abstain,
        total_participants: total,
        majority_reached,
        outcome,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_communication_allows_no_restrictions() {
        let gov = CoordinationGovernor::new(CoordinationPolicy::open("p1", "open"));
        let result = gov.check_communication(&AgentId::new("a1"), &AgentId::new("a2"));
        assert!(result.allowed);
    }

    #[test]
    fn test_check_communication_denies_denied_pair() {
        let policy = CoordinationPolicy::new("p1", "restricted")
            .with_denied_pairs(vec![(AgentId::new("a1"), AgentId::new("a2"))]);
        let gov = CoordinationGovernor::new(policy);
        let result = gov.check_communication(&AgentId::new("a1"), &AgentId::new("a2"));
        assert!(!result.allowed);
        // Also check reverse direction
        let result2 = gov.check_communication(&AgentId::new("a2"), &AgentId::new("a1"));
        assert!(!result2.allowed);
    }

    #[test]
    fn test_check_communication_denies_unlisted_when_allowed_set() {
        let policy = CoordinationPolicy::new("p1", "allowlist")
            .with_allowed_pairs(vec![(AgentId::new("a1"), AgentId::new("a2"))]);
        let gov = CoordinationGovernor::new(policy);
        assert!(gov.check_communication(&AgentId::new("a1"), &AgentId::new("a2")).allowed);
        assert!(!gov.check_communication(&AgentId::new("a1"), &AgentId::new("a3")).allowed);
    }

    #[test]
    fn test_send_message_creates_and_records() {
        let mut gov = CoordinationGovernor::new(CoordinationPolicy::open("p1", "open"));
        let msg = gov.send_message(
            &AgentId::new("a1"),
            &AgentId::new("a2"),
            MessageType::Query,
            "hello?",
            false,
            1000,
        ).unwrap();
        assert_eq!(msg.content, "hello?");
        assert_eq!(gov.message_count(), 1);
    }

    #[test]
    fn test_send_message_fails_denied() {
        let policy = CoordinationPolicy::new("p1", "deny")
            .with_denied_pairs(vec![(AgentId::new("a1"), AgentId::new("a2"))]);
        let mut gov = CoordinationGovernor::new(policy);
        let result = gov.send_message(
            &AgentId::new("a1"),
            &AgentId::new("a2"),
            MessageType::Query,
            "hello",
            false,
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_messages_between() {
        let mut gov = CoordinationGovernor::new(CoordinationPolicy::open("p1", "open"));
        gov.send_message(&AgentId::new("a1"), &AgentId::new("a2"), MessageType::Query, "q", false, 1000).unwrap();
        gov.send_message(&AgentId::new("a2"), &AgentId::new("a1"), MessageType::Response, "r", false, 1001).unwrap();
        gov.send_message(&AgentId::new("a1"), &AgentId::new("a3"), MessageType::Alert, "a", false, 1002).unwrap();
        assert_eq!(gov.messages_between(&AgentId::new("a1"), &AgentId::new("a2")).len(), 2);
    }

    #[test]
    fn test_messages_for_agent() {
        let mut gov = CoordinationGovernor::new(CoordinationPolicy::open("p1", "open"));
        gov.send_message(&AgentId::new("a1"), &AgentId::new("a2"), MessageType::Query, "q", false, 1000).unwrap();
        gov.send_message(&AgentId::new("a3"), &AgentId::new("a1"), MessageType::Alert, "a", false, 1001).unwrap();
        assert_eq!(gov.messages_for_agent(&AgentId::new("a1")).len(), 2);
    }

    #[test]
    fn test_message_type_display() {
        let types = vec![
            MessageType::TaskAssignment,
            MessageType::StatusUpdate,
            MessageType::DataShare,
            MessageType::Query,
            MessageType::Response,
            MessageType::Alert,
            MessageType::Coordination,
            MessageType::Custom("special".into()),
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_collective_decision_majority_reached() {
        let mut cd = CollectiveDecision::new(
            "cd1", "deploy?",
            vec![AgentId::new("a1"), AgentId::new("a2"), AgentId::new("a3")],
            0.5, 1000,
        );
        cd.cast_vote(AgentId::new("a1"), Vote { decision: VoteDecision::Approve, confidence: 0.9, reasoning: "go".into(), cast_at: 1001 });
        cd.cast_vote(AgentId::new("a2"), Vote { decision: VoteDecision::Approve, confidence: 0.8, reasoning: "go".into(), cast_at: 1002 });
        cd.cast_vote(AgentId::new("a3"), Vote { decision: VoteDecision::Reject, confidence: 0.7, reasoning: "no".into(), cast_at: 1003 });
        let tally = tally_votes(&cd);
        assert!(tally.majority_reached);
        assert_eq!(tally.outcome, Some(VoteDecision::Approve));
    }

    #[test]
    fn test_collective_decision_no_majority() {
        let mut cd = CollectiveDecision::new(
            "cd1", "deploy?",
            vec![AgentId::new("a1"), AgentId::new("a2"), AgentId::new("a3"), AgentId::new("a4")],
            0.75, 1000,
        );
        cd.cast_vote(AgentId::new("a1"), Vote { decision: VoteDecision::Approve, confidence: 0.9, reasoning: "yes".into(), cast_at: 1001 });
        cd.cast_vote(AgentId::new("a2"), Vote { decision: VoteDecision::Reject, confidence: 0.8, reasoning: "no".into(), cast_at: 1002 });
        let tally = tally_votes(&cd);
        assert!(!tally.majority_reached);
    }

    #[test]
    fn test_tally_votes_counts() {
        let mut cd = CollectiveDecision::new(
            "cd1", "test",
            vec![AgentId::new("a1"), AgentId::new("a2"), AgentId::new("a3")],
            0.5, 1000,
        );
        cd.cast_vote(AgentId::new("a1"), Vote { decision: VoteDecision::Approve, confidence: 0.9, reasoning: "y".into(), cast_at: 1001 });
        cd.cast_vote(AgentId::new("a2"), Vote { decision: VoteDecision::Reject, confidence: 0.7, reasoning: "n".into(), cast_at: 1002 });
        cd.cast_vote(AgentId::new("a3"), Vote { decision: VoteDecision::Abstain, confidence: 0.5, reasoning: "idk".into(), cast_at: 1003 });
        let tally = tally_votes(&cd);
        assert_eq!(tally.approve, 1);
        assert_eq!(tally.reject, 1);
        assert_eq!(tally.abstain, 1);
        assert_eq!(tally.total_participants, 3);
    }

    #[test]
    fn test_vote_decision_display() {
        assert_eq!(VoteDecision::Approve.to_string(), "Approve");
        assert_eq!(VoteDecision::Reject.to_string(), "Reject");
        assert_eq!(VoteDecision::Abstain.to_string(), "Abstain");
    }

    #[test]
    fn test_collective_status_display() {
        let statuses = vec![
            CollectiveStatus::Open,
            CollectiveStatus::Decided { outcome: "approved".into() },
            CollectiveStatus::Expired,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 3);
    }

    #[test]
    fn test_abstain_does_not_count_toward_majority() {
        let mut cd = CollectiveDecision::new(
            "cd1", "test",
            vec![AgentId::new("a1"), AgentId::new("a2"), AgentId::new("a3")],
            0.5, 1000,
        );
        cd.cast_vote(AgentId::new("a1"), Vote { decision: VoteDecision::Approve, confidence: 0.9, reasoning: "y".into(), cast_at: 1001 });
        cd.cast_vote(AgentId::new("a2"), Vote { decision: VoteDecision::Abstain, confidence: 0.5, reasoning: "x".into(), cast_at: 1002 });
        cd.cast_vote(AgentId::new("a3"), Vote { decision: VoteDecision::Abstain, confidence: 0.5, reasoning: "x".into(), cast_at: 1003 });
        let tally = tally_votes(&cd);
        // 1 approve out of 1 voting = 100% > 50% required
        assert!(tally.majority_reached);
        assert_eq!(tally.outcome, Some(VoteDecision::Approve));
    }
}
