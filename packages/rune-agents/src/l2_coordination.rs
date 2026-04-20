// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Multi-agent coordination protocols.
//
// Structured coordination protocols for multi-agent systems with
// defined interaction patterns, sessions, and timeout management.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::AgentError;

// ── ProtocolType ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ProtocolType {
    LeaderFollower { leader: String },
    Consensus { quorum: usize },
    Pipeline { stages: Vec<String> },
    Broadcast,
    RequestResponse,
    Auction { reserve_price: String },
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::LeaderFollower { .. } => "LeaderFollower",
            Self::Consensus { .. } => "Consensus",
            Self::Pipeline { .. } => "Pipeline",
            Self::Broadcast => "Broadcast",
            Self::RequestResponse => "RequestResponse",
            Self::Auction { .. } => "Auction",
        };
        f.write_str(s)
    }
}

// ── L2CoordinationProtocol ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2CoordinationProtocol {
    pub id: String,
    pub name: String,
    pub protocol_type: ProtocolType,
    pub participants: Vec<String>,
    pub max_participants: Option<usize>,
    pub timeout_ms: i64,
    pub created_at: i64,
}

impl L2CoordinationProtocol {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        protocol_type: ProtocolType,
        timeout_ms: i64,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            protocol_type,
            participants: Vec::new(),
            max_participants: None,
            timeout_ms,
            created_at,
        }
    }

    pub fn with_participants(mut self, participants: Vec<String>) -> Self {
        self.participants = participants;
        self
    }

    pub fn with_max_participants(mut self, max: usize) -> Self {
        self.max_participants = Some(max);
        self
    }
}

// ── SessionStatus ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Active => "Active",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::TimedOut => "TimedOut",
            Self::Cancelled => "Cancelled",
        };
        f.write_str(s)
    }
}

// ── L2MessageType ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2MessageType {
    Propose,
    Accept,
    Reject,
    Inform,
    Query,
    Delegate,
    Acknowledge,
}

impl fmt::Display for L2MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Propose => "Propose",
            Self::Accept => "Accept",
            Self::Reject => "Reject",
            Self::Inform => "Inform",
            Self::Query => "Query",
            Self::Delegate => "Delegate",
            Self::Acknowledge => "Acknowledge",
        };
        f.write_str(s)
    }
}

// ── CoordinationMessage ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CoordinationMessage {
    pub from_agent: String,
    pub to_agent: Option<String>,
    pub message_type: L2MessageType,
    pub payload: String,
    pub timestamp: i64,
}

// ── L2CoordinationSession ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2CoordinationSession {
    pub session_id: String,
    pub protocol_id: String,
    pub status: SessionStatus,
    pub participants: Vec<String>,
    pub messages: Vec<CoordinationMessage>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub timeout_at: i64,
}

impl L2CoordinationSession {
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

// ── L2CoordinationManager ─────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2CoordinationManager {
    protocols: HashMap<String, L2CoordinationProtocol>,
    sessions: HashMap<String, L2CoordinationSession>,
}

impl L2CoordinationManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_protocol(&mut self, protocol: L2CoordinationProtocol) {
        self.protocols.insert(protocol.id.clone(), protocol);
    }

    pub fn start_session(
        &mut self,
        protocol_id: &str,
        session_id: &str,
        now: i64,
    ) -> Result<&L2CoordinationSession, AgentError> {
        let protocol = self
            .protocols
            .get(protocol_id)
            .ok_or_else(|| AgentError::ProtocolNotFound(protocol_id.to_string()))?;

        let session = L2CoordinationSession {
            session_id: session_id.to_string(),
            protocol_id: protocol_id.to_string(),
            status: SessionStatus::Active,
            participants: protocol.participants.clone(),
            messages: Vec::new(),
            started_at: now,
            completed_at: None,
            timeout_at: now + protocol.timeout_ms,
        };

        self.sessions.insert(session_id.to_string(), session);
        Ok(self.sessions.get(session_id).unwrap())
    }

    pub fn send_message(
        &mut self,
        session_id: &str,
        message: CoordinationMessage,
    ) -> Result<(), AgentError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id.to_string()))?;

        if session.status != SessionStatus::Active {
            return Err(AgentError::InvalidOperation(format!(
                "Session {session_id} is not active"
            )));
        }

        session.messages.push(message);
        Ok(())
    }

    pub fn complete_session(
        &mut self,
        session_id: &str,
        now: i64,
    ) -> Result<(), AgentError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id.to_string()))?;
        session.status = SessionStatus::Completed;
        session.completed_at = Some(now);
        Ok(())
    }

    pub fn active_sessions(&self) -> Vec<&L2CoordinationSession> {
        self.sessions
            .values()
            .filter(|s| s.status == SessionStatus::Active)
            .collect()
    }

    pub fn sessions_for_agent(&self, agent_id: &str) -> Vec<&L2CoordinationSession> {
        self.sessions
            .values()
            .filter(|s| s.participants.iter().any(|p| p == agent_id))
            .collect()
    }

    pub fn check_timeouts(&mut self, now: i64) -> Vec<String> {
        let mut timed_out = Vec::new();
        for session in self.sessions.values_mut() {
            if session.status == SessionStatus::Active && now >= session.timeout_at {
                session.status = SessionStatus::TimedOut;
                session.completed_at = Some(now);
                timed_out.push(session.session_id.clone());
            }
        }
        timed_out
    }

    pub fn protocol_count(&self) -> usize {
        self.protocols.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_manager() -> L2CoordinationManager {
        let mut mgr = L2CoordinationManager::new();
        mgr.register_protocol(
            L2CoordinationProtocol::new(
                "p-1", "Consensus protocol",
                ProtocolType::Consensus { quorum: 3 }, 60000, 1000,
            )
            .with_participants(vec!["a1".into(), "a2".into(), "a3".into()]),
        );
        mgr
    }

    #[test]
    fn test_register_protocol_and_start_session() {
        let mut mgr = setup_manager();
        let session = mgr.start_session("p-1", "s-1", 2000).unwrap();
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.participants.len(), 3);
    }

    #[test]
    fn test_send_message_appends() {
        let mut mgr = setup_manager();
        mgr.start_session("p-1", "s-1", 2000).unwrap();
        mgr.send_message("s-1", CoordinationMessage {
            from_agent: "a1".into(),
            to_agent: Some("a2".into()),
            message_type: L2MessageType::Propose,
            payload: "task plan".into(),
            timestamp: 2100,
        }).unwrap();
        let session = mgr.sessions.get("s-1").unwrap();
        assert_eq!(session.message_count(), 1);
    }

    #[test]
    fn test_complete_session_sets_status() {
        let mut mgr = setup_manager();
        mgr.start_session("p-1", "s-1", 2000).unwrap();
        mgr.complete_session("s-1", 3000).unwrap();
        let session = mgr.sessions.get("s-1").unwrap();
        assert_eq!(session.status, SessionStatus::Completed);
        assert_eq!(session.completed_at, Some(3000));
    }

    #[test]
    fn test_active_sessions_filters() {
        let mut mgr = setup_manager();
        mgr.start_session("p-1", "s-1", 2000).unwrap();
        mgr.start_session("p-1", "s-2", 2000).unwrap();
        mgr.complete_session("s-2", 3000).unwrap();
        assert_eq!(mgr.active_sessions().len(), 1);
    }

    #[test]
    fn test_sessions_for_agent() {
        let mut mgr = setup_manager();
        mgr.start_session("p-1", "s-1", 2000).unwrap();
        let sessions = mgr.sessions_for_agent("a1");
        assert_eq!(sessions.len(), 1);
        let none = mgr.sessions_for_agent("unknown");
        assert!(none.is_empty());
    }

    #[test]
    fn test_check_timeouts_detects_expired() {
        let mut mgr = setup_manager();
        mgr.start_session("p-1", "s-1", 2000).unwrap();
        // timeout_at = 2000 + 60000 = 62000
        let timed_out = mgr.check_timeouts(70000);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], "s-1");
        assert_eq!(mgr.sessions.get("s-1").unwrap().status, SessionStatus::TimedOut);
    }

    #[test]
    fn test_session_tracks_message_count() {
        let mut mgr = setup_manager();
        mgr.start_session("p-1", "s-1", 2000).unwrap();
        for i in 0..5 {
            mgr.send_message("s-1", CoordinationMessage {
                from_agent: "a1".into(),
                to_agent: None,
                message_type: L2MessageType::Inform,
                payload: format!("msg-{i}"),
                timestamp: 2100 + i,
            }).unwrap();
        }
        assert_eq!(mgr.sessions.get("s-1").unwrap().message_count(), 5);
    }

    #[test]
    fn test_protocol_type_all_variants() {
        let types = vec![
            ProtocolType::LeaderFollower { leader: "a1".into() },
            ProtocolType::Consensus { quorum: 3 },
            ProtocolType::Pipeline { stages: vec!["s1".into(), "s2".into()] },
            ProtocolType::Broadcast,
            ProtocolType::RequestResponse,
            ProtocolType::Auction { reserve_price: "100".into() },
        ];
        for pt in &types {
            assert!(!pt.to_string().is_empty());
        }
    }
}
