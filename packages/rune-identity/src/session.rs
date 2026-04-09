// ═══════════════════════════════════════════════════════════════════════
// Session Management — Authenticated State Over Time
//
// Sessions track who is authenticated, when, and with what trust level.
// Supports idle timeouts, concurrent limits, trust decay, and renewal.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::authn::AuthnResult;
use crate::error::IdentityError;
use crate::identity::IdentityId;

// ── SessionId ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── SessionStatus ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Expired,
    Revoked { reason: String },
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked { reason } => write!(f, "Revoked: {reason}"),
        }
    }
}

// ── Session ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub identity_id: IdentityId,
    pub authenticated_at: i64,
    pub last_activity_at: i64,
    pub expires_at: i64,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,
    pub trust_score: f64,
    pub status: SessionStatus,
    pub mfa_verified: bool,
    pub metadata: HashMap<String, String>,
}

// ── SessionConfig ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub max_duration_ms: i64,
    pub idle_timeout_ms: i64,
    pub max_concurrent: u32,
    pub require_mfa: bool,
    pub trust_decay_rate: f64,
    pub renewal_allowed: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_duration_ms: 24 * 60 * 60 * 1000, // 24 hours
            idle_timeout_ms: 30 * 60 * 1000,       // 30 minutes
            max_concurrent: 5,
            require_mfa: false,
            trust_decay_rate: 0.05,
            renewal_allowed: true,
        }
    }
}

impl SessionConfig {
    pub fn high_security() -> Self {
        Self {
            max_duration_ms: 60 * 60 * 1000,   // 1 hour
            idle_timeout_ms: 10 * 60 * 1000,    // 10 minutes
            max_concurrent: 1,
            require_mfa: true,
            trust_decay_rate: 0.15,
            renewal_allowed: false,
        }
    }

    pub fn service() -> Self {
        Self {
            max_duration_ms: 8 * 60 * 60 * 1000, // 8 hours
            idle_timeout_ms: 60 * 60 * 1000,      // 1 hour
            max_concurrent: 10,
            require_mfa: false,
            trust_decay_rate: 0.02,
            renewal_allowed: true,
        }
    }
}

// ── SessionValidation ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionValidation {
    pub valid: bool,
    pub reason: Option<String>,
    pub current_trust_score: f64,
    pub remaining_ms: i64,
    pub idle_ms: i64,
}

// ── SessionManager ────────────────────────────────────────────────────

pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    identity_sessions: HashMap<IdentityId, Vec<SessionId>>,
    config: SessionConfig,
    next_id: u64,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            identity_sessions: HashMap::new(),
            config,
            next_id: 1,
        }
    }

    pub fn create_session(
        &mut self,
        identity_id: IdentityId,
        authn_result: &AuthnResult,
        now: i64,
    ) -> Result<Session, IdentityError> {
        // Check concurrent limit
        let current_count = self.active_session_count(&identity_id);
        if current_count >= self.config.max_concurrent as usize {
            return Err(IdentityError::MaxConcurrentSessions {
                max: self.config.max_concurrent,
                current: current_count as u32,
            });
        }

        let trust_score = match authn_result {
            AuthnResult::Success { trust_score, .. } => *trust_score,
            _ => return Err(IdentityError::InvalidOperation("cannot create session from failed auth".into())),
        };

        let session_id = SessionId::new(format!("sess-{}", self.next_id));
        self.next_id += 1;

        let session = Session {
            id: session_id.clone(),
            identity_id: identity_id.clone(),
            authenticated_at: now,
            last_activity_at: now,
            expires_at: now + self.config.max_duration_ms,
            source_ip: None,
            user_agent: None,
            device_id: None,
            trust_score,
            status: SessionStatus::Active,
            mfa_verified: false,
            metadata: HashMap::new(),
        };

        self.sessions.insert(session_id.clone(), session.clone());
        self.identity_sessions.entry(identity_id).or_default().push(session_id);

        Ok(session)
    }

    pub fn get_session(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn validate_session(&self, id: &SessionId, now: i64) -> SessionValidation {
        let session = match self.sessions.get(id) {
            Some(s) => s,
            None => return SessionValidation {
                valid: false,
                reason: Some("session not found".into()),
                current_trust_score: 0.0,
                remaining_ms: 0,
                idle_ms: 0,
            },
        };

        // Check revoked
        if let SessionStatus::Revoked { reason } = &session.status {
            return SessionValidation {
                valid: false,
                reason: Some(format!("session revoked: {reason}")),
                current_trust_score: 0.0,
                remaining_ms: 0,
                idle_ms: now - session.last_activity_at,
            };
        }

        // Check expired
        if now >= session.expires_at {
            return SessionValidation {
                valid: false,
                reason: Some("session expired".into()),
                current_trust_score: 0.0,
                remaining_ms: 0,
                idle_ms: now - session.last_activity_at,
            };
        }

        // Check idle timeout
        let idle_ms = now - session.last_activity_at;
        if idle_ms >= self.config.idle_timeout_ms {
            return SessionValidation {
                valid: false,
                reason: Some("idle timeout exceeded".into()),
                current_trust_score: 0.0,
                remaining_ms: session.expires_at - now,
                idle_ms,
            };
        }

        // Calculate decayed trust score
        let hours_since_auth = (now - session.authenticated_at) as f64 / 3_600_000.0;
        let decayed_trust = (session.trust_score * (1.0 - self.config.trust_decay_rate * hours_since_auth))
            .clamp(0.0, 1.0);

        SessionValidation {
            valid: true,
            reason: None,
            current_trust_score: decayed_trust,
            remaining_ms: session.expires_at - now,
            idle_ms,
        }
    }

    pub fn touch(&mut self, id: &SessionId, now: i64) -> Result<(), IdentityError> {
        let session = self.sessions.get_mut(id)
            .ok_or_else(|| IdentityError::SessionNotFound(id.clone()))?;
        session.last_activity_at = now;
        Ok(())
    }

    pub fn revoke_session(&mut self, id: &SessionId, reason: &str) -> Result<(), IdentityError> {
        let session = self.sessions.get_mut(id)
            .ok_or_else(|| IdentityError::SessionNotFound(id.clone()))?;
        session.status = SessionStatus::Revoked { reason: reason.into() };
        Ok(())
    }

    pub fn revoke_all_sessions(&mut self, identity_id: &IdentityId, reason: &str) -> usize {
        let session_ids: Vec<SessionId> = self.identity_sessions
            .get(identity_id)
            .cloned()
            .unwrap_or_default();

        let mut count = 0;
        for sid in &session_ids {
            if let Some(session) = self.sessions.get_mut(sid) {
                if session.status == SessionStatus::Active {
                    session.status = SessionStatus::Revoked { reason: reason.into() };
                    count += 1;
                }
            }
        }
        count
    }

    pub fn active_sessions(&self, identity_id: &IdentityId) -> Vec<&Session> {
        self.identity_sessions.get(identity_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.sessions.get(id))
                    .filter(|s| s.status == SessionStatus::Active)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn active_session_count(&self, identity_id: &IdentityId) -> usize {
        self.active_sessions(identity_id).len()
    }

    pub fn cleanup_expired(&mut self, now: i64) -> usize {
        let expired_ids: Vec<SessionId> = self.sessions.iter()
            .filter(|(_, s)| s.status == SessionStatus::Active && now >= s.expires_at)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(session) = self.sessions.get_mut(id) {
                session.status = SessionStatus::Expired;
            }
        }
        count
    }

    pub fn renew_session(&mut self, id: &SessionId, now: i64) -> Result<(), IdentityError> {
        if !self.config.renewal_allowed {
            return Err(IdentityError::InvalidOperation("session renewal not allowed".into()));
        }
        let session = self.sessions.get_mut(id)
            .ok_or_else(|| IdentityError::SessionNotFound(id.clone()))?;
        if session.status != SessionStatus::Active {
            return Err(IdentityError::SessionRevoked(id.clone()));
        }
        if now >= session.expires_at {
            return Err(IdentityError::SessionExpired(id.clone()));
        }
        session.expires_at = now + self.config.max_duration_ms;
        session.last_activity_at = now;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::CredentialId;

    fn success_result(id: &str) -> AuthnResult {
        AuthnResult::Success {
            identity_id: IdentityId::new(id),
            credential_id: CredentialId::new("c1"),
            authenticated_at: 1000,
            trust_score: 0.8,
        }
    }

    #[test]
    fn test_session_create() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        assert_eq!(session.identity_id.as_str(), "user:alice");
        assert_eq!(session.trust_score, 0.8);
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn test_session_validate_active() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        let validation = mgr.validate_session(&session.id, 1000 + 60_000);
        assert!(validation.valid);
        assert!(validation.current_trust_score > 0.0);
        assert!(validation.remaining_ms > 0);
    }

    #[test]
    fn test_session_validate_expired() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        let validation = mgr.validate_session(&session.id, session.expires_at + 1);
        assert!(!validation.valid);
        assert!(validation.reason.unwrap().contains("expired"));
    }

    #[test]
    fn test_session_idle_timeout() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        // Exceed idle timeout (30 min default)
        let validation = mgr.validate_session(&session.id, 1000 + 31 * 60 * 1000);
        assert!(!validation.valid);
        assert!(validation.reason.unwrap().contains("idle"));
    }

    #[test]
    fn test_session_touch() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        mgr.touch(&session.id, 1000 + 20 * 60 * 1000).unwrap();
        // Now idle timeout measured from touch time
        let validation = mgr.validate_session(&session.id, 1000 + 40 * 60 * 1000);
        assert!(validation.valid); // only 20 min since touch
    }

    #[test]
    fn test_session_revoke() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        mgr.revoke_session(&session.id, "security incident").unwrap();
        let validation = mgr.validate_session(&session.id, 1500);
        assert!(!validation.valid);
        assert!(validation.reason.unwrap().contains("revoked"));
    }

    #[test]
    fn test_session_revoke_all() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let id = IdentityId::new("user:alice");
        mgr.create_session(id.clone(), &success_result("user:alice"), 1000).unwrap();
        mgr.create_session(id.clone(), &success_result("user:alice"), 1001).unwrap();
        let count = mgr.revoke_all_sessions(&id, "password changed");
        assert_eq!(count, 2);
        assert_eq!(mgr.active_session_count(&id), 0);
    }

    #[test]
    fn test_session_max_concurrent() {
        let config = SessionConfig { max_concurrent: 2, ..SessionConfig::default() };
        let mut mgr = SessionManager::new(config);
        let id = IdentityId::new("user:alice");
        mgr.create_session(id.clone(), &success_result("user:alice"), 1000).unwrap();
        mgr.create_session(id.clone(), &success_result("user:alice"), 1001).unwrap();
        let result = mgr.create_session(id.clone(), &success_result("user:alice"), 1002);
        assert!(matches!(result, Err(IdentityError::MaxConcurrentSessions { .. })));
    }

    #[test]
    fn test_session_cleanup_expired() {
        let config = SessionConfig { max_duration_ms: 1000, ..SessionConfig::default() };
        let mut mgr = SessionManager::new(config);
        mgr.create_session(IdentityId::new("user:alice"), &success_result("user:alice"), 100).unwrap();
        mgr.create_session(IdentityId::new("user:bob"), &success_result("user:bob"), 500).unwrap();
        let count = mgr.cleanup_expired(1200);
        assert_eq!(count, 1); // alice expired, bob still active
    }

    #[test]
    fn test_session_renew() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        let old_expires = session.expires_at;
        mgr.renew_session(&session.id, 5000).unwrap();
        let renewed = mgr.get_session(&session.id).unwrap();
        assert!(renewed.expires_at > old_expires);
    }

    #[test]
    fn test_session_config_high_security() {
        let config = SessionConfig::high_security();
        assert_eq!(config.max_duration_ms, 60 * 60 * 1000);
        assert_eq!(config.max_concurrent, 1);
        assert!(config.require_mfa);
        assert!(!config.renewal_allowed);
    }

    #[test]
    fn test_session_config_service() {
        let config = SessionConfig::service();
        assert_eq!(config.max_duration_ms, 8 * 60 * 60 * 1000);
        assert_eq!(config.max_concurrent, 10);
        assert!(!config.require_mfa);
    }

    #[test]
    fn test_session_trust_decay() {
        let config = SessionConfig {
            idle_timeout_ms: 3 * 60 * 60 * 1000, // 3 hours
            ..SessionConfig::default()
        };
        let mut mgr = SessionManager::new(config);
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            0,
        ).unwrap();
        // After 2 hours, trust should decay: 0.8 * (1.0 - 0.05 * 2) = 0.8 * 0.9 = 0.72
        let validation = mgr.validate_session(&session.id, 2 * 3_600_000);
        assert!(validation.valid);
        assert!(validation.current_trust_score < 0.8);
        assert!(validation.current_trust_score > 0.7);
    }
}
