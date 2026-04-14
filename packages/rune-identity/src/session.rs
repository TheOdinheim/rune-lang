// ═══════════════════════════════════════════════════════════════════════
// Session Management — Authenticated State Over Time
//
// Sessions track who is authenticated, when, and with what trust level.
// Supports idle timeouts, concurrent limits, trust decay, and renewal.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

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

// ── SessionFingerprint (Layer 2) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFingerprint {
    pub ip_hash: String,
    pub ua_hash: String,
}

impl SessionFingerprint {
    pub fn new(ip: &str, user_agent: &str) -> Self {
        Self {
            ip_hash: sha3_hash(ip),
            ua_hash: sha3_hash(user_agent),
        }
    }

    pub fn matches(&self, ip: &str, user_agent: &str) -> bool {
        sha3_hash(ip) == self.ip_hash && sha3_hash(user_agent) == self.ua_hash
    }

    pub fn matches_ip(&self, ip: &str) -> bool {
        sha3_hash(ip) == self.ip_hash
    }
}

fn sha3_hash(input: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("idt_{}", hex::encode(bytes))
}

fn hash_session_token(token: &str) -> String {
    sha3_hash(token)
}

// ── SessionManager ────────────────────────────────────────────────────

pub struct SessionManager {
    sessions: HashMap<String, Session>,  // keyed by token hash
    identity_sessions: HashMap<IdentityId, Vec<String>>,  // token hashes
    config: SessionConfig,
    next_id: u64,
    fingerprints: HashMap<String, SessionFingerprint>,  // token_hash -> fingerprint
}

fn session_key(id: &SessionId) -> String {
    let raw = id.as_str();
    if raw.starts_with("idt_") {
        hash_session_token(raw)
    } else {
        // Legacy counter-based IDs — use as-is for backward compat
        raw.to_string()
    }
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            identity_sessions: HashMap::new(),
            config,
            next_id: 1,
            fingerprints: HashMap::new(),
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

        // Layer 2: crypto random token with idt_ prefix
        let raw_token = generate_session_token();
        let token_hash = hash_session_token(&raw_token);
        let session_id = SessionId::new(&raw_token);
        self.next_id += 1;

        let session = Session {
            id: session_id,
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

        self.sessions.insert(token_hash.clone(), session.clone());
        self.identity_sessions.entry(identity_id).or_default().push(token_hash);

        Ok(session)
    }

    pub fn get_session(&self, id: &SessionId) -> Option<&Session> {
        let key = session_key(id);
        self.sessions.get(&key)
    }

    pub fn validate_session(&self, id: &SessionId, now: i64) -> SessionValidation {
        let key = session_key(id);
        let session = match self.sessions.get(&key) {
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
        let key = session_key(id);
        let session = self.sessions.get_mut(&key)
            .ok_or_else(|| IdentityError::SessionNotFound(id.clone()))?;
        session.last_activity_at = now;
        Ok(())
    }

    pub fn revoke_session(&mut self, id: &SessionId, reason: &str) -> Result<(), IdentityError> {
        let key = session_key(id);
        let session = self.sessions.get_mut(&key)
            .ok_or_else(|| IdentityError::SessionNotFound(id.clone()))?;
        session.status = SessionStatus::Revoked { reason: reason.into() };
        Ok(())
    }

    pub fn revoke_all_sessions(&mut self, identity_id: &IdentityId, reason: &str) -> usize {
        let hashes: Vec<String> = self.identity_sessions
            .get(identity_id)
            .cloned()
            .unwrap_or_default();

        let mut count = 0;
        for h in &hashes {
            if let Some(session) = self.sessions.get_mut(h) {
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
            .map(|hashes| {
                hashes.iter()
                    .filter_map(|h| self.sessions.get(h))
                    .filter(|s| s.status == SessionStatus::Active)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn active_session_count(&self, identity_id: &IdentityId) -> usize {
        self.active_sessions(identity_id).len()
    }

    pub fn cleanup_expired(&mut self, now: i64) -> usize {
        let expired_keys: Vec<String> = self.sessions.iter()
            .filter(|(_, s)| s.status == SessionStatus::Active && now >= s.expires_at)
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in &expired_keys {
            if let Some(session) = self.sessions.get_mut(key) {
                session.status = SessionStatus::Expired;
            }
        }
        count
    }

    pub fn renew_session(&mut self, id: &SessionId, now: i64) -> Result<(), IdentityError> {
        if !self.config.renewal_allowed {
            return Err(IdentityError::InvalidOperation("session renewal not allowed".into()));
        }
        let key = session_key(id);
        let session = self.sessions.get_mut(&key)
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

    // ── Layer 2: Session Security Controls ──────────────────────────

    pub fn concurrent_session_count(&self, identity_id: &IdentityId) -> usize {
        self.active_session_count(identity_id)
    }

    pub fn revoke_oldest_sessions(&mut self, identity_id: &IdentityId, keep: usize, reason: &str) -> usize {
        let mut active: Vec<(String, i64)> = self.identity_sessions
            .get(identity_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|h| {
                self.sessions.get(&h).and_then(|s| {
                    if s.status == SessionStatus::Active {
                        Some((h, s.authenticated_at))
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Sort by authenticated_at ascending (oldest first)
        active.sort_by_key(|(_, t)| *t);

        let to_revoke = active.len().saturating_sub(keep);
        let mut count = 0;
        for (h, _) in active.iter().take(to_revoke) {
            if let Some(session) = self.sessions.get_mut(h) {
                session.status = SessionStatus::Revoked { reason: reason.into() };
                count += 1;
            }
        }
        count
    }

    pub fn sessions_by_identity(&self, identity_id: &IdentityId) -> Vec<&Session> {
        self.identity_sessions.get(identity_id)
            .map(|hashes| {
                hashes.iter()
                    .filter_map(|h| self.sessions.get(h))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn set_fingerprint(&mut self, id: &SessionId, fingerprint: SessionFingerprint) {
        let key = session_key(id);
        self.fingerprints.insert(key, fingerprint);
    }

    pub fn validate_fingerprint(&self, id: &SessionId, ip: &str, user_agent: &str) -> bool {
        let key = session_key(id);
        self.fingerprints.get(&key).is_some_and(|fp| fp.matches(ip, user_agent))
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

    // ── Part 2: Cryptographic Session Token Tests ────────────────────

    #[test]
    fn test_session_token_has_idt_prefix() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        assert!(session.id.as_str().starts_with("idt_"));
    }

    #[test]
    fn test_session_token_is_68_chars() {
        // "idt_" (4) + 64 hex chars = 68
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        assert_eq!(session.id.as_str().len(), 68);
    }

    #[test]
    fn test_session_tokens_are_unique() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let s1 = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        let s2 = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1001,
        ).unwrap();
        assert_ne!(s1.id.as_str(), s2.id.as_str());
    }

    #[test]
    fn test_session_stored_by_hash_not_raw_token() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        // Internal storage key should be the hash, not the raw token
        let raw = session.id.as_str();
        assert!(!mgr.sessions.contains_key(raw));
        let hashed = hash_session_token(raw);
        assert!(mgr.sessions.contains_key(&hashed));
    }

    #[test]
    fn test_session_lookup_by_raw_token() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        // get_session should work with the raw token
        let found = mgr.get_session(&session.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().identity_id.as_str(), "user:alice");
    }

    #[test]
    fn test_session_fingerprint_creation() {
        let fp = SessionFingerprint::new("192.168.1.1", "Mozilla/5.0");
        assert_eq!(fp.ip_hash.len(), 64);
        assert_eq!(fp.ua_hash.len(), 64);
        // Never stores raw values
        assert_ne!(fp.ip_hash, "192.168.1.1");
    }

    #[test]
    fn test_session_fingerprint_matches() {
        let fp = SessionFingerprint::new("10.0.0.1", "Chrome/100");
        assert!(fp.matches("10.0.0.1", "Chrome/100"));
        assert!(!fp.matches("10.0.0.2", "Chrome/100"));
        assert!(!fp.matches("10.0.0.1", "Firefox/99"));
    }

    #[test]
    fn test_session_fingerprint_matches_ip() {
        let fp = SessionFingerprint::new("10.0.0.1", "Chrome/100");
        assert!(fp.matches_ip("10.0.0.1"));
        assert!(!fp.matches_ip("10.0.0.2"));
    }

    #[test]
    fn test_session_set_and_validate_fingerprint() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let session = mgr.create_session(
            IdentityId::new("user:alice"),
            &success_result("user:alice"),
            1000,
        ).unwrap();
        mgr.set_fingerprint(&session.id, SessionFingerprint::new("1.2.3.4", "UA"));
        assert!(mgr.validate_fingerprint(&session.id, "1.2.3.4", "UA"));
        assert!(!mgr.validate_fingerprint(&session.id, "5.6.7.8", "UA"));
    }

    #[test]
    fn test_concurrent_session_count() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let id = IdentityId::new("user:alice");
        mgr.create_session(id.clone(), &success_result("user:alice"), 1000).unwrap();
        mgr.create_session(id.clone(), &success_result("user:alice"), 1001).unwrap();
        assert_eq!(mgr.concurrent_session_count(&id), 2);
    }

    #[test]
    fn test_revoke_oldest_sessions() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let id = IdentityId::new("user:alice");
        mgr.create_session(id.clone(), &success_result("user:alice"), 1000).unwrap();
        mgr.create_session(id.clone(), &success_result("user:alice"), 2000).unwrap();
        mgr.create_session(id.clone(), &success_result("user:alice"), 3000).unwrap();
        let revoked = mgr.revoke_oldest_sessions(&id, 1, "too many sessions");
        assert_eq!(revoked, 2);
        assert_eq!(mgr.active_session_count(&id), 1);
    }

    #[test]
    fn test_sessions_by_identity() {
        let mut mgr = SessionManager::new(SessionConfig::default());
        let id = IdentityId::new("user:alice");
        mgr.create_session(id.clone(), &success_result("user:alice"), 1000).unwrap();
        mgr.create_session(id.clone(), &success_result("user:alice"), 2000).unwrap();
        let sessions = mgr.sessions_by_identity(&id);
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_session_fingerprint_mismatch_different_ip() {
        let fp = SessionFingerprint::new("192.168.1.1", "Chrome/120");
        let fp2 = SessionFingerprint::new("10.0.0.1", "Chrome/120");
        assert_ne!(fp.ip_hash, fp2.ip_hash);
        assert_eq!(fp.ua_hash, fp2.ua_hash);
    }
}
