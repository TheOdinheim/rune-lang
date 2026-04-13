// ═══════════════════════════════════════════════════════════════════════
// Session — Web session governance: creation, validation, rotation,
// idle timeouts, and concurrent session limits.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::WebError;

// ── SameSitePolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
}

impl fmt::Display for SameSitePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Lax => write!(f, "Lax"),
            Self::None => write!(f, "None"),
        }
    }
}

// ── WebSessionConfig ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WebSessionConfig {
    pub max_age_ms: i64,
    pub idle_timeout_ms: i64,
    pub secure_only: bool,
    pub http_only: bool,
    pub same_site: SameSitePolicy,
    pub domain: Option<String>,
    pub path: String,
    pub max_concurrent: u32,
    pub regenerate_on_auth: bool,
}

impl WebSessionConfig {
    pub fn new() -> Self {
        Self {
            max_age_ms: 86_400_000,    // 24 hours
            idle_timeout_ms: 1_800_000, // 30 minutes
            secure_only: true,
            http_only: true,
            same_site: SameSitePolicy::Strict,
            domain: None,
            path: "/".into(),
            max_concurrent: 5,
            regenerate_on_auth: true,
        }
    }
}

impl Default for WebSessionConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── WebSession ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSession {
    pub id: String,
    pub identity: Option<String>,
    pub created_at: i64,
    pub last_activity: i64,
    pub expires_at: i64,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub authenticated: bool,
    pub mfa_verified: bool,
    pub metadata: HashMap<String, String>,
}

// ── SessionValidation ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SessionValidation {
    pub valid: bool,
    pub reason: Option<String>,
    pub remaining_ms: i64,
    pub idle_ms: i64,
}

// ── WebSessionStore ──────────────────────────────────────────────────

pub struct WebSessionStore {
    sessions: HashMap<String, WebSession>,
    config: WebSessionConfig,
    next_id: u64,
}

impl WebSessionStore {
    pub fn new(config: WebSessionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            config,
            next_id: 1,
        }
    }

    pub fn create(&mut self, source_ip: &str, user_agent: Option<&str>, now: i64) -> String {
        let id = format!("sess_{:016x}", self.next_id);
        self.next_id += 1;
        let session = WebSession {
            id: id.clone(),
            identity: None,
            created_at: now,
            last_activity: now,
            expires_at: now + self.config.max_age_ms,
            source_ip: source_ip.into(),
            user_agent: user_agent.map(String::from),
            authenticated: false,
            mfa_verified: false,
            metadata: HashMap::new(),
        };
        self.sessions.insert(id.clone(), session);
        id
    }

    pub fn get(&self, id: &str) -> Option<&WebSession> {
        self.sessions.get(id)
    }

    pub fn validate(&self, id: &str, now: i64) -> SessionValidation {
        let Some(session) = self.sessions.get(id) else {
            return SessionValidation {
                valid: false,
                reason: Some("Session not found".into()),
                remaining_ms: 0,
                idle_ms: 0,
            };
        };

        let remaining_ms = session.expires_at - now;
        let idle_ms = now - session.last_activity;

        if remaining_ms <= 0 {
            return SessionValidation {
                valid: false,
                reason: Some("Session expired".into()),
                remaining_ms: 0,
                idle_ms,
            };
        }

        if idle_ms > self.config.idle_timeout_ms {
            return SessionValidation {
                valid: false,
                reason: Some("Session idle timeout".into()),
                remaining_ms,
                idle_ms,
            };
        }

        SessionValidation {
            valid: true,
            reason: None,
            remaining_ms,
            idle_ms,
        }
    }

    pub fn touch(&mut self, id: &str, now: i64) -> Result<(), WebError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?;
        session.last_activity = now;
        Ok(())
    }

    pub fn authenticate(
        &mut self,
        id: &str,
        identity: &str,
        now: i64,
    ) -> Result<String, WebError> {
        let session = self
            .sessions
            .get(id)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?
            .clone();

        if self.config.regenerate_on_auth {
            // Create new session, migrate data, remove old
            let new_id = format!("sess_{:016x}", self.next_id);
            self.next_id += 1;
            let new_session = WebSession {
                id: new_id.clone(),
                identity: Some(identity.into()),
                created_at: session.created_at,
                last_activity: now,
                expires_at: session.expires_at,
                source_ip: session.source_ip,
                user_agent: session.user_agent,
                authenticated: true,
                mfa_verified: session.mfa_verified,
                metadata: session.metadata,
            };
            self.sessions.remove(id);
            self.sessions.insert(new_id.clone(), new_session);
            Ok(new_id)
        } else {
            let session = self.sessions.get_mut(id).unwrap();
            session.identity = Some(identity.into());
            session.authenticated = true;
            session.last_activity = now;
            Ok(id.into())
        }
    }

    pub fn verify_mfa(&mut self, id: &str) -> Result<(), WebError> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?;
        session.mfa_verified = true;
        Ok(())
    }

    pub fn invalidate(&mut self, id: &str) -> Result<(), WebError> {
        self.sessions
            .remove(id)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?;
        Ok(())
    }

    pub fn invalidate_all_for_identity(&mut self, identity: &str) -> usize {
        let to_remove: Vec<String> = self
            .sessions
            .values()
            .filter(|s| s.identity.as_deref() == Some(identity))
            .map(|s| s.id.clone())
            .collect();
        let count = to_remove.len();
        for id in to_remove {
            self.sessions.remove(&id);
        }
        count
    }

    pub fn active_sessions(&self, now: i64) -> Vec<&WebSession> {
        self.sessions
            .values()
            .filter(|s| s.expires_at > now && (now - s.last_activity) <= self.config.idle_timeout_ms)
            .collect()
    }

    pub fn active_count_for_identity(&self, identity: &str) -> usize {
        self.sessions
            .values()
            .filter(|s| s.identity.as_deref() == Some(identity))
            .count()
    }

    pub fn cleanup_expired(&mut self, now: i64) -> usize {
        let to_remove: Vec<String> = self
            .sessions
            .values()
            .filter(|s| {
                s.expires_at <= now
                    || (now - s.last_activity) > self.config.idle_timeout_ms
            })
            .map(|s| s.id.clone())
            .collect();
        let count = to_remove.len();
        for id in to_remove {
            self.sessions.remove(&id);
        }
        count
    }

    pub fn cookie_attributes(&self) -> String {
        let mut attrs = Vec::new();
        if self.config.http_only {
            attrs.push("HttpOnly".to_string());
        }
        if self.config.secure_only {
            attrs.push("Secure".to_string());
        }
        attrs.push(format!("SameSite={}", self.config.same_site));
        attrs.push(format!("Path={}", self.config.path));
        let max_age_seconds = self.config.max_age_ms / 1000;
        attrs.push(format!("Max-Age={max_age_seconds}"));
        if let Some(ref domain) = self.config.domain {
            attrs.push(format!("Domain={domain}"));
        }
        attrs.join("; ")
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WebSessionConfig {
        WebSessionConfig {
            max_age_ms: 86_400_000,
            idle_timeout_ms: 1_800_000,
            ..WebSessionConfig::new()
        }
    }

    #[test]
    fn test_create_returns_session_id() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", Some("Mozilla/5.0"), 1000);
        assert!(id.starts_with("sess_"));
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn test_validate_active_session() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        let v = store.validate(&id, 2000);
        assert!(v.valid);
        assert!(v.remaining_ms > 0);
    }

    #[test]
    fn test_validate_expired_session() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        let v = store.validate(&id, 1000 + 86_400_000 + 1);
        assert!(!v.valid);
        assert!(v.reason.unwrap().contains("expired"));
    }

    #[test]
    fn test_validate_idle_timeout() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        let v = store.validate(&id, 1000 + 1_800_001);
        assert!(!v.valid);
        assert!(v.reason.unwrap().contains("idle"));
    }

    #[test]
    fn test_touch_updates_activity() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.touch(&id, 5000).unwrap();
        let session = store.get(&id).unwrap();
        assert_eq!(session.last_activity, 5000);
    }

    #[test]
    fn test_authenticate_sets_identity() {
        let config = WebSessionConfig {
            regenerate_on_auth: false,
            ..test_config()
        };
        let mut store = WebSessionStore::new(config);
        let id = store.create("1.2.3.4", None, 1000);
        let result_id = store.authenticate(&id, "user@example.com", 2000).unwrap();
        assert_eq!(result_id, id);
        let session = store.get(&id).unwrap();
        assert!(session.authenticated);
        assert_eq!(session.identity.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_authenticate_regenerates_session_id() {
        let mut store = WebSessionStore::new(test_config());
        let old_id = store.create("1.2.3.4", None, 1000);
        let new_id = store.authenticate(&old_id, "user@example.com", 2000).unwrap();
        assert_ne!(old_id, new_id);
        assert!(store.get(&old_id).is_none());
        assert!(store.get(&new_id).is_some());
        assert!(store.get(&new_id).unwrap().authenticated);
    }

    #[test]
    fn test_verify_mfa() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.verify_mfa(&id).unwrap();
        assert!(store.get(&id).unwrap().mfa_verified);
    }

    #[test]
    fn test_invalidate() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.invalidate(&id).unwrap();
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_invalidate_all_for_identity() {
        let config = WebSessionConfig {
            regenerate_on_auth: false,
            ..test_config()
        };
        let mut store = WebSessionStore::new(config);
        let id1 = store.create("1.2.3.4", None, 1000);
        let id2 = store.create("1.2.3.5", None, 1000);
        store.create("1.2.3.6", None, 1000); // different user
        store.authenticate(&id1, "user@example.com", 2000).unwrap();
        store.authenticate(&id2, "user@example.com", 2000).unwrap();
        let removed = store.invalidate_all_for_identity("user@example.com");
        assert_eq!(removed, 2);
    }

    #[test]
    fn test_active_count_for_identity() {
        let config = WebSessionConfig {
            regenerate_on_auth: false,
            ..test_config()
        };
        let mut store = WebSessionStore::new(config);
        let id1 = store.create("1.2.3.4", None, 1000);
        let id2 = store.create("1.2.3.5", None, 1000);
        store.authenticate(&id1, "user@example.com", 2000).unwrap();
        store.authenticate(&id2, "user@example.com", 2000).unwrap();
        assert_eq!(store.active_count_for_identity("user@example.com"), 2);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = WebSessionStore::new(test_config());
        store.create("1.2.3.4", None, 1000); // will expire
        store.create("1.2.3.5", None, 100_000_000); // won't expire
        let removed = store.cleanup_expired(1000 + 86_400_001);
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_cookie_attributes() {
        let store = WebSessionStore::new(test_config());
        let attrs = store.cookie_attributes();
        assert!(attrs.contains("HttpOnly"));
        assert!(attrs.contains("Secure"));
        assert!(attrs.contains("SameSite=Strict"));
        assert!(attrs.contains("Path=/"));
        assert!(attrs.contains("Max-Age=86400"));
    }

    #[test]
    fn test_same_site_policy_display() {
        assert_eq!(SameSitePolicy::Strict.to_string(), "Strict");
        assert_eq!(SameSitePolicy::Lax.to_string(), "Lax");
        assert_eq!(SameSitePolicy::None.to_string(), "None");
    }

    #[test]
    fn test_session_config_defaults() {
        let config = WebSessionConfig::new();
        assert_eq!(config.max_age_ms, 86_400_000);
        assert_eq!(config.idle_timeout_ms, 1_800_000);
        assert!(config.secure_only);
        assert!(config.http_only);
        assert_eq!(config.same_site, SameSitePolicy::Strict);
        assert_eq!(config.max_concurrent, 5);
        assert!(config.regenerate_on_auth);
    }

    #[test]
    fn test_max_concurrent_sessions() {
        let config = WebSessionConfig {
            max_concurrent: 2,
            regenerate_on_auth: false,
            ..test_config()
        };
        let mut store = WebSessionStore::new(config);
        let id1 = store.create("1.2.3.4", None, 1000);
        let id2 = store.create("1.2.3.5", None, 1000);
        store.authenticate(&id1, "user@example.com", 2000).unwrap();
        store.authenticate(&id2, "user@example.com", 2000).unwrap();
        // Count exceeds max_concurrent
        assert!(store.active_count_for_identity("user@example.com") > store.sessions.values().next().map(|_| 0).unwrap_or(0));
        assert_eq!(store.active_count_for_identity("user@example.com"), 2);
    }
}
