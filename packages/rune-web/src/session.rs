// ═══════════════════════════════════════════════════════════════════════
// Session — Web session governance: creation, validation, rotation,
// idle timeouts, and concurrent session limits.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

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

// ── SessionBinding ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SessionBinding {
    pub bound_ip: Option<String>,
    pub bound_user_agent: Option<String>,
}

// ── SessionTokenHasher ─────────────────────────────────────────────

pub struct SessionTokenHasher;

impl SessionTokenHasher {
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}

// ── generate_session_id ────────────────────────────────────────────

fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("sess_{}", hex::encode(bytes))
}

// ── WebSessionStore ──────────────────────────────────────────────────

pub struct WebSessionStore {
    sessions: HashMap<String, WebSession>,
    config: WebSessionConfig,
    bindings: HashMap<String, SessionBinding>,
    request_counts: HashMap<String, u64>,
    request_timestamps: HashMap<String, Vec<i64>>,
}

impl WebSessionStore {
    pub fn new(config: WebSessionConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            config,
            bindings: HashMap::new(),
            request_counts: HashMap::new(),
            request_timestamps: HashMap::new(),
        }
    }

    pub fn create(&mut self, source_ip: &str, user_agent: Option<&str>, now: i64) -> String {
        let raw_id = generate_session_id();
        let hashed_id = SessionTokenHasher::hash_token(&raw_id);
        let id = hashed_id.clone();
        let session = WebSession {
            id: raw_id.clone(),
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
        self.sessions.insert(id, session);
        raw_id
    }

    fn resolve_key(&self, id: &str) -> String {
        // If caller passes a raw session ID, hash it for lookup
        if self.sessions.contains_key(id) {
            return id.to_string();
        }
        SessionTokenHasher::hash_token(id)
    }

    pub fn get(&self, id: &str) -> Option<&WebSession> {
        let key = self.resolve_key(id);
        self.sessions.get(&key)
    }

    pub fn validate(&self, id: &str, now: i64) -> SessionValidation {
        let key = self.resolve_key(id);
        let Some(session) = self.sessions.get(&key) else {
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
        let key = self.resolve_key(id);
        let session = self
            .sessions
            .get_mut(&key)
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
        let key = self.resolve_key(id);
        let session = self
            .sessions
            .get(&key)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?
            .clone();

        if self.config.regenerate_on_auth {
            // Create new session, migrate data, remove old
            let raw_new_id = generate_session_id();
            let new_key = SessionTokenHasher::hash_token(&raw_new_id);
            let new_session = WebSession {
                id: raw_new_id.clone(),
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
            self.sessions.remove(&key);
            self.sessions.insert(new_key, new_session);
            Ok(raw_new_id)
        } else {
            let session = self.sessions.get_mut(&key).unwrap();
            session.identity = Some(identity.into());
            session.authenticated = true;
            session.last_activity = now;
            Ok(id.into())
        }
    }

    pub fn verify_mfa(&mut self, id: &str) -> Result<(), WebError> {
        let key = self.resolve_key(id);
        let session = self
            .sessions
            .get_mut(&key)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?;
        session.mfa_verified = true;
        Ok(())
    }

    pub fn invalidate(&mut self, id: &str) -> Result<(), WebError> {
        let key = self.resolve_key(id);
        self.sessions
            .remove(&key)
            .ok_or_else(|| WebError::SessionNotFound(id.into()))?;
        Ok(())
    }

    pub fn invalidate_all_for_identity(&mut self, identity: &str) -> usize {
        let to_remove: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.identity.as_deref() == Some(identity))
            .map(|(k, _)| k.clone())
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.sessions.remove(&key);
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
            .iter()
            .filter(|(_, s)| {
                s.expires_at <= now
                    || (now - s.last_activity) > self.config.idle_timeout_ms
            })
            .map(|(k, _)| k.clone())
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.sessions.remove(&key);
        }
        count
    }

    // ── Session binding (Layer 2) ──────────────────────────────────

    pub fn bind_to_ip(&mut self, id: &str, ip: &str) -> Result<(), WebError> {
        let key = self.resolve_key(id);
        if !self.sessions.contains_key(&key) {
            return Err(WebError::SessionNotFound(id.into()));
        }
        let binding = self.bindings.entry(key).or_default();
        binding.bound_ip = Some(ip.into());
        Ok(())
    }

    pub fn bind_to_user_agent(&mut self, id: &str, ua: &str) -> Result<(), WebError> {
        let key = self.resolve_key(id);
        if !self.sessions.contains_key(&key) {
            return Err(WebError::SessionNotFound(id.into()));
        }
        let binding = self.bindings.entry(key).or_default();
        binding.bound_user_agent = Some(ua.into());
        Ok(())
    }

    pub fn validate_with_binding(&self, id: &str, now: i64, ip: Option<&str>, ua: Option<&str>) -> SessionValidation {
        let base = self.validate(id, now);
        if !base.valid {
            return base;
        }
        let key = self.resolve_key(id);
        if let Some(binding) = self.bindings.get(&key) {
            if let (Some(bound_ip), Some(req_ip)) = (&binding.bound_ip, ip) {
                if bound_ip != req_ip {
                    return SessionValidation {
                        valid: false,
                        reason: Some("IP binding mismatch".into()),
                        remaining_ms: base.remaining_ms,
                        idle_ms: base.idle_ms,
                    };
                }
            }
            if let (Some(bound_ua), Some(req_ua)) = (&binding.bound_user_agent, ua) {
                if bound_ua != req_ua {
                    return SessionValidation {
                        valid: false,
                        reason: Some("User-Agent binding mismatch".into()),
                        remaining_ms: base.remaining_ms,
                        idle_ms: base.idle_ms,
                    };
                }
            }
        }
        base
    }

    // ── Session activity tracking (Layer 2) ────────────────────────

    pub fn record_request(&mut self, id: &str, now: i64) {
        let key = self.resolve_key(id);
        *self.request_counts.entry(key.clone()).or_insert(0) += 1;
        let timestamps = self.request_timestamps.entry(key).or_default();
        timestamps.push(now);
        if timestamps.len() > 1000 {
            timestamps.drain(..timestamps.len() - 1000);
        }
    }

    pub fn session_request_count(&self, id: &str) -> u64 {
        let key = self.resolve_key(id);
        self.request_counts.get(&key).copied().unwrap_or(0)
    }

    pub fn session_request_rate(&self, id: &str, window_ms: i64, now: i64) -> Option<f64> {
        let key = self.resolve_key(id);
        let timestamps = self.request_timestamps.get(&key)?;
        let cutoff = now - window_ms;
        let count = timestamps.iter().filter(|&&ts| ts > cutoff).count();
        if window_ms <= 0 {
            return None;
        }
        Some(count as f64 / (window_ms as f64 / 1000.0))
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_crypto_session_id_format() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        assert!(id.starts_with("sess_"));
        // 32 random bytes = 64 hex chars + "sess_" prefix = 69 chars
        assert_eq!(id.len(), 69);
        // Hex chars only after prefix
        assert!(id[5..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_session_token_hasher_deterministic() {
        let h1 = SessionTokenHasher::hash_token("test_token");
        let h2 = SessionTokenHasher::hash_token("test_token");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA3-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_session_token_hasher_different_inputs() {
        let h1 = SessionTokenHasher::hash_token("token_a");
        let h2 = SessionTokenHasher::hash_token("token_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_session_stored_by_hash() {
        let mut store = WebSessionStore::new(test_config());
        let raw_id = store.create("1.2.3.4", None, 1000);
        let hashed = SessionTokenHasher::hash_token(&raw_id);
        // Internally stored under hashed key
        assert!(store.sessions.contains_key(&hashed));
        // But accessible via raw ID through resolve_key
        assert!(store.get(&raw_id).is_some());
    }

    #[test]
    fn test_bind_to_ip() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.bind_to_ip(&id, "1.2.3.4").unwrap();
        let v = store.validate_with_binding(&id, 2000, Some("1.2.3.4"), None);
        assert!(v.valid);
    }

    #[test]
    fn test_validate_with_binding_ip_mismatch() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.bind_to_ip(&id, "1.2.3.4").unwrap();
        let v = store.validate_with_binding(&id, 2000, Some("5.6.7.8"), None);
        assert!(!v.valid);
        assert!(v.reason.unwrap().contains("IP binding"));
    }

    #[test]
    fn test_bind_to_user_agent() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.bind_to_user_agent(&id, "Mozilla/5.0").unwrap();
        let v = store.validate_with_binding(&id, 2000, None, Some("Mozilla/5.0"));
        assert!(v.valid);
    }

    #[test]
    fn test_validate_with_binding_ua_mismatch() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        store.bind_to_user_agent(&id, "Mozilla/5.0").unwrap();
        let v = store.validate_with_binding(&id, 2000, None, Some("curl/7.68"));
        assert!(!v.valid);
        assert!(v.reason.unwrap().contains("User-Agent binding"));
    }

    #[test]
    fn test_record_request_and_count() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        assert_eq!(store.session_request_count(&id), 0);
        store.record_request(&id, 2000);
        store.record_request(&id, 3000);
        store.record_request(&id, 4000);
        assert_eq!(store.session_request_count(&id), 3);
    }

    #[test]
    fn test_session_request_rate() {
        let mut store = WebSessionStore::new(test_config());
        let id = store.create("1.2.3.4", None, 1000);
        for i in 0..10 {
            store.record_request(&id, 2000 + i * 100);
        }
        // 10 requests in 2000..2900, window_ms=2000 from now=3000, cutoff=1000
        // All 10 are > 1000, so count=10, rate = 10 / 2.0 = 5.0 req/s
        let rate = store.session_request_rate(&id, 2000, 3000).unwrap();
        assert!(rate > 4.5 && rate <= 5.5);
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
