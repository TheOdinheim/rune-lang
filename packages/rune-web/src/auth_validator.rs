// ═══════════════════════════════════════════════════════════════════════
// Auth Validator — Token shape and binding validation trait.
//
// Layer 3 defines the contract for validating the SHAPE and BINDING
// of web-layer authentication tokens. This does NOT perform identity
// authentication — that is rune-identity's responsibility.
// TokenValidator asks "is this a well-formed token that maps to a
// known binding in our backend," not "who is this person."
//
// Constant-time comparison is mandatory for all token equality checks.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::backend::{ApiKeyBinding, WebBackend};
use crate::error::WebError;
use crate::session::WebSession;

// ── ValidationResult ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Valid {
        binding_id: String,
        claims: HashMap<String, String>,
    },
    Invalid {
        reason: String,
    },
    Expired,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

// ── TokenValidator trait ───────────────────────────────────────

pub trait TokenValidator {
    fn validate_token(&self, token: &str, now: i64) -> ValidationResult;
    fn token_type_supported(&self) -> &str;
    fn validator_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── constant_time_eq ───────────────────────────────────────────

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── ApiKeyValidator ────────────────────────────────────────────

/// Validates API keys by SHA3-256 hash comparison against stored
/// bindings. Uses constant-time equality.
pub struct ApiKeyValidator {
    id: String,
    bindings: Vec<ApiKeyBinding>,
    active: bool,
}

impl ApiKeyValidator {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            bindings: Vec::new(),
            active: true,
        }
    }

    pub fn add_binding(&mut self, binding: ApiKeyBinding) {
        self.bindings.push(binding);
    }

    pub fn load_from_backend(&mut self, backend: &dyn WebBackend) {
        self.bindings.clear();
        for key_id in backend.list_api_key_bindings() {
            if let Some(binding) = backend.retrieve_api_key_binding(key_id) {
                self.bindings.push(binding.clone());
            }
        }
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl TokenValidator for ApiKeyValidator {
    fn validate_token(&self, token: &str, now: i64) -> ValidationResult {
        let mut hasher = Sha3_256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        for binding in &self.bindings {
            if constant_time_eq(token_hash.as_bytes(), binding.key_hash.as_bytes()) {
                if binding.revoked {
                    return ValidationResult::Invalid {
                        reason: "API key has been revoked".to_string(),
                    };
                }
                if binding.is_expired(now) {
                    return ValidationResult::Expired;
                }
                let mut claims = HashMap::new();
                claims.insert("owner".to_string(), binding.owner.clone());
                for scope in &binding.scopes {
                    claims.insert(format!("scope:{scope}"), "true".to_string());
                }
                return ValidationResult::Valid {
                    binding_id: binding.key_id.clone(),
                    claims,
                };
            }
        }

        ValidationResult::Invalid {
            reason: "API key not recognized".to_string(),
        }
    }

    fn token_type_supported(&self) -> &str {
        "api-key"
    }

    fn validator_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── JwtStructureValidator ──────────────────────────────────────

/// Validates JWT header and payload structure and required claims
/// presence. Does NOT verify the signing key — signature verification
/// is delegated to rune-identity.
pub struct JwtStructureValidator {
    id: String,
    required_claims: Vec<String>,
    active: bool,
}

impl JwtStructureValidator {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            required_claims: vec!["sub".to_string(), "exp".to_string(), "iat".to_string()],
            active: true,
        }
    }

    pub fn with_required_claims(mut self, claims: &[&str]) -> Self {
        self.required_claims = claims.iter().map(|c| c.to_string()).collect();
        self
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Decode base64url without padding (JWT standard).
    fn base64url_decode(input: &str) -> Option<Vec<u8>> {
        // Replace URL-safe chars and add padding
        let mut s = input.replace('-', "+").replace('_', "/");
        let pad = (4 - s.len() % 4) % 4;
        for _ in 0..pad {
            s.push('=');
        }
        // Simple base64 decode using a lookup table
        Self::simple_base64_decode(&s)
    }

    fn simple_base64_decode(input: &str) -> Option<Vec<u8>> {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = Vec::new();
        let bytes: Vec<u8> = input.bytes().filter(|b| *b != b'=').collect();
        for chunk in bytes.chunks(4) {
            let mut buf = [0u8; 4];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = TABLE.iter().position(|&c| c == b).unwrap_or(0) as u8;
            }
            output.push((buf[0] << 2) | (buf[1] >> 4));
            if chunk.len() > 2 {
                output.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if chunk.len() > 3 {
                output.push((buf[2] << 6) | buf[3]);
            }
        }
        Some(output)
    }
}

impl TokenValidator for JwtStructureValidator {
    fn validate_token(&self, token: &str, now: i64) -> ValidationResult {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return ValidationResult::Invalid {
                reason: "JWT must have 3 parts (header.payload.signature)".to_string(),
            };
        }

        // Decode header
        let header_bytes = match Self::base64url_decode(parts[0]) {
            Some(b) => b,
            None => return ValidationResult::Invalid {
                reason: "Invalid base64 in JWT header".to_string(),
            },
        };
        let header_str = match String::from_utf8(header_bytes) {
            Ok(s) => s,
            Err(_) => return ValidationResult::Invalid {
                reason: "JWT header is not valid UTF-8".to_string(),
            },
        };
        let header: serde_json::Value = match serde_json::from_str(&header_str) {
            Ok(v) => v,
            Err(_) => return ValidationResult::Invalid {
                reason: "JWT header is not valid JSON".to_string(),
            },
        };

        // Check typ and alg
        if header.get("alg").is_none() {
            return ValidationResult::Invalid {
                reason: "JWT header missing 'alg' field".to_string(),
            };
        }

        // Decode payload
        let payload_bytes = match Self::base64url_decode(parts[1]) {
            Some(b) => b,
            None => return ValidationResult::Invalid {
                reason: "Invalid base64 in JWT payload".to_string(),
            },
        };
        let payload_str = match String::from_utf8(payload_bytes) {
            Ok(s) => s,
            Err(_) => return ValidationResult::Invalid {
                reason: "JWT payload is not valid UTF-8".to_string(),
            },
        };
        let payload: serde_json::Value = match serde_json::from_str(&payload_str) {
            Ok(v) => v,
            Err(_) => return ValidationResult::Invalid {
                reason: "JWT payload is not valid JSON".to_string(),
            },
        };

        // Check required claims
        for claim in &self.required_claims {
            if payload.get(claim.as_str()).is_none() {
                return ValidationResult::Invalid {
                    reason: format!("JWT missing required claim: {claim}"),
                };
            }
        }

        // Check expiration
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
            if now >= exp {
                return ValidationResult::Expired;
            }
        }

        // Extract claims
        let mut claims = HashMap::new();
        if let Some(sub) = payload.get("sub").and_then(|v| v.as_str()) {
            claims.insert("sub".to_string(), sub.to_string());
        }
        if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
            claims.insert("iss".to_string(), iss.to_string());
        }

        ValidationResult::Valid {
            binding_id: "jwt-structure-validated".to_string(),
            claims,
        }
    }

    fn token_type_supported(&self) -> &str {
        "jwt"
    }

    fn validator_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── SessionCookieValidator ─────────────────────────────────────

/// Validates session cookie exists in backend and has not expired.
pub struct SessionCookieValidator {
    id: String,
    sessions: Vec<WebSession>,
    active: bool,
}

impl SessionCookieValidator {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            sessions: Vec::new(),
            active: true,
        }
    }

    pub fn add_session(&mut self, session: WebSession) {
        self.sessions.push(session);
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl TokenValidator for SessionCookieValidator {
    fn validate_token(&self, token: &str, now: i64) -> ValidationResult {
        // Find session by ID (constant-time scan of all sessions)
        let mut found: Option<&WebSession> = None;
        for session in &self.sessions {
            if constant_time_eq(token.as_bytes(), session.id.as_bytes()) {
                found = Some(session);
            }
        }

        let Some(session) = found else {
            return ValidationResult::Invalid {
                reason: "Session not found".to_string(),
            };
        };

        if now >= session.expires_at {
            return ValidationResult::Expired;
        }

        let mut claims = HashMap::new();
        claims.insert("session_id".to_string(), session.id.clone());
        if let Some(ref identity) = session.identity {
            claims.insert("identity".to_string(), identity.clone());
        }
        if session.authenticated {
            claims.insert("authenticated".to_string(), "true".to_string());
        }

        ValidationResult::Valid {
            binding_id: session.id.clone(),
            claims,
        }
    }

    fn token_type_supported(&self) -> &str {
        "session-cookie"
    }

    fn validator_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── ApiKeyValidator ────────────────────────────────────────

    #[test]
    fn test_api_key_valid() {
        let mut validator = ApiKeyValidator::new("v1");
        validator.add_binding(ApiKeyBinding::new("k1", "my-secret-key", "owner", 1000));
        let result = validator.validate_token("my-secret-key", 2000);
        assert!(result.is_valid());
        if let ValidationResult::Valid { binding_id, claims } = result {
            assert_eq!(binding_id, "k1");
            assert_eq!(claims.get("owner").unwrap(), "owner");
        }
    }

    #[test]
    fn test_api_key_wrong_key() {
        let mut validator = ApiKeyValidator::new("v1");
        validator.add_binding(ApiKeyBinding::new("k1", "my-secret-key", "owner", 1000));
        let result = validator.validate_token("wrong-key", 2000);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_api_key_revoked() {
        let mut validator = ApiKeyValidator::new("v1");
        let mut binding = ApiKeyBinding::new("k1", "my-secret-key", "owner", 1000);
        binding.revoked = true;
        validator.add_binding(binding);
        let result = validator.validate_token("my-secret-key", 2000);
        assert!(!result.is_valid());
        assert!(matches!(result, ValidationResult::Invalid { .. }));
    }

    #[test]
    fn test_api_key_expired() {
        let mut validator = ApiKeyValidator::new("v1");
        let binding = ApiKeyBinding::new("k1", "my-secret-key", "owner", 1000)
            .with_expires_at(3000);
        validator.add_binding(binding);
        assert!(validator.validate_token("my-secret-key", 2000).is_valid());
        assert_eq!(validator.validate_token("my-secret-key", 3000), ValidationResult::Expired);
    }

    #[test]
    fn test_api_key_with_scopes() {
        let mut validator = ApiKeyValidator::new("v1");
        let binding = ApiKeyBinding::new("k1", "my-key", "owner", 1000)
            .with_scopes(&["read", "write"]);
        validator.add_binding(binding);
        let result = validator.validate_token("my-key", 2000);
        if let ValidationResult::Valid { claims, .. } = result {
            assert_eq!(claims.get("scope:read").unwrap(), "true");
            assert_eq!(claims.get("scope:write").unwrap(), "true");
        } else {
            panic!("expected Valid");
        }
    }

    #[test]
    fn test_api_key_metadata() {
        let validator = ApiKeyValidator::new("v1");
        assert_eq!(validator.token_type_supported(), "api-key");
        assert_eq!(validator.validator_id(), "v1");
        assert!(validator.is_active());
    }

    // ── JwtStructureValidator ──────────────────────────────────

    fn make_jwt(header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let h = base64url_encode(&serde_json::to_vec(header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(payload).unwrap());
        format!("{h}.{p}.fakesignature")
    }

    fn base64url_encode(data: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
            result.push(TABLE[(b0 >> 2)] as char);
            result.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 {
                result.push(TABLE[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
            }
            if chunk.len() > 2 {
                result.push(TABLE[b2 & 0x3f] as char);
            }
        }
        result.replace('+', "-").replace('/', "_")
    }

    #[test]
    fn test_jwt_valid_structure() {
        let validator = JwtStructureValidator::new("jwt-v1");
        let jwt = make_jwt(
            &serde_json::json!({"alg": "HS256", "typ": "JWT"}),
            &serde_json::json!({"sub": "user-1", "exp": 9999999999_i64, "iat": 1000}),
        );
        let result = validator.validate_token(&jwt, 2000);
        assert!(result.is_valid());
    }

    #[test]
    fn test_jwt_missing_parts() {
        let validator = JwtStructureValidator::new("jwt-v1");
        let result = validator.validate_token("not-a-jwt", 2000);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_jwt_missing_alg() {
        let validator = JwtStructureValidator::new("jwt-v1");
        let jwt = make_jwt(
            &serde_json::json!({"typ": "JWT"}),
            &serde_json::json!({"sub": "user-1", "exp": 9999999999_i64, "iat": 1000}),
        );
        let result = validator.validate_token(&jwt, 2000);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_jwt_missing_required_claim() {
        let validator = JwtStructureValidator::new("jwt-v1");
        let jwt = make_jwt(
            &serde_json::json!({"alg": "HS256"}),
            &serde_json::json!({"exp": 9999999999_i64, "iat": 1000}), // missing "sub"
        );
        let result = validator.validate_token(&jwt, 2000);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_jwt_expired() {
        let validator = JwtStructureValidator::new("jwt-v1");
        let jwt = make_jwt(
            &serde_json::json!({"alg": "HS256"}),
            &serde_json::json!({"sub": "user-1", "exp": 1000, "iat": 500}),
        );
        let result = validator.validate_token(&jwt, 2000);
        assert_eq!(result, ValidationResult::Expired);
    }

    #[test]
    fn test_jwt_metadata() {
        let validator = JwtStructureValidator::new("jwt-v1");
        assert_eq!(validator.token_type_supported(), "jwt");
        assert!(validator.is_active());
    }

    // ── SessionCookieValidator ─────────────────────────────────

    fn make_session(id: &str, expires_at: i64) -> WebSession {
        WebSession {
            id: id.to_string(),
            identity: Some("user@example.com".to_string()),
            created_at: 1000,
            last_activity: 1000,
            expires_at,
            source_ip: "1.2.3.4".to_string(),
            user_agent: None,
            authenticated: true,
            mfa_verified: false,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_session_cookie_valid() {
        let mut validator = SessionCookieValidator::new("sess-v1");
        validator.add_session(make_session("sess-abc", 100_000));
        let result = validator.validate_token("sess-abc", 2000);
        assert!(result.is_valid());
        if let ValidationResult::Valid { claims, .. } = result {
            assert_eq!(claims.get("identity").unwrap(), "user@example.com");
            assert_eq!(claims.get("authenticated").unwrap(), "true");
        }
    }

    #[test]
    fn test_session_cookie_not_found() {
        let validator = SessionCookieValidator::new("sess-v1");
        let result = validator.validate_token("unknown-session", 2000);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_session_cookie_expired() {
        let mut validator = SessionCookieValidator::new("sess-v1");
        validator.add_session(make_session("sess-abc", 3000));
        assert!(validator.validate_token("sess-abc", 2000).is_valid());
        assert_eq!(validator.validate_token("sess-abc", 3000), ValidationResult::Expired);
    }

    #[test]
    fn test_session_cookie_metadata() {
        let validator = SessionCookieValidator::new("sess-v1");
        assert_eq!(validator.token_type_supported(), "session-cookie");
        assert!(validator.is_active());
    }

    // ── Constant-time eq ───────────────────────────────────────

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
