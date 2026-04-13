// ═══════════════════════════════════════════════════════════════════════
// Gateway — Central API gateway combining endpoint matching, rate
// limiting, authentication enforcement, and request governance.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::endpoint::{EndpointId, EndpointRegistry, Endpoint, HttpMethod, RateLimitConfig};
use crate::error::WebError;
use crate::request::{RequestValidator, WebRequest};
use crate::response::{ResponseGovernanceResult, ResponseGovernor, ResponsePolicy, WebResponse};

// ── GatewayConfig ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub name: String,
    pub default_rate_limit: RateLimitConfig,
    pub require_auth_by_default: bool,
    pub max_concurrent_requests: Option<u64>,
    pub request_timeout_ms: u64,
    pub enabled: bool,
}

impl GatewayConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default_rate_limit: RateLimitConfig::default_authenticated(),
            require_auth_by_default: true,
            max_concurrent_requests: None,
            request_timeout_ms: 30_000,
            enabled: true,
        }
    }
}

// ── RateLimitState ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RateLimitState {
    tokens: f64,
    max_tokens: f64,
    last_refill: i64,
    request_count: u64,
}

// ── RateLimitResult ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after_ms: Option<u64>,
    pub detail: String,
}

// ── RateLimiter ──────────────────────────────────────────────────────

pub struct RateLimiter {
    limits: HashMap<String, RateLimitState>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
        }
    }

    pub fn check(&mut self, key: &str, config: &RateLimitConfig, now: i64) -> RateLimitResult {
        let state = self.limits.entry(key.to_string()).or_insert_with(|| {
            RateLimitState {
                tokens: config.burst_size as f64,
                max_tokens: config.burst_size as f64,
                last_refill: now,
                request_count: 0,
            }
        });

        // Refill tokens
        let elapsed_ms = ((now - state.last_refill) * 1000).max(0) as f64;
        let tokens_per_ms = config.requests_per_minute as f64 / 60_000.0;
        let refill = elapsed_ms * tokens_per_ms;
        state.tokens = (state.tokens + refill).min(state.max_tokens);
        state.last_refill = now;

        state.request_count += 1;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            RateLimitResult {
                allowed: true,
                remaining: state.tokens as u64,
                retry_after_ms: None,
                detail: format!("{} tokens remaining", state.tokens as u64),
            }
        } else {
            let wait_ms = ((1.0 - state.tokens) / tokens_per_ms) as u64;
            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after_ms: Some(wait_ms),
                detail: format!("Rate limit exceeded, retry after {wait_ms}ms"),
            }
        }
    }

    pub fn reset(&mut self, key: &str) {
        self.limits.remove(key);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── GatewayOutcome ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayOutcome {
    Allow,
    Deny { reason: String },
    RateLimited { retry_after_ms: u64 },
    AuthRequired,
    MfaRequired,
    EndpointNotFound,
    MethodNotAllowed { allowed: Vec<HttpMethod> },
}

impl GatewayOutcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}

impl fmt::Display for GatewayOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny { reason } => write!(f, "Deny: {reason}"),
            Self::RateLimited { retry_after_ms } => {
                write!(f, "RateLimited(retry={retry_after_ms}ms)")
            }
            Self::AuthRequired => write!(f, "AuthRequired"),
            Self::MfaRequired => write!(f, "MfaRequired"),
            Self::EndpointNotFound => write!(f, "EndpointNotFound"),
            Self::MethodNotAllowed { allowed } => {
                let methods: Vec<String> = allowed.iter().map(|m| m.to_string()).collect();
                write!(f, "MethodNotAllowed(allowed: {})", methods.join(", "))
            }
        }
    }
}

// ── GatewayCheck ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

// ── GatewayDecision ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayDecision {
    pub request_id: String,
    pub endpoint: Option<EndpointId>,
    pub outcome: GatewayOutcome,
    pub checks: Vec<GatewayCheck>,
    pub processing_time_us: u64,
    pub timestamp: i64,
}

// ── GatewayStats ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayStats {
    pub total_requests: u64,
    pub allowed: u64,
    pub denied: u64,
    pub rate_limited: u64,
    pub auth_required: u64,
    pub not_found: u64,
    pub denial_rate: f64,
    pub rate_limit_rate: f64,
}

impl fmt::Display for GatewayStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Gateway: {} requests ({} allowed, {} denied, {} rate-limited, {} auth-required, {} not-found) denial_rate={:.2}% rl_rate={:.2}%",
            self.total_requests,
            self.allowed,
            self.denied,
            self.rate_limited,
            self.auth_required,
            self.not_found,
            self.denial_rate * 100.0,
            self.rate_limit_rate * 100.0,
        )
    }
}

// ── ApiGateway ───────────────────────────────────────────────────────

pub struct ApiGateway {
    config: GatewayConfig,
    endpoints: EndpointRegistry,
    rate_limiter: RateLimiter,
    request_validator: RequestValidator,
    response_governor: ResponseGovernor,
    request_count: u64,
    denied_count: u64,
    rate_limited_count: u64,
    auth_required_count: u64,
    not_found_count: u64,
}

impl ApiGateway {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            endpoints: EndpointRegistry::new(),
            rate_limiter: RateLimiter::new(),
            request_validator: RequestValidator::new(),
            response_governor: ResponseGovernor::new(ResponsePolicy::new()),
            request_count: 0,
            denied_count: 0,
            rate_limited_count: 0,
            auth_required_count: 0,
            not_found_count: 0,
        }
    }

    pub fn with_endpoints(mut self, endpoints: EndpointRegistry) -> Self {
        self.endpoints = endpoints;
        self
    }

    pub fn register_endpoint(&mut self, endpoint: Endpoint) -> Result<(), WebError> {
        self.endpoints.register(endpoint)
    }

    pub fn process_request(&mut self, request: &WebRequest, now: i64) -> GatewayDecision {
        self.request_count += 1;
        let mut checks = Vec::new();

        // a. Match endpoint
        let endpoint = self.endpoints.match_path(&request.path, request.method);
        let Some(endpoint) = endpoint else {
            self.not_found_count += 1;
            return GatewayDecision {
                request_id: request.id.clone(),
                endpoint: None,
                outcome: GatewayOutcome::EndpointNotFound,
                checks,
                processing_time_us: 0,
                timestamp: now,
            };
        };

        let endpoint_id = endpoint.id.clone();

        // c. Auth check
        if endpoint.auth_required && request.identity.is_none() {
            self.auth_required_count += 1;
            checks.push(GatewayCheck {
                name: "auth".into(),
                passed: false,
                detail: "Authentication required".into(),
            });
            return GatewayDecision {
                request_id: request.id.clone(),
                endpoint: Some(endpoint_id),
                outcome: GatewayOutcome::AuthRequired,
                checks,
                processing_time_us: 0,
                timestamp: now,
            };
        }

        // d. MFA check
        if endpoint.mfa_required {
            let has_mfa = request
                .headers
                .keys()
                .any(|k| k.to_lowercase() == "x-mfa-verified");
            if !has_mfa {
                checks.push(GatewayCheck {
                    name: "mfa".into(),
                    passed: false,
                    detail: "MFA verification required".into(),
                });
                return GatewayDecision {
                    request_id: request.id.clone(),
                    endpoint: Some(endpoint_id),
                    outcome: GatewayOutcome::MfaRequired,
                    checks,
                    processing_time_us: 0,
                    timestamp: now,
                };
            }
        }

        // e. Rate limit
        let rate_config = endpoint
            .rate_limit
            .as_ref()
            .unwrap_or(&self.config.default_rate_limit);
        let rate_key = if rate_config.per_identity {
            request.identity.clone().unwrap_or_else(|| request.source_ip.clone())
        } else if rate_config.per_ip {
            request.source_ip.clone()
        } else {
            "global".into()
        };
        let rate_result = self.rate_limiter.check(&rate_key, rate_config, now);
        if !rate_result.allowed {
            self.rate_limited_count += 1;
            checks.push(GatewayCheck {
                name: "rate_limit".into(),
                passed: false,
                detail: rate_result.detail.clone(),
            });
            return GatewayDecision {
                request_id: request.id.clone(),
                endpoint: Some(endpoint_id),
                outcome: GatewayOutcome::RateLimited {
                    retry_after_ms: rate_result.retry_after_ms.unwrap_or(1000),
                },
                checks,
                processing_time_us: 0,
                timestamp: now,
            };
        }
        checks.push(GatewayCheck {
            name: "rate_limit".into(),
            passed: true,
            detail: rate_result.detail,
        });

        // f. Validate request
        let validation = self.request_validator.validate(request);
        if !validation.valid {
            self.denied_count += 1;
            let failed: Vec<String> = validation
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.detail.clone())
                .collect();
            checks.push(GatewayCheck {
                name: "validation".into(),
                passed: false,
                detail: failed.join("; "),
            });
            return GatewayDecision {
                request_id: request.id.clone(),
                endpoint: Some(endpoint_id),
                outcome: GatewayOutcome::Deny {
                    reason: "Request validation failed".into(),
                },
                checks,
                processing_time_us: 0,
                timestamp: now,
            };
        }
        checks.push(GatewayCheck {
            name: "validation".into(),
            passed: true,
            detail: "All checks passed".into(),
        });

        // g. Role check
        if !endpoint.allowed_roles.is_empty() {
            // For Layer 1, roles are passed via header X-Roles (comma-separated)
            let user_roles: Vec<String> = request
                .headers
                .get("X-Roles")
                .or_else(|| request.headers.get("x-roles"))
                .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();
            let has_role = endpoint
                .allowed_roles
                .iter()
                .any(|r| user_roles.contains(r));
            if !has_role {
                self.denied_count += 1;
                checks.push(GatewayCheck {
                    name: "role".into(),
                    passed: false,
                    detail: "Insufficient role permissions".into(),
                });
                return GatewayDecision {
                    request_id: request.id.clone(),
                    endpoint: Some(endpoint_id),
                    outcome: GatewayOutcome::Deny {
                        reason: "Insufficient role permissions".into(),
                    },
                    checks,
                    processing_time_us: 0,
                    timestamp: now,
                };
            }
        }

        // Allow
        GatewayDecision {
            request_id: request.id.clone(),
            endpoint: Some(endpoint_id),
            outcome: GatewayOutcome::Allow,
            checks,
            processing_time_us: 0,
            timestamp: now,
        }
    }

    pub fn process_response(&mut self, response: &mut WebResponse) -> ResponseGovernanceResult {
        self.response_governor.govern(response)
    }

    pub fn stats(&self) -> GatewayStats {
        let total = self.request_count;
        let denied = self.denied_count;
        let rate_limited = self.rate_limited_count;
        let auth_required = self.auth_required_count;
        let not_found = self.not_found_count;
        let allowed = total - denied - rate_limited - auth_required - not_found;
        GatewayStats {
            total_requests: total,
            allowed,
            denied,
            rate_limited,
            auth_required,
            not_found,
            denial_rate: if total > 0 { denied as f64 / total as f64 } else { 0.0 },
            rate_limit_rate: if total > 0 { rate_limited as f64 / total as f64 } else { 0.0 },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{Endpoint, EndpointClassification};

    fn test_gateway() -> ApiGateway {
        let config = GatewayConfig::new("test-gateway");
        let mut gateway = ApiGateway::new(config);
        gateway
            .register_endpoint(
                Endpoint::new("ep1", "/api/v1/data", HttpMethod::Get, EndpointClassification::Authenticated)
                    .with_rate_limit(RateLimitConfig {
                        requests_per_minute: 60,
                        burst_size: 5,
                        per_ip: true,
                        per_identity: false,
                    }),
            )
            .unwrap();
        gateway
            .register_endpoint(
                Endpoint::new("ep2", "/api/v1/admin", HttpMethod::Post, EndpointClassification::Critical)
                    .with_roles(vec!["admin".into()]),
            )
            .unwrap();
        gateway
            .register_endpoint(
                Endpoint::new("ep3", "/public/health", HttpMethod::Get, EndpointClassification::Public),
            )
            .unwrap();
        gateway
            .register_endpoint(
                Endpoint::new("ep4", "/api/v1/old", HttpMethod::Get, EndpointClassification::Authenticated)
                    .with_deprecated(1000, "/api/v2/new"),
            )
            .unwrap();
        gateway
    }

    fn valid_request(path: &str, method: HttpMethod) -> WebRequest {
        WebRequest::new("r1", method, path, "1.2.3.4", 1000)
            .with_header("Host", "api.example.com")
            .with_identity("user1")
    }

    #[test]
    fn test_gateway_allows_valid_request() {
        let mut gw = test_gateway();
        let req = valid_request("/api/v1/data", HttpMethod::Get);
        let decision = gw.process_request(&req, 1000);
        assert!(decision.outcome.is_allowed());
        assert_eq!(decision.endpoint.unwrap().0, "ep1");
    }

    #[test]
    fn test_gateway_endpoint_not_found() {
        let mut gw = test_gateway();
        let req = valid_request("/nonexistent", HttpMethod::Get);
        let decision = gw.process_request(&req, 1000);
        assert_eq!(decision.outcome, GatewayOutcome::EndpointNotFound);
    }

    #[test]
    fn test_gateway_auth_required() {
        let mut gw = test_gateway();
        let req = WebRequest::new("r1", HttpMethod::Get, "/api/v1/data", "1.2.3.4", 1000)
            .with_header("Host", "api.example.com");
        // No identity
        let decision = gw.process_request(&req, 1000);
        assert_eq!(decision.outcome, GatewayOutcome::AuthRequired);
    }

    #[test]
    fn test_gateway_mfa_required() {
        let mut gw = test_gateway();
        let req = WebRequest::new("r1", HttpMethod::Post, "/api/v1/admin", "1.2.3.4", 1000)
            .with_header("Host", "api.example.com")
            .with_header("Content-Type", "application/json")
            .with_header("X-Roles", "admin")
            .with_identity("admin1")
            .with_body("{}");
        // No MFA header
        let decision = gw.process_request(&req, 1000);
        assert_eq!(decision.outcome, GatewayOutcome::MfaRequired);
    }

    #[test]
    fn test_gateway_rate_limited() {
        let mut gw = test_gateway();
        // Exhaust the 5-burst rate limit
        for i in 0..5 {
            let req = WebRequest::new(format!("r{i}"), HttpMethod::Get, "/api/v1/data", "1.2.3.4", 1000)
                .with_header("Host", "api.example.com")
                .with_identity("user1");
            let d = gw.process_request(&req, 1000);
            assert!(d.outcome.is_allowed(), "request {i} should be allowed");
        }
        // 6th request should be rate limited
        let req = valid_request("/api/v1/data", HttpMethod::Get);
        let decision = gw.process_request(&req, 1000);
        assert!(matches!(decision.outcome, GatewayOutcome::RateLimited { .. }));
    }

    #[test]
    fn test_gateway_deny_failed_validation() {
        let mut gw = test_gateway();
        // Register a blocked-path endpoint to test validation denial:
        gw.register_endpoint(
            Endpoint::new("ep_env", "/.env", HttpMethod::Get, EndpointClassification::Public),
        ).unwrap();
        let req2 = WebRequest::new("r2", HttpMethod::Get, "/.env", "1.2.3.4", 1000)
            .with_header("Host", "api.example.com");
        let decision = gw.process_request(&req2, 1000);
        assert!(matches!(decision.outcome, GatewayOutcome::Deny { .. }));
    }

    #[test]
    fn test_gateway_tracks_stats() {
        let mut gw = test_gateway();
        let req = valid_request("/api/v1/data", HttpMethod::Get);
        gw.process_request(&req, 1000);
        let req2 = valid_request("/nonexistent", HttpMethod::Get);
        gw.process_request(&req2, 1000);
        let stats = gw.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.not_found, 1);
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut rl = RateLimiter::new();
        let config = RateLimitConfig::default_public();
        let result = rl.check("ip:1.2.3.4", &config, 1000);
        assert!(result.allowed);
    }

    #[test]
    fn test_rate_limiter_denies_exhausted() {
        let mut rl = RateLimiter::new();
        let config = RateLimitConfig {
            requests_per_minute: 60,
            burst_size: 2,
            per_ip: true,
            per_identity: false,
        };
        rl.check("ip:1.2.3.4", &config, 1000); // 1 token left
        rl.check("ip:1.2.3.4", &config, 1000); // 0 tokens
        let result = rl.check("ip:1.2.3.4", &config, 1000); // denied
        assert!(!result.allowed);
        assert!(result.retry_after_ms.is_some());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut rl = RateLimiter::new();
        let config = RateLimitConfig {
            requests_per_minute: 60,
            burst_size: 2,
            per_ip: true,
            per_identity: false,
        };
        rl.check("ip:1.2.3.4", &config, 1000);
        rl.check("ip:1.2.3.4", &config, 1000);
        // Wait 2 seconds = 2 tokens refilled at 1/sec
        let result = rl.check("ip:1.2.3.4", &config, 1002);
        assert!(result.allowed);
    }

    #[test]
    fn test_rate_limiter_reset() {
        let mut rl = RateLimiter::new();
        let config = RateLimitConfig::default_public();
        rl.check("ip:1.2.3.4", &config, 1000);
        rl.reset("ip:1.2.3.4");
        // After reset, tokens are full again
        let result = rl.check("ip:1.2.3.4", &config, 1000);
        assert!(result.allowed);
        assert_eq!(result.remaining, config.burst_size - 1);
    }

    #[test]
    fn test_gateway_outcome_is_allowed_and_denied() {
        assert!(GatewayOutcome::Allow.is_allowed());
        assert!(!GatewayOutcome::Allow.is_denied());
        assert!(!GatewayOutcome::AuthRequired.is_allowed());
        assert!(GatewayOutcome::AuthRequired.is_denied());
        assert!(GatewayOutcome::Deny { reason: "x".into() }.is_denied());
    }

    #[test]
    fn test_gateway_stats_display() {
        let stats = GatewayStats {
            total_requests: 100,
            allowed: 80,
            denied: 5,
            rate_limited: 10,
            auth_required: 3,
            not_found: 2,
            denial_rate: 0.05,
            rate_limit_rate: 0.10,
        };
        let s = stats.to_string();
        assert!(s.contains("100 requests"));
        assert!(s.contains("80 allowed"));
    }

    #[test]
    fn test_gateway_deprecated_endpoint() {
        let mut gw = test_gateway();
        let req = valid_request("/api/v1/old", HttpMethod::Get);
        let decision = gw.process_request(&req, 1000);
        // Deprecated endpoints still allow access
        assert!(decision.outcome.is_allowed());
    }
}
