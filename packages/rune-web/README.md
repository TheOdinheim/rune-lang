# rune-web

API gateway protection, HTTP request/response governance, endpoint classification, request signing, web threat mitigation, and session governance for the RUNE governance ecosystem.

## Overview

`rune-web` governs the HTTP boundary of RUNE-protected systems. Every HTTP request entering a RUNE-governed service passes through rune-web's governance boundary: authentication is verified, rate limits are enforced, endpoints are classified by sensitivity, requests are validated against security rules, responses are checked for data leakage, and the full exchange is audit-logged.

This is the web-specific counterpart to rune-shield's inference boundary — rune-shield guards the AI model boundary, rune-web guards the HTTP boundary.

## Modules

| Module | Purpose |
|--------|---------|
| `endpoint` | EndpointId (newtype), Endpoint (14 fields), HttpMethod (7 variants), EndpointClassification (6 levels: Public→Critical with Ord), RateLimitConfig (3 presets: default_public/default_authenticated/default_internal), EndpointRegistry (register/get/match_path with pattern matching/by_classification/deprecated_endpoints/sensitive_endpoints) |
| `request` | WebRequest (10 fields), RequestValidation (valid/checks/sanitized_path/risk_score), RequestCheck, RequestValidator (7 configurable limits, blocked paths, required headers, with_defaults per classification), validate (9 checks: path length/traversal/blocked/header count+size/required headers/query params/body size/content-type), sanitize_path, is_path_traversal, is_blocked_path |
| `response` | WebResponse, ResponsePolicy (6 toggles, strict preset), ResponseGovernor (govern with security header injection/server stripping/data leakage scanning), DataLeakageType (5 variants: InternalIpAddress/StackTrace/InternalPath/SecretExposure/DebugInformation), ResponseGovernanceResult |
| `gateway` | GatewayConfig, RateLimiter (token bucket: check/reset), RateLimitResult, ApiGateway (process_request/process_response/stats/register_endpoint), GatewayOutcome (7 variants: Allow/Deny/RateLimited/AuthRequired/MfaRequired/EndpointNotFound/MethodNotAllowed), GatewayDecision, GatewayStats |
| `signing` | SigningAlgorithm (HmacSha3_256/HmacSha256), SigningConfig (6 fields), RequestSigner (sign/verify with canonical string construction/constant-time comparison), SignedRequest, SignatureVerification (valid/reason/clock_skew_ms) |
| `threat` | WebThreatType (8 variants: Csrf/Clickjacking/ContentInjection/OpenRedirect/HttpMethodOverride/HeaderInjection/HostHeaderAttack/SlowlorisAttack), WebThreatCheck, WebThreatDetector (scan_request with 6 active checks, csrf_token_present, check_open_redirect) |
| `session` | SameSitePolicy (Strict/Lax/None), WebSessionConfig (9 fields with secure defaults), WebSession (10 fields), WebSessionStore (create/get/validate/touch/authenticate with session regeneration/verify_mfa/invalidate/invalidate_all_for_identity/active_sessions/cleanup_expired/cookie_attributes), SessionValidation |
| `cors` | CorsPolicy (3 presets: permissive/strict/none), CorsChecker (check_preflight/check_simple/response_headers), CorsResult |
| `audit` | WebEventType (15 variants), WebAuditEvent (6 fields), WebAuditLog (record/events_by_severity/events_for_request/since/threat_events/rate_limit_events/session_events/data_leakage_events) |
| `error` | WebError with 13 typed variants |

## Four-pillar alignment

- **Security Baked In**: Every HTTP request passes through multi-layered validation (path traversal detection, blocked paths, header injection scanning, CSRF protection, content-type verification). Response governance enforces security headers (HSTS, CSP-adjacent, X-Frame-Options, Referrer-Policy) and strips fingerprinting headers (Server, X-Powered-By). Request signing uses HMAC with constant-time comparison and clock skew protection.
- **Assumed Breach**: Data leakage scanning catches internal IP addresses, stack traces, file system paths, credentials, and debug information in outbound responses. Session governance provides idle timeouts, session regeneration on authentication (prevents fixation), and bulk invalidation. Rate limiting uses token bucket algorithm to contain abuse.
- **Zero Trust Throughout**: Endpoints are classified by sensitivity (Public→Critical) with proportional controls. Authentication is required by default. MFA enforcement for critical operations. Role-based access control at the gateway level. CORS enforcement prevents unauthorized cross-origin access. Open redirect detection blocks exfiltration.
- **No Single Points of Failure**: Multiple validation layers (endpoint classification, request validation, rate limiting, threat detection, response governance). Multiple threat detection checks run independently. Session store supports concurrent session limits per identity. Gateway tracks comprehensive stats for operational visibility.

## Test summary

107 tests covering all modules:

| Module | Tests |
|--------|-------|
| error | 1 |
| endpoint | 13 |
| request | 13 |
| response | 13 |
| gateway | 14 |
| signing | 9 |
| threat | 10 |
| session | 16 |
| cors | 10 |
| audit | 8 |
