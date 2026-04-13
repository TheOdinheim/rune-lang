// ═══════════════════════════════════════════════════════════════════════
// rune-web — API gateway protection, HTTP governance, endpoint
// classification, request signing, web threat mitigation, and session
// governance for the RUNE governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod cors;
pub mod endpoint;
pub mod error;
pub mod gateway;
pub mod request;
pub mod response;
pub mod session;
pub mod signing;
pub mod threat;

// ── Re-exports ───────────────────────────────────────────────────────

pub use audit::{WebAuditEvent, WebAuditLog, WebEventType};
pub use cors::{CorsChecker, CorsPolicy, CorsResult};
pub use endpoint::{
    Endpoint, EndpointClassification, EndpointId, EndpointRegistry, HttpMethod, RateLimitConfig,
};
pub use error::WebError;
pub use gateway::{
    ApiGateway, GatewayCheck, GatewayConfig, GatewayDecision, GatewayOutcome, GatewayStats,
    RateLimitResult, RateLimiter,
};
pub use request::{RequestCheck, RequestValidation, RequestValidator, WebRequest};
pub use response::{
    DataLeakageFind, DataLeakageType, ResponseGovernanceResult, ResponseGovernor, ResponsePolicy,
    WebResponse,
};
pub use session::{
    SameSitePolicy, SessionValidation, WebSession, WebSessionConfig, WebSessionStore,
};
pub use signing::{
    RequestSigner, SignatureVerification, SignedRequest, SigningAlgorithm, SigningConfig,
};
pub use threat::{WebThreatCheck, WebThreatDetector, WebThreatType};
