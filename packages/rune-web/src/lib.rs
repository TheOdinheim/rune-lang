// ═══════════════════════════════════════════════════════════════════════
// rune-web — API gateway protection, HTTP governance, endpoint
// classification, request signing, web threat mitigation, and session
// governance for the RUNE governance ecosystem.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod auth_validator;
pub mod backend;
pub mod cors;
pub mod cors_policy;
pub mod endpoint;
pub mod error;
pub mod gateway;
pub mod http_adapter;
pub mod rate_limit;
pub mod request;
pub mod request_log_export;
pub mod request_stream;
pub mod response;
pub mod session;
pub mod signing;
pub mod threat;

// ── Re-exports ───────────────────────────────────────────────────────

pub use audit::{WebAuditEvent, WebAuditLog, WebEventType};
pub use cors::{
    CorsChecker, CorsPolicy, CorsResult, CorsViolation, PreflightCache, is_valid_origin,
    vary_origin_header,
};
pub use endpoint::{
    Endpoint, EndpointClassification, EndpointId, EndpointRegistry, HttpMethod, RateLimitConfig,
};
pub use error::WebError;
pub use gateway::{
    ApiGateway, EndpointRateLimiter, GatewayCheck, GatewayConfig, GatewayContext,
    GatewayDecision, GatewayHealthMetrics, GatewayOutcome, GatewayStats, GatewayTiming,
    MiddlewareFn, MiddlewareResult, RateLimitHeaders, RateLimitResult, RateLimiter,
    RateLimiterStats, SlidingWindowLimiter,
};
pub use request::{
    RequestCheck, RequestValidation, RequestValidator, WebRequest, is_loopback, is_private_ip,
    is_valid_ipv4,
};
pub use response::{
    DataLeakageFind, DataLeakageScanner, DataLeakageType, ResponseGovernanceResult,
    ResponseGovernor, ResponsePolicy, WebResponse,
};
pub use session::{
    SameSitePolicy, SessionBinding, SessionTokenHasher, SessionValidation, WebSession,
    WebSessionConfig, WebSessionStore,
};
pub use signing::{
    RequestSigner, SignatureMetadata, SignatureVerification, SignedRequest, SigningAlgorithm,
    SigningConfig, derive_signing_key,
};
pub use threat::{WebThreatCheck, WebThreatDetector, WebThreatType};

// ── Layer 3 re-exports ──────────────────────────────────────────────

pub use auth_validator::{
    ApiKeyValidator, JwtStructureValidator, SessionCookieValidator, TokenValidator,
    ValidationResult,
};
pub use backend::{ApiKeyBinding, BackendInfo, InMemoryWebBackend, RoutePolicy, WebBackend};
pub use cors_policy::{
    CorsDecision, CorsPolicyBackendInfo, CorsPolicyStore, InMemoryCorsPolicyStore,
    StoredCorsPolicy,
};
pub use http_adapter::{
    HttpAdapter, InterceptResult, PassThroughHttpAdapter, RecordingHttpAdapter,
};
pub use rate_limit::{
    BucketStatus, InMemoryLeakyBucket, InMemorySlidingWindow, InMemoryTokenBucket,
    RateLimitBackend, RateLimitBackendInfo, RateLimitDecision,
};
pub use request_log_export::{
    CombinedLogFormatExporter, CommonLogFormatExporter, EcsHttpExporter, JsonRequestLogExporter,
    OtelHttpExporter, RequestLogEntry, RequestLogExporter,
};
pub use request_stream::{
    FilteredRequestSubscriber, RequestCollector, RequestEvent, RequestLifecycleEvent,
    RequestLifecycleEventType, RequestSubscriber, RequestSubscriberRegistry,
};
