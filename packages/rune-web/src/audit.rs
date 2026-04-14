// ═══════════════════════════════════════════════════════════════════════
// Audit — Web-specific audit events for request/response governance,
// session management, and threat detection.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use rune_security::SecuritySeverity;

// ── WebEventType ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebEventType {
    RequestReceived { method: String, path: String },
    RequestAllowed { endpoint_id: String },
    RequestDenied { reason: String },
    RateLimited { key: String, retry_after_ms: u64 },
    AuthRequired { path: String },
    MfaRequired { path: String },
    ValidationFailed { checks: usize },
    ThreatDetected { threat_type: String, confidence: f64 },
    DataLeakageDetected { leak_type: String },
    SessionCreated { session_id: String },
    SessionInvalidated { session_id: String },
    SignatureVerified { key_id: String, valid: bool },
    CorsBlocked { origin: String },
    DeprecatedEndpointAccessed { endpoint: String, successor: String },
    ResponseGoverned { headers_added: usize, leaks_found: usize },
    // Layer 2 additions
    HmacSignatureVerified { key_id: String, algorithm: String },
    SessionTokenHashed { session_id: String },
    RegexPatternBlocked { pattern_name: String, input_snippet: String },
    SlidingWindowLimited { key: String, window_ms: i64 },
    DataLeakageRegexMatch { leak_type: String, pattern: String },
    CorsViolationLogged { origin: String, reason: String },
    MiddlewareExecuted { middleware_name: String, result: String },
    GatewayTimingRecorded { total_us: i64 },
}

impl fmt::Display for WebEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestReceived { method, path } => {
                write!(f, "RequestReceived({method} {path})")
            }
            Self::RequestAllowed { endpoint_id } => {
                write!(f, "RequestAllowed({endpoint_id})")
            }
            Self::RequestDenied { reason } => write!(f, "RequestDenied({reason})"),
            Self::RateLimited { key, retry_after_ms } => {
                write!(f, "RateLimited({key}, retry={retry_after_ms}ms)")
            }
            Self::AuthRequired { path } => write!(f, "AuthRequired({path})"),
            Self::MfaRequired { path } => write!(f, "MfaRequired({path})"),
            Self::ValidationFailed { checks } => {
                write!(f, "ValidationFailed({checks} checks)")
            }
            Self::ThreatDetected { threat_type, confidence } => {
                write!(f, "ThreatDetected({threat_type}, confidence={confidence:.2})")
            }
            Self::DataLeakageDetected { leak_type } => {
                write!(f, "DataLeakageDetected({leak_type})")
            }
            Self::SessionCreated { session_id } => {
                write!(f, "SessionCreated({session_id})")
            }
            Self::SessionInvalidated { session_id } => {
                write!(f, "SessionInvalidated({session_id})")
            }
            Self::SignatureVerified { key_id, valid } => {
                write!(f, "SignatureVerified({key_id}, valid={valid})")
            }
            Self::CorsBlocked { origin } => write!(f, "CorsBlocked({origin})"),
            Self::DeprecatedEndpointAccessed { endpoint, successor } => {
                write!(f, "DeprecatedEndpointAccessed({endpoint} → {successor})")
            }
            Self::ResponseGoverned { headers_added, leaks_found } => {
                write!(f, "ResponseGoverned(+{headers_added} headers, {leaks_found} leaks)")
            }
            Self::HmacSignatureVerified { key_id, algorithm } => {
                write!(f, "HmacSignatureVerified({key_id}, {algorithm})")
            }
            Self::SessionTokenHashed { session_id } => {
                write!(f, "SessionTokenHashed({session_id})")
            }
            Self::RegexPatternBlocked { pattern_name, input_snippet } => {
                write!(f, "RegexPatternBlocked({pattern_name}: {input_snippet})")
            }
            Self::SlidingWindowLimited { key, window_ms } => {
                write!(f, "SlidingWindowLimited({key}, window={window_ms}ms)")
            }
            Self::DataLeakageRegexMatch { leak_type, pattern } => {
                write!(f, "DataLeakageRegexMatch({leak_type}: {pattern})")
            }
            Self::CorsViolationLogged { origin, reason } => {
                write!(f, "CorsViolationLogged({origin}: {reason})")
            }
            Self::MiddlewareExecuted { middleware_name, result } => {
                write!(f, "MiddlewareExecuted({middleware_name}: {result})")
            }
            Self::GatewayTimingRecorded { total_us } => {
                write!(f, "GatewayTimingRecorded({total_us}us)")
            }
        }
    }
}

// ── WebAuditEvent ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WebAuditEvent {
    pub event_type: WebEventType,
    pub severity: SecuritySeverity,
    pub timestamp: i64,
    pub source_ip: String,
    pub detail: String,
    pub request_id: Option<String>,
}

// ── WebAuditLog ──────────────────────────────────────────────────────

pub struct WebAuditLog {
    events: Vec<WebAuditEvent>,
}

impl WebAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: WebAuditEvent) {
        self.events.push(event);
    }

    pub fn events_by_severity(&self, severity: SecuritySeverity) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    pub fn events_for_request(&self, request_id: &str) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.request_id.as_deref() == Some(request_id))
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn threat_events(&self) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, WebEventType::ThreatDetected { .. }))
            .collect()
    }

    pub fn rate_limit_events(&self) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, WebEventType::RateLimited { .. }))
            .collect()
    }

    pub fn session_events(&self) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    WebEventType::SessionCreated { .. } | WebEventType::SessionInvalidated { .. }
                )
            })
            .collect()
    }

    pub fn data_leakage_events(&self) -> Vec<&WebAuditEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.event_type, WebEventType::DataLeakageDetected { .. }))
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for WebAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(event_type: WebEventType, severity: SecuritySeverity, request_id: Option<&str>) -> WebAuditEvent {
        WebAuditEvent {
            event_type,
            severity,
            timestamp: 1000,
            source_ip: "1.2.3.4".into(),
            detail: "test".into(),
            request_id: request_id.map(String::from),
        }
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::RequestReceived { method: "GET".into(), path: "/api".into() },
            SecuritySeverity::Info,
            Some("r1"),
        ));
        assert_eq!(log.event_count(), 1);
    }

    #[test]
    fn test_events_by_severity() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::RequestAllowed { endpoint_id: "ep1".into() },
            SecuritySeverity::Info,
            None,
        ));
        log.record(sample_event(
            WebEventType::RequestDenied { reason: "blocked".into() },
            SecuritySeverity::High,
            None,
        ));
        assert_eq!(log.events_by_severity(SecuritySeverity::Info).len(), 1);
        assert_eq!(log.events_by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_events_for_request() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::RequestReceived { method: "POST".into(), path: "/api".into() },
            SecuritySeverity::Info,
            Some("r1"),
        ));
        log.record(sample_event(
            WebEventType::RequestAllowed { endpoint_id: "ep1".into() },
            SecuritySeverity::Info,
            Some("r1"),
        ));
        log.record(sample_event(
            WebEventType::RequestReceived { method: "GET".into(), path: "/other".into() },
            SecuritySeverity::Info,
            Some("r2"),
        ));
        assert_eq!(log.events_for_request("r1").len(), 2);
        assert_eq!(log.events_for_request("r2").len(), 1);
    }

    #[test]
    fn test_threat_events() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::ThreatDetected { threat_type: "CSRF".into(), confidence: 0.9 },
            SecuritySeverity::High,
            None,
        ));
        log.record(sample_event(
            WebEventType::RequestAllowed { endpoint_id: "ep1".into() },
            SecuritySeverity::Info,
            None,
        ));
        assert_eq!(log.threat_events().len(), 1);
    }

    #[test]
    fn test_rate_limit_events() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::RateLimited { key: "ip:1.2.3.4".into(), retry_after_ms: 5000 },
            SecuritySeverity::Medium,
            None,
        ));
        assert_eq!(log.rate_limit_events().len(), 1);
    }

    #[test]
    fn test_session_events() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::SessionCreated { session_id: "s1".into() },
            SecuritySeverity::Info,
            None,
        ));
        log.record(sample_event(
            WebEventType::SessionInvalidated { session_id: "s1".into() },
            SecuritySeverity::Info,
            None,
        ));
        assert_eq!(log.session_events().len(), 2);
    }

    #[test]
    fn test_data_leakage_events() {
        let mut log = WebAuditLog::new();
        log.record(sample_event(
            WebEventType::DataLeakageDetected { leak_type: "InternalIP".into() },
            SecuritySeverity::High,
            None,
        ));
        assert_eq!(log.data_leakage_events().len(), 1);
    }

    #[test]
    fn test_web_event_type_display_all_variants() {
        let types: Vec<WebEventType> = vec![
            WebEventType::RequestReceived { method: "GET".into(), path: "/api".into() },
            WebEventType::RequestAllowed { endpoint_id: "ep1".into() },
            WebEventType::RequestDenied { reason: "blocked".into() },
            WebEventType::RateLimited { key: "ip".into(), retry_after_ms: 1000 },
            WebEventType::AuthRequired { path: "/admin".into() },
            WebEventType::MfaRequired { path: "/critical".into() },
            WebEventType::ValidationFailed { checks: 3 },
            WebEventType::ThreatDetected { threat_type: "CSRF".into(), confidence: 0.9 },
            WebEventType::DataLeakageDetected { leak_type: "IP".into() },
            WebEventType::SessionCreated { session_id: "s1".into() },
            WebEventType::SessionInvalidated { session_id: "s1".into() },
            WebEventType::SignatureVerified { key_id: "k1".into(), valid: true },
            WebEventType::CorsBlocked { origin: "evil.com".into() },
            WebEventType::DeprecatedEndpointAccessed { endpoint: "/old".into(), successor: "/new".into() },
            WebEventType::ResponseGoverned { headers_added: 5, leaks_found: 0 },
            // Layer 2
            WebEventType::HmacSignatureVerified { key_id: "k1".into(), algorithm: "HMAC-SHA3-256".into() },
            WebEventType::SessionTokenHashed { session_id: "s1".into() },
            WebEventType::RegexPatternBlocked { pattern_name: "ssti".into(), input_snippet: "{{".into() },
            WebEventType::SlidingWindowLimited { key: "user1".into(), window_ms: 60_000 },
            WebEventType::DataLeakageRegexMatch { leak_type: "PrivateKey".into(), pattern: "BEGIN".into() },
            WebEventType::CorsViolationLogged { origin: "evil.com".into(), reason: "not allowed".into() },
            WebEventType::MiddlewareExecuted { middleware_name: "auth".into(), result: "continue".into() },
            WebEventType::GatewayTimingRecorded { total_us: 1500 },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 23);
    }
}
