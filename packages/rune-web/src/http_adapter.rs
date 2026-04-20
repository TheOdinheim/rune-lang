// ═══════════════════════════════════════════════════════════════════════
// HTTP Adapter — Framework-neutral HTTP interception trait.
//
// Layer 3 defines the contract for plugging any Rust web framework
// (axum, actix, hyper, tower, warp, rocket) into RUNE without
// rune-web binding to any one of them. The trait operates on
// framework-neutral WebRequest and WebResponse types. Downstream
// adapter crates (rune-web-axum, rune-web-actix, etc.) implement
// this trait to bridge framework-specific types.
// ═══════════════════════════════════════════════════════════════════════

use crate::error::WebError;
use crate::request::WebRequest;
use crate::response::WebResponse;

// ── InterceptResult ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptResult {
    /// Request passes through unmodified.
    Continue,
    /// Request was modified; use the updated request.
    Modified,
    /// Request was rejected; respond immediately with this status.
    Reject { status_code: u16, reason: String },
}

// ── HttpAdapter trait ──────────────────────────────────────────

pub trait HttpAdapter {
    fn intercept_request(&mut self, request: &mut WebRequest) -> Result<InterceptResult, WebError>;
    fn emit_response(&mut self, response: &mut WebResponse) -> Result<(), WebError>;
    fn adapter_name(&self) -> &str;
    fn framework_version(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── RecordingHttpAdapter ───────────────────────────────────────

/// Records every intercepted request and emitted response for testing.
pub struct RecordingHttpAdapter {
    name: String,
    intercepted_requests: Vec<WebRequest>,
    emitted_responses: Vec<WebResponse>,
    active: bool,
}

impl RecordingHttpAdapter {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            intercepted_requests: Vec::new(),
            emitted_responses: Vec::new(),
            active: true,
        }
    }

    pub fn intercepted_requests(&self) -> &[WebRequest] {
        &self.intercepted_requests
    }

    pub fn emitted_responses(&self) -> &[WebResponse] {
        &self.emitted_responses
    }

    pub fn request_count(&self) -> usize {
        self.intercepted_requests.len()
    }

    pub fn response_count(&self) -> usize {
        self.emitted_responses.len()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl HttpAdapter for RecordingHttpAdapter {
    fn intercept_request(&mut self, request: &mut WebRequest) -> Result<InterceptResult, WebError> {
        self.intercepted_requests.push(request.clone());
        Ok(InterceptResult::Continue)
    }

    fn emit_response(&mut self, response: &mut WebResponse) -> Result<(), WebError> {
        self.emitted_responses.push(response.clone());
        Ok(())
    }

    fn adapter_name(&self) -> &str {
        &self.name
    }

    fn framework_version(&self) -> &str {
        "recording/1.0"
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── PassThroughHttpAdapter ─────────────────────────────────────

/// Forwards without modification. Useful for performance baselines.
pub struct PassThroughHttpAdapter {
    name: String,
    request_count: u64,
    response_count: u64,
    active: bool,
}

impl PassThroughHttpAdapter {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            request_count: 0,
            response_count: 0,
            active: true,
        }
    }

    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    pub fn response_count(&self) -> u64 {
        self.response_count
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl HttpAdapter for PassThroughHttpAdapter {
    fn intercept_request(&mut self, _request: &mut WebRequest) -> Result<InterceptResult, WebError> {
        self.request_count += 1;
        Ok(InterceptResult::Continue)
    }

    fn emit_response(&mut self, _response: &mut WebResponse) -> Result<(), WebError> {
        self.response_count += 1;
        Ok(())
    }

    fn adapter_name(&self) -> &str {
        &self.name
    }

    fn framework_version(&self) -> &str {
        "passthrough/1.0"
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
    use crate::endpoint::HttpMethod;

    fn make_request() -> WebRequest {
        WebRequest::new("req-1", HttpMethod::Get, "/api/v1/test", "1.2.3.4", 1000)
            .with_header("Host", "example.com")
    }

    fn make_response() -> WebResponse {
        WebResponse::new(200).with_header("Content-Type", "application/json")
    }

    #[test]
    fn test_recording_adapter_intercepts() {
        let mut adapter = RecordingHttpAdapter::new("test-recorder");
        let mut req = make_request();
        let result = adapter.intercept_request(&mut req).unwrap();
        assert_eq!(result, InterceptResult::Continue);
        assert_eq!(adapter.request_count(), 1);
        assert_eq!(adapter.intercepted_requests()[0].id, "req-1");
    }

    #[test]
    fn test_recording_adapter_emits() {
        let mut adapter = RecordingHttpAdapter::new("test-recorder");
        let mut resp = make_response();
        adapter.emit_response(&mut resp).unwrap();
        assert_eq!(adapter.response_count(), 1);
        assert_eq!(adapter.emitted_responses()[0].status_code, 200);
    }

    #[test]
    fn test_recording_adapter_metadata() {
        let adapter = RecordingHttpAdapter::new("test-recorder");
        assert_eq!(adapter.adapter_name(), "test-recorder");
        assert_eq!(adapter.framework_version(), "recording/1.0");
        assert!(adapter.is_active());
    }

    #[test]
    fn test_recording_adapter_deactivate() {
        let mut adapter = RecordingHttpAdapter::new("test-recorder");
        adapter.deactivate();
        assert!(!adapter.is_active());
    }

    #[test]
    fn test_passthrough_adapter_counts() {
        let mut adapter = PassThroughHttpAdapter::new("bench");
        let mut req = make_request();
        let mut resp = make_response();
        adapter.intercept_request(&mut req).unwrap();
        adapter.intercept_request(&mut req).unwrap();
        adapter.emit_response(&mut resp).unwrap();
        assert_eq!(adapter.request_count(), 2);
        assert_eq!(adapter.response_count(), 1);
    }

    #[test]
    fn test_passthrough_adapter_metadata() {
        let adapter = PassThroughHttpAdapter::new("bench");
        assert_eq!(adapter.adapter_name(), "bench");
        assert_eq!(adapter.framework_version(), "passthrough/1.0");
        assert!(adapter.is_active());
    }

    #[test]
    fn test_passthrough_adapter_deactivate() {
        let mut adapter = PassThroughHttpAdapter::new("bench");
        adapter.deactivate();
        assert!(!adapter.is_active());
    }

    #[test]
    fn test_intercept_result_variants() {
        let cont = InterceptResult::Continue;
        let modified = InterceptResult::Modified;
        let reject = InterceptResult::Reject {
            status_code: 403,
            reason: "Forbidden".into(),
        };
        assert_eq!(cont, InterceptResult::Continue);
        assert_eq!(modified, InterceptResult::Modified);
        assert_ne!(cont, reject);
    }

    #[test]
    fn test_multiple_request_response_cycle() {
        let mut adapter = RecordingHttpAdapter::new("cycle-test");
        for i in 0..5 {
            let mut req = WebRequest::new(
                format!("req-{i}"),
                HttpMethod::Post,
                "/api/data",
                "10.0.0.1",
                1000 + i,
            );
            adapter.intercept_request(&mut req).unwrap();
        }
        assert_eq!(adapter.request_count(), 5);
    }
}
