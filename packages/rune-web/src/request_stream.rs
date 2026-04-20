// ═══════════════════════════════════════════════════════════════════════
// Request Stream — Request event streaming and subscriber registry.
//
// Layer 3 defines the contract for streaming HTTP request lifecycle
// events to external consumers. Mirrors the FindingSubscriber
// pattern from rune-detection.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::request::WebRequest;

// ── RequestLifecycleEventType ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestLifecycleEventType {
    RequestReceived,
    RequestValidated,
    RequestRejected { reason: String },
    ResponseEmitted { status_code: u16 },
    RateLimitTriggered { key: String },
    CorsPreflightHandled { origin: String },
    SessionCreated { session_id: String },
    SessionExpired { session_id: String },
    ApiKeyValidated { key_id: String },
    ApiKeyRejected { key_id: String, reason: String },
}

impl fmt::Display for RequestLifecycleEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestReceived => write!(f, "RequestReceived"),
            Self::RequestValidated => write!(f, "RequestValidated"),
            Self::RequestRejected { reason } => write!(f, "RequestRejected({reason})"),
            Self::ResponseEmitted { status_code } => write!(f, "ResponseEmitted({status_code})"),
            Self::RateLimitTriggered { key } => write!(f, "RateLimitTriggered({key})"),
            Self::CorsPreflightHandled { origin } => write!(f, "CorsPreflightHandled({origin})"),
            Self::SessionCreated { session_id } => write!(f, "SessionCreated({session_id})"),
            Self::SessionExpired { session_id } => write!(f, "SessionExpired({session_id})"),
            Self::ApiKeyValidated { key_id } => write!(f, "ApiKeyValidated({key_id})"),
            Self::ApiKeyRejected { key_id, reason } => write!(f, "ApiKeyRejected({key_id}, {reason})"),
        }
    }
}

// ── RequestLifecycleEvent ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestLifecycleEvent {
    pub event_id: String,
    pub event_type: RequestLifecycleEventType,
    pub request_id: String,
    pub timestamp: i64,
    pub detail: String,
}

impl RequestLifecycleEvent {
    pub fn new(
        event_id: &str,
        event_type: RequestLifecycleEventType,
        request_id: &str,
        timestamp: i64,
        detail: &str,
    ) -> Self {
        Self {
            event_id: event_id.to_string(),
            event_type,
            request_id: request_id.to_string(),
            timestamp,
            detail: detail.to_string(),
        }
    }
}

// ── RequestEvent (what subscribers receive) ────────────────────

#[derive(Debug, Clone)]
pub struct RequestEvent {
    pub request: WebRequest,
    pub lifecycle_event: RequestLifecycleEventType,
    pub timestamp: i64,
}

impl RequestEvent {
    pub fn new(request: &WebRequest, lifecycle_event: RequestLifecycleEventType) -> Self {
        Self {
            request: request.clone(),
            lifecycle_event,
            timestamp: request.timestamp,
        }
    }
}

// ── RequestSubscriber trait ────────────────────────────────────

pub trait RequestSubscriber {
    fn on_request_event(&mut self, event: &RequestEvent);
    fn subscriber_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── RequestSubscriberRegistry ──────────────────────────────────

pub struct RequestSubscriberRegistry {
    subscribers: Vec<Box<dyn RequestSubscriber>>,
}

impl RequestSubscriberRegistry {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    pub fn register(&mut self, subscriber: Box<dyn RequestSubscriber>) {
        self.subscribers.push(subscriber);
    }

    pub fn notify(&mut self, event: &RequestEvent) {
        for sub in &mut self.subscribers {
            if sub.is_active() {
                sub.on_request_event(event);
            }
        }
    }

    pub fn notify_batch(&mut self, events: &[&RequestEvent]) {
        for event in events {
            self.notify(event);
        }
    }

    pub fn active_count(&self) -> usize {
        self.subscribers.iter().filter(|s| s.is_active()).count()
    }

    pub fn remove_inactive(&mut self) -> usize {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.is_active());
        before - self.subscribers.len()
    }
}

impl Default for RequestSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── RequestCollector (reference implementation) ────────────────

pub struct RequestCollector {
    id: String,
    events: Vec<RequestEvent>,
    active: bool,
}

impl RequestCollector {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            events: Vec::new(),
            active: true,
        }
    }

    pub fn events(&self) -> &[RequestEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn drain(&mut self) -> Vec<RequestEvent> {
        self.events.drain(..).collect()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl RequestSubscriber for RequestCollector {
    fn on_request_event(&mut self, event: &RequestEvent) {
        self.events.push(event.clone());
    }

    fn subscriber_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── FilteredRequestSubscriber ──────────────────────────────────

/// Filters request events before forwarding to an inner collector.
/// Supports filtering by HTTP method, status code range, or route pattern.
pub struct FilteredRequestSubscriber {
    id: String,
    inner: RequestCollector,
    method_filter: Option<String>,
    status_min: Option<u16>,
    status_max: Option<u16>,
    route_pattern: Option<String>,
    active: bool,
}

impl FilteredRequestSubscriber {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            inner: RequestCollector::new(&format!("{id}-inner")),
            method_filter: None,
            status_min: None,
            status_max: None,
            route_pattern: None,
            active: true,
        }
    }

    pub fn with_method_filter(mut self, method: &str) -> Self {
        self.method_filter = Some(method.to_string());
        self
    }

    pub fn with_status_range(mut self, min: u16, max: u16) -> Self {
        self.status_min = Some(min);
        self.status_max = Some(max);
        self
    }

    pub fn with_route_pattern(mut self, pattern: &str) -> Self {
        self.route_pattern = Some(pattern.to_string());
        self
    }

    pub fn collected(&self) -> &[RequestEvent] {
        self.inner.events()
    }

    pub fn collected_count(&self) -> usize {
        self.inner.event_count()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    fn matches(&self, event: &RequestEvent) -> bool {
        if let Some(ref method) = self.method_filter {
            if format!("{}", event.request.method) != *method {
                return false;
            }
        }
        if let Some(min) = self.status_min {
            if let RequestLifecycleEventType::ResponseEmitted { status_code } = &event.lifecycle_event {
                if *status_code < min {
                    return false;
                }
            }
        }
        if let Some(max) = self.status_max {
            if let RequestLifecycleEventType::ResponseEmitted { status_code } = &event.lifecycle_event {
                if *status_code > max {
                    return false;
                }
            }
        }
        if let Some(ref pattern) = self.route_pattern
            && !event.request.path.contains(pattern.as_str())
        {
            return false;
        }
        true
    }
}

impl RequestSubscriber for FilteredRequestSubscriber {
    fn on_request_event(&mut self, event: &RequestEvent) {
        if self.matches(event) {
            self.inner.on_request_event(event);
        }
    }

    fn subscriber_id(&self) -> &str {
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
    use crate::endpoint::HttpMethod;

    fn make_event(method: HttpMethod, path: &str, lifecycle: RequestLifecycleEventType) -> RequestEvent {
        let req = WebRequest::new("req-1", method, path, "1.2.3.4", 1000)
            .with_header("Host", "example.com");
        RequestEvent::new(&req, lifecycle)
    }

    #[test]
    fn test_collector_collects() {
        let mut collector = RequestCollector::new("c1");
        let event = make_event(HttpMethod::Get, "/api", RequestLifecycleEventType::RequestReceived);
        collector.on_request_event(&event);
        assert_eq!(collector.event_count(), 1);
    }

    #[test]
    fn test_collector_drain() {
        let mut collector = RequestCollector::new("c1");
        let event = make_event(HttpMethod::Get, "/api", RequestLifecycleEventType::RequestReceived);
        collector.on_request_event(&event);
        let drained = collector.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(collector.event_count(), 0);
    }

    #[test]
    fn test_registry_notify() {
        let mut registry = RequestSubscriberRegistry::new();
        registry.register(Box::new(RequestCollector::new("c1")));
        let event = make_event(HttpMethod::Get, "/api", RequestLifecycleEventType::RequestReceived);
        registry.notify(&event);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_remove_inactive() {
        let mut registry = RequestSubscriberRegistry::new();
        let mut collector = RequestCollector::new("c1");
        collector.deactivate();
        registry.register(Box::new(collector));
        registry.register(Box::new(RequestCollector::new("c2")));
        let removed = registry.remove_inactive();
        assert_eq!(removed, 1);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_filtered_method_filter() {
        let mut sub = FilteredRequestSubscriber::new("f1")
            .with_method_filter("GET");
        sub.on_request_event(&make_event(HttpMethod::Get, "/api", RequestLifecycleEventType::RequestReceived));
        sub.on_request_event(&make_event(HttpMethod::Post, "/api", RequestLifecycleEventType::RequestReceived));
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_filtered_status_range() {
        let mut sub = FilteredRequestSubscriber::new("f1")
            .with_status_range(400, 599);
        sub.on_request_event(&make_event(
            HttpMethod::Get, "/api",
            RequestLifecycleEventType::ResponseEmitted { status_code: 200 },
        ));
        sub.on_request_event(&make_event(
            HttpMethod::Get, "/api",
            RequestLifecycleEventType::ResponseEmitted { status_code: 404 },
        ));
        sub.on_request_event(&make_event(
            HttpMethod::Get, "/api",
            RequestLifecycleEventType::ResponseEmitted { status_code: 500 },
        ));
        assert_eq!(sub.collected_count(), 2);
    }

    #[test]
    fn test_filtered_route_pattern() {
        let mut sub = FilteredRequestSubscriber::new("f1")
            .with_route_pattern("/admin");
        sub.on_request_event(&make_event(HttpMethod::Get, "/api/users", RequestLifecycleEventType::RequestReceived));
        sub.on_request_event(&make_event(HttpMethod::Get, "/admin/settings", RequestLifecycleEventType::RequestReceived));
        assert_eq!(sub.collected_count(), 1);
    }

    #[test]
    fn test_lifecycle_event_types_display() {
        let types = vec![
            RequestLifecycleEventType::RequestReceived,
            RequestLifecycleEventType::RequestValidated,
            RequestLifecycleEventType::RequestRejected { reason: "blocked".into() },
            RequestLifecycleEventType::ResponseEmitted { status_code: 200 },
            RequestLifecycleEventType::RateLimitTriggered { key: "ip:1.2.3.4".into() },
            RequestLifecycleEventType::CorsPreflightHandled { origin: "https://example.com".into() },
            RequestLifecycleEventType::SessionCreated { session_id: "s1".into() },
            RequestLifecycleEventType::SessionExpired { session_id: "s1".into() },
            RequestLifecycleEventType::ApiKeyValidated { key_id: "k1".into() },
            RequestLifecycleEventType::ApiKeyRejected { key_id: "k1".into(), reason: "expired".into() },
        ];
        for t in &types {
            let event = RequestLifecycleEvent::new("e1", t.clone(), "req-1", 1000, "test");
            assert_eq!(event.request_id, "req-1");
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_deactivated_subscriber_skipped() {
        let mut registry = RequestSubscriberRegistry::new();
        let mut sub = FilteredRequestSubscriber::new("f1");
        sub.deactivate();
        registry.register(Box::new(sub));
        let event = make_event(HttpMethod::Get, "/api", RequestLifecycleEventType::RequestReceived);
        registry.notify(&event);
        assert_eq!(registry.active_count(), 0);
    }
}
