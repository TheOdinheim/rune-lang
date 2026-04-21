// ═══════════════════════════════════════════════════════════════════════
// Trace Context Propagator — Distributed trace context propagation
// across service boundaries.
//
// The trait defines how trace context propagates through HTTP headers,
// message queue attributes, or equivalent transport mechanisms without
// binding to any specific transport.  Customers implement Carrier for
// their transport medium.
//
// W3C Trace Context is the default.  B3 (Zipkin) and Jaeger formats
// are also supported.  MultiFormatPropagator writes all formats on
// injection and tries each on extraction for maximum interoperability.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MonitoringError;

// ── PropagationFormat ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PropagationFormat {
    W3cTraceContext,
    B3Single,
    B3Multi,
    Jaeger,
    Custom { name: String },
}

impl fmt::Display for PropagationFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::W3cTraceContext => write!(f, "W3C-TraceContext"),
            Self::B3Single => write!(f, "B3-Single"),
            Self::B3Multi => write!(f, "B3-Multi"),
            Self::Jaeger => write!(f, "Jaeger"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── TraceContext ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub sampled: bool,
    pub trace_flags: u8,
    pub tracestate: HashMap<String, String>,
}

impl TraceContext {
    pub fn new(trace_id: &str, span_id: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            sampled: true,
            trace_flags: 1,
            tracestate: HashMap::new(),
        }
    }

    pub fn with_sampled(mut self, sampled: bool) -> Self {
        self.sampled = sampled;
        if sampled { self.trace_flags |= 1; } else { self.trace_flags &= !1; }
        self
    }

    pub fn with_tracestate(mut self, key: &str, value: &str) -> Self {
        self.tracestate.insert(key.to_string(), value.to_string());
        self
    }
}

// ── Carrier trait ────────────────────────────────────────────────

pub trait Carrier {
    fn get(&self, key: &str) -> Option<&str>;
    fn set(&mut self, key: &str, value: &str);
}

/// Simple HashMap-based carrier for testing.
pub struct HashMapCarrier {
    headers: HashMap<String, String>,
}

impl HashMapCarrier {
    pub fn new() -> Self {
        Self { headers: HashMap::new() }
    }
}

impl Default for HashMapCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl Carrier for HashMapCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(|s| s.as_str())
    }

    fn set(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }
}

// ── TraceContextPropagator trait ─────────────────────────────────

pub trait TraceContextPropagator {
    fn inject_context(&self, ctx: &TraceContext, carrier: &mut dyn Carrier) -> Result<(), MonitoringError>;
    fn extract_context(&self, carrier: &dyn Carrier) -> Result<Option<TraceContext>, MonitoringError>;
    fn supported_formats(&self) -> Vec<PropagationFormat>;
    fn propagator_id(&self) -> &str;
}

// ── W3cTraceContextPropagator ────────────────────────────────────

pub struct W3cTraceContextPropagator {
    id: String,
}

impl W3cTraceContextPropagator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl TraceContextPropagator for W3cTraceContextPropagator {
    fn inject_context(&self, ctx: &TraceContext, carrier: &mut dyn Carrier) -> Result<(), MonitoringError> {
        let flags = format!("{:02x}", ctx.trace_flags);
        let traceparent = format!("00-{}-{}-{flags}", ctx.trace_id, ctx.span_id);
        carrier.set("traceparent", &traceparent);
        if !ctx.tracestate.is_empty() {
            let state: Vec<String> = ctx.tracestate.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            carrier.set("tracestate", &state.join(","));
        }
        Ok(())
    }

    fn extract_context(&self, carrier: &dyn Carrier) -> Result<Option<TraceContext>, MonitoringError> {
        let Some(traceparent) = carrier.get("traceparent") else {
            return Ok(None);
        };
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() < 4 {
            return Ok(None);
        }
        let trace_id = parts[1].to_string();
        let span_id = parts[2].to_string();
        let flags = u8::from_str_radix(parts[3], 16).unwrap_or(0);
        let sampled = flags & 1 == 1;
        let mut tracestate = HashMap::new();
        if let Some(state_str) = carrier.get("tracestate") {
            for pair in state_str.split(',') {
                if let Some((k, v)) = pair.split_once('=') {
                    tracestate.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
        Ok(Some(TraceContext {
            trace_id,
            span_id,
            sampled,
            trace_flags: flags,
            tracestate,
        }))
    }

    fn supported_formats(&self) -> Vec<PropagationFormat> {
        vec![PropagationFormat::W3cTraceContext]
    }

    fn propagator_id(&self) -> &str { &self.id }
}

// ── B3Propagator ─────────────────────────────────────────────────

pub struct B3Propagator {
    id: String,
}

impl B3Propagator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl TraceContextPropagator for B3Propagator {
    fn inject_context(&self, ctx: &TraceContext, carrier: &mut dyn Carrier) -> Result<(), MonitoringError> {
        // B3 single header
        let sampled_flag = if ctx.sampled { "1" } else { "0" };
        let b3 = format!("{}-{}-{sampled_flag}", ctx.trace_id, ctx.span_id);
        carrier.set("b3", &b3);
        // B3 multi headers
        carrier.set("X-B3-TraceId", &ctx.trace_id);
        carrier.set("X-B3-SpanId", &ctx.span_id);
        carrier.set("X-B3-Sampled", sampled_flag);
        Ok(())
    }

    fn extract_context(&self, carrier: &dyn Carrier) -> Result<Option<TraceContext>, MonitoringError> {
        // Try single header first
        if let Some(b3) = carrier.get("b3") {
            let parts: Vec<&str> = b3.split('-').collect();
            if parts.len() >= 2 {
                let sampled = parts.get(2).is_none_or(|s| *s == "1");
                return Ok(Some(TraceContext {
                    trace_id: parts[0].to_string(),
                    span_id: parts[1].to_string(),
                    sampled,
                    trace_flags: if sampled { 1 } else { 0 },
                    tracestate: HashMap::new(),
                }));
            }
        }
        // Try multi headers
        if let (Some(trace_id), Some(span_id)) = (carrier.get("X-B3-TraceId"), carrier.get("X-B3-SpanId")) {
            let sampled = carrier.get("X-B3-Sampled").is_none_or(|s| s == "1");
            return Ok(Some(TraceContext {
                trace_id: trace_id.to_string(),
                span_id: span_id.to_string(),
                sampled,
                trace_flags: if sampled { 1 } else { 0 },
                tracestate: HashMap::new(),
            }));
        }
        Ok(None)
    }

    fn supported_formats(&self) -> Vec<PropagationFormat> {
        vec![PropagationFormat::B3Single, PropagationFormat::B3Multi]
    }

    fn propagator_id(&self) -> &str { &self.id }
}

// ── MultiFormatPropagator ────────────────────────────────────────

pub struct MultiFormatPropagator {
    id: String,
    propagators: Vec<Box<dyn TraceContextPropagator>>,
}

impl MultiFormatPropagator {
    pub fn new(id: &str, propagators: Vec<Box<dyn TraceContextPropagator>>) -> Self {
        Self {
            id: id.to_string(),
            propagators,
        }
    }
}

impl TraceContextPropagator for MultiFormatPropagator {
    fn inject_context(&self, ctx: &TraceContext, carrier: &mut dyn Carrier) -> Result<(), MonitoringError> {
        for p in &self.propagators {
            p.inject_context(ctx, carrier)?;
        }
        Ok(())
    }

    fn extract_context(&self, carrier: &dyn Carrier) -> Result<Option<TraceContext>, MonitoringError> {
        for p in &self.propagators {
            if let Some(ctx) = p.extract_context(carrier)? {
                return Ok(Some(ctx));
            }
        }
        Ok(None)
    }

    fn supported_formats(&self) -> Vec<PropagationFormat> {
        self.propagators.iter().flat_map(|p| p.supported_formats()).collect()
    }

    fn propagator_id(&self) -> &str { &self.id }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_w3c_inject_and_extract() {
        let prop = W3cTraceContextPropagator::new("w3c-1");
        let ctx = TraceContext::new("abc123", "span456")
            .with_tracestate("vendor", "value1");
        let mut carrier = HashMapCarrier::new();
        prop.inject_context(&ctx, &mut carrier).unwrap();

        let extracted = prop.extract_context(&carrier).unwrap().unwrap();
        assert_eq!(extracted.trace_id, "abc123");
        assert_eq!(extracted.span_id, "span456");
        assert!(extracted.sampled);
        assert_eq!(extracted.tracestate.get("vendor").unwrap(), "value1");
    }

    #[test]
    fn test_w3c_extract_missing() {
        let prop = W3cTraceContextPropagator::new("w3c-1");
        let carrier = HashMapCarrier::new();
        assert!(prop.extract_context(&carrier).unwrap().is_none());
    }

    #[test]
    fn test_w3c_sampled_false() {
        let prop = W3cTraceContextPropagator::new("w3c-1");
        let ctx = TraceContext::new("abc123", "span456").with_sampled(false);
        let mut carrier = HashMapCarrier::new();
        prop.inject_context(&ctx, &mut carrier).unwrap();
        let extracted = prop.extract_context(&carrier).unwrap().unwrap();
        assert!(!extracted.sampled);
    }

    #[test]
    fn test_b3_inject_and_extract_single() {
        let prop = B3Propagator::new("b3-1");
        let ctx = TraceContext::new("trace1", "span1");
        let mut carrier = HashMapCarrier::new();
        prop.inject_context(&ctx, &mut carrier).unwrap();

        // Clear multi headers to test single-header extraction
        let mut single_carrier = HashMapCarrier::new();
        single_carrier.set("b3", carrier.get("b3").unwrap());
        let extracted = prop.extract_context(&single_carrier).unwrap().unwrap();
        assert_eq!(extracted.trace_id, "trace1");
        assert_eq!(extracted.span_id, "span1");
    }

    #[test]
    fn test_b3_extract_multi_headers() {
        let prop = B3Propagator::new("b3-1");
        let mut carrier = HashMapCarrier::new();
        carrier.set("X-B3-TraceId", "trace1");
        carrier.set("X-B3-SpanId", "span1");
        carrier.set("X-B3-Sampled", "0");
        let extracted = prop.extract_context(&carrier).unwrap().unwrap();
        assert_eq!(extracted.trace_id, "trace1");
        assert!(!extracted.sampled);
    }

    #[test]
    fn test_b3_extract_missing() {
        let prop = B3Propagator::new("b3-1");
        let carrier = HashMapCarrier::new();
        assert!(prop.extract_context(&carrier).unwrap().is_none());
    }

    #[test]
    fn test_multi_format_inject_all() {
        let multi = MultiFormatPropagator::new("multi-1", vec![
            Box::new(W3cTraceContextPropagator::new("w3c")),
            Box::new(B3Propagator::new("b3")),
        ]);
        let ctx = TraceContext::new("trace1", "span1");
        let mut carrier = HashMapCarrier::new();
        multi.inject_context(&ctx, &mut carrier).unwrap();
        // Both formats injected
        assert!(carrier.get("traceparent").is_some());
        assert!(carrier.get("b3").is_some());
    }

    #[test]
    fn test_multi_format_extract_first_match() {
        let multi = MultiFormatPropagator::new("multi-1", vec![
            Box::new(W3cTraceContextPropagator::new("w3c")),
            Box::new(B3Propagator::new("b3")),
        ]);
        // Only B3 header present
        let mut carrier = HashMapCarrier::new();
        carrier.set("b3", "trace1-span1-1");
        let extracted = multi.extract_context(&carrier).unwrap().unwrap();
        assert_eq!(extracted.trace_id, "trace1");
    }

    #[test]
    fn test_supported_formats() {
        let prop = W3cTraceContextPropagator::new("w3c-1");
        assert_eq!(prop.supported_formats(), vec![PropagationFormat::W3cTraceContext]);

        let prop = B3Propagator::new("b3-1");
        assert_eq!(prop.supported_formats().len(), 2);
    }

    #[test]
    fn test_propagation_format_display() {
        assert_eq!(PropagationFormat::W3cTraceContext.to_string(), "W3C-TraceContext");
        assert_eq!(PropagationFormat::B3Single.to_string(), "B3-Single");
        assert_eq!(PropagationFormat::Jaeger.to_string(), "Jaeger");
        assert_eq!(PropagationFormat::Custom { name: "x".into() }.to_string(), "Custom(x)");
    }

    #[test]
    fn test_trace_context_builder() {
        let ctx = TraceContext::new("t1", "s1")
            .with_sampled(false)
            .with_tracestate("vendor", "val");
        assert!(!ctx.sampled);
        assert_eq!(ctx.tracestate.get("vendor").unwrap(), "val");
    }

    #[test]
    fn test_propagator_id() {
        let prop = W3cTraceContextPropagator::new("w3c-1");
        assert_eq!(prop.propagator_id(), "w3c-1");
    }
}
