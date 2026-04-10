// ═══════════════════════════════════════════════════════════════════════
// Signal — normalized input events for detection
//
// Raw events from any source (network, API, user action, model
// inference, policy, audit) are normalized into Signal values for
// downstream analysis by anomaly/pattern/behavior detectors.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── SignalSource ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalSource {
    NetworkTraffic,
    ApiRequest,
    UserAction,
    SystemEvent,
    ModelInference,
    PolicyEvaluation,
    AuditLog,
    Custom(String),
}

impl fmt::Display for SignalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkTraffic => write!(f, "NetworkTraffic"),
            Self::ApiRequest => write!(f, "ApiRequest"),
            Self::UserAction => write!(f, "UserAction"),
            Self::SystemEvent => write!(f, "SystemEvent"),
            Self::ModelInference => write!(f, "ModelInference"),
            Self::PolicyEvaluation => write!(f, "PolicyEvaluation"),
            Self::AuditLog => write!(f, "AuditLog"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── SignalType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalType {
    TextInput,
    NumericValue,
    BinaryPayload,
    Categorical,
    Temporal,
    Structural,
}

impl fmt::Display for SignalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SignalValue ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SignalValue {
    Text(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
    List(Vec<SignalValue>),
    Map(HashMap<String, String>),
}

impl SignalValue {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Integer(i) => Some(*i as f64),
            _ => None,
        }
    }
}

// ── Signal ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Signal {
    pub id: String,
    pub source: SignalSource,
    pub signal_type: SignalType,
    pub timestamp: i64,
    pub value: SignalValue,
    pub metadata: HashMap<String, String>,
    pub context: Option<String>,
}

impl Signal {
    pub fn new(
        id: &str,
        source: SignalSource,
        signal_type: SignalType,
        value: SignalValue,
        timestamp: i64,
    ) -> Self {
        Self {
            id: id.into(),
            source,
            signal_type,
            timestamp,
            value,
            metadata: HashMap::new(),
            context: None,
        }
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn with_context(mut self, ctx: &str) -> Self {
        self.context = Some(ctx.into());
        self
    }
}

// ── SignalBatch ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SignalBatch {
    pub signals: Vec<Signal>,
    pub window_start: i64,
    pub window_end: i64,
}

impl SignalBatch {
    pub fn new(start: i64, end: i64) -> Self {
        Self {
            signals: Vec::new(),
            window_start: start,
            window_end: end,
        }
    }

    pub fn add(&mut self, signal: Signal) {
        self.signals.push(signal);
    }

    pub fn len(&self) -> usize {
        self.signals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    pub fn signals_of_type(&self, signal_type: &SignalType) -> Vec<&Signal> {
        self.signals.iter().filter(|s| &s.signal_type == signal_type).collect()
    }

    pub fn signals_from_source(&self, source: &SignalSource) -> Vec<&Signal> {
        self.signals.iter().filter(|s| &s.source == source).collect()
    }

    pub fn time_range_ms(&self) -> i64 {
        self.window_end - self.window_start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_construction() {
        let s = Signal::new(
            "sig-1",
            SignalSource::ApiRequest,
            SignalType::TextInput,
            SignalValue::Text("hello".into()),
            1000,
        )
        .with_metadata("ip", "1.2.3.4")
        .with_context("ctx-1");
        assert_eq!(s.id, "sig-1");
        assert_eq!(s.timestamp, 1000);
        assert_eq!(s.metadata.get("ip"), Some(&"1.2.3.4".to_string()));
        assert_eq!(s.context, Some("ctx-1".into()));
    }

    #[test]
    fn test_signal_value_variants() {
        let _text = SignalValue::Text("t".into());
        let n = SignalValue::Number(1.5);
        let i = SignalValue::Integer(42);
        let _b = SignalValue::Boolean(true);
        let _by = SignalValue::Bytes(vec![0u8, 1, 2]);
        let _l = SignalValue::List(vec![SignalValue::Integer(1)]);
        let mut map = HashMap::new();
        map.insert("k".into(), "v".into());
        let _m = SignalValue::Map(map);
        assert_eq!(n.as_number(), Some(1.5));
        assert_eq!(i.as_number(), Some(42.0));
    }

    #[test]
    fn test_signal_source_display() {
        assert_eq!(SignalSource::NetworkTraffic.to_string(), "NetworkTraffic");
        assert_eq!(SignalSource::ApiRequest.to_string(), "ApiRequest");
        assert_eq!(SignalSource::UserAction.to_string(), "UserAction");
        assert_eq!(SignalSource::SystemEvent.to_string(), "SystemEvent");
        assert_eq!(SignalSource::ModelInference.to_string(), "ModelInference");
        assert_eq!(SignalSource::PolicyEvaluation.to_string(), "PolicyEvaluation");
        assert_eq!(SignalSource::AuditLog.to_string(), "AuditLog");
        assert_eq!(
            SignalSource::Custom("foo".into()).to_string(),
            "Custom(foo)"
        );
    }

    #[test]
    fn test_signal_type_display() {
        for t in [
            SignalType::TextInput,
            SignalType::NumericValue,
            SignalType::BinaryPayload,
            SignalType::Categorical,
            SignalType::Temporal,
            SignalType::Structural,
        ] {
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn test_batch_add_and_len() {
        let mut b = SignalBatch::new(0, 1000);
        assert!(b.is_empty());
        b.add(Signal::new(
            "s1",
            SignalSource::ApiRequest,
            SignalType::TextInput,
            SignalValue::Text("x".into()),
            100,
        ));
        assert_eq!(b.len(), 1);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_batch_signals_of_type() {
        let mut b = SignalBatch::new(0, 1000);
        b.add(Signal::new(
            "s1",
            SignalSource::ApiRequest,
            SignalType::TextInput,
            SignalValue::Text("x".into()),
            100,
        ));
        b.add(Signal::new(
            "s2",
            SignalSource::ApiRequest,
            SignalType::NumericValue,
            SignalValue::Number(1.0),
            200,
        ));
        assert_eq!(b.signals_of_type(&SignalType::TextInput).len(), 1);
        assert_eq!(b.signals_of_type(&SignalType::NumericValue).len(), 1);
    }

    #[test]
    fn test_batch_signals_from_source() {
        let mut b = SignalBatch::new(0, 1000);
        b.add(Signal::new(
            "s1",
            SignalSource::ApiRequest,
            SignalType::TextInput,
            SignalValue::Text("x".into()),
            100,
        ));
        b.add(Signal::new(
            "s2",
            SignalSource::AuditLog,
            SignalType::TextInput,
            SignalValue::Text("y".into()),
            200,
        ));
        assert_eq!(b.signals_from_source(&SignalSource::ApiRequest).len(), 1);
        assert_eq!(b.signals_from_source(&SignalSource::AuditLog).len(), 1);
    }

    #[test]
    fn test_batch_time_range_ms() {
        let b = SignalBatch::new(1000, 5000);
        assert_eq!(b.time_range_ms(), 4000);
    }
}
