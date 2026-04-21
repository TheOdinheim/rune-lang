// ═══════════════════════════════════════════════════════════════════════
// Reasoning Trace Recorder — Captures step-by-step decision paths of
// rule-based or symbolic systems.
//
// Unlike feature attribution (which applies to statistical models),
// reasoning traces apply to systems where the decision logic is
// explicit and enumerable.
//
// DepthLimitedReasoningTraceRecorder wraps another recorder and caps
// trace depth at a configurable threshold to prevent resource
// exhaustion on adversarially deep reasoning graphs — matching the
// pattern from rune-provenance's DepthLimitedLineageTracker.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::ExplainabilityError;

// ── StepType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StepType {
    Premise,
    Inference,
    RuleMatch,
    Query,
    Assumption,
    Constraint,
}

impl fmt::Display for StepType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Premise => write!(f, "premise"),
            Self::Inference => write!(f, "inference"),
            Self::RuleMatch => write!(f, "rule-match"),
            Self::Query => write!(f, "query"),
            Self::Assumption => write!(f, "assumption"),
            Self::Constraint => write!(f, "constraint"),
        }
    }
}

// ── ReasoningStep ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningStep {
    pub step_id: String,
    pub trace_id: String,
    pub step_number: usize,
    pub step_type: StepType,
    pub description: String,
    pub inputs: HashMap<String, String>,
    pub outputs: HashMap<String, String>,
    pub executed_at: i64,
}

impl ReasoningStep {
    pub fn new(
        step_id: &str,
        trace_id: &str,
        step_number: usize,
        step_type: StepType,
        description: &str,
        executed_at: i64,
    ) -> Self {
        Self {
            step_id: step_id.to_string(),
            trace_id: trace_id.to_string(),
            step_number,
            step_type,
            description: description.to_string(),
            inputs: HashMap::new(),
            outputs: HashMap::new(),
            executed_at,
        }
    }

    pub fn with_input(mut self, key: &str, value: &str) -> Self {
        self.inputs.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_output(mut self, key: &str, value: &str) -> Self {
        self.outputs.insert(key.to_string(), value.to_string());
        self
    }
}

// ── RecordedReasoningTrace ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RecordedReasoningTrace {
    pub trace_id: String,
    pub decision_id: String,
    pub steps: Vec<ReasoningStep>,
    pub conclusion: Option<String>,
    pub started_at: i64,
    pub completed: bool,
}

impl RecordedReasoningTrace {
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

// ── ReasoningTraceRecorder trait ────────────────────────────────

pub trait ReasoningTraceRecorder {
    fn begin_trace(&mut self, decision_id: &str, started_at: i64) -> Result<String, ExplainabilityError>;
    fn record_step(&mut self, trace_id: &str, step: ReasoningStep) -> Result<(), ExplainabilityError>;
    fn record_conclusion(&mut self, trace_id: &str, conclusion: &str) -> Result<(), ExplainabilityError>;
    fn get_trace(&self, trace_id: &str) -> Result<RecordedReasoningTrace, ExplainabilityError>;
    fn list_active_traces(&self) -> Vec<&RecordedReasoningTrace>;
    fn recorder_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryReasoningTraceRecorder ──────────────────────────────

pub struct InMemoryReasoningTraceRecorder {
    id: String,
    traces: HashMap<String, RecordedReasoningTrace>,
    next_trace_id: usize,
}

impl InMemoryReasoningTraceRecorder {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            traces: HashMap::new(),
            next_trace_id: 0,
        }
    }
}

impl ReasoningTraceRecorder for InMemoryReasoningTraceRecorder {
    fn begin_trace(&mut self, decision_id: &str, started_at: i64) -> Result<String, ExplainabilityError> {
        let trace_id = format!("trace-{}", self.next_trace_id);
        self.next_trace_id += 1;
        let trace = RecordedReasoningTrace {
            trace_id: trace_id.clone(),
            decision_id: decision_id.to_string(),
            steps: Vec::new(),
            conclusion: None,
            started_at,
            completed: false,
        };
        self.traces.insert(trace_id.clone(), trace);
        Ok(trace_id)
    }

    fn record_step(&mut self, trace_id: &str, step: ReasoningStep) -> Result<(), ExplainabilityError> {
        let trace = self.traces.get_mut(trace_id)
            .ok_or_else(|| ExplainabilityError::TraceConstructionFailed(format!("trace not found: {trace_id}")))?;
        if trace.completed {
            return Err(ExplainabilityError::TraceConstructionFailed("trace already completed".to_string()));
        }
        trace.steps.push(step);
        Ok(())
    }

    fn record_conclusion(&mut self, trace_id: &str, conclusion: &str) -> Result<(), ExplainabilityError> {
        let trace = self.traces.get_mut(trace_id)
            .ok_or_else(|| ExplainabilityError::TraceConstructionFailed(format!("trace not found: {trace_id}")))?;
        trace.conclusion = Some(conclusion.to_string());
        trace.completed = true;
        Ok(())
    }

    fn get_trace(&self, trace_id: &str) -> Result<RecordedReasoningTrace, ExplainabilityError> {
        self.traces.get(trace_id).cloned()
            .ok_or_else(|| ExplainabilityError::TraceConstructionFailed(format!("trace not found: {trace_id}")))
    }

    fn list_active_traces(&self) -> Vec<&RecordedReasoningTrace> {
        self.traces.values().filter(|t| !t.completed).collect()
    }

    fn recorder_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── DepthLimitedReasoningTraceRecorder ──────────────────────────

pub struct DepthLimitedReasoningTraceRecorder {
    inner: Box<dyn ReasoningTraceRecorder>,
    max_depth: usize,
    step_counts: HashMap<String, usize>,
}

impl DepthLimitedReasoningTraceRecorder {
    pub fn new(inner: Box<dyn ReasoningTraceRecorder>, max_depth: usize) -> Self {
        Self {
            inner,
            max_depth,
            step_counts: HashMap::new(),
        }
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
}

impl ReasoningTraceRecorder for DepthLimitedReasoningTraceRecorder {
    fn begin_trace(&mut self, decision_id: &str, started_at: i64) -> Result<String, ExplainabilityError> {
        let trace_id = self.inner.begin_trace(decision_id, started_at)?;
        self.step_counts.insert(trace_id.clone(), 0);
        Ok(trace_id)
    }

    fn record_step(&mut self, trace_id: &str, step: ReasoningStep) -> Result<(), ExplainabilityError> {
        let count = self.step_counts.get(trace_id).copied().unwrap_or(0);
        if count >= self.max_depth {
            return Err(ExplainabilityError::TraceConstructionFailed(
                format!("trace depth limit exceeded: {count} >= {}", self.max_depth),
            ));
        }
        self.inner.record_step(trace_id, step)?;
        self.step_counts.insert(trace_id.to_string(), count + 1);
        Ok(())
    }

    fn record_conclusion(&mut self, trace_id: &str, conclusion: &str) -> Result<(), ExplainabilityError> {
        self.inner.record_conclusion(trace_id, conclusion)
    }

    fn get_trace(&self, trace_id: &str) -> Result<RecordedReasoningTrace, ExplainabilityError> {
        self.inner.get_trace(trace_id)
    }

    fn list_active_traces(&self) -> Vec<&RecordedReasoningTrace> {
        self.inner.list_active_traces()
    }

    fn recorder_id(&self) -> &str { self.inner.recorder_id() }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_type_display() {
        assert_eq!(StepType::Premise.to_string(), "premise");
        assert_eq!(StepType::Inference.to_string(), "inference");
        assert_eq!(StepType::RuleMatch.to_string(), "rule-match");
        assert_eq!(StepType::Query.to_string(), "query");
        assert_eq!(StepType::Assumption.to_string(), "assumption");
        assert_eq!(StepType::Constraint.to_string(), "constraint");
    }

    #[test]
    fn test_reasoning_step_builder() {
        let step = ReasoningStep::new("s1", "t1", 0, StepType::Premise, "user is admin", 1000)
            .with_input("user_role", "admin")
            .with_output("granted", "true");
        assert_eq!(step.inputs.get("user_role").unwrap(), "admin");
        assert_eq!(step.outputs.get("granted").unwrap(), "true");
    }

    #[test]
    fn test_begin_and_record_trace() {
        let mut recorder = InMemoryReasoningTraceRecorder::new("rec-1");
        let trace_id = recorder.begin_trace("decision-1", 1000).unwrap();
        let step = ReasoningStep::new("s1", &trace_id, 0, StepType::Premise, "check auth", 1001);
        recorder.record_step(&trace_id, step).unwrap();
        recorder.record_conclusion(&trace_id, "Access granted").unwrap();

        let trace = recorder.get_trace(&trace_id).unwrap();
        assert_eq!(trace.step_count(), 1);
        assert_eq!(trace.conclusion.as_deref(), Some("Access granted"));
        assert!(trace.completed);
    }

    #[test]
    fn test_record_step_after_conclusion_fails() {
        let mut recorder = InMemoryReasoningTraceRecorder::new("rec-1");
        let trace_id = recorder.begin_trace("d-1", 1000).unwrap();
        recorder.record_conclusion(&trace_id, "done").unwrap();
        let step = ReasoningStep::new("s1", &trace_id, 0, StepType::Inference, "late step", 1002);
        assert!(recorder.record_step(&trace_id, step).is_err());
    }

    #[test]
    fn test_list_active_traces() {
        let mut recorder = InMemoryReasoningTraceRecorder::new("rec-1");
        let t1 = recorder.begin_trace("d-1", 1000).unwrap();
        recorder.begin_trace("d-2", 1001).unwrap();
        recorder.record_conclusion(&t1, "done").unwrap();
        assert_eq!(recorder.list_active_traces().len(), 1);
    }

    #[test]
    fn test_get_nonexistent_trace() {
        let recorder = InMemoryReasoningTraceRecorder::new("rec-1");
        assert!(recorder.get_trace("nonexistent").is_err());
    }

    #[test]
    fn test_recorder_id() {
        let recorder = InMemoryReasoningTraceRecorder::new("rec-1");
        assert_eq!(recorder.recorder_id(), "rec-1");
        assert!(recorder.is_active());
    }

    #[test]
    fn test_depth_limited_recorder() {
        let inner = Box::new(InMemoryReasoningTraceRecorder::new("inner"));
        let mut recorder = DepthLimitedReasoningTraceRecorder::new(inner, 2);
        assert_eq!(recorder.max_depth(), 2);

        let trace_id = recorder.begin_trace("d-1", 1000).unwrap();
        let s1 = ReasoningStep::new("s1", &trace_id, 0, StepType::Premise, "step 1", 1001);
        recorder.record_step(&trace_id, s1).unwrap();
        let s2 = ReasoningStep::new("s2", &trace_id, 1, StepType::Inference, "step 2", 1002);
        recorder.record_step(&trace_id, s2).unwrap();
        // Third step should fail — depth limit exceeded
        let s3 = ReasoningStep::new("s3", &trace_id, 2, StepType::RuleMatch, "step 3", 1003);
        assert!(recorder.record_step(&trace_id, s3).is_err());
    }

    #[test]
    fn test_depth_limited_conclusion_still_works() {
        let inner = Box::new(InMemoryReasoningTraceRecorder::new("inner"));
        let mut recorder = DepthLimitedReasoningTraceRecorder::new(inner, 1);
        let trace_id = recorder.begin_trace("d-1", 1000).unwrap();
        let s1 = ReasoningStep::new("s1", &trace_id, 0, StepType::Premise, "only step", 1001);
        recorder.record_step(&trace_id, s1).unwrap();
        recorder.record_conclusion(&trace_id, "done").unwrap();
        let trace = recorder.get_trace(&trace_id).unwrap();
        assert!(trace.completed);
    }
}
