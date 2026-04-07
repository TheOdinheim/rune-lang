// ═══════════════════════════════════════════════════════════════════════
// Runtime Policy Evaluator
//
// Loads compiled .rune.wasm modules and provides a clean API for host
// applications to evaluate policy decisions. This is the interface that
// rune-python, rune-rs, and any embedding host will call.
//
// Pillar: Security Baked In — compiled governance modules are immutable
// WASM bytecode. The runtime cannot modify policy logic.
//
// Pillar: Assumed Breach — each evaluation gets a fresh Store (arena
// model). No state leaks between evaluations.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use std::time::{Duration, Instant};

use wasmtime::{Engine, Instance, Module, Store};

// ── Policy decision ───────────────────────────────────────────────────

/// A governance policy decision returned by rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Permit,
    Deny,
    Escalate,
    Quarantine,
}

impl PolicyDecision {
    /// Convert from the WASM i32 encoding.
    pub fn from_i32(value: i32) -> Result<Self, RuntimeError> {
        match value {
            0 => Ok(PolicyDecision::Permit),
            1 => Ok(PolicyDecision::Deny),
            2 => Ok(PolicyDecision::Escalate),
            3 => Ok(PolicyDecision::Quarantine),
            _ => Err(RuntimeError::InvalidDecision(value)),
        }
    }

    /// Convert to the WASM i32 encoding.
    pub fn to_i32(self) -> i32 {
        match self {
            PolicyDecision::Permit => 0,
            PolicyDecision::Deny => 1,
            PolicyDecision::Escalate => 2,
            PolicyDecision::Quarantine => 3,
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Permit => write!(f, "Permit"),
            PolicyDecision::Deny => write!(f, "Deny"),
            PolicyDecision::Escalate => write!(f, "Escalate"),
            PolicyDecision::Quarantine => write!(f, "Quarantine"),
        }
    }
}

// ── Request / Result types ────────────────────────────────────────────

/// A policy evaluation request matching the standard evaluate signature.
#[derive(Debug, Clone)]
pub struct PolicyRequest {
    pub subject_id: i64,
    pub action: i64,
    pub resource_id: i64,
    pub risk_score: i64,
}

impl PolicyRequest {
    pub fn new(subject_id: i64, action: i64, resource_id: i64, risk_score: i64) -> Self {
        Self { subject_id, action, resource_id, risk_score }
    }
}

/// The result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub evaluation_duration: Duration,
}

/// The result of evaluating an individual rule.
#[derive(Debug, Clone)]
pub struct RuleResult {
    pub rule_name: String,
    pub decision: PolicyDecision,
    pub evaluation_duration: Duration,
}

/// A value that can be passed to rule functions.
#[derive(Debug, Clone)]
pub enum Value {
    Int(i64),
    Float(f64),
    Bool(bool),
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors that can occur during runtime policy evaluation.
#[derive(Debug)]
pub enum RuntimeError {
    /// Failed to load or validate a WASM module.
    ModuleLoadError(String),
    /// A required export was not found in the module.
    ExportNotFound(String),
    /// WASM execution failed.
    EvaluationFailed(String),
    /// The WASM function returned an invalid policy decision value.
    InvalidDecision(i32),
    /// Compilation failed (for compile-and-evaluate pipeline).
    CompilationFailed(String),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::ModuleLoadError(msg) => write!(f, "module load error: {msg}"),
            RuntimeError::ExportNotFound(name) => write!(f, "export not found: {name}"),
            RuntimeError::EvaluationFailed(msg) => write!(f, "evaluation failed: {msg}"),
            RuntimeError::InvalidDecision(val) => write!(f, "invalid policy decision value: {val}"),
            RuntimeError::CompilationFailed(msg) => write!(f, "compilation failed: {msg}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

// ── PolicyModule ──────────────────────────────────────────────────────

/// A compiled policy module ready for evaluation.
///
/// Thread-safe: the wasmtime Engine and compiled Module can be shared
/// across threads. Each evaluation creates a fresh Store.
pub struct PolicyModule {
    engine: Engine,
    module: Module,
}

impl PolicyModule {
    /// Load a policy module from WASM bytes.
    pub fn from_bytes(wasm_bytes: &[u8]) -> Result<Self, RuntimeError> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm_bytes)
            .map_err(|e| RuntimeError::ModuleLoadError(e.to_string()))?;
        Ok(Self { engine, module })
    }

    /// Load a policy module from a .rune.wasm file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, RuntimeError> {
        let bytes = std::fs::read(path)
            .map_err(|e| RuntimeError::ModuleLoadError(format!("{}: {e}", path.display())))?;
        Self::from_bytes(&bytes)
    }

    /// Create a PolicyEvaluator for this module.
    pub fn evaluator(&self) -> Result<PolicyEvaluator, RuntimeError> {
        PolicyEvaluator::new(&self.engine, &self.module)
    }

    /// List all exported function names.
    pub fn list_exports(&self) -> Vec<String> {
        self.module.exports()
            .filter(|e| e.ty().func().is_some())
            .map(|e| e.name().to_string())
            .collect()
    }

    /// List only policy rule exports (names containing `__`).
    pub fn list_policy_rules(&self) -> Vec<String> {
        self.list_exports()
            .into_iter()
            .filter(|name| name.contains("__"))
            .collect()
    }

    /// Check if the standard `evaluate` entry point exists.
    pub fn has_evaluate(&self) -> bool {
        self.list_exports().iter().any(|name| name == "evaluate")
    }
}

impl fmt::Debug for PolicyModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyModule")
            .field("exports", &self.list_exports())
            .finish()
    }
}

// ── PolicyEvaluator ───────────────────────────────────────────────────

/// Evaluates policy decisions against a loaded WASM module.
///
/// Each evaluation creates a fresh wasmtime Store + Instance, following
/// the arena allocation model from RUNE_06. No state leaks between
/// evaluations.
pub struct PolicyEvaluator {
    engine: Engine,
    module: Module,
}

impl PolicyEvaluator {
    fn new(engine: &Engine, module: &Module) -> Result<Self, RuntimeError> {
        Ok(Self {
            engine: engine.clone(),
            module: module.clone(),
        })
    }

    /// Evaluate the standard `evaluate(subject_id, action, resource_id, risk_score)`
    /// entry point.
    pub fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyResult, RuntimeError> {
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|e| RuntimeError::EvaluationFailed(e.to_string()))?;

        let func = instance
            .get_typed_func::<(i64, i64, i64, i64), i32>(&mut store, "evaluate")
            .map_err(|_| RuntimeError::ExportNotFound("evaluate".to_string()))?;

        let start = Instant::now();
        let raw = func
            .call(
                &mut store,
                (request.subject_id, request.action, request.resource_id, request.risk_score),
            )
            .map_err(|e| RuntimeError::EvaluationFailed(e.to_string()))?;
        let duration = start.elapsed();

        let decision = PolicyDecision::from_i32(raw)?;
        Ok(PolicyResult {
            decision,
            evaluation_duration: duration,
        })
    }

    /// Evaluate an individual exported rule by name.
    pub fn evaluate_rule(
        &self,
        rule_name: &str,
        args: &[Value],
    ) -> Result<PolicyResult, RuntimeError> {
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|e| RuntimeError::EvaluationFailed(e.to_string()))?;

        // Find the exported function.
        let func = instance
            .get_func(&mut store, rule_name)
            .ok_or_else(|| RuntimeError::ExportNotFound(rule_name.to_string()))?;

        // Build argument list as wasmtime Vals.
        let wasm_args: Vec<wasmtime::Val> = args
            .iter()
            .map(|v| match v {
                Value::Int(n) => wasmtime::Val::I64(*n),
                Value::Float(f) => wasmtime::Val::F64(f.to_bits()),
                Value::Bool(b) => wasmtime::Val::I32(if *b { 1 } else { 0 }),
            })
            .collect();

        let mut results = vec![wasmtime::Val::I32(0)];

        let start = Instant::now();
        func.call(&mut store, &wasm_args, &mut results)
            .map_err(|e| RuntimeError::EvaluationFailed(format!("{rule_name}: {e}")))?;
        let duration = start.elapsed();

        let raw = match results[0] {
            wasmtime::Val::I32(v) => v,
            wasmtime::Val::I64(v) => v as i32,
            _ => return Err(RuntimeError::EvaluationFailed(
                format!("{rule_name}: unexpected return type"),
            )),
        };

        let decision = PolicyDecision::from_i32(raw)?;
        Ok(PolicyResult {
            decision,
            evaluation_duration: duration,
        })
    }
}
