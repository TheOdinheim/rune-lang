// ═══════════════════════════════════════════════════════════════════════
// Compile-and-Evaluate Pipeline
//
// Convenience functions that combine compilation and runtime evaluation
// into a single call. Used for testing, REPL-style evaluation, and
// one-shot policy checks.
// ═══════════════════════════════════════════════════════════════════════

use crate::compiler::compile_source;
use crate::runtime::evaluator::{PolicyModule, PolicyRequest, PolicyResult, RuntimeError};

/// Compile RUNE source code and load it as a reusable PolicyModule.
pub fn compile_and_load(source: &str) -> Result<PolicyModule, RuntimeError> {
    let wasm_bytes = compile_source(source, 0)
        .map_err(|errors| {
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            RuntimeError::CompilationFailed(msgs.join("; "))
        })?;
    PolicyModule::from_bytes(&wasm_bytes)
}

/// Compile RUNE source code and evaluate a policy request in one step.
///
/// This is a convenience function for testing and one-shot evaluation.
/// For repeated evaluations, use `compile_and_load` to get a reusable
/// PolicyModule.
pub fn compile_and_evaluate(
    source: &str,
    request: &PolicyRequest,
) -> Result<PolicyResult, RuntimeError> {
    let module = compile_and_load(source)?;
    let evaluator = module.evaluator()?;
    evaluator.evaluate(request)
}
