// ═══════════════════════════════════════════════════════════════════════
// RUNE Embedding API — C ABI for host applications
//
// Provides a C-compatible interface for any language with C FFI support
// (Rust, Go, Python, Java, C#, Ruby, Swift, Zig) to load and evaluate
// RUNE policy modules.
//
// Governance constraint (Section 8.4.4): Every failure mode defaults to
// DENY. There is no code path that returns an implicit PERMIT due to an
// internal failure.
//
// Pillar: Security Baked In — fail-closed by design.
// Pillar: Assumed Breach — every evaluation is audit-recorded.
// Pillar: Zero Trust Throughout — opaque handles prevent host tampering.
// ═══════════════════════════════════════════════════════════════════════

pub mod safe_api;

#[cfg(test)]
mod tests;

use std::ffi::{c_char, CStr};
use std::panic::catch_unwind;

use crate::runtime::audit::AuditRecord;
use crate::runtime::evaluator::{PolicyDecision, PolicyModule, PolicyRequest, RuntimeError};
use crate::runtime::pipeline::{PipelineConfig, RuntimePipeline};

// ── Outcome constants ──────────────────────────────────────────────

pub const RUNE_PERMIT: i32 = 0;
pub const RUNE_DENY: i32 = 1;
pub const RUNE_ESCALATE: i32 = 2;
pub const RUNE_QUARANTINE: i32 = 3;
pub const RUNE_ERROR: i32 = -1;

// ── C-compatible types ─────────────────────────────────────────────

/// Policy evaluation request (C-compatible layout).
#[repr(C)]
pub struct RunePolicyRequest {
    pub subject_id: i64,
    pub action: i64,
    pub resource_id: i64,
    pub risk_score: i64,
    pub context_json: *const c_char,
    pub context_json_len: usize,
}

/// Policy evaluation decision (C-compatible layout).
#[repr(C)]
pub struct RunePolicyDecision {
    pub outcome: i32,
    pub matched_rule: [c_char; 256],
    pub evaluation_duration_us: u64,
    pub error_message: [c_char; 512],
    pub audit_record_id: u64,
}

impl From<PolicyDecision> for i32 {
    fn from(d: PolicyDecision) -> i32 {
        d.to_i32()
    }
}

impl RunePolicyDecision {
    /// Create a default decision (all zeroed, outcome = DENY).
    fn new_deny() -> Self {
        Self {
            outcome: RUNE_DENY,
            matched_rule: [0; 256],
            evaluation_duration_us: 0,
            error_message: [0; 512],
            audit_record_id: 0,
        }
    }

    /// Create an error decision — always DENY with an error message.
    fn error(msg: &str) -> Self {
        let mut decision = Self::new_deny();
        decision.outcome = RUNE_ERROR;
        copy_to_fixed_buf(&mut decision.error_message, msg);
        decision
    }
}

/// Convert a Result<PolicyResult, RuntimeError> to a RunePolicyDecision.
/// This is the fail-closed function: Err always maps to DENY.
fn decision_from_result(
    result: Result<crate::runtime::evaluator::PolicyResult, RuntimeError>,
    audit_trail_len: u64,
) -> RunePolicyDecision {
    match result {
        Ok(pr) => {
            let mut decision = RunePolicyDecision::new_deny();
            decision.outcome = pr.decision.to_i32();
            decision.evaluation_duration_us = pr.evaluation_duration.as_micros() as u64;
            decision.audit_record_id = audit_trail_len;
            copy_to_fixed_buf(&mut decision.matched_rule, "evaluate");
            decision
        }
        Err(err) => {
            // FAIL-CLOSED: any error produces DENY.
            let mut decision = RunePolicyDecision::new_deny();
            decision.outcome = RUNE_DENY;
            copy_to_fixed_buf(&mut decision.error_message, &err.to_string());
            decision
        }
    }
}

/// Copy a Rust string into a fixed-size c_char buffer, null-terminated.
fn copy_to_fixed_buf(buf: &mut [c_char], s: &str) {
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(buf.len() - 1);
    for i in 0..copy_len {
        buf[i] = bytes[i] as c_char;
    }
    buf[copy_len] = 0;
}

// ── Opaque module handle ───────────────────────────────────────────

/// Opaque handle for a loaded RUNE policy module.
/// Heap-allocated and returned as a raw pointer to the host.
#[allow(dead_code)]
pub struct RuneModule {
    pipeline: RuntimePipeline,
    module_name: String,
    last_error: Option<String>,
}

// ── Lifecycle API (C ABI exports) ──────────────────────────────────

/// Load a RUNE policy module from source code.
///
/// Returns an opaque handle on success, or null on failure.
/// The caller must call `rune_module_free` to release the handle.
#[unsafe(no_mangle)]
pub extern "C" fn rune_module_load_source(
    source: *const c_char,
    source_len: usize,
    signing_key: *const u8,
    signing_key_len: usize,
    module_name: *const c_char,
    module_name_len: usize,
) -> *mut RuneModule {
    let result = catch_unwind(|| {
        if source.is_null() || signing_key.is_null() || module_name.is_null() {
            return std::ptr::null_mut();
        }

        let source_str = unsafe {
            let slice = std::slice::from_raw_parts(source as *const u8, source_len);
            match std::str::from_utf8(slice) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            }
        };

        let key = unsafe { std::slice::from_raw_parts(signing_key, signing_key_len) };

        let name_str = unsafe {
            let slice = std::slice::from_raw_parts(module_name as *const u8, module_name_len);
            match std::str::from_utf8(slice) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            }
        };

        let config = PipelineConfig {
            signing_key: key.to_vec(),
            module_name: name_str.to_string(),
            attestation_checker: None,
        };

        match RuntimePipeline::from_source(source_str, config) {
            Ok(pipeline) => {
                let module = Box::new(RuneModule {
                    pipeline,
                    module_name: name_str.to_string(),
                    last_error: None,
                });
                Box::into_raw(module)
            }
            Err(_) => std::ptr::null_mut(),
        }
    });

    result.unwrap_or(std::ptr::null_mut())
}

/// Load a RUNE policy module from pre-compiled WASM bytes.
///
/// Returns an opaque handle on success, or null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn rune_module_load_wasm(
    wasm_bytes: *const u8,
    wasm_len: usize,
    signing_key: *const u8,
    signing_key_len: usize,
    module_name: *const c_char,
    module_name_len: usize,
) -> *mut RuneModule {
    let result = catch_unwind(|| {
        if wasm_bytes.is_null() || signing_key.is_null() || module_name.is_null() {
            return std::ptr::null_mut();
        }

        let wasm = unsafe { std::slice::from_raw_parts(wasm_bytes, wasm_len) };
        let key = unsafe { std::slice::from_raw_parts(signing_key, signing_key_len) };

        let name_str = unsafe {
            let slice = std::slice::from_raw_parts(module_name as *const u8, module_name_len);
            match std::str::from_utf8(slice) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            }
        };

        let policy_module = match PolicyModule::from_bytes(wasm) {
            Ok(m) => m,
            Err(_) => return std::ptr::null_mut(),
        };

        let evaluator = match crate::runtime::evaluator::AuditedPolicyEvaluator::new(
            &policy_module,
            key.to_vec(),
            name_str,
        ) {
            Ok(e) => e,
            Err(_) => return std::ptr::null_mut(),
        };

        // We need a RuntimePipeline, but it doesn't have a from_wasm constructor.
        // Build one by creating the pipeline through the evaluator directly.
        // Since RuntimePipeline wraps AuditedPolicyEvaluator, we construct it
        // using the from_evaluator method we'll add.
        let pipeline = RuntimePipeline::from_evaluator(evaluator);

        let module = Box::new(RuneModule {
            pipeline,
            module_name: name_str.to_string(),
            last_error: None,
        });
        Box::into_raw(module)
    });

    result.unwrap_or(std::ptr::null_mut())
}

/// Evaluate a policy request against a loaded module.
///
/// Returns 0 on success, -1 on error.
/// FAIL-CLOSED: any error writes DENY to the decision output.
/// The decision is always written, even on error.
#[unsafe(no_mangle)]
pub extern "C" fn rune_evaluate(
    module: *mut RuneModule,
    request: *const RunePolicyRequest,
    decision: *mut RunePolicyDecision,
) -> i32 {
    let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Null check — fail-closed to DENY.
        if module.is_null() || request.is_null() || decision.is_null() {
            if !decision.is_null() {
                unsafe {
                    *decision = RunePolicyDecision::error("null pointer passed to rune_evaluate");
                }
            }
            return RUNE_ERROR;
        }

        let module_ref = unsafe { &mut *module };
        let request_ref = unsafe { &*request };

        let policy_request = PolicyRequest::new(
            request_ref.subject_id,
            request_ref.action,
            request_ref.resource_id,
            request_ref.risk_score,
        );

        let eval_result = module_ref.pipeline.evaluate(&policy_request);
        let audit_len = module_ref.pipeline.audit_trail().len() as u64;

        let out = decision_from_result(eval_result, audit_len);
        unsafe { *decision = out };

        if unsafe { (*decision).outcome } == RUNE_ERROR || unsafe { (*decision).outcome } == RUNE_DENY {
            // Store last error if there was one.
            let err_buf = unsafe { &(*decision).error_message };
            let err_str = c_buf_to_string(err_buf);
            if !err_str.is_empty() {
                module_ref.last_error = Some(err_str);
            }
        }

        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            // Panic — fail-closed to DENY.
            if !decision.is_null() {
                unsafe {
                    *decision = RunePolicyDecision::error("internal panic in rune_evaluate");
                }
            }
            RUNE_ERROR
        }
    }
}

/// Free a loaded module handle.
///
/// Safe to call with null (no-op).
#[unsafe(no_mangle)]
pub extern "C" fn rune_module_free(module: *mut RuneModule) {
    if !module.is_null() {
        unsafe {
            drop(Box::from_raw(module));
        }
    }
}

/// Get the number of audit records in the module's trail.
///
/// Returns 0 if the module pointer is null.
#[unsafe(no_mangle)]
pub extern "C" fn rune_audit_trail_len(module: *mut RuneModule) -> u64 {
    if module.is_null() {
        return 0;
    }
    let module_ref = unsafe { &*module };
    module_ref.pipeline.audit_trail().len() as u64
}

/// Get the last error message from the module.
///
/// Returns a pointer to a null-terminated C string, valid until the
/// next rune_evaluate call. Returns null if no error or module is null.
#[unsafe(no_mangle)]
pub extern "C" fn rune_last_error(module: *mut RuneModule) -> *const c_char {
    if module.is_null() {
        return std::ptr::null();
    }
    let module_ref = unsafe { &*module };
    match &module_ref.last_error {
        Some(err) => err.as_ptr() as *const c_char,
        None => std::ptr::null(),
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn c_buf_to_string(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}
