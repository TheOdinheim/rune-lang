# Build Log 04

## 2026-04-07 — M5 Layer 1: Runtime Policy Evaluator

### What was built

A production runtime for compiled RUNE policy modules. Host applications (rune-python, rune-rs, or any embedding) load .rune.wasm files and evaluate policy decisions through a clean API. Each evaluation gets a fresh wasmtime Store (arena model from RUNE_06) — no state leaks between evaluations.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Moved wasmtime from dev-dependency to dependency | +1 / -1 line |
| src/lib.rs | Added runtime module | +1 line |
| src/runtime/mod.rs | Module declarations | New file, 5 lines |
| src/runtime/evaluator.rs | PolicyModule, PolicyEvaluator, PolicyDecision, types, errors | New file, ~250 lines |
| src/runtime/pipeline.rs | compile_and_load, compile_and_evaluate convenience functions | New file, ~35 lines |
| src/runtime/tests.rs | 32 tests covering all runtime functionality | New file, ~320 lines |

### Architecture

**PolicyModule** (thread-safe, reusable):
- Loads WASM bytes or .rune.wasm files
- Stores wasmtime Engine + compiled Module
- Module inspection: `list_exports()`, `list_policy_rules()`, `has_evaluate()`
- Creates `PolicyEvaluator` instances for evaluation

**PolicyEvaluator** (per-evaluation arena):
- `evaluate(request)` — calls standard `evaluate(subject_id, action, resource_id, risk_score) -> i32`
- `evaluate_rule(name, args)` — calls individual exported rules by name
- Fresh Store + Instance per call (arena model, zero state leakage)
- Records evaluation duration for performance monitoring

**PolicyDecision** encoding: Permit=0, Deny=1, Escalate=2, Quarantine=3

**Pipeline convenience**:
- `compile_and_load(source)` → reusable PolicyModule
- `compile_and_evaluate(source, request)` → one-shot evaluation

### Error handling

| Error variant | When |
|---------------|------|
| ModuleLoadError | Invalid WASM bytes or file read failure |
| ExportNotFound | Missing `evaluate` or named rule export |
| EvaluationFailed | WASM execution trap or runtime error |
| InvalidDecision | Return value not in 0..3 range |
| CompilationFailed | Source code has lex/parse/type errors |

### Test results

```
cargo build: clean, 0 warnings
cargo test: 467 passed (49 lexer + 102 parser + 166 types + 24 ir + 31 codegen + 18 compiler + 45 smt + 32 runtime), 0 failed
```

### New runtime tests (32 tests)

| Test | What it covers |
|------|---------------|
| test_policy_decision_from_i32 | All 4 decisions + invalid value |
| test_policy_decision_to_i32 | Reverse mapping |
| test_policy_decision_display | Display formatting |
| test_policy_decision_roundtrip | from_i32(to_i32()) roundtrip |
| test_load_compiled_module | Load valid WASM bytes |
| test_load_invalid_wasm_error | Invalid bytes produce ModuleLoadError |
| test_has_evaluate_true | Policy module has evaluate export |
| test_has_evaluate_false_for_plain_functions | No policies → no evaluate |
| test_list_exports | All function exports listed |
| test_list_policy_rules | Only __ rules listed |
| test_evaluate_permit | Standard evaluate → Permit |
| test_evaluate_deny | Standard evaluate → Deny |
| test_evaluate_escalate | Standard evaluate → Escalate |
| test_evaluate_quarantine | Standard evaluate → Quarantine |
| test_evaluate_decisions_change_based_on_input | Different inputs → different decisions |
| test_evaluate_first_non_permit_wins | Multi-rule: first non-permit wins |
| test_evaluate_no_evaluate_export_error | No policies → ExportNotFound |
| test_evaluate_rule_by_name | Direct rule call |
| test_evaluate_rule_with_args | Rule call with i64 arguments |
| test_evaluate_rule_nonexistent_error | Missing rule → ExportNotFound |
| test_evaluation_timing_recorded | Duration is recorded |
| test_evaluation_sub_millisecond | Fast evaluation (<10ms) |
| test_multiple_evaluations_isolated | Arena model: no state leaks |
| test_multiple_evaluators_from_same_module | Multiple evaluators from one module |
| test_compile_and_evaluate_permit | One-shot pipeline → Permit |
| test_compile_and_evaluate_deny | One-shot pipeline → Deny |
| test_compile_and_evaluate_compilation_error | Bad source → CompilationFailed |
| test_compile_and_load_reusable | Reusable module from source |
| test_realistic_governance_multi_rule | Conditional logic + helper functions |
| test_realistic_governance_permit_path | Low-risk path → Permit |
| test_realistic_multi_policy_governance | Multi-policy: deny wins over permit |
| test_runtime_error_display | Error message formatting |

### Pillars served

- **Security Baked In:** Policy modules are compiled WASM bytecode — the runtime cannot modify policy logic. Decisions are computed from immutable governance rules.
- **Assumed Breach:** Each evaluation creates a fresh wasmtime Store and Instance. No state leaks between evaluations — the arena model ensures complete isolation.
- **Zero Trust Throughout:** The runtime validates module structure (exports, signatures) before evaluation. Invalid decisions produce errors, not undefined behavior.
- **No Single Points of Failure:** Individual rules can be evaluated independently via `evaluate_rule()`. The standard `evaluate` entry point aggregates all rules with first-non-permit-wins semantics, but direct rule access enables fine-grained policy auditing.

---

## 2026-04-07 — M5 Layer 2: Cryptographic Audit Trail

### What was built

Append-only cryptographic audit trail with hash chain and placeholder PQC signatures. Every policy decision is recorded with a SHA-256 hash chain (stand-in for SHA-3) and HMAC-SHA256 signatures (stand-in for ML-DSA). The crypto module is designed so swapping to real PQC primitives post-M10 is a single-file change.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added sha2, hmac, hex dependencies | +3 lines |
| src/runtime/mod.rs | Added audit module | +1 line |
| src/runtime/audit.rs | AuditTrail, AuditRecord, hash chain, signatures, crypto module | New file, ~300 lines |
| src/runtime/evaluator.rs | AuditedPolicyEvaluator wrapping evaluator with audit trail | +75 lines |
| src/runtime/tests.rs | 17 new audit and integration tests | +200 lines |

### Architecture

**AuditRecord**: record_id, timestamp, event_type, policy_module, function_name, decision, input_hash, previous_hash, record_hash, signature

**Hash chain**: Each record's `record_hash = SHA256(record_id || timestamp || event_type || ...)`. Each record's `previous_hash` = prior record's `record_hash`. First record links to genesis (all zeros). Append-only — tampering breaks the chain.

**Signatures**: `signature = HMAC-SHA256(signing_key, record_hash)`. Verification walks the chain checking each signature. Interface designed for ML-DSA swap.

**Crypto abstraction**: Two functions in `audit::crypto` module:
- `hash(payload) -> hex_string` — currently SHA-256, will be SHA-3
- `sign(key, data) -> hex_string` — currently HMAC-SHA256, will be ML-DSA

**AuditedPolicyEvaluator**: Wraps PolicyEvaluator, automatically records every `evaluate()` and `evaluate_rule()` call. Provides `audit_trail()` and `export_audit_log()`.

### Test results

```
cargo build: clean, 0 warnings
cargo test: 484 passed (49 lexer + 102 parser + 166 types + 24 ir + 31 codegen + 18 compiler + 45 smt + 49 runtime), 0 failed
```

### New audit tests (17 tests)

| Test | What it covers |
|------|---------------|
| test_audit_record_decision_and_verify_chain | Single record, chain verifies |
| test_audit_multiple_records_chain_integrity | 3 records, chain links correct |
| test_audit_genesis_record_has_zero_previous | First record links to genesis |
| test_audit_record_counter_increments | IDs increment 0, 1, 2 |
| test_audit_tamper_detection_modified_record | Modified record detectable |
| test_audit_verify_signatures | All signatures verify with correct key |
| test_audit_verify_signatures_wrong_key | Wrong key → InvalidSignature |
| test_audit_empty_trail_verification_error | Empty trail → EmptyTrail error |
| test_audit_event_types | FunctionEntry/Exit, CapabilityExercise, ModelInvocation |
| test_audit_latest_record | latest() returns most recent |
| test_audit_decision_field_recorded | Decision, input_hash, module, function stored |
| test_audit_verification_error_display | Error message formatting |
| test_audited_evaluator_records_decision | evaluate() auto-records to trail |
| test_audited_evaluator_multiple_evaluations | 3 evaluations, chain intact |
| test_audited_evaluator_export_log | export_audit_log() returns records |
| test_audited_evaluator_rule_evaluation | evaluate_rule() records to trail |
| test_hash_input_utility | hash_input deterministic, 64 hex chars |

### Pillars served

- **Security Baked In:** Every policy decision is automatically recorded in a cryptographic audit trail. The compiler inserts AuditMark instructions; the runtime records them. No opt-out.
- **Assumed Breach:** The hash chain detects tampering. Modifying any record breaks the chain link. Signatures provide non-repudiation — the signing key proves who recorded the decision.
- **Zero Trust Throughout:** Each record is independently verifiable. Chain verification and signature verification are separate operations that can be performed by different parties.
- **No Single Points of Failure:** The audit trail is self-contained and exportable. Records can be verified offline without access to the original runtime or policy module.
