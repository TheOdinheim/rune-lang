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
