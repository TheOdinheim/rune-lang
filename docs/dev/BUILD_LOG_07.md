# Build Log 07

## 2026-04-09 — M8 Layer 1: FFI Syntax, Extern Blocks, FFI Effect Enforcement, Audit Instrumentation

### What was built

Foreign Function Interface (FFI) frontend for RUNE: `extern` blocks declaring C-compatible function signatures, standalone `extern fn` sugar, ABI string parsing ("C" only), automatic `ffi` effect on all extern functions with transitive enforcement, IR audit instrumentation (FfiCallStart/FfiCallEnd markers around every FFI call), plus toolchain updates (tree-sitter, formatter, LSP, docgen).

### Four-pillar alignment

- **Security Baked In**: FFI calls require explicit `ffi` effect declaration — no silent boundary crossing
- **Assumed Breach**: Every FFI call bracketed with FfiCallStart/FfiCallEnd audit marks for traceability
- **Zero Trust Throughout**: Transitive effect enforcement — callers of FFI callers must also declare `ffi`
- **No Single Points of Failure**: ABI validation rejects unsupported ABIs at parse time

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/lexer/token.rs | `Extern` keyword variant + keyword_from_str entry | +2 lines |
| src/ast/nodes.rs | ExternBlock, ExternFnDecl structs, ItemKind::Extern variant | +20 lines |
| src/parser/parser.rs | parse_extern_block, parse_extern_fn_decl, synchronize/dispatch | ~80 lines |
| src/types/checker.rs | register_extern_block (ffi effect), visibility map, check_item | ~30 lines |
| src/ir/nodes.rs | AuditKind::FfiCallStart/FfiCallEnd variants + Display | +6 lines |
| src/ir/lower.rs | extern_functions HashSet, FfiCallStart/End around extern calls | ~25 lines |
| src/formatter/mod.rs | format_extern_block (standalone + block form) | ~50 lines |
| tools/tree-sitter-rune/grammar.js | extern_block, extern_fn_declaration rules | ~20 lines |
| tools/tree-sitter-rune/queries/highlights.scm | extern keyword + extern_fn_declaration highlight | +2 lines |
| src/lsp/mod.rs | extern keyword hover, extern fn completions/hover/go-to-def | ~30 lines |
| src/docgen/mod.rs | DocItemKind::ExternFunction, extern extraction + rendering | ~40 lines |

### Architecture

**Extern block parsing:**
- Block form: `extern { fn sha256(data: Int) -> Int; fn md5(data: Int) -> Int; }`
- Standalone sugar: `extern fn sha256(data: Int) -> Int;` (desugars to single-fn block)
- ABI string: `extern "C" { ... }` — only "C" accepted, others rejected at parse time
- Extern fn declarations have no body — parser errors if `{` found after params
- `pub extern` propagates visibility to all contained functions

**FFI effect enforcement:**
- All extern functions registered as `Symbol::Function` with `effects: vec!["ffi"]`
- Existing M2 Layer 3 `check_callee_effects()` infrastructure handles enforcement automatically
- Callers must declare `with effects { ffi }` or get a clear error message
- Transitive: if `hash()` calls extern `sha256()`, then callers of `hash()` also need `ffi`

**IR audit instrumentation:**
- `AuditKind::FfiCallStart { function_name }` emitted before every extern call
- `AuditKind::FfiCallEnd { function_name }` emitted after every extern call
- Lowerer tracks extern function names in `extern_functions: HashSet<String>`
- WASM codegen handles new variants via existing AuditMark wildcard (nop)

### Test summary

24 new tests added (741 total, up from 717):

| Area | Tests | What's covered |
|------|-------|----------------|
| Lexer | 4 | extern keyword, extern fn tokens, block tokens, ABI string |
| Parser | 10 | single/multi fn blocks, standalone, ABI, pub, no-return, no-params, errors |
| Type checker | 12 | registration, callable, ffi effect required, transitive, module integration |
| Formatter | 4 | standalone, block, ABI, idempotent |
| LSP | 3 | keyword hover, completions, hover info |
| Docgen | 2 | extraction, markdown rendering |
| IR | 3 | FfiCallStart/End marks, non-extern no marks, display |

### Decisions

- **Reused Symbol::Function for extern fns** rather than adding new Symbol variant. The `effects: vec!["ffi"]` field leverages existing effect checking — zero new enforcement code needed.
- **Formatter uses block form when ABI present** even for single functions. Standalone sugar only applies to `extern fn name(...);` without ABI string.
- **No new WASM codegen changes needed** — AuditMark wildcard match already handles new FfiCallStart/FfiCallEnd as nops.

---

## 2026-04-09 — M8 Layer 2: C ABI Embedding API with Fail-Closed Governance

### What was built

C-compatible embedding API for host applications to load and evaluate RUNE policy modules. Exposes opaque handles through `extern "C"` functions so any language with C FFI support (Rust, Go, Python, Java, C#, Ruby, Swift, Zig) can invoke RUNE governance. Includes a safe Rust wrapper (no unsafe required for Rust callers) and a C header file.

### Four-pillar alignment

- **Security Baked In**: Every failure mode defaults to DENY — no code path returns implicit PERMIT on error
- **Assumed Breach**: All evaluations recorded in cryptographic audit trail automatically
- **Zero Trust Throughout**: Opaque handles prevent host applications from inspecting/tampering internals
- **No Single Points of Failure**: `catch_unwind` on all C API entry points — panics produce DENY, never crash the host

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/embedding/mod.rs | C ABI types, lifecycle functions, fail-closed logic | New (~310 lines) |
| src/embedding/safe_api.rs | Safe Rust wrapper (RuneEngine, EmbeddingRequest/Decision) | New (~140 lines) |
| src/embedding/tests.rs | 24 tests: structs, fail-closed, lifecycle, safe API, integration | New (~310 lines) |
| tools/rune.h | C header with struct defs, function prototypes, docs | New (~160 lines) |
| src/lib.rs | Added `pub mod embedding` (runtime feature-gated) | +2 lines |
| src/runtime/pipeline.rs | Added `from_evaluator()` constructor for WASM-loaded modules | +6 lines |
| Cargo.toml | Added `[lib] crate-type = ["rlib", "cdylib"]` | +3 lines |

### Architecture

**C ABI types:**
- `RunePolicyRequest` (#[repr(C)]): subject_id, action, resource_id, risk_score, context_json, context_json_len
- `RunePolicyDecision` (#[repr(C)]): outcome (i32), matched_rule ([c_char;256]), evaluation_duration_us, error_message ([c_char;512]), audit_record_id
- Outcome constants: RUNE_PERMIT=0, RUNE_DENY=1, RUNE_ESCALATE=2, RUNE_QUARANTINE=3, RUNE_ERROR=-1

**Opaque handle lifecycle:**
- `rune_module_load_source()` → compile source → RuntimePipeline → heap-allocate → return raw pointer
- `rune_module_load_wasm()` → load WASM bytes → PolicyModule → AuditedPolicyEvaluator → return raw pointer
- `rune_evaluate()` → validate pointers → evaluate → write decision → fail-closed on any error
- `rune_module_free()` → reconstruct Box → drop (safe with null)
- `rune_audit_trail_len()` / `rune_last_error()` → query state

**Fail-closed design:**
- `decision_from_result()`: Ok → actual decision, Err → DENY with error message
- Null pointer checks on all C API entry points → DENY
- `catch_unwind` wraps all C API entry points → panics produce DENY
- Error decisions always populate error_message buffer

**Safe Rust API (RuneEngine):**
- `from_source()` / `from_wasm()` → Result<Self, String>
- `evaluate()` → EmbeddingDecision (always returns, errors → Deny)
- `audit_trail_len()` / `export_audit_log()` → audit access
- No raw pointers exposed to callers

**cdylib build target:**
- Cargo.toml: `crate-type = ["rlib", "cdylib"]` — builds both Rust lib and C shared library
- Binary targets (rune-lang, rune-lsp) link against rlib

### Test summary

24 new tests added (765 lib + 14 integration = 779 total, up from 755):

| Area | Tests | What's covered |
|------|-------|----------------|
| C ABI structs | 4 | layout, outcome constants, PolicyDecision→i32 conversion |
| Fail-closed | 4 | error→DENY, null module→DENY, invalid source→null, error message |
| C lifecycle | 4 | load/evaluate/free, free null, audit trail increases, null trail len |
| Safe Rust API | 6 | from_source, invalid source, permit/deny/risk, audit trail, export |
| Integration | 6 | full scenario, risk-based, multi-rule, WASM load, C API WASM |

### Decisions

- **Additive design**: Embedding API wraps existing RuntimePipeline — zero changes to existing Rust API
- **RuntimePipeline::from_evaluator()**: Single new method to support WASM-loaded modules through the embedding API
- **catch_unwind on all C entry points**: Panics produce DENY, never crash the host process
- **Fixed-size buffers in RunePolicyDecision**: [c_char; 256] for rule name, [c_char; 512] for error message — simple C-compatible layout without heap allocation in the output struct
