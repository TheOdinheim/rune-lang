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

---

## 2026-04-09 — M8 Layer 3: FlatBuffers Wire Format with Zero-Copy Serialization

### What was built

Custom binary wire format for cross-language policy evaluation at sub-millisecond latency. Tagged field encoding for PolicyRequest and PolicyDecision serialization/deserialization, C ABI wire evaluation function, safe Rust wire API methods, and FlatBuffers schema as the contract definition. The wire format supports rich nested structures (Subject, Action, Resource, Context, Attestation) beyond the basic i64 fields.

### Four-pillar alignment

- **Security Baked In**: Deserialization failure produces DENY — no implicit PERMIT from malformed input
- **Assumed Breach**: Wire evaluations feed through the same cryptographic audit trail as struct-based calls
- **Zero Trust Throughout**: Every field validated during deserialization; unknown tags safely skipped
- **No Single Points of Failure**: Buffer-too-small returns -2 with required size, never truncates decisions

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/embedding/wire.rs | Wire types, binary serialization/deserialization | New (~430 lines) |
| src/embedding/mod.rs | Added `rune_evaluate_wire()` C ABI function | +100 lines |
| src/embedding/safe_api.rs | Added `evaluate_wire()` and `evaluate_wire_bytes()` | +40 lines |
| src/embedding/tests.rs | 20 new wire format tests | +270 lines |
| schemas/policy.fbs | FlatBuffers schema (contract definition) | New (~50 lines) |
| tools/rune.h | Added `rune_evaluate_wire` prototype | +20 lines |
| Cargo.toml | Added flatbuffers dependency (optional, runtime feature) | +1 line |

### Architecture

**Wire types:**
- `WireRequest`: subject (WireSubject), action (WireAction), resource (WireResource), context (WireContext), attestation (WireAttestation) — rich nested structure
- `WireDecision`: outcome (PolicyDecision), matched_rule, evaluation_duration_us, explanation, audit (WireAuditInfo)
- All types derive Default for fail-closed construction

**Binary tagged field encoding:**
- Format: `[u32 total_len][u8 tag][field_id:u8][field_len:u32][data...]`
- Tag byte identifies type: 0x01=i32, 0x02=i64, 0x03=u64, 0x04=string, 0x05=bytes, 0x06=string_list, 0x07=key_value
- Field IDs: FIELD_SUBJECT_ID=1, FIELD_ACTION=2, FIELD_RESOURCE_ID=3, etc.
- Unknown field IDs safely skipped (forward compatibility)
- Zero-alloc read path for primitive fields

**Conversions:**
- `From<&WireRequest> for PolicyRequest` — maps to the standard evaluate() signature
- `From<&PolicyResult> for WireDecision` — wraps evaluation results
- WireError enum: MalformedBuffer, MissingRequiredField, InvalidOutcome

**C ABI (`rune_evaluate_wire`):**
- Takes serialized request bytes, evaluates, writes serialized decision to output buffer
- Returns 0 (success), -1 (error), -2 (buffer too small, writes required size)
- Deserialization failure → serialized DENY decision (fail-closed)

**Safe Rust API:**
- `evaluate_wire(&WireRequest) -> WireDecision` — typed wire evaluation
- `evaluate_wire_bytes(&[u8]) -> Result<Vec<u8>, WireError>` — bytes-in/bytes-out path

### Test summary

20 new tests added (785 lib + 14 integration = 799 total, up from 779):

| Area | Tests | What's covered |
|------|-------|----------------|
| Serialization round-trips | 9 | minimal/full request, decision, empty fields, all outcomes, large payload, unknown fields |
| Conversion | 3 | WireRequest→PolicyRequest, PolicyResult→WireDecision, error→Deny |
| Wire embedding API | 4 | safe API wire eval, wire bytes eval, deserialization error→Deny, C ABI wire eval |
| Benchmarks | 4 | request serialization, decision serialization, round-trip, deserialization |

### Decisions

- **Custom binary format instead of FlatBuffers runtime**: The `flatbuffers` crate is an optional dependency; the actual encoding uses a simpler tagged field format. The FlatBuffers schema (`schemas/policy.fbs`) serves as the contract definition and documentation.
- **Rich wire types vs flat i64 fields**: WireRequest supports nested Subject/Action/Resource/Context/Attestation structures, enabling richer policy evaluation than the basic 4-field PolicyRequest.
- **Unknown field skip**: Deserializer skips unrecognized field IDs, enabling forward-compatible schema evolution without breaking existing clients.

---

## 2026-04-09 — M8 Layer 4: Language Integration Packages — M8 COMPLETE

### What was built

First-class integration packages for Rust and Python that wrap the C ABI embedding API and wire format, so developers work with native data structures instead of raw pointers or bytes. A Rust crate (`rune-rs`) with builder pattern, JSON evaluation, and audit trail access. A Python package (`rune-python`) with wasmtime-based WASM execution and dictionary evaluation. Usage examples for Rust, Python, and C. A comprehensive integration guide.

### Four-pillar alignment

- **Security Baked In**: Both packages inherit fail-closed semantics — errors always produce Deny
- **Assumed Breach**: Audit trail is accessible through both Rust and Python APIs
- **Zero Trust Throughout**: Packages wrap opaque handles — no internal access exposed
- **No Single Points of Failure**: Three integration paths (Rust, Python, C) with identical governance guarantees

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added workspace declaration | +3 lines |
| packages/rune-rs/Cargo.toml | Rust crate package manifest | New (~12 lines) |
| packages/rune-rs/src/lib.rs | PolicyEngine, Request, Decision, Outcome, AuditEntry + 16 tests | New (~430 lines) |
| packages/rune-python/pyproject.toml | Python package manifest | New (~15 lines) |
| packages/rune-python/rune/__init__.py | PolicyEngine, Decision, RuneError, load() | New (~220 lines) |
| packages/rune-python/rune/py.typed | PEP 561 type marker | New (empty) |
| packages/rune-python/tests/test_rune.py | Python tests (Decision, RuneError, validation) | New (~80 lines) |
| packages/rune-python/README.md | Python package documentation | New (~70 lines) |
| examples/rust_integration.rs.example | Rust usage example | New (~60 lines) |
| examples/python_integration.py | Python usage example | New (~55 lines) |
| examples/c_integration.c | C API usage example | New (~80 lines) |
| docs/INTEGRATION_GUIDE.md | Comprehensive multi-language integration guide | New (~165 lines) |

### Architecture

**rune-rs crate:**
- `PolicyEngine`: wraps `RuneEngine` from the embedding safe API
- `Request`: builder pattern (`Request::new().subject(1).risk(85)`) + `Default` + serde
- `Outcome`: Permit/Deny/Escalate/Quarantine with `is_permit()`/`is_deny()` helpers
- `Decision`: outcome, matched_rule, evaluation_time, error, audit_id
- `AuditEntry`: simplified view of `AuditRecord` with `From` conversion
- `evaluate_json()`: deserialize JSON → Request → evaluate (for REST handlers)

**rune-python package:**
- `PolicyEngine`: loads WASM via wasmtime, calls `evaluate` export directly
- `Decision`: outcome string, `permitted`/`denied` properties
- `evaluate_dict()`: evaluate from Python dict (for REST handlers)
- Source compilation via `rune-lang` CLI subprocess
- `load()` shorthand for `PolicyEngine(wasm_path=...)`

### Test summary

16 new Rust tests added (815 total: 785 rune-lang lib + 14 integration + 16 rune-rs):

| Area | Tests | What's covered |
|------|-------|----------------|
| Engine lifecycle | 2 | from_source valid, from_source invalid |
| All outcomes | 4 | permit, deny, escalate, quarantine |
| Risk-based policy | 1 | different scores produce different outcomes |
| Request builder | 2 | builder pattern, default values |
| Outcome helpers | 2 | Display formatting, is_permit/is_deny |
| Audit trail | 2 | trail grows, entries have event types |
| JSON evaluation | 2 | valid JSON, invalid JSON error |
| Error display | 1 | RuneError Display formatting |

Python tests (not run from cargo): Decision, RuneError, PolicyEngine validation, wasmtime integration.

### Decisions

- **Workspace member**: rune-rs is a Cargo workspace member, not a standalone repo. Simplifies development and testing before M13 publish.
- **Default signing key**: `PolicyEngine::from_source()` uses a default key for convenience; `from_source_with_key()` available for production.
- **Python uses wasmtime directly**: Rather than FFI into the C ABI (which would require building the shared library), the Python package loads compiled WASM bytes through wasmtime-py. Same execution path, simpler distribution.
- **Example files use .rs.example extension**: Prevents Cargo from trying to compile examples that depend on rune-rs as part of the rune-lang build.
