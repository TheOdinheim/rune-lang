# Build Log 08

## 2026-04-09 — M9 Layer 1: LLVM Backend Infrastructure, Feature Gating, Basic IR-to-LLVM Translation

### What was built

LLVM native compilation backend translating RUNE IR to LLVM IR via inkwell, then to native object code (.o files). Feature-gated behind `--features llvm` so the default build (cargo build, cargo test) requires no LLVM installation. Covers all IR instruction kinds: constants, arithmetic, comparisons, logical/bitwise ops, variables (alloca/store/load), function calls, governance decisions, select/copy, and terminators (return, branch, conditional branch, unreachable). CLI gains `--target native` flag. Full pipeline: RUNE source → lex → parse → type check → IR → LLVM IR → native ELF object file.

### Four-pillar alignment

- **Security Baked In**: Governance decisions compile to i32 constants matching the C ABI (0=Permit, 1=Deny, 2=Escalate, 3=Quarantine)
- **Assumed Breach**: AuditMark instructions compile to nops (placeholder for native audit runtime in Layer 2)
- **Zero Trust Throughout**: LLVM module verification catches malformed IR before object emission
- **No Single Points of Failure**: Dual backend (WASM + LLVM) — same IR, two compilation targets

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/codegen/llvm_gen.rs | LLVM codegen: LlvmCodegen struct, type mapping, all InstKinds, terminators, output | New (~370 lines) |
| src/codegen/llvm_tests.rs | 27 tests: constants, arithmetic, comparisons, booleans, params, calls, variables, floats, governance, verification, object output, pipeline | New (~360 lines) |
| src/codegen/mod.rs | Added `#[cfg(feature = "llvm")] pub mod llvm_gen` and test module | +6 lines |
| src/compiler/mod.rs | Added `compile_to_native()` and `compile_to_native_file()` (feature-gated) | +90 lines |
| src/main.rs | Added `--target` flag to Build, `cmd_build_native()` with feature gate | +45 lines |
| Cargo.toml | Added `inkwell` dependency (optional), `llvm` feature | +2 lines |

### Architecture

**Feature gating:**
- `Cargo.toml`: `llvm = ["inkwell"]`, NOT in default features
- All LLVM code: `#[cfg(feature = "llvm")]`
- CLI: `cmd_build_native()` has both `#[cfg(feature = "llvm")]` and `#[cfg(not(feature = "llvm"))]` variants
- Default `cargo test` runs zero LLVM tests, all 815 existing tests pass

**LLVM type mapping:**
- IrType::Int → i64, Float → f64, Bool → i1, String → ptr, Unit → i8
- PolicyDecision → i32 (matches C ABI constants)
- Ptr → opaque pointer, FuncRef → i32

**Instruction compilation:**
- All 30+ InstKind variants handled (constants, arithmetic, comparisons, logical, bitwise, variables, calls, governance, select, copy, audit nops)
- Float-aware: arithmetic dispatches to float instructions when result type is Float
- Function names sanitized (:: → __) matching WASM backend convention

**Output paths:**
- `emit_llvm_ir()` → String (for debugging/testing)
- `emit_bitcode(path)` → LLVM bitcode file
- `emit_object_file(path)` → native .o file via TargetMachine
- `emit_object_bytes()` → Vec<u8> via memory buffer

### Test summary

27 new tests (only run with `cargo test --features llvm`):

| Area | Tests | What's covered |
|------|-------|----------------|
| Constants | 4 | int, float, bool, string |
| Arithmetic | 4 | add, sub, mul, div |
| Comparisons | 4 | eq, ne, lt, gt |
| Boolean ops | 3 | and, or, not |
| Parameters | 1 | correct param types in function signature |
| Function calls | 1 | call instruction generation |
| Variables | 1 | alloca + store + load pattern |
| Float arithmetic | 1 | fadd instruction |
| Governance | 1 | DecisionKind → i32 constant |
| Verification | 3 | module verifies, correct return type, correct param count |
| Object output | 3 | non-empty bytes, ELF magic, file write |
| Pipeline | 3 | full source→native, invalid source→errors, params |

### Decisions

- **inkwell 0.5 with llvm18-0 feature**: Targets LLVM 18, the current stable LTS release on Ubuntu
- **Feature-gated, not default**: LLVM installation is heavy (~500MB). Default builds use WASM only.
- **Same IR, two backends**: The IR module is backend-agnostic. WASM and LLVM codegen consume the same IrModule.
- **AuditMark as nop**: Native audit runtime integration deferred to Layer 2. Governance decisions are correctly encoded as i32 values.
- **Host target only**: Currently targets the host triple (x86-64 on WSL2). Cross-compilation support deferred to Layer 3.

---

## 2026-04-09 — M9 Layer 2: Complete IR-to-LLVM Translation — Control Flow, Policy Decisions, Cross-Backend Equivalence

### What was built

Complete IR-to-LLVM translation covering control flow (if/else, while loops), all four policy decisions compiled to i32 constants, evaluate entry point with first-non-permit-wins semantics matching the WASM backend, and cross-backend semantic equivalence tests. Fixed 12 Layer 1 tests that failed due to LLVM constant folding by rewriting helpers to use function parameters. Total: 48 LLVM-gated tests.

### Four-pillar alignment

- **Security Baked In**: All four governance decisions (Permit=0, Deny=1, Escalate=2, Quarantine=3) compile to correct i32 constants in native code
- **Assumed Breach**: Evaluate entry point enforces first-non-permit-wins — any deny/escalate/quarantine short-circuits, matching WASM semantics
- **Zero Trust Throughout**: Cross-backend equivalence tests verify WASM and LLVM produce structurally identical output for the same source
- **No Single Points of Failure**: Dual backend fully operational — same source, same IR, two compilation targets with equivalent behavior

### Files modified

| File | Purpose | Changes |
|------|---------|---------|
| src/codegen/llvm_gen.rs | LLVM codegen: evaluate wrapper, Linkage import, unused import cleanup | +120 lines (370→490 net) |
| src/codegen/llvm_tests.rs | Complete rewrite: 48 tests with param-based helpers, control flow, evaluate, cross-backend equivalence | Rewritten (~530→894 lines) |

### Architecture

**Constant folding fix:**
- Layer 1 tests used literal constants (e.g., `IntConst(10) + IntConst(3)`), which LLVM folds at construction time to `ret i64 13`
- Layer 2 rewrites all arithmetic/comparison/boolean tests to use `param_binop_module()` and `param_unaryop_module()` helpers that pass values as function parameters, preventing constant folding

**Control flow:**
- If/else: CondBranch terminator → LLVM conditional branch with then/else/merge basic blocks, phi node for merge
- While loops: header block (condition check) → body block → back-edge branch to header → exit block
- Multi-block functions: arbitrary block counts with correct branch targets

**Policy decision compilation:**
- GovernanceDecision(Permit) → `i32 0`, Deny → `i32 1`, Escalate → `i32 2`, Quarantine → `i32 3`
- Matches C ABI and WASM backend encoding exactly

**Evaluate entry point:**
- `evaluate(i64, i64, i64, i64) -> i32` function with External linkage
- Identifies policy rules: `return_type == PolicyDecision && name.contains("::")`
- For each rule: call → compare result != 0 (Permit) → conditional branch
- First non-Permit result returned immediately; all Permit → return 0
- Matches WASM `compile_evaluate_wrapper()` semantics exactly

**Cross-backend equivalence testing:**
- Compiles same RUNE source through both WASM and LLVM pipelines
- WASM path: compile + execute via wasmtime → verify actual decision value
- LLVM path: compile → verify IR structure (correct functions, branches, constants)
- 6 equivalence tests: permit, deny, escalate, quarantine, risk-based conditional, multi-rule

### Test summary

48 tests (only run with `cargo test --features llvm`):

| Area | Tests | What's covered |
|------|-------|----------------|
| Constants | 4 | int, float, bool, string |
| Arithmetic (params) | 4 | add, sub, mul, div using function parameters |
| Comparisons (params) | 4 | eq, ne, lt, gt using function parameters |
| Boolean ops (params) | 3 | and, or, not using function parameters |
| Float (params) | 1 | fadd instruction |
| Parameters | 1 | correct param types in function signature |
| Function calls | 1 | call instruction generation |
| Variables | 1 | alloca + store + load pattern |
| Governance decisions | 4 | all four decisions → correct i32 constants |
| Control flow | 4 | if/else, nested if/else, while loop, multi-block |
| Risk policy | 1 | conditional branch in compiled policy |
| Evaluate entry point | 4 | exists, calls rules, returns i32, first-non-permit-wins |
| Cross-backend equiv | 6 | permit, deny, escalate, quarantine, risk, multi-rule |
| Verification/output | 6 | module verify, return type, param count, bytes, file, IR |
| Pipeline integration | 4 | source→native, invalid→errors, params, policy→native |

### Decisions

- **Param-based test helpers**: Prevents LLVM constant folding from eliminating operations under test. All arithmetic/comparison/boolean tests now use function parameters.
- **Cross-backend structural equivalence**: Since LLVM native code can't easily be JIT-executed in tests, we verify IR structure matches expected patterns while WASM tests verify actual execution.
- **First-non-permit-wins**: Evaluate wrapper matches WASM backend exactly. If any rule returns non-Permit, that decision is returned immediately. Default is Permit (0).
- **48 total tests**: 21 new tests added to Layer 1's 27, with 12 Layer 1 tests rewritten to use parameters.

---

## 2026-04-09 — M9 Layer 3: Native Binary Linking — Shared Libraries, Executables, CLI Integration

### What was built

Native binary linking that turns LLVM object files into usable artifacts: shared libraries (.so) via `cc -shared`, standalone executables with a generated main() wrapper, and CLI integration with `--target native-shared` and `--target native-exe`. Updated C header (rune.h) with native shared library documentation. AuditMark instructions remain nops in native code — the host application handles audit via the existing embedding API.

### Four-pillar alignment

- **Security Baked In**: Standalone executables use fail-closed main() — if no evaluate function exists, returns 1 (Deny)
- **Assumed Breach**: Shared libraries export the same evaluate ABI as WASM — host audit recording via RuntimePipeline works identically
- **Zero Trust Throughout**: PIC object emission for shared libraries, no external dependencies beyond libc
- **No Single Points of Failure**: Three native output formats (.o, .so, .bin) plus WASM — operators choose per deployment

### Files modified

| File | Purpose | Changes |
|------|---------|---------|
| src/codegen/llvm_gen.rs | compile_main_wrapper(), emit_object_file_pic() | +55 lines |
| src/compiler/mod.rs | compile_to_ir() helper, compile_to_shared_library(), compile_to_executable() | Refactored + ~130 new lines |
| src/main.rs | CLI: native-shared, native-exe targets; updated cmd_build_native dispatch | ~20 lines modified |
| tools/rune.h | Native shared library documentation, dlopen usage example | +25 lines |
| src/codegen/llvm_tests.rs | 16 new tests: main wrapper, shared lib, executable, PIC, backward compat | +250 lines |

### Architecture

**Shared library pipeline:**
1. Source → lex → parse → type check → IR → LLVM codegen
2. emit_object_file_pic() — PIC (Position Independent Code) object via RelocMode::PIC
3. `cc -shared -nostdlib -o output.so temp.o` — system linker produces .so
4. Exports: evaluate(i64, i64, i64, i64) → i32, plus all policy rule functions
5. Loadable via dlopen/ctypes/cgo — no external dependencies beyond libc

**Executable pipeline:**
1. Source → lex → parse → type check → IR → LLVM codegen
2. compile_main_wrapper() — generates main() in LLVM IR calling evaluate(0,0,0,0)
3. emit_object_file() — standard object file
4. `cc -o output.bin temp.o` — system linker produces executable
5. Exit code = policy decision (0=Permit, 1=Deny, 2=Escalate, 3=Quarantine)

**Audit strategy:**
- AuditMark instructions remain nops in native code
- Host applications use the C ABI embedding API (RuntimePipeline) for audit recording
- Same approach as WASM: the policy code returns decisions, the host records the audit trail
- Full native audit runtime deferred to M10 (standard library)

### Test summary

16 new tests (64 total LLVM-gated with `cargo test --features llvm`):

| Area | Tests | What's covered |
|------|-------|----------------|
| Main wrapper | 2 | IR contains main+evaluate call, fail-closed without evaluate |
| Shared library | 5 | file produced, ELF shared object, evaluate symbol, invalid source, risk policy |
| Executable | 6 | file produced, ELF executable, permissions, permit→exit 0, deny→exit 1, invalid source |
| Object file compat | 2 | compile_to_native_file and compile_to_native still work |
| PIC emission | 1 | emit_object_file_pic produces valid ELF |

### Decisions

- **System linker (cc)**: Same approach as clang — shell out to `cc` for final linking. Clear error if cc not found.
- **-nostdlib for shared libraries**: Policy code is self-contained, no C runtime needed.
- **No embedded audit runtime**: Host handles audit via embedding API. Avoids duplicate audit trails.
- **Fail-closed main()**: If no evaluate function, executable returns 1 (Deny). Matches governance constraint.
- **Graceful linker-absent tests**: Tests skip with a message if cc is not available, rather than failing.
