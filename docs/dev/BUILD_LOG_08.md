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
