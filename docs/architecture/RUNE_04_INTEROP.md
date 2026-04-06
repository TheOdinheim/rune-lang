# RUNE Architecture Reference — Language Interoperability

**Document ID:** ODIN-ARCH-LANG-2026-001
**DO NOT DELETE THIS FILE**

---

## Core Principle

RUNE does NOT replace existing languages. It composes with them. RUNE slots into existing AI deployment stacks (Python, Rust, Go, etc.) as the governance enforcement layer that every other component calls into. Like SQL for databases — you use it for one specific domain and call it from whatever language runs the rest.

## Embedding API

How host languages load and invoke compiled RUNE policy modules. Two modes:

### WASM Embedding (Cloud/Portable)
- Compiled .rune.wasm modules export standard WASM functions
- Host loads module through WASM runtime (wasmtime, wasmer, wazero)
- Calls exported `evaluate` function with serialized PolicyRequest
- Receives typed PolicyDecision (PERMIT, DENY, ESCALATE, QUARANTINE) + AuditRecord
- Component Model enables zero-serialization-overhead when both sides are WASM components
- Each evaluation gets fresh WASM instance (capability-based isolation = Zero Trust)

### Native Embedding (Bare Metal/Appliance)
- LLVM backend compiles to shared libraries (.so, .dylib, .dll) with C-compatible ABI
- Three exported functions:
  - `rune_module_load` → initializes module, returns opaque context handle
  - `rune_evaluate` → takes context + serialized PolicyRequest → returns PolicyDecision + AuditRecord
  - `rune_module_free` → releases context
- Any language with C FFI can call RUNE (Rust, Go, Python, Java, C#, Ruby, Swift, Zig)
- Same pattern as SQLite and Lua

### Embedding API Contract
Host constructs a **PolicyRequest** containing:
- **Subject:** identity, roles, clearance level, authentication method
- **Action:** action type, target resource, requested permissions
- **Resource:** resource type, classification level, metadata
- **Context:** timestamp, source IP, risk score, session ID, custom key-value pairs
- **Attestation:** signer identity, signature bytes, SLSA provenance predicate, architecture hash

RUNE returns a **PolicyDecision** containing:
- **Outcome:** PERMIT, DENY, ESCALATE, or QUARANTINE
- **Matched rule:** identifier of the policy rule that produced the decision
- **Evaluation duration:** microseconds
- **Explanation:** human-readable reasoning
- **AuditRecord:** signed, linked to hash chain

The host NEVER constructs policy logic. It passes data in, gets a decision out. Governance logic lives entirely inside the compiled RUNE module.

## Language Integration Packages

### Python (rune-python) — PyPI — HIGH PRIORITY
- Wraps WASM embedding via wasmtime-py (portable) or native shared lib via cffi (performance)
- API: `rune.load('policy.rune.wasm')` → Policy object, `policy.evaluate(request)` → Decision, `decision.permitted` → bool
- Type hints for IDE autocompletion
- Handles serialization transparently (devs work with dicts/dataclasses, never raw bytes)
- Error messages reference Python types and stack frames, not RUNE internals

### Rust (rune-rs) — crates.io — HIGH PRIORITY
- Zero-cost abstractions over embedding API with Rust-native types
- PolicyRequest/PolicyDecision as Rust structs with serde support
- Both WASM embedding (wasmtime dependency) and native embedding (direct linking)
- Async support via tokio integration

### Additional Targets (Phase 2)
- Go, TypeScript/Node.js, Java/Kotlin
- C ABI covers all of these immediately through their FFI mechanisms (cgo, N-API, JNI)

## Wire Format

### FlatBuffers (Primary Serialization)
- Zero-copy deserialization: receiver reads fields directly from buffer without parsing/allocating
- Typical PolicyRequest (10-15 fields): 200-500 nanoseconds serialization
- Schema in .fbs file ships with toolchain, generates bindings for all languages automatically
- Schema evolution: new fields added without recompiling existing modules

### Performance Comparison
| Format | Serialization Time | Allocation Required |
|--------|-------------------|-------------------|
| FlatBuffers | 200-500ns | No (zero-copy) |
| Protocol Buffers | 1-5µs | Yes |
| JSON | 5-20µs | Yes |

## Four-Pillar Enforcement at the Language Boundary

**The interop layer is the most critical governance enforcement point.**

### Inbound Governance (Zero Trust at Ingress)
Every PolicyRequest from a host is untrusted. Three validation layers execute INSIDE the RUNE module (not in host code, because host is untrusted):
1. **Structural:** FlatBuffers schema conformance, required fields, type matching
2. **Semantic:** Cryptographic signature validity, capability token integrity, value range checks, clock skew
3. **Provenance:** Sigstore chain verification, SLSA predicates, hardware attestation

### Outbound Governance (Effect System at FFI)
Every FFI call to C/Rust libraries crosses from governed to ungoverned code:
- FFI calls MUST be declared as `ffi` effect in function type signature
- Undeclared FFI call = compile-time type error
- Wrapped in explicit escape hatch (like Rust's `unsafe`)
- Compiler auto-inserts audit instrumentation around every FFI crossing
- Instrumentation is mandatory and cannot be disabled

### Audit Trail Continuity
- Hash chain spans the language boundary without gaps
- Inbound: captures full PolicyRequest as received (not as host claims)
- Outbound FFI: generates sub-records within parent evaluation record
- If audit subsystem unavailable: fail closed (DENY inbound, block outbound FFI)

### Fail-Closed Behavior
Every failure mode at the boundary defaults to DENY:
- FlatBuffers deserialization fails → DENY
- Required field missing → DENY
- Attestation chain unverifiable → QUARANTINE
- FFI timeout/exception/type mismatch → treat as unavailable, default-deny
- RUNE runtime error → structured error with DENY semantics
- No code path returns implicit PERMIT due to internal failure

### Compartmentalization (Assumed Breach at FFI)
- Foreign code treated as potential compromise vector
- WASM path: sandbox provides capability-based isolation
- Native path: capabilities not forwarded across FFI boundary
- FFI return values are UNTRUSTED — must pass through type system before governance use
- Compiler tracks which decisions depend on FFI return values for retroactive review
