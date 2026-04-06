# RUNE Architecture Reference — Compiler Pipeline

**Document ID:** ODIN-ARCH-LANG-2026-001
**DO NOT DELETE THIS FILE**

---

## Pipeline Overview

Source code (.rune) → Frontend (lexer, parser, AST) → Four Pillars Type Checker → Typed IR + Audit Instrumentation → Backend (Cranelift or LLVM) → Output (WASM, WASM AOT, or native binary)

## Frontend

Hand-written recursive descent parser (NOT a parser generator). Rust, Go, Swift, and Zig all chose this for the same reason: dramatically better error messages, which directly impacts adoption.

### Components
1. **Lexer:** Single-pass scanner, tokenizes source files
2. **Parser:** Consumes tokens, builds the AST
3. **Name Resolution:** Binds identifiers to declarations across module boundaries
4. **Output:** Fully resolved AST with source location information for diagnostics

## Four Pillars Type System

The core innovation. Five complementary mechanisms enforce the four pillars.

### 3.2.1 Capability Types (Zero Trust)
- Every resource access requires an explicit capability token
- No ambient authority — a function that reads a file must receive `FileRead` capability as a parameter
- Capabilities are unforgeable (created only by runtime or trusted init code)
- Follows principle of least privilege by construction
- Precedent: seL4 verified microkernel (capability-based access control with mathematical proofs)

### 3.2.2 Session Types and Isolation Boundaries (Assumed Breach)
- Every module executes within a typed isolation boundary
- Cross-boundary communication follows session types (proven in Idris 2)
- Communication protocol encoded in type system
- Effect systems restrict what side effects code can perform
- Pure functions provably cannot access network or filesystem

### 3.2.3 Linear Types (No Single Points of Failure)
- Resources consumed exactly once
- Secrets, DB connections, encryption keys cannot be accidentally duplicated or silently dropped
- Refinement types express replication requirements: `Replicated<Config, MinReplicas=3>`
- Compiler rejects deployments that don't meet replication requirements

### 3.2.4 Effect System (Security Baked In)
- Default is safe — every side effect tracked in the type system
- Function type signatures declare exactly which effects they may perform
- Undeclared effects = type error (won't compile)
- Explicit escape hatch (analogous to Rust's `unsafe`) for operations that can't be statically verified
- Every use is flagged, auditable, and grep-able

### 3.2.5 Refinement Types and SMT Verification
- Governance predicates expressed as refinement types
- Verified by SMT solver (Z3 or CVC5) at compile time
- Example: `Model { biasAudit == true, dataRetention <= 30, riskCategory in ["limited", "minimal"] }`
- If metadata doesn't satisfy predicate, code doesn't compile
- AWS Cedar demonstrates this at scale (~75ms avg SMT encoding + solving)

### 3.2.6 Graduated Adoption Model

**This is critical for adoption.** Four progressive levels, inspired by SPARK/Ada:

| Level | Experience | Features Active | Guarantees |
|-------|-----------|----------------|------------|
| **Bronze** | Feels like a config file. Declarative rules, simple conditions, minimal annotations. Readable by anyone who knows Rust/TS/YAML. | Basic ADTs, default-deny, auto-audit, pattern matching, arena-based memory management (fully automatic, request-scoped) | Audited decisions, default-deny, compiled (not interpreted), basic type safety, memory safety via arena allocation — no manual memory management, no use-after-free, no leaks within an evaluation |
| **Silver** | Feels like typed Rust/TS. Developer adds capability requirements and effect declarations. | Bronze + capability types (Zero Trust) + effect tracking (Baked In) + explicit lifetime annotations available (optional) | No resource access without capability, undeclared effects are compile errors, escape hatch available, optional lifetime checking for cross-evaluation data |
| **Gold** | Feels like Rust with rich annotations. Governance predicates as refinement types. SMT works behind the scenes. | Silver + refinement types + linear types + session types + full ownership and borrowing for fine-grained memory control | Compile-time governance verification, single-use resources, enforced communication protocols, full ownership model prevents resource leaks |
| **Platinum** | For specialists: formal verification engineers, defense contractors, DO-178C. | Gold + full formal verification, TLA+ model checking, Lean/Coq proof export | Mathematical proof of correctness for all inputs, independently verifiable compliance certificates, formal verification of memory safety properties |

**Critical constraint:** Bronze-level code MUST be simpler than equivalent Python. If it isn't, the language has failed its most basic adoption test. At Bronze, capabilities are inferred, effects tracked silently, audit instrumentation automatic.

**Error messages adapt to level:** Bronze sees policy/governance concepts. Silver+ sees type-system concepts. A Bronze developer never sees messages about linear types or session types.

## Intermediate Representation (IR)

- Compiler lowers AST to typed IR after type checking
- IR preserves type information from pillar checker
- Insertion point for automatic audit instrumentation
- Compiler inserts logging at every policy decision point, model invocation, and capability exercise WITHOUT developer intervention

## Dual Backend Architecture

| Backend | Use Case | Output | Tradeoff |
|---------|---------|--------|----------|
| **Cranelift** | Dev builds, WASM targets | WASM modules, JIT-compiled native | 10x faster compilation, ~14% slower output than LLVM |
| **LLVM** | Release builds, bare metal | Optimized native binaries | Full optimization suite, slower compilation |

- Cranelift: ~200K lines of Rust (vs LLVM's 20M lines of C++)
- Cranelift is the primary backend for DSL phase
- LLVM added in Phase 2 (Month 30) for optimized native builds
- Mirrors what Rust itself does: Cranelift for dev, LLVM for release
