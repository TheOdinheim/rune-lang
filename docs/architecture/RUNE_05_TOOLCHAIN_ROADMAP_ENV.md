# RUNE Architecture Reference — Toolchain, Roadmap, and Build Environment

**Document ID:** ODIN-ARCH-LANG-2026-001
**DO NOT DELETE THIS FILE**

---

## Toolchain Requirements

| Component | Priority | Implementation | Rationale |
|-----------|---------|---------------|-----------|
| LSP server | Critical (Day 1) | Rust, integrated with RUNE compiler frontend | VS Code + Claude Code integration; diagnostics, completions, go-to-definition |
| Package manager | Critical (Day 1) | Rust CLI tool with registry | Dependency management for policy modules; WASM component distribution |
| Formatter | High (Month 2) | Rust, AST-based | Consistent code style; automated formatting in CI |
| Online playground | High (Month 3) | WASM-compiled compiler in browser | Zero-friction trial; community building |
| Tree-sitter grammar | Medium (Month 4) | Standard tree-sitter grammar file | Syntax highlighting; GitHub language detection |
| Debugger (DAP) | Medium (Month 6) | Debug Adapter Protocol | Step-through debugging of policy evaluation |
| Doc generator | Medium (Month 6) | Source code annotations | API docs for policy modules; type-checked examples |
| Python package (rune-python) | High (Month 9) | PyPI, wrapping wasmtime-py | Zero-friction adoption in AI/ML pipelines |
| Rust crate (rune-rs) | High (Month 9) | crates.io, native + WASM embedding | First-class Rust integration |
| Wire format schema | Critical (Month 9) | FlatBuffers .fbs with generated bindings | Sub-ms serialization for PolicyRequest/PolicyDecision |

## Development Roadmap

### Phase 1: DSL Foundation (Months 1-18)

| Milestone | Target | Deliverable |
|-----------|--------|------------|
| M1: Parser + AST | Month 3 | Hand-written recursive descent parser; full AST with source locations; basic diagnostic reporting |
| M2: Core type system | Month 6 | Capability types, linear types, effect tracking; basic four-pillar enforcement; type error diagnostics |
| M3: Cranelift backend | Month 9 | WASM compilation; sub-ms policy eval; embedding API (WASM + C ABI); FlatBuffers wire format; rune-python + rune-rs |
| M4: Refinement types | Month 12 | Z3/CVC5 SMT integration; governance predicate verification; EU AI Act risk category encoding |
| M5: Runtime engine | Month 15 | Policy evaluator, audit trail, attestation checker; cryptographic hash chain with ML-DSA (post-quantum) signatures and SHA-3 hashing; hybrid PQC/classical attestation verification; WASM runtime; native shared lib (cdylib) |
| M6: Toolchain MVP | Month 18 | LSP server, package manager, formatter, playground; tree-sitter grammar; documentation |

### Phase 2: Generalization (Months 18-42)

| Milestone | Target | Deliverable |
|-----------|--------|------------|
| M7: Module system | Month 24 | First-class modules with explicit interfaces; crate-style deps; edition system |
| M8: C/Rust FFI | Month 27 | FFI to C and Rust; Go, TS/Node.js, Java/Kotlin integration packages |
| M9: LLVM backend | Month 30 | Optimized native compilation; x86-64 and ARM64; bare-metal deployment |
| M10: Standard library | Month 36 | rune::crypto (PQC-first: ML-DSA, ML-KEM, SHA-3), rune::net, rune::io, rune::attestation, rune::policy, rune::audit; all functions carry effect and capability annotations |
| M11: Formal verification | Month 42 | SMT-backed proof mode; TLA+ model checking; optional Lean/Coq proof export |

### Phase 3: Production Maturity (Months 42-72)

| Milestone | Target | Deliverable |
|-----------|--------|------------|
| M12: RUNE 1.0 | Month 48 | Stable spec; backward compat guarantee; edition 2026 frozen |
| M13: Ecosystem growth | Month 54 | Community registry; third-party tooling; RUNE certification |
| M14: Enterprise adoption | Month 60 | Enterprise support; FedRAMP, IL4/IL5; managed cloud service |
| M15: Mainstream | Month 72 | Job postings; university curriculum; industry standard |

## Build Environment

| Component | Specification |
|-----------|--------------|
| Machine | ASUS TUF Gaming Laptop (factory reset, dedicated to RUNE) |
| CPU | AMD Ryzen (8 cores, 16 threads, Zen architecture) |
| Memory | 64 GB DDR5 (54 GB allocated to WSL2, 8 GB Windows host) |
| Storage | ~450 GB NVMe SSD |
| OS | Windows 11 (host) + WSL2 Ubuntu 24.04 LTS (dev environment) |
| Monthly cost | $0 (owned hardware) |
| Toolchain | Rust (rustc + cargo), Claude Code, Cranelift (crate dep), wasmtime |
| WSL2 config | .wslconfig: memory=56GB, swap=8GB, processors=16 |
| Project path | ~/projects/rune |
| Performance | ASUS Armoury Crate → Performance/Turbo mode |

**All code lives on the Linux filesystem** (under /home/), never /mnt/c/. WSL2's ext4 runs at native NVMe speed; cross-filesystem 9P bridge incurs 5-10x I/O overhead.

Claude Code runs natively inside WSL2 on the Linux filesystem with full Rust toolchain access.

A Hetzner AX52 (~$70/month) may be added later as CI/CD build server. Complementary, not replacement.

## Design Principles for DSL-to-General-Purpose Evolution

### 14.1 Algebraic Data Types with Generics
Product types + sum types + parametric polymorphism. Universally useful, avoids over-specializing for policy rules.

### 14.2 First-Class Module System
Modules are first-class values with explicit interfaces (Rust crate model). Policy modules and general libraries use the same mechanism.

### 14.3 Compile-Time Metaprogramming
Zig's `comptime` model: compile-time and runtime code use same syntax. Domain-specific extensions are compile-time computations, not language modifications. Critical for scaling to all 16 PPD-21 sectors.

### 14.4 Clean C and Rust FFI
FFI to C provides access to existing ecosystems day one. PyTorch C++, ONNX Runtime, OpenSSL, libsodium, system APIs all accessible.

### 14.5 Edition System for Backward Compatibility
Rust's edition model (2015, 2018, 2021, 2024). Different editions coexist in same project. Policies written in edition 2026 compile correctly in 2028, 2030, and beyond. This is a binding architectural commitment.

## Formal Verification Strategy

| Layer | Approach | Precedent | Phase |
|-------|---------|-----------|-------|
| Policy evaluation engine | SMT proof that decisions match spec for all inputs | AWS Cedar (Lean) | Phase 1 |
| Sandboxing/isolation | Proof of memory isolation and capability confinement | seL4 (Isabelle/HOL) | Phase 2 |
| Cryptographic protocols | Memory safety, functional correctness, timing resistance | F*/HACL* (Firefox, Linux, Wireguard) | Phase 2 |
| Distributed properties | Deadlock freedom, consensus, Byzantine fault tolerance | AWS TLA+ (DynamoDB, S3, EBS) | Phase 3 |

## Risk Assessment

| Risk | Severity | Likelihood | Mitigation |
|------|---------|-----------|-----------|
| Developer adoption fails | Critical | Medium | Kill app strategy; open source; playground; docs; AEGIS proof point |
| Type system too complex | High | Medium | Graduated adoption (Section 3.2.6): Bronze feels like config, Gold adds SMT |
| LLVM integration delays | Medium | Low | Cranelift-first, LLVM not needed until Month 30 |
| Competitor launches similar DSL | Medium | Low | First-mover; four-pillar type system creates deep differentiation |
| Resource constraints (solo founder) | High | High | Claude Code accelerates 3-5x; owned hardware = $0/month |
| SMT solver performance at scale | Medium | Medium | Incremental type checking; cached verification results |
| PQC algorithm maturity and performance | Medium | Low | NIST standards finalized; rune::crypto defaults to PQC with classical fallback; hybrid verification for attestation |
