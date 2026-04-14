# RUNE

**Governance-first programming language for AI security and critical infrastructure protection.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 2024 Edition](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Tests: 3,000+](https://img.shields.io/badge/Tests-3%2C000%2B-green.svg)](#current-status)

> M10 Complete | 3,000+ Tests | 21 Governance Libraries | Rust 2024 Edition

---

## The Problem

AI governance today is enforced through documentation, hope, and after-the-fact auditing. Policy-as-code tools exist (OPA/Rego, AWS Cedar, NVIDIA Colang), but none operate at the language level. Libraries can be bypassed. Configuration can be ignored. Compliance frameworks exist on paper while production systems run ungoverned.

The EU AI Act high-risk provisions take effect August 2, 2026. Colorado's AI Act follows June 30, 2026. Organizations need governance that is structurally impossible to bypass, not merely inconvenient to skip.

## The Solution

RUNE encodes governance as a type system. Where Rust's borrow checker prevents memory safety violations before code runs, RUNE's pillar checker prevents governance and security violations before code deploys. Policy compliance becomes a type-checking problem: well-typed programs are provably compliant.

### The Four Foundational Pillars

Every architectural decision serves at least one pillar. These are non-negotiable compiler-enforced constraints.

| Pillar | Enforcement Mechanism | Guarantee |
|--------|----------------------|-----------|
| **Security / Privacy / Governance Baked In** | Effect system + default-deny semantics | Unsafe operations require explicit escape hatch; all side effects tracked and auditable |
| **Assumed Breach** | Session types + compartmentalization boundaries | Every module runs in an isolation boundary; cross-boundary communication follows typed protocols |
| **No Single Points of Failure** | Linear types + redundancy predicates | Critical resources consumed exactly once; replication requirements expressed as type constraints |
| **Zero Trust Throughout** | Capability-based types + information flow labels | No implicit authority; every resource access requires explicit, unforgeable capability token |

## Architecture Overview

RUNE compiles to three targets through a dual-backend architecture:

- **Cranelift** for fast development builds and WebAssembly
- **LLVM** for optimized native binaries
- **WebAssembly** for sandboxed, portable deployment

The same source code deploys to cloud-scale inference pipelines, air-gapped edge appliances, and federal communications infrastructure without modification.

The compiler pipeline flows through: **Source** -> **Lexer** -> **Parser** -> **AST** -> **HIR** -> **MIR** -> **LIR** -> **Backend (Cranelift/LLVM)** -> **Target (native/WASM)**

The standard library provides cryptographic primitives (SHA3-256, HMAC-SHA3-256, HKDF, Ed25519, X25519, AES-256-GCM, ChaCha20-Poly1305), encoding (base64, hex), and a structured error model with full audit trails.

## Governance Library Ecosystem

RUNE ships with 21 governance-focused crate libraries organized in five tiers of increasing abstraction. Each crate enforces one dimension of the four-pillar model.

### Tier 1: Language Foundation

| Crate | Purpose |
|-------|---------|
| `rune-lang` | Core compiler, parser, AST, type system, standard library, cryptographic primitives |

### Tier 2: Security Primitives

| Crate | Purpose |
|-------|---------|
| `rune-permissions` | RBAC/ABAC, permission algebra, role hierarchy, access decisions |
| `rune-security` | Threat modeling, security contexts, classification, vulnerability tracking |
| `rune-identity` | Authentication, identity lifecycle, MFA, session management, credential vaulting |
| `rune-secrets` | Secret vault, ChaCha20-Poly1305 envelope encryption, Shamir sharing, key rotation, zeroization |

### Tier 3: Governance Core

| Crate | Purpose |
|-------|---------|
| `rune-privacy` | Consent management, data minimization, purpose limitation, GDPR/CCPA enforcement |
| `rune-truth` | Merkle audit logs, tamper-evident records, cryptographic verification |
| `rune-explainability` | Decision explanations, factor analysis, audience-targeted explanations |
| `rune-document` | Document governance, classification, access control, retention policies |
| `rune-provenance` | Data lineage, transformation tracking, origin verification |

### Tier 4: Active Defense

| Crate | Purpose |
|-------|---------|
| `rune-detection` | Statistical anomaly detection, regex pattern matching, behavioral baselines, alert correlation, threat scoring |
| `rune-shield` | AI inference immune system, injection detection, token classification, content fingerprinting, exfiltration analysis |
| `rune-monitoring` | System health, SLA tracking, capacity planning, resource monitoring |
| `rune-safety` | Safety constraints, IEC 61508 / DO-178C / ISO 26262 compliance, hazard analysis, failsafe registry |

### Tier 5: Orchestration

| Crate | Purpose |
|-------|---------|
| `rune-policy-ext` | Policy lifecycle management, versioning, conflict detection, simulation, framework binding |
| `rune-audit-ext` | Unified audit store, cross-crate correlation, query engine, export (JSON Lines/CEF/CSV), retention |
| `rune-framework` | Governance pipeline orchestration, component registry, workflow templates, health assessment |
| `rune-agents` | Agent governance (GUNGNIR layer), autonomy levels, tool permissions, delegation, multi-agent coordination |
| `rune-networking-ext` | Network governance, TLS enforcement, traffic classification, segmentation, DNS policy, software firewall |
| `rune-web` | API gateway governance, rate limiting, request/response validation, HMAC signing, session governance |

### Interoperability

| Crate | Purpose |
|-------|---------|
| `rune-rs` | Rust FFI bridge for embedding RUNE governance in Rust applications |
| `rune-python` | Python FFI bridge for embedding RUNE governance in Python applications |

## Product Ecosystem

RUNE is the 5th standalone product in the Odin's LLC portfolio:

| Product | Function |
|---------|----------|
| **AEGIS** | AI inference layer immune system. Detects/neutralizes prompt injection, data exfiltration, adversarial attacks. |
| **GUNGNIR** | Governed autonomous intelligence agent. Passive OSINT collection across all 16 PPD-21 critical infrastructure sectors. |
| **MIMIR** | Multi-jurisdictional regulatory intelligence engine. 200+ frameworks, 40+ jurisdictions. |
| **HEIMDALL** | OT/ICS immune system. Modbus, DNP3, OPC UA, IEC 61850 protocol governance. |
| **RUNE** | This language. Governance-first programming language for AI security and critical infrastructure. |

RUNE is independent. It is not a subsystem or integration layer for the other products. It has its own compiler, toolchain, ecosystem, and adoption trajectory.

## Building From Source

### Prerequisites

- Rust 1.85+ (2024 Edition)
- Cargo

### Build

```bash
git clone https://github.com/TheOdinheim/rune-lang.git
cd rune-lang
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Individual crate testing

```bash
cargo test -p rune-detection
cargo test -p rune-shield
cargo test -p rune-secrets
```

## Current Status

**Milestone 10 Complete.**

- 3,000+ tests across 21 governance libraries, zero failures
- Rust 2024 Edition throughout
- Layer 1 (foundational API) complete for all crates
- Layer 2 (production-grade internals) complete for `rune-secrets`, `rune-shield`, `rune-detection`
- Compiler pipeline: Lexer, Parser, AST complete; HIR/MIR/LIR in progress
- Standard library: SHA3-256, HMAC-SHA3-256, HKDF, Ed25519, X25519, AES-256-GCM, ChaCha20-Poly1305, base64, hex

### What "governance-first" means in practice

- Every crate emits structured audit events for every security-relevant operation
- Every decision includes an explanation chain traceable to policy
- Every secret is zeroized on drop
- Every network connection is classified by trust level before data flows
- Every agent action is bounded by autonomy envelopes
- Every detection signal is scored, correlated, and attributed

## License

MIT

---

Built by [Odin's LLC](https://github.com/TheOdinheim) | [RUNE Language](https://github.com/TheOdinheim/rune-lang)
