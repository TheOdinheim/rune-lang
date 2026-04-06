# RUNE Architecture Reference — Targets, Runtime, and AI Primitives

**Document ID:** ODIN-ARCH-LANG-2026-001
**DO NOT DELETE THIS FILE**

---

## Compilation Targets

Same source code deploys to all three targets. This is the hybrid execution requirement.

### WASM + WASI (Cloud and Portable)
- WebAssembly 3.0 (W3C standard Sept 2025): Memory64, GC, exception handling, 128-bit SIMD
- WASI Preview 2: stable networking and HTTP; Preview 3: native async
- Component Model: cross-language composition without serialization overhead
- Capability-based security maps directly to Zero Trust pillar
- Cold start: ~0.5ms (Fermyon Spin) vs 200-500ms (AWS Lambda)
- Wasmer 6.0: 95% of native speed on compute benchmarks

### WASM AOT (Edge and Air-Gapped)
- Cranelift compiles WASM modules ahead-of-time to native code via Wasmtime
- No network dependency, no JIT compiler
- Meets determinism requirements of safety-critical systems
- Deployment path for Lanner Electronics appliances (ICS-P375, LEC-6041)

### Native Binary (Bare Metal and Appliance)
- LLVM backend produces optimized binaries for x86-64 and ARM64
- High-performance inference pipeline integration
- Federal infrastructure deployment (ASTRO 25, P25 systems)
- P25/ASTRO 25 latency: 350-650ms per hop for voice
- FirstNet: 30-50ms LTE user-plane latency
- Policy enforcement adding >10ms becomes operationally impactful
- Native path: policy decisions at hardware speed, zero sandboxing overhead

## Latency Requirements

**Sub-millisecond policy evaluation is the target.**
- AWS Cedar benchmark: ~7µs per individual evaluation
- RUNE targets <1ms per policy decision
- Most governance checks resolved at compile time = ZERO runtime overhead
- Only runtime-dependent predicates (request payloads, model outputs, risk scores) hit the runtime evaluator
- The dual-backend lets operators choose compilation target matching their latency requirements

## Runtime Enforcement Engine

Handles governance predicates that can't be resolved at compile time.

### Policy Evaluator
- Executes compiled policy modules against runtime inputs
- Target: <1ms per decision
- Policies compiled to native code or WASM, NOT interpreted

### Cryptographic Audit Trail
- Every policy decision, model invocation, capability exercise automatically logged
- Compiler inserts audit instrumentation during IR lowering
- Records: policy version, input hash, decision outcome, timestamp, cryptographic signature
- Hash chain links each record to predecessor (tamper detection)
- **Post-quantum by default:** Audit trail uses ML-DSA (NIST FIPS 204) signatures and SHA-3 hash chain for quantum resistance. This is an architectural commitment — PQC is the default, not an option.
- Classical signatures (EdDSA) available as explicit fallback for interoperability with systems that cannot verify PQC signatures yet. Classical is the degraded path, not the primary path.

### Model Attestation Checker
- Verifies model trust chains before execution
- `AttestedModel` type carries cryptographic proof as phantom type parameter
- Type system refuses to load/invoke unattested models
- Verifies: Sigstore-compatible signatures, SLSA provenance predicates, hardware attestation chains
- Failed attestation = rejected before processing any input
- **Hybrid PQC/classical verification:** When both PQC and classical signatures are available, both are verified. PQC is required when available — classical alone is insufficient. Defense deployments (CMMC, IL4/IL5) can reject classical-only attestations entirely.

## AI-Native Language Primitives

First-class types for AI-specific concerns. Part of the core type system, not library abstractions.

### Tensor Types with Provenance Tracking
- Carry shape, dtype, and provenance metadata at the type level
- Example: `Tensor<Shape=[28,28], DType=Float32, Provenance={dataset: "ImageNet", license: "CC-BY", lineage: hash}>`
- Shape verified at compile time (prevents dimension mismatch crashes)
- Provenance tracked through operations: concat merges, slicing inherits, incompatible mixes = type error
- Based on: TensorSafe (Haskell), Jif/FlowCaml (information flow type systems)

### Model Attestation Types
- `AttestedModel<Signer, Policy, Architecture>` — parameterized type carrying trust chain as type info
- Compiler won't allow invocation of unparameterized `Model` type
- Only `AttestedModel` instances with valid type parameters can be called
- Analogous to Rust ownership types but for trust chains

### Policy-as-Types
- Curry-Howard correspondence: policy = proposition, type constraint encodes it, well-typed program = proof of compliance
- Refinement types + SMT for decidable policy fragment
- Complex requirements (EU AI Act risk categories, NIST AI RMF, CMMC levels) = enumerated type hierarchies with obligations

### Secure Enclave Primitives
- `secure_zone` block declares isolation boundary with explicit capability requirements
- Data crossing zone boundaries: typed, auto-serialized, integrity-checked
- Maps to WASM sandboxing (cloud) and hardware TEEs (Intel SGX, ARM TrustZone) on edge
