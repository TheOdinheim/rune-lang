# RUNE Architecture Reference — Standard Library Architecture and Post-Quantum Cryptography

**Document ID:** ODIN-ARCH-LANG-2026-001
**DO NOT DELETE THIS FILE**

---

## Core Principle: Annotated by Construction

**Architectural commitment:** every function in the standard library carries effect and capability annotations. The compiler enforces the rules, the library implements the operations, the annotations bridge them.

A function in `rune::net` that sends an HTTP request declares `network` effect. A function in `rune::io` that reads a file declares `io` effect and requires `FileSystem` capability. A function in `rune::policy` that composes compliance rules declares no effects — it is pure. This is not a convention or a best practice. It is enforced by the compiler: un-annotated public functions in published packages are rejected at install time.

### Transitive Effect Enforcement

Effects propagate through call chains via type signatures, not runtime checks.

```rune
// rune::net
fn fetch(url: String) -> Response
    with effects { network }
{ ... }

// Application code — if A calls B calls fetch, BOTH must declare network
fn get_data(url: String) -> Data
    with effects { network }    // REQUIRED — calls fetch transitively
{
    let resp = fetch(url);
    parse(resp)
}

fn handler(req: Request) -> Response
    with effects { network }    // REQUIRED — calls get_data
{
    let data = get_data(req.url);
    respond(data)
}
```

If `handler` omits `with effects { network }`, the compiler rejects it. The effect propagates from `fetch` through `get_data` to `handler`. There is no way to "forget" that a code path touches the network.

## Three-Layer Ecosystem

### Layer 1: Core (Ships with Compiler)

The core is always available. No opt-in required. Minimal footprint.

| Component | Purpose | Effects/Capabilities |
|-----------|---------|---------------------|
| Primitive types | `Int`, `Float`, `Bool`, `String`, `()` | None (pure) |
| `PolicyDecision` | `permit`, `deny`, `escalate`, `quarantine` | None (pure) |
| Capability primitives | `Capability` trait, capability token types | None (pure — capabilities are types, not effects) |
| Effect primitives | `Effect` trait, effect declaration types | None (pure — effect declarations are types) |
| Arena allocator | Request-scoped memory management (see RUNE_06) | None (invisible at Bronze) |
| Audit trail runtime | Record creation, hash chain, cryptographic signing | `audit` effect (auto-inserted by compiler) |
| FlatBuffers runtime | Zero-copy serialization for PolicyRequest/PolicyDecision | None (pure — serialization is deterministic) |

The audit trail runtime uses **ML-DSA signatures** (post-quantum, NIST FIPS 204) and **SHA-3 hash chain** by default. See the PQC section below.

### Layer 2: Standard Library (Ships with Toolchain, Opt-In per Module)

Each standard library module is opt-in. Importing a module makes its effects available but does not automatically grant them — the developer must still declare effects on their functions.

#### `rune::crypto` — Cryptographic Primitives

**PQC-first architecture.** Post-quantum algorithms are the DEFAULT. Classical algorithms require explicit opt-in.

| Function Group | Algorithms | Effect | Notes |
|---------------|-----------|--------|-------|
| Hash functions | SHA-3 (256/384/512), BLAKE3 | `crypto` | Pure computation, but marked `crypto` for audit |
| Digital signatures | ML-DSA (default), EdDSA (classical fallback) | `crypto` | ML-DSA = NIST FIPS 204, lattice-based |
| Key encapsulation | ML-KEM (default), X25519 (classical fallback) | `crypto` | ML-KEM = NIST FIPS 203, lattice-based |
| Symmetric encryption | AES-256-GCM | `crypto` | NIST approved, quantum-resistant at 256-bit |
| Verification | Sigstore chain verification, SLSA predicate validation | `crypto` | Supply chain attestation |

```rune
use rune::crypto::sign;

// Defaults to ML-DSA (post-quantum)
let signature = sign(data, private_key)
    with effects { crypto };

// Classical requires explicit opt-in
use rune::crypto::classical;
let legacy_sig = classical::ed25519_sign(data, private_key)
    with effects { crypto };
```

#### `rune::net` — Networking

| Function Group | Protocols | Effect | Capability |
|---------------|----------|--------|------------|
| HTTP client | HTTP/1.1, HTTP/2, HTTP/3 | `network` | None (effect sufficient) |
| TCP/UDP | Raw sockets | `network` | `Network` capability |
| TLS | TLS 1.3 with PQC key exchange (ML-KEM) | `network` + `crypto` | None |
| DNS | Resolver | `network` | None |

#### `rune::io` — File System Operations

| Function Group | Operations | Effect | Capability |
|---------------|-----------|--------|------------|
| File read | `read`, `read_to_string`, `read_lines` | `io` | `FileSystem` |
| File write | `write`, `append`, `create` | `io` | `FileSystem` |
| Directory | `list_dir`, `create_dir`, `exists` | `io` | `FileSystem` |
| Path | `join`, `parent`, `extension` | None (pure) | None |

```rune
use rune::io;

fn load_config(fs: FileSystem, path: String) -> Config
    with effects { io }
{
    let contents = io::read_to_string(path);
    parse_config(contents)
}
```

The `FileSystem` capability is required as a parameter — no ambient file access. This is Zero Trust enforcement at the library level.

#### `rune::attestation` — Model and Supply Chain Attestation

| Function Group | Operations | Effect |
|---------------|-----------|--------|
| Sigstore | `verify_signature`, `verify_chain`, `check_transparency_log` | `attestation` |
| SLSA | `verify_provenance`, `check_build_level`, `validate_predicate` | `attestation` |
| Hardware | `verify_tpm_quote`, `check_sgx_report`, `validate_trustzone` | `attestation` |

#### `rune::policy` — Compliance Frameworks

**Pure module — no effects.** Policy composition is a compile-time concern.

| Function Group | Frameworks | Effect |
|---------------|-----------|--------|
| EU AI Act | Risk categories, conformity assessment, transparency obligations | None (pure) |
| NIST AI RMF | Govern, Map, Measure, Manage functions | None (pure) |
| CMMC | Levels 1-3, practice requirements, assessment objectives | None (pure) |
| Composition | `compose_policies`, `merge_decisions`, `priority_override` | None (pure) |

```rune
use rune::policy::eu_ai_act;

policy model_compliance {
    rule check_risk_category(model: AttestedModel) {
        match eu_ai_act::classify_risk(model) {
            RiskCategory::Unacceptable => deny,
            RiskCategory::High => escalate,
            RiskCategory::Limited => permit,
            RiskCategory::Minimal => permit,
        }
    }
}
```

#### `rune::audit` — Audit Records and Export

| Function Group | Operations | Effect |
|---------------|-----------|--------|
| Records | `create_record`, `append_to_chain`, `seal_batch` | `audit` |
| Hash chain | `verify_chain_integrity`, `detect_tampering` | `audit` |
| Export (SARIF) | `to_sarif`, Static Analysis Results Interchange Format | `audit` |
| Export (OSCAL) | `to_oscal`, Open Security Controls Assessment Language | `audit` |

### Layer 3: Community Package Registry

Third-party packages published to the RUNE registry are subject to **annotation enforcement at install time**:

- Every public function MUST carry effect and capability annotations
- Un-annotated public functions cause package installation to FAIL
- The package manager verifies annotations before adding the dependency
- This is not a lint or a warning — it is a hard gate

This ensures the transitive effect enforcement property holds across the entire dependency graph, including third-party code.

## Post-Quantum Cryptography (PQC)

### Background: NIST PQC Standards

NIST finalized three post-quantum cryptographic standards in August 2024:

| Standard | Algorithm | Type | FIPS |
|----------|----------|------|------|
| ML-KEM | CRYSTALS-Kyber | Key Encapsulation Mechanism | FIPS 203 |
| ML-DSA | CRYSTALS-Dilithium | Digital Signature Algorithm | FIPS 204 |
| SLH-DSA | SPHINCS+ | Stateless Hash-Based Signature | FIPS 205 |

These are production-ready, standardized algorithms. RUNE adopts them as defaults, not experiments.

### Audit Trail: PQC by Default

The cryptographic audit trail (RUNE_03, Runtime Enforcement Engine) uses PQC:

- **Signatures:** ML-DSA (FIPS 204) by default. Every audit record is signed with a post-quantum signature.
- **Hash chain:** SHA-3 (FIPS 202). Each record's hash links to its predecessor. SHA-3 provides quantum resistance at current security levels.
- **Classical fallback:** EdDSA signatures available as explicit opt-in for interoperability with systems that cannot verify PQC signatures yet. Classical is the fallback, not the default.

```rune
// Audit trail internals (compiler-inserted, not user-written)
audit_record {
    signature: ml_dsa_sign(record_hash, audit_signing_key),  // PQC default
    chain_hash: sha3_256(previous_hash || record_hash),       // quantum-resistant
}
```

### Model Attestation: Hybrid PQC/Classical

Model attestation verification (RUNE_03, Model Attestation Checker) uses a hybrid approach:

| Scenario | Verification | Outcome |
|----------|-------------|---------|
| PQC signature available | Verify PQC signature | Accept if valid |
| Classical + PQC available | Verify BOTH | Accept only if both valid |
| Classical only, PQC unavailable | Verify classical | Accept with warning (degraded) |
| Classical only, PQC available | Reject | PQC required when available |
| No signature | Reject | Unattested models cannot be loaded |

**Defense deployments** (CMMC, IL4/IL5, federal infrastructure) can set a policy flag that rejects classical-only attestations entirely. When PQC is available in the ecosystem, there is no reason to accept weaker guarantees.

```rune
policy attestation_policy {
    rule verify_model(model: AttestedModel, pqc_available: Bool) {
        if model.has_pqc_signature() {
            if verify_pqc(model) { permit } else { deny }
        } else if pqc_available {
            deny  // PQC available but model doesn't use it
        } else {
            if verify_classical(model) { escalate } else { deny }
        }
    }
}
```

### `rune::crypto` PQC Architecture

The `rune::crypto` module is **PQC-first, classical-fallback**:

- `rune::crypto::sign(data, key)` → ML-DSA signature (default)
- `rune::crypto::verify(data, signature, key)` → ML-DSA verification (default)
- `rune::crypto::encapsulate(public_key)` → ML-KEM encapsulation (default)
- `rune::crypto::hash(data)` → SHA-3-256 (default)

Classical algorithms live in `rune::crypto::classical`:

- `rune::crypto::classical::ed25519_sign(data, key)` → EdDSA
- `rune::crypto::classical::x25519_dh(private, public)` → X25519

This naming convention makes the security posture visible in source code. A `grep` for `rune::crypto::classical` identifies every use of non-PQC cryptography in a codebase.

### PQC Performance Characteristics

| Operation | ML-DSA (PQC) | EdDSA (Classical) | Notes |
|-----------|-------------|-------------------|-------|
| Key generation | ~0.15ms | ~0.03ms | One-time cost |
| Sign | ~0.5ms | ~0.05ms | Per audit record |
| Verify | ~0.2ms | ~0.1ms | Per attestation check |
| Signature size | ~2.4 KB | 64 bytes | Storage/bandwidth tradeoff |
| Public key size | ~1.3 KB | 32 bytes | Storage/bandwidth tradeoff |

ML-DSA is ~10x slower than EdDSA for signing but still sub-millisecond. For RUNE's audit trail (one signature per evaluation, not per instruction), this is well within the <1ms policy evaluation target.

## Pillars Served

- **Security Baked In:** Every stdlib function carries effect annotations. Undeclared effects are compile errors. PQC by default ensures audit trails and attestations are quantum-resistant.
- **Assumed Breach:** PQC protects audit trails against "harvest now, decrypt later" attacks. Hybrid attestation verification defends against algorithm compromise.
- **No Single Points of Failure:** Classical fallback ensures interoperability when PQC is unavailable. Transitive effect enforcement means no function in the call chain can silently bypass governance.
- **Zero Trust Throughout:** Capability requirements on io/network functions enforce least privilege. No ambient authority — every resource access requires explicit capability token. Un-annotated packages rejected at install time.
