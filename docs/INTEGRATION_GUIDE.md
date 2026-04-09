# RUNE Integration Guide

How to evaluate RUNE governance policies from Rust, Python, and C.

All integration paths enforce the same guarantee: **fail-closed by default**.
Every error produces Deny, never Permit. Every evaluation is audit-recorded.

## 1. Rust Integration (rune-rs)

### Installation

```toml
[dependencies]
rune-rs = "0.1"
```

### Quick Start

```rust
use rune_rs::{PolicyEngine, Request};

let mut engine = PolicyEngine::from_source(r#"
    policy AccessControl {
        rule check_risk(subject_id: Int, action: Int,
                        resource_id: Int, risk_score: Int) -> PolicyDecision {
            if risk_score > 80 { deny } else { permit }
        }
    }
"#)?;

let decision = engine.evaluate(&Request::new().risk(85));
assert!(decision.outcome.is_deny());
```

### Request Builder

```rust
let req = Request::new()
    .subject(42)
    .action(1)
    .resource(100)
    .risk(85);

// Or use struct defaults:
let req = Request { risk_score: 85, ..Default::default() };
```

### JSON Evaluation

For REST API handlers that receive JSON request bodies:

```rust
let json = r#"{"subject_id": 1, "action": 2, "resource_id": 3, "risk_score": 50}"#;
let decision = engine.evaluate_json(json)?;
```

### Audit Trail

```rust
println!("Records: {}", engine.audit_count());
for entry in engine.audit_trail() {
    println!("[{}] {} — {:?}", entry.id, entry.event_type, entry.decision);
}
```

### Error Handling

`PolicyEngine::from_source()` returns `Result<Self, RuneError>` for load errors.
`evaluate()` always returns a `Decision` — errors produce `Outcome::Deny` with the
error message in `decision.error`.

## 2. Python Integration (rune-python)

### Installation

```bash
pip install rune-python
```

### Quick Start

```python
import rune

engine = rune.load("policy.rune.wasm")
decision = engine.evaluate(subject_id=1, action=2, risk_score=85)

if decision.denied:
    print("Access denied")
```

### Dictionary Evaluation

For REST API handlers that receive JSON request bodies:

```python
request = {"subject_id": 1, "action": 2, "resource_id": 3, "risk_score": 50}
decision = engine.evaluate_dict(request)
```

### From Source

If the `rune-lang` CLI is on PATH, you can compile from source:

```python
engine = rune.PolicyEngine(source="""
    policy AccessControl {
        rule allow_all(subject_id: Int, action: Int,
                       resource_id: Int, risk_score: Int) -> PolicyDecision {
            permit
        }
    }
""")
```

### Error Handling

`PolicyEngine()` raises `RuneError` for setup errors (bad WASM, missing file).
`evaluate()` always returns a `Decision` — runtime errors produce
`Decision("Deny")` with the error in `decision.error`.

## 3. C Integration (direct API)

### Include

```c
#include "rune.h"
```

Link against `librune_lang.so` (Linux), `librune_lang.dylib` (macOS),
or `rune_lang.dll` (Windows).

### Lifecycle

```c
// Load
RuneModule *module = rune_module_load_source(
    source, source_len, key, key_len, name, name_len);
if (module == NULL) { /* handle error */ }

// Evaluate
RunePolicyRequest request = { .risk_score = 85 };
RunePolicyDecision decision;
int32_t rc = rune_evaluate(module, &request, &decision);

// decision.outcome is always valid, even on error (fail-closed)
if (decision.outcome == RUNE_DENY) { /* denied */ }

// Free
rune_module_free(module);  // safe with NULL
```

### Outcome Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `RUNE_PERMIT` | 0 | Access granted |
| `RUNE_DENY` | 1 | Access denied |
| `RUNE_ESCALATE` | 2 | Needs human review |
| `RUNE_QUARANTINE` | 3 | Quarantined |
| `RUNE_ERROR` | -1 | Internal error (decision is DENY) |

## 4. Native Compilation

RUNE can compile policies to native code via the LLVM backend for bare-metal
and appliance deployments where sub-millisecond latency is required.

### Prerequisites

Native targets require LLVM 18 and the `llvm` feature:

```bash
cargo build --features llvm
```

### Targets

| Flag | Output | Extension | Use Case |
|------|--------|-----------|----------|
| `--target wasm` | WASM module | `.rune.wasm` | Default. Sandboxed, portable. |
| `--target native` | Object file | `.rune.o` | Linkable object for custom builds. |
| `--target native-shared` | Shared library | `.rune.so` | dlopen, ctypes, cgo integration. |
| `--target native-exe` | Executable | `.rune.bin` | Standalone policy evaluation. |

### Workflow

```bash
# Compile to executable
rune build --target native-exe policy.rune
./policy.rune.bin    # exit code: 0=Permit, 1=Deny, 2=Escalate, 3=Quarantine

# Compile to shared library
rune build --target native-shared policy.rune
# Load via dlopen — exports: evaluate(i64, i64, i64, i64) -> i32
```

### Loading a Native Shared Library

```c
#include <dlfcn.h>
void *lib = dlopen("policy.rune.so", RTLD_NOW);
int32_t (*evaluate)(int64_t, int64_t, int64_t, int64_t) = dlsym(lib, "evaluate");
int32_t decision = evaluate(user_id, action, resource, risk);
// 0=Permit, 1=Deny, 2=Escalate, 3=Quarantine
dlclose(lib);
```

The shared library has no external dependencies beyond libc. Individual policy
rule functions are also exported (e.g., `access_control__evaluate`).

## 5. Standard Library

RUNE provides a standard library of governance-focused modules accessible via
the `rune_lang::stdlib` namespace. All modules are PQC-first: cryptographic
operations default to post-quantum algorithms.

### Prelude

Import commonly used types and functions:

```rust
use rune_lang::stdlib::prelude::*;
```

### Modules

| Module | Effect | Purpose |
|--------|--------|---------|
| `crypto` | `crypto` | SHA-3 hashing, ML-DSA signing (placeholder), HMAC, KEM |
| `attestation` | `crypto` | Model trust chain verification, PQC signing |
| `policy` | none | Decision combinators, risk assessment, request builders |
| `audit` | `io` (export) | Audit trail views, chain verification, JSON/CSV export |
| `io` | `io` | File read/write/append, directory operations |
| `net` | `network` | TCP connections, DNS resolution, URL parsing |
| `env` | `io` | Environment variables, hostname, working directory |
| `time` | `io` | Unix timestamps, duration formatting |
| `collections` | none | Sort, unique, contains, min/max/sum/avg |

### PQC-First Design

- **Default hash**: SHA3-256 (FIPS 202), not SHA-256
- **Default signature**: ML-DSA-65 (FIPS 204 placeholder), not HMAC-SHA256
- **Default KEM**: ML-KEM-768 (FIPS 203 placeholder)
- Classical algorithms available as explicit fallbacks

## 6. Wire Format

For high-throughput scenarios (>10k evaluations/second), use the wire format
API to avoid struct copying overhead.

### When to Use

- **Struct API**: Default choice. Clean, type-safe, easy to debug.
- **Wire format**: Cross-language IPC, network policy evaluation, latency-critical paths.

### Rust Wire API

```rust
use rune_lang::embedding::safe_api::RuneEngine;
use rune_lang::embedding::wire::{WireRequest, deserialize_request, serialize_decision};

// Typed wire evaluation
let decision = engine.evaluate_wire(&wire_request);

// Zero-copy bytes path
let response_bytes = engine.evaluate_wire_bytes(&request_bytes)?;
```

### C Wire API

```c
uint8_t decision_buf[4096];
size_t written;
int32_t rc = rune_evaluate_wire(
    module, request_bytes, request_len,
    decision_buf, sizeof(decision_buf), &written);
// rc: 0 = success, -1 = error, -2 = buffer too small
```

### Performance

| Operation | Typical Latency |
|-----------|----------------|
| Struct evaluate | 10-50 us |
| Wire serialize | 200-500 ns |
| Wire deserialize | 200-500 ns |
| Wire round-trip | 10-50 us (dominated by WASM evaluation) |
