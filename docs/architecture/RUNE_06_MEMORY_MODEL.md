# RUNE Architecture Reference — Memory Management Model

**Document ID:** ODIN-ARCH-LANG-2026-001
**DO NOT DELETE THIS FILE**

---

## Core Principle: Arena-Based Allocation

RUNE uses **arena-based (region-based) allocation** as its default memory management model. This is not garbage collection, not reference counting, and not a mandatory borrow checker. It is a memory model purpose-built for policy evaluation workloads.

Policy evaluations are **request-scoped**: a PolicyRequest arrives, the evaluator processes it, a PolicyDecision is produced, and all intermediate data is freed at once in a single O(1) operation. No GC pauses, no reference counting overhead, no fragmentation. This maps directly to the evaluation lifecycle described in RUNE_04 (Embedding API Contract).

### Why Arena Allocation

| Property | Arena | GC (Go/Java) | RC (Swift/Rust Arc) | Borrow Checker (Rust) |
|----------|-------|---------------|---------------------|----------------------|
| Allocation cost | O(1) pointer bump | O(1) amortized | O(1) + atomic incr | O(1) |
| Deallocation cost | O(1) arena reset | Unpredictable pause | Atomic decrement | Compile-time (zero) |
| Fragmentation | None (linear bump) | GC compaction | Yes | N/A |
| Latency predictability | Excellent | Poor (GC pauses) | Good | Excellent |
| Developer burden | None (Bronze) | None | Low | High |
| Fit for request-scoped work | Perfect | Overkill | Overkill | Overkill |

Arena allocation is the optimal strategy for RUNE's primary workload pattern: allocate many small objects during evaluation, use them, then discard everything at once.

### How Arena Allocation Works

```
Evaluation starts:
  Arena pointer = base address
  
During evaluation:
  alloc(N bytes) = current pointer; pointer += N   // O(1), no free-list
  
Evaluation ends:
  Arena pointer = base address   // O(1), all memory "freed"
```

Every allocation is a pointer bump. Every deallocation is a pointer reset. There is no per-object free, no free list, no compaction, and no GC roots to scan.

## Execution Paths

### WASM Path: Instance-as-Arena

Each policy evaluation gets a **fresh WASM instance**. The WASM linear memory IS the arena.

```
PolicyRequest arrives
  → Spin up fresh WASM instance (cold start ~0.5ms, warm pool ~0.05ms)
  → WASM linear memory = arena for this evaluation
  → Execute compiled policy module
  → Extract PolicyDecision + AuditRecord from WASM memory
  → Discard WASM instance = free ALL memory
```

This provides **defense-in-depth**: the compiler manages arena allocation statically (no use-after-free possible within an evaluation), and the WASM runtime provides dynamic bounds checking (no buffer overflows possible, even in the presence of compiler bugs). Two independent safety layers.

**WASM memory safety guarantees:**
- Linear memory is bounds-checked on every access (hardware-assisted on x86-64 via guard pages)
- No pointer arithmetic that escapes the linear memory region
- Stack and heap are separate; stack overflows trapped, not exploitable
- Instance isolation: one evaluation cannot read/write another's memory

### Native Path: Thread-Local Arena

For native binary deployment (LLVM backend), each evaluation thread owns a **thread-local arena**.

```
Thread starts:
  Arena = mmap(ARENA_SIZE)   // e.g., 4MB, one-time cost
  
Per evaluation:
  Arena pointer = base        // reset
  ... allocations via pointer bump ...
  → Extract PolicyDecision + AuditRecord
  Arena pointer = base        // reset, ready for next evaluation
  
Thread exits:
  munmap(arena)               // one-time cleanup
```

**No cross-thread sharing of arena memory.** This eliminates data races on the allocation path without requiring locks or atomics. Each thread's arena is completely independent.

**Native memory safety guarantees:**
- Compiler-enforced arena scoping: references into the arena cannot escape the evaluation boundary
- Type system tracks arena-scoped vs persistent values (see Cross-Evaluation Persistence below)
- Debug builds include canary values at allocation boundaries for corruption detection

## Cross-Evaluation Persistence

Not all data is request-scoped. Some state must persist across evaluations:

| Data | Lifetime | Storage |
|------|----------|---------|
| Compiled policy modules | Application lifetime | Static (loaded once, read-only) |
| Cached configuration | Until reload | Reference-counted (explicit) |
| Audit state (hash chain head) | Application lifetime | Reference-counted (explicit) |
| Evaluation inputs/outputs | Single evaluation | Arena-scoped |
| Intermediate expressions | Single evaluation | Arena-scoped |
| Pattern match temporaries | Single evaluation | Arena-scoped |

### Type System Enforcement

The type system tracks the distinction between arena-scoped values and persistent values. An arena-scoped value **cannot** be stored in a persistent structure without explicit conversion.

```
// This is a type error — arena-scoped value escaping to persistent storage
let config: Persistent<Config> = arena_value;  // COMPILE ERROR

// Must explicitly copy/convert
let config: Persistent<Config> = arena_value.to_persistent();  // OK
```

This prevents the most common arena bug: dangling references to freed arena memory. The compiler catches it, not the developer.

### Persistent Storage Mechanism

Cross-evaluation data uses **explicit reference counting** (not arena allocation):

- `Rc<T>` for single-threaded contexts (WASM, single-threaded native)
- `Arc<T>` for multi-threaded native contexts
- Reference counting is explicit in the type system — developers opt in, not out
- No cycles possible in persistent policy data (acyclic by construction: policy modules are immutable, config is read-only, audit chain is append-only)

## Memory Management at Each Adoption Level

### Bronze: Fully Automatic

The developer writes policy rules. Memory management is invisible.

```rune
policy access_control {
    rule check_request(user: User, resource: Resource) {
        if user.role == "admin" { permit }
        else if resource.classification == "public" { permit }
        else { deny }
    }
}
```

No allocations visible in source code. No `new`, no `free`, no `drop`, no lifetime annotations. The compiler allocates everything in the evaluation arena and resets it when the evaluation completes. Memory safety is guaranteed by construction: all arena memory is freed together, so dangling references within an evaluation are impossible (everything is live until the arena resets, at which point nothing is live).

**Bronze guarantee:** No use-after-free, no double-free, no memory leaks within an evaluation. No developer action required.

### Silver: Optional Lifetime Annotations

Silver developers can annotate lifetimes for cross-evaluation data:

```rune
// Silver: explicit lifetime for config that persists across evaluations
fn load_config<'app>(path: String) -> &'app Config
    with effects { io }
{
    // ...
}
```

Lifetime annotations are **optional** — the compiler infers arena scope by default. Annotations are only needed when data must outlive a single evaluation.

**Silver guarantee:** Optional lifetime checking for cross-evaluation data. Arena-scoped values cannot accidentally escape to persistent storage.

### Gold: Full Ownership and Borrowing

Gold adds Rust-style ownership and borrowing for fine-grained memory control:

```rune
// Gold: linear types ensure exactly-once consumption
fn transfer_key(key: Linear<EncryptionKey>) -> EncryptedPayload {
    let result = encrypt(payload, &key);
    consume(key);  // key is gone — cannot be used again
    result
}
```

Ownership tracking prevents resource leaks: encryption keys, database connections, and capability tokens are consumed exactly once.

**Gold guarantee:** Full ownership model prevents resource leaks. Linear types enforce single-use semantics for sensitive resources.

### Platinum: Formal Verification

Platinum adds formal verification of memory safety properties:

```rune
// Platinum: verified memory bounds
#[verify(no_overflow, arena_bounded)]
fn process_batch(items: &[PolicyRequest]) -> Vec<PolicyDecision> {
    // Compiler proves: total allocation fits in arena
    // Compiler proves: no index-out-of-bounds in iteration
    items.map(|req| evaluate(req))
}
```

**Platinum guarantee:** Mathematical proof that memory access is safe for all inputs. SMT solver verifies arena bounds, absence of overflow, and correctness of lifetime annotations.

## Memory Budgets and Limits

### Per-Evaluation Limits

| Parameter | WASM Path | Native Path |
|-----------|-----------|-------------|
| Default arena size | WASM linear memory max (configurable per module) | 4 MB (configurable) |
| Max allocation per eval | Bounded by arena size | Bounded by arena size |
| Overflow behavior | WASM trap (OOM) | Structured error → DENY |

Arena overflow during evaluation produces a structured error with DENY semantics — fail closed, consistent with RUNE_04's fail-closed behavior.

### Defense Against Resource Exhaustion

- **WASM path:** WASM runtime enforces memory limits per instance. A malicious or buggy policy cannot consume unbounded memory.
- **Native path:** Arena size is fixed at thread startup. Allocation beyond the arena fails deterministically.
- **Evaluation timeout:** Combined with memory limits, prevents both time and space exhaustion.

## Pillars Served

- **Security Baked In:** Arena allocation eliminates entire classes of memory bugs (use-after-free, double-free, memory leaks) without developer effort. Audit trail persists via explicit reference-counted storage — cannot be accidentally freed.
- **Assumed Breach:** Each evaluation gets isolated memory (fresh WASM instance or thread-local arena). One compromised evaluation cannot read another's memory. Memory corruption in one evaluation is contained.
- **No Single Points of Failure:** Arena overflow produces structured DENY, not a crash. No GC pauses that could cause cascading timeouts. Deterministic latency preserves system availability.
- **Zero Trust Throughout:** Arena-scoped values cannot escape to persistent storage without explicit, type-checked conversion. No implicit sharing between evaluations. WASM bounds checking provides runtime enforcement independent of compiler correctness.
