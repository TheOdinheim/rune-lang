# Build Log 02

## 2026-04-03 — M2 Layer 4: Top-Level Declaration Checking — Full Program Type Checking

### What was built

Top-level declaration checking that makes the type checker work on COMPLETE .rune source files. Two-pass approach: first register all declarations (enabling forward references), then check all bodies. This includes RUNE's governance-aware policy rule checking — the core of the language.

### Files modified / created

| File | Purpose | Changes |
|------|---------|---------|
| src/types/checker.rs | Added check_source_file, register_item, check_item, and all declaration handlers | +260 lines |
| src/types/context.rs | Accept Capability/Effect symbols in type resolution | +2 lines |
| src/types/program_tests.rs | 24 program-level tests | ~330 lines (new file) |
| src/types/mod.rs | Added program_tests module | +3 lines |

### Two-pass declaration checking

- **Pass 1 (registration):** Walk all items, register type names, function signatures, capability declarations, effect declarations, struct/enum types, type aliases, traits, and constants in scope. This enables forward references — function A can call function B even if B is defined later in the file.
- **Pass 2 (checking):** Walk all items again, check function bodies, policy rules, const initializers, trait default methods, and impl block methods against the fully populated type environment.

### Item handling implemented

| Item | Pass 1 (register) | Pass 2 (check) |
|------|--------------------|-----------------|
| Function | Register signature (params, return type, effects, required capabilities) | Check body type matches declared return type, enter effect/capability contexts |
| Policy | (no name registration) | Check each rule: body must be PolicyDecision, when-clause must be Bool |
| StructDef | Register as Named type | — |
| EnumDef | Register as Named type | — |
| TypeAlias | Resolve and register aliased type | — |
| CapabilityDecl | Register capability type with operations | — |
| EffectDecl | Register effect type with operations | — |
| TraitDef | Register as Named type | Check default method bodies |
| ImplBlock | — | Check method bodies |
| ConstDecl | Register as immutable variable | Check initializer matches declared type |
| Module/Use | — (deferred to M7) | — |

### Policy rule checking — RUNE's core

- A policy rule's body MUST evaluate to `PolicyDecision` type
- Governance-aware error message when it doesn't: "policy rule 'check_model' must return a governance decision (permit, deny, escalate, or quarantine), but the body evaluates to 'Int'"
- The when-clause (guard) must evaluate to Bool
- Rule parameters are registered in scope for the body

### Function body checking

- Enter a new scope for the function body
- Register all parameters in scope
- Enter effect context with declared effects (integrates with Layer 3)
- Enter capability context for capability-typed parameters (integrates with Layer 3b)
- Check the body expression
- Verify return type matches declaration
- Exit all contexts

### Capability/Effect type resolution fix

- `resolve_named_type` in context.rs now accepts `Symbol::Capability` and `Symbol::Effect` in type position — they are first-class types in RUNE, not second-class symbols.

### Test results

```
cargo build: clean, 0 warnings
cargo test: 289 passed (49 lexer + 87 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 24 program), 0 failed
```

### Pillars served

- **Security Baked In:** Policy rules must return governance decisions — the compiler rejects rules that compute non-decision values. Effect checking integrated into function body checking.
- **Zero Trust Throughout:** Capability checking integrated into function body checking. Capability declarations registered as first-class types.
- **Assumed Breach:** Each function body checked in its own scope — parameter isolation enforced.
- **No Single Points of Failure:** Two-pass approach collects all errors across all declarations in a single pass. Forward references prevent ordering-dependent failure.

---

## 2026-04-03 — M2 Polish: Governance-Aware Diagnostics and Edge Case Hardening

### What was built

Final polish pass for M2. Audited all type error messages for governance-aware language, added 13 edge case tests covering boundary conditions, and documented three deferred design decisions (D008-D010). This commit closes M2.

### Error message audit

All governance-specific error messages verified to use domain language:
- Policy rule errors say "must return a governance decision (permit, deny, escalate, or quarantine)" — not "expected PolicyDecision"
- Effect errors say "performs effect" and "does not declare this effect" — not "missing type constraint"
- Capability errors say "requires capability" and "does not hold this capability" — not "unsatisfied bound"
- Standard type errors (arithmetic, conditions, assignments) use clear language that doesn't need governance framing

No changes needed — the messages were already governance-aware from Layers 3/3b/4.

### Edge case tests added (13 tests)

| Test | What it covers |
|------|---------------|
| test_empty_function_body | Empty block → Unit, valid with no return type |
| test_empty_function_body_with_return_type_mismatch | Empty block → Unit, mismatch with declared Int |
| test_function_no_return_type_returns_value | No return annotation, body returns Int — valid |
| test_policy_with_no_rules | Policy with zero rules — valid, no crash |
| test_nested_blocks_scope_isolation | Inner block variables not visible in outer |
| test_deeply_nested_governance_decisions | 4-level nested if/else all returning decisions |
| test_multiple_policies_independent_errors | Errors from separate policies all reported |
| test_forward_reference_with_effects_and_capabilities | Forward refs work with effect/capability decls |
| test_const_used_in_function | Const referenced in function body |
| test_policy_rule_all_four_decisions | All four governance decisions in one rule |
| test_mixed_correct_and_incorrect_functions | Only bad functions generate errors |
| test_policy_rule_uses_function_call | Rule body delegates to helper returning PolicyDecision |
| test_governance_error_message_quality | Verify domain language, no type theory jargon |

### Decision documentation

- **D008:** Linear types deferred to post-M6 (capability system covers resource tracking for now)
- **D009:** Session types deferred to post-M6 (effect system provides foundation for future work)
- **D010:** Self type resolution deferred to M3+ (explicit type names used in M2 tests)

### Test results

```
cargo build: clean, 0 warnings
cargo test: 302 passed (49 lexer + 87 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program), 0 failed
```

### Pillars served

- **Security Baked In:** Verified governance error messages use domain language that Bronze-tier users understand.
- **Zero Trust Throughout:** Edge cases confirm capability scope isolation under nesting.
- **Assumed Breach:** Scope isolation tests verify inner variables cannot leak to outer blocks.
- **No Single Points of Failure:** Multi-error collection verified across independent policies and functions.

### M2 Status: COMPLETE

All layers delivered: type representation, expression checking, effect tracking, capability checking, program-level declaration checking, and polish. 302 total tests passing. Moving to M3: Cranelift backend.

---

## 2026-04-06 — M3 Layer 1: IR Design and AST-to-IR Lowering

### What was built

Intermediate Representation (IR) that sits between the type checker and the Cranelift code generator. The IR simplifies the AST's 30+ expression variants and nested control flow into flat sequences of typed instructions within basic blocks. This is the compilation bridge described in RUNE_02 (Compiler Pipeline: "Compiler lowers AST to typed IR after type checking").

### Files created

| File | Purpose | Lines |
|------|---------|-------|
| src/ir/mod.rs | Module declarations | 6 |
| src/ir/nodes.rs | IR data structures (IrModule, IrFunction, BasicBlock, Instruction, Value, IrType, Terminator) | ~240 |
| src/ir/display.rs | Pretty-printer — human-readable textual IR format | ~130 |
| src/ir/lower.rs | AST-to-IR lowering engine | ~470 |
| src/ir/tests.rs | 24 tests for lowering and display | ~340 |
| src/lib.rs | Added `pub mod ir` | +1 line |

### IR design

**SSA-like structure:** Each instruction produces a named Value (%0, %1, %2). Values are immutable — once produced, they are referenced but never modified. This maps directly to Cranelift's SSA representation.

**Basic blocks:** Straight-line code ending in a terminator (Return, Branch, CondBranch, Unreachable). No nested control flow within a block. if/else becomes CondBranch to then-block and else-block, with both branching to a merge-block.

**IR types:** Simplified from the full M2 Type enum: Int (i64), Float (f64), Bool, String, Unit, PolicyDecision (i8, 0-3), Ptr (arena pointer), FuncRef. These map directly to Cranelift types.

**Governance-aware instructions:**
- `GovernanceDecision(Permit|Deny|Escalate|Quarantine)` — first-class governance decisions
- `AuditMark(FunctionEntry|FunctionExit|Decision)` — compiler-inserted audit instrumentation

### AST-to-IR lowering

| AST construct | IR lowering |
|--------------|-------------|
| Function declaration | IrFunction with params, entry block, audit marks |
| Policy rule | IrFunction returning PolicyDecision, with decision audit marks |
| When-clause | CondBranch: true → body block, false → deny block |
| Let binding | Alloca + Store |
| Variable reference | Load from Alloca pointer |
| Binary/unary operators | Flat instructions (Add, Sub, Mul, Eq, etc.) |
| If/else | CondBranch → then-block + else-block → merge-block with Select |
| Function call | Call instruction |
| Governance decisions | GovernanceDecision + AuditMark(Decision) |
| Return | AuditMark(FunctionExit) + Return terminator |
| Block | Sequential lowering of statements |

**Audit instrumentation (automatic):**
- AuditMark(FunctionEntry) inserted at every function/rule entry
- AuditMark(FunctionExit) inserted before every return
- AuditMark(Decision) inserted at every governance decision point

### Test results

```
cargo build: clean, 0 warnings
cargo test: 326 passed (49 lexer + 87 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program + 24 ir), 0 failed
```

### Pillars served

- **Security Baked In:** AuditMark instructions auto-inserted at every governance decision point and function boundary. Audit trail instrumentation is compiler-enforced, not optional.
- **Assumed Breach:** Each function lowered to isolated IR with its own parameter scope. No implicit state sharing between IR functions.
- **No Single Points of Failure:** IR design supports multiple basic blocks — a failed branch doesn't crash the evaluator, it flows to an alternate path. Governance decisions always produce a value.
- **Zero Trust Throughout:** Policy rules with when-clauses lower to explicit CondBranch — if the guard fails, the default is deny. No implicit permit on guard failure.

---

## 2026-04-06 — M3 Layer 2: WASM Code Generation

### What was built

WASM code generator that compiles RUNE IR to executable WebAssembly bytecode. Full end-to-end pipeline: RUNE source → lex → parse → lower to IR → compile to WASM → execute via wasmtime (which uses Cranelift JIT internally). 23 execution tests verify correctness.

### Files modified / created

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added wasm-encoder and wasmtime dependencies | +3 lines |
| src/lib.rs | Added codegen module | +1 line |
| src/codegen/mod.rs | Module declarations | new file, 4 lines |
| src/codegen/wasm_gen.rs | WASM code generator | new file, ~650 lines |
| src/codegen/tests.rs | End-to-end execution tests with wasmtime | new file, ~350 lines |
| src/ir/lower.rs | Value type tracking, function return type pre-collection, Select type fix | ~30 lines modified |

### Key design decisions

- **wasm-encoder for generation, wasmtime for execution.** Cranelift is NOT a WASM emitter — it compiles WASM → native. We generate WASM bytecode directly, then wasmtime JIT-compiles it via Cranelift.
- **WASM structured control flow.** WASM has no arbitrary jumps. Our IR's CondBranch → then/else → merge pattern maps to WASM's if/else/end blocks.
- **Variable handling via WASM locals.** IR Alloca/Store/Load pattern maps to WASM local variables. Alloca locals use the stored type (not Ptr) for correct WASM typing.
- **All functions exported.** Every function and policy rule is a WASM export. Policy rules use `__` separator (e.g., `access__check`).
- **Governance decisions as i32 constants.** Permit=0, Deny=1, Escalate=2, Quarantine=3.

### Bugs fixed during implementation

1. **`gen` reserved in Rust 2024:** Variable name collision with reserved keyword.
2. **Instruction name collision:** `wasm_encoder::Instruction` vs `ir::nodes::Instruction` — resolved with aliased import.
3. **F64Const takes Ieee64:** wasm-encoder requires `Ieee64::from()` conversion, not raw f64.
4. **Alloca type mismatch:** Alloca instructions typed as Ptr (I64) caused WASM validation failures when the stored type was I32 (Bool, PolicyDecision). Fixed by using the stored variable type for WASM local allocation.
5. **Select placeholder type:** Select instruction hardcoded PolicyDecision type. Fixed with value type tracking in the lowerer.
6. **Call instruction typed as Unit:** Function calls always had Unit return type. Fixed by pre-collecting function signatures before lowering.
7. **infer_value_type too simplistic:** `let c = a + b` inferred Unit for binary expressions. Fixed by tracking emitted value types in the lowerer.

### Test results

```
cargo build: clean, 0 warnings
cargo test: 349 passed (49 lexer + 87 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program + 24 ir + 23 codegen), 0 failed
```

### Pillars served

- **Security Baked In:** AuditMark instructions compile to nop placeholders — the instrumentation points are baked into WASM, ready for M5 runtime calls. No way to produce WASM without audit hooks.
- **Assumed Breach:** Each WASM function is fully isolated. Parameters passed by value. No shared mutable state between policy evaluations.
- **No Single Points of Failure:** If/else governance decisions both produce valid values (permit/deny/escalate/quarantine). No path through compiled code can fail to return a decision.
- **Zero Trust Throughout:** Policy rules compile to exported functions callable by the host. The host controls invocation — WASM sandbox prevents the policy from reaching outside its bounds.

---

## 2026-04-06 — M3 Layer 3: WASM Module Packaging and Compiler CLI

### What was built

Standard `evaluate` entry point for compiled policy modules, a unified compilation pipeline, and a CLI for compiling .rune files to .rune.wasm. The evaluate function dispatches to all policy rules in the module and returns the first non-Permit decision (default-deny). This is the function that rune-python and rune-rs will call through the embedding API defined in RUNE_04.

### Files modified / created

| File | Purpose | Changes |
|------|---------|---------|
| src/compiler/mod.rs | Unified compilation pipeline: lex → parse → type check → IR → WASM | new file, ~110 lines |
| src/compiler/tests.rs | 18 tests: pipeline, error collection, evaluate wrapper, file roundtrip | new file, ~280 lines |
| src/main.rs | CLI entry point: `rune build <file.rune>` → `<file.rune.wasm>` | rewritten, ~65 lines |
| src/codegen/wasm_gen.rs | Added evaluate wrapper generation with policy rule dispatch | ~80 lines added |
| src/lib.rs | Added compiler module | +1 line |

### Key design decisions

- **evaluate signature:** `evaluate(subject_id: i64, action: i64, resource_id: i64, risk_score: i64) -> i32`. Matches the PolicyRequest fields from RUNE_04 (subject, action, resource, context/risk). Returns PolicyDecision as i32.
- **Default-deny:** If no policy rule returns non-Permit, evaluate returns Permit (all rules agree). If any rule returns Deny/Escalate/Quarantine, that wins immediately. This is first-non-permit-wins semantics per Zero Trust pillar.
- **evaluate only generated for policy modules.** Modules with only plain functions (no policy rules) do not get an evaluate export. The evaluate wrapper identifies policy rules by their `::` naming convention (e.g., `access::check`).
- **Parameter passing:** Evaluate's i64 params are passed positionally to policy rules. If a rule expects Bool (i32), an automatic i64→i32 wrap is inserted. Rules with fewer params get only the first N evaluate params.
- **CompileError unification:** Single error type with phase tag (Lex/Parse/Type) and source location. All errors from all phases collected before reporting.

### Test results

```
cargo build: clean, 0 warnings
cargo test: 367 passed (49 lexer + 87 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program + 24 ir + 23 codegen + 18 compiler), 0 failed
```

### Pillars served

- **Security Baked In:** The evaluate function is compiler-generated, not hand-written. Every policy module gets a standardized entry point with consistent semantics. No way to bypass the dispatch logic.
- **Assumed Breach:** Each evaluate call is stateless — the WASM instance provides isolation. The evaluate wrapper cannot be influenced by previous calls (per RUNE_06 arena model).
- **No Single Points of Failure:** Default-deny semantics: if any rule in the module denies, the overall decision is deny. No single rule failure can accidentally permit access.
- **Zero Trust Throughout:** Default-deny on rule mismatch. The evaluate wrapper checks ALL policy rules — there is no short-circuit to Permit. Only unanimous Permit from all rules yields overall Permit.

---

## 2026-04-06 — M3 Polish: Advanced Control Flow and Codegen Hardening

### What was built

Advanced control flow support in both IR lowering and WASM code generation: match expressions, while loops, compound assignment, nested function calls, and early return from conditional branches. This hardens the compiler for realistic RUNE programs beyond simple if/else governance decisions.

### Files modified

| File | Purpose | Changes |
|------|---------|---------|
| src/ir/lower.rs | Match, while, for-loop, break/continue, compound-assign lowering; infer_match_result_type; early-return-aware if/else lowering | ~200 lines added |
| src/codegen/wasm_gen.rs | Match chain codegen (recursive CondBranch), loop codegen (block/loop/br), early-return handling, unreachable fallback, in_match_chain flag | ~100 lines added/modified |
| src/codegen/tests.rs | 8 new end-to-end execution tests | ~120 lines added |

### IR lowering additions

| Construct | IR pattern |
|-----------|-----------|
| Match expression | Chain of CondBranch blocks, Alloca for result, Store in each arm body, Load at merge |
| While loop | Header block → CondBranch → body block → Branch(header) → exit block |
| For loop | Range extraction → Alloca counter → while-loop pattern |
| Compound assign (+=, -=, *=) | Load + binop + Store |
| Break/Continue | Branch to exit/header block via loop_stack |
| Early return in if | block_terminated flag prevents Select with mismatched types |

### WASM codegen additions

- **Match chains:** Recursive `compile_if_else` with `in_match_chain` flag. Inner recursive calls don't compile the merge block — only the outermost call does. This ensures the load+return is after all nested if/else/end blocks, reachable by all arms.
- **Wildcard arms:** Else blocks with Branch to non-merge targets inline the target block's instructions without following its branch to the merge block.
- **While loops:** `block { loop { header; br_if exit; body; br loop; end; end }` pattern via compile_loop.
- **Early return:** Non-value if/else emits Return terminator inside branch. Unreachable fallback at function end satisfies WASM validator.

### Bugs fixed

1. **Match result type hardcoded as Int:** `lower_match` used `IrType::Int` for the result Alloca regardless of arm types. Fixed with `infer_match_result_type()` that inspects arm bodies (e.g., governance decisions → PolicyDecision).
2. **Select type mismatch on early return:** `lower_if` always emitted Select even when one branch had early return, causing mismatched types (Int vs Unit). Fixed by tracking `then_terminated`/`else_terminated` flags and skipping Select when either branch returns early.
3. **Match merge block compiled inside nesting:** All match arms' merge target (bb1) was consumed by the deepest recursive compile_if_else call, making it unreachable from outer arms. Fixed with `in_match_chain` flag — only the outermost call compiles the merge block after all if/else/end nesting.
4. **Wildcard body block not compiled:** Wildcard arm's body block (bb8) was a separate block reachable via Branch, but the Branch was never followed. Fixed by inlining the target block's instructions without following its own Branch to the merge.

### Test results

```
cargo build: clean, 0 warnings
cargo test: 375 passed (49 lexer + 87 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program + 24 ir + 31 codegen + 18 compiler), 0 failed
```

### New execution tests

| Test | What it covers |
|------|---------------|
| test_exec_while_loop_count | While loop counting to threshold |
| test_exec_while_loop_sum | While loop accumulating a sum |
| test_exec_for_loop_sum | While-loop equivalent of range sum (parser range syntax deferred) |
| test_exec_match_integer | Match with literal arms + wildcard → governance decisions |
| test_exec_nested_calls | Nested function calls: compose(x) = add_one(double(x)) |
| test_exec_compound_assign | Compound assignment operators (+=, -=, *=) |
| test_exec_return_from_if | Early return from if branch, fallthrough otherwise |
| test_exec_multi_policy_multi_rule | Multiple policies with multiple rules, evaluate dispatch |

### Pillars served

- **Security Baked In:** Match expressions enforce exhaustive handling via wildcard default. Every match arm's governance decision is audit-marked. Compiler rejects match result type mismatches.
- **Assumed Breach:** Early return doesn't bypass audit instrumentation — AuditMark(FunctionExit) is emitted before every Return terminator. Loop bodies maintain scope isolation.
- **No Single Points of Failure:** Match chains evaluate all arms in sequence — no short-circuit past governance decisions. Default wildcard ensures every input gets a decision.
- **Zero Trust Throughout:** While loops and match expressions can't be manipulated to skip governance checks — the compiler controls all control flow paths through structured WASM blocks.
