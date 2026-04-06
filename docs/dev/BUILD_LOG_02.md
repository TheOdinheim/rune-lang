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
