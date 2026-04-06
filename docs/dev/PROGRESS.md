# RUNE Development Progress

## Current Milestone

**M3: Cranelift backend** — Target: Month 9

IR design, AST-to-IR lowering, WASM code generation, module packaging, and compiler CLI complete. RUNE programs compile to .rune.wasm modules with a standard `evaluate` entry point.

### M1 Deliverables

| Deliverable | Status |
|-------------|--------|
| Lexer / tokenizer | **Done** (49 tests passing) |
| Token types for RUNE syntax | **Done** (all keyword, symbol, literal categories) |
| Recursive descent parser | **Done** (Pratt parsing, all 3 phases, error recovery) |
| AST node definitions | **Done** (all governance, type, expression, pattern nodes) |
| Source location tracking (spans) | **Done** (Span struct with file_id, offsets, line, column) |
| Basic diagnostic / error reporting | **Done** (LexError + ParseError with clear messages + spans) |
| Unit tests for lexer | **Done** (49 tests: keywords, literals, operators, errors, integration) |
| Unit tests for parser | **Done** (87 tests: all constructs, precedence, patterns, errors, integration) |
| Integration tests (parse full .rune files) | **Done** (realistic multi-construct RUNE program test) |

### Milestones Overview

| Milestone | Target | Status |
|-----------|--------|--------|
| M1: Parser + AST | Month 3 | **Complete** |
| M2: Core type system | Month 6 | **Complete** |
| M3: Cranelift backend | Month 9 | **Complete** — IR, WASM codegen, module packaging, CLI, advanced control flow |
| M4: Refinement types | Month 12 | Not started |
| M5: Runtime engine | Month 15 | Not started |
| M6: Toolchain MVP | Month 18 | Not started |

## What's Done

- Project scaffold created (Cargo workspace, directory structure)
- Architecture reference documents written (docs/architecture/)
- Build environment standing (Rust toolchain on WSL2 Ubuntu 24.04)
- Development documentation structure initialized
- **Lexer fully implemented** — single-pass scanner with 49 tests passing
  - All RUNE keywords (policy, capability, effect, governance, control flow, modules)
  - All operators and delimiters
  - Integer literals (decimal, hex, octal, binary with _ separators)
  - Float literals (decimal point, exponent notation)
  - String literals with escape sequences
  - Line and nested block comments
  - Full Span tracking (file_id, byte offsets, line, column)
  - Clear error messages for all invalid input paths

- **AST node definitions complete** — full type hierarchy for RUNE syntax
  - Governance: PolicyDecl, RuleDef, CapabilityDecl, EffectDecl
  - Types: StructDef, EnumDef, TypeAlias, ImplBlock, TraitDef, generics
  - Functions: FnDecl, FnSignature, Param, effect annotations
  - Expressions: literals, binary/unary ops, calls, field access, control flow
  - Governance expressions: attest, audit, secure_zone, unsafe_ffi, permit/deny/escalate/quarantine
  - Patterns: wildcard, binding, literal, constructor, struct, tuple
  - Modules: ModuleDecl, UseDecl, Path

- **Recursive descent parser complete** — all three phases implemented
  - Phase 1: governance core (policy, rules, functions, let, expressions, if/else, return)
  - Phase 2: type system (struct, enum, type alias, impl, trait, match, patterns, generics)
  - Phase 3: governance-specific (capability, effect, attest, audit, secure_zone, unsafe_ffi, perform, handle, modules, use, const)
  - Pratt parsing with correct operator precedence (11 levels, 17 binary ops)
  - Error recovery: synchronize on `;` / `}` and continue parsing

- **M2 Layer 1: Type representation and symbol table** (33 tests)
  - Type enum with primitives, composites, inference vars, error type
  - Governance-specific types: Capability, AttestedModel, PolicyDecision, Effect
  - TypeId handles + TypeTable arena for interning
  - ScopeStack with lexical scoping (define, lookup, shadow, enter/exit)
  - TypeContext: builtins, type interning, AST TypeExpr → TypeId resolution
  - Fresh type variable generation for inference

- **M2 Layer 2 Pass 1: Type checker for expressions and statements** (55 tests)
  - TypeChecker walks AST, assigns TypeId to every expression
  - All expression kinds checked: literals, binary/unary ops, calls, if/else, match, blocks, loops
  - Governance decisions → PolicyDecision; attest → Bool; audit/secure_zone/unsafe_ffi → block type
  - Let bindings with type annotation checking, scope registration
  - Error type propagation prevents cascading diagnostics

- **M2 Layer 3: Effect tracking — first pillar enforcement** (23 tests)
  - Effect context stack with EffectFrame tracking allowed effects per scope
  - Function call effect checking: callee effects must be subset of caller's declared effects
  - Pure function guarantee: no-effects functions cannot call effectful functions
  - `unsafe_ffi` blocks suppress effect checking; `audit` blocks implicitly add audit effect
  - `perform` expressions checked against allowed effect set
  - Per-effect error reporting for precise diagnostics

- **M2 Layer 3b: Capability checking — Zero Trust pillar enforcement** (18 tests)
  - Capability context stack with CapabilityFrame tracking available capabilities per scope
  - Function call capability checking: callee's required_capabilities must be held by caller
  - secure_zone blocks provide listed capabilities to their body, scoped (no leak)
  - Nested capability scopes: inner zones inherit outer capabilities
  - Symbol::Function extended with required_capabilities field
  - Per-capability error reporting for precise diagnostics

- **M2 Layer 4: Top-level declaration checking — full program type checking** (24 tests)
  - Two-pass approach: register all declarations, then check all bodies
  - Forward references: functions can call each other regardless of declaration order
  - Policy rule checking: body must return PolicyDecision, governance-aware error messages
  - Function body checking: return type verification, effect/capability context integration
  - All declaration types handled: functions, policies, structs, enums, traits, impls, capabilities, effects, consts, type aliases
  - Capability/Effect symbols accepted in type position (first-class types)

- **M2 Polish: Governance-aware diagnostics and edge case hardening** (13 new tests)
  - Error message audit: all governance errors use domain language (not type theory jargon)
  - Edge case tests: empty bodies, no return type, policy with no rules, nested blocks, deep nesting
  - Multi-error collection: independent errors from multiple policies/functions all reported
  - Governance error quality: messages list all four decisions (permit, deny, escalate, quarantine)
  - Decision documentation: D008 (linear types), D009 (session types), D010 (Self type) deferred

- **M3 Layer 1: IR design and AST-to-IR lowering** (24 tests)
  - IR data structures: IrModule, IrFunction, BasicBlock, Instruction, Value, IrType, Terminator
  - SSA-like design: each instruction produces a named Value (%0, %1, %2)
  - Flat instructions: no nested expressions, all operations on Values
  - Explicit control flow: if/else → CondBranch with then/else/merge blocks
  - Governance-aware: GovernanceDecision and AuditMark as first-class instructions
  - AST-to-IR lowering: functions, let bindings, variables, binary/unary ops, if/else, calls
  - Policy rules lower to functions returning PolicyDecision with audit marks
  - Audit instrumentation: AuditMark at function entry/exit and every governance decision
  - Pretty-printer: human-readable textual IR format for debugging
  - IrType system: Int, Float, Bool, String, Unit, PolicyDecision, Ptr, FuncRef

- **M3 Layer 2: WASM code generation** (23 end-to-end execution tests)
  - IR → WASM bytecode via wasm-encoder, executed by wasmtime (Cranelift JIT)
  - Full pipeline: RUNE source → lex → parse → lower to IR → compile to WASM → execute
  - IrType → WASM mapping: Int→I64, Float→F64, Bool→I32, PolicyDecision→I32
  - Governance decisions as i32 values: Permit=0, Deny=1, Escalate=2, Quarantine=3
  - All functions exported with sanitized names (:: → __)
  - If/else → WASM structured control flow (if/else/end blocks)
  - Variables: Alloca/Store/Load pattern → WASM locals
  - Function calls between RUNE functions via WASM call instruction
  - AuditMark → nop (placeholder for M5 runtime calls)
  - Value type tracking in lowerer for correct WASM local types
  - Function return type pre-collection for forward reference support in calls

- **M3 Layer 3: WASM module packaging and compiler CLI** (18 tests)
  - Standard `evaluate(subject_id, action, resource_id, risk_score) → PolicyDecision` entry point
  - evaluate dispatches to all policy rules, first-non-Permit-wins semantics
  - Default-deny: if no rules match or module has no policies, returns Deny
  - Unified compile pipeline: `compile_source()` → Result<WASM bytes, errors>
  - CompileError unifies LexError, ParseError, TypeError with phase tags
  - CLI: `rune build <file.rune>` → `<file.rune.wasm>` with error reporting
  - File compilation roundtrip test: write .rune → compile → load .wasm → execute → verify
  - Parameter passing: evaluate i64 params → rule params with automatic i64→i32 truncation

- **M3 Polish: Advanced control flow and codegen hardening** (8 new execution tests)
  - Match expressions: chain of CondBranch blocks with wildcard default, result type inference
  - While loops: header/body/exit pattern → WASM block/loop/br structured control flow
  - Compound assignment (+=, -=, *=): Load + binop + Store pattern
  - Nested function calls: compose(x) = add_one(double(x))
  - Early return from if branches: block_terminated tracking, unreachable fallback
  - Match chain codegen: in_match_chain flag ensures merge block compiled after all nesting
  - For-loop IR lowering (range syntax parsing deferred to M4+)

## What's Next

- ~~M3 Layer 1: IR design and AST-to-IR lowering~~ **Done** (24 tests)
- ~~M3 Layer 2: WASM code generation~~ **Done** (23 execution tests)
- ~~M3 Layer 3: Module packaging + compiler CLI~~ **Done** (18 compiler tests)
- ~~M3 Polish: Advanced control flow and codegen hardening~~ **Done** (8 new execution tests)
- M4: Refinement types
- M5: Runtime engine
- M6: Toolchain MVP
