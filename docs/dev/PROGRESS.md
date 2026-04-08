# RUNE Development Progress

## Current Milestone

**M7: Module System** — Target: Month 21 — **In Progress**

Module system implementation. Layers 1–3 complete: parser/AST, name resolution/type checking, and multi-file compilation. File-based modules (`mod name;`) resolve to `name.rune` or `name/mod.rune`, parse, type-check, and compile into the same WASM module. 688 tests passing.

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
| M4: Refinement types | Month 12 | **Complete** — syntax + AST, Z3 SMT solver, refinement subtyping + call-site verification |
| M5: Runtime engine | Month 15 | **Complete** — runtime evaluator, audit trail, attestation, integration pipeline |
| M6: Toolchain MVP | Month 18 | **Complete** — tree-sitter, VS Code, CLI, formatter, LSP, manifest, scaffolding, docgen, playground |
| M7: Module System | Month 21 | **In Progress** — L1: parser/AST, L2: name resolution, L3: multi-file compilation |

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

- **M4 Layer 1: Refinement type syntax and AST extensions** (15 parser tests)
  - RefinementPredicate, RefinementOp, RefinementValue, WhereClause AST nodes
  - TypeExprKind::Refined — any type can carry `where { predicates }`
  - ItemKind::TypeConstraint — `type RiskModel = Model where { ... }`
  - ExprKind::Require — `require expr satisfies { predicates }`
  - Where, Satisfies, Not keywords added to lexer
  - All 6 comparison ops + in/not-in membership tests
  - Refinement values: Bool, Int, Float, String, List
  - Type checker resolves Refined types to base type (SMT verification deferred)

- **M4 Layer 2: Z3 SMT solver integration** (28 tests: 17 unit + 11 integration)
  - Z3 crate v0.20 with bundled feature (compiles Z3 from source)
  - SmtResult enum: Satisfiable, Unsatisfiable(explanation), Unknown(reason)
  - Predicate-to-Z3 translation: Bool, Int, Float→Real (exact rational), String
  - In/NotIn: OR of equalities / AND of inequalities
  - Human-readable UNSAT explanations listing all contradictory constraints
  - Type checker integration at 3 points: TypeConstraint, Require, refined params
  - EU AI Act risk category encoding verified as satisfiable/contradictory

- **M4 Layer 3: Refinement subtyping and call-site verification** (17 tests: 8 unit + 9 integration)
  - SMT implication checking: `check_implication(caller, callee)` verifies caller predicates entail callee
  - Call-site refinement verification: every argument to a refined parameter checked via Z3
  - Symbol::Variable carries `refinements`, Symbol::Function carries `param_refinements`
  - Governance-aware error messages: "no refinement guarantees" / "does not imply"
  - Refinement subtyping: superset predicates satisfy subset, weaker rejected
  - `require` expression lowers to Bool true in IR (predicates verified at compile time)

- **M5 Layer 1: Runtime policy evaluator** (32 tests)
  - PolicyModule: loads WASM bytes or .rune.wasm files, thread-safe Engine + Module
  - PolicyEvaluator: fresh Store per evaluation (arena model), evaluate() + evaluate_rule()
  - PolicyDecision: Permit/Deny/Escalate/Quarantine with i32 encoding
  - Module inspection: list_exports(), list_policy_rules(), has_evaluate()
  - compile_and_evaluate() and compile_and_load() convenience pipeline
  - Evaluation timing recorded for performance monitoring
  - RuntimeError enum with context for all failure modes

- **M5 Layer 2: Cryptographic audit trail** (17 tests)
  - AuditTrail: append-only hash chain with SHA-256 (placeholder for SHA-3)
  - AuditRecord: record_id, timestamp, event_type, decision, input_hash, chain links, signature
  - HMAC-SHA256 signatures (placeholder for ML-DSA / FIPS 204)
  - Crypto abstraction: hash() and sign() in single module for PQC swap
  - AuditedPolicyEvaluator: auto-records every evaluation to audit trail
  - Chain verification (detect tampering) and signature verification (non-repudiation)

- **M5 Layer 3: Model attestation checker** (23 tests)
  - ModelAttestation: model_id, model_hash, signer, signature, timestamp, provenance
  - ModelProvenance: source_repository, training_data_hash, framework, architecture, slsa_level
  - AttestationChecker: three-layer verification (signature → provenance → policy)
  - AttestationPolicy: required_signers, SLSA level, framework allowlist, freshness
  - Evaluator integration: with_attestation() + verify_model() with audit trail recording
  - Uses shared crypto module — single PQC swap point for audit + attestation

- **M5 Layer 4: End-to-end integration pipeline** (10 tests)
  - RuntimePipeline: from_source → compile → load → attest → evaluate → audit
  - PipelineConfig: signing_key, module_name, optional AttestationChecker
  - Full lifecycle API: evaluate, evaluate_rule, verify_model, audit_trail, export
  - 10 end-to-end tests including realistic EU AI Act governance scenario

- **M6 Layer 1: Tree-sitter grammar, VS Code extension, CLI polish** (6 CLI integration tests + 8 tree-sitter corpus tests)
  - Tree-sitter grammar: all RUNE constructs, syntax highlighting queries
  - VS Code extension: TextMate grammar, language configuration
  - CLI: clap-based build/check/run subcommands, rustc-style error reporting with source lines
  - check_source() for type-check-only mode (no codegen)

- **M6 Layer 2: AST-based formatter** (18 unit + 2 CLI tests)
  - format_source(): parse → walk AST → pretty-print with consistent style
  - CLI: `rune fmt` (in-place) and `rune fmt --check` (CI mode)
  - 4-space indent, operator spacing, blank lines between items, comment preservation
  - Idempotent: format(format(x)) == format(x)

- **M6 Layer 3: LSP server** (27 unit tests)
  - RuneLanguageServer (tower-lsp): real-time diagnostics, hover, go-to-definition, completions
  - rune-lsp binary: separate from CLI, stdin/stdout transport, works with any LSP-compatible editor
  - VS Code extension updated: spawns rune-lsp, connects via vscode-languageclient
  - catch_unwind wraps all compilation — malformed input cannot crash the server
  - 30+ keyword hover docs, 40+ keyword completions, identifier completions from parsed AST

- **M6 Layer 4: Package manifest, project scaffolding, documentation generator** (24 unit + 3 CLI tests)
  - rune.toml manifest: [package] + [build] sections with graduation_level and edition
  - `rune new <name>`: creates project with rune.toml, src/main.rune, README.md
  - `rune doc <file>`: extracts doc comments from AST, generates Markdown with ToC
  - Project-aware build/check: finds rune.toml, defaults to src/main.rune

- **M6 Layer 5: Online playground and feature-gated compilation** (6 unit tests)
  - Feature flags: smt, runtime, lsp, playground (all optional, default = smt + runtime + lsp)
  - Browser playground: CodeMirror editor, Check/Build/Format, WASM execution in browser
  - Playground WASM API: check, compile, format via wasm-bindgen
  - Minimal build: `--no-default-features` compiles lexer + parser + types + IR + codegen + formatter + manifest + docgen

## What's Next

- ~~M3 Layer 1: IR design and AST-to-IR lowering~~ **Done** (24 tests)
- ~~M3 Layer 2: WASM code generation~~ **Done** (23 execution tests)
- ~~M3 Layer 3: Module packaging + compiler CLI~~ **Done** (18 compiler tests)
- ~~M3 Polish: Advanced control flow and codegen hardening~~ **Done** (8 new execution tests)
- ~~M4 Layer 1: Refinement type syntax and AST~~ **Done** (15 parser tests)
- ~~M4 Layer 2: Z3 SMT solver integration~~ **Done** (28 tests)
- ~~M4 Layer 3: Refinement subtyping and call-site verification~~ **Done** (17 tests)
- ~~M5 Layer 1: Runtime policy evaluator~~ **Done** (32 tests)
- ~~M5 Layer 2: Cryptographic audit trail~~ **Done** (17 tests)
- ~~M5 Layer 3: Model attestation checker~~ **Done** (23 tests)
- ~~M5 Layer 4: End-to-end integration pipeline~~ **Done** (10 tests)
- ~~M6 Layer 1: Tree-sitter grammar, VS Code extension, CLI polish~~ **Done** (6 CLI + 8 corpus tests)
- ~~M6 Layer 2: AST-based formatter~~ **Done** (18 unit + 2 CLI tests)
- ~~M6 Layer 3: LSP server~~ **Done** (27 unit tests)
- ~~M6 Layer 4: Package manifest, project scaffolding, docgen~~ **Done** (24 unit + 3 CLI tests)
- ~~M6 Layer 5: Online playground and feature-gated compilation~~ **Done** (6 unit tests)
- **M7 Layer 1: Module syntax, visibility, use imports, qualified paths** (23 parser + 10 formatter tests)
  - Visibility enum (Public/Private) on PolicyDecl, StructDef, EnumDef, TypeAliasDecl, TypeConstraintDecl, ModuleDecl, UseDecl
  - Module declarations: inline `mod name { ... }` and file-based `mod name;`
  - Use imports: single (`use a::b;`), glob (`use a::*;`), alias (`use a::b as c;`), module (`use a;`)
  - Qualified paths: `self::helper`, `super::utils::hash`, `a::b::c::d`
  - Super keyword added to lexer
  - Tree-sitter grammar updated for all new syntax
  - Formatter updated with visibility prefixes and module body formatting

- **M7 Layer 2: Module-scoped name resolution and type checking** (29 tests)
  - Symbol::Module variant with nested symbol tables and visibility maps
  - Module registration: two-pass (register + check) within module scope, snapshot to Symbol::Module
  - Qualified path resolution: `crypto::verify`, `a::b::c` walk module chains
  - Visibility enforcement: private items inaccessible from outside, "add `pub`" suggestions
  - Use imports: single (`use a::b;`), glob (`use a::*;`), alias (`use a::b as c;`)
  - Glob imports skip private items silently, conflict detection for existing names
  - Cross-module effect and capability propagation (transparent, no module-specific changes)
  - File-based modules (`mod name;`) register as empty placeholders
  - Full backward compatibility: flat-scope code works identically

- **M7 Layer 3: Multi-file compilation and module loading** (7 loader + 12 integration tests)
  - ModuleLoader: file resolution (sibling file or directory mod.rune), caching, cycle detection
  - TypeChecker integration: set_module_loader, set_current_file, file-based module lex+parse+type-check
  - IR lowering: module functions name-mangled (module::function), recursive for nested modules
  - compile_project/check_project: project-aware compilation entry points
  - CLI: cmd_build and cmd_check use compile_project/check_project
  - Nested file modules: mod rules; → rules/mod.rune → mod access; → rules/access.rune

## What's Next

- M7 Layer 4+: Module re-exports, pub(crate) visibility, module-level constants
- M8+: FFI, LLVM backend, standard library, formal verification
