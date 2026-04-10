# RUNE Development Progress

## Current Milestone

**M10: Standard Library** — Target: Month 36 — **In Progress**

**M10 COMPLETE.** Layer 4: stdlib packaging, PQC swap, integration tests. 967 tests passing (+ 91 LLVM-gated).

### M8 Deliverables

| Deliverable | Status |
|-------------|--------|
| Extern block syntax (block + standalone + ABI) | **Done** (M8 L1) |
| FFI effect enforcement (auto + transitive) | **Done** (M8 L1) |
| IR audit instrumentation (FfiCallStart/End) | **Done** (M8 L1) |
| Toolchain updates (formatter, LSP, docgen, tree-sitter) | **Done** (M8 L1) |
| C ABI embedding API (fail-closed, opaque handles) | **Done** (M8 L2) |
| Safe Rust wrapper (RuneEngine) | **Done** (M8 L2) |
| C header file (tools/rune.h) | **Done** (M8 L2) |
| cdylib build target | **Done** (M8 L2) |
| FlatBuffers wire format (binary serialization) | **Done** (M8 L3) |
| Wire format C ABI (rune_evaluate_wire) | **Done** (M8 L3) |
| Safe Rust wire API (evaluate_wire, evaluate_wire_bytes) | **Done** (M8 L3) |
| FlatBuffers schema contract (schemas/policy.fbs) | **Done** (M8 L3) |
| rune-rs Rust integration crate (PolicyEngine, Request builder, JSON eval) | **Done** (M8 L4) |
| rune-python Python integration package (wasmtime-based WASM execution) | **Done** (M8 L4) |
| Usage examples (Rust, Python, C) | **Done** (M8 L4) |
| Integration guide (docs/INTEGRATION_GUIDE.md) | **Done** (M8 L4) |
| LLVM backend (infra, IR translation, native linking, validation) | **Done** (M9 L1-L4) |
| Standard library (9 modules, PQC-first, prelude) | **Done** (M10 L1-L4) |
| Formal verification | Planned |

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
| M7: Module System | Month 21 | **Complete** — L1–L4: parser/AST, name resolution, multi-file, edition/LSP/docgen/integration |
| M8: FFI & Backend | Month 24 | **Complete** — L1-L4: extern blocks, ffi effects, C ABI embedding, wire format, rune-rs, rune-python |
| M9: LLVM Backend | Month 30 | **Complete** — L1-L4: LLVM infra, IR translation, native linking, cross-backend validation |
| M10: Standard Library | Month 36 | **Complete** — L1-L4: crypto, io, net, env, time, collections, attestation, policy, audit, PQC swap |

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

- **M7 Layer 4: Edition system, LSP module support, end-to-end integration** (6 edition + 11 LSP + 5 docgen + 3 CLI tests)
  - Edition enum (Edition2026), resolve from rune.toml, passed to TypeChecker
  - LSP: mod/use/as/self/super/pub keyword hover, module declaration hover, module completions, module go-to-definition
  - Docgen: DocItemKind::Module, public-only children extraction
  - CLI: multi-file build/check integration tests
  - Invalid edition detection with clear error messages

- **M8 Layer 1: FFI syntax, extern blocks, ffi effect enforcement, audit instrumentation** (24 new tests)
  - Extern block syntax: block form `extern { fn ...; }`, standalone `extern fn ...;`, ABI string `extern "C"`
  - ExternBlock and ExternFnDecl AST nodes, ItemKind::Extern variant
  - All extern functions carry automatic `ffi` effect, enforced transitively via existing M2 infrastructure
  - IR audit marks: FfiCallStart/FfiCallEnd around every extern function call
  - Toolchain: tree-sitter grammar, formatter, LSP hover/completions/go-to-def, docgen

- **M8 Layer 2: C ABI embedding API with fail-closed governance** (24 new tests)
  - C-compatible types: RunePolicyRequest (#[repr(C)]), RunePolicyDecision, outcome constants
  - Opaque handle lifecycle: rune_module_load_source, rune_module_load_wasm, rune_evaluate, rune_module_free
  - Fail-closed: every error → DENY, catch_unwind on all C entry points, null checks
  - Safe Rust wrapper: RuneEngine with from_source/from_wasm/evaluate/audit_trail_len/export_audit_log
  - C header file (tools/rune.h) with full documentation
  - cdylib build target for shared library generation (.so/.dylib/.dll)

- **M8 Layer 3: FlatBuffers wire format with zero-copy serialization** (20 new tests)
  - Custom binary tagged field encoding for PolicyRequest/PolicyDecision serialization
  - Wire types: WireRequest (nested Subject/Action/Resource/Context/Attestation), WireDecision
  - C ABI: rune_evaluate_wire (bytes in, bytes out, fail-closed on deserialization error)
  - Safe Rust API: evaluate_wire (typed), evaluate_wire_bytes (zero-copy bytes path)
  - FlatBuffers schema (schemas/policy.fbs) as contract definition
  - Forward-compatible: unknown field IDs safely skipped during deserialization

- **M8 Layer 4: Language integration packages — M8 COMPLETE** (16 new Rust tests)
  - rune-rs Rust crate: PolicyEngine, Request builder, Outcome, Decision, AuditEntry, evaluate_json
  - rune-python Python package: PolicyEngine (wasmtime WASM execution), Decision, load()
  - Usage examples: Rust, Python, C integration patterns
  - Integration guide: docs/INTEGRATION_GUIDE.md covering all three language paths

- **M9 Layer 1: LLVM backend infrastructure, feature gating, basic IR-to-LLVM translation** (27 new LLVM-gated tests)
  - LlvmCodegen: all IR instruction kinds translated to LLVM IR via inkwell
  - Feature-gated: `llvm = ["inkwell"]`, not in default features
  - compile_to_native() and compile_to_native_file() pipeline functions
  - CLI: `--target native` flag on Build subcommand
  - Full pipeline: RUNE source → native ELF object file (.o)

- **M9 Layer 2: Complete IR-to-LLVM translation — control flow, policy decisions, cross-backend equivalence** (48 total LLVM-gated tests)
  - Control flow: if/else (CondBranch → LLVM conditional branch + phi), while loops (header/body/exit)
  - Policy decisions: all four governance decisions compile to correct i32 constants
  - Evaluate entry point: `evaluate(i64,i64,i64,i64)->i32` with first-non-permit-wins, matching WASM
  - Cross-backend equivalence: 6 tests verifying WASM execution and LLVM IR structure agree
  - Fixed Layer 1 constant folding: param-based test helpers prevent LLVM from folding constants

- **M9 Layer 3: Native binary linking — shared libraries, executables, CLI integration** (64 total LLVM-gated tests)
  - Shared library output: compile_to_shared_library() → .so via cc -shared with PIC
  - Executable output: compile_to_executable() → standalone binary with generated main()
  - CLI: `--target native-shared` (.rune.so) and `--target native-exe` (.rune.bin)
  - rune.h updated with native shared library documentation and dlopen example
  - Pipeline refactored: compile_to_ir() + build_llvm_codegen() shared helpers

- **M9 Layer 4: Cross-backend validation, benchmarking, end-to-end integration — M9 COMPLETE** (91 total LLVM-gated tests)
  - 16 cross-backend tests: WASM evaluator + native executable produce identical decisions
  - 8 benchmarks: WASM eval <1ms, native exe <10ms, compilation <30s, timing comparisons
  - 4 CLI tests: native-shared/native-exe output, deny exit code, unknown target error
  - Integration guide updated with native compilation section

- **M10 Layer 1: rune::crypto — PQC-first cryptographic primitives** (40 new tests)
  - SHA-3 (FIPS 202): sha3_256, sha3_512, hex variants, generic dispatch
  - ML-DSA-65 (FIPS 204): placeholder with correct interface, uses HMAC-SHA3-256 internally
  - HMAC: SHA3-256 (PQC) and SHA-256 (classical), constant-time verification
  - ML-KEM-768 (FIPS 203): placeholder interface, returns NotImplemented
  - Backward compatible with M5 audit trail (byte-for-byte verified)

- **M10 Layer 2: rune::io, rune::net, rune::env, rune::time, rune::collections** (47 new tests)
  - rune::io: file read/write/append, directory ops, IoError with From<std::io::Error>
  - rune::net: TCP connect/send/receive, DNS resolution, URL parsing (pure), TcpConnection with audit tracking
  - rune::env: environment variables, hostname, cwd
  - rune::time: Unix timestamps, duration formatting, constants
  - rune::collections: sort, unique, contains, min/max/sum/avg (pure, no effects)

- **M10 Layer 3: rune::attestation, rune::policy, rune::audit — governance standard library** (55 new tests)
  - rune::attestation: ModelCard builder, TrustPolicy tiers (permissive/strict/defense), TrustVerifier, PQC signing
  - rune::policy: Decision enum with combinators (first_non_permit, most_severe, unanimous), PolicyRequest builder, RiskLevel
  - rune::audit: AuditEntry with SHA3-256 hashes, AuditTrailView with filters, DecisionSummary, chain verification, JSON/CSV export

- **M10 Layer 4: stdlib packaging, PQC swap, integration tests — M10 COMPLETE** (10 new tests)
  - Prelude: `stdlib::prelude` re-exports from all 9 stdlib modules
  - PQC swap: runtime audit trail now uses SHA3-256/HMAC-SHA3-256 (was SHA-256/HMAC-SHA256)
  - Classical fallbacks: hash_sha256/sign_sha256 retained for backward compatibility
  - Integration tests: full pipeline, crypto chain verification, effect documentation, prelude completeness

- **rune-permissions Layer 1: Core types, role hierarchies, RBAC engine** (97 new tests)
  - Workspace crate: packages/rune-permissions/ with types, roles, RBAC, grants, context, decisions, errors, store
  - Role hierarchies: multiple inheritance, cycle detection, diamond deduplication, mutual exclusion
  - Classification levels: Bell-LaPadula "no read up" (Public through TopSecret)
  - Built-in templates: system_admin, security_officer, operator, auditor, viewer, ai_agent
  - Unified PermissionStore: RBAC + direct grants, audit logging

- **rune-secrets Layer 1: Secret lifecycle management** (131 new tests)
  - Workspace crate: packages/rune-secrets/ with 10 modules
  - SecretValue with zeroization on Drop, constant-time comparison, [REDACTED] debug
  - SecretVault: in-memory store with Bell-LaPadula clearance checks, usage limits, expiration
  - Envelope encryption: DEK/KEK pattern using HMAC-SHA3-256 XOR stream cipher
  - HKDF key derivation (RFC 5869) using HMAC-SHA3-256, password hashing placeholder
  - Shamir's Secret Sharing: GF(256) arithmetic, K-of-N split/reconstruct
  - Rotation policies: aggressive/standard/relaxed/token presets, status tracking
  - Classification handling rules per level, violation detection
  - Transit encryption with 5-minute expiry, route-specific key derivation
  - Secret audit logging with filtering, export, security metrics

- **rune-identity Layer 1: Identity lifecycle, authentication, sessions, trust scoring** (120 new tests)
  - Workspace crate: packages/rune-identity/ with 11 modules
  - Identity types: User, Service, Device, AiAgent, System with type-specific policies
  - Credential management: password (HKDF), API key (SHA3-256), token, certificate, MFA TOTP/WebAuthn
  - Authentication: multi-method with rate limiting, lockout, IP allowlist, MFA step-up
  - Session management: trust decay, idle timeout, concurrent limits, revoke-all
  - Continuous trust scoring: weighted factors, configurable decay, step-up thresholds
  - Attestation chains: SHA3-256 hash chain, HMAC-SHA3-256 signatures, tamper detection
  - Verifiable claims: signed assertions (roles, attributes, memberships, delegations)
  - Federation interfaces: OIDC and SAML2 data structures for adapter integration
  - Identity audit logging: 19 event types, security event filtering

- **rune-shield Layer 1: AI inference immune system, prompt injection defense, exfiltration prevention** (98 new tests)
  - Workspace crate: packages/rune-shield/ with 12 modules
  - Governance mapping: ShieldAction → GovernanceDecision (Permit=0, Deny=1, Escalate=2, Quarantine=3); Allow/Modify map to Permit, Block to Deny, Quarantine to Quarantine, Escalate to Escalate; single exhaustive mapping function
  - Graduated policy: ShieldLevel (Bronze/Silver/Gold/Platinum) with monotonically tightening max_input_length, injection_block/quarantine thresholds, adversarial_threshold, exfiltration_block_threshold; Bronze 10000B/0.9/0.7, Silver 8000B/0.8/0.6, Gold 5000B/0.7/0.5, Platinum 3000B/0.6/0.4
  - Input validation: length, UTF-8, null-byte, control-char (strict mode), blocked-pattern checks; InputSanitizer with strip_control_chars/normalize_whitespace/truncate (UTF-8-boundary-safe)/escape_html
  - Prompt injection detection: 5 weighted strategies summing to 1.0 — KeywordHeuristic (0.4), StructuralAnalysis (0.3, delimiter abuse + role markers), LengthAnomaly (0.1), EncodingDetection (0.1, base64/hex/URL/unicode escapes), InstructionDensity (0.1); neutralize() wraps input in [USER_INPUT_BEGIN]/[USER_INPUT_END] and redacts inline role markers
  - Exfiltration detection: ExfiltrationDetector wraps rune-privacy's PiiDetector plus 5 built-in SensitivePattern libraries (InternalSystemPrompt, TrainingData, InternalArchitecture, ApiKeys[Critical], InternalUrls); PII leaks → Modify, sensitive-pattern leaks → Block; redact_pii() replaces emails/SSNs/IPs/phones/credit cards with redaction markers via token-based classification + whole-text phone pass
  - Adversarial detection: AdversarialDetector with Shannon entropy (low/high flagged), ExcessiveRepetition (max-run + 3-char substring counts), UnicodeAnomaly (zero-width, bidi override, control chars), LowInformationDensity (unique-token ratio)
  - Quarantine: QuarantineStore with sequential Q-N IDs, content types (Input/Output/Request), QuarantineVerdict lifecycle (Released/Confirmed/FalsePositive/Modified), false_positive_rate, average_review_time_ms, pending_review/reviewed filters
  - Immune memory: ImmuneMemory tracks AttackSignature (confirmation_count log-based confidence boost capped at 0.3) and FalsePositivePattern (suppress after threshold=3); boost_confidence/should_suppress threaded into the shield pipeline
  - Output filter: OutputFilter with 6 OutputFindingType variants (PiiLeak/SystemPromptLeak/TrainingDataLeak/InternalArchitectureLeak/ApiKeyLeak/InternalUrlLeak); distinguishes redact-in-place vs block based on finding type
  - Shield engine: 8-step input pipeline (receipt → validation → adversarial → injection → memory lookup → verdict → quarantine/block/escalate/neutralize → stats+audit), 5-step output pipeline (receipt → length check → exfiltration scan → verdict → stats+audit), ShieldStats with detection_rate
  - Audit log: ShieldAuditEvent with 15 ShieldEventType variants (InputReceived/Validated/Rejected, InjectionDetected/Blocked/Neutralized, AdversarialDetected, Quarantined/Released/Confirmed, OutputInspected, ExfiltrationDetected, OutputModified/Blocked, Escalated); blocks/quarantines/injections/exfiltrations/by_severity/since filters

- **rune-detection Layer 1: anomaly detection, pattern matching, behavioral analysis, alert management** (103 new tests)
  - Workspace crate: packages/rune-detection/ with 10 modules
  - Signals: Signal/SignalSource/SignalType/SignalValue/SignalBatch — normalized events from network/API/user/system/model-inference/policy/audit sources
  - Anomaly detection: AnomalyDetector with ring-buffer history, z-score / IQR / moving-average methods, combined detect returning most severe verdict, mean/std_dev/percentile
  - Pattern matching: 7 heuristic attack detectors (PromptInjection, SqlInjection, PathTraversal, XssAttempt, CommandInjection, DataExfiltration, EncodedPayload), CustomPattern with keyword threshold, confidence scaling
  - Behavioral analysis: BehaviorAnalyzer with Welford online mean/variance, per-profile per-metric baselines, z-score deviation vs baseline, insufficient-data → Unknown
  - Alerts: AlertManager with dedup window (default 5 min), lifecycle (New → Acknowledged → Resolved / FalsePositive), false-positive rate, severity distribution, max-alerts with oldest-first eviction
  - IoCs: IoCType (9 variants inc. Custom), IoCDatabase with expiry/active flags, text scanning for IP/Domain/URL/FileHash/Email, case-insensitive domain/URL/email/user-agent matching
  - Rules: DetectionRule with composable RuleCondition (SignalMatch, ValueAbove, ValueBelow, TextContains, TextContainsAny, AnomalyScore, PatternDetected, BehaviorDeviation, IoCMatch, RateExceeds, And, Or, Not), RuleEvalContext, built-in templates (high_request_rate, prompt_injection, anomalous_value, ioc_match, behavioral_deviation)
  - Pipelines: DetectionPipeline chaining independent stages (AnomalyDetection, PatternScan, BehaviorAnalysis, IoCCheck, RuleEvaluation), two-pass execution so rules can reference any earlier detector's output, embedded AlertManager raises alerts on rule triggers
  - Detection audit log: 10 event types (AnomalyDetected, PatternMatched, BehaviorDeviation, IoCFound, RuleTriggered, AlertRaised, AlertAcknowledged, AlertResolved, AlertFalsePositive, PipelineProcessed), detection/alert filters

- **rune-security Layer 1: threat modeling, vulnerability scoring, security context, incident management** (108 new tests)
  - Workspace crate: packages/rune-security/ with 10 modules
  - Severity: SecuritySeverity (Info–Emergency), score-to-severity mapping, response SLAs (720h/168h/24h/4h/0h), SeverityChange with escalation/de-escalation detection, color codes
  - Threat taxonomy: STRIDE (6) + AI-specific (PromptInjection, DataPoisoning, ModelExfiltration, AdversarialInput, GovernanceBypass) + SupplyChainCompromise + InsiderThreat, affected_pillar mapping (reuses rune_permissions::Pillar), MITRE ATT&CK IDs, ThreatActor with 9 actor types and 5 sophistication levels, ThreatModelBuilder with overall_risk and unmitigated filter
  - Vulnerability scoring: simplified CVSS v3.1 base score (ISS, Exploitability, scope-unchanged and scope-changed formulas, 10.0 cap, roundup), AiImpact metrics (model integrity, training data integrity, inference reliability, governance bypass, data exfiltration), VulnerabilityDatabase with severity/category/status filters
  - Security posture: A–F grading (F < D < C < B < A ordering), 7 dimension categories with weighted scoring, PostureAssessor generating category-specific recommendations for dimensions below 70
  - Security context: SecurityContext with fluent builder, restrict-only-narrows / elevate-only-raises semantics, ContextStack with most-restrictive clearance and worst-case risk across nested contexts, max depth 64 with SecurityError::ContextDepthExceeded
  - Incident management: IncidentStatus state machine with next_valid_statuses() enforcement, EscalationPolicy with severity-based SLAs, IncidentTracker with acknowledge/update_status/resolve/close, MTTA/MTTR calculation, incidents_needing_escalation
  - Policy rules: composable RuleCondition (Always/SeverityAbove/ClassificationAbove/ThreatActive/ContextMatch/And/Or/Not), RuleAction (Allow/Deny/RequireMfa/RequireApproval/Encrypt/Audit/Alert/Quarantine/RateLimit), built-in policy templates (default_network, default_data_protection, default_ai_governance), SecurityPolicySet evaluate/violations
  - Security metrics: MTTD/MTTR/MTTC/vulnerability_age/patch_coverage/incident_rate/false_positive_rate/detection_coverage, MetricStore with history/average/max/min/trend (5% threshold, 4-point minimum, lower-is-better vs higher-is-better), SecurityDashboard with DashboardSummary
  - Security audit log: 10 event types (ThreatIdentified, VulnerabilityDiscovered, VulnerabilityPatched, IncidentReported, IncidentEscalated, IncidentResolved, PostureAssessed, PolicyViolation, ContextElevated, SecurityMetricRecorded), events_by_severity/type, since/critical/incident/violation filters

- **rune-privacy Layer 1: PII detection, differential privacy, anonymization, consent, data subject rights** (104 new tests)
  - Workspace crate: packages/rune-privacy/ with 10 modules
  - PII detection: 21 categories including GDPR Article 9 special categories (Health, Biometric, Genetic, etc.), sensitivity levels, heuristic detectors (email, SSN, phone, IP, credit card), pattern library
  - Anonymization: redaction, masking, generalization, SHA3-256 hashing, HMAC-SHA3-256 pseudonymization, deterministic Laplace/Gaussian noise, k-anonymity, l-diversity, t-closeness, composable pipelines
  - Differential privacy: (ε, δ)-DP with strict/standard/relaxed budgets, Laplace/Gaussian/Exponential mechanisms, count/sum/average/histogram queries, budget exhaustion rejection
  - Purpose limitation: GDPR Art. 6 legal basis, data tagging, purpose-use checks, data minimization (excess/missing fields)
  - Consent management: lifecycle (active/withdrawn/expired/superseded), evidence (method/IP/UA/signature), per-purpose consent lookup, expiration cleanup
  - Data subject rights: GDPR Art. 15–22 and CCPA §1798.105/110/120, 30-day / 45-day deadlines, overdue detection, request tracking by subject
  - Retention: policies by category/purpose/classification, most-restrictive enforcement, expiry actions (Delete/Anonymize/Archive/Review)
  - Privacy Impact Assessment: PIA/DPIA builder, risk rating, mitigations, category-specific recommendations
  - Privacy audit log: 11 event types with subject/type/time/violation/consent filters

## What's Next

- rune-permissions Layer 2+: policy integration, persistence, API
- rune-secrets Layer 2+: real AEAD encryption, Argon2id, persistence
- rune-identity Layer 2+: persistence, real OIDC/SAML, Argon2id passwords, session store
- rune-privacy Layer 2+: real regex patterns, full DP library integration, persistence, policy-as-code
- rune-security Layer 2+: full CVSS v3.1 (temporal + environmental), threat intel feeds, persistent incident store, SOAR integration
- rune-detection Layer 2+: real regex/ML pattern matchers, streaming time-series store, cross-signal correlation, SIEM integrations
- rune-shield Layer 2+: ML-backed injection classifier, cross-conversation attack correlation, shield-alert integration with rune-detection AlertManager, automated FP → suppression loop, rate-limiting and MFA gating as additional ShieldActions, persistence for quarantine and immune memory
- Future: formal verification, pub(crate) visibility, cross-compilation, runeOS fork
