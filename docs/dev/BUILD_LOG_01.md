# Build Log 01

## 2026-04-03 — Project Initialization

### What happened

- Initial rune-lang project scaffold committed (commit af5eec1)
- Architecture reference documents in place (docs/architecture/RUNE_01 through RUNE_05)
- Build environment confirmed: Rust toolchain on WSL2 Ubuntu 24.04 LTS, 64 GB DDR5, AMD Ryzen 8-core
- Development documentation structure created (docs/dev/)
- Living documents initialized: PROGRESS.md, BUILD_LOG_01.md, DECISIONS_01.md, TROUBLESHOOTING_01.md

### Current state

- Cargo workspace is set up and builds clean
- No compiler code written yet — documentation-first approach
- M1 (Parser + AST) is the active milestone, target Month 3

### Environment

- Machine: ASUS TUF Gaming Laptop, dedicated to RUNE
- OS: Windows 11 host + WSL2 Ubuntu 24.04
- Toolchain: Rust (rustc + cargo), Claude Code
- Project path: ~/projects/rune (Linux filesystem, not /mnt/c/)

---

## 2026-04-03 — Lexer Implementation

### What was built

Complete single-pass lexer (tokenizer) for RUNE source files.

### Files created

| File | Purpose | Lines |
|------|---------|-------|
| src/lib.rs | Crate root, module declarations | 1 |
| src/lexer/mod.rs | Lexer module declarations | 4 |
| src/lexer/token.rs | Token enum (all RUNE token kinds), Span struct, keyword lookup | ~200 |
| src/lexer/scanner.rs | Lexer struct — single-pass scanning logic | ~370 |
| src/lexer/tests.rs | 49 comprehensive tests | ~430 |

### Token categories implemented

- **Keywords (42):** policy, rule, permit, deny, escalate, quarantine, when, unless, type, struct, enum, fn, let, mut, const, self, capability, require, grant, revoke, effect, perform, handle, pure, if, else, match, for, in, while, return, break, continue, mod, use, pub, as, attest, audit, secure_zone, unsafe_ffi, true, false
- **Operators (22):** arithmetic (+, -, *, /, %), comparison (==, !=, <, >, <=, >=), logical (&&, ||, !), bitwise (&, |, ^, ~, <<, >>), assignment (=, +=, -=, *=, /=, %=)
- **Delimiters (12):** ; : :: , . .. ... -> => @ { } ( ) [ ] < >
- **Literals:** integers (decimal, 0x hex, 0o octal, 0b binary, _ separators), floats (decimal point, exponent), strings (with \n \t \r \\ \" \0 escapes)
- **Comments:** line (//) and nested block (/* */)

### Design decisions

- Tokens store raw text for numeric literals — defer base/size parsing to later stages
- String literals store the resolved value (escapes processed at lex time)
- Nested block comments supported (matches Rust behavior)
- `secure_zone` and `unsafe_ffi` are single keyword tokens (not two words)
- `1..2` correctly produces IntLiteral, DotDot, IntLiteral (not a float)

### Test results

```
cargo test: 49 passed, 0 failed, 0 ignored
cargo build: clean, no warnings
```

### Pillars served

- **Security Baked In:** Every token carries a Span for precise, auditable error reporting
- **Zero Trust Throughout:** No assumptions about input validity; every error path produces an actionable diagnostic

---

## 2026-04-03 — AST Node Definitions

### What was built

Complete AST data structure hierarchy for RUNE's governance-first syntax. No parser yet — these are the types the parser will produce.

### Files created

| File | Purpose | Lines |
|------|---------|-------|
| src/ast/mod.rs | Module declaration | 1 |
| src/ast/nodes.rs | All AST node types | ~470 |

### Node categories

**Top-level items (ItemKind):** Policy, Capability, Effect, TypeAlias, StructDef, EnumDef, ImplBlock, TraitDef, Function, Module, Use, Const

**Governance constructs:**
- `PolicyDecl` — policy blocks containing rules
- `RuleDef` — rules with params, when-clause, and governance decision body
- `CapabilityDecl` — capability types with function signatures, require/grant/revoke
- `EffectDecl` — effect types with operation signatures

**Type system:**
- `StructDef` with generic params and fields
- `EnumDef` with Unit/Tuple/Struct variant forms
- `ImplBlock` for methods and trait implementations
- `TraitDef` with associated types and method signatures
- `GenericParam` with bounds
- `TypeExpr` — Named, Tuple, Function, Unit, Reference

**Expressions (ExprKind):** 30 variants including:
- Literals, identifiers, paths
- Binary/unary operators (BinOp: 17 variants, UnaryOp: 3 variants)
- Call, FieldAccess, MethodCall, Index
- If/else, Match, For, While, Block, Return, Break, Continue
- Let binding, Assign, CompoundAssign
- Governance: Permit, Deny, Escalate, Quarantine, Attest, Audit, SecureZone, UnsafeFfi
- Effects: Perform, Handle
- StructLiteral, Tuple, Range

**Patterns (PatternKind):** Wildcard, Binding, Literal, Constructor, Struct, Tuple, Path

**Supporting types:** Block, Stmt, MatchArm, Handler, FieldInit, FieldPattern, Param, Ident, Path

### Design decisions

- Every node carries a Span — no exceptions
- `Box<T>` for all recursive types (Expr contains Expr)
- Governance decisions (permit/deny/escalate/quarantine) are expression variants, not statements — they are values
- `FnSignature` separated from `FnDecl` so traits, capabilities, and effects can reuse signatures without bodies
- `VariantFields` enum (Unit/Tuple/Struct) handles all Rust-style enum variant forms
- Patterns are a first-class AST concept for match arms and future let-pattern destructuring

### Test results

```
cargo build: clean, no warnings
cargo test: 49 passed (existing lexer tests), 0 failed
```

### Pillars served

- **Security Baked In:** Effect annotations on function signatures; audit/attest as first-class expressions
- **Assumed Breach:** SecureZone node models isolation boundaries with explicit capability requirements
- **No Single Points of Failure:** AST can represent linear type annotations (future M2 work)
- **Zero Trust Throughout:** Capability declarations are top-level items, not afterthoughts

---

## 2026-04-03 — Recursive Descent Parser (All Three Phases)

### What was built

Complete hand-written recursive descent parser for the entire RUNE grammar. Pratt parsing (precedence climbing) for expressions with correct operator precedence. Error recovery via synchronization (skip to `;` or `}`) to report multiple errors per file.

### Files created

| File | Purpose | Lines |
|------|---------|-------|
| src/parser/mod.rs | Module declarations | 7 |
| src/parser/parser.rs | Parser struct, top-level items, error recovery | ~470 |
| src/parser/expr.rs | Expression parsing with Pratt precedence climbing | ~380 |
| src/parser/types.rs | Type expression parsing | ~100 |
| src/parser/patterns.rs | Pattern parsing for match arms | ~160 |
| src/parser/tests.rs | 87 comprehensive tests | ~490 |

### Phase 1 — Governance core

- Policy declarations with rules
- Rule definitions with params, when-clause guards, governance decision bodies
- Governance decisions as expressions: permit, deny, escalate, quarantine
- Function declarations with optional return types and effect annotations
- Let bindings (with optional mut and type annotation)
- Literals (int, float, string, bool), identifiers, paths
- Binary operations with Pratt precedence (17 operators, 11 precedence levels)
- Unary operations (!, -, ~)
- Function calls, method calls, field access, indexing
- Block expressions, if/else (including else-if chains)
- Return, break, continue
- Assignment (=) and compound assignment (+=, -=, *=, /=, %=)

### Phase 2 — Type system

- Struct definitions with generic params and bounds
- Enum definitions with unit, tuple, and struct variants
- Type aliases
- Impl blocks (bare and trait-for-type)
- Trait definitions with method signatures and default bodies
- Type expressions: named with generics, tuple, function, unit, reference
- Match expressions with 7 pattern kinds (wildcard, binding, literal, constructor, struct, tuple, path)
- Match guards (when clauses)
- For and while loops

### Phase 3 — Governance-specific + modules

- Capability declarations with fn signatures, require/grant/revoke
- Effect declarations with operation signatures
- Attest expressions: attest(expr)
- Audit blocks: audit { body }
- Secure zone blocks: secure_zone { capabilities } { body }
- Unsafe FFI blocks: unsafe_ffi { body }
- Perform expressions: perform Effect::op(args)
- Handle expressions with handlers
- Module declarations (inline and external)
- Use declarations with optional aliases
- Const declarations

### Issues encountered and fixed

1. `self` keyword not accepted as identifier in parameter positions — fixed by extending `expect_identifier()` to accept `SelfValue` token
2. `self` not accepted in expression position — fixed by adding `SelfValue` case to `parse_prefix()`

### Test results

```
cargo build: clean, 0 warnings
cargo test: 136 passed (49 lexer + 87 parser), 0 failed
```

### Pillars served

- **Security Baked In:** Every AST node carries a Span; error recovery reports multiple diagnostics per file; clear error messages at every parse failure point
- **Assumed Breach:** secure_zone parsed as first-class expression with explicit capability requirements
- **Zero Trust Throughout:** capability declarations, attest expressions, and perform/handle for effects all parsed as core grammar, not afterthoughts
- **No Single Points of Failure:** Error recovery ensures one malformed declaration doesn't prevent parsing the rest of the file

---

## 2026-04-03 — M2 Layer 1: Type Representation and Symbol Table

### What was built

Internal type representation, symbol table with lexical scoping, and type context with AST-to-type resolution. This is the foundation for the type checker — data structures only, no checking logic yet.

### Files created

| File | Purpose | Lines |
|------|---------|-------|
| src/types/mod.rs | Module declarations | 6 |
| src/types/ty.rs | Type enum, TypeId, TypeTable, TypeVarId | ~220 |
| src/types/scope.rs | ScopeStack, Symbol enum, lexical scoping | ~160 |
| src/types/context.rs | TypeContext, builtin registration, type resolution | ~200 |
| src/types/tests.rs | 33 tests for all type system data structures | ~340 |

### Type representation (Type enum)

- **Primitives:** Int, Float, Bool, String, Unit
- **Composite:** Named (with resolved generic args), Function (with effects), Tuple, Ref
- **Inference:** Var(TypeVarId) for unification
- **Error recovery:** Error type — operations on Error produce Error, preventing cascading diagnostics
- **Governance-specific (unique to RUNE):**
  - Capability { name, operations } — capability token types (Zero Trust)
  - AttestedModel { signer, policy, architecture } — trust chain as type info (Zero Trust)
  - PolicyDecision — type of permit/deny/escalate/quarantine (Security Baked In)
  - Effect { name, operations } — effect type declarations (Security Baked In)

### Symbol table (ScopeStack)

- Stack of lexical scopes with HashMap<String, Symbol> per scope
- Symbol variants: Variable, Function, Type, Capability, Effect
- lookup() walks child → parent for name resolution
- define() rejects redefinition within the same scope, allows shadowing across scopes
- enter_scope() / exit_scope() for blocks, functions, modules

### Type context (TypeContext)

- Owns TypeTable (type interning arena) + ScopeStack + inference variable counter
- Registers builtins on creation: Int, Float, Bool, String, PolicyDecision, i32, i64, f32, f64, bool
- intern_type() stores types and deduplicates primitives
- resolve_type_expr() bridges AST TypeExpr → internal TypeId
- fresh_type_var() creates new inference variables

### Test results

```
cargo build: clean, 0 warnings
cargo test: 169 passed (49 lexer + 87 parser + 33 types), 0 failed
```

### Pillars served

- **Security Baked In:** Effect type is first-class in Type enum; functions carry effect lists in their type
- **Assumed Breach:** ScopeStack enforces isolation boundaries — each scope is a compartment
- **No Single Points of Failure:** Error type prevents cascading failures in type checking
- **Zero Trust Throughout:** Capability and AttestedModel are primitive types, not library wrappers

---

## 2026-04-03 — M2 Layer 2 Pass 1: Type Checker for Expressions and Statements

### What was built

Type checker that walks the AST and assigns types to every expression, statement, and block. This is the core inference engine — given a parsed function body, it produces a TypeId for each node and collects type errors without cascading.

### Files created

| File | Purpose | Lines |
|------|---------|-------|
| src/types/checker.rs | TypeChecker struct — check_expr, check_block, check_stmt, compatibility | ~460 |
| src/types/checker_tests.rs | 55 tests covering all expression kinds and error paths | ~340 |

### Expression checking implemented

- **Literals:** Int, Float, Bool, String → direct type assignment
- **Identifiers:** scope lookup → type from Symbol, error for undefined
- **Binary ops:** arithmetic (numeric), comparison (→Bool), logical (Bool), bitwise (Int)
- **Unary ops:** Neg (numeric), Not (Bool), BitNot (Int)
- **Function calls:** arity check, argument type check, return type extraction
- **If/else:** Bool condition, branch type compatibility, no-else → Unit
- **Match:** scrutinee type, arm type consistency, guard must be Bool
- **Blocks:** enter scope, check stmts, tail expr type or Unit
- **For/While:** condition must be Bool (while), body is Unit
- **Let bindings:** infer from initializer, check annotation match, register in scope
- **Assignment/CompoundAssign:** type compatibility checks
- **Return/Break/Continue:** return carries value type, others are Unit
- **Governance decisions:** permit/deny/escalate/quarantine → PolicyDecision
- **Governance expressions:** attest → Bool, audit → block type, secure_zone/unsafe_ffi → block type
- **Tuples:** collect element types into Tuple type
- **Struct literals, Range, Perform, Handle:** stub to fresh type vars for future passes

### Statement checking

- `Expr` statement: check and discard type → Unit
- `TailExpr`: check and return expression type
- `Item` statement: Unit (item declarations checked in future pass)

### Type compatibility

- Structural equality with TypeId comparison
- Error type propagation: Error is compatible with everything (prevents cascading)
- Type variables compatible with everything (for future unification)

### Test results

```
cargo build: clean, 0 warnings
cargo test: 224 passed (49 lexer + 87 parser + 33 types + 55 checker), 0 failed
```

### Pillars served

- **Security Baked In:** Governance decisions are type-checked to produce PolicyDecision; attest expressions verified to return Bool
- **Assumed Breach:** Scope isolation enforced during block checking — variables don't leak across boundaries
- **No Single Points of Failure:** Error type absorbs operations without cascading; multiple errors collected per check
- **Zero Trust Throughout:** Undefined variables produce errors immediately; function call arity strictly enforced
