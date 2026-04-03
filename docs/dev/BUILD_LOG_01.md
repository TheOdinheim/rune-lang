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
