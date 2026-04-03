# RUNE Development Progress

## Current Milestone

**M1: Parser + AST** — Target: Month 3

Hand-written recursive descent parser producing a fully located AST with basic diagnostic reporting.

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
| M1: Parser + AST | Month 3 | **In Progress** |
| M2: Core type system | Month 6 | Not started |
| M3: Cranelift backend | Month 9 | Not started |
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

## What's Next

- M1 is feature-complete — all deliverables done
- Consider additional edge-case tests, fuzzing, or stress testing
- Begin M2 planning: core type system with pillar enforcement
