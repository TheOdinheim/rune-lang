# RUNE Development Progress

## Current Milestone

**M1: Parser + AST** — Target: Month 3

Hand-written recursive descent parser producing a fully located AST with basic diagnostic reporting.

### M1 Deliverables

| Deliverable | Status |
|-------------|--------|
| Lexer / tokenizer | **Done** (49 tests passing) |
| Token types for RUNE syntax | **Done** (all keyword, symbol, literal categories) |
| Recursive descent parser | Not started |
| AST node definitions | Not started |
| Source location tracking (spans) | **Done** (Span struct with file_id, offsets, line, column) |
| Basic diagnostic / error reporting | **Done** (LexError with clear messages + spans) |
| Unit tests for lexer | **Done** (49 tests: keywords, literals, operators, errors, integration) |
| Unit tests for parser | Not started |
| Integration tests (parse full .rune files) | Not started |

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

## What's Next

- Define AST node types
- Begin recursive descent parser
- Parser error recovery strategy
