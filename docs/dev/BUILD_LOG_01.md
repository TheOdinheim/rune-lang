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
