# Build Log 05

## 2026-04-07 — M6 Layer 1: Tree-sitter Grammar, VS Code Extension, CLI Polish

### What was built

Developer experience tooling for RUNE: tree-sitter grammar for syntax highlighting across editors (VS Code, Neovim, Helix, Zed, GitHub), a VS Code extension skeleton with TextMate grammar, and a polished CLI with `build`, `check`, and `run` subcommands using clap.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added clap dependency | +1 line |
| src/main.rs | CLI rewrite with clap subcommands, colored errors, source-line display | Rewritten, ~185 lines |
| src/compiler/mod.rs | Added check_source() and phase_tag() | +50 lines |
| tools/tree-sitter-rune/grammar.js | Tree-sitter grammar definition | New file, ~350 lines |
| tools/tree-sitter-rune/queries/highlights.scm | Syntax highlighting queries | New file, ~110 lines |
| tools/tree-sitter-rune/package.json | Tree-sitter package metadata | New file |
| tools/tree-sitter-rune/test/corpus/policies.txt | 8 grammar test cases | New file, ~200 lines |
| tools/vscode-rune/package.json | VS Code extension manifest | New file |
| tools/vscode-rune/syntaxes/rune.tmLanguage.json | TextMate grammar | New file, ~150 lines |
| tools/vscode-rune/language-configuration.json | Editor configuration | New file |
| tests/cli_tests.rs | 6 CLI integration tests | New file, ~70 lines |

### Architecture

**Tree-sitter grammar** covers all RUNE constructs:
- Policy and rule declarations with parameters and type annotations
- Function declarations with return types, effect annotations, capability annotations
- Type system: struct, enum, type alias, type constraint with where clauses, traits, impl blocks
- Expressions: if/else, match, while, for, binary/unary ops, function calls, governance decisions
- Governance: permit/deny/escalate/quarantine, attest, audit, secure_zone, unsafe_ffi
- Refinement types: where clauses with comparison and membership predicates
- Comments (line and block), all literal types

**VS Code extension** provides:
- TextMate grammar for syntax highlighting before LSP is ready
- Language configuration: comment toggling, bracket pairs, auto-closing, indentation rules
- File association: `.rune` files automatically use RUNE highlighting

**CLI subcommands**:
- `rune build <file.rune>` — compile to WASM, report file size
- `rune check <file.rune>` — type-check only (lex + parse + type check), no codegen
- `rune run <file.rune>` — compile and evaluate with optional `--subject`, `--action`, `--resource`, `--risk` flags
- `rune --version` — print version info
- `rune --help` / `rune help` — usage information

**Error reporting** (rustc-style):
- Shows filename, line number, column number
- Displays the relevant source line with a caret pointing to the error location
- Color-coded: errors in red, success in green, warnings in yellow
- Phase tag: `error[lex]`, `error[parse]`, `error[type]`

**Exit codes**: 0 = success, 1 = compilation error, 2 = runtime error, 3 = CLI usage error

### Test results

```
cargo build: clean, 0 warnings
cargo test: 523 passed (517 lib + 6 CLI integration), 0 failed
Tree-sitter corpus: 8 test cases covering all major constructs
```

### New CLI integration tests (6 tests)

| Test | What it covers |
|------|---------------|
| test_cli_check_valid_source_exits_0 | check on valid .rune → exit 0, "no errors" |
| test_cli_check_invalid_source_exits_1 | check on invalid .rune → exit 1, error message |
| test_cli_build_produces_wasm_file | build creates .rune.wasm file with content |
| test_cli_version_prints_version | --version prints "rune 0.1.0" |
| test_cli_unknown_subcommand_exits_nonzero | unknown command → non-zero exit |
| test_cli_run_valid_policy | run evaluates and prints "Permit" |

### Pillars served

- **Security Baked In:** The CLI enforces the full compilation pipeline — `rune check` runs all type checking and SMT verification without generating code. There is no way to skip type checking.
- **Zero Trust Throughout:** `rune run` goes through the complete trust chain: compile → load → evaluate. Future versions will require attestation before execution.
- **Assumed Breach:** Error reporting includes phase tags and source locations for forensic analysis of compilation failures.
- **No Single Points of Failure:** The tree-sitter grammar enables RUNE adoption across multiple editors (VS Code, Neovim, Helix, Zed) and platforms (GitHub rendering). No vendor lock-in.

---

## 2026-04-07 — M6 Layer 2: AST-Based Formatter

### What was built

Canonical AST-based formatter for RUNE source code. `rune fmt` parses .rune files, walks the AST, and pretty-prints with consistent style. Like rustfmt and gofmt, the formatter is opinionated — one correct style. Supports `--check` mode for CI.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/lib.rs | Added formatter module | +1 line |
| src/formatter/mod.rs | Formatter struct, format_source(), AST walker, comment preservation | New file, ~560 lines |
| src/formatter/tests.rs | 18 formatter tests (unit + idempotency) | New file, ~200 lines |
| src/main.rs | Added `rune fmt` and `rune fmt --check` subcommands | +35 lines |
| tests/cli_tests.rs | 2 new CLI integration tests for fmt | +20 lines |

### Architecture

**Formatter** struct: indent_level, output buffer, comment tracking. Walks the full AST with methods for each node type: format_policy, format_rule, format_function, format_type_constraint, format_struct, format_enum, format_expression, format_block, etc.

**Formatting rules:**
- 4-space indentation, no tabs
- Opening brace on same line, closing brace aligned with declaration
- Single space around binary operators, after commas, after colons
- One blank line between top-level declarations
- Where clause predicates on separate lines, indented
- No trailing whitespace, exactly one trailing newline
- Comments preserved via line-position extraction from source

**CLI integration:**
- `rune fmt <file>` — format in place
- `rune fmt --check <file>` — CI mode, exit 1 if changes needed

### Test results

```
cargo build: clean, 0 warnings
cargo test: 545 passed (537 lib + 8 CLI), 0 failed
```

### New formatter tests (18 unit + 2 CLI = 20 tests)

| Test | What it covers |
|------|---------------|
| test_simple_policy_formatting | Indentation, braces, spacing |
| test_simple_policy_idempotent | format(format(x)) == format(x) |
| test_function_with_params_and_return | Params, return type, operator spacing |
| test_function_idempotent | Function idempotency |
| test_type_constraint_where_clause | Predicates on separate lines |
| test_if_else_formatting | Braces, indentation |
| test_nested_if_else | Nested if/else chains |
| test_governance_decisions_standalone | All four decisions as rule bodies |
| test_governance_decisions_inline_in_if | Inline in if/else |
| test_binary_expression_spacing | Operator spacing |
| test_multiple_declarations_blank_line | Blank lines between items |
| test_comments_preserved | Comment text in output |
| test_idempotency_policy | Simple idempotency |
| test_idempotency_complex | Complex multi-item idempotency |
| test_no_trailing_whitespace | No trailing spaces on any line |
| test_file_ends_with_one_newline | Exactly one trailing newline |
| test_empty_policy_body | Empty policy body |
| test_complex_real_world_policy | Multi-rule EU AI Act policy |
| test_format_source_error_on_invalid_syntax | Error on bad input |
| test_let_statement_formatting | Let with type annotation |
| test_cli_fmt_check_formatted_exits_0 | --check on formatted file |
| test_cli_fmt_check_unformatted_exits_1 | --check on unformatted file |

### Pillars served

- **Security Baked In:** Consistent formatting eliminates hiding spots for policy manipulation. Every .rune file looks the same, making code review reliable.
- **Assumed Breach:** `rune fmt --check` in CI ensures no unformatted code is merged. Formatting changes are visible in diffs.
- **Zero Trust Throughout:** The formatter reuses the same lexer and parser as the compiler — formatting cannot bypass syntax validation.
- **No Single Points of Failure:** The formatter is a library function (`format_source`) and a CLI command (`rune fmt`). Both interfaces are available for different integration needs.
