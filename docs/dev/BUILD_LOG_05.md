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
