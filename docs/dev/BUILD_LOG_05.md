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

---

## 2026-04-07 — M6 Layer 3: LSP Server

### What was built

Language Server Protocol (LSP) server for RUNE providing real-time diagnostics, go-to-definition, hover, and completions. Works with VS Code, Neovim, Helix, Zed, and any LSP-compatible editor. Handles invalid and incomplete source gracefully — never panics on malformed input.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added tower-lsp, tokio, serde_json deps; declared rune-lsp binary | +12 lines |
| src/lib.rs | Added lsp module | +1 line |
| src/lsp/mod.rs | RuneLanguageServer, diagnostics, hover, goto-def, completions | New file, ~450 lines |
| src/lsp/tests.rs | 27 LSP tests | New file, ~200 lines |
| src/bin/rune-lsp.rs | LSP server binary entry point (tokio + tower-lsp) | New file, ~12 lines |
| tools/vscode-rune/package.json | Added activation events, main, LSP client dependency | Updated |
| tools/vscode-rune/extension.js | VS Code language client connecting to rune-lsp | New file, ~40 lines |

### Architecture

**RuneLanguageServer** (tower-lsp LanguageServer):
- TextDocumentSyncKind::Full — receives full document on every change
- document_map: stores open document contents
- Diagnostics: runs check_source on every edit, wraps in catch_unwind for safety
- Hover: keyword documentation (30+ keywords) + declaration info from parsed AST
- Go-to-definition: parses file, finds declaration span, converts to LSP Location
- Completions: keyword completions (40+ items) + identifier completions from file

**rune-lsp binary**: tokio + tower-lsp stdin/stdout transport, separate from CLI

**VS Code extension**: spawns rune-lsp, connects via vscode-languageclient

### Test results

```
cargo build: clean, 0 warnings
cargo test: 572 passed (564 lib + 8 CLI), 0 failed
```

### New LSP tests (27 tests)

| Test | What it covers |
|------|---------------|
| test_find_word_at_identifier | Word extraction at identifier |
| test_find_word_at_keyword | Word extraction at keyword |
| test_find_word_at_type | Word extraction at type name |
| test_find_word_at_whitespace_returns_none | Whitespace → None |
| test_find_word_at_operator_returns_none | Operator → None |
| test_find_word_at_start_of_line | Start of line |
| test_find_word_at_end_of_line | End of line |
| test_find_word_past_end_returns_none | Past end → None |
| test_find_word_empty_line_returns_none | Empty line → None |
| test_find_word_multiline | Multi-line source |
| test_diagnostic_line_column_conversion | 1-based → 0-based |
| test_diagnostics_multiple_errors | Multiple errors |
| test_diagnostics_valid_source_zero_diagnostics | Clean source → 0 diags |
| test_diagnostics_invalid_source_has_error | Bad source → ERROR diag |
| test_keyword_hover_policy | "policy" → docs |
| test_keyword_hover_permit | "permit" → docs |
| test_keyword_hover_deny | "deny" → docs |
| test_keyword_hover_escalate | "escalate" → docs |
| test_keyword_hover_quarantine | "quarantine" → docs |
| test_keyword_hover_unknown_returns_none | Unknown → None |
| test_keyword_hover_types | Int/Float/Bool/String → docs |
| test_keyword_completions_contains_governance | All governance keywords |
| test_keyword_completions_contains_type_keywords | Type keywords present |
| test_completion_item_kinds | KEYWORD vs STRUCT kinds |
| test_identifier_completions_from_source | File declarations in completions |
| test_identifier_completion_kinds | FUNCTION vs MODULE kinds |
| test_identifier_completions_invalid_source_returns_empty | Bad source → empty |

### Pillars served

- **Security Baked In:** Real-time diagnostics catch governance errors as developers type — before code is committed or compiled. The same check_source pipeline runs in the editor.
- **Zero Trust Throughout:** The LSP reuses the compiler's lexer, parser, and type checker. No separate or weaker validation path.
- **Assumed Breach:** catch_unwind wraps all compilation — malformed input cannot crash the server. Internal errors are reported as diagnostics.
- **No Single Points of Failure:** The LSP is a separate binary (rune-lsp) working with any LSP-compatible editor. VS Code extension is provided but not required.

---

## 2026-04-07 — M6 Layer 4: Package Manifest, Project Scaffolding, Documentation Generator

### What was built

Project ecosystem tooling for RUNE: `rune.toml` manifest format defining project metadata and build configuration, `rune new` scaffolding command for instant project creation, `rune doc` documentation generator that extracts comments from source and produces Markdown, and project-aware `build`/`check` commands that find `rune.toml` and default to `src/main.rune`.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added serde and toml dependencies | +2 lines |
| src/lib.rs | Added manifest and docgen modules | +2 lines |
| src/manifest/mod.rs | RuneManifest, PackageSection, BuildSection, validation, TOML serialization | New file, ~200 lines |
| src/manifest/tests.rs | 11 manifest tests | New file, ~170 lines |
| src/docgen/mod.rs | Doc extraction from AST, Markdown rendering | New file, ~260 lines |
| src/docgen/tests.rs | 13 docgen tests | New file, ~170 lines |
| src/main.rs | Added new/doc subcommands, project-aware build/check, find_manifest | +120 lines |
| tests/cli_tests.rs | 3 new CLI integration tests (new, new-exists, doc) | +70 lines |

### Architecture

**Package manifest (rune.toml)**:
- [package]: name, version, edition (default "2026"), description, authors, license
- [build]: target (wasm/native), optimization (debug/release), graduation_level (bronze/silver/gold/platinum)
- Validation: name (lowercase alphanumeric + hyphens), semver version, valid graduation level, valid edition
- Round-trip: from_file/from_str → RuneManifest → to_toml_string

**Project scaffolding (`rune new`)**:
- Creates project-name/ with rune.toml, src/main.rune, README.md
- Starter main.rune: Bronze-level access control policy
- Error handling: directory-exists check, creation failure reporting

**Project-aware commands**:
- find_manifest(): walks up directory tree looking for rune.toml
- `rune build` / `rune check` without file argument: finds rune.toml, builds src/main.rune
- Prints project name from manifest in output

**Documentation generator (`rune doc`)**:
- Parses .rune source, walks AST, extracts doc comments from lines above declarations
- DocItem: name, kind (Policy/Rule/Function/Type/Struct/Enum), doc_comment, signature, children, line_number
- Children: rules inside policies, fields inside structs, variants inside enums
- Markdown output: title, table of contents with anchors, code blocks for signatures, doc comments as descriptions
- --stdout flag for piping, otherwise writes <file>.md

### Test results

```
cargo build: clean, 0 warnings
cargo test: 600 passed (589 lib + 11 CLI), 0 failed
```

### New tests (24 unit + 3 CLI = 27 tests)

**Manifest tests (11)**:

| Test | What it covers |
|------|---------------|
| test_parse_full_manifest | All fields parsed correctly |
| test_parse_minimal_manifest | Only name + version, defaults applied |
| test_default_new_has_correct_values | edition 2026, bronze, wasm, debug |
| test_invalid_name_uppercase | Uppercase → InvalidName |
| test_invalid_name_spaces | Spaces → InvalidName |
| test_invalid_name_starts_with_digit | Digit start → InvalidName |
| test_invalid_graduation_level | "diamond" → InvalidGraduationLevel |
| test_invalid_version | Non-semver → InvalidVersion |
| test_round_trip | default_new → to_toml_string → from_str roundtrip |
| test_from_file_nonexistent_returns_io_error | Missing file → IoError |
| test_validate_catches_empty_name | Empty name → InvalidName |
| test_invalid_edition | "abc" → InvalidEdition |

**Docgen tests (13)**:

| Test | What it covers |
|------|---------------|
| test_extract_docs_policy_with_comment | Policy + doc comment extraction |
| test_extract_docs_function_with_comment | Function + doc comment extraction |
| test_extract_docs_no_comment | Declaration without comment → None |
| test_extract_children_rules_inside_policy | Rules as policy children |
| test_extract_struct_fields_as_children | Struct fields as children |
| test_render_markdown_table_of_contents | ToC with links |
| test_render_markdown_code_blocks | Signatures in code blocks |
| test_render_markdown_doc_comments | Doc comments in output |
| test_empty_source_produces_empty_docs | Empty → empty |
| test_invalid_source_produces_empty_docs | Bad source → empty |
| test_multiline_doc_comment | Multi-line // comments joined |
| test_extract_enum_variants | Enum variants as children |
| test_render_empty_items | Empty items → "No documented items" |

**CLI integration tests (3)**:

| Test | What it covers |
|------|---------------|
| test_cli_new_creates_project | Creates rune.toml, src/main.rune, README.md |
| test_cli_new_fails_if_exists | Directory exists → exit 1 |
| test_cli_doc_generates_markdown | Generates .md with doc comments |

### Pillars served

- **Security Baked In:** The graduation_level in rune.toml defines the language subset available to each project. Bronze projects cannot use advanced features, enforcing a safe on-ramp.
- **Zero Trust Throughout:** `rune doc` reuses the compiler's lexer and parser — documentation cannot be generated from invalid source. No silent failures.
- **Assumed Breach:** Project-aware commands validate the manifest before using it. Invalid names, versions, and graduation levels are rejected with clear errors.
- **No Single Points of Failure:** The manifest format, docgen, and scaffolding are all library functions and CLI commands. Both interfaces are available for different integration needs.
