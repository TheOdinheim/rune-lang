# Build Log 07

## 2026-04-09 — M8 Layer 1: FFI Syntax, Extern Blocks, FFI Effect Enforcement, Audit Instrumentation

### What was built

Foreign Function Interface (FFI) frontend for RUNE: `extern` blocks declaring C-compatible function signatures, standalone `extern fn` sugar, ABI string parsing ("C" only), automatic `ffi` effect on all extern functions with transitive enforcement, IR audit instrumentation (FfiCallStart/FfiCallEnd markers around every FFI call), plus toolchain updates (tree-sitter, formatter, LSP, docgen).

### Four-pillar alignment

- **Security Baked In**: FFI calls require explicit `ffi` effect declaration — no silent boundary crossing
- **Assumed Breach**: Every FFI call bracketed with FfiCallStart/FfiCallEnd audit marks for traceability
- **Zero Trust Throughout**: Transitive effect enforcement — callers of FFI callers must also declare `ffi`
- **No Single Points of Failure**: ABI validation rejects unsupported ABIs at parse time

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/lexer/token.rs | `Extern` keyword variant + keyword_from_str entry | +2 lines |
| src/ast/nodes.rs | ExternBlock, ExternFnDecl structs, ItemKind::Extern variant | +20 lines |
| src/parser/parser.rs | parse_extern_block, parse_extern_fn_decl, synchronize/dispatch | ~80 lines |
| src/types/checker.rs | register_extern_block (ffi effect), visibility map, check_item | ~30 lines |
| src/ir/nodes.rs | AuditKind::FfiCallStart/FfiCallEnd variants + Display | +6 lines |
| src/ir/lower.rs | extern_functions HashSet, FfiCallStart/End around extern calls | ~25 lines |
| src/formatter/mod.rs | format_extern_block (standalone + block form) | ~50 lines |
| tools/tree-sitter-rune/grammar.js | extern_block, extern_fn_declaration rules | ~20 lines |
| tools/tree-sitter-rune/queries/highlights.scm | extern keyword + extern_fn_declaration highlight | +2 lines |
| src/lsp/mod.rs | extern keyword hover, extern fn completions/hover/go-to-def | ~30 lines |
| src/docgen/mod.rs | DocItemKind::ExternFunction, extern extraction + rendering | ~40 lines |

### Architecture

**Extern block parsing:**
- Block form: `extern { fn sha256(data: Int) -> Int; fn md5(data: Int) -> Int; }`
- Standalone sugar: `extern fn sha256(data: Int) -> Int;` (desugars to single-fn block)
- ABI string: `extern "C" { ... }` — only "C" accepted, others rejected at parse time
- Extern fn declarations have no body — parser errors if `{` found after params
- `pub extern` propagates visibility to all contained functions

**FFI effect enforcement:**
- All extern functions registered as `Symbol::Function` with `effects: vec!["ffi"]`
- Existing M2 Layer 3 `check_callee_effects()` infrastructure handles enforcement automatically
- Callers must declare `with effects { ffi }` or get a clear error message
- Transitive: if `hash()` calls extern `sha256()`, then callers of `hash()` also need `ffi`

**IR audit instrumentation:**
- `AuditKind::FfiCallStart { function_name }` emitted before every extern call
- `AuditKind::FfiCallEnd { function_name }` emitted after every extern call
- Lowerer tracks extern function names in `extern_functions: HashSet<String>`
- WASM codegen handles new variants via existing AuditMark wildcard (nop)

### Test summary

24 new tests added (741 total, up from 717):

| Area | Tests | What's covered |
|------|-------|----------------|
| Lexer | 4 | extern keyword, extern fn tokens, block tokens, ABI string |
| Parser | 10 | single/multi fn blocks, standalone, ABI, pub, no-return, no-params, errors |
| Type checker | 12 | registration, callable, ffi effect required, transitive, module integration |
| Formatter | 4 | standalone, block, ABI, idempotent |
| LSP | 3 | keyword hover, completions, hover info |
| Docgen | 2 | extraction, markdown rendering |
| IR | 3 | FfiCallStart/End marks, non-extern no marks, display |

### Decisions

- **Reused Symbol::Function for extern fns** rather than adding new Symbol variant. The `effects: vec!["ffi"]` field leverages existing effect checking — zero new enforcement code needed.
- **Formatter uses block form when ABI present** even for single functions. Standalone sugar only applies to `extern fn name(...);` without ABI string.
- **No new WASM codegen changes needed** — AuditMark wildcard match already handles new FfiCallStart/FfiCallEnd as nops.
