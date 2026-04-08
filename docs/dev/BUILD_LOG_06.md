# Build Log 06

## 2026-04-08 — M7 Layer 1: Module Syntax, Visibility, Use Imports, Qualified Paths

### What was built

Module system frontend for RUNE: `pub` visibility on all declaration types, `mod` declarations (inline and file-based), `use` imports with glob and alias support, qualified paths with `self::` and `super::` prefixes. Pure parser and AST work — no name resolution or type checking yet.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/ast/nodes.rs | Visibility enum, UseKind enum, visibility field on 7 decl types | +30 lines |
| src/lexer/token.rs | Added Super keyword variant and keyword_from_str entry | +2 lines |
| src/parser/parser.rs | Visibility propagation, module/use parsing, path segments, glob lookahead | ~120 lines modified |
| src/parser/expr.rs | self::/super:: qualified path expressions | +25 lines |
| src/parser/tests.rs | 23 new M7 L1 parser tests | +350 lines |
| src/formatter/mod.rs | Visibility prefixes, inline module bodies, UseKind::Glob formatting | ~60 lines modified |
| src/formatter/tests.rs | 10 new M7 L1 formatter tests | +80 lines |
| tools/tree-sitter-rune/grammar.js | pub on all decls, inline modules, glob imports, self/super paths | ~30 lines modified |
| tools/tree-sitter-rune/queries/highlights.scm | Added "as", "self", "super" highlight rules | +3 lines |

### Architecture

**Visibility system:**
- `Visibility` enum: `Public` / `Private` (Default = Private)
- Added to PolicyDecl, StructDef, EnumDef, TypeAliasDecl, TypeConstraintDecl, ModuleDecl, UseDecl
- FnSignature retains its existing `is_pub: bool` for backward compatibility
- Parser reads optional `pub` before any declaration and propagates visibility

**Module declarations:**
- Inline: `mod crypto { fn verify() -> Bool { true } }` — body parsed recursively
- File-based: `mod crypto;` — placeholder for future file resolution
- Both support `pub mod`

**Use imports:**
- `use crypto::verify;` → UseKind::Single (multi-segment path)
- `use crypto::*;` → UseKind::Glob (glob import)
- `use crypto;` → UseKind::Module (single-segment path)
- `use crypto::verify as v;` → UseKind::Single with alias
- `pub use` re-exports supported

**Qualified paths:**
- `parse_path_segment()` accepts Identifier, SelfValue, or Super tokens
- `parse_path()` uses lookahead to stop before `::*` (glob handled by caller)
- Expression parser handles `self::helper` and `super::utils::hash` as ExprKind::Path

**Tree-sitter grammar updates:**
- `optional("pub")` added to policy, type alias, type constraint, mod, use declarations
- mod_declaration: `choice(";", seq("{", repeat($._item), "}"))` for inline bodies
- use_declaration: optional glob (`::*`) and alias (`as name`)
- `_path_segment`: `choice($.identifier, "self", "super")`
- Highlights: `"as" @keyword`, `"self" @variable.builtin`, `"super" @variable.builtin`

### Test results

```
cargo build: clean, 0 warnings
cargo test: 640 passed (629 lib + 11 CLI), 0 failed
```

### New parser tests (23 tests)

| Test | What it covers |
|------|---------------|
| test_parse_module_inline | `mod name { ... }` with body items |
| test_parse_module_file | `mod name;` file-based module |
| test_parse_pub_module | `pub mod name { ... }` |
| test_parse_nested_modules | `mod a { mod b { ... } }` |
| test_parse_use_single | `use crypto::verify;` |
| test_parse_use_glob | `use crypto::*;` |
| test_parse_use_alias | `use crypto::verify as v;` |
| test_parse_pub_use | `pub use crypto::verify;` |
| test_parse_use_module | `use crypto;` single-segment |
| test_parse_pub_policy | `pub policy name { ... }` |
| test_parse_pub_struct | `pub struct Name { ... }` |
| test_parse_pub_enum | `pub enum Name { ... }` |
| test_parse_pub_fn | `pub fn name() { ... }` |
| test_parse_pub_type_alias | `pub type Name = Type;` |
| test_parse_pub_trait | `pub trait Name { ... }` |
| test_parse_visibility_default_private | Default visibility is Private |
| test_parse_pub_before_rule_error | `pub rule` → error (rules are always private) |
| test_parse_self_path | `self::helper` as path expression |
| test_parse_super_path | `super::utils::hash` as path expression |
| test_parse_deep_path | `a::b::c::d` multi-segment path |
| test_parse_use_deep_path | `use a::b::c::d;` deep path |
| test_parse_self_in_use | `use self::helper;` |
| test_parse_super_in_use | `use super::utils::hash;` |

### New formatter tests (10 tests)

| Test | What it covers |
|------|---------------|
| test_module_inline_formatting | Inline module with indented body |
| test_module_file_formatting | `mod crypto;` file-based |
| test_pub_visibility_formatting | `pub fn` prefix |
| test_pub_policy_formatting | `pub policy` prefix |
| test_use_single_formatting | `use crypto::verify;` |
| test_use_glob_formatting | `use crypto::*;` |
| test_use_alias_formatting | `use crypto::verify as v;` |
| test_pub_use_formatting | `pub use crypto::verify;` |
| test_nested_module_formatting | Nested modules with correct indentation |
| test_pub_module_formatting | `pub mod` with body |

### Pillars served

- **Security Baked In:** Visibility control (`pub` / private) ensures governance declarations are not accidentally exposed. Modules enforce encapsulation boundaries for policy code.
- **Zero Trust Throughout:** Qualified paths (`self::`, `super::`) require explicit path resolution — no implicit name imports. Every reference will be traceable to its source module.
- **Assumed Breach:** The parser rejects invalid visibility placement (e.g., `pub rule` is an error — rules inherit policy visibility). Invalid syntax is caught at parse time with clear diagnostics.
- **No Single Points of Failure:** Module syntax supports both inline and file-based declarations, enabling multiple project organization strategies. Tree-sitter grammar updated for all editors.
