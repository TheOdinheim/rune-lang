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

---

## 2026-04-08 — M7 Layer 2: Module-Scoped Name Resolution, Visibility Enforcement, Use Imports

### What was built

The type checker's symbol table now supports module scopes. Inline modules create `Symbol::Module` entries containing their own symbol tables and visibility maps. Qualified paths (`crypto::verify`, `a::b::c`) resolve through module chains. Visibility is enforced — private items are inaccessible from outside their module with helpful error messages. Use imports (`use`, `use as`, `use *`) bring module symbols into the current scope. Effects and capabilities propagate across module boundaries unchanged.

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/types/scope.rs | Added `Symbol::Module` variant with symbols, visibility_map; `current_scope_bindings()` method | +20 lines |
| src/types/context.rs | Unchanged — module path resolution handled in checker | 0 lines |
| src/types/checker.rs | Module registration, use import resolution, qualified path resolution, visibility enforcement | +250 lines |
| src/types/mod.rs | Added module_tests module | +3 lines |
| src/types/module_tests.rs | 29 new module system tests | New file, ~350 lines |

### Architecture

**Symbol::Module:**
- `symbols: HashMap<String, Symbol>` — all declarations in the module
- `visibility_map: HashMap<String, Visibility>` — tracks which symbols are pub
- Created by snapshotting the scope after checking all items inside the module body
- File-based modules (`mod name;`) register as empty placeholders (file loading deferred to M7 L3)

**Module registration (two-pass within modules):**
1. Enter a new scope, register all items (Pass 1), check all bodies (Pass 2)
2. Snapshot the scope's symbols and build a visibility map from the items
3. Exit the scope and register `Symbol::Module` in the parent scope
4. This is recursive — nested modules are handled naturally

**Qualified path resolution (`resolve_qualified_path`):**
- Walks module segments left to right, checking each intermediate module exists
- Checks visibility at each step — private intermediate modules block resolution
- Final segment looked up as a symbol in the target module, visibility checked
- Returns the symbol's type for use in expression type checking

**Visibility enforcement:**
- Private items: type error with message including `add 'pub'` suggestion
- Check existence first, then visibility (avoids false "private" for missing items)
- Private nested modules block access to their contents even if inner items are pub

**Use import resolution:**
- `UseKind::Single`: resolve path, check visibility, alias in current scope
- `UseKind::Glob`: resolve module path, import all public symbols, skip private silently
- Glob conflicts with existing names produce type errors
- `UseKind::Module`: no-op (module name already registered)
- `pub use`: re-export handled by marking imported name in visibility map

**Cross-module effect and capability propagation:**
- No module-specific changes needed — effects and capabilities are properties of `Symbol::Function`
- When a qualified call resolves to a function, its effects propagate to the caller
- `lookup_fn_extras_from_path` walks module chain to find `required_capabilities` and `param_refinements`

**Backward compatibility:**
- Root file scope is implicit — all top-level declarations live in it
- Code without `mod`/`use` works exactly as before: `ScopeStack` lookup unchanged
- `register_item` now handles `ItemKind::Module` and `ItemKind::Use` instead of skipping them

### Test results

```
cargo build: clean, 0 warnings
cargo test: 669 passed (658 lib + 11 CLI), 0 failed
All 640 pre-existing tests pass unchanged.
```

### New module system tests (29 tests)

| Test | What it covers |
|------|---------------|
| test_module_public_function_accessible | `pub fn` in module callable via qualified path |
| test_module_private_function_error | Private fn in module → type error |
| test_nested_modules | `a::b::inner()` resolves through nested modules |
| test_module_mixed_visibility | Public accessible, private not, in same module |
| test_private_item_error_message_has_add_pub | Error suggests `add 'pub'` |
| test_qualified_path_call | `math::add(1, 2)` resolves and type-checks |
| test_multi_segment_path | `a::b::c()` resolves through module chain |
| test_nonexistent_module_error | "module not found" error |
| test_nonexistent_function_in_module_error | "not found in module" error |
| test_self_path_resolves | `self::helper()` resolves in current scope |
| test_super_path_resolves | `super::helper()` resolves to parent scope |
| test_use_single_import | `use crypto::verify;` then `verify()` works |
| test_use_alias_import | `use crypto::verify as v;` then `v()` works |
| test_use_glob_import | `use crypto::*;` imports all public items |
| test_use_glob_skips_private | Glob skips private items silently |
| test_use_glob_conflict_with_existing_name | Glob conflict → type error |
| test_use_private_item_error | `use` of private item → type error |
| test_pub_use_reexport | `pub use` re-exports item |
| test_cross_module_effect_propagation | Effectful module fn → effect error in pure caller |
| test_cross_module_effect_allowed | Effectful module fn → OK when caller declares effects |
| test_no_modules_works_as_before | Flat scope code unchanged |
| test_flat_scope_policies_still_work | Policies without modules unchanged |
| test_flat_scope_types_still_work | Types without modules unchanged |
| test_module_function_type_checks_body | Type errors inside module bodies caught |
| test_qualified_call_type_mismatch | Wrong arg type in qualified call |
| test_qualified_call_arity_mismatch | Wrong arity in qualified call |
| test_private_module_nested | Private nested module blocks access |
| test_pub_nested_module_accessible | `pub mod` nested module accessible |
| test_module_file_based_placeholder | `mod crypto;` registers without error |

### Pillars served

- **Security Baked In:** Visibility enforcement prevents accidental exposure of internal governance logic. Private policy helpers, internal types, and utility functions cannot be accessed from outside their module without explicit `pub`.
- **Zero Trust Throughout:** Every cross-module reference goes through visibility checking. Effects and capabilities propagate transparently — a function in module A that calls module B still has its effects verified. No implicit trust across module boundaries.
- **Assumed Breach:** Error messages are governance-aware: "add `pub` to make it accessible" guides developers toward explicit visibility. Module boundaries create isolation zones — a compromised module's private internals are inaccessible.
- **No Single Points of Failure:** Module scopes allow organizing governance policies across files and teams. `pub use` re-exports enable curated public APIs from submodules. Glob imports provide convenient access patterns without sacrificing encapsulation.
