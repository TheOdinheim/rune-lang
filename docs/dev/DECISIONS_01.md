# Decisions Log 01

## D001 — 2026-04-03: Documentation-first approach

**Decision:** Initialize all development documentation before writing any compiler code.

**Rationale:** Captures architectural intent and decision history from day one. Prevents knowledge loss across sessions. Living documents (BUILD_LOG, DECISIONS, TROUBLESHOOTING, PROGRESS) provide continuity.

**Pillars served:** Security Baked In (audit trail of decisions), Assumed Breach (documented rationale enables review).

## D002 — 2026-04-03: Hand-written recursive descent parser (not parser generator)

**Decision:** M1 uses a hand-written recursive descent parser, not a parser generator (pest, lalrpop, nom, etc.).

**Rationale:** Per architecture docs — hand-written parser gives full control over error recovery, diagnostic quality, and incremental parsing for the future LSP server. Parser generators constrain error messages and make source location tracking harder. Rust, Go, Swift, and most production compilers use hand-written parsers for these reasons.

**Pillars served:** Security Baked In (precise error diagnostics prevent miscompilation), Zero Trust Throughout (no implicit trust in generated parser correctness).

## D003 — 2026-04-03: Defer string interning to post-M1

**Decision:** `IntLiteral(String)`, `FloatLiteral(String)`, `StringLiteral(String)`, and `Identifier(String)` each heap-allocate per token. We accept this for M1 and plan to introduce string interning before M2.

**Rationale:** String interning (a global table mapping strings to small integer IDs) eliminates redundant allocations and makes token comparison O(1). Not needed for M1's correctness goals, but will be required for acceptable performance on large codebases. Premature optimization now would add complexity to the lexer before the API is stable.

**Action:** Introduce an `Interner` (or use an existing crate like `string_interner`) when beginning M2 or when profiling shows allocation pressure.

**Pillars served:** No Single Points of Failure (interning prevents unbounded memory growth on adversarial inputs).

## D004 — 2026-04-03: Generic angle bracket disambiguation deferred to parser

**Decision:** The lexer produces the same `LeftAngle`/`RightAngle` tokens for both comparison operators (`<`, `>`) and generic type delimiters (`Vec<T>`, `AttestedModel<Signer, Policy>`). Disambiguation is the parser's responsibility.

**Rationale:** This is the standard approach used by Rust, C++, Swift, and most languages with both generics and comparison operators. The lexer cannot distinguish these without contextual knowledge of whether an expression or type is being parsed. Attempting to disambiguate in the lexer would violate the single-pass constraint and couple the lexer to parser state.

**Pillars served:** Security Baked In (clean separation of concerns reduces misclassification bugs).

## D005 — 2026-04-03: FnSignature effects field uses Vec<Path> for DSL phase

**Decision:** The `effects` field on `FnSignature` is typed as `Vec<Path>`, meaning effect annotations reference effect declarations by path (e.g., `with effects { io, network }`).

**Rationale:** For the DSL phase (M1-M6), path references to named effect declarations are sufficient. The effect system at this level verifies that declared effects exist and that functions don't perform undeclared effects. When the full effect system gets type-level tracking in M2, this field may evolve to carry richer type information (e.g., effect parameters, effect polymorphism, effect row types). Vec<Path> is the correct starting representation that doesn't prematurely constrain the design.

**Future consideration:** If RUNE adds effect polymorphism (functions generic over which effects they perform), this field will need to become a more expressive type like `Vec<EffectExpr>` where `EffectExpr` can represent both concrete effect paths and effect type variables.

**Pillars served:** Security Baked In (effect tracking is the enforcement mechanism for this pillar).

## D006 — 2026-04-03: Pratt parsing for expression precedence

**Decision:** Use Pratt parsing (precedence climbing) for all expression parsing rather than a grammar-rule-per-precedence-level approach.

**Rationale:** Pratt parsing handles arbitrary precedence levels in a single function with a precedence table, rather than requiring N mutually recursive functions (one per precedence level). This is cleaner, easier to extend when adding new operators, and matches how production compilers (rustc, V8) handle expression parsing. Our 11 precedence levels and 17 binary operators are handled by one `parse_expr_bp` function and a lookup table.

**Pillars served:** Security Baked In (simpler code = fewer bugs in precedence handling).

## D007 — 2026-04-03: `self` accepted as identifier in parameter and expression positions

**Decision:** The parser accepts the `SelfValue` keyword token as a valid identifier in parameter names and expression positions, mapping it to the string "self".

**Rationale:** `self` is both a keyword (for the type system) and a valid name in method parameters (`fn method(self: Self)`). Rather than complicating the lexer, we handle this in the parser where context makes the distinction clear. This mirrors Rust's approach.
