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
