# Decisions Log 01

## D001 — 2026-04-03: Documentation-first approach

**Decision:** Initialize all development documentation before writing any compiler code.

**Rationale:** Captures architectural intent and decision history from day one. Prevents knowledge loss across sessions. Living documents (BUILD_LOG, DECISIONS, TROUBLESHOOTING, PROGRESS) provide continuity.

**Pillars served:** Security Baked In (audit trail of decisions), Assumed Breach (documented rationale enables review).

## D002 — 2026-04-03: Hand-written recursive descent parser (not parser generator)

**Decision:** M1 uses a hand-written recursive descent parser, not a parser generator (pest, lalrpop, nom, etc.).

**Rationale:** Per architecture docs — hand-written parser gives full control over error recovery, diagnostic quality, and incremental parsing for the future LSP server. Parser generators constrain error messages and make source location tracking harder. Rust, Go, Swift, and most production compilers use hand-written parsers for these reasons.

**Pillars served:** Security Baked In (precise error diagnostics prevent miscompilation), Zero Trust Throughout (no implicit trust in generated parser correctness).
