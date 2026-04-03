# Troubleshooting Log 01

## Template

Each entry follows this format:

### TXXX — Date: Brief description

**Symptom:** What was observed.

**Cause:** Root cause identified.

**Fix:** What resolved it.

**Prevention:** How to avoid it in the future.

---

### T001 — 2026-04-03: `self` keyword rejected as parameter name in parser

**Symptom:** Three parser tests failed (test_trait_definition, test_trait_with_default_method, test_impl_trait_for_type) with error: "expected identifier, found SelfValue".

**Cause:** The lexer tokenizes `self` as `TokenKind::SelfValue` (a keyword), but `expect_identifier()` only accepted `TokenKind::Identifier`. Method parameters like `self: Self` need `self` to be valid in identifier position.

**Fix:** Extended `expect_identifier()` to accept `SelfValue` and map it to the string `"self"`. Also added `SelfValue` handling in `parse_prefix()` for expression positions (e.g., `{ self }` in method bodies).

**Prevention:** When adding keywords that can also serve as identifiers in certain positions, remember to handle them in `expect_identifier()` from the start. Consider a "contextual keyword" pattern if more cases arise.
