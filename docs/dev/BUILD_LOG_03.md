# Build Log 03

## 2026-04-06 — M4 Layer 1: Refinement Type Syntax and AST Extensions

### What was built

Refinement type syntax — types with compile-time governance predicates. This is the foundation for SMT-verified policy constraints: `type RiskModel = Model where { bias_audit == true, data_retention <= 30 }`. Extended the lexer, AST, and parser to support refinement types on type aliases, function parameters, and standalone `require` assertions.

### Files modified / created

| File | Purpose | Changes |
|------|---------|---------|
| src/lexer/token.rs | Added Where, Satisfies, Not keywords + keyword_from_str entries | +10 lines |
| src/ast/nodes.rs | RefinementPredicate, RefinementOp, RefinementValue, WhereClause, TypeExprKind::Refined, ExprKind::Require, ItemKind::TypeConstraint, TypeConstraintDecl | +65 lines |
| src/parser/types.rs | parse_type_expr wraps base with where clause, parse_where_clause, parse_refinement_predicate, parse_refinement_op, parse_refinement_value, parse_refinement_scalar, parse_refinement_list, parse_predicate_block | +130 lines |
| src/parser/parser.rs | parse_type_decl dispatches TypeAlias vs TypeConstraint based on where clause | +20 lines |
| src/parser/expr.rs | parse_require_expr for `require expr satisfies { ... }` | +15 lines |
| src/parser/tests.rs | 15 new tests for refinement syntax | +190 lines |
| src/types/checker.rs | TypeConstraint registration (resolves to base type), Require → Bool | +15 lines |
| src/types/context.rs | TypeExprKind::Refined resolves to base type | +3 lines |
| src/ir/lower.rs | Refined type mapping, Require fallback | +3 lines |

### Refinement type syntax

| Syntax | AST node | Example |
|--------|----------|---------|
| `type N = T where { ... };` | ItemKind::TypeConstraint | `type RiskModel = Model where { bias_audit == true };` |
| `param: T where { ... }` | TypeExprKind::Refined | `fn deploy(m: Model where { certified == true })` |
| `require e satisfies { ... }` | ExprKind::Require | `require model satisfies { bias_audit == true }` |

### Refinement predicate structure

Each predicate is `field op value` where:
- **field**: identifier (struct field name)
- **op**: `==`, `!=`, `<`, `>`, `<=`, `>=`, `in`, `not in`
- **value**: Bool, Int, Float, String, or List (for in/not-in)

### New keywords

| Keyword | Token | Purpose |
|---------|-------|---------|
| `where` | Where | Introduces refinement predicate block |
| `satisfies` | Satisfies | Links target expression to predicate block in `require` |
| `not` | Not | Used in `not in` operator |

### Test results

```
cargo build: clean, 0 warnings
cargo test: 390 passed (49 lexer + 102 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program + 24 ir + 31 codegen + 18 compiler), 0 failed
```

### New parser tests (15 tests)

| Test | What it covers |
|------|---------------|
| test_refinement_type_alias_basic | Two predicates: == bool, <= int |
| test_refinement_type_in_list | `in ["limited", "minimal"]` list membership |
| test_refinement_type_not_in | `not in [...]` exclusion operator |
| test_refinement_type_all_comparison_ops | All 6 comparison operators in one type |
| test_refinement_type_negative_value | Negative integer: `< -10` |
| test_refinement_type_float_value | Float predicate: `<= 0.05` |
| test_refinement_type_string_value | String predicate: `== "approved"` |
| test_refinement_param_type | Refinement type on function parameter |
| test_require_satisfies_expr | `require model satisfies { ... }` expression |
| test_require_satisfies_single_predicate | Single predicate require |
| test_refinement_empty_where_clause | Empty where clause: `where {}` |
| test_plain_type_alias_still_works | Plain alias unaffected by changes |
| test_refinement_trailing_comma | Trailing comma after last predicate |
| test_require_in_policy_rule | require inside policy rule body |
| test_where_keyword_lexes | where, satisfies, not keyword recognition |

### Pillars served

- **Security Baked In:** Refinement types carry governance constraints as part of the type system. The `where` clause syntax is the foundation for compile-time SMT verification of policy predicates — constraints that will be checked before code ever executes.
- **Zero Trust Throughout:** The `require expr satisfies { ... }` expression enables explicit verification of values against predicates. No implicit trust — every model, config, or artifact can be checked against its declared constraints.
- **Assumed Breach:** Refinement predicates on function parameters mean callers must prove compliance at call sites. A function accepting `Model where { certified == true }` cannot be called with an uncertified model.
- **No Single Points of Failure:** Type constraints are reusable (`type RiskModel = Model where { ... }`) — a single predicate set can guard multiple functions, preventing inconsistent checks across the codebase.
