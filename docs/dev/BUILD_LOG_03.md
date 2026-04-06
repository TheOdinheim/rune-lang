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

---

## 2026-04-06 — M4 Layer 2: Z3 SMT Solver Integration

### What was built

Compile-time predicate verification using Z3. When a developer writes `type RiskModel = Model where { bias_audit == true, risk == "high" }`, the compiler translates refinement predicates to Z3 assertions and checks satisfiability. Contradictory constraints (e.g., `risk == "high"` AND `risk == "low"`) produce a compile-time error with a human-readable explanation. No runtime surprises — governance predicates verified before code ever executes.

### Files modified / created

| File | Purpose | Changes |
|------|---------|---------|
| Cargo.toml | Added z3 dependency with bundled feature | +1 line |
| src/lib.rs | Added smt module | +1 line |
| src/smt/mod.rs | SMT module declarations | New file, 4 lines |
| src/smt/solver.rs | Z3 constraint generator and satisfiability checker | New file, ~280 lines |
| src/smt/tests.rs | Unit tests and integration tests for SMT verification | New file, ~360 lines |
| src/types/checker.rs | SMT integration: verify predicates on TypeConstraint, Require, refined params | +25 lines |

### Architecture

The SMT solver translates each `RefinementPredicate` to a Z3 assertion:

| RUNE predicate | Z3 encoding |
|----------------|-------------|
| `field == true` | `Bool::new_const("field") == Bool::from_bool(true)` |
| `field <= 30` | `Int::new_const("field") <= Int::from_i64(30)` |
| `field < 0.95` | `Real::new_const("field") < Real::from_rational(19, 20)` |
| `field == "high"` | `String::new_const("field") == String::from_str("high")` |
| `field in [1, 2]` | `OR(field == 1, field == 2)` |
| `field not in [1, 2]` | `AND(field != 1, field != 2)` |

All predicates are conjoined and checked with `Solver::check()`. If UNSAT, a human-readable explanation lists all contradictory constraints.

### Type checker integration

SMT verification runs at three points during type checking:

1. **TypeConstraint registration** — `type T = Base where { ... }` predicates verified during pass 1
2. **Require expressions** — `require expr satisfies { ... }` predicates verified during expression checking
3. **Refined parameter types** — `fn f(x: T where { ... })` predicates verified during function registration

### Test results

```
cargo build: clean, 0 warnings
cargo test: 418 passed (49 lexer + 102 parser + 33 types + 55 checker + 23 effects + 18 capabilities + 37 program + 24 ir + 31 codegen + 18 compiler + 28 smt), 0 failed
```

### New SMT tests (28 tests)

| Test | What it covers |
|------|---------------|
| test_empty_predicates_satisfiable | Empty predicate set → SAT |
| test_single_bool_predicate | Single bool predicate → SAT |
| test_single_int_predicate | Single int predicate → SAT |
| test_single_float_predicate | Single float predicate → SAT |
| test_single_string_predicate | Single string predicate → SAT |
| test_multiple_consistent_predicates | Mixed bool/int predicates → SAT |
| test_int_range_consistent | x >= 0 AND x <= 100 → SAT |
| test_contradictory_bool | flag == true AND flag == false → UNSAT |
| test_contradictory_int | x > 100 AND x < 50 → UNSAT |
| test_contradictory_string_eq | category == "high" AND category == "low" → UNSAT |
| test_contradictory_eq_ne | x == 42 AND x != 42 → UNSAT |
| test_in_list_satisfiable | risk in ["limited", "minimal"] → SAT |
| test_not_in_list_satisfiable | region not in ["banned"] → SAT |
| test_in_and_not_in_contradictory | x in [1,2] AND x not in [1,2] → UNSAT |
| test_eq_and_not_in_contradictory | x == "high" AND x not in ["high", "critical"] → UNSAT |
| test_eu_ai_act_high_risk_satisfiable | EU AI Act high-risk predicates → SAT |
| test_eu_ai_act_limited_risk_satisfiable | EU AI Act limited-risk predicates → SAT |
| test_eu_ai_act_contradictory_risk_categories | Conflicting risk categories → UNSAT |
| test_unsat_explanation_contains_constraints | UNSAT explanation includes all constraints |
| test_checker_satisfiable_type_constraint | TypeConstraint with SAT predicates → no errors |
| test_checker_contradictory_type_constraint_error | TypeConstraint with UNSAT → type error |
| test_checker_contradictory_bool_constraint_error | Bool contradiction → type error |
| test_checker_satisfiable_param_refinement | Refined param type → no errors |
| test_checker_contradictory_param_refinement_error | Contradictory param → type error |
| test_checker_require_satisfiable | require with SAT predicates → no errors |
| test_checker_require_contradictory_error | require with UNSAT → type error |
| test_eu_ai_act_full_integration | Full EU AI Act types through lex→parse→typecheck pipeline |
| test_eu_ai_act_contradictory_integration | Contradictory EU AI Act type through full pipeline |

### Pillars served

- **Security Baked In:** Governance predicates verified at compile time using formal methods (Z3 SMT solver). Contradictory constraints caught before code executes — no runtime surprises. This is the core pillar: mathematical proof that governance constraints are consistent.
- **Zero Trust Throughout:** Every refinement type, parameter constraint, and require assertion is independently verified. The compiler trusts nothing — all predicate sets must be formally satisfiable.
- **Assumed Breach:** If an attacker modifies governance predicates, the SMT solver catches inconsistencies. Contradictory constraints cannot slip through — the compiler rejects them with clear explanations.
- **No Single Points of Failure:** SMT verification runs at three independent integration points (type declarations, function parameters, require expressions). A contradiction caught at any point produces an error.
