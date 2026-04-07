#[cfg(test)]
mod tests {
    use crate::ast::nodes::*;
    use crate::lexer::token::Span;
    use crate::smt::solver::{verify_predicates, SmtResult};

    fn dummy_span() -> Span {
        Span::new(0, 0, 0, 1, 1)
    }

    fn pred(field: &str, op: RefinementOp, value: RefinementValue) -> RefinementPredicate {
        RefinementPredicate {
            field: Ident::new(field.to_string(), dummy_span()),
            op,
            value,
            span: dummy_span(),
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // Basic satisfiability
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_predicates_satisfiable() {
        assert_eq!(verify_predicates(&[]), SmtResult::Satisfiable);
    }

    #[test]
    fn test_single_bool_predicate() {
        let preds = vec![pred("bias_audit", RefinementOp::Eq, RefinementValue::Bool(true))];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_single_int_predicate() {
        let preds = vec![pred("retention", RefinementOp::Le, RefinementValue::Int(30))];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_single_float_predicate() {
        let preds = vec![pred("score", RefinementOp::Lt, RefinementValue::Float(0.95))];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_single_string_predicate() {
        let preds = vec![pred(
            "category",
            RefinementOp::Eq,
            RefinementValue::String("high".to_string()),
        )];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple consistent predicates
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_consistent_predicates() {
        let preds = vec![
            pred("bias_audit", RefinementOp::Eq, RefinementValue::Bool(true)),
            pred("retention", RefinementOp::Le, RefinementValue::Int(30)),
            pred("certified", RefinementOp::Eq, RefinementValue::Bool(true)),
        ];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_int_range_consistent() {
        let preds = vec![
            pred("x", RefinementOp::Ge, RefinementValue::Int(0)),
            pred("x", RefinementOp::Le, RefinementValue::Int(100)),
        ];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    // ═════════════════════════════════════════════════════════════════
    // Contradictory predicates — UNSAT
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_contradictory_bool() {
        let preds = vec![
            pred("flag", RefinementOp::Eq, RefinementValue::Bool(true)),
            pred("flag", RefinementOp::Eq, RefinementValue::Bool(false)),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_contradictory_int() {
        let preds = vec![
            pred("x", RefinementOp::Gt, RefinementValue::Int(100)),
            pred("x", RefinementOp::Lt, RefinementValue::Int(50)),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_contradictory_string_eq() {
        let preds = vec![
            pred("category", RefinementOp::Eq, RefinementValue::String("high".into())),
            pred("category", RefinementOp::Eq, RefinementValue::String("low".into())),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_contradictory_eq_ne() {
        let preds = vec![
            pred("x", RefinementOp::Eq, RefinementValue::Int(42)),
            pred("x", RefinementOp::Ne, RefinementValue::Int(42)),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    // ═════════════════════════════════════════════════════════════════
    // In / NotIn membership tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_in_list_satisfiable() {
        let preds = vec![pred(
            "risk",
            RefinementOp::In,
            RefinementValue::List(vec![
                RefinementValue::String("limited".into()),
                RefinementValue::String("minimal".into()),
            ]),
        )];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_not_in_list_satisfiable() {
        let preds = vec![pred(
            "region",
            RefinementOp::NotIn,
            RefinementValue::List(vec![
                RefinementValue::String("banned".into()),
            ]),
        )];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_in_and_not_in_contradictory() {
        // x in [1, 2] AND x not in [1, 2] → UNSAT
        let preds = vec![
            pred(
                "x",
                RefinementOp::In,
                RefinementValue::List(vec![RefinementValue::Int(1), RefinementValue::Int(2)]),
            ),
            pred(
                "x",
                RefinementOp::NotIn,
                RefinementValue::List(vec![RefinementValue::Int(1), RefinementValue::Int(2)]),
            ),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_eq_and_not_in_contradictory() {
        // x == "high" AND x not in ["high", "critical"] → UNSAT
        let preds = vec![
            pred("x", RefinementOp::Eq, RefinementValue::String("high".into())),
            pred(
                "x",
                RefinementOp::NotIn,
                RefinementValue::List(vec![
                    RefinementValue::String("high".into()),
                    RefinementValue::String("critical".into()),
                ]),
            ),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    // ═════════════════════════════════════════════════════════════════
    // EU AI Act risk category encoding
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_eu_ai_act_high_risk_satisfiable() {
        let preds = vec![
            pred("risk_category", RefinementOp::Eq, RefinementValue::String("high".into())),
            pred("conformity_assessment", RefinementOp::Eq, RefinementValue::Bool(true)),
            pred("human_oversight", RefinementOp::Eq, RefinementValue::Bool(true)),
            pred("transparency_obligations", RefinementOp::Eq, RefinementValue::Bool(true)),
        ];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_eu_ai_act_limited_risk_satisfiable() {
        let preds = vec![
            pred("risk_category", RefinementOp::Eq, RefinementValue::String("limited".into())),
            pred("transparency_obligations", RefinementOp::Eq, RefinementValue::Bool(true)),
        ];
        assert_eq!(verify_predicates(&preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_eu_ai_act_contradictory_risk_categories() {
        let preds = vec![
            pred("risk_category", RefinementOp::Eq, RefinementValue::String("high".into())),
            pred("risk_category", RefinementOp::Eq, RefinementValue::String("minimal".into())),
        ];
        let result = verify_predicates(&preds);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_unsat_explanation_contains_constraints() {
        let preds = vec![
            pred("x", RefinementOp::Eq, RefinementValue::Int(1)),
            pred("x", RefinementOp::Eq, RefinementValue::Int(2)),
        ];
        let result = verify_predicates(&preds);
        if let SmtResult::Unsatisfiable(explanation) = result {
            assert!(explanation.contains("x == 1"));
            assert!(explanation.contains("x == 2"));
            assert!(explanation.contains("contradictory"));
        } else {
            panic!("expected Unsatisfiable, got {result:?}");
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration with type checker
    // ═════════════════════════════════════════════════════════════════

    /// Helper: lex + parse + type check, return errors.
    fn typecheck_errors(source: &str) -> Vec<String> {
        use crate::lexer::scanner::Lexer;
        use crate::parser::parser::Parser;
        use crate::types::checker::TypeChecker;
        use crate::types::context::TypeContext;

        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");

        let mut ctx = TypeContext::new();
        let mut checker = TypeChecker::new(&mut ctx);
        checker.check_source_file(&file);
        drop(checker);
        ctx.errors.iter().map(|e| e.message.clone()).collect()
    }

    #[test]
    fn test_checker_satisfiable_type_constraint() {
        let errors = typecheck_errors(
            "type Safe = Int where { bias_audit == true, retention <= 30 };",
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_checker_contradictory_type_constraint_error() {
        let errors = typecheck_errors(
            r#"type Impossible = Int where { risk == "high", risk == "low" };"#,
        );
        assert!(!errors.is_empty(), "expected type error for contradictory constraints");
        let msg = &errors[0];
        assert!(msg.contains("contradictory"), "error should mention contradictory: {msg}");
        assert!(msg.contains("Impossible"), "error should name the type: {msg}");
    }

    #[test]
    fn test_checker_contradictory_bool_constraint_error() {
        let errors = typecheck_errors(
            "type Bad = Int where { enabled == true, enabled == false };",
        );
        assert!(!errors.is_empty());
        assert!(errors[0].contains("contradictory"));
    }

    #[test]
    fn test_checker_satisfiable_param_refinement() {
        let errors = typecheck_errors(
            "fn deploy(model: Int where { certified == true }) -> Int { 42 }",
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_checker_contradictory_param_refinement_error() {
        let errors = typecheck_errors(
            "fn bad(x: Int where { val > 100, val < 50 }) -> Int { 0 }",
        );
        assert!(!errors.is_empty());
        assert!(errors[0].contains("contradictory"));
    }

    #[test]
    fn test_checker_require_satisfiable() {
        let errors = typecheck_errors(
            "fn check(m: Int) -> Bool { require m satisfies { x == true } }",
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_checker_require_contradictory_error() {
        let errors = typecheck_errors(
            r#"fn check(m: Int) -> Bool { require m satisfies { x == "a", x == "b" } }"#,
        );
        assert!(!errors.is_empty());
        assert!(errors[0].contains("contradictory"));
    }

    #[test]
    fn test_eu_ai_act_full_integration() {
        // Full RUNE source with EU AI Act risk categories as refinement types.
        let errors = typecheck_errors(r#"
type HighRiskAI = Int where {
    risk_category == "high",
    conformity_assessment == true,
    human_oversight == true,
    transparency_obligations == true,
};

type LimitedRiskAI = Int where {
    risk_category == "limited",
    transparency_obligations == true,
};

fn deploy_high_risk(system: HighRiskAI) -> Int { 1 }
fn deploy_limited(system: LimitedRiskAI) -> Int { 2 }
"#);
        assert!(errors.is_empty(), "EU AI Act types should be satisfiable: {errors:?}");
    }

    #[test]
    fn test_eu_ai_act_contradictory_integration() {
        let errors = typecheck_errors(r#"
type Impossible = Int where {
    risk_category == "high",
    risk_category == "minimal",
};
"#);
        assert!(!errors.is_empty(), "contradictory risk categories should produce error");
        assert!(errors[0].contains("Impossible"));
        assert!(errors[0].contains("contradictory"));
    }

    // ═════════════════════════════════════════════════════════════════
    // SMT implication checking (M4 Layer 3)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_implication_superset_implies_subset() {
        use crate::smt::solver::{check_implication, SmtResult};
        // caller: { certified == true, audited == true }
        // callee: { certified == true }
        // Superset implies subset → SAT
        let caller = vec![
            pred("certified", RefinementOp::Eq, RefinementValue::Bool(true)),
            pred("audited", RefinementOp::Eq, RefinementValue::Bool(true)),
        ];
        let callee = vec![
            pred("certified", RefinementOp::Eq, RefinementValue::Bool(true)),
        ];
        assert_eq!(check_implication(&caller, &callee), SmtResult::Satisfiable);
    }

    #[test]
    fn test_implication_exact_match() {
        use crate::smt::solver::{check_implication, SmtResult};
        let preds = vec![
            pred("x", RefinementOp::Eq, RefinementValue::Int(42)),
        ];
        assert_eq!(check_implication(&preds, &preds), SmtResult::Satisfiable);
    }

    #[test]
    fn test_implication_empty_caller_fails() {
        use crate::smt::solver::{check_implication, SmtResult};
        // No caller predicates cannot imply non-empty callee predicates.
        let callee = vec![
            pred("certified", RefinementOp::Eq, RefinementValue::Bool(true)),
        ];
        let result = check_implication(&[], &callee);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_implication_empty_callee_passes() {
        use crate::smt::solver::{check_implication, SmtResult};
        // Any caller predicates imply empty callee predicates.
        let caller = vec![
            pred("x", RefinementOp::Eq, RefinementValue::Int(1)),
        ];
        assert_eq!(check_implication(&caller, &[]), SmtResult::Satisfiable);
    }

    #[test]
    fn test_implication_weaker_does_not_imply_stronger() {
        use crate::smt::solver::{check_implication, SmtResult};
        // caller: { x <= 100 }
        // callee: { x <= 50 }
        // x <= 100 does NOT imply x <= 50 (e.g., x = 75)
        let caller = vec![pred("x", RefinementOp::Le, RefinementValue::Int(100))];
        let callee = vec![pred("x", RefinementOp::Le, RefinementValue::Int(50))];
        let result = check_implication(&caller, &callee);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_implication_stronger_implies_weaker() {
        use crate::smt::solver::{check_implication, SmtResult};
        // caller: { x <= 50 }
        // callee: { x <= 100 }
        // x <= 50 implies x <= 100
        let caller = vec![pred("x", RefinementOp::Le, RefinementValue::Int(50))];
        let callee = vec![pred("x", RefinementOp::Le, RefinementValue::Int(100))];
        assert_eq!(check_implication(&caller, &callee), SmtResult::Satisfiable);
    }

    #[test]
    fn test_implication_disjoint_fields_fails() {
        use crate::smt::solver::{check_implication, SmtResult};
        // caller: { audited == true }
        // callee: { certified == true }
        // Different fields — no implication.
        let caller = vec![pred("audited", RefinementOp::Eq, RefinementValue::Bool(true))];
        let callee = vec![pred("certified", RefinementOp::Eq, RefinementValue::Bool(true))];
        let result = check_implication(&caller, &callee);
        assert!(matches!(result, SmtResult::Unsatisfiable(_)));
    }

    #[test]
    fn test_implication_range_entailment() {
        use crate::smt::solver::{check_implication, SmtResult};
        // caller: { x >= 10, x <= 20 }
        // callee: { x >= 0, x <= 100 }
        // [10,20] ⊂ [0,100] → implication holds
        let caller = vec![
            pred("x", RefinementOp::Ge, RefinementValue::Int(10)),
            pred("x", RefinementOp::Le, RefinementValue::Int(20)),
        ];
        let callee = vec![
            pred("x", RefinementOp::Ge, RefinementValue::Int(0)),
            pred("x", RefinementOp::Le, RefinementValue::Int(100)),
        ];
        assert_eq!(check_implication(&caller, &callee), SmtResult::Satisfiable);
    }

    // ═════════════════════════════════════════════════════════════════
    // Call-site refinement verification (M4 Layer 3)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_call_matching_refined_param_passes() {
        // Caller passes value with matching refinement → no error.
        let errors = typecheck_errors(r#"
fn deploy(model: Int where { certified == true }) -> Int { 1 }
fn caller(m: Int where { certified == true }) -> Int { deploy(m) }
"#);
        assert!(errors.is_empty(), "matching refinement should pass: {errors:?}");
    }

    #[test]
    fn test_call_unrefined_arg_to_refined_param_error() {
        // Caller passes plain value to refined parameter → error.
        let errors = typecheck_errors(r#"
fn deploy(model: Int where { certified == true }) -> Int { 1 }
fn caller(m: Int) -> Int { deploy(m) }
"#);
        assert!(!errors.is_empty(), "unrefined arg to refined param should error");
        assert!(errors[0].contains("no refinement guarantees"), "error: {}", errors[0]);
    }

    #[test]
    fn test_call_superset_refinement_passes() {
        // Caller's value has superset of callee's predicates → passes.
        let errors = typecheck_errors(r#"
fn deploy(model: Int where { certified == true }) -> Int { 1 }
fn caller(m: Int where { certified == true, audited == true }) -> Int { deploy(m) }
"#);
        assert!(errors.is_empty(), "superset refinement should pass: {errors:?}");
    }

    #[test]
    fn test_call_weaker_refinement_error() {
        // Caller's value has weaker predicates than callee requires → error.
        let errors = typecheck_errors(r#"
fn deploy(model: Int where { score <= 50 }) -> Int { 1 }
fn caller(m: Int where { score <= 100 }) -> Int { deploy(m) }
"#);
        assert!(!errors.is_empty(), "weaker refinement should error");
        assert!(errors[0].contains("does not imply"), "error: {}", errors[0]);
    }

    #[test]
    fn test_type_constraint_subtype_of_base() {
        // TypeConstraint used where base type expected → passes (subtype).
        let errors = typecheck_errors(r#"
type SafeModel = Int where { certified == true };
fn accept_int(x: Int) -> Int { x }
fn caller(m: SafeModel) -> Int { accept_int(m) }
"#);
        assert!(errors.is_empty(), "TypeConstraint subtype of base should pass: {errors:?}");
    }

    #[test]
    fn test_base_type_used_where_type_constraint_expected_error() {
        // Plain base type used where TypeConstraint expected → error.
        let errors = typecheck_errors(r#"
type SafeModel = Int where { certified == true };
fn deploy(model: Int where { certified == true }) -> Int { 1 }
fn caller(m: Int) -> Int { deploy(m) }
"#);
        assert!(!errors.is_empty(), "base type where TypeConstraint expected should error");
        assert!(errors[0].contains("no refinement guarantees"), "error: {}", errors[0]);
    }

    #[test]
    fn test_multiple_refined_params() {
        // Function with multiple refined parameters, all satisfied.
        let errors = typecheck_errors(r#"
fn process(x: Int where { a == true }, y: Int where { b == true }) -> Int { 1 }
fn caller(p: Int where { a == true }, q: Int where { b == true }) -> Int { process(p, q) }
"#);
        assert!(errors.is_empty(), "multiple matching refined params should pass: {errors:?}");
    }

    #[test]
    fn test_chained_refinements() {
        // fn a requires { certified }, fn b requires { certified, audited },
        // b calls a → passes because b's param has superset.
        let errors = typecheck_errors(r#"
fn deploy(model: Int where { certified == true }) -> Int { 1 }
fn deploy_audited(model: Int where { certified == true, audited == true }) -> Int { deploy(model) }
"#);
        assert!(errors.is_empty(), "chained refinements should pass: {errors:?}");
    }

    #[test]
    fn test_disjoint_refinement_error() {
        // Caller has refinement on different field → error.
        let errors = typecheck_errors(r#"
fn deploy(model: Int where { certified == true }) -> Int { 1 }
fn caller(m: Int where { audited == true }) -> Int { deploy(m) }
"#);
        assert!(!errors.is_empty(), "disjoint refinement should error");
    }
}
