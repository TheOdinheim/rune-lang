#[cfg(test)]
mod tests {
    use crate::ast::nodes::*;
    use crate::lexer::scanner::Lexer;
    use crate::lexer::token::Span;
    use crate::parser::parser::Parser;
    use crate::types::checker::TypeChecker;
    use crate::types::context::TypeContext;
    use crate::types::scope::Symbol;
    use crate::types::ty::Type;

    fn dummy_span() -> Span {
        Span::new(0, 0, 0, 1, 1)
    }

    /// Parse a source string into a SourceFile.
    fn parse(source: &str) -> SourceFile {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        file
    }

    /// Set up a TypeContext with a `consume(x: Int) -> ()` helper.
    fn setup_ctx() -> TypeContext {
        let mut ctx = TypeContext::new();
        let span = dummy_span();
        let int_ty = ctx.intern_type(Type::Int);
        let unit_ty = ctx.intern_type(Type::Unit);

        ctx.define(
            "consume",
            Symbol::Function {
                params: vec![int_ty],
                return_type: unit_ty,
                effects: vec![],
                required_capabilities: vec![],
                param_refinements: vec![vec![]],
                span,
            },
            span,
        )
        .unwrap();

        ctx.define(
            "make_resource",
            Symbol::Function {
                params: vec![],
                return_type: int_ty,
                effects: vec![],
                required_capabilities: vec![],
                param_refinements: vec![],
                span,
            },
            span,
        )
        .unwrap();

        ctx
    }

    /// Check source, return error messages.
    fn check_errors(source: &str) -> Vec<String> {
        let file = parse(source);
        let mut ctx = setup_ctx();
        let mut checker = TypeChecker::new(&mut ctx);
        checker.check_source_file(&file);
        ctx.errors.iter().map(|e| e.message.clone()).collect()
    }

    /// Check source, assert no errors.
    fn check_ok(source: &str) {
        let errors = check_errors(source);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    /// Check source, assert at least one error containing `needle`.
    fn check_err(source: &str, needle: &str) {
        let errors = check_errors(source);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "expected error containing '{needle}', got: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Parsing tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn parse_linear_type_annotation() {
        let file = parse("fn f(x: linear Int) -> () { consume(x) }");
        let ItemKind::Function(ref f) = file.items[0].kind else { panic!("expected fn") };
        match &f.signature.params[0].ty.kind {
            TypeExprKind::Qualified { linearity, inner } => {
                assert_eq!(*linearity, Linearity::Linear);
                assert!(matches!(inner.kind, TypeExprKind::Named { .. }));
            }
            other => panic!("expected Qualified, got {other:?}"),
        }
    }

    #[test]
    fn parse_affine_type_annotation() {
        let file = parse("fn f(x: affine Int) -> () { consume(x) }");
        let ItemKind::Function(ref f) = file.items[0].kind else { panic!("expected fn") };
        match &f.signature.params[0].ty.kind {
            TypeExprKind::Qualified { linearity, .. } => {
                assert_eq!(*linearity, Linearity::Affine);
            }
            other => panic!("expected Qualified, got {other:?}"),
        }
    }

    #[test]
    fn parse_linear_let_binding() {
        let file = parse("fn f() -> () { let x: linear Int = 42; consume(x) }");
        // Just verify it parses without error.
        assert!(!file.items.is_empty());
    }

    #[test]
    fn parse_affine_let_binding() {
        let file = parse("fn f() -> () { let x: affine Int = 42; consume(x) }");
        assert!(!file.items.is_empty());
    }

    #[test]
    fn parse_linear_tuple_type() {
        let file = parse("fn f(x: linear (Int, Int)) -> () { consume(x) }");
        let ItemKind::Function(ref f) = file.items[0].kind else { panic!("expected fn") };
        assert!(matches!(f.signature.params[0].ty.kind, TypeExprKind::Qualified { .. }));
    }

    // ═════════════════════════════════════════════════════════════════
    // Linear variable — must be consumed exactly once
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn linear_var_consumed_once_ok() {
        check_ok("fn f() -> () { let x: linear Int = 42; consume(x) }");
    }

    #[test]
    fn linear_var_never_consumed_error() {
        check_err(
            "fn f() -> () { let x: linear Int = 42; }",
            "linear variable `x` must be consumed exactly once",
        );
    }

    #[test]
    fn linear_var_consumed_twice_error() {
        check_err(
            "fn f() -> () { let x: linear Int = 42; consume(x); consume(x) }",
            "used after being consumed",
        );
    }

    #[test]
    fn linear_param_consumed_once_ok() {
        check_ok("fn f(x: linear Int) -> () { consume(x) }");
    }

    #[test]
    fn linear_param_never_consumed_error() {
        check_err(
            "fn f(x: linear Int) -> () { }",
            "linear variable `x` must be consumed exactly once",
        );
    }

    #[test]
    fn linear_param_consumed_twice_error() {
        check_err(
            "fn f(x: linear Int) -> () { consume(x); consume(x) }",
            "used after being consumed",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Affine variable — at most once
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn affine_var_consumed_once_ok() {
        check_ok("fn f() -> () { let x: affine Int = 42; consume(x) }");
    }

    #[test]
    fn affine_var_never_consumed_ok() {
        // Affine allows drop — no error.
        check_ok("fn f() -> () { let x: affine Int = 42; }");
    }

    #[test]
    fn affine_var_consumed_twice_error() {
        check_err(
            "fn f() -> () { let x: affine Int = 42; consume(x); consume(x) }",
            "used after being consumed",
        );
    }

    #[test]
    fn affine_param_consumed_twice_error() {
        check_err(
            "fn f(x: affine Int) -> () { consume(x); consume(x) }",
            "used after being consumed",
        );
    }

    #[test]
    fn affine_param_unused_ok() {
        check_ok("fn f(x: affine Int) -> () { }");
    }

    // ═════════════════════════════════════════════════════════════════
    // Unrestricted — no constraints
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn unrestricted_var_used_multiple_times_ok() {
        check_ok("fn f() -> () { let x: Int = 42; consume(x); consume(x) }");
    }

    #[test]
    fn unrestricted_var_unused_ok() {
        check_ok("fn f() -> () { let x: Int = 42; }");
    }

    // ═════════════════════════════════════════════════════════════════
    // Branch analysis (if/else)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn linear_consumed_in_both_branches_ok() {
        check_ok(
            "fn f(cond: Bool) -> () {
                let x: linear Int = 42;
                if cond {
                    consume(x)
                } else {
                    consume(x)
                }
            }",
        );
    }

    #[test]
    fn linear_consumed_in_then_only_error() {
        check_err(
            "fn f(cond: Bool) -> () {
                let x: linear Int = 42;
                if cond {
                    consume(x)
                } else {
                }
            }",
            "must be consumed in all branches or none",
        );
    }

    #[test]
    fn linear_consumed_in_else_only_error() {
        check_err(
            "fn f(cond: Bool) -> () {
                let x: linear Int = 42;
                if cond {
                } else {
                    consume(x)
                }
            }",
            "must be consumed in all branches or none",
        );
    }

    #[test]
    fn affine_consumed_in_one_branch_ok() {
        // Affine: at-most-once is satisfied if consumed in one branch.
        // No branch inconsistency error for affine types.
        check_ok(
            "fn f(cond: Bool) -> () {
                let x: affine Int = 42;
                if cond {
                    consume(x)
                } else {
                }
            }",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Loop barriers
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn linear_consumed_in_while_loop_error() {
        check_err(
            "fn f() -> () {
                let x: linear Int = 42;
                while true {
                    consume(x)
                }
            }",
            "cannot be consumed inside a loop",
        );
    }

    #[test]
    fn affine_consumed_in_while_loop_error() {
        check_err(
            "fn f() -> () {
                let x: affine Int = 42;
                while true {
                    consume(x)
                }
            }",
            "cannot be consumed inside a loop",
        );
    }

    #[test]
    fn linear_consumed_in_for_loop_error() {
        check_err(
            "fn f(items: Int) -> () {
                let x: linear Int = 42;
                for i in items {
                    consume(x)
                }
            }",
            "cannot be consumed inside a loop",
        );
    }

    #[test]
    fn unrestricted_in_loop_ok() {
        // Unrestricted vars have no loop restriction.
        check_ok(
            "fn f() -> () {
                let x: Int = 42;
                while true {
                    consume(x)
                }
            }",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Scoping
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn linear_var_consumed_in_inner_block_ok() {
        check_ok(
            "fn f() -> () {
                let x: linear Int = 42;
                {
                    consume(x)
                }
            }",
        );
    }

    #[test]
    fn linear_var_defined_and_consumed_in_block_ok() {
        check_ok(
            "fn f() -> () {
                {
                    let x: linear Int = 42;
                    consume(x)
                }
            }",
        );
    }

    #[test]
    fn linear_var_not_consumed_in_block_error() {
        check_err(
            "fn f() -> () {
                {
                    let x: linear Int = 42;
                }
            }",
            "linear variable `x` must be consumed exactly once",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple linear variables
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn two_linear_vars_both_consumed_ok() {
        check_ok(
            "fn f() -> () {
                let x: linear Int = 1;
                let y: linear Int = 2;
                consume(x);
                consume(y)
            }",
        );
    }

    #[test]
    fn two_linear_vars_one_unconsumed_error() {
        check_err(
            "fn f() -> () {
                let x: linear Int = 1;
                let y: linear Int = 2;
                consume(x)
            }",
            "linear variable `y` must be consumed exactly once",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Linearity enum and display
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn linearity_display() {
        assert_eq!(format!("{}", Linearity::Unrestricted), "unrestricted");
        assert_eq!(format!("{}", Linearity::Linear), "linear");
        assert_eq!(format!("{}", Linearity::Affine), "affine");
    }

    #[test]
    fn linearity_default_is_unrestricted() {
        assert_eq!(Linearity::default(), Linearity::Unrestricted);
    }

    #[test]
    fn linearity_equality() {
        assert_eq!(Linearity::Linear, Linearity::Linear);
        assert_ne!(Linearity::Linear, Linearity::Affine);
        assert_ne!(Linearity::Affine, Linearity::Unrestricted);
    }

    // ═════════════════════════════════════════════════════════════════
    // Error messages with source locations
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn double_consume_error_mentions_first_location() {
        let errors = check_errors(
            "fn f() -> () { let x: linear Int = 42; consume(x); consume(x) }",
        );
        let err = errors.iter().find(|e| e.contains("used after being consumed")).unwrap();
        assert!(err.contains("first consumed at line"));
    }

    #[test]
    fn loop_barrier_error_mentions_linearity() {
        let errors = check_errors(
            "fn f() -> () {
                let x: affine Int = 42;
                while true { consume(x) }
            }",
        );
        let err = errors.iter().find(|e| e.contains("cannot be consumed inside a loop")).unwrap();
        assert!(err.contains("affine variable"));
    }

    // ═════════════════════════════════════════════════════════════════
    // Mixed linearity
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn mixed_linear_and_unrestricted_ok() {
        check_ok(
            "fn f() -> () {
                let x: linear Int = 1;
                let y: Int = 2;
                consume(x);
                consume(y);
                consume(y)
            }",
        );
    }

    #[test]
    fn mixed_affine_and_linear() {
        check_err(
            "fn f() -> () {
                let x: linear Int = 1;
                let y: affine Int = 2;
                consume(y)
            }",
            "linear variable `x` must be consumed exactly once",
        );
    }
}
