#[cfg(test)]
mod tests {
    use crate::ast::nodes::*;
    use crate::lexer::scanner::Lexer;
    use crate::lexer::token::Span;
    use crate::parser::parser::Parser;
    use crate::types::checker::TypeChecker;
    use crate::types::context::TypeContext;
    use crate::types::scope::Symbol;
    use crate::types::ty::{Type, TypeId};

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

    /// Extract the body block expression from a single-function source file.
    fn get_fn_body(source: &str) -> (Expr, SourceFile) {
        let file = parse(source);
        let ItemKind::Function(ref f) = file.items[0].kind else {
            panic!("expected fn");
        };
        let body = f.body.as_ref().expect("expected body").as_ref().clone();
        (body, file)
    }

    /// Type-check a function body expression, returning (result TypeId, TypeContext).
    fn check_fn_body(source: &str) -> (TypeId, TypeContext) {
        let (body, _file) = get_fn_body(source);
        let mut ctx = TypeContext::new();
        let result = {
            let mut checker = TypeChecker::new(&mut ctx);
            checker.check_expr(&body)
        };
        (result, ctx)
    }

    /// Check a function body and expect no type errors.
    fn check_ok(source: &str) -> (TypeId, TypeContext) {
        let (id, ctx) = check_fn_body(source);
        assert!(
            ctx.errors.is_empty(),
            "unexpected type errors: {:?}",
            ctx.errors
        );
        (id, ctx)
    }

    /// Check a function body and expect type errors.
    fn check_errors(source: &str) -> Vec<String> {
        let (_, ctx) = check_fn_body(source);
        assert!(!ctx.errors.is_empty(), "expected type errors but got none");
        ctx.errors.into_iter().map(|e| e.message).collect()
    }

    // ═════════════════════════════════════════════════════════════════
    // Literals
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_int_literal_type() {
        let (id, ctx) = check_ok("fn f() { 42 }");
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_float_literal_type() {
        let (id, ctx) = check_ok("fn f() { 3.14 }");
        assert_eq!(*ctx.get_type(id), Type::Float);
    }

    #[test]
    fn test_string_literal_type() {
        let (id, ctx) = check_ok(r#"fn f() { "hello" }"#);
        assert_eq!(*ctx.get_type(id), Type::String);
    }

    #[test]
    fn test_bool_literal_type() {
        let (id, ctx) = check_ok("fn f() { true }");
        assert_eq!(*ctx.get_type(id), Type::Bool);
    }

    // ═════════════════════════════════════════════════════════════════
    // Variables and let bindings
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_let_binding_infers_type() {
        let (id, ctx) = check_ok("fn f() { let x = 42; x }");
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_let_mut_binding() {
        let (id, ctx) = check_ok("fn f() { let mut x = 10; x }");
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_let_with_type_annotation_matching() {
        let (id, ctx) = check_ok("fn f() { let x: Int = 42; x }");
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_let_with_type_annotation_mismatch() {
        let errors = check_errors("fn f() { let x: Bool = 42; x }");
        assert!(errors.iter().any(|e| e.contains("does not match")));
    }

    #[test]
    fn test_undefined_variable() {
        let errors = check_errors("fn f() { undefined_var }");
        assert!(errors.iter().any(|e| e.contains("undefined variable")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Binary operators
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_int_addition() {
        let source = "fn f() { let a = 1; let b = 2; a + b }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_float_arithmetic() {
        let source = "fn f() { let a = 1.0; let b = 2.0; a * b }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Float);
    }

    #[test]
    fn test_comparison_returns_bool() {
        let source = "fn f() { let a = 1; let b = 2; a == b }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Bool);
    }

    #[test]
    fn test_logical_and() {
        let source = "fn f() { let a = true; let b = false; a && b }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Bool);
    }

    #[test]
    fn test_bitwise_ops() {
        let source = "fn f() { let a = 0; let b = 1; a | b }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_arithmetic_on_non_numeric_error() {
        let errors = check_errors("fn f() { let a = true; a + a }");
        assert!(errors.iter().any(|e| e.contains("arithmetic") && e.contains("Bool")));
    }

    #[test]
    fn test_mismatched_arithmetic_types_error() {
        let source = "fn f() { let a = 1; let b = 1.0; a + b }";
        let errors = check_errors(source);
        assert!(errors.iter().any(|e| e.contains("mismatched")));
    }

    #[test]
    fn test_logical_on_non_bool_error() {
        let errors = check_errors("fn f() { let a = 1; a && a }");
        assert!(errors.iter().any(|e| e.contains("logical") && e.contains("Int")));
    }

    #[test]
    fn test_bitwise_on_non_int_error() {
        let errors = check_errors("fn f() { let a = true; a | a }");
        assert!(errors.iter().any(|e| e.contains("bitwise") && e.contains("Bool")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Unary operators
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_unary_neg() {
        let source = "fn f() { let x = 5; -x }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_unary_not() {
        let source = "fn f() { let x = true; !x }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Bool);
    }

    #[test]
    fn test_unary_bitnot() {
        let source = "fn f() { let x = 0; ~x }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_unary_neg_on_bool_error() {
        let errors = check_errors("fn f() { let x = true; -x }");
        assert!(errors.iter().any(|e| e.contains("numeric") && e.contains("Bool")));
    }

    #[test]
    fn test_unary_not_on_int_error() {
        let errors = check_errors("fn f() { let x = 42; !x }");
        assert!(errors.iter().any(|e| e.contains("`!`") && e.contains("Int")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Function calls
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_function_call_correct() {
        let source = "fn f() { let x = 1; add(x, x) }";
        // Register `add` as a function in scope.
        let (body, _file) = get_fn_body(source);
        let mut ctx = TypeContext::new();
        let span = dummy_span();
        let int_ty = ctx.intern_type(Type::Int);
        ctx.define(
            "add",
            Symbol::Function {
                params: vec![int_ty, int_ty],
                return_type: int_ty,
                effects: Vec::new(),
                span,
            },
            span,
        ).unwrap();
        let result = {
            let mut checker = TypeChecker::new(&mut ctx);
            checker.check_expr(&body)
        };
        assert!(ctx.errors.is_empty(), "errors: {:?}", ctx.errors);
        assert_eq!(*ctx.get_type(result), Type::Int);
    }

    #[test]
    fn test_function_call_wrong_arg_count() {
        let source = "fn f() { add(1) }";
        let (body, _file) = get_fn_body(source);
        let mut ctx = TypeContext::new();
        let span = dummy_span();
        let int_ty = ctx.intern_type(Type::Int);
        ctx.define(
            "add",
            Symbol::Function {
                params: vec![int_ty, int_ty],
                return_type: int_ty,
                effects: Vec::new(),
                span,
            },
            span,
        ).unwrap();
        {
            let mut checker = TypeChecker::new(&mut ctx);
            checker.check_expr(&body);
        }
        assert!(ctx.errors.iter().any(|e| e.message.contains("expects 2 argument(s), found 1")));
    }

    #[test]
    fn test_function_call_wrong_arg_type() {
        let source = "fn f() { add(true, 1) }";
        let (body, _file) = get_fn_body(source);
        let mut ctx = TypeContext::new();
        let span = dummy_span();
        let int_ty = ctx.intern_type(Type::Int);
        ctx.define(
            "add",
            Symbol::Function {
                params: vec![int_ty, int_ty],
                return_type: int_ty,
                effects: Vec::new(),
                span,
            },
            span,
        ).unwrap();
        {
            let mut checker = TypeChecker::new(&mut ctx);
            checker.check_expr(&body);
        }
        assert!(ctx.errors.iter().any(|e| e.message.contains("argument 1")));
    }

    #[test]
    fn test_call_non_function_error() {
        let source = "fn f() { let x = 42; x(1) }";
        let errors = check_errors(source);
        assert!(errors.iter().any(|e| e.contains("not a function")));
    }

    // ═════════════════════════════════════════════════════════════════
    // If/else
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_if_else_same_type() {
        let source = "fn f() { if true { 1 } else { 2 } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_if_without_else_is_unit() {
        let source = "fn f() { if true { 1 } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    #[test]
    fn test_if_non_bool_condition_error() {
        let errors = check_errors("fn f() { if 42 { 1 } }");
        assert!(errors.iter().any(|e| e.contains("`if` condition must be Bool")));
    }

    #[test]
    fn test_if_else_mismatched_types_error() {
        let errors = check_errors(r#"fn f() { if true { 1 } else { "hello" } }"#);
        assert!(errors.iter().any(|e| e.contains("incompatible types")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Match
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_match_consistent_arms() {
        let source = "fn f() { match true { _ => 1, _ => 2 } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_match_inconsistent_arms_error() {
        let errors = check_errors(r#"fn f() { match true { _ => 1, _ => "x" } }"#);
        assert!(errors.iter().any(|e| e.contains("incompatible types")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Blocks
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_block_tail_expr_type() {
        let source = "fn f() { { let x = 42; x } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_block_no_tail_is_unit() {
        let source = "fn f() { { let x = 42; } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    #[test]
    fn test_block_scoping() {
        // Variable defined in inner block should not be visible in outer.
        let errors = check_errors("fn f() { { let x = 1; }; x }");
        assert!(errors.iter().any(|e| e.contains("undefined variable `x`")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Governance decisions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_permit_type() {
        let source = "fn f() { permit }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }

    #[test]
    fn test_deny_type() {
        let source = "fn f() { deny }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }

    #[test]
    fn test_escalate_type() {
        let source = "fn f() { escalate }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }

    #[test]
    fn test_quarantine_type() {
        let source = "fn f() { quarantine }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }

    // ═════════════════════════════════════════════════════════════════
    // Governance expressions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_attest_returns_bool() {
        let source = "fn f() { let m = 1; attest(m) }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Bool);
    }

    #[test]
    fn test_audit_block_type() {
        let source = "fn f() { audit { 42 } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_unsafe_ffi_block_type() {
        let source = "fn f() { unsafe_ffi { 42 } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    // ═════════════════════════════════════════════════════════════════
    // Assignment
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_assignment_compatible_types() {
        let source = "fn f() { let mut x = 1; x = 2 }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    #[test]
    fn test_assignment_incompatible_types_error() {
        let errors = check_errors(r#"fn f() { let mut x = 1; x = "str" }"#);
        assert!(errors.iter().any(|e| e.contains("cannot assign")));
    }

    #[test]
    fn test_compound_assignment() {
        let source = "fn f() { let mut x = 1; x += 2 }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    // ═════════════════════════════════════════════════════════════════
    // Tuples
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_tuple_type() {
        let source = "fn f() { (1, true) }";
        let (id, ctx) = check_ok(source);
        match ctx.get_type(id) {
            Type::Tuple(elems) => {
                assert_eq!(elems.len(), 2);
                assert_eq!(*ctx.get_type(elems[0]), Type::Int);
                assert_eq!(*ctx.get_type(elems[1]), Type::Bool);
            }
            other => panic!("expected Tuple, got {other:?}"),
        }
    }

    #[test]
    fn test_unit_tuple() {
        let source = "fn f() { () }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    // ═════════════════════════════════════════════════════════════════
    // While loop
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_while_non_bool_condition_error() {
        let errors = check_errors("fn f() { while 42 { 1 } }");
        assert!(errors.iter().any(|e| e.contains("`while` condition must be Bool")));
    }

    // ═════════════════════════════════════════════════════════════════
    // Error recovery
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_does_not_cascade() {
        // An undefined var produces Error type; using it in arithmetic
        // should NOT produce a second "non-numeric" error.
        let source = "fn f() { let x = 1; x + undefined_var }";
        let (_, ctx) = check_fn_body(source);
        let error_count = ctx.errors.len();
        assert_eq!(error_count, 1, "expected exactly 1 error (undefined var), got {error_count}: {:?}", ctx.errors);
    }

    #[test]
    fn test_multiple_independent_errors() {
        // Two independent errors should both be reported.
        let source = r#"fn f() { let a = true; a + a; if 42 { 1 } }"#;
        let (_, ctx) = check_fn_body(source);
        assert!(ctx.errors.len() >= 2, "expected at least 2 errors, got {}: {:?}", ctx.errors.len(), ctx.errors);
    }

    // ═════════════════════════════════════════════════════════════════
    // Return
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_return_expression() {
        let source = "fn f() { return 42; }";
        let (id, ctx) = check_ok(source);
        // The block's type comes from the statement (expr with semicolon = unit).
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration: realistic governance snippet
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_governance_if_else_decision() {
        let source = r#"
fn f() {
    let trusted = true;
    if trusted {
        permit
    } else {
        deny
    }
}
"#;
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }

    #[test]
    fn test_governance_match_decision() {
        let source = r#"
fn f() {
    let level = 1;
    match level {
        _ => permit,
        _ => deny
    }
}
"#;
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }

    #[test]
    fn test_governance_audit_permit() {
        let source = "fn f() { audit { permit } }";
        let (id, ctx) = check_ok(source);
        assert_eq!(*ctx.get_type(id), Type::PolicyDecision);
    }
}
