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

    /// Extract the body block expression from the first function in source.
    fn get_fn_body(source: &str) -> (Expr, SourceFile) {
        let file = parse(source);
        let ItemKind::Function(ref f) = file.items[0].kind else {
            panic!("expected fn");
        };
        let body = f.body.as_ref().expect("expected body").as_ref().clone();
        (body, file)
    }

    /// Set up a TypeContext with common helper functions registered.
    /// - `fetch(url: String) -> String` with effects [network]
    /// - `write_file(path: String) -> ()` with effects [io]
    /// - `send(url: String) -> String` with effects [network, io]
    /// - `validate(x: Int) -> Bool` pure (no effects)
    /// - `log_audit(msg: String) -> ()` with effects [audit]
    fn setup_ctx() -> TypeContext {
        let mut ctx = TypeContext::new();
        let span = dummy_span();
        let string_ty = ctx.intern_type(Type::String);
        let int_ty = ctx.intern_type(Type::Int);
        let bool_ty = ctx.intern_type(Type::Bool);
        let unit_ty = ctx.intern_type(Type::Unit);

        ctx.define(
            "fetch",
            Symbol::Function {
                params: vec![string_ty],
                return_type: string_ty,
                effects: vec!["network".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "write_file",
            Symbol::Function {
                params: vec![string_ty],
                return_type: unit_ty,
                effects: vec!["io".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "send",
            Symbol::Function {
                params: vec![string_ty],
                return_type: string_ty,
                effects: vec!["network".to_string(), "io".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "validate",
            Symbol::Function {
                params: vec![int_ty],
                return_type: bool_ty,
                effects: Vec::new(),
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "log_audit",
            Symbol::Function {
                params: vec![string_ty],
                return_type: unit_ty,
                effects: vec!["audit".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx
    }

    /// Check a function body with effect context, given pre-configured ctx.
    fn check_with_effects(
        source: &str,
        ctx: &mut TypeContext,
        fn_name: &str,
        allowed_effects: Vec<String>,
    ) -> Vec<String> {
        let (body, _file) = get_fn_body(source);
        {
            let mut checker = TypeChecker::new(ctx);
            checker.enter_function_effects(fn_name, allowed_effects);
            checker.check_expr(&body);
            checker.exit_function_effects();
        }
        ctx.errors.iter().map(|e| e.message.clone()).collect()
    }

    // ═════════════════════════════════════════════════════════════════
    // Effectful function calling effectful function: PASS
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_effectful_fn_calls_effectful_fn_pass() {
        let source = r#"fn f() { fetch("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["network".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_effectful_fn_with_multiple_effects_pass() {
        // Caller declares both network and io — can call send() which needs both.
        let source = r#"fn f() { send("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f",
            vec!["network".to_string(), "io".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_effectful_fn_superset_of_callee_pass() {
        // Caller declares network, io, audit — superset of fetch's [network].
        let source = r#"fn f() { fetch("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f",
            vec!["network".to_string(), "io".to_string(), "audit".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_pure_fn_calls_pure_fn_pass() {
        // Pure caller calling pure callee — no effect issues.
        let source = "fn f() { validate(42) }";
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", Vec::new(),
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // Function WITHOUT declared effects calling effectful function: ERROR
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_pure_fn_calls_effectful_fn_error() {
        let source = r#"fn process() { fetch("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "process", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("pure function") && e.contains("process")
                && e.contains("fetch") && e.contains("network")),
            "expected pure function error, got: {errors:?}"
        );
    }

    #[test]
    fn test_pure_fn_calls_multi_effect_fn_error() {
        let source = r#"fn process() { send("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "process", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("pure function") && e.contains("process")
                && e.contains("send") && e.contains("network") && e.contains("io")),
            "expected pure function error, got: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Missing subset of effects: ERROR
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_missing_one_effect_error() {
        // Caller has [network] but calls send() which needs [network, io].
        let source = r#"fn f() { send("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["network".to_string()],
        );
        assert!(
            errors.iter().any(|e| e.contains("io") && e.contains("send")
                && !e.contains("network")),
            "expected missing 'io' error (not 'network'), got: {errors:?}"
        );
        // Should NOT complain about network since it's declared.
        assert!(
            !errors.iter().any(|e| e.contains("effect `network`")),
            "should not report network as missing: {errors:?}"
        );
    }

    #[test]
    fn test_missing_all_effects_reports_each() {
        // Caller has [] effects but is NOT pure (has some unrelated effect).
        // Actually, let's make caller have [audit] but callee needs [network, io].
        let source = r#"fn f() { send("http://example.com") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["audit".to_string()],
        );
        // Should report two separate errors: missing network and missing io.
        let network_err = errors.iter().any(|e| e.contains("effect `network`"));
        let io_err = errors.iter().any(|e| e.contains("effect `io`"));
        assert!(network_err, "expected missing 'network' error: {errors:?}");
        assert!(io_err, "expected missing 'io' error: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // Effect propagation across call chains
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_effect_propagation_chain() {
        // A function that calls both fetch (network) and write_file (io)
        // must declare both effects.
        let source = r#"fn f() { fetch("url"); write_file("path") }"#;
        let mut ctx = setup_ctx();

        // Only declare network — should error on write_file's io effect.
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["network".to_string()],
        );
        assert!(
            errors.iter().any(|e| e.contains("io") && e.contains("write_file")),
            "expected missing 'io' from write_file: {errors:?}"
        );
    }

    #[test]
    fn test_effect_propagation_full_declaration_pass() {
        // Declares both effects — should pass.
        let source = r#"fn f() { fetch("url"); write_file("path") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f",
            vec!["network".to_string(), "io".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // unsafe_ffi suppresses effect checking
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_unsafe_ffi_suppresses_effect_checking() {
        // Pure function calling effectful function inside unsafe_ffi — no error.
        let source = r#"fn f() { unsafe_ffi { fetch("http://example.com") } }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", Vec::new(),
        );
        assert!(errors.is_empty(), "unsafe_ffi should suppress effect errors: {errors:?}");
    }

    #[test]
    fn test_unsafe_ffi_only_suppresses_inside_block() {
        // Effects outside the unsafe_ffi block should still be checked.
        let source = r#"fn f() { unsafe_ffi { 42 }; fetch("url") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("pure function") && e.contains("fetch")),
            "effect error should still fire outside unsafe_ffi: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // audit block carries implicit audit effect
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_audit_block_implicit_effect() {
        // Inside an audit block, calling log_audit (which needs audit effect)
        // should pass because audit blocks implicitly carry the audit effect.
        let source = r#"fn f() { audit { log_audit("checked") } }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", Vec::new(),
        );
        // The audit block adds the audit effect, so log_audit should be allowed.
        // But the outer function is pure — the audit block implicitly provides audit.
        // However, the outer function itself doesn't declare audit... so:
        // The audit block pushes a frame that ADDS audit to the allowed set.
        // Since the outer function is pure (empty effects), the audit block
        // frame has allowed_effects = ["audit"].
        assert!(errors.is_empty(), "audit block should implicitly allow audit effect: {errors:?}");
    }

    #[test]
    fn test_audit_block_does_not_allow_other_effects() {
        // An audit block only adds the audit effect, not others.
        let source = r#"fn f() { audit { fetch("url") } }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", Vec::new(),
        );
        // fetch needs network, audit block only provides audit.
        // But the outer function is pure, so audit block has ["audit"].
        // fetch needs network — not in ["audit"], so error.
        assert!(
            errors.iter().any(|e| e.contains("network")),
            "audit block should not allow network effect: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // perform expression checked against allowed effects
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_perform_allowed_effect_pass() {
        let source = "fn f() { perform Network::request(42) }";
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["Network".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_perform_undeclared_effect_error() {
        let source = "fn f() { perform Network::request(42) }";
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["io".to_string()],
        );
        assert!(
            errors.iter().any(|e| e.contains("Network") && e.contains("not declared")),
            "expected undeclared effect error: {errors:?}"
        );
    }

    #[test]
    fn test_perform_in_pure_function_error() {
        let source = "fn f() { perform Network::request(42) }";
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "validate_pure", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("pure function") && e.contains("Network")),
            "expected pure function error: {errors:?}"
        );
    }

    #[test]
    fn test_perform_in_unsafe_ffi_suppressed() {
        let source = "fn f() { unsafe_ffi { perform Network::request(42) } }";
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", Vec::new(),
        );
        assert!(errors.is_empty(), "unsafe_ffi should suppress perform effect checking: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // Nested function scopes: inner function's effects don't leak
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_effect_context_no_checking() {
        // When NOT inside an effect context (no enter_function_effects call),
        // effect checking is skipped entirely — top-level code, scripts, etc.
        let source = r#"fn f() { fetch("url") }"#;
        let (body, _file) = get_fn_body(source);
        let mut ctx = setup_ctx();
        {
            let mut checker = TypeChecker::new(&mut ctx);
            // Deliberately NOT calling enter_function_effects.
            checker.check_expr(&body);
        }
        assert!(ctx.errors.is_empty(), "no effect context should mean no checking: {:?}", ctx.errors);
    }

    #[test]
    fn test_nested_effect_frames_independent() {
        // Simulate: outer function has [network], enters unsafe_ffi, exits,
        // then calls an effectful function — should still be checked.
        let source = r#"fn f() { unsafe_ffi { send("a") }; write_file("b") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "f", vec!["network".to_string()],
        );
        // write_file needs io, caller only has network — should error.
        // send inside unsafe_ffi should not error.
        assert!(
            errors.iter().any(|e| e.contains("io") && e.contains("write_file")),
            "expected io error for write_file outside unsafe_ffi: {errors:?}"
        );
        // Should NOT have errors about send (it's inside unsafe_ffi).
        assert!(
            !errors.iter().any(|e| e.contains("send")),
            "should not have errors about send inside unsafe_ffi: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration: realistic governance patterns
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_governance_pipeline_with_effects() {
        // A governance function that fetches data and audits the decision.
        let source = r#"
fn f() {
    let data = fetch("http://model-registry.internal");
    audit { log_audit("policy check started") };
    if true { permit } else { deny }
}
"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "evaluate_policy",
            vec!["network".to_string(), "audit".to_string()],
        );
        assert!(errors.is_empty(), "governance pipeline should pass: {errors:?}");
    }

    #[test]
    fn test_governance_pipeline_missing_network_effect() {
        let source = r#"
fn f() {
    let data = fetch("http://model-registry.internal");
    if true { permit } else { deny }
}
"#;
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "evaluate_policy",
            vec!["audit".to_string()],
        );
        assert!(
            errors.iter().any(|e| e.contains("network") && e.contains("fetch")),
            "should catch missing network effect: {errors:?}"
        );
    }

    #[test]
    fn test_pure_validation_function() {
        // A pure function that only does computation — should pass.
        let source = "fn f() { let x = validate(42); if x { permit } else { deny } }";
        let mut ctx = setup_ctx();
        let errors = check_with_effects(
            source, &mut ctx, "pure_check", Vec::new(),
        );
        assert!(errors.is_empty(), "pure validation should pass: {errors:?}");
    }
}
