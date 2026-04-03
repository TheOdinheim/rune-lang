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

    fn parse(source: &str) -> SourceFile {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        file
    }

    fn get_fn_body(source: &str) -> (Expr, SourceFile) {
        let file = parse(source);
        let ItemKind::Function(ref f) = file.items[0].kind else {
            panic!("expected fn");
        };
        let body = f.body.as_ref().expect("expected body").as_ref().clone();
        (body, file)
    }

    /// Set up a TypeContext with functions that require capabilities.
    /// - `read_file(path: String) -> String` requires capability FileSystem
    /// - `write_file(path: String, data: String) -> ()` requires capability FileSystem
    /// - `send_request(url: String) -> String` requires capability Network
    /// - `transfer(url: String, path: String) -> ()` requires FileSystem, Network
    /// - `validate(x: Int) -> Bool` no capabilities required
    fn setup_ctx() -> TypeContext {
        let mut ctx = TypeContext::new();
        let span = dummy_span();
        let string_ty = ctx.intern_type(Type::String);
        let int_ty = ctx.intern_type(Type::Int);
        let bool_ty = ctx.intern_type(Type::Bool);
        let unit_ty = ctx.intern_type(Type::Unit);

        ctx.define(
            "read_file",
            Symbol::Function {
                params: vec![string_ty],
                return_type: string_ty,
                effects: Vec::new(),
                required_capabilities: vec!["FileSystem".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "write_file",
            Symbol::Function {
                params: vec![string_ty, string_ty],
                return_type: unit_ty,
                effects: Vec::new(),
                required_capabilities: vec!["FileSystem".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "send_request",
            Symbol::Function {
                params: vec![string_ty],
                return_type: string_ty,
                effects: Vec::new(),
                required_capabilities: vec!["Network".to_string()],
                span,
            },
            span,
        ).unwrap();

        ctx.define(
            "transfer",
            Symbol::Function {
                params: vec![string_ty, string_ty],
                return_type: unit_ty,
                effects: Vec::new(),
                required_capabilities: vec!["FileSystem".to_string(), "Network".to_string()],
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
                required_capabilities: Vec::new(),
                span,
            },
            span,
        ).unwrap();

        ctx
    }

    /// Check a function body with capability context.
    fn check_with_capabilities(
        source: &str,
        ctx: &mut TypeContext,
        fn_name: &str,
        available_capabilities: Vec<String>,
    ) -> Vec<String> {
        let (body, _file) = get_fn_body(source);
        {
            let mut checker = TypeChecker::new(ctx);
            checker.enter_function_capabilities(fn_name, available_capabilities);
            checker.check_expr(&body);
            checker.exit_function_capabilities();
        }
        ctx.errors.iter().map(|e| e.message.clone()).collect()
    }

    // ═════════════════════════════════════════════════════════════════
    // Function with capability calling capability-requiring function: PASS
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_fn_with_capability_calls_requiring_fn_pass() {
        let source = r#"fn f() { read_file("config.toml") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "load_config",
            vec!["FileSystem".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_fn_with_multiple_capabilities_pass() {
        let source = r#"fn f() { transfer("http://example.com", "/tmp/file") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "sync_files",
            vec!["FileSystem".to_string(), "Network".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_fn_with_superset_capabilities_pass() {
        // Caller has FileSystem and Network, callee only needs FileSystem.
        let source = r#"fn f() { read_file("config.toml") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "load_config",
            vec!["FileSystem".to_string(), "Network".to_string()],
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_fn_calling_no_capability_fn_pass() {
        // Caller has no capabilities, callee doesn't need any.
        let source = "fn f() { validate(42) }";
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "check", Vec::new(),
        );
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // Function WITHOUT capability calling capability-requiring function: ERROR
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_fn_without_capability_error() {
        let source = r#"fn f() { read_file("config.toml") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "process_data", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("read_file")
                && e.contains("FileSystem")
                && e.contains("process_data")),
            "expected capability error: {errors:?}"
        );
    }

    #[test]
    fn test_fn_missing_one_of_multiple_capabilities_error() {
        // transfer requires FileSystem + Network, caller only has FileSystem.
        let source = r#"fn f() { transfer("url", "path") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "partial_sync",
            vec!["FileSystem".to_string()],
        );
        // Should error on missing Network but NOT on FileSystem.
        assert!(
            errors.iter().any(|e| e.contains("Network") && e.contains("transfer")),
            "expected missing Network capability: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("capability `FileSystem`")),
            "should not report FileSystem as missing: {errors:?}"
        );
    }

    #[test]
    fn test_fn_missing_all_capabilities_reports_each() {
        // transfer requires FileSystem + Network, caller has neither.
        let source = r#"fn f() { transfer("url", "path") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "no_caps", Vec::new(),
        );
        let fs_err = errors.iter().any(|e| e.contains("FileSystem"));
        let net_err = errors.iter().any(|e| e.contains("Network"));
        assert!(fs_err, "expected missing FileSystem: {errors:?}");
        assert!(net_err, "expected missing Network: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // secure_zone providing capabilities to its body: PASS
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_secure_zone_provides_capability() {
        let source = r#"fn f() { secure_zone { FileSystem } { read_file("config.toml") } }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "isolated_load", Vec::new(),
        );
        assert!(errors.is_empty(), "secure_zone should provide FileSystem: {errors:?}");
    }

    #[test]
    fn test_secure_zone_provides_multiple_capabilities() {
        let source = r#"fn f() { secure_zone { FileSystem, Network } { transfer("url", "path") } }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "isolated_transfer", Vec::new(),
        );
        assert!(errors.is_empty(), "secure_zone should provide both capabilities: {errors:?}");
    }

    // ═════════════════════════════════════════════════════════════════
    // Capability not available outside secure_zone: ERROR
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_capability_not_available_outside_secure_zone() {
        // secure_zone provides FileSystem inside, but read_file call is OUTSIDE.
        let source = r#"fn f() { secure_zone { FileSystem } { 42 }; read_file("config.toml") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "leaky_fn", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("FileSystem") && e.contains("read_file")),
            "capability should not leak outside secure_zone: {errors:?}"
        );
    }

    #[test]
    fn test_secure_zone_partial_coverage() {
        // secure_zone provides FileSystem but callee also needs Network.
        let source = r#"fn f() { secure_zone { FileSystem } { transfer("url", "path") } }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "partial_zone", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("Network")),
            "secure_zone with FileSystem should not provide Network: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("capability `FileSystem`")),
            "FileSystem should be provided by secure_zone: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Nested capability scopes
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_nested_secure_zones_accumulate_capabilities() {
        // Outer zone provides FileSystem, inner zone adds Network.
        let source = r#"fn f() {
            secure_zone { FileSystem } {
                secure_zone { Network } {
                    transfer("url", "path")
                }
            }
        }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "nested_zones", Vec::new(),
        );
        assert!(errors.is_empty(), "nested zones should accumulate capabilities: {errors:?}");
    }

    #[test]
    fn test_fn_capability_plus_secure_zone() {
        // Function has FileSystem, secure_zone adds Network.
        let source = r#"fn f() {
            secure_zone { Network } {
                transfer("url", "path")
            }
        }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "hybrid_fn",
            vec!["FileSystem".to_string()],
        );
        assert!(errors.is_empty(), "fn capability + secure_zone should combine: {errors:?}");
    }

    #[test]
    fn test_inner_secure_zone_does_not_leak_to_outer() {
        // Inner zone provides Network, but outer scope should not have it.
        let source = r#"fn f() {
            secure_zone { Network } { 42 };
            send_request("url")
        }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "no_leak", Vec::new(),
        );
        assert!(
            errors.iter().any(|e| e.contains("Network") && e.contains("send_request")),
            "inner zone capability should not leak: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple capabilities required: all must be present
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_calls_each_with_different_capabilities() {
        // Caller has FileSystem but not Network — read_file passes, send_request fails.
        let source = r#"fn f() { read_file("f"); send_request("url") }"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "mixed",
            vec!["FileSystem".to_string()],
        );
        // Should error for send_request (needs Network) but not read_file.
        assert!(
            errors.iter().any(|e| e.contains("Network") && e.contains("send_request")),
            "should error on send_request: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("read_file")),
            "should not error on read_file: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // No capability context: no checking (top-level)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_capability_context_no_checking() {
        let source = r#"fn f() { read_file("config.toml") }"#;
        let (body, _file) = get_fn_body(source);
        let mut ctx = setup_ctx();
        {
            let mut checker = TypeChecker::new(&mut ctx);
            // Deliberately NOT calling enter_function_capabilities.
            checker.check_expr(&body);
        }
        assert!(ctx.errors.is_empty(), "no capability context should skip checking: {:?}", ctx.errors);
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration: combined effect + capability checking
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_combined_effects_and_capabilities() {
        // Set up a function that needs both effects and capabilities.
        let source = r#"fn f() { read_file("config.toml") }"#;
        let (_body, _file) = get_fn_body(source);
        let mut ctx = setup_ctx();

        // Re-register read_file with both effects and capabilities.
        // (The existing one is already there, but let's add one with effects too.)
        let span = dummy_span();
        let string_ty = ctx.intern_type(Type::String);
        ctx.enter_scope(); // new scope so we can shadow
        ctx.define(
            "read_file_io",
            Symbol::Function {
                params: vec![string_ty],
                return_type: string_ty,
                effects: vec!["io".to_string()],
                required_capabilities: vec!["FileSystem".to_string()],
                span,
            },
            span,
        ).unwrap();

        // Parse a source that calls read_file_io.
        let source2 = r#"fn f() { read_file_io("config.toml") }"#;
        let (body2, _file2) = get_fn_body(source2);

        {
            let mut checker = TypeChecker::new(&mut ctx);
            // Enter with effects but no capabilities.
            checker.enter_function_effects("handler", vec!["io".to_string()]);
            checker.enter_function_capabilities("handler", Vec::new());
            checker.check_expr(&body2);
            checker.exit_function_capabilities();
            checker.exit_function_effects();
        }
        // Should have a capability error (missing FileSystem) but no effect error (io declared).
        let errors: Vec<String> = ctx.errors.iter().map(|e| e.message.clone()).collect();
        assert!(
            errors.iter().any(|e| e.contains("FileSystem")),
            "should error on missing FileSystem capability: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("effect")),
            "should not error on effects (io is declared): {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration: governance with capabilities
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_governance_secure_zone_policy() {
        // A governance function that reads config inside a secure zone.
        let source = r#"
fn f() {
    let config = secure_zone { FileSystem } { read_file("policy.toml") };
    if true { permit } else { deny }
}
"#;
        let mut ctx = setup_ctx();
        let errors = check_with_capabilities(
            source, &mut ctx, "evaluate_policy", Vec::new(),
        );
        assert!(errors.is_empty(), "governance with secure_zone should pass: {errors:?}");
    }
}
