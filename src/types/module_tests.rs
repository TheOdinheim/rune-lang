#[cfg(test)]
mod tests {
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;
    use crate::types::checker::TypeChecker;
    use crate::types::context::TypeContext;

    /// Parse and type-check a complete source file, returning error messages.
    fn check_program(source: &str) -> Vec<String> {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        let mut ctx = TypeContext::new();
        {
            let mut checker = TypeChecker::new(&mut ctx);
            checker.check_source_file(&file);
        }
        ctx.errors.iter().map(|e| e.message.clone()).collect()
    }

    /// Parse and type-check, expecting no errors.
    fn check_ok(source: &str) {
        let errors = check_program(source);
        assert!(errors.is_empty(), "unexpected type errors: {errors:?}");
    }

    /// Parse and type-check, expecting at least one error containing `needle`.
    fn check_err(source: &str, needle: &str) {
        let errors = check_program(source);
        assert!(
            errors.iter().any(|e| e.contains(needle)),
            "expected error containing `{needle}`, got: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Module scope tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_module_public_function_accessible() {
        check_ok(r#"
            mod crypto {
                pub fn verify() -> Bool { true }
            }
            fn main() -> Bool { crypto::verify() }
        "#);
    }

    #[test]
    fn test_module_private_function_error() {
        check_err(
            r#"
            mod crypto {
                fn internal() -> Int { 0 }
            }
            fn main() -> Int { crypto::internal() }
            "#,
            "private",
        );
    }

    #[test]
    fn test_nested_modules() {
        check_ok(r#"
            mod a {
                pub mod b {
                    pub fn inner() -> Int { 1 }
                }
            }
            fn main() -> Int { a::b::inner() }
        "#);
    }

    #[test]
    fn test_module_mixed_visibility() {
        // Public function accessible, private function not.
        check_ok(r#"
            mod m {
                pub fn public_fn() -> Int { 1 }
                fn private_fn() -> Int { 2 }
            }
            fn main() -> Int { m::public_fn() }
        "#);
        check_err(
            r#"
            mod m {
                pub fn public_fn() -> Int { 1 }
                fn private_fn() -> Int { 2 }
            }
            fn main() -> Int { m::private_fn() }
            "#,
            "private",
        );
    }

    #[test]
    fn test_private_item_error_message_has_add_pub() {
        let errors = check_program(r#"
            mod crypto {
                fn secret() -> Int { 42 }
            }
            fn main() -> Int { crypto::secret() }
        "#);
        assert!(
            errors.iter().any(|e| e.contains("add `pub`")),
            "error should suggest adding pub: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Qualified path tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_qualified_path_call() {
        check_ok(r#"
            mod math {
                pub fn add(x: Int, y: Int) -> Int { x + y }
            }
            fn main() -> Int { math::add(1, 2) }
        "#);
    }

    #[test]
    fn test_multi_segment_path() {
        check_ok(r#"
            mod a {
                pub mod b {
                    pub fn c() -> Int { 42 }
                }
            }
            fn main() -> Int { a::b::c() }
        "#);
    }

    #[test]
    fn test_nonexistent_module_error() {
        check_err(
            r#"fn main() -> Int { nonexistent::foo() }"#,
            "module `nonexistent` not found",
        );
    }

    #[test]
    fn test_nonexistent_function_in_module_error() {
        check_err(
            r#"
            mod crypto {
                pub fn verify() -> Bool { true }
            }
            fn main() -> Bool { crypto::missing() }
            "#,
            "not found in module",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // self:: and super:: tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_self_path_resolves() {
        // self:: in a module context resolves to the current scope.
        // At top level, self:: resolves in the current (root) scope.
        check_ok(r#"
            fn helper() -> Int { 42 }
            fn main() -> Int { self::helper() }
        "#);
    }

    #[test]
    fn test_super_path_resolves() {
        // super:: at the top level falls back to identifier lookup.
        // Inside a module, super:: would resolve to the parent.
        // For now, test that it doesn't crash and resolves the name.
        check_ok(r#"
            fn helper() -> Int { 42 }
            fn main() -> Int { super::helper() }
        "#);
    }

    // ═════════════════════════════════════════════════════════════════
    // Use import tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_use_single_import() {
        check_ok(r#"
            mod crypto {
                pub fn verify() -> Bool { true }
            }
            use crypto::verify;
            fn main() -> Bool { verify() }
        "#);
    }

    #[test]
    fn test_use_alias_import() {
        check_ok(r#"
            mod crypto {
                pub fn verify() -> Bool { true }
            }
            use crypto::verify as v;
            fn main() -> Bool { v() }
        "#);
    }

    #[test]
    fn test_use_glob_import() {
        check_ok(r#"
            mod crypto {
                pub fn verify() -> Bool { true }
                pub fn sign() -> Bool { true }
            }
            use crypto::*;
            fn main() -> Bool { verify() }
        "#);
    }

    #[test]
    fn test_use_glob_skips_private() {
        // Glob imports should skip private items without error.
        // Using the private item directly should fail.
        check_ok(r#"
            mod crypto {
                pub fn verify() -> Bool { true }
                fn internal() -> Int { 0 }
            }
            use crypto::*;
            fn main() -> Bool { verify() }
        "#);
    }

    #[test]
    fn test_use_glob_conflict_with_existing_name() {
        check_err(
            r#"
            fn verify() -> Bool { false }
            mod crypto {
                pub fn verify() -> Bool { true }
            }
            use crypto::*;
            "#,
            "already exists",
        );
    }

    #[test]
    fn test_use_private_item_error() {
        check_err(
            r#"
            mod crypto {
                fn internal() -> Int { 0 }
            }
            use crypto::internal;
            "#,
            "private",
        );
    }

    #[test]
    fn test_pub_use_reexport() {
        check_ok(r#"
            mod inner {
                pub fn helper() -> Int { 42 }
            }
            mod outer {
                pub use inner::helper;
            }
        "#);
    }

    // ═════════════════════════════════════════════════════════════════
    // Effect propagation across modules
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_cross_module_effect_propagation() {
        // A function in module B has effects; calling from A without
        // declaring those effects should be an error.
        check_err(
            r#"
            effect Network {
                fn fetch(url: String) -> String;
            }
            mod net {
                pub fn call_api() -> Int with effects { Network } { 1 }
            }
            fn pure_fn() -> Int { net::call_api() }
            "#,
            "effect",
        );
    }

    #[test]
    fn test_cross_module_effect_allowed() {
        // Calling a module function with effects is allowed when
        // the caller declares those effects.
        check_ok(r#"
            effect Network {
                fn fetch(url: String) -> String;
            }
            mod net {
                pub fn call_api() -> Int with effects { Network } { 1 }
            }
            fn caller() -> Int with effects { Network } { net::call_api() }
        "#);
    }

    // ═════════════════════════════════════════════════════════════════
    // Backward compatibility tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_modules_works_as_before() {
        check_ok(r#"
            fn add(a: Int, b: Int) -> Int { a + b }
            fn main() -> Int { add(1, 2) }
        "#);
    }

    #[test]
    fn test_flat_scope_policies_still_work() {
        check_ok(r#"
            policy access {
                rule allow(x: Int) {
                    if x > 0 { permit } else { deny }
                }
            }
        "#);
    }

    #[test]
    fn test_flat_scope_types_still_work() {
        check_ok(r#"
            struct Point { x: Int, y: Int }
            fn origin() -> Point { origin() }
        "#);
    }

    // ═════════════════════════════════════════════════════════════════
    // Module type checking
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_module_function_type_checks_body() {
        // Type errors inside module bodies should be caught.
        check_err(
            r#"
            mod m {
                pub fn bad() -> Int { "not an int" }
            }
            "#,
            "String",
        );
    }

    #[test]
    fn test_qualified_call_type_mismatch() {
        check_err(
            r#"
            mod math {
                pub fn add(x: Int, y: Int) -> Int { x + y }
            }
            fn main() -> Int { math::add(1, "two") }
            "#,
            "String",
        );
    }

    #[test]
    fn test_qualified_call_arity_mismatch() {
        check_err(
            r#"
            mod math {
                pub fn add(x: Int, y: Int) -> Int { x + y }
            }
            fn main() -> Int { math::add(1) }
            "#,
            "expects 2 argument(s), found 1",
        );
    }

    #[test]
    fn test_private_module_nested() {
        // Private nested module should not be accessible from outside.
        check_err(
            r#"
            mod a {
                mod b {
                    pub fn inner() -> Int { 1 }
                }
            }
            fn main() -> Int { a::b::inner() }
            "#,
            "private",
        );
    }

    #[test]
    fn test_pub_nested_module_accessible() {
        check_ok(r#"
            mod a {
                pub mod b {
                    pub fn inner() -> Int { 1 }
                }
            }
            fn main() -> Int { a::b::inner() }
        "#);
    }

    #[test]
    fn test_module_file_based_placeholder() {
        // File-based modules should register without error.
        // They're empty placeholders for now.
        check_ok(r#"
            mod crypto;
            fn main() -> Int { 42 }
        "#);
    }

    // ═════════════════════════════════════════════════════════════════
    // M8: Extern blocks and FFI effect enforcement
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_extern_fn_registered_and_callable() {
        check_ok(r#"
            extern { fn sha256(data: Int) -> Int; }
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
        "#);
    }

    #[test]
    fn test_extern_fn_standalone_callable() {
        check_ok(r#"
            extern fn sha256(data: Int) -> Int;
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
        "#);
    }

    #[test]
    fn test_extern_fn_without_ffi_effect_error() {
        check_err(
            r#"
            extern { fn sha256(data: Int) -> Int; }
            fn hash(x: Int) -> Int { sha256(x) }
            "#,
            "effect",
        );
    }

    #[test]
    fn test_extern_fn_ffi_effect_transitive() {
        // Calling a function that calls extern requires ffi effect too.
        check_err(
            r#"
            extern fn sha256(data: Int) -> Int;
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
            fn wrapper(x: Int) -> Int { hash(x) }
            "#,
            "effect",
        );
    }

    #[test]
    fn test_extern_fn_ffi_effect_transitive_allowed() {
        check_ok(r#"
            extern fn sha256(data: Int) -> Int;
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
            fn wrapper(x: Int) -> Int with effects { ffi } { hash(x) }
        "#);
    }

    #[test]
    fn test_extern_fn_no_return_type() {
        check_ok(r#"
            extern fn log_msg(msg: String);
            fn do_log(s: String) with effects { ffi } { log_msg(s) }
        "#);
    }

    #[test]
    fn test_extern_block_multiple_fns() {
        check_ok(r#"
            extern {
                fn sha256(data: Int) -> Int;
                fn sha512(data: Int) -> Int;
            }
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
            fn hash2(x: Int) -> Int with effects { ffi } { sha512(x) }
        "#);
    }

    #[test]
    fn test_extern_with_abi_callable() {
        check_ok(r#"
            extern "C" fn sha256(data: Int) -> Int;
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
        "#);
    }

    #[test]
    fn test_pub_extern_visibility() {
        check_ok(r#"
            pub extern { fn sha256(data: Int) -> Int; }
            fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
        "#);
    }

    #[test]
    fn test_extern_fn_in_module() {
        check_ok(r#"
            mod crypto {
                pub extern fn sha256(data: Int) -> Int;
                pub fn hash(x: Int) -> Int with effects { ffi } { sha256(x) }
            }
            fn main() -> Int with effects { ffi } { crypto::hash(42) }
        "#);
    }

    #[test]
    fn test_extern_fn_multiple_params() {
        check_ok(r#"
            extern fn hmac(key: Int, data: Int) -> Int;
            fn sign(k: Int, d: Int) -> Int with effects { ffi } { hmac(k, d) }
        "#);
    }

    #[test]
    fn test_extern_alongside_regular_fns() {
        check_ok(r#"
            extern fn sha256(data: Int) -> Int;
            fn pure_add(a: Int, b: Int) -> Int { a + b }
            fn hash_and_add(x: Int) -> Int with effects { ffi } { sha256(x) + pure_add(1, 2) }
        "#);
    }
}
