#[cfg(test)]
mod tests {
    use wasmtime::*;

    use crate::codegen::wasm_gen::compile_to_wasm;
    use crate::ir::lower::Lowerer;
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;

    /// Full pipeline: RUNE source → lex → parse → lower to IR → compile to WASM.
    fn compile(source: &str) -> Vec<u8> {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        let mut lowerer = Lowerer::new();
        let ir_module = lowerer.lower_source_file(&file);
        compile_to_wasm(&ir_module)
    }

    /// Load WASM bytes into a wasmtime instance and return (store, instance).
    fn load_wasm(wasm_bytes: &[u8]) -> (Store<()>, Instance) {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm_bytes)
            .expect("failed to load WASM module");
        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[])
            .expect("failed to instantiate WASM module");
        (store, instance)
    }

    // ═════════════════════════════════════════════════════════════════
    // WASM module validity
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_wasm_module_valid() {
        let wasm = compile("fn noop() { }");
        let engine = Engine::default();
        let result = Module::new(&engine, &wasm);
        assert!(result.is_ok(), "WASM module should be valid: {:?}", result.err());
    }

    // ═════════════════════════════════════════════════════════════════
    // Integer arithmetic — end-to-end execution
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_add() {
        let wasm = compile("fn add(a: Int, b: Int) -> Int { a + b }");
        let (mut store, instance) = load_wasm(&wasm);
        let add = instance.get_typed_func::<(i64, i64), i64>(&mut store, "add")
            .expect("failed to get 'add' function");
        let result = add.call(&mut store, (3, 4)).expect("call failed");
        assert_eq!(result, 7);
    }

    #[test]
    fn test_exec_subtract() {
        let wasm = compile("fn sub(a: Int, b: Int) -> Int { a - b }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i64>(&mut store, "sub")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (10, 3)).unwrap(), 7);
    }

    #[test]
    fn test_exec_multiply() {
        let wasm = compile("fn mul(a: Int, b: Int) -> Int { a * b }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i64>(&mut store, "mul")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (6, 7)).unwrap(), 42);
    }

    #[test]
    fn test_exec_divide() {
        let wasm = compile("fn div(a: Int, b: Int) -> Int { a / b }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i64>(&mut store, "div")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (20, 4)).unwrap(), 5);
    }

    #[test]
    fn test_exec_modulo() {
        let wasm = compile("fn rem(a: Int, b: Int) -> Int { a % b }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i64>(&mut store, "rem")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (17, 5)).unwrap(), 2);
    }

    #[test]
    fn test_exec_nested_arithmetic() {
        let wasm = compile("fn calc(a: Int, b: Int) -> Int { (a + b) * (a - b) }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i64>(&mut store, "calc")
            .expect("failed to get function");
        // (5 + 3) * (5 - 3) = 8 * 2 = 16
        assert_eq!(func.call(&mut store, (5, 3)).unwrap(), 16);
    }

    // ═════════════════════════════════════════════════════════════════
    // Constants
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_int_constant() {
        let wasm = compile("fn forty_two() -> Int { 42 }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i64>(&mut store, "forty_two")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, ()).unwrap(), 42);
    }

    #[test]
    fn test_exec_bool_true() {
        let wasm = compile("fn yes() -> Bool { true }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i32>(&mut store, "yes")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, ()).unwrap(), 1);
    }

    #[test]
    fn test_exec_bool_false() {
        let wasm = compile("fn no() -> Bool { false }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i32>(&mut store, "no")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, ()).unwrap(), 0);
    }

    // ═════════════════════════════════════════════════════════════════
    // Let bindings and variables
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_let_binding() {
        let wasm = compile("fn compute(x: Int) -> Int { let y = x; y }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64,), i64>(&mut store, "compute")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (99,)).unwrap(), 99);
    }

    #[test]
    fn test_exec_let_with_expression() {
        let wasm = compile("fn compute(a: Int, b: Int) -> Int { let c = a + b; c }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i64>(&mut store, "compute")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (10, 20)).unwrap(), 30);
    }

    // ═════════════════════════════════════════════════════════════════
    // Comparison operators
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_equality() {
        let wasm = compile("fn eq(a: Int, b: Int) -> Bool { a == b }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i32>(&mut store, "eq")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (5, 5)).unwrap(), 1);
        assert_eq!(func.call(&mut store, (5, 6)).unwrap(), 0);
    }

    #[test]
    fn test_exec_less_than() {
        let wasm = compile("fn lt(a: Int, b: Int) -> Bool { a < b }");
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64, i64), i32>(&mut store, "lt")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (3, 5)).unwrap(), 1);
        assert_eq!(func.call(&mut store, (5, 3)).unwrap(), 0);
    }

    // ═════════════════════════════════════════════════════════════════
    // Governance decisions — the core test
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_permit() {
        let wasm = compile(r#"
policy access {
    rule allow_all() { permit }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i32>(&mut store, "access__allow_all")
            .expect("failed to get policy rule function");
        // Permit = 0
        assert_eq!(func.call(&mut store, ()).unwrap(), 0);
    }

    #[test]
    fn test_exec_deny() {
        let wasm = compile(r#"
policy access {
    rule deny_all() { deny }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i32>(&mut store, "access__deny_all")
            .expect("failed to get policy rule function");
        // Deny = 1
        assert_eq!(func.call(&mut store, ()).unwrap(), 1);
    }

    #[test]
    fn test_exec_escalate() {
        let wasm = compile(r#"
policy access {
    rule needs_review() { escalate }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i32>(&mut store, "access__needs_review")
            .expect("failed to get policy rule function");
        // Escalate = 2
        assert_eq!(func.call(&mut store, ()).unwrap(), 2);
    }

    #[test]
    fn test_exec_quarantine() {
        let wasm = compile(r#"
policy access {
    rule isolate() { quarantine }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(), i32>(&mut store, "access__isolate")
            .expect("failed to get policy rule function");
        // Quarantine = 3
        assert_eq!(func.call(&mut store, ()).unwrap(), 3);
    }

    // ═════════════════════════════════════════════════════════════════
    // If/else — conditional governance decisions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_if_else_permit_deny() {
        let wasm = compile(r#"
policy access {
    rule check(trusted: Bool) {
        if trusted { permit } else { deny }
    }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i32,), i32>(&mut store, "access__check")
            .expect("failed to get function");

        // trusted=true → permit (0)
        assert_eq!(func.call(&mut store, (1,)).unwrap(), 0);
        // trusted=false → deny (1)
        assert_eq!(func.call(&mut store, (0,)).unwrap(), 1);
    }

    #[test]
    fn test_exec_if_else_integer() {
        let wasm = compile(r#"
fn pick(cond: Bool) -> Int {
    if cond { 42 } else { 99 }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i32,), i64>(&mut store, "pick")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (1,)).unwrap(), 42);
        assert_eq!(func.call(&mut store, (0,)).unwrap(), 99);
    }

    // ═════════════════════════════════════════════════════════════════
    // Function calls between RUNE functions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_function_call() {
        let wasm = compile(r#"
fn double(x: Int) -> Int { x + x }
fn quad(x: Int) -> Int { double(double(x)) }
"#);
        let (mut store, instance) = load_wasm(&wasm);
        let func = instance.get_typed_func::<(i64,), i64>(&mut store, "quad")
            .expect("failed to get function");
        assert_eq!(func.call(&mut store, (5,)).unwrap(), 20);
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple functions and policies in one module
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_multiple_exports() {
        let wasm = compile(r#"
fn helper(x: Int) -> Int { x + 1 }

policy governance {
    rule always_permit() { permit }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);

        let helper = instance.get_typed_func::<(i64,), i64>(&mut store, "helper")
            .expect("failed to get helper");
        assert_eq!(helper.call(&mut store, (10,)).unwrap(), 11);

        let rule = instance.get_typed_func::<(), i32>(&mut store, "governance__always_permit")
            .expect("failed to get policy rule");
        assert_eq!(rule.call(&mut store, ()).unwrap(), 0); // permit
    }

    // ═════════════════════════════════════════════════════════════════
    // Full pipeline integration — realistic governance scenario
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_exec_full_governance_pipeline() {
        let wasm = compile(r#"
fn validate_score(score: Int) -> Bool { score > 50 }

policy model_governance {
    rule check_model(score: Int, trusted: Bool) {
        if trusted { permit } else { deny }
    }
}
"#);
        let (mut store, instance) = load_wasm(&wasm);

        // Test the helper function.
        let validate = instance.get_typed_func::<(i64,), i32>(&mut store, "validate_score")
            .expect("failed to get validate_score");
        assert_eq!(validate.call(&mut store, (75,)).unwrap(), 1); // true
        assert_eq!(validate.call(&mut store, (25,)).unwrap(), 0); // false

        // Test the policy rule.
        let check = instance.get_typed_func::<(i64, i32), i32>(
            &mut store,
            "model_governance__check_model",
        ).expect("failed to get policy rule");
        assert_eq!(check.call(&mut store, (90, 1)).unwrap(), 0); // trusted → permit
        assert_eq!(check.call(&mut store, (90, 0)).unwrap(), 1); // untrusted → deny
    }
}
