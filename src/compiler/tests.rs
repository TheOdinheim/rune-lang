#[cfg(test)]
mod tests {
    use wasmtime::*;

    use crate::compiler::{compile_source, CompilePhase};

    /// Load WASM bytes into a wasmtime instance.
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
    // compile_source — success cases
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_compile_simple_function() {
        let result = compile_source("fn add(a: Int, b: Int) -> Int { a + b }", 0);
        assert!(result.is_ok(), "compilation should succeed");
        let wasm = result.unwrap();
        assert!(!wasm.is_empty());
    }

    #[test]
    fn test_compile_policy_module() {
        let result = compile_source(r#"
policy access {
    rule allow_all() { permit }
}
"#, 0);
        assert!(result.is_ok(), "compilation should succeed");
    }

    // ═════════════════════════════════════════════════════════════════
    // compile_source — error collection
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_compile_lex_error() {
        // Unterminated string literal produces a lex error.
        let result = compile_source("fn test() { \"unterminated }", 0);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert_eq!(errors[0].phase, CompilePhase::Lex);
    }

    #[test]
    fn test_compile_parse_error() {
        let result = compile_source("fn bad( { }", 0);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert_eq!(errors[0].phase, CompilePhase::Parse);
    }

    #[test]
    fn test_compile_type_error() {
        // Function claims to return Int but body returns Bool.
        let result = compile_source("fn wrong() -> Int { true }", 0);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
        assert_eq!(errors[0].phase, CompilePhase::Type);
    }

    #[test]
    fn test_compile_error_display() {
        let result = compile_source("fn bad( { }", 0);
        let errors = result.unwrap_err();
        let msg = format!("{}", errors[0]);
        assert!(msg.contains("parse error"));
        assert!(msg.contains("line"));
    }

    // ═════════════════════════════════════════════════════════════════
    // evaluate wrapper — standard entry point
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_export_exists() {
        let wasm = compile_source(r#"
policy access {
    rule allow_all() { permit }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        );
        assert!(evaluate.is_ok(), "evaluate export should exist");
    }

    #[test]
    fn test_evaluate_permit() {
        let wasm = compile_source(r#"
policy access {
    rule allow_all() { permit }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (1, 2, 3, 0)).unwrap();
        assert_eq!(decision, 0, "should return Permit (0)");
    }

    #[test]
    fn test_evaluate_deny() {
        let wasm = compile_source(r#"
policy access {
    rule block_all() { deny }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (1, 2, 3, 0)).unwrap();
        assert_eq!(decision, 1, "should return Deny (1)");
    }

    #[test]
    fn test_evaluate_escalate() {
        let wasm = compile_source(r#"
policy review {
    rule needs_review() { escalate }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (0, 0, 0, 0)).unwrap();
        assert_eq!(decision, 2, "should return Escalate (2)");
    }

    #[test]
    fn test_evaluate_quarantine() {
        let wasm = compile_source(r#"
policy isolation {
    rule isolate() { quarantine }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (0, 0, 0, 0)).unwrap();
        assert_eq!(decision, 3, "should return Quarantine (3)");
    }

    #[test]
    fn test_evaluate_first_non_permit_wins() {
        // Two rules: first permits, second denies. Evaluate should return Deny.
        let wasm = compile_source(r#"
policy access {
    rule check_a() { permit }
    rule check_b() { deny }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (1, 2, 3, 0)).unwrap();
        assert_eq!(decision, 1, "first non-Permit should win → Deny (1)");
    }

    #[test]
    fn test_evaluate_all_permit() {
        // Multiple rules all permitting → evaluate returns Permit.
        let wasm = compile_source(r#"
policy access {
    rule check_a() { permit }
    rule check_b() { permit }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (0, 0, 0, 0)).unwrap();
        assert_eq!(decision, 0, "all Permit → Permit (0)");
    }

    #[test]
    fn test_evaluate_not_generated_for_plain_functions() {
        // Module with only plain functions (no policies) should NOT have evaluate.
        let wasm = compile_source("fn add(a: Int, b: Int) -> Int { a + b }", 0)
            .expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        );
        assert!(evaluate.is_err(), "evaluate should not exist for non-policy modules");
    }

    // ═════════════════════════════════════════════════════════════════
    // Full pipeline — realistic governance scenario
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_realistic_governance() {
        let wasm = compile_source(r#"
fn is_high_risk(score: Int) -> Bool { score > 80 }

policy model_governance {
    rule check_risk(risk_score: Int) {
        if risk_score > 80 { escalate } else { permit }
    }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);

        // Individual rule still accessible.
        let check = instance.get_typed_func::<(i64,), i32>(
            &mut store, "model_governance__check_risk",
        ).expect("failed to get policy rule");
        assert_eq!(check.call(&mut store, (90,)).unwrap(), 2); // escalate
        assert_eq!(check.call(&mut store, (50,)).unwrap(), 0); // permit

        // Evaluate wrapper: risk_score is the 4th param.
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        // rule takes 1 param (risk_score), evaluate passes its first param.
        // With subject_id=90 as first arg → rule gets 90 → escalate.
        let decision = evaluate.call(&mut store, (90, 0, 0, 0)).unwrap();
        assert_eq!(decision, 2, "high risk_score → Escalate");

        let decision = evaluate.call(&mut store, (50, 0, 0, 0)).unwrap();
        assert_eq!(decision, 0, "low risk_score → Permit");
    }

    #[test]
    fn test_evaluate_multiple_policies() {
        let wasm = compile_source(r#"
policy auth {
    rule check_auth() { permit }
}

policy data {
    rule check_data() { deny }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        // auth permits but data denies → first non-permit (deny) wins.
        let decision = evaluate.call(&mut store, (0, 0, 0, 0)).unwrap();
        assert_eq!(decision, 1, "deny from data policy should win");
    }

    #[test]
    fn test_evaluate_with_helper_functions() {
        // Helper functions (non-policy) should not be included in evaluate dispatch.
        let wasm = compile_source(r#"
fn helper() -> Int { 42 }

policy access {
    rule check() { permit }
}
"#, 0).expect("compilation failed");

        let (mut store, instance) = load_wasm(&wasm);

        // Helper is still exported.
        let helper = instance.get_typed_func::<(), i64>(&mut store, "helper")
            .expect("helper should be exported");
        assert_eq!(helper.call(&mut store, ()).unwrap(), 42);

        // Evaluate only dispatches to policy rules.
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");
        let decision = evaluate.call(&mut store, (0, 0, 0, 0)).unwrap();
        assert_eq!(decision, 0, "only policy rule (permit) should matter");
    }

    // ═════════════════════════════════════════════════════════════════
    // File compilation end-to-end
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_file_compilation_roundtrip() {
        use std::fs;

        let dir = std::env::temp_dir().join("rune_test_compile");
        fs::create_dir_all(&dir).unwrap();
        let source_path = dir.join("test_policy.rune");

        fs::write(&source_path, r#"
policy security {
    rule enforce() { deny }
}
"#).unwrap();

        // Read and compile.
        let source = fs::read_to_string(&source_path).unwrap();
        let wasm = compile_source(&source, 0).expect("compilation failed");

        // Write the .wasm file.
        let wasm_path = source_path.with_extension("rune.wasm");
        fs::write(&wasm_path, &wasm).unwrap();

        // Read back and execute.
        let wasm_bytes = fs::read(&wasm_path).unwrap();
        let (mut store, instance) = load_wasm(&wasm_bytes);
        let evaluate = instance.get_typed_func::<(i64, i64, i64, i64), i32>(
            &mut store, "evaluate",
        ).expect("failed to get evaluate");

        let decision = evaluate.call(&mut store, (0, 0, 0, 0)).unwrap();
        assert_eq!(decision, 1, "security policy should deny");

        // Cleanup.
        let _ = fs::remove_dir_all(&dir);
    }

    // ═════════════════════════════════════════════════════════════════
    // Edition system
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_edition_from_str_valid() {
        use crate::compiler::edition::Edition;
        assert_eq!(Edition::from_str("2026"), Ok(Edition::Edition2026));
    }

    #[test]
    fn test_edition_from_str_invalid() {
        use crate::compiler::edition::Edition;
        let result = Edition::from_str("2099");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown edition"));
    }

    #[test]
    fn test_edition_default_is_2026() {
        use crate::compiler::edition::Edition;
        assert_eq!(Edition::default(), Edition::Edition2026);
    }

    #[test]
    fn test_compile_project_with_edition_in_manifest() {
        use std::fs;
        use crate::compiler::compile_project;
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "rune_edition_{}_{}", std::process::id(), n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("rune.toml"), r#"
[package]
name = "test"
version = "0.1.0"
edition = "2026"
"#).unwrap();
        fs::write(dir.join("main.rune"), r#"
            fn add(a: Int, b: Int) -> Int { a + b }
            policy access { rule allow() { permit } }
        "#).unwrap();

        let result = compile_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compile_project_invalid_edition_in_manifest() {
        use std::fs;
        use crate::compiler::compile_project;
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "rune_bad_edition_{}_{}", std::process::id(), n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("rune.toml"), r#"
[package]
name = "test"
version = "0.1.0"
edition = "2099"
"#).unwrap();
        fs::write(dir.join("main.rune"), "fn x() -> Int { 1 }").unwrap();

        let result = compile_project(&dir.join("main.rune"));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.message.contains("unknown edition")),
            "expected edition error: {:?}", errors
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compile_project_no_manifest_uses_default_edition() {
        use std::fs;
        use crate::compiler::compile_project;
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "rune_no_manifest_{}_{}", std::process::id(), n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // No rune.toml — should use default edition.
        fs::write(dir.join("main.rune"), "fn x() -> Int { 42 }").unwrap();

        let result = compile_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
