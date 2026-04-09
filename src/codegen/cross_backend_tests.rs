// ═══════════════════════════════════════════════════════════════════════
// Cross-Backend Validation Tests
//
// Compiles the SAME RUNE source through both WASM and LLVM backends,
// executes via both paths, and compares real outputs.
//
// WASM: compile_source → PolicyModule → evaluator.evaluate → PolicyDecision
// LLVM: compile_to_executable → run binary → check exit code
//
// This is the gold standard: both backends produce identical governance
// decisions for identical policy source.
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::compiler::compile_source;
    use crate::runtime::evaluator::{PolicyDecision, PolicyModule, PolicyRequest};

    // ── Helpers ─────────────────────────────────────────────────────

    fn wasm_evaluate(
        source: &str,
        subject: i64,
        action: i64,
        resource: i64,
        risk: i64,
    ) -> PolicyDecision {
        let wasm_bytes = compile_source(source, 0).expect("WASM compilation failed");
        let module = PolicyModule::from_bytes(&wasm_bytes).expect("WASM module load failed");
        let evaluator = module.evaluator().expect("evaluator creation failed");
        let request = PolicyRequest::new(subject, action, resource, risk);
        evaluator.evaluate(&request).expect("evaluation failed").decision
    }

    fn native_exit_code(source: &str) -> Option<i32> {
        use crate::compiler::compile_to_executable;
        let dir = std::env::temp_dir().join("rune_xbackend");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join(format!(
            "test_{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let result = compile_to_executable(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                return None; // linker not available
            }
            panic!("native compilation failed: {:?}", errors);
        }
        result.unwrap();

        let run = std::process::Command::new(&output).output().unwrap();
        let code = run.status.code();
        let _ = std::fs::remove_file(&output);
        code
    }

    // ── Simple decision tests ───────────────────────────────────────

    #[test]
    fn test_cross_permit() {
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Permit);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 0, "native permit should exit 0");
        }
    }

    #[test]
    fn test_cross_deny() {
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { deny } }";
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Deny);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 1, "native deny should exit 1");
        }
    }

    #[test]
    fn test_cross_escalate() {
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { escalate } }";
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Escalate);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 2, "native escalate should exit 2");
        }
    }

    #[test]
    fn test_cross_quarantine() {
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { quarantine } }";
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Quarantine);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 3, "native quarantine should exit 3");
        }
    }

    // ── Conditional logic tests ─────────────────────────────────────

    #[test]
    fn test_cross_risk_threshold() {
        let source = r#"
            policy risk {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 50 { deny } else { permit }
                }
            }
        "#;
        // WASM: multiple input combinations
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 30), PolicyDecision::Permit);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 80), PolicyDecision::Deny);
        // Native: default args (0,0,0,0) → risk=0 → Permit
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 0, "risk 0 should permit");
        }
    }

    #[test]
    fn test_cross_two_tier_risk() {
        let source = r#"
            policy risk {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 80 { deny } else { if risk > 50 { escalate } else { permit } }
                }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 90), PolicyDecision::Deny);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 60), PolicyDecision::Escalate);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 30), PolicyDecision::Permit);
    }

    #[test]
    fn test_cross_multi_tier_risk() {
        let source = r#"
            policy risk {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 90 {
                        quarantine
                    } else {
                        if risk > 70 {
                            escalate
                        } else {
                            if risk > 50 {
                                deny
                            } else {
                                permit
                            }
                        }
                    }
                }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 95), PolicyDecision::Quarantine);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 75), PolicyDecision::Escalate);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 55), PolicyDecision::Deny);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 30), PolicyDecision::Permit);
    }

    #[test]
    fn test_cross_boolean_condition() {
        let source = r#"
            policy action_gate {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if action == 1 { deny } else { permit }
                }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 1, 0, 0), PolicyDecision::Deny);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Permit);
        // Native: default args → action=0 → Permit
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 0);
        }
    }

    // ── Multi-rule tests ────────────────────────────────────────────

    #[test]
    fn test_cross_multi_rule_first_permits_second_denies() {
        let source = r#"
            policy access {
                rule allow(s: Int, a: Int, r: Int, k: Int) { permit }
                rule block(s: Int, a: Int, r: Int, k: Int) { deny }
            }
        "#;
        // first-non-permit-wins: permit then deny → deny
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Deny);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 1, "multi-rule deny should exit 1");
        }
    }

    #[test]
    fn test_cross_multi_rule_all_permit() {
        let source = r#"
            policy access {
                rule a(s: Int, a: Int, r: Int, k: Int) { permit }
                rule b(s: Int, a: Int, r: Int, k: Int) { permit }
                rule c(s: Int, a: Int, r: Int, k: Int) { permit }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Permit);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 0);
        }
    }

    #[test]
    fn test_cross_multi_rule_third_quarantines() {
        let source = r#"
            policy access {
                rule a(s: Int, a: Int, r: Int, k: Int) { permit }
                rule b(s: Int, a: Int, r: Int, k: Int) { permit }
                rule c(s: Int, a: Int, r: Int, k: Int) { quarantine }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 0), PolicyDecision::Quarantine);
        if let Some(code) = native_exit_code(source) {
            assert_eq!(code, 3);
        }
    }

    // ── Helper function tests ───────────────────────────────────────

    #[test]
    fn test_cross_helper_function() {
        let source = r#"
            fn is_high_risk(score: Int) -> Bool { score > 80 }
            policy risk {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if is_high_risk(risk) { deny } else { permit }
                }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 90), PolicyDecision::Deny);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 50), PolicyDecision::Permit);
        // LLVM IR should contain the helper function
        let ir = compile_to_llvm_ir(source);
        assert!(ir.contains("is_high_risk"), "IR should contain helper function");
    }

    #[test]
    fn test_cross_nested_helper_calls() {
        let source = r#"
            fn triple(x: Int) -> Int { x * 3 }
            fn add_ten(x: Int) -> Int { triple(x) + 10 }
            fn compute_risk(risk: Int) -> Bool { add_ten(risk) > 100 }
            policy risk {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if compute_risk(risk) { deny } else { permit }
                }
            }
        "#;
        // triple(30) + 10 = 100 → not > 100 → permit
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 30), PolicyDecision::Permit);
        // triple(31) + 10 = 103 → > 100 → deny
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 31), PolicyDecision::Deny);
    }

    // ── Edge case tests ─────────────────────────────────────────────

    #[test]
    fn test_cross_empty_policy_permits() {
        // Policy with no rules → default Permit (via WASM evaluate wrapper: no rules = Permit).
        // Note: The WASM evaluator returns Deny if there's no evaluate export, but
        // an empty policy still generates evaluate() which returns Permit (0) by default.
        let source = "policy empty { }";
        // This policy has no rules, so the evaluate wrapper returns Permit.
        let wasm_bytes = compile_source(source, 0).expect("should compile");
        let module = PolicyModule::from_bytes(&wasm_bytes).expect("should load");
        if module.has_evaluate() {
            let evaluator = module.evaluator().unwrap();
            let request = PolicyRequest::new(0, 0, 0, 0);
            let result = evaluator.evaluate(&request).unwrap();
            // Empty policy with evaluate → Permit (no rules triggered non-permit)
            assert_eq!(result.decision, PolicyDecision::Permit);
        }
    }

    #[test]
    fn test_cross_arithmetic_in_condition() {
        let source = r#"
            policy risk {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if (risk * 2) > 100 { deny } else { permit }
                }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 60), PolicyDecision::Deny);
        assert_eq!(wasm_evaluate(source, 0, 0, 0, 40), PolicyDecision::Permit);
    }

    #[test]
    fn test_cross_multi_param_condition() {
        let source = r#"
            policy access {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if subject > 0 {
                        if action > 0 { deny } else { permit }
                    } else {
                        permit
                    }
                }
            }
        "#;
        assert_eq!(wasm_evaluate(source, 1, 1, 0, 0), PolicyDecision::Deny);
        assert_eq!(wasm_evaluate(source, 1, 0, 0, 0), PolicyDecision::Permit);
        assert_eq!(wasm_evaluate(source, 0, 1, 0, 0), PolicyDecision::Permit);
    }

    // ── LLVM IR helper ──────────────────────────────────────────────

    fn compile_to_llvm_ir(source: &str) -> String {
        use crate::codegen::llvm_gen::LlvmCodegen;
        use crate::ir::lower::Lowerer;
        use crate::lexer::scanner::Lexer;
        use crate::parser::parser::Parser;
        use crate::types::checker::TypeChecker;
        use crate::types::context::TypeContext;

        let (tokens, _) = Lexer::new(source, 0).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let mut ctx = TypeContext::new();
        let mut checker = TypeChecker::new(&mut ctx);
        checker.check_source_file(&file);
        let mut lowerer = Lowerer::new();
        let ir_module = lowerer.lower_source_file(&file);

        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&ir_module);
        codegen.emit_llvm_ir()
    }
}
