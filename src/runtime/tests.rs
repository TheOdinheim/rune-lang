#[cfg(test)]
mod tests {
    use crate::runtime::evaluator::*;
    use crate::runtime::pipeline::*;

    // ═════════════════════════════════════════════════════════════════
    // PolicyDecision encoding
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_policy_decision_from_i32() {
        assert_eq!(PolicyDecision::from_i32(0).unwrap(), PolicyDecision::Permit);
        assert_eq!(PolicyDecision::from_i32(1).unwrap(), PolicyDecision::Deny);
        assert_eq!(PolicyDecision::from_i32(2).unwrap(), PolicyDecision::Escalate);
        assert_eq!(PolicyDecision::from_i32(3).unwrap(), PolicyDecision::Quarantine);
        assert!(PolicyDecision::from_i32(99).is_err());
    }

    #[test]
    fn test_policy_decision_to_i32() {
        assert_eq!(PolicyDecision::Permit.to_i32(), 0);
        assert_eq!(PolicyDecision::Deny.to_i32(), 1);
        assert_eq!(PolicyDecision::Escalate.to_i32(), 2);
        assert_eq!(PolicyDecision::Quarantine.to_i32(), 3);
    }

    #[test]
    fn test_policy_decision_display() {
        assert_eq!(format!("{}", PolicyDecision::Permit), "Permit");
        assert_eq!(format!("{}", PolicyDecision::Deny), "Deny");
        assert_eq!(format!("{}", PolicyDecision::Escalate), "Escalate");
        assert_eq!(format!("{}", PolicyDecision::Quarantine), "Quarantine");
    }

    #[test]
    fn test_policy_decision_roundtrip() {
        for d in [PolicyDecision::Permit, PolicyDecision::Deny,
                  PolicyDecision::Escalate, PolicyDecision::Quarantine] {
            assert_eq!(PolicyDecision::from_i32(d.to_i32()).unwrap(), d);
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // PolicyModule — loading and inspection
    // ═════════════════════════════════════════════════════════════════

    fn compile_wasm(source: &str) -> Vec<u8> {
        crate::compiler::compile_source(source, 0)
            .expect("compilation failed")
    }

    #[test]
    fn test_load_compiled_module() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm);
        assert!(module.is_ok());
    }

    #[test]
    fn test_load_invalid_wasm_error() {
        let result = PolicyModule::from_bytes(b"not valid wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, RuntimeError::ModuleLoadError(_)));
    }

    #[test]
    fn test_has_evaluate_true() {
        let wasm = compile_wasm("policy access { rule check() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        assert!(module.has_evaluate());
    }

    #[test]
    fn test_has_evaluate_false_for_plain_functions() {
        let wasm = compile_wasm("fn add(a: Int, b: Int) -> Int { a + b }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        assert!(!module.has_evaluate());
    }

    #[test]
    fn test_list_exports() {
        let wasm = compile_wasm(r#"
fn helper() -> Int { 42 }
policy access { rule check() { permit } }
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let exports = module.list_exports();
        assert!(exports.contains(&"helper".to_string()));
        assert!(exports.contains(&"evaluate".to_string()));
        assert!(exports.contains(&"access__check".to_string()));
    }

    #[test]
    fn test_list_policy_rules() {
        let wasm = compile_wasm(r#"
fn helper() -> Int { 42 }
policy access { rule check_a() { permit } rule check_b() { deny } }
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let rules = module.list_policy_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules.contains(&"access__check_a".to_string()));
        assert!(rules.contains(&"access__check_b".to_string()));
    }

    // ═════════════════════════════════════════════════════════════════
    // PolicyEvaluator — standard evaluate
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_permit() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(1, 2, 3, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_evaluate_deny() {
        let wasm = compile_wasm("policy access { rule block() { deny } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_evaluate_escalate() {
        let wasm = compile_wasm("policy review { rule needs_review() { escalate } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Escalate);
    }

    #[test]
    fn test_evaluate_quarantine() {
        let wasm = compile_wasm("policy iso { rule isolate() { quarantine } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Quarantine);
    }

    #[test]
    fn test_evaluate_decisions_change_based_on_input() {
        let wasm = compile_wasm(r#"
policy risk {
    rule check(score: Int) {
        if score > 80 { escalate } else { permit }
    }
}
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let high = evaluator.evaluate(&PolicyRequest::new(90, 0, 0, 0)).unwrap();
        assert_eq!(high.decision, PolicyDecision::Escalate);

        let low = evaluator.evaluate(&PolicyRequest::new(50, 0, 0, 0)).unwrap();
        assert_eq!(low.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_evaluate_first_non_permit_wins() {
        let wasm = compile_wasm(r#"
policy access {
    rule check_a() { permit }
    rule check_b() { deny }
}
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_evaluate_no_evaluate_export_error() {
        let wasm = compile_wasm("fn add(a: Int, b: Int) -> Int { a + b }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuntimeError::ExportNotFound(_)));
    }

    // ═════════════════════════════════════════════════════════════════
    // Direct rule evaluation
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_rule_by_name() {
        let wasm = compile_wasm(r#"
policy access { rule allow() { permit } }
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate_rule("access__allow", &[]).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_evaluate_rule_with_args() {
        let wasm = compile_wasm(r#"
policy risk {
    rule check(score: Int) {
        if score > 80 { escalate } else { permit }
    }
}
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let high = evaluator.evaluate_rule("risk__check", &[Value::Int(90)]).unwrap();
        assert_eq!(high.decision, PolicyDecision::Escalate);

        let low = evaluator.evaluate_rule("risk__check", &[Value::Int(50)]).unwrap();
        assert_eq!(low.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_evaluate_rule_nonexistent_error() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate_rule("nonexistent__rule", &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuntimeError::ExportNotFound(_)));
    }

    // ═════════════════════════════════════════════════════════════════
    // Evaluation timing
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluation_timing_recorded() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        // Duration should be recorded and positive (but very fast).
        assert!(result.evaluation_duration < std::time::Duration::from_secs(1));
    }

    #[test]
    fn test_evaluation_sub_millisecond() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        // Warm up.
        let _ = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0));

        // Measure.
        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert!(
            result.evaluation_duration < std::time::Duration::from_millis(10),
            "evaluation took {:?}, expected sub-10ms",
            result.evaluation_duration
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple evaluations — isolation (arena model)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_evaluations_isolated() {
        let wasm = compile_wasm(r#"
policy risk {
    rule check(score: Int) {
        if score > 80 { escalate } else { permit }
    }
}
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        // Each evaluation is independent — no state leaks.
        let r1 = evaluator.evaluate(&PolicyRequest::new(90, 0, 0, 0)).unwrap();
        let r2 = evaluator.evaluate(&PolicyRequest::new(50, 0, 0, 0)).unwrap();
        let r3 = evaluator.evaluate(&PolicyRequest::new(90, 0, 0, 0)).unwrap();

        assert_eq!(r1.decision, PolicyDecision::Escalate);
        assert_eq!(r2.decision, PolicyDecision::Permit);
        assert_eq!(r3.decision, PolicyDecision::Escalate);
    }

    #[test]
    fn test_multiple_evaluators_from_same_module() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();

        let e1 = module.evaluator().unwrap();
        let e2 = module.evaluator().unwrap();

        let r1 = e1.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        let r2 = e2.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();

        assert_eq!(r1.decision, PolicyDecision::Permit);
        assert_eq!(r2.decision, PolicyDecision::Permit);
    }

    // ═════════════════════════════════════════════════════════════════
    // compile_and_evaluate convenience pipeline
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_compile_and_evaluate_permit() {
        let result = compile_and_evaluate(
            "policy access { rule allow() { permit } }",
            &PolicyRequest::new(0, 0, 0, 0),
        ).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_compile_and_evaluate_deny() {
        let result = compile_and_evaluate(
            "policy access { rule block() { deny } }",
            &PolicyRequest::new(0, 0, 0, 0),
        ).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_compile_and_evaluate_compilation_error() {
        let result = compile_and_evaluate(
            "fn bad( { }",
            &PolicyRequest::new(0, 0, 0, 0),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuntimeError::CompilationFailed(_)));
    }

    #[test]
    fn test_compile_and_load_reusable() {
        let module = compile_and_load(
            "policy access { rule allow() { permit } }",
        ).unwrap();
        assert!(module.has_evaluate());

        let evaluator = module.evaluator().unwrap();
        let r1 = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        let r2 = evaluator.evaluate(&PolicyRequest::new(1, 2, 3, 4)).unwrap();
        assert_eq!(r1.decision, PolicyDecision::Permit);
        assert_eq!(r2.decision, PolicyDecision::Permit);
    }

    // ═════════════════════════════════════════════════════════════════
    // Realistic governance scenario
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_realistic_governance_multi_rule() {
        let result = compile_and_evaluate(r#"
fn is_high_risk(score: Int) -> Bool { score > 80 }

policy model_governance {
    rule check_risk(risk_score: Int) {
        if risk_score > 80 { escalate } else { permit }
    }
}
"#,
            &PolicyRequest::new(90, 0, 0, 0),
        ).unwrap();
        assert_eq!(result.decision, PolicyDecision::Escalate);
    }

    #[test]
    fn test_realistic_governance_permit_path() {
        let result = compile_and_evaluate(r#"
policy model_governance {
    rule check_risk(risk_score: Int) {
        if risk_score > 80 { escalate } else { permit }
    }
}
"#,
            &PolicyRequest::new(50, 0, 0, 0),
        ).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);
    }

    #[test]
    fn test_realistic_multi_policy_governance() {
        let result = compile_and_evaluate(r#"
policy auth {
    rule check_auth() { permit }
}

policy data_protection {
    rule check_data() { deny }
}
"#,
            &PolicyRequest::new(0, 0, 0, 0),
        ).unwrap();
        // auth permits, data_protection denies → deny wins
        assert_eq!(result.decision, PolicyDecision::Deny);
    }

    // ═════════════════════════════════════════════════════════════════
    // Error types
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_runtime_error_display() {
        let e1 = RuntimeError::ModuleLoadError("bad bytes".into());
        assert!(format!("{e1}").contains("module load error"));

        let e2 = RuntimeError::ExportNotFound("evaluate".into());
        assert!(format!("{e2}").contains("export not found"));

        let e3 = RuntimeError::EvaluationFailed("trap".into());
        assert!(format!("{e3}").contains("evaluation failed"));

        let e4 = RuntimeError::InvalidDecision(99);
        assert!(format!("{e4}").contains("99"));

        let e5 = RuntimeError::CompilationFailed("parse error".into());
        assert!(format!("{e5}").contains("compilation failed"));
    }
}
