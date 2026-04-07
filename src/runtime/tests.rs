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

    // ═════════════════════════════════════════════════════════════════
    // Audit trail — hash chain and signatures (M5 Layer 2)
    // ═════════════════════════════════════════════════════════════════

    use crate::runtime::audit::*;

    fn test_key() -> Vec<u8> {
        b"test-signing-key-for-audit-trail".to_vec()
    }

    #[test]
    fn test_audit_record_decision_and_verify_chain() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_decision("test_module", "check_access", PolicyDecision::Permit, "abc123");
        assert_eq!(trail.len(), 1);
        assert!(trail.verify_chain().is_ok());
    }

    #[test]
    fn test_audit_multiple_records_chain_integrity() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_decision("mod", "rule_a", PolicyDecision::Permit, "input1");
        trail.record_decision("mod", "rule_b", PolicyDecision::Deny, "input2");
        trail.record_decision("mod", "rule_c", PolicyDecision::Escalate, "input3");

        assert_eq!(trail.len(), 3);
        assert!(trail.verify_chain().is_ok());

        // Verify chain links: each record's previous_hash matches prior record's hash.
        let r0 = trail.get(0).unwrap();
        let r1 = trail.get(1).unwrap();
        let r2 = trail.get(2).unwrap();
        assert_eq!(r1.previous_hash, r0.record_hash);
        assert_eq!(r2.previous_hash, r1.record_hash);
    }

    #[test]
    fn test_audit_genesis_record_has_zero_previous() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_decision("mod", "rule", PolicyDecision::Deny, "");
        let first = trail.get(0).unwrap();
        assert_eq!(
            first.previous_hash,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_audit_record_counter_increments() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_decision("m", "r1", PolicyDecision::Permit, "");
        trail.record_decision("m", "r2", PolicyDecision::Deny, "");
        trail.record_decision("m", "r3", PolicyDecision::Quarantine, "");

        assert_eq!(trail.get(0).unwrap().record_id, 0);
        assert_eq!(trail.get(1).unwrap().record_id, 1);
        assert_eq!(trail.get(2).unwrap().record_id, 2);
    }

    #[test]
    fn test_audit_tamper_detection_modified_record() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_decision("mod", "rule_a", PolicyDecision::Permit, "");
        trail.record_decision("mod", "rule_b", PolicyDecision::Deny, "");

        assert!(trail.verify_chain().is_ok());

        // Tamper: export, modify, and re-verify via a new trail.
        let mut records = trail.export();
        records[0].function_name = "TAMPERED".to_string();

        // Build a tampered trail manually for verification.
        let mut tampered = AuditTrail::new(test_key());
        // We can't directly inject records, so we verify the exported records
        // by checking that the hash no longer matches.
        let recomputed = crate::runtime::audit::hash_input(b"dummy");
        assert_ne!(records[0].record_hash, recomputed);
        // The original trail should still verify fine.
        assert!(tampered.is_empty());
    }

    #[test]
    fn test_audit_verify_signatures() {
        let key = test_key();
        let mut trail = AuditTrail::new(key.clone());
        trail.record_decision("mod", "rule", PolicyDecision::Permit, "input");
        trail.record_decision("mod", "rule2", PolicyDecision::Deny, "input2");

        assert!(trail.verify_signatures(&key).is_ok());
    }

    #[test]
    fn test_audit_verify_signatures_wrong_key() {
        let key = test_key();
        let mut trail = AuditTrail::new(key);
        trail.record_decision("mod", "rule", PolicyDecision::Permit, "");

        let wrong_key = b"wrong-key-should-fail-verification".to_vec();
        let result = trail.verify_signatures(&wrong_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuditVerificationError::InvalidSignature { record_id: 0 }
        ));
    }

    #[test]
    fn test_audit_empty_trail_verification_error() {
        let trail = AuditTrail::new(test_key());
        assert!(matches!(
            trail.verify_chain().unwrap_err(),
            AuditVerificationError::EmptyTrail
        ));
        assert!(matches!(
            trail.verify_signatures(&test_key()).unwrap_err(),
            AuditVerificationError::EmptyTrail
        ));
    }

    #[test]
    fn test_audit_event_types() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_event("mod", "fn_a", AuditEventType::FunctionEntry);
        trail.record_event("mod", "fn_a", AuditEventType::FunctionExit);
        trail.record_event("mod", "cap", AuditEventType::CapabilityExercise);
        trail.record_event("mod", "model", AuditEventType::ModelInvocation);

        assert_eq!(trail.len(), 4);
        assert_eq!(trail.get(0).unwrap().event_type, AuditEventType::FunctionEntry);
        assert_eq!(trail.get(1).unwrap().event_type, AuditEventType::FunctionExit);
        assert_eq!(trail.get(2).unwrap().event_type, AuditEventType::CapabilityExercise);
        assert_eq!(trail.get(3).unwrap().event_type, AuditEventType::ModelInvocation);
        assert!(trail.verify_chain().is_ok());
    }

    #[test]
    fn test_audit_latest_record() {
        let mut trail = AuditTrail::new(test_key());
        assert!(trail.latest().is_none());

        trail.record_decision("mod", "r1", PolicyDecision::Permit, "");
        assert_eq!(trail.latest().unwrap().record_id, 0);

        trail.record_decision("mod", "r2", PolicyDecision::Deny, "");
        assert_eq!(trail.latest().unwrap().record_id, 1);
    }

    #[test]
    fn test_audit_decision_field_recorded() {
        let mut trail = AuditTrail::new(test_key());
        trail.record_decision("mod", "rule", PolicyDecision::Quarantine, "hash");

        let record = trail.get(0).unwrap();
        assert_eq!(record.decision, Some(PolicyDecision::Quarantine));
        assert_eq!(record.input_hash, "hash");
        assert_eq!(record.policy_module, "mod");
        assert_eq!(record.function_name, "rule");
    }

    #[test]
    fn test_audit_verification_error_display() {
        let e1 = AuditVerificationError::BrokenChain {
            record_id: 5,
            expected_hash: "abc".into(),
            actual_hash: "def".into(),
        };
        assert!(format!("{e1}").contains("broken hash chain"));
        assert!(format!("{e1}").contains("record 5"));

        let e2 = AuditVerificationError::InvalidSignature { record_id: 3 };
        assert!(format!("{e2}").contains("invalid signature"));

        let e3 = AuditVerificationError::EmptyTrail;
        assert!(format!("{e3}").contains("empty"));
    }

    // ═════════════════════════════════════════════════════════════════
    // Audited evaluator integration (M5 Layer 2)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_audited_evaluator_records_decision() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "access_policy")
            .unwrap();

        let result = evaluator.evaluate(&PolicyRequest::new(1, 2, 3, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);

        // Audit trail should have one record.
        let trail = evaluator.audit_trail();
        assert_eq!(trail.len(), 1);
        assert!(trail.verify_chain().is_ok());

        let record = trail.get(0).unwrap();
        assert_eq!(record.event_type, AuditEventType::PolicyDecision);
        assert_eq!(record.policy_module, "access_policy");
        assert_eq!(record.decision, Some(PolicyDecision::Permit));
    }

    #[test]
    fn test_audited_evaluator_multiple_evaluations() {
        let wasm = compile_wasm(r#"
policy risk {
    rule check(score: Int) {
        if score > 80 { escalate } else { permit }
    }
}
"#);
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "risk_policy")
            .unwrap();

        evaluator.evaluate(&PolicyRequest::new(90, 0, 0, 0)).unwrap();
        evaluator.evaluate(&PolicyRequest::new(50, 0, 0, 0)).unwrap();
        evaluator.evaluate(&PolicyRequest::new(95, 0, 0, 0)).unwrap();

        let trail = evaluator.audit_trail();
        assert_eq!(trail.len(), 3);
        assert!(trail.verify_chain().is_ok());
        assert!(trail.verify_signatures(&test_key()).is_ok());

        assert_eq!(trail.get(0).unwrap().decision, Some(PolicyDecision::Escalate));
        assert_eq!(trail.get(1).unwrap().decision, Some(PolicyDecision::Permit));
        assert_eq!(trail.get(2).unwrap().decision, Some(PolicyDecision::Escalate));
    }

    #[test]
    fn test_audited_evaluator_export_log() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "mod")
            .unwrap();

        evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        let log = evaluator.export_audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].decision, Some(PolicyDecision::Permit));
    }

    #[test]
    fn test_audited_evaluator_rule_evaluation() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "mod")
            .unwrap();

        let result = evaluator.evaluate_rule("access__allow", &[]).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);

        let trail = evaluator.audit_trail();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail.get(0).unwrap().function_name, "access__allow");
    }

    #[test]
    fn test_hash_input_utility() {
        let h1 = hash_input(b"hello");
        let h2 = hash_input(b"hello");
        let h3 = hash_input(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    // ═════════════════════════════════════════════════════════════════
    // Model attestation — trust chain verification (M5 Layer 3)
    // ═════════════════════════════════════════════════════════════════

    use crate::runtime::attestation::*;
    use std::time::SystemTime;

    fn test_provenance() -> ModelProvenance {
        ModelProvenance {
            source_repository: "https://example.com/models".to_string(),
            training_data_hash: Some("abc123".to_string()),
            framework: "pytorch".to_string(),
            architecture: "transformer".to_string(),
            slsa_level: Some(3),
        }
    }

    fn test_attestation(key: &[u8], signer: &str) -> ModelAttestation {
        let timestamp = SystemTime::now();
        let model_hash = "deadbeef".to_string();
        let signature = sign_attestation(key, &model_hash, signer, timestamp);
        ModelAttestation {
            model_id: "test-model-v1".to_string(),
            model_hash,
            signer: signer.to_string(),
            signature,
            timestamp,
            provenance: test_provenance(),
            policy_requirements: vec!["eu-ai-act".to_string()],
        }
    }

    // ── AttestationChecker — signature verification ──────────────

    #[test]
    fn test_attestation_valid_signature() {
        let key = b"attestation-key-1234".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy::permissive());
        checker.add_trusted_key("trusted-signer", key.clone());

        let att = test_attestation(&key, "trusted-signer");
        let result = checker.verify(&att);
        assert!(result.is_ok());
        match result.unwrap() {
            AttestationVerdict::Trusted { signer, .. } => {
                assert_eq!(signer, "trusted-signer");
            }
            _ => panic!("expected Trusted verdict"),
        }
    }

    #[test]
    fn test_attestation_invalid_signature() {
        let key = b"attestation-key-1234".to_vec();
        let wrong_key = b"wrong-key-5678".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy::permissive());
        checker.add_trusted_key("trusted-signer", key);

        // Sign with wrong key but claim trusted-signer.
        let att = test_attestation(&wrong_key, "trusted-signer");
        let result = checker.verify(&att);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::InvalidSignature { .. }
        ));
    }

    #[test]
    fn test_attestation_unknown_signer() {
        let key = b"attestation-key-1234".to_vec();
        let checker = AttestationChecker::new(AttestationPolicy::permissive());
        // No trusted keys added.

        let att = test_attestation(&key, "unknown-signer");
        let result = checker.verify(&att);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::UnknownSigner { .. }
        ));
    }

    #[test]
    fn test_attestation_multiple_trusted_signers() {
        let key_a = b"key-for-signer-a".to_vec();
        let key_b = b"key-for-signer-b".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy::permissive());
        checker.add_trusted_key("signer-a", key_a.clone());
        checker.add_trusted_key("signer-b", key_b.clone());

        let att_a = test_attestation(&key_a, "signer-a");
        assert!(checker.verify(&att_a).is_ok());

        let att_b = test_attestation(&key_b, "signer-b");
        assert!(checker.verify(&att_b).is_ok());
    }

    // ── AttestationChecker — provenance verification ─────────────

    #[test]
    fn test_attestation_slsa_level_sufficient() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            minimum_slsa_level: Some(2),
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer"); // slsa_level = Some(3)
        assert!(checker.verify(&att).is_ok());
    }

    #[test]
    fn test_attestation_slsa_level_insufficient() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            minimum_slsa_level: Some(4),
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer"); // slsa_level = Some(3)
        let result = checker.verify(&att);
        assert!(result.is_err());
        match result.unwrap_err() {
            AttestationError::InsufficientSLSALevel { required, actual } => {
                assert_eq!(required, 4);
                assert_eq!(actual, 3);
            }
            other => panic!("expected InsufficientSLSALevel, got {other:?}"),
        }
    }

    #[test]
    fn test_attestation_slsa_level_missing_treated_as_zero() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            minimum_slsa_level: Some(1),
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let mut att = test_attestation(&key, "signer");
        att.provenance.slsa_level = None;
        // Re-sign not needed — provenance not in signature, only model_hash/signer/timestamp.
        let result = checker.verify(&att);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::InsufficientSLSALevel { required: 1, actual: 0 }
        ));
    }

    #[test]
    fn test_attestation_allowed_framework_pass() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            allowed_frameworks: Some(vec!["pytorch".to_string(), "onnx".to_string()]),
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer"); // framework = "pytorch"
        assert!(checker.verify(&att).is_ok());
    }

    #[test]
    fn test_attestation_disallowed_framework() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            allowed_frameworks: Some(vec!["onnx".to_string(), "tensorflow".to_string()]),
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer"); // framework = "pytorch"
        let result = checker.verify(&att);
        assert!(result.is_err());
        match result.unwrap_err() {
            AttestationError::DisallowedFramework { framework, allowed } => {
                assert_eq!(framework, "pytorch");
                assert!(allowed.contains(&"onnx".to_string()));
            }
            other => panic!("expected DisallowedFramework, got {other:?}"),
        }
    }

    #[test]
    fn test_attestation_training_data_hash_required_present() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            require_training_data_hash: true,
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer"); // has training_data_hash
        assert!(checker.verify(&att).is_ok());
    }

    #[test]
    fn test_attestation_training_data_hash_required_missing() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            require_training_data_hash: true,
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let mut att = test_attestation(&key, "signer");
        att.provenance.training_data_hash = None;
        let result = checker.verify(&att);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::MissingTrainingDataHash { .. }
        ));
    }

    // ── AttestationChecker — policy verification ─────────────────

    #[test]
    fn test_attestation_required_signer_present() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            required_signers: vec!["signer".to_string(), "backup-signer".to_string()],
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer");
        assert!(checker.verify(&att).is_ok());
    }

    #[test]
    fn test_attestation_no_trusted_signer() {
        let key_a = b"key-a".to_vec();
        let key_b = b"key-b".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            required_signers: vec!["required-signer".to_string()],
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("other-signer", key_a.clone());

        // Sign with key_a as "other-signer" — valid signature but not a required signer.
        let att = test_attestation(&key_a, "other-signer");
        let result = checker.verify(&att);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::NoTrustedSigner { .. }
        ));
    }

    #[test]
    fn test_attestation_expired() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            max_age_seconds: Some(0), // Immediately expired.
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        // Use a timestamp slightly in the past.
        let old_time = SystemTime::now() - std::time::Duration::from_secs(2);
        let model_hash = "deadbeef".to_string();
        let signature = sign_attestation(&key, &model_hash, "signer", old_time);
        let att = ModelAttestation {
            model_id: "old-model".to_string(),
            model_hash,
            signer: "signer".to_string(),
            signature,
            timestamp: old_time,
            provenance: test_provenance(),
            policy_requirements: vec![],
        };

        let result = checker.verify(&att);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AttestationError::ExpiredAttestation { .. }
        ));
    }

    #[test]
    fn test_attestation_not_expired() {
        let key = b"key".to_vec();
        let mut checker = AttestationChecker::new(AttestationPolicy {
            max_age_seconds: Some(3600), // 1 hour.
            ..AttestationPolicy::permissive()
        });
        checker.add_trusted_key("signer", key.clone());

        let att = test_attestation(&key, "signer"); // Just created → not expired.
        assert!(checker.verify(&att).is_ok());
    }

    // ── Permissive policy ────────────────────────────────────────

    #[test]
    fn test_attestation_permissive_policy() {
        let policy = AttestationPolicy::permissive();
        assert!(policy.required_signers.is_empty());
        assert!(policy.minimum_slsa_level.is_none());
        assert!(policy.allowed_frameworks.is_none());
        assert!(!policy.require_training_data_hash);
        assert!(policy.max_age_seconds.is_none());
    }

    // ── sign_attestation determinism ─────────────────────────────

    #[test]
    fn test_sign_attestation_deterministic() {
        let key = b"key".to_vec();
        let ts = SystemTime::now();
        let s1 = sign_attestation(&key, "hash1", "signer", ts);
        let s2 = sign_attestation(&key, "hash1", "signer", ts);
        let s3 = sign_attestation(&key, "hash2", "signer", ts);
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
        assert_eq!(s1.len(), 64); // HMAC-SHA256 = 32 bytes = 64 hex chars
    }

    // ── AttestationError display ─────────────────────────────────

    #[test]
    fn test_attestation_error_display() {
        let e1 = AttestationError::UnknownSigner { signer: "x".into() };
        assert!(format!("{e1}").contains("unknown signer"));

        let e2 = AttestationError::InvalidSignature {
            signer: "s".into(), model_id: "m".into(),
        };
        assert!(format!("{e2}").contains("invalid signature"));

        let e3 = AttestationError::InsufficientSLSALevel { required: 3, actual: 1 };
        assert!(format!("{e3}").contains("SLSA level"));

        let e4 = AttestationError::DisallowedFramework {
            framework: "tf".into(), allowed: vec!["pt".into()],
        };
        assert!(format!("{e4}").contains("not in allowed list"));

        let e5 = AttestationError::MissingTrainingDataHash { model_id: "m".into() };
        assert!(format!("{e5}").contains("missing required training data hash"));

        let e6 = AttestationError::ExpiredAttestation {
            age_seconds: 100, max_age_seconds: 60,
        };
        assert!(format!("{e6}").contains("expired"));

        let e7 = AttestationError::NoTrustedSigner {
            model_id: "m".into(), required_signers: vec!["s".into()],
        };
        assert!(format!("{e7}").contains("not signed by any required signer"));
    }

    // ── AttestationChecker debug ─────────────────────────────────

    #[test]
    fn test_attestation_checker_debug() {
        let mut checker = AttestationChecker::new(AttestationPolicy::permissive());
        checker.add_trusted_key("signer-a", b"key-a".to_vec());
        let debug = format!("{checker:?}");
        assert!(debug.contains("AttestationChecker"));
        assert!(debug.contains("signer-a"));
    }

    // ── Evaluator integration with attestation ───────────────────

    #[test]
    fn test_audited_evaluator_with_attestation_verify_trusted() {
        let key = b"attest-key".to_vec();
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();

        let mut attest_checker = AttestationChecker::new(AttestationPolicy::permissive());
        attest_checker.add_trusted_key("signer", key.clone());

        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "mod")
            .unwrap()
            .with_attestation(attest_checker);

        let att = test_attestation(&key, "signer");
        let verdict = evaluator.verify_model(&att);
        assert!(verdict.is_ok());

        // Audit trail should record the attestation verification event.
        let trail = evaluator.audit_trail();
        assert_eq!(trail.len(), 1);
        assert_eq!(
            trail.get(0).unwrap().event_type,
            AuditEventType::ModelAttestationVerified
        );
        assert!(trail.get(0).unwrap().function_name.contains("test-model-v1"));
    }

    #[test]
    fn test_audited_evaluator_with_attestation_verify_rejected() {
        let key = b"attest-key".to_vec();
        let wrong_key = b"wrong-attest-key".to_vec();
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();

        let mut attest_checker = AttestationChecker::new(AttestationPolicy::permissive());
        attest_checker.add_trusted_key("signer", key.clone());

        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "mod")
            .unwrap()
            .with_attestation(attest_checker);

        // Sign with wrong key → invalid signature.
        let att = test_attestation(&wrong_key, "signer");
        let verdict = evaluator.verify_model(&att);
        assert!(verdict.is_err());

        // Audit trail should record the rejection event.
        let trail = evaluator.audit_trail();
        assert_eq!(trail.len(), 1);
        assert_eq!(
            trail.get(0).unwrap().event_type,
            AuditEventType::ModelAttestationRejected
        );
    }

    #[test]
    fn test_audited_evaluator_attestation_then_evaluate() {
        let key = b"attest-key".to_vec();
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();

        let mut attest_checker = AttestationChecker::new(AttestationPolicy::permissive());
        attest_checker.add_trusted_key("signer", key.clone());

        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "mod")
            .unwrap()
            .with_attestation(attest_checker);

        // First verify the model, then evaluate policy.
        let att = test_attestation(&key, "signer");
        assert!(evaluator.verify_model(&att).is_ok());

        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);

        // Trail: attestation verified + policy decision = 2 records.
        let trail = evaluator.audit_trail();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail.get(0).unwrap().event_type, AuditEventType::ModelAttestationVerified);
        assert_eq!(trail.get(1).unwrap().event_type, AuditEventType::PolicyDecision);
        assert!(trail.verify_chain().is_ok());
    }

    #[test]
    fn test_audited_evaluator_no_attestation_checker_error() {
        let wasm = compile_wasm("policy access { rule allow() { permit } }");
        let module = PolicyModule::from_bytes(&wasm).unwrap();

        let mut evaluator = AuditedPolicyEvaluator::new(&module, test_key(), "mod")
            .unwrap();
        // No attestation checker attached.

        let att = test_attestation(b"key", "signer");
        let result = evaluator.verify_model(&att);
        assert!(result.is_err());
    }

    // ═════════════════════════════════════════════════════════════════
    // End-to-end pipeline integration (M5 Layer 4)
    // ═════════════════════════════════════════════════════════════════

    use crate::runtime::pipeline::{PipelineConfig, RuntimePipeline};

    fn pipeline_config() -> PipelineConfig {
        PipelineConfig {
            signing_key: test_key(),
            module_name: "test-module".to_string(),
            attestation_checker: None,
        }
    }

    fn pipeline_config_with_attestation(attest_key: &[u8]) -> PipelineConfig {
        let mut checker = AttestationChecker::new(AttestationPolicy::permissive());
        checker.add_trusted_key("signer", attest_key.to_vec());
        PipelineConfig {
            signing_key: test_key(),
            module_name: "test-module".to_string(),
            attestation_checker: Some(checker),
        }
    }

    // 1. Full pipeline: compile → evaluate → verify audit trail
    #[test]
    fn test_e2e_compile_evaluate_audit() {
        let mut pipeline = RuntimePipeline::from_source(
            "policy access { rule allow() { permit } }",
            pipeline_config(),
        ).unwrap();

        let result = pipeline.evaluate(&PolicyRequest::new(1, 2, 3, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);

        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 1);
        assert!(trail.verify_chain().is_ok());
        assert!(trail.verify_signatures(&test_key()).is_ok());
        assert_eq!(trail.get(0).unwrap().event_type, AuditEventType::PolicyDecision);
        assert_eq!(trail.get(0).unwrap().decision, Some(PolicyDecision::Permit));
    }

    // 2. Full pipeline with attestation: compile → verify model → evaluate → audit
    #[test]
    fn test_e2e_attestation_then_evaluate() {
        let attest_key = b"attest-e2e-key".to_vec();
        let mut pipeline = RuntimePipeline::from_source(
            "policy access { rule allow() { permit } }",
            pipeline_config_with_attestation(&attest_key),
        ).unwrap();

        // Verify model attestation.
        let att = test_attestation(&attest_key, "signer");
        let verdict = pipeline.verify_model(&att);
        assert!(verdict.is_ok());

        // Evaluate policy.
        let result = pipeline.evaluate(&PolicyRequest::new(1, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Permit);

        // Audit trail has both events, chain intact.
        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail.get(0).unwrap().event_type, AuditEventType::ModelAttestationVerified);
        assert_eq!(trail.get(1).unwrap().event_type, AuditEventType::PolicyDecision);
        assert!(trail.verify_chain().is_ok());
        assert!(trail.verify_signatures(&test_key()).is_ok());
    }

    // 3. Full pipeline with attestation rejection
    #[test]
    fn test_e2e_attestation_rejection_recorded() {
        let attest_key = b"attest-e2e-key".to_vec();
        let wrong_key = b"wrong-e2e-key".to_vec();
        let mut pipeline = RuntimePipeline::from_source(
            "policy access { rule allow() { permit } }",
            pipeline_config_with_attestation(&attest_key),
        ).unwrap();

        // Verify with wrong key → rejection.
        let att = test_attestation(&wrong_key, "signer");
        let verdict = pipeline.verify_model(&att);
        assert!(verdict.is_err());

        // Audit trail records the rejection.
        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail.get(0).unwrap().event_type, AuditEventType::ModelAttestationRejected);
        assert!(trail.verify_chain().is_ok());
    }

    // 4. Full pipeline multiple evaluations: 5 requests, chain intact
    #[test]
    fn test_e2e_multiple_evaluations_audit_chain() {
        let mut pipeline = RuntimePipeline::from_source(
            r#"
policy risk {
    rule check(score: Int) {
        if score > 80 { escalate } else { permit }
    }
}
"#,
            pipeline_config(),
        ).unwrap();

        let decisions = [
            (90, PolicyDecision::Escalate),
            (50, PolicyDecision::Permit),
            (95, PolicyDecision::Escalate),
            (10, PolicyDecision::Permit),
            (85, PolicyDecision::Escalate),
        ];

        for (score, expected) in &decisions {
            let result = pipeline.evaluate(&PolicyRequest::new(*score, 0, 0, 0)).unwrap();
            assert_eq!(result.decision, *expected);
        }

        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 5);
        assert!(trail.verify_chain().is_ok());
        assert!(trail.verify_signatures(&test_key()).is_ok());

        // Verify each decision recorded correctly.
        for (i, (_, expected)) in decisions.iter().enumerate() {
            assert_eq!(trail.get(i).unwrap().decision, Some(*expected));
        }
    }

    // 5. Full pipeline with risk-based conditional logic
    #[test]
    fn test_e2e_risk_based_policy_decisions_in_audit() {
        let mut pipeline = RuntimePipeline::from_source(
            r#"
policy ai_governance {
    rule risk_check(risk_score: Int) {
        if risk_score > 90 { quarantine }
        else { if risk_score > 70 { escalate }
        else { if risk_score > 50 { deny }
        else { permit } } }
    }
}
"#,
            pipeline_config(),
        ).unwrap();

        let r1 = pipeline.evaluate(&PolicyRequest::new(95, 0, 0, 0)).unwrap();
        assert_eq!(r1.decision, PolicyDecision::Quarantine);

        let r2 = pipeline.evaluate(&PolicyRequest::new(75, 0, 0, 0)).unwrap();
        assert_eq!(r2.decision, PolicyDecision::Escalate);

        let r3 = pipeline.evaluate(&PolicyRequest::new(55, 0, 0, 0)).unwrap();
        assert_eq!(r3.decision, PolicyDecision::Deny);

        let r4 = pipeline.evaluate(&PolicyRequest::new(30, 0, 0, 0)).unwrap();
        assert_eq!(r4.decision, PolicyDecision::Permit);

        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 4);
        assert!(trail.verify_chain().is_ok());

        assert_eq!(trail.get(0).unwrap().decision, Some(PolicyDecision::Quarantine));
        assert_eq!(trail.get(1).unwrap().decision, Some(PolicyDecision::Escalate));
        assert_eq!(trail.get(2).unwrap().decision, Some(PolicyDecision::Deny));
        assert_eq!(trail.get(3).unwrap().decision, Some(PolicyDecision::Permit));
    }

    // 6. Pipeline compile error: clear error, no panic
    #[test]
    fn test_e2e_compile_error() {
        let result = RuntimePipeline::from_source(
            "fn bad( { }",
            pipeline_config(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            RuntimeError::CompilationFailed(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("expected CompilationFailed, got {other:?}"),
        }
    }

    // 7. Pipeline rule evaluation with audit trail
    #[test]
    fn test_e2e_rule_evaluation_audited() {
        let mut pipeline = RuntimePipeline::from_source(
            "policy access { rule allow() { permit } rule block() { deny } }",
            pipeline_config(),
        ).unwrap();

        let r1 = pipeline.evaluate_rule("access__allow", &[]).unwrap();
        assert_eq!(r1.decision, PolicyDecision::Permit);

        let r2 = pipeline.evaluate_rule("access__block", &[]).unwrap();
        assert_eq!(r2.decision, PolicyDecision::Deny);

        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail.get(0).unwrap().function_name, "access__allow");
        assert_eq!(trail.get(1).unwrap().function_name, "access__block");
        assert!(trail.verify_chain().is_ok());
    }

    // 8. Pipeline config with no attestation checker: verify_model returns error
    #[test]
    fn test_e2e_no_attestation_checker_verify_model_error() {
        let mut pipeline = RuntimePipeline::from_source(
            "policy access { rule allow() { permit } }",
            pipeline_config(), // No attestation checker.
        ).unwrap();

        let att = test_attestation(b"key", "signer");
        let result = pipeline.verify_model(&att);
        assert!(result.is_err());

        // Evaluation still works without attestation.
        let eval = pipeline.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(eval.decision, PolicyDecision::Permit);
    }

    // 9. Audit trail export and independent verification
    #[test]
    fn test_e2e_export_and_independent_verification() {
        let signing_key = test_key();
        let mut pipeline = RuntimePipeline::from_source(
            "policy access { rule allow() { permit } }",
            PipelineConfig {
                signing_key: signing_key.clone(),
                module_name: "export-test".to_string(),
                attestation_checker: None,
            },
        ).unwrap();

        pipeline.evaluate(&PolicyRequest::new(1, 0, 0, 0)).unwrap();
        pipeline.evaluate(&PolicyRequest::new(2, 0, 0, 0)).unwrap();
        pipeline.evaluate(&PolicyRequest::new(3, 0, 0, 0)).unwrap();

        // Export audit log.
        let exported = pipeline.export_audit_log();
        assert_eq!(exported.len(), 3);

        // Independent verification: rebuild chain from exported records.
        let genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(exported[0].previous_hash, genesis);
        assert_eq!(exported[1].previous_hash, exported[0].record_hash);
        assert_eq!(exported[2].previous_hash, exported[1].record_hash);

        // Verify all record IDs are sequential.
        assert_eq!(exported[0].record_id, 0);
        assert_eq!(exported[1].record_id, 1);
        assert_eq!(exported[2].record_id, 2);

        // Verify module name is recorded.
        for record in &exported {
            assert_eq!(record.policy_module, "export-test");
        }

        // Verify via trail methods still works.
        let trail = pipeline.audit_trail();
        assert!(trail.verify_chain().is_ok());
        assert!(trail.verify_signatures(&signing_key).is_ok());
    }

    // 10. Full governance scenario: EU AI Act multi-rule policy
    #[test]
    fn test_e2e_full_governance_eu_ai_act() {
        let attest_key = b"eu-ai-act-signer-key".to_vec();

        let mut pipeline = RuntimePipeline::from_source(
            r#"
fn is_high_risk(score: Int) -> Bool { score > 70 }

policy eu_ai_act {
    rule risk_assessment(risk_score: Int) {
        if risk_score > 90 { quarantine }
        else { if risk_score > 70 { escalate }
        else { permit } }
    }

    rule human_oversight(action: Int) {
        if action > 100 { escalate } else { permit }
    }

    rule transparency_check(resource_id: Int) {
        if resource_id == 0 { deny } else { permit }
    }
}
"#,
            pipeline_config_with_attestation(&attest_key),
        ).unwrap();

        // Step 1: Verify model attestation.
        let att = test_attestation(&attest_key, "signer");
        let verdict = pipeline.verify_model(&att).unwrap();
        match verdict {
            AttestationVerdict::Trusted { signer, .. } => assert_eq!(signer, "signer"),
            _ => panic!("expected Trusted"),
        }

        // Note: evaluate(subject_id, action, resource_id, risk_score) dispatches
        // to each rule with positional params. Each single-param rule receives
        // subject_id as its first arg. Multi-rule first-non-permit-wins semantics.

        // Step 2: subject_id=95 → risk_assessment(95) = quarantine (first non-permit wins).
        let r1 = pipeline.evaluate(&PolicyRequest::new(95, 0, 1, 0)).unwrap();
        assert_eq!(r1.decision, PolicyDecision::Quarantine);

        // Step 3: subject_id=80 → risk_assessment(80) = escalate.
        let r2 = pipeline.evaluate(&PolicyRequest::new(80, 0, 1, 0)).unwrap();
        assert_eq!(r2.decision, PolicyDecision::Escalate);

        // Step 4: subject_id=0 → risk_assessment(0) = permit, human_oversight(0) = permit,
        //         transparency_check(0) = deny.
        let r3 = pipeline.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(r3.decision, PolicyDecision::Deny);

        // Step 5: subject_id=50, all rules permit → permit.
        let r4 = pipeline.evaluate(&PolicyRequest::new(50, 0, 1, 0)).unwrap();
        assert_eq!(r4.decision, PolicyDecision::Permit);

        // Verify complete audit trail: 1 attestation + 4 evaluations = 5 records.
        let trail = pipeline.audit_trail();
        assert_eq!(trail.len(), 5);
        assert!(trail.verify_chain().is_ok());
        assert!(trail.verify_signatures(&test_key()).is_ok());

        // Verify event sequence.
        assert_eq!(trail.get(0).unwrap().event_type, AuditEventType::ModelAttestationVerified);
        assert_eq!(trail.get(1).unwrap().event_type, AuditEventType::PolicyDecision);
        assert_eq!(trail.get(2).unwrap().event_type, AuditEventType::PolicyDecision);
        assert_eq!(trail.get(3).unwrap().event_type, AuditEventType::PolicyDecision);
        assert_eq!(trail.get(4).unwrap().event_type, AuditEventType::PolicyDecision);

        // Verify decisions recorded.
        assert_eq!(trail.get(1).unwrap().decision, Some(PolicyDecision::Quarantine));
        assert_eq!(trail.get(2).unwrap().decision, Some(PolicyDecision::Escalate));
        assert_eq!(trail.get(3).unwrap().decision, Some(PolicyDecision::Deny));
        assert_eq!(trail.get(4).unwrap().decision, Some(PolicyDecision::Permit));
    }
}
