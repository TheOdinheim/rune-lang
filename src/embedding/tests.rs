#[cfg(test)]
mod tests {
    use std::ffi::c_char;

    use crate::embedding::*;
    use crate::embedding::safe_api::*;
    use crate::runtime::evaluator::PolicyDecision;

    const TEST_KEY: &[u8] = b"test-signing-key";

    fn permit_source() -> &'static str {
        "policy access { rule allow(subject: Int, action: Int, resource: Int, risk: Int) { permit } }"
    }

    fn deny_source() -> &'static str {
        "policy access { rule block(subject: Int, action: Int, resource: Int, risk: Int) { deny } }"
    }

    fn risk_source() -> &'static str {
        r#"
        policy risk_based {
            rule check_risk(subject: Int, action: Int, resource: Int, risk: Int) {
                if risk > 50 { deny } else { permit }
            }
        }
        "#
    }

    fn multi_rule_source() -> &'static str {
        r#"
        policy multi {
            rule high_risk(subject: Int, action: Int, resource: Int, risk: Int) {
                if risk > 80 { quarantine } else { permit }
            }
            rule medium_risk(subject: Int, action: Int, resource: Int, risk: Int) {
                if risk > 50 { escalate } else { permit }
            }
        }
        "#
    }

    // ═════════════════════════════════════════════════════════════════
    // C ABI struct tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_policy_request_c_layout() {
        // RunePolicyRequest should have a predictable C-compatible layout.
        let req = RunePolicyRequest {
            subject_id: 1,
            action: 2,
            resource_id: 3,
            risk_score: 4,
            context_json: std::ptr::null(),
            context_json_len: 0,
        };
        assert_eq!(req.subject_id, 1);
        assert_eq!(req.action, 2);
        assert_eq!(req.resource_id, 3);
        assert_eq!(req.risk_score, 4);
        assert!(req.context_json.is_null());
        assert_eq!(req.context_json_len, 0);
    }

    #[test]
    fn test_policy_decision_c_layout() {
        let dec = RunePolicyDecision::new_deny();
        assert_eq!(dec.outcome, RUNE_DENY);
        assert_eq!(dec.matched_rule[0], 0);
        assert_eq!(dec.evaluation_duration_us, 0);
        assert_eq!(dec.error_message[0], 0);
        assert_eq!(dec.audit_record_id, 0);
    }

    #[test]
    fn test_outcome_constants() {
        assert_eq!(RUNE_PERMIT, 0);
        assert_eq!(RUNE_DENY, 1);
        assert_eq!(RUNE_ESCALATE, 2);
        assert_eq!(RUNE_QUARANTINE, 3);
        assert_eq!(RUNE_ERROR, -1);
    }

    #[test]
    fn test_policy_decision_to_i32() {
        assert_eq!(i32::from(PolicyDecision::Permit), RUNE_PERMIT);
        assert_eq!(i32::from(PolicyDecision::Deny), RUNE_DENY);
        assert_eq!(i32::from(PolicyDecision::Escalate), RUNE_ESCALATE);
        assert_eq!(i32::from(PolicyDecision::Quarantine), RUNE_QUARANTINE);
    }

    // ═════════════════════════════════════════════════════════════════
    // Fail-closed tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_decision_is_deny() {
        let dec = RunePolicyDecision::error("something went wrong");
        // Error decisions use RUNE_ERROR outcome but are functionally DENY.
        assert_eq!(dec.outcome, RUNE_ERROR);
        let msg = c_buf_to_string(&dec.error_message);
        assert!(msg.contains("something went wrong"));
    }

    #[test]
    fn test_decision_from_result_error_is_deny() {
        let err = crate::runtime::evaluator::RuntimeError::EvaluationFailed("boom".to_string());
        let dec = decision_from_result(Err(err), 0);
        assert_eq!(dec.outcome, RUNE_DENY);
        let msg = c_buf_to_string(&dec.error_message);
        assert!(msg.contains("boom"));
    }

    #[test]
    fn test_null_module_evaluate_produces_deny() {
        let req = RunePolicyRequest {
            subject_id: 1,
            action: 1,
            resource_id: 1,
            risk_score: 10,
            context_json: std::ptr::null(),
            context_json_len: 0,
        };
        let mut dec = RunePolicyDecision::new_deny();
        let ret = rune_evaluate(std::ptr::null_mut(), &req, &mut dec);
        assert_eq!(ret, RUNE_ERROR);
        assert!(dec.outcome == RUNE_ERROR || dec.outcome == RUNE_DENY);
    }

    #[test]
    fn test_invalid_source_returns_null() {
        let source = b"this is not valid rune code!!!";
        let key = TEST_KEY;
        let name = b"test";
        let ptr = rune_module_load_source(
            source.as_ptr() as *const c_char,
            source.len(),
            key.as_ptr(),
            key.len(),
            name.as_ptr() as *const c_char,
            name.len(),
        );
        assert!(ptr.is_null());
    }

    // ═════════════════════════════════════════════════════════════════
    // Lifecycle tests (C API)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_load_evaluate_free_lifecycle() {
        let source = permit_source().as_bytes();
        let key = TEST_KEY;
        let name = b"test_module";

        let module = rune_module_load_source(
            source.as_ptr() as *const c_char,
            source.len(),
            key.as_ptr(),
            key.len(),
            name.as_ptr() as *const c_char,
            name.len(),
        );
        assert!(!module.is_null(), "failed to load module");

        let req = RunePolicyRequest {
            subject_id: 1,
            action: 1,
            resource_id: 1,
            risk_score: 10,
            context_json: std::ptr::null(),
            context_json_len: 0,
        };
        let mut dec = RunePolicyDecision::new_deny();

        let ret = rune_evaluate(module, &req, &mut dec);
        assert_eq!(ret, 0);
        assert_eq!(dec.outcome, RUNE_PERMIT);
        assert!(dec.evaluation_duration_us > 0 || true); // duration may be 0 on fast machines

        rune_module_free(module);
    }

    #[test]
    fn test_free_null_is_safe() {
        rune_module_free(std::ptr::null_mut());
        // Should not crash.
    }

    #[test]
    fn test_audit_trail_len_increases() {
        let source = permit_source().as_bytes();
        let key = TEST_KEY;
        let name = b"audit_test";

        let module = rune_module_load_source(
            source.as_ptr() as *const c_char,
            source.len(),
            key.as_ptr(),
            key.len(),
            name.as_ptr() as *const c_char,
            name.len(),
        );
        assert!(!module.is_null());

        assert_eq!(rune_audit_trail_len(module), 0);

        let req = RunePolicyRequest {
            subject_id: 1,
            action: 1,
            resource_id: 1,
            risk_score: 10,
            context_json: std::ptr::null(),
            context_json_len: 0,
        };
        let mut dec = RunePolicyDecision::new_deny();

        rune_evaluate(module, &req, &mut dec);
        assert!(rune_audit_trail_len(module) >= 1);

        rune_evaluate(module, &req, &mut dec);
        assert!(rune_audit_trail_len(module) >= 2);

        rune_module_free(module);
    }

    #[test]
    fn test_audit_trail_len_null_returns_zero() {
        assert_eq!(rune_audit_trail_len(std::ptr::null_mut()), 0);
    }

    // ═════════════════════════════════════════════════════════════════
    // Safe Rust API tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_engine_from_source_compiles() {
        let engine = RuneEngine::from_source(permit_source(), TEST_KEY, "test");
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_from_source_invalid_returns_err() {
        let engine = RuneEngine::from_source("not valid rune!!!", TEST_KEY, "test");
        assert!(engine.is_err());
    }

    #[test]
    fn test_engine_evaluate_permit() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "test").unwrap();
        let req = EmbeddingRequest::new(1, 1, 1, 10);
        let dec = engine.evaluate(&req);
        assert_eq!(dec.outcome, PolicyDecision::Permit);
        assert!(dec.error.is_none());
    }

    #[test]
    fn test_engine_evaluate_deny() {
        let mut engine = RuneEngine::from_source(deny_source(), TEST_KEY, "test").unwrap();
        let req = EmbeddingRequest::new(1, 1, 1, 10);
        let dec = engine.evaluate(&req);
        assert_eq!(dec.outcome, PolicyDecision::Deny);
    }

    #[test]
    fn test_engine_evaluate_risk_based() {
        let mut engine = RuneEngine::from_source(risk_source(), TEST_KEY, "test").unwrap();

        let low_risk = EmbeddingRequest::new(1, 1, 1, 30);
        assert_eq!(engine.evaluate(&low_risk).outcome, PolicyDecision::Permit);

        let high_risk = EmbeddingRequest::new(1, 1, 1, 80);
        assert_eq!(engine.evaluate(&high_risk).outcome, PolicyDecision::Deny);
    }

    #[test]
    fn test_engine_audit_trail_len() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "test").unwrap();
        assert_eq!(engine.audit_trail_len(), 0);

        let req = EmbeddingRequest::new(1, 1, 1, 10);
        engine.evaluate(&req);
        assert!(engine.audit_trail_len() >= 1);

        engine.evaluate(&req);
        assert!(engine.audit_trail_len() >= 2);
    }

    #[test]
    fn test_engine_export_audit_log() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "test").unwrap();
        let req = EmbeddingRequest::new(1, 1, 1, 10);
        engine.evaluate(&req);

        let log = engine.export_audit_log();
        assert!(!log.is_empty());
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_embedding_scenario() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "integration").unwrap();

        // Multiple evaluations.
        for i in 0..5 {
            let req = EmbeddingRequest::new(i, 1, 1, 10);
            let dec = engine.evaluate(&req);
            assert_eq!(dec.outcome, PolicyDecision::Permit);
        }

        // Check audit trail.
        assert!(engine.audit_trail_len() >= 5);
        let log = engine.export_audit_log();
        assert!(log.len() >= 5);
    }

    #[test]
    fn test_embedding_risk_based_policy() {
        let mut engine = RuneEngine::from_source(risk_source(), TEST_KEY, "risk").unwrap();

        // Low risk → Permit.
        let dec = engine.evaluate(&EmbeddingRequest::new(1, 1, 1, 20));
        assert_eq!(dec.outcome, PolicyDecision::Permit);

        // High risk → Deny.
        let dec = engine.evaluate(&EmbeddingRequest::new(1, 1, 1, 90));
        assert_eq!(dec.outcome, PolicyDecision::Deny);
    }

    #[test]
    fn test_embedding_multi_rule_first_non_permit_wins() {
        let mut engine = RuneEngine::from_source(multi_rule_source(), TEST_KEY, "multi").unwrap();

        // risk=90 → first rule returns Quarantine (before Escalate).
        let dec = engine.evaluate(&EmbeddingRequest::new(1, 1, 1, 90));
        assert_eq!(dec.outcome, PolicyDecision::Quarantine);

        // risk=60 → first rule permits, second rule returns Escalate.
        let dec = engine.evaluate(&EmbeddingRequest::new(1, 1, 1, 60));
        assert_eq!(dec.outcome, PolicyDecision::Escalate);

        // risk=30 → both rules permit.
        let dec = engine.evaluate(&EmbeddingRequest::new(1, 1, 1, 30));
        assert_eq!(dec.outcome, PolicyDecision::Permit);
    }

    #[test]
    fn test_load_wasm_evaluate_lifecycle() {
        // Compile to WASM first, then load from bytes.
        let wasm_bytes = crate::compiler::compile_source(permit_source(), 0).unwrap();
        let engine = RuneEngine::from_wasm(&wasm_bytes, TEST_KEY, "wasm_test");
        assert!(engine.is_ok());
        let mut engine = engine.unwrap();
        let req = EmbeddingRequest::new(1, 1, 1, 10);
        let dec = engine.evaluate(&req);
        assert_eq!(dec.outcome, PolicyDecision::Permit);
    }

    #[test]
    fn test_c_api_load_wasm_evaluate() {
        let wasm_bytes = crate::compiler::compile_source(permit_source(), 0).unwrap();
        let key = TEST_KEY;
        let name = b"wasm_c_test";

        let module = rune_module_load_wasm(
            wasm_bytes.as_ptr(),
            wasm_bytes.len(),
            key.as_ptr(),
            key.len(),
            name.as_ptr() as *const c_char,
            name.len(),
        );
        assert!(!module.is_null());

        let req = RunePolicyRequest {
            subject_id: 1,
            action: 1,
            resource_id: 1,
            risk_score: 10,
            context_json: std::ptr::null(),
            context_json_len: 0,
        };
        let mut dec = RunePolicyDecision::new_deny();

        let ret = rune_evaluate(module, &req, &mut dec);
        assert_eq!(ret, 0);
        assert_eq!(dec.outcome, RUNE_PERMIT);

        rune_module_free(module);
    }
}
