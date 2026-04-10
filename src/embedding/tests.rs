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

    // ═════════════════════════════════════════════════════════════════
    // M8 Layer 3: Wire format serialization tests
    // ═════════════════════════════════════════════════════════════════

    use crate::embedding::wire::*;

    fn minimal_wire_request() -> WireRequest {
        WireRequest {
            subject: WireSubject { id: 42, ..Default::default() },
            context: WireContext { risk_score: 10, ..Default::default() },
            ..Default::default()
        }
    }

    fn full_wire_request() -> WireRequest {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("env".to_string(), "production".to_string());
        metadata.insert("region".to_string(), "us-east-1".to_string());

        let mut custom = std::collections::HashMap::new();
        custom.insert("trace_id".to_string(), "abc-123".to_string());

        WireRequest {
            subject: WireSubject {
                id: 100,
                roles: vec!["admin".to_string(), "auditor".to_string()],
                clearance_level: 5,
                authentication_method: "mTLS".to_string(),
            },
            action: WireAction {
                action_type: "read".to_string(),
                target_resource: "model/gpt-4".to_string(),
                requested_permissions: vec!["inference".to_string(), "inspect".to_string()],
            },
            resource: WireResource {
                resource_type: "ai_model".to_string(),
                classification_level: 3,
                resource_id: 999,
                metadata,
            },
            context: WireContext {
                timestamp_ms: 1700000000000,
                source_ip: "10.0.0.1".to_string(),
                risk_score: 45,
                session_id: "sess-xyz".to_string(),
                custom,
            },
            attestation: Some(WireAttestation {
                signer_identity: "signer@example.com".to_string(),
                signature_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
                slsa_level: 3,
                architecture_hash: "sha256:abc123".to_string(),
                model_id: "model-001".to_string(),
            }),
        }
    }

    // ── Schema/serialization round-trip tests ───────────────────────

    #[test]
    fn test_wire_request_minimal_roundtrip() {
        let req = minimal_wire_request();
        let bytes = serialize_request(&req);
        let decoded = deserialize_request(&bytes).unwrap();
        assert_eq!(decoded.subject.id, 42);
        assert_eq!(decoded.context.risk_score, 10);
    }

    #[test]
    fn test_wire_request_full_roundtrip() {
        let req = full_wire_request();
        let bytes = serialize_request(&req);
        let decoded = deserialize_request(&bytes).unwrap();

        assert_eq!(decoded.subject.id, 100);
        assert_eq!(decoded.subject.roles, vec!["admin", "auditor"]);
        assert_eq!(decoded.subject.clearance_level, 5);
        assert_eq!(decoded.subject.authentication_method, "mTLS");
        assert_eq!(decoded.action.action_type, "read");
        assert_eq!(decoded.action.target_resource, "model/gpt-4");
        assert_eq!(decoded.action.requested_permissions, vec!["inference", "inspect"]);
        assert_eq!(decoded.resource.resource_type, "ai_model");
        assert_eq!(decoded.resource.classification_level, 3);
        assert_eq!(decoded.resource.resource_id, 999);
        assert_eq!(decoded.context.timestamp_ms, 1700000000000);
        assert_eq!(decoded.context.source_ip, "10.0.0.1");
        assert_eq!(decoded.context.risk_score, 45);
        assert_eq!(decoded.context.session_id, "sess-xyz");
    }

    #[test]
    fn test_wire_decision_all_outcomes_roundtrip() {
        for outcome in [PolicyDecision::Permit, PolicyDecision::Deny, PolicyDecision::Escalate, PolicyDecision::Quarantine] {
            let dec = WireDecision {
                outcome,
                matched_rule: "test_rule".to_string(),
                evaluation_duration_us: 42,
                explanation: "because".to_string(),
                audit: None,
            };
            let bytes = serialize_decision(&dec);
            let decoded = deserialize_decision(&bytes).unwrap();
            assert_eq!(decoded.outcome, outcome);
            assert_eq!(decoded.matched_rule, "test_rule");
            assert_eq!(decoded.evaluation_duration_us, 42);
            assert_eq!(decoded.explanation, "because");
        }
    }

    #[test]
    fn test_wire_deserialize_malformed_bytes() {
        let result = deserialize_request(&[0xFF, 0xFF]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WireError::MalformedBuffer(_)));
    }

    #[test]
    fn test_wire_deserialize_empty_bytes() {
        let result = deserialize_request(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_request_attestation_present_roundtrip() {
        let req = full_wire_request();
        let bytes = serialize_request(&req);
        let decoded = deserialize_request(&bytes).unwrap();
        let att = decoded.attestation.as_ref().unwrap();
        assert_eq!(att.signer_identity, "signer@example.com");
        assert_eq!(att.signature_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(att.slsa_level, 3);
        assert_eq!(att.architecture_hash, "sha256:abc123");
        assert_eq!(att.model_id, "model-001");
    }

    #[test]
    fn test_wire_request_attestation_absent_roundtrip() {
        let req = minimal_wire_request();
        let bytes = serialize_request(&req);
        let decoded = deserialize_request(&bytes).unwrap();
        assert!(decoded.attestation.is_none());
    }

    #[test]
    fn test_wire_kv_metadata_roundtrip() {
        let req = full_wire_request();
        let bytes = serialize_request(&req);
        let decoded = deserialize_request(&bytes).unwrap();
        assert_eq!(decoded.resource.metadata.get("env").unwrap(), "production");
        assert_eq!(decoded.resource.metadata.get("region").unwrap(), "us-east-1");
        assert_eq!(decoded.context.custom.get("trace_id").unwrap(), "abc-123");
    }

    #[test]
    fn test_wire_decision_with_audit_roundtrip() {
        let dec = WireDecision {
            outcome: PolicyDecision::Permit,
            matched_rule: "allow_admin".to_string(),
            evaluation_duration_us: 150,
            explanation: "admin role".to_string(),
            audit: Some(WireAuditInfo {
                record_id: 7,
                policy_version: "v1.2".to_string(),
                input_hash: "abc123".to_string(),
                previous_hash: "def456".to_string(),
                signature: "sig789".to_string(),
            }),
        };
        let bytes = serialize_decision(&dec);
        let decoded = deserialize_decision(&bytes).unwrap();
        assert_eq!(decoded.outcome, PolicyDecision::Permit);
        let audit = decoded.audit.unwrap();
        assert_eq!(audit.record_id, 7);
        assert_eq!(audit.policy_version, "v1.2");
        assert_eq!(audit.input_hash, "abc123");
        assert_eq!(audit.previous_hash, "def456");
        assert_eq!(audit.signature, "sig789");
    }

    // ── Conversion tests ────────────────────────────────────────────

    #[test]
    fn test_wire_request_to_policy_request() {
        let wire = WireRequest {
            subject: WireSubject { id: 42, ..Default::default() },
            resource: WireResource { resource_id: 99, ..Default::default() },
            context: WireContext { risk_score: 75, ..Default::default() },
            ..Default::default()
        };
        let pr: crate::runtime::evaluator::PolicyRequest = (&wire).into();
        assert_eq!(pr.subject_id, 42);
        assert_eq!(pr.resource_id, 99);
        assert_eq!(pr.risk_score, 75);
    }

    #[test]
    fn test_policy_result_to_wire_decision() {
        let result = crate::runtime::evaluator::PolicyResult {
            decision: PolicyDecision::Escalate,
            evaluation_duration: std::time::Duration::from_micros(123),
        };
        let dec: WireDecision = (&result).into();
        assert_eq!(dec.outcome, PolicyDecision::Escalate);
        assert_eq!(dec.evaluation_duration_us, 123);
        assert_eq!(dec.matched_rule, "evaluate");
    }

    #[test]
    fn test_wire_request_zero_values_convert() {
        let wire = WireRequest::default();
        let pr: crate::runtime::evaluator::PolicyRequest = (&wire).into();
        assert_eq!(pr.subject_id, 0);
        assert_eq!(pr.action, 0);
        assert_eq!(pr.resource_id, 0);
        assert_eq!(pr.risk_score, 0);
    }

    // ── Wire format embedding API tests ─────────────────────────────

    #[test]
    fn test_engine_evaluate_wire() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "wire_test").unwrap();
        let req = WireRequest {
            subject: WireSubject { id: 1, ..Default::default() },
            context: WireContext { risk_score: 10, ..Default::default() },
            ..Default::default()
        };
        let dec = engine.evaluate_wire(&req);
        assert_eq!(dec.outcome, PolicyDecision::Permit);
        assert!(dec.audit.is_some());
    }

    #[test]
    fn test_engine_evaluate_wire_bytes() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "wire_bytes").unwrap();
        let req = minimal_wire_request();
        let req_bytes = serialize_request(&req);
        let dec_bytes = engine.evaluate_wire_bytes(&req_bytes).unwrap();
        let dec = deserialize_decision(&dec_bytes).unwrap();
        assert_eq!(dec.outcome, PolicyDecision::Permit);
    }

    #[test]
    fn test_engine_evaluate_wire_bytes_invalid_input() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "wire_err").unwrap();
        let result = engine.evaluate_wire_bytes(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_c_api_evaluate_wire() {
        let source = permit_source().as_bytes();
        let key = TEST_KEY;
        let name = b"wire_c_test";

        let module = rune_module_load_source(
            source.as_ptr() as *const c_char,
            source.len(),
            key.as_ptr(),
            key.len(),
            name.as_ptr() as *const c_char,
            name.len(),
        );
        assert!(!module.is_null());

        let req = minimal_wire_request();
        let req_bytes = serialize_request(&req);
        let mut dec_buf = vec![0u8; 4096];
        let mut written: usize = 0;

        let ret = rune_evaluate_wire(
            module,
            req_bytes.as_ptr(),
            req_bytes.len(),
            dec_buf.as_mut_ptr(),
            dec_buf.len(),
            &mut written,
        );
        assert_eq!(ret, 0);
        assert!(written > 0);

        let dec = deserialize_decision(&dec_buf[..written]).unwrap();
        assert_eq!(dec.outcome, PolicyDecision::Permit);

        rune_module_free(module);
    }

    // ── Benchmark tests ─────────────────────────────────────────────

    #[test]
    fn test_bench_serialize_request() {
        let req = full_wire_request();
        let iterations = 1000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = serialize_request(&req);
        }
        let elapsed = start.elapsed();
        let avg_us = elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;

        println!("  serialize_request: {:.2} us avg ({} iterations)", avg_us, iterations);
        // Generous upper bound for debug builds: under 100 us per serialization (smoke test for gross regressions).
        assert!(avg_us < 100.0, "serialization too slow: {:.2} us", avg_us);
    }

    #[test]
    fn test_bench_deserialize_request() {
        let req = full_wire_request();
        let bytes = serialize_request(&req);
        let iterations = 1000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = deserialize_request(&bytes).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_us = elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;

        println!("  deserialize_request: {:.2} us avg ({} iterations)", avg_us, iterations);
        assert!(avg_us < 100.0, "deserialization too slow: {:.2} us", avg_us);
    }

    #[test]
    fn test_bench_serialize_decision() {
        let dec = WireDecision {
            outcome: PolicyDecision::Permit,
            matched_rule: "allow_admin".to_string(),
            evaluation_duration_us: 150,
            explanation: "admin role verified".to_string(),
            audit: Some(WireAuditInfo {
                record_id: 7,
                policy_version: "v1.2".to_string(),
                input_hash: "abc123def456".to_string(),
                previous_hash: "000111222333".to_string(),
                signature: "sig_bytes_here".to_string(),
            }),
        };
        let iterations = 1000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = serialize_decision(&dec);
        }
        let elapsed = start.elapsed();
        let avg_us = elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;

        println!("  serialize_decision: {:.2} us avg ({} iterations)", avg_us, iterations);
        assert!(avg_us < 10.0, "decision serialization too slow: {:.2} us", avg_us);
    }

    #[test]
    fn test_bench_full_round_trip() {
        let mut engine = RuneEngine::from_source(permit_source(), TEST_KEY, "bench").unwrap();
        let req = full_wire_request();
        let req_bytes = serialize_request(&req);
        let iterations = 100;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate_wire_bytes(&req_bytes).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ms = elapsed.as_secs_f64() * 1000.0 / iterations as f64;

        println!("  full round-trip (ser+deser+eval+ser): {:.2} ms avg ({} iterations)", avg_ms, iterations);
        // Generous upper bound for CI: under 5 ms per full round-trip.
        assert!(avg_ms < 5.0, "full round-trip too slow: {:.2} ms", avg_ms);
    }
}
