// ═══════════════════════════════════════════════════════════════════════
// Standard Library Integration Tests (M10 Layer 4)
//
// End-to-end tests proving all stdlib modules compose correctly and
// the PQC swap from SHA-256/HMAC-SHA256 to SHA3-256/HMAC-SHA3-256
// preserves all functional properties.
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    // ── 1. Full stdlib pipeline ────────────────────────────────────

    #[test]
    fn test_full_stdlib_pipeline() {
        use crate::stdlib::attestation::*;
        use crate::stdlib::policy::*;
        use crate::stdlib::audit::*;

        // Step 1: Create and sign a model card.
        let card = ModelCard::new("governance-model-v2", "sha3-abc123")
            .signer("security-team")
            .framework("pytorch")
            .architecture("transformer")
            .slsa_level(3)
            .training_data_hash("tdh-456")
            .build();

        let signed = sign_model(b"team-key", &card);
        assert!(!signed.signature.is_empty());

        // Step 2: Verify model trust with a policy.
        let policy = TrustPolicy::new()
            .require_signer("security-team")
            .min_slsa(2)
            .build();
        let verifier = TrustVerifier::new(policy);
        let trust = verifier.verify(&card);
        assert!(matches!(trust, TrustResult::Trusted { .. }));

        // Step 3: Verify the signed model with PQC crypto.
        assert!(verify_signed_model(b"team-key", &signed));
        assert!(!verify_signed_model(b"wrong-key", &signed));

        // Step 4: Evaluate policy decisions.
        let _req = PolicyRequest::new().subject(1).action(2).resource(3).risk(85);
        let decisions = vec![Decision::Permit, Decision::Deny, Decision::Escalate];
        assert_eq!(first_non_permit(&decisions), Decision::Deny);
        assert_eq!(most_severe(&decisions), Decision::Deny);
        assert!(!all_permit(&decisions));
        assert!(any_deny(&decisions));

        // Step 5: Assess risk.
        assert_eq!(risk_level(85), RiskLevel::Critical);
        assert_eq!(risk_level(30), RiskLevel::Medium);

        // Step 6: Create audit entries for each step.
        let entries = vec![
            AuditEntry::new(1, 1000, AuditEventKind::ModelAttestation, "attestation", "verify")
                .with_decision(0),
            AuditEntry::new(2, 2000, AuditEventKind::Decision, "access_control", "evaluate")
                .with_decision(1),
            AuditEntry::new(3, 3000, AuditEventKind::FunctionCall, "policy", "risk_check"),
        ];
        let trail = AuditTrailView::new(entries);

        // Step 7: Verify audit chain.
        assert!(verify_chain(&trail).is_ok());
        assert!(verify_integrity(&trail).is_ok());

        // Step 8: Export.
        let json = crate::stdlib::audit::to_json(&trail);
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("ModelAttestation"));
        let csv = crate::stdlib::audit::to_csv(&trail);
        assert!(csv.contains("id,timestamp"));
        assert!(csv.contains("Decision"));

        // Step 9: Decision summary.
        let summary = trail.decision_summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.permits, 1);
        assert_eq!(summary.denies, 1);
    }

    // ── 2. Crypto → Audit chain test ───────────────────────────────

    #[test]
    fn test_pqc_crypto_audit_chain() {
        use crate::stdlib::audit::*;

        // Create entries — their hashes use SHA3-256 internally.
        let entries = vec![
            AuditEntry::new(1, 100, AuditEventKind::Decision, "mod", "fn")
                .with_decision(0),
            AuditEntry::new(2, 200, AuditEventKind::Decision, "mod", "fn")
                .with_decision(1),
            AuditEntry::new(3, 300, AuditEventKind::Decision, "mod", "fn")
                .with_decision(2),
        ];
        let trail = AuditTrailView::new(entries);

        // Chain integrity holds.
        assert!(verify_integrity(&trail).is_ok());

        // Hashes are 64 hex chars (SHA3-256 = 32 bytes).
        assert_eq!(trail.get(0).unwrap().record_hash.len(), 64);
        assert_eq!(trail.get(0).unwrap().input_hash.len(), 64);
    }

    // ── 3. Crypto backward compatibility ───────────────────────────

    #[test]
    fn test_sha256_fallback_still_works() {
        // The old SHA-256 function is still available via stdlib.
        let result = crate::stdlib::crypto::hash::sha256_hex(b"abc");
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hmac_sha256_fallback_still_works() {
        // The old HMAC-SHA256 function is still available via stdlib.
        let key = b"test-key";
        let data = b"test-data";
        let mac1 = crate::stdlib::crypto::sign::hmac_sha256(key, data);
        let mac2 = crate::stdlib::crypto::sign::hmac_sha256(key, data);
        assert_eq!(mac1, mac2);
        assert_eq!(mac1.len(), 32); // HMAC-SHA256 = 32 bytes
    }

    #[test]
    fn test_runtime_crypto_fallback_available() {
        // The runtime crypto module retains classical fallbacks.
        let sha256_hash = crate::runtime::audit::crypto::hash_sha256("test");
        assert_eq!(sha256_hash.len(), 64); // 32 bytes = 64 hex chars

        let sha256_sig = crate::runtime::audit::crypto::sign_sha256(b"key", "data");
        assert_eq!(sha256_sig.len(), 64);
    }

    #[test]
    fn test_runtime_crypto_now_uses_sha3() {
        // Verify the default hash/sign are now SHA3, not SHA256.
        let sha3_hash = crate::runtime::audit::crypto::hash("test");
        let sha256_hash = crate::runtime::audit::crypto::hash_sha256("test");
        // SHA3-256 and SHA-256 produce different bytes for the same input.
        assert_ne!(sha3_hash, sha256_hash);
        // Both are 64 hex chars (32 bytes).
        assert_eq!(sha3_hash.len(), 64);
        assert_eq!(sha256_hash.len(), 64);
    }

    // ── 4. Cross-module effect documentation ───────────────────────

    #[test]
    fn test_effect_structs_exist() {
        // Verify all effect-carrying modules document their effect requirements.
        assert_eq!(crate::stdlib::crypto::CryptoEffects::HASH, "crypto");
        assert_eq!(crate::stdlib::crypto::CryptoEffects::SIGN, "crypto");
        assert_eq!(crate::stdlib::crypto::CryptoEffects::VERIFY, "crypto");
        assert_eq!(crate::stdlib::crypto::CryptoEffects::KEM, "crypto");
        assert_eq!(crate::stdlib::io::IoEffects::READ, "io");
        assert_eq!(crate::stdlib::io::IoEffects::WRITE, "io");
        assert_eq!(crate::stdlib::net::NetEffects::TCP, "network");
        assert_eq!(crate::stdlib::net::NetEffects::DNS, "network");
        assert_eq!(crate::stdlib::env::EnvEffects::ENV, "io");
        assert_eq!(crate::stdlib::time::TimeEffects::CLOCK, "io");
    }

    // ── 5. Decision combinator integration ─────────────────────────

    #[test]
    fn test_realistic_multi_rule_evaluation() {
        use crate::stdlib::policy::*;

        // Scenario: three policy engines evaluate the same request.
        // Engine 1 (risk-based): risk > 75 → Deny, else Permit
        let risk_score = 60;
        let risk_decision = if risk_score > 75 {
            Decision::Deny
        } else {
            Decision::Permit
        };

        // Engine 2 (role-based): action 3 is restricted → Escalate
        let action = 3;
        let role_decision = if action == 3 {
            Decision::Escalate
        } else {
            Decision::Permit
        };

        // Engine 3 (compliance): always permits for this resource
        let compliance_decision = Decision::Permit;

        let all = vec![risk_decision, role_decision, compliance_decision];

        // first_non_permit: finds the Escalate (first non-permit).
        assert_eq!(first_non_permit(&all), Decision::Escalate);

        // most_severe: Escalate is severity 1, which is the max here.
        assert_eq!(most_severe(&all), Decision::Escalate);

        // Not unanimous.
        assert_eq!(unanimous(&all), None);

        // No deny, but any_deny checks severity >= Deny.severity().
        // Escalate.severity() = 1 < Deny.severity() = 2, so no.
        assert!(!any_deny(&all));

        // Risk level for score 60.
        assert_eq!(risk_level(risk_score), RiskLevel::High);
    }

    // ── 6. Prelude completeness ────────────────────────────────────

    #[test]
    fn test_prelude_completeness() {
        use crate::stdlib::prelude::*;

        // Crypto: hash, sign, verify.
        let hash = default_hash(b"prelude-test");
        assert_eq!(hash.len(), 32);
        let sig = default_sign(b"key", b"data");
        assert!(default_verify(b"key", b"data", &sig));
        let _ = HashAlgorithm::default();
        let _ = SignatureAlgorithm::default();

        // Policy: Decision, combinators, risk.
        let d = Decision::Permit;
        assert!(d.is_permit());
        let req = PolicyRequest::new().subject(1).risk(50);
        assert_eq!(req.risk_score, 50);
        assert_eq!(first_non_permit(&[Decision::Permit]), Decision::Permit);
        assert_eq!(most_severe(&[Decision::Deny]), Decision::Deny);
        assert!(all_permit(&[Decision::Permit]));
        assert!(any_deny(&[Decision::Deny]));
        assert_eq!(risk_level(10), RiskLevel::Low);

        // Attestation: ModelCard, TrustPolicy, TrustVerifier.
        let card = ModelCard::new("m", "h").signer("s").build();
        let policy = TrustPolicy::permissive();
        let verifier = TrustVerifier::new(policy);
        let result = verifier.verify(&card);
        assert!(matches!(result, TrustResult::Trusted { .. }));
        let signed = sign_model(b"k", &card);
        assert!(verify_signed_model(b"k", &signed));

        // Audit: AuditEntry, trail, summary, verification.
        let entry = AuditEntry::new(1, 100, AuditEventKind::Decision, "m", "f")
            .with_decision(0);
        let trail = AuditTrailView::new(vec![entry]);
        assert_eq!(trail.len(), 1);
        let summary = trail.decision_summary();
        assert_eq!(summary.total, 1);
        assert!(verify_chain(&trail).is_ok());
        assert!(verify_integrity(&trail).is_ok());

        // IO: types available (don't actually do I/O in this test).
        let _: fn(&str) -> Result<Vec<u8>, IoError> = read_file;
        let _: fn(&str, &[u8]) -> Result<(), IoError> = write_file;
        let _: fn(&str) -> Result<String, IoError> = read_file_string;

        // Time: timestamps.
        let ms = now_unix_ms();
        let secs = now_unix_secs();
        assert!(ms > 0);
        assert!(secs > 0);
        let _elapsed = elapsed_ms(ms);

        // Collections: utilities.
        let mut v = vec![3, 1, 2];
        sort_i64(&mut v);
        assert_eq!(v, vec![1, 2, 3]);
        assert_eq!(unique_i64(&[1, 1, 2]), vec![1, 2]);
        assert!(contains_i64(&[1, 2, 3], 2));
        assert_eq!(min_i64(&[5, 3, 8]), Some(3));
        assert_eq!(max_i64(&[5, 3, 8]), Some(8));
        assert_eq!(sum_i64(&[1, 2, 3]), 6);
    }

    // ── 7. Runtime audit trail PQC verification ────────────────────

    #[test]
    fn test_runtime_audit_trail_pqc() {
        use crate::runtime::audit::AuditTrail;
        use crate::runtime::evaluator::PolicyDecision;

        let key = b"pqc-test-key".to_vec();
        let mut trail = AuditTrail::new(key.clone());

        trail.record_decision("module", "rule", PolicyDecision::Permit, "input1");
        trail.record_decision("module", "rule", PolicyDecision::Deny, "input2");
        trail.record_event("module", "rule", crate::runtime::audit::AuditEventType::FunctionEntry);

        assert_eq!(trail.len(), 3);

        // Chain integrity verified — PQC hashes form a valid chain.
        assert!(trail.verify_chain().is_ok());

        // Signatures verified — PQC HMAC-SHA3-256 signatures are consistent.
        assert!(trail.verify_signatures(&key).is_ok());

        // Hash chain links correctly.
        let r0 = trail.get(0).unwrap();
        let r1 = trail.get(1).unwrap();
        let r2 = trail.get(2).unwrap();
        assert_eq!(r1.previous_hash, r0.record_hash);
        assert_eq!(r2.previous_hash, r1.record_hash);
    }
}
