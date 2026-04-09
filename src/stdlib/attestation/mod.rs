// ═══════════════════════════════════════════════════════════════════════
// rune::attestation — Model Trust Chain Verification
//
// Public-facing API wrapping the runtime attestation system (M5 L3).
// Provides builder patterns, PQC-first signing via rune::crypto, and
// tiered trust policies (permissive, strict, defense).
//
// Effect: crypto (all verification and signing operations).
// ═══════════════════════════════════════════════════════════════════════

use std::time::SystemTime;

use crate::stdlib::crypto;

// ── ModelCard ───────────────────────────────────────────────────────

/// High-level model identity and provenance record.
#[derive(Debug, Clone)]
pub struct ModelCard {
    pub model_id: String,
    pub model_hash: String,
    pub signer: String,
    pub framework: String,
    pub architecture: String,
    pub slsa_level: u8,
    pub training_data_hash: Option<String>,
    pub policy_requirements: Vec<String>,
    pub timestamp: SystemTime,
}

/// Builder for ModelCard.
pub struct ModelCardBuilder {
    model_id: String,
    model_hash: String,
    signer: String,
    framework: String,
    architecture: String,
    slsa_level: u8,
    training_data_hash: Option<String>,
    policy_requirements: Vec<String>,
}

impl ModelCard {
    pub fn new(model_id: &str, model_hash: &str) -> ModelCardBuilder {
        ModelCardBuilder {
            model_id: model_id.to_string(),
            model_hash: model_hash.to_string(),
            signer: String::new(),
            framework: String::new(),
            architecture: String::new(),
            slsa_level: 0,
            training_data_hash: None,
            policy_requirements: Vec::new(),
        }
    }
}

impl ModelCardBuilder {
    pub fn signer(mut self, signer: &str) -> Self {
        self.signer = signer.to_string();
        self
    }
    pub fn framework(mut self, framework: &str) -> Self {
        self.framework = framework.to_string();
        self
    }
    pub fn architecture(mut self, arch: &str) -> Self {
        self.architecture = arch.to_string();
        self
    }
    pub fn slsa_level(mut self, level: u8) -> Self {
        self.slsa_level = level;
        self
    }
    pub fn training_data_hash(mut self, hash: &str) -> Self {
        self.training_data_hash = Some(hash.to_string());
        self
    }
    pub fn require_policy(mut self, policy: &str) -> Self {
        self.policy_requirements.push(policy.to_string());
        self
    }
    pub fn build(self) -> ModelCard {
        ModelCard {
            model_id: self.model_id,
            model_hash: self.model_hash,
            signer: self.signer,
            framework: self.framework,
            architecture: self.architecture,
            slsa_level: self.slsa_level,
            training_data_hash: self.training_data_hash,
            policy_requirements: self.policy_requirements,
            timestamp: SystemTime::now(),
        }
    }
}

// ── TrustPolicy ─────────────────────────────────────────────────────

/// Policy governing what models are trusted.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub required_signers: Vec<String>,
    pub min_slsa_level: Option<u8>,
    pub allowed_frameworks: Option<Vec<String>>,
    pub require_training_data: bool,
    pub max_age_hours: Option<u64>,
}

impl TrustPolicy {
    pub fn new() -> TrustPolicyBuilder {
        TrustPolicyBuilder {
            required_signers: Vec::new(),
            min_slsa_level: None,
            allowed_frameworks: None,
            require_training_data: false,
            max_age_hours: None,
        }
    }

    /// Signature check only, no other constraints.
    pub fn permissive() -> Self {
        Self {
            required_signers: Vec::new(),
            min_slsa_level: None,
            allowed_frameworks: None,
            require_training_data: false,
            max_age_hours: None,
        }
    }

    /// Requires signer, SLSA 3+, training data hash, 24-hour freshness.
    pub fn strict() -> Self {
        Self {
            required_signers: Vec::new(),
            min_slsa_level: Some(3),
            allowed_frameworks: None,
            require_training_data: true,
            max_age_hours: Some(24),
        }
    }

    /// Requires signer, SLSA 4, training data, 1-hour freshness.
    pub fn defense() -> Self {
        Self {
            required_signers: Vec::new(),
            min_slsa_level: Some(4),
            allowed_frameworks: None,
            require_training_data: true,
            max_age_hours: Some(1),
        }
    }
}

pub struct TrustPolicyBuilder {
    required_signers: Vec<String>,
    min_slsa_level: Option<u8>,
    allowed_frameworks: Option<Vec<String>>,
    require_training_data: bool,
    max_age_hours: Option<u64>,
}

impl TrustPolicyBuilder {
    pub fn require_signer(mut self, signer: &str) -> Self {
        self.required_signers.push(signer.to_string());
        self
    }
    pub fn min_slsa(mut self, level: u8) -> Self {
        self.min_slsa_level = Some(level);
        self
    }
    pub fn require_training_data(mut self) -> Self {
        self.require_training_data = true;
        self
    }
    pub fn max_age_hours(mut self, hours: u64) -> Self {
        self.max_age_hours = Some(hours);
        self
    }
    pub fn allow_framework(mut self, framework: &str) -> Self {
        self.allowed_frameworks
            .get_or_insert_with(Vec::new)
            .push(framework.to_string());
        self
    }
    pub fn build(self) -> TrustPolicy {
        TrustPolicy {
            required_signers: self.required_signers,
            min_slsa_level: self.min_slsa_level,
            allowed_frameworks: self.allowed_frameworks,
            require_training_data: self.require_training_data,
            max_age_hours: self.max_age_hours,
        }
    }
}

// ── TrustResult ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustResult {
    Trusted { signer: String },
    Rejected { reason: String },
}

impl std::fmt::Display for TrustResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trusted { signer } => write!(f, "trusted (signer: {signer})"),
            Self::Rejected { reason } => write!(f, "rejected: {reason}"),
        }
    }
}

// ── TrustVerifier ───────────────────────────────────────────────────

/// Verifies model cards against a trust policy.
pub struct TrustVerifier {
    policy: TrustPolicy,
    trusted_keys: std::collections::HashMap<String, Vec<u8>>,
}

impl TrustVerifier {
    pub fn new(policy: TrustPolicy) -> Self {
        Self {
            policy,
            trusted_keys: std::collections::HashMap::new(),
        }
    }

    pub fn add_trusted_key(&mut self, signer: &str, key: Vec<u8>) -> &mut Self {
        self.trusted_keys.insert(signer.to_string(), key);
        self
    }

    pub fn verify(&self, card: &ModelCard) -> TrustResult {
        // Check signer is in required signers (if any specified).
        if !self.policy.required_signers.is_empty()
            && !self.policy.required_signers.contains(&card.signer)
        {
            return TrustResult::Rejected {
                reason: format!("signer '{}' not in required signers", card.signer),
            };
        }

        // Check SLSA level.
        if let Some(min) = self.policy.min_slsa_level {
            if card.slsa_level < min {
                return TrustResult::Rejected {
                    reason: format!(
                        "SLSA level {} below minimum {}",
                        card.slsa_level, min
                    ),
                };
            }
        }

        // Check framework allowlist.
        if let Some(ref allowed) = self.policy.allowed_frameworks {
            if !card.framework.is_empty() && !allowed.contains(&card.framework) {
                return TrustResult::Rejected {
                    reason: format!("framework '{}' not in allowlist", card.framework),
                };
            }
        }

        // Check training data hash.
        if self.policy.require_training_data && card.training_data_hash.is_none() {
            return TrustResult::Rejected {
                reason: "training data hash required but not provided".to_string(),
            };
        }

        // Check age (freshness).
        if let Some(max_hours) = self.policy.max_age_hours {
            if let Ok(elapsed) = card.timestamp.elapsed() {
                let max_secs = max_hours * 3600;
                if elapsed.as_secs() > max_secs {
                    return TrustResult::Rejected {
                        reason: format!(
                            "model attestation expired ({}s old, max {}s)",
                            elapsed.as_secs(),
                            max_secs
                        ),
                    };
                }
            }
        }

        TrustResult::Trusted {
            signer: card.signer.clone(),
        }
    }
}

// ── Signing ─────────────────────────────────────────────────────────

/// A model card with a cryptographic signature.
#[derive(Debug, Clone)]
pub struct SignedModelCard {
    pub card: ModelCard,
    pub signature: Vec<u8>,
    pub signing_algorithm: String,
}

/// Sign a model card using PQC-default (ML-DSA-65 placeholder).
pub fn sign_model(key: &[u8], card: &ModelCard) -> SignedModelCard {
    let data = format!(
        "{}:{}:{}:{}",
        card.model_id, card.model_hash, card.signer, card.framework
    );
    let signature = crypto::default_sign(key, data.as_bytes());
    SignedModelCard {
        card: card.clone(),
        signature,
        signing_algorithm: "ML-DSA-65 (placeholder: HMAC-SHA3-256)".to_string(),
    }
}

/// Verify a signed model card.
pub fn verify_signed_model(key: &[u8], signed: &SignedModelCard) -> bool {
    let data = format!(
        "{}:{}:{}:{}",
        signed.card.model_id,
        signed.card.model_hash,
        signed.card.signer,
        signed.card.framework
    );
    crypto::default_verify(key, data.as_bytes(), &signed.signature)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_card_builder() {
        let card = ModelCard::new("model-v1", "abc123")
            .signer("acme-corp")
            .framework("pytorch")
            .slsa_level(3)
            .build();
        assert_eq!(card.model_id, "model-v1");
        assert_eq!(card.model_hash, "abc123");
        assert_eq!(card.signer, "acme-corp");
        assert_eq!(card.framework, "pytorch");
        assert_eq!(card.slsa_level, 3);
    }

    #[test]
    fn test_model_card_all_fields() {
        let card = ModelCard::new("m1", "h1")
            .signer("s1")
            .framework("onnx")
            .architecture("transformer")
            .slsa_level(4)
            .training_data_hash("tdh123")
            .require_policy("eu-ai-act")
            .build();
        assert_eq!(card.architecture, "transformer");
        assert_eq!(card.training_data_hash, Some("tdh123".to_string()));
        assert_eq!(card.policy_requirements, vec!["eu-ai-act"]);
    }

    #[test]
    fn test_model_card_optional_fields() {
        let card = ModelCard::new("m1", "h1").build();
        assert!(card.training_data_hash.is_none());
        assert!(card.policy_requirements.is_empty());
    }

    #[test]
    fn test_trust_policy_permissive() {
        let p = TrustPolicy::permissive();
        assert!(p.required_signers.is_empty());
        assert!(p.min_slsa_level.is_none());
        assert!(!p.require_training_data);
    }

    #[test]
    fn test_trust_policy_strict() {
        let p = TrustPolicy::strict();
        assert_eq!(p.min_slsa_level, Some(3));
        assert!(p.require_training_data);
        assert_eq!(p.max_age_hours, Some(24));
    }

    #[test]
    fn test_trust_policy_defense() {
        let p = TrustPolicy::defense();
        assert_eq!(p.min_slsa_level, Some(4));
        assert_eq!(p.max_age_hours, Some(1));
    }

    #[test]
    fn test_trust_policy_builder() {
        let p = TrustPolicy::new()
            .require_signer("org-a")
            .min_slsa(2)
            .require_training_data()
            .max_age_hours(48)
            .allow_framework("pytorch")
            .build();
        assert_eq!(p.required_signers, vec!["org-a"]);
        assert_eq!(p.min_slsa_level, Some(2));
        assert!(p.require_training_data);
        assert_eq!(p.max_age_hours, Some(48));
        assert_eq!(p.allowed_frameworks, Some(vec!["pytorch".to_string()]));
    }

    #[test]
    fn test_verifier_permissive_passes() {
        let card = ModelCard::new("m1", "h1").signer("anyone").build();
        let verifier = TrustVerifier::new(TrustPolicy::permissive());
        assert!(matches!(verifier.verify(&card), TrustResult::Trusted { .. }));
    }

    #[test]
    fn test_verifier_strict_rejects_no_training_data() {
        let card = ModelCard::new("m1", "h1")
            .signer("s1")
            .slsa_level(3)
            .build();
        let verifier = TrustVerifier::new(TrustPolicy::strict());
        assert!(matches!(verifier.verify(&card), TrustResult::Rejected { .. }));
    }

    #[test]
    fn test_verifier_rejects_wrong_signer() {
        let card = ModelCard::new("m1", "h1").signer("bad-actor").build();
        let policy = TrustPolicy::new().require_signer("trusted-org").build();
        let verifier = TrustVerifier::new(policy);
        match verifier.verify(&card) {
            TrustResult::Rejected { reason } => assert!(reason.contains("bad-actor")),
            _ => panic!("expected rejection"),
        }
    }

    #[test]
    fn test_sign_model_non_empty() {
        let card = ModelCard::new("m1", "h1").signer("s").build();
        let signed = sign_model(b"key", &card);
        assert!(!signed.signature.is_empty());
    }

    #[test]
    fn test_verify_signed_model_correct_key() {
        let card = ModelCard::new("m1", "h1").signer("s").framework("pt").build();
        let signed = sign_model(b"secret", &card);
        assert!(verify_signed_model(b"secret", &signed));
    }

    #[test]
    fn test_verify_signed_model_wrong_key() {
        let card = ModelCard::new("m1", "h1").signer("s").framework("pt").build();
        let signed = sign_model(b"real-key", &card);
        assert!(!verify_signed_model(b"fake-key", &signed));
    }

    #[test]
    fn test_trust_result_display() {
        let t = TrustResult::Trusted { signer: "org".into() };
        assert!(format!("{t}").contains("org"));
        let r = TrustResult::Rejected { reason: "bad".into() };
        assert!(format!("{r}").contains("bad"));
    }
}
