// ═══════════════════════════════════════════════════════════════════════
// Trust Scoring — Continuous Trust Assessment
//
// Trust is not binary — it's a 0.0 to 1.0 score that changes over time
// based on authentication strength, device posture, behavioral patterns,
// and environmental factors.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_permissions::ClassificationLevel;
use serde::{Deserialize, Serialize};

use crate::authn::AuthnMethod;
use crate::session::Session;

// ── TrustLevel ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Full = 4,
}

impl TrustLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 0.8 => Self::Full,
            s if s >= 0.6 => Self::High,
            s if s >= 0.4 => Self::Medium,
            s if s >= 0.2 => Self::Low,
            _ => Self::None,
        }
    }

    pub fn min_score(&self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::Low => 0.2,
            Self::Medium => 0.4,
            Self::High => 0.6,
            Self::Full => 0.8,
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── TrustScore ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustScore {
    pub score: f64,
    pub factors: Vec<TrustFactor>,
    pub calculated_at: i64,
    pub expires_at: i64,
}

impl TrustScore {
    pub fn new(score: f64) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            factors: Vec::new(),
            calculated_at: 0,
            expires_at: 0,
        }
    }

    pub fn with_factors(mut self, factors: Vec<TrustFactor>) -> Self {
        self.factors = factors;
        self
    }

    pub fn with_timestamps(mut self, calculated_at: i64, expires_at: i64) -> Self {
        self.calculated_at = calculated_at;
        self.expires_at = expires_at;
        self
    }

    pub fn level(&self) -> TrustLevel {
        TrustLevel::from_score(self.score)
    }

    pub fn is_sufficient(&self, required: TrustLevel) -> bool {
        self.level() >= required
    }
}

// ── TrustFactor ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustFactor {
    pub factor_type: TrustFactorType,
    pub weight: f64,
    pub value: f64,
    pub detail: String,
}

impl TrustFactor {
    pub fn new(factor_type: TrustFactorType, weight: f64, value: f64, detail: impl Into<String>) -> Self {
        Self {
            factor_type,
            weight: weight.clamp(0.0, 1.0),
            value: value.clamp(0.0, 1.0),
            detail: detail.into(),
        }
    }
}

// ── TrustFactorType ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrustFactorType {
    AuthenticationStrength,
    SessionAge,
    DevicePosture,
    NetworkLocation,
    BehaviorPattern,
    RiskScore,
    FailedAttempts,
    CredentialAge,
}

impl fmt::Display for TrustFactorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── TrustCalculator ──────────────────────────────────────────────────

pub struct TrustCalculator {
    weights: HashMap<TrustFactorType, f64>,
    pub decay_rate_per_hour: f64,
}

impl TrustCalculator {
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert(TrustFactorType::AuthenticationStrength, 0.30);
        weights.insert(TrustFactorType::SessionAge, 0.15);
        weights.insert(TrustFactorType::DevicePosture, 0.15);
        weights.insert(TrustFactorType::NetworkLocation, 0.10);
        weights.insert(TrustFactorType::BehaviorPattern, 0.10);
        weights.insert(TrustFactorType::RiskScore, 0.10);
        weights.insert(TrustFactorType::FailedAttempts, 0.05);
        weights.insert(TrustFactorType::CredentialAge, 0.05);
        Self { weights, decay_rate_per_hour: 0.05 }
    }

    pub fn with_weights(weights: HashMap<TrustFactorType, f64>) -> Self {
        Self { weights, decay_rate_per_hour: 0.05 }
    }

    pub fn calculate(&self, factors: &[TrustFactor]) -> TrustScore {
        if factors.is_empty() {
            return TrustScore::new(0.0);
        }

        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;

        for factor in factors {
            let effective_weight = self.weights
                .get(&factor.factor_type)
                .copied()
                .unwrap_or(factor.weight);
            weighted_sum += factor.value * effective_weight;
            weight_total += effective_weight;
        }

        let score = if weight_total > 0.0 {
            (weighted_sum / weight_total).clamp(0.0, 1.0)
        } else {
            0.0
        };

        TrustScore::new(score).with_factors(factors.to_vec())
    }

    pub fn calculate_with_decay(
        &self,
        factors: &[TrustFactor],
        session_age_hours: f64,
    ) -> TrustScore {
        let base = self.calculate(factors);
        let decay_multiplier = (1.0 - self.decay_rate_per_hour * session_age_hours).clamp(0.0, 1.0);
        TrustScore::new(base.score * decay_multiplier).with_factors(base.factors)
    }

    pub fn auth_strength_score(method: &AuthnMethod, mfa_used: bool) -> f64 {
        let base: f64 = match method {
            AuthnMethod::Password { .. } => 0.4,
            AuthnMethod::ApiKey { .. } => 0.5,
            AuthnMethod::BearerToken { .. } => 0.5,
            AuthnMethod::Certificate { .. } => 0.8,
            AuthnMethod::Mfa { .. } => 0.7,
        };
        if mfa_used && !matches!(method, AuthnMethod::Mfa { .. }) {
            (base + 0.3).min(0.95)
        } else {
            base
        }
    }
}

impl Default for TrustCalculator {
    fn default() -> Self {
        Self::new()
    }
}

// ── TrustPolicy ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustPolicy {
    pub minimum_trust: TrustLevel,
    pub require_recent_auth_hours: Option<u64>,
    pub require_mfa_above: Option<ClassificationLevel>,
    pub step_up_auth_threshold: f64,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            minimum_trust: TrustLevel::Low,
            require_recent_auth_hours: None,
            require_mfa_above: None,
            step_up_auth_threshold: 0.3,
        }
    }
}

impl TrustPolicy {
    pub fn high_security() -> Self {
        Self {
            minimum_trust: TrustLevel::High,
            require_recent_auth_hours: Some(4),
            require_mfa_above: Some(ClassificationLevel::Confidential),
            step_up_auth_threshold: 0.5,
        }
    }

    pub fn evaluate(
        &self,
        score: &TrustScore,
        session: &Session,
        resource_classification: ClassificationLevel,
    ) -> TrustEvaluation {
        let actual_level = score.level();
        let meets_trust = actual_level >= self.minimum_trust;

        // Check recent auth
        let recent_auth_ok = self.require_recent_auth_hours.map_or(true, |hours| {
            let max_age_ms = hours as i64 * 3_600_000;
            (score.calculated_at - session.authenticated_at).abs() < max_age_ms
        });

        // Check MFA requirement for classification
        let mfa_ok = self.require_mfa_above.as_ref().map_or(true, |level| {
            if resource_classification > *level {
                session.mfa_verified
            } else {
                true
            }
        });

        let step_up_required = score.score < self.step_up_auth_threshold;
        let allowed = meets_trust && recent_auth_ok && mfa_ok && !step_up_required;

        let reason = if !meets_trust {
            format!("trust level {actual_level} below minimum {:?}", self.minimum_trust)
        } else if !recent_auth_ok {
            "authentication too old".into()
        } else if !mfa_ok {
            format!("MFA required for {:?} resources", resource_classification)
        } else if step_up_required {
            "step-up authentication required".into()
        } else {
            "access granted".into()
        };

        TrustEvaluation {
            allowed,
            trust_score: score.score,
            required_level: self.minimum_trust.clone(),
            actual_level,
            step_up_required,
            reason,
        }
    }
}

// ── TrustEvaluation ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustEvaluation {
    pub allowed: bool,
    pub trust_score: f64,
    pub required_level: TrustLevel,
    pub actual_level: TrustLevel,
    pub step_up_required: bool,
    pub reason: String,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityId;
    use crate::session::{SessionId, SessionStatus};

    fn test_session(trust: f64, auth_at: i64) -> Session {
        Session {
            id: SessionId::new("s1"),
            identity_id: IdentityId::new("user:test"),
            authenticated_at: auth_at,
            last_activity_at: auth_at,
            expires_at: auth_at + 86_400_000,
            source_ip: None,
            user_agent: None,
            device_id: None,
            trust_score: trust,
            status: SessionStatus::Active,
            mfa_verified: false,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_trust_level_from_score() {
        assert_eq!(TrustLevel::from_score(0.0), TrustLevel::None);
        assert_eq!(TrustLevel::from_score(0.1), TrustLevel::None);
        assert_eq!(TrustLevel::from_score(0.2), TrustLevel::Low);
        assert_eq!(TrustLevel::from_score(0.4), TrustLevel::Medium);
        assert_eq!(TrustLevel::from_score(0.6), TrustLevel::High);
        assert_eq!(TrustLevel::from_score(0.8), TrustLevel::Full);
        assert_eq!(TrustLevel::from_score(1.0), TrustLevel::Full);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Full > TrustLevel::High);
        assert!(TrustLevel::High > TrustLevel::Medium);
        assert!(TrustLevel::Medium > TrustLevel::Low);
        assert!(TrustLevel::Low > TrustLevel::None);
    }

    #[test]
    fn test_trust_level_min_score() {
        assert_eq!(TrustLevel::None.min_score(), 0.0);
        assert_eq!(TrustLevel::Low.min_score(), 0.2);
        assert_eq!(TrustLevel::Medium.min_score(), 0.4);
        assert_eq!(TrustLevel::High.min_score(), 0.6);
        assert_eq!(TrustLevel::Full.min_score(), 0.8);
    }

    #[test]
    fn test_trust_score_level() {
        assert_eq!(TrustScore::new(0.5).level(), TrustLevel::Medium);
        assert_eq!(TrustScore::new(0.85).level(), TrustLevel::Full);
    }

    #[test]
    fn test_trust_score_is_sufficient() {
        let score = TrustScore::new(0.7);
        assert!(score.is_sufficient(TrustLevel::Low));
        assert!(score.is_sufficient(TrustLevel::High));
        assert!(!score.is_sufficient(TrustLevel::Full));
    }

    #[test]
    fn test_trust_calculator_single_factor() {
        let calc = TrustCalculator::new();
        let factors = vec![
            TrustFactor::new(TrustFactorType::AuthenticationStrength, 1.0, 0.8, "password+mfa"),
        ];
        let score = calc.calculate(&factors);
        assert!((score.score - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_trust_calculator_multiple_factors() {
        let calc = TrustCalculator::new();
        let factors = vec![
            TrustFactor::new(TrustFactorType::AuthenticationStrength, 0.3, 0.8, "strong"),
            TrustFactor::new(TrustFactorType::DevicePosture, 0.15, 0.6, "known device"),
            TrustFactor::new(TrustFactorType::NetworkLocation, 0.1, 1.0, "trusted network"),
        ];
        let score = calc.calculate(&factors);
        assert!(score.score > 0.0);
        assert!(score.score <= 1.0);
    }

    #[test]
    fn test_trust_calculator_with_decay() {
        let calc = TrustCalculator::new();
        let factors = vec![
            TrustFactor::new(TrustFactorType::AuthenticationStrength, 1.0, 0.8, "test"),
        ];
        let no_decay = calc.calculate(&factors);
        let with_decay = calc.calculate_with_decay(&factors, 4.0);
        assert!(with_decay.score < no_decay.score);
    }

    #[test]
    fn test_auth_strength_score() {
        assert!((TrustCalculator::auth_strength_score(
            &AuthnMethod::Password { password_bytes: vec![] }, false
        ) - 0.4).abs() < 0.01);

        assert!((TrustCalculator::auth_strength_score(
            &AuthnMethod::Password { password_bytes: vec![] }, true
        ) - 0.7).abs() < 0.01);

        assert!((TrustCalculator::auth_strength_score(
            &AuthnMethod::Certificate { fingerprint: String::new() }, false
        ) - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_trust_policy_allows() {
        let policy = TrustPolicy::default();
        let score = TrustScore::new(0.7).with_timestamps(1000, 2000);
        let session = test_session(0.7, 1000);
        let eval = policy.evaluate(&score, &session, ClassificationLevel::Internal);
        assert!(eval.allowed);
    }

    #[test]
    fn test_trust_policy_denies_low_trust() {
        let policy = TrustPolicy { minimum_trust: TrustLevel::High, ..TrustPolicy::default() };
        let score = TrustScore::new(0.3).with_timestamps(1000, 2000);
        let session = test_session(0.3, 1000);
        let eval = policy.evaluate(&score, &session, ClassificationLevel::Internal);
        assert!(!eval.allowed);
    }

    #[test]
    fn test_trust_policy_step_up() {
        let policy = TrustPolicy { step_up_auth_threshold: 0.5, ..TrustPolicy::default() };
        let score = TrustScore::new(0.4).with_timestamps(1000, 2000);
        let session = test_session(0.4, 1000);
        let eval = policy.evaluate(&score, &session, ClassificationLevel::Internal);
        assert!(!eval.allowed);
        assert!(eval.step_up_required);
    }

    #[test]
    fn test_trust_calculator_empty_factors() {
        let calc = TrustCalculator::new();
        let score = calc.calculate(&[]);
        assert_eq!(score.score, 0.0);
    }
}
