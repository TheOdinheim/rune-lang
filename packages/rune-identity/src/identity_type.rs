// ═══════════════════════════════════════════════════════════════════════
// Identity Types — User, Service, Device, AiAgent, System
//
// Different identity types have different trust models, authentication
// requirements, and lifecycle rules.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use serde::{Deserialize, Serialize};

// ── IdentityType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IdentityType {
    User {
        mfa_required: bool,
        max_sessions: u32,
        password_policy: PasswordPolicy,
    },
    Service {
        api_key_required: bool,
        ip_allowlist: Vec<String>,
        rate_limit: Option<u64>,
    },
    Device {
        device_class: DeviceClass,
        attestation_required: bool,
        firmware_version: Option<String>,
    },
    AiAgent {
        model_id: String,
        attestation_required: bool,
        governance_level: GovernanceLevel,
        max_autonomy: AutonomyLevel,
    },
    System,
}

impl IdentityType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::User { .. } => "User",
            Self::Service { .. } => "Service",
            Self::Device { .. } => "Device",
            Self::AiAgent { .. } => "AiAgent",
            Self::System => "System",
        }
    }

    pub fn requires_mfa(&self) -> bool {
        match self {
            Self::User { mfa_required, .. } => *mfa_required,
            _ => false,
        }
    }

    pub fn default_user() -> Self {
        Self::User {
            mfa_required: false,
            max_sessions: 5,
            password_policy: PasswordPolicy::default(),
        }
    }

    pub fn default_service() -> Self {
        Self::Service {
            api_key_required: true,
            ip_allowlist: Vec::new(),
            rate_limit: None,
        }
    }

    pub fn default_device(class: DeviceClass) -> Self {
        Self::Device {
            device_class: class,
            attestation_required: false,
            firmware_version: None,
        }
    }

    pub fn default_ai_agent(model_id: impl Into<String>) -> Self {
        Self::AiAgent {
            model_id: model_id.into(),
            attestation_required: true,
            governance_level: GovernanceLevel::FullyGoverned,
            max_autonomy: AutonomyLevel::Low,
        }
    }
}

impl fmt::Display for IdentityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_name())
    }
}

// ── PasswordPolicy ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub max_age_days: u64,
    pub history_count: usize,
}

impl PasswordPolicy {
    pub fn strict() -> Self {
        Self {
            min_length: 16,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            max_age_days: 30,
            history_count: 24,
        }
    }

    pub fn validate(&self, password: &str) -> Vec<PasswordViolation> {
        let mut violations = Vec::new();
        if password.len() < self.min_length {
            violations.push(PasswordViolation::TooShort {
                min: self.min_length,
                actual: password.len(),
            });
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            violations.push(PasswordViolation::MissingUppercase);
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            violations.push(PasswordViolation::MissingLowercase);
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            violations.push(PasswordViolation::MissingDigit);
        }
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            violations.push(PasswordViolation::MissingSpecial);
        }
        violations
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            max_age_days: 90,
            history_count: 12,
        }
    }
}

// ── PasswordViolation ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordViolation {
    TooShort { min: usize, actual: usize },
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSpecial,
    InHistory,
}

impl fmt::Display for PasswordViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { min, actual } => write!(f, "too short: minimum {min}, got {actual}"),
            Self::MissingUppercase => write!(f, "missing uppercase letter"),
            Self::MissingLowercase => write!(f, "missing lowercase letter"),
            Self::MissingDigit => write!(f, "missing digit"),
            Self::MissingSpecial => write!(f, "missing special character"),
            Self::InHistory => write!(f, "password was recently used"),
        }
    }
}

// ── DeviceClass ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceClass {
    Server,
    Workstation,
    Mobile,
    IoT,
    EdgeAppliance,
    Hsm,
}

impl fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EdgeAppliance => write!(f, "EdgeAppliance"),
            Self::Hsm => write!(f, "HSM"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ── GovernanceLevel ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceLevel {
    Supervised = 0,
    SemiAutonomous = 1,
    FullyGoverned = 2,
}

impl fmt::Display for GovernanceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── AutonomyLevel ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutonomyLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Full = 4,
}

impl AutonomyLevel {
    pub fn max_action_severity(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Full => 4,
        }
    }
}

impl fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_type_display() {
        assert_eq!(IdentityType::default_user().to_string(), "User");
        assert_eq!(IdentityType::default_service().to_string(), "Service");
        assert_eq!(IdentityType::default_device(DeviceClass::Server).to_string(), "Device");
        assert_eq!(IdentityType::default_ai_agent("gpt-4").to_string(), "AiAgent");
        assert_eq!(IdentityType::System.to_string(), "System");
    }

    #[test]
    fn test_identity_type_requires_mfa() {
        let user_mfa = IdentityType::User {
            mfa_required: true,
            max_sessions: 5,
            password_policy: PasswordPolicy::default(),
        };
        assert!(user_mfa.requires_mfa());
        assert!(!IdentityType::default_user().requires_mfa());
        assert!(!IdentityType::default_service().requires_mfa());
    }

    #[test]
    fn test_password_policy_default() {
        let p = PasswordPolicy::default();
        assert_eq!(p.min_length, 12);
        assert!(p.require_uppercase);
        assert_eq!(p.max_age_days, 90);
        assert_eq!(p.history_count, 12);
    }

    #[test]
    fn test_password_policy_strict() {
        let p = PasswordPolicy::strict();
        assert_eq!(p.min_length, 16);
        assert_eq!(p.max_age_days, 30);
        assert_eq!(p.history_count, 24);
    }

    #[test]
    fn test_password_policy_validates_good_password() {
        let p = PasswordPolicy::default();
        let violations = p.validate("MyStr0ng!Pass");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_password_policy_catches_short() {
        let p = PasswordPolicy::default();
        let violations = p.validate("Ab1!");
        assert!(violations.iter().any(|v| matches!(v, PasswordViolation::TooShort { .. })));
    }

    #[test]
    fn test_password_policy_catches_missing_uppercase() {
        let p = PasswordPolicy::default();
        let violations = p.validate("mystrongpass1!");
        assert!(violations.contains(&PasswordViolation::MissingUppercase));
    }

    #[test]
    fn test_password_policy_catches_missing_digit() {
        let p = PasswordPolicy::default();
        let violations = p.validate("MyStrongPass!!");
        assert!(violations.contains(&PasswordViolation::MissingDigit));
    }

    #[test]
    fn test_password_policy_catches_missing_special() {
        let p = PasswordPolicy::default();
        let violations = p.validate("MyStrongPass12");
        assert!(violations.contains(&PasswordViolation::MissingSpecial));
    }

    #[test]
    fn test_password_policy_catches_missing_lowercase() {
        let p = PasswordPolicy::default();
        let violations = p.validate("MYSTRONGPASS1!");
        assert!(violations.contains(&PasswordViolation::MissingLowercase));
    }

    #[test]
    fn test_password_violation_display() {
        assert!(PasswordViolation::TooShort { min: 12, actual: 5 }.to_string().contains("12"));
        assert!(PasswordViolation::MissingUppercase.to_string().contains("uppercase"));
        assert!(PasswordViolation::InHistory.to_string().contains("recently"));
    }

    #[test]
    fn test_device_class_display() {
        assert_eq!(DeviceClass::Server.to_string(), "Server");
        assert_eq!(DeviceClass::EdgeAppliance.to_string(), "EdgeAppliance");
        assert_eq!(DeviceClass::Hsm.to_string(), "HSM");
    }

    #[test]
    fn test_governance_level_ordering() {
        assert!(GovernanceLevel::FullyGoverned > GovernanceLevel::SemiAutonomous);
        assert!(GovernanceLevel::SemiAutonomous > GovernanceLevel::Supervised);
    }

    #[test]
    fn test_autonomy_level_ordering() {
        assert!(AutonomyLevel::Full > AutonomyLevel::High);
        assert!(AutonomyLevel::High > AutonomyLevel::Medium);
        assert!(AutonomyLevel::Medium > AutonomyLevel::Low);
        assert!(AutonomyLevel::Low > AutonomyLevel::None);
    }

    #[test]
    fn test_autonomy_level_max_action_severity() {
        assert_eq!(AutonomyLevel::None.max_action_severity(), 0);
        assert_eq!(AutonomyLevel::Low.max_action_severity(), 1);
        assert_eq!(AutonomyLevel::Medium.max_action_severity(), 2);
        assert_eq!(AutonomyLevel::High.max_action_severity(), 3);
        assert_eq!(AutonomyLevel::Full.max_action_severity(), 4);
    }
}
